"""대시보드 FastAPI — 정적 SPA 서빙 + 로그 조회 API + 실험 제어 (VM C, god-view 전용).

기존 orchestrator/api.py(:8090)와 독립. 같은 로그 디렉토리를 읽으므로 나란히 돌아간다.
관리망에서만 열람(공격망에선 접근 불가). 읽기 전용 조회 + 실험 시작/중지.

실행:  PORT=12345 python3 -m orchestrator.dashboard
       CAPSTONE_LOGS=/path/to/logs PORT=12345 python3 -m orchestrator.dashboard
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent                                   # 레포 루트(orchestrator/dashboard → ..)
_LOGS = Path(os.environ.get("CAPSTONE_LOGS", str(_HERE.parent / "logs")))
_STATIC = _HERE / "static"
_RUN_LOG = _LOGS / "run.out"

app = FastAPI(title="Helix — 공수 루프 관제 대시보드")

# ⬆⬆ 빌드 버전 — 패치할 때마다 +1 (app.js 의 UI_BUILD 과 같은 값으로 함께 올린다).
# /api/status 로 내보내 대시보드가 '서버가 최신 코드로 재시작됐는지' 좌상단 버전으로 확인한다.
SERVER_BUILD = 1

# 실험 프로세스 상태(단일 워커 전제: 한 번에 하나만).
_run: dict = {"proc": None, "started": None, "params": None, "id": None}


# ───────────── 로그 읽기 헬퍼 ─────────────
def _read_jsonl(path: Path) -> list:
    out: list = []
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return out


def _read_json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _running() -> bool:
    p = _run["proc"]
    return bool(p and p.poll() is None)


def _external_running(prog: dict) -> bool:
    """CLI 등 외부 실행 감지 — progress.json 최신성으로(턴제한*2+120, 최소 300초 창)."""
    updated = prog.get("updated_at") or 0
    window = max(300, int(prog.get("time_limit_sec") or 180) * 2 + 120)
    return bool(prog.get("status") == "running" and updated and (time.time() - updated) < window)


_STOP_FLAG = _LOGS / "stop.request"              # orchestrator.main 이 매 라운드 경계에서 읽는 협조적 중지 플래그


def _write_stop_flag() -> bool:
    """협조적 중지 — 권한·pid·progress 최신성과 무관하게 전달되는 1차 경로.
    orchestrator.main 이 같은 로그 디렉토리에서 이 파일을 읽어 현재 라운드만 마치고 안전 종료한다."""
    try:
        _LOGS.mkdir(parents=True, exist_ok=True)
        _STOP_FLAG.write_text(str(time.time()), encoding="utf-8")
        return True
    except OSError:
        return False


def _pid_is_orchestrator(pid: int) -> bool:
    """/proc/<pid>/cmdline 로 실제 orchestrator.main 프로세스인지 검증 — progress 최신성 창에 기대지
    않고(긴 턴에 묵은 pid 오인 방지) 바로 신호를 보낼 수 있게. 대시보드(orchestrator.dashboard)는 제외."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cl = f.read().decode("utf-8", "replace")
        return ("orchestrator.main" in cl) and ("orchestrator.dashboard" not in cl)
    except OSError:
        return False


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True            # 권한 등 — 보수적으로 살아있다고 본다
    # pid 가 존재해도 좀비(Z, 종료됐지만 부모가 아직 회수 안 함)는 죽은 것으로 본다.
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            st = f.read().decode("utf-8", "replace")
        state = st[st.rfind(")") + 1:].split()[0] if ")" in st else ""
        if state == "Z":
            return False
    except OSError:
        return False           # /proc 항목 없음 = 죽음
    return True


def _wait_pid_dead(pid: int, timeout: float) -> bool:
    """timeout 동안 pid 가 죽길 기다린다. 죽으면 True."""
    end = time.time() + max(0.0, timeout)
    while time.time() < end:
        if not _pid_alive(pid):
            return True
        time.sleep(0.2)
    return not _pid_alive(pid)


def _pkill_orchestrator(sig: str = "-TERM") -> bool:
    """pid 폴백 실패 시 최후 수단 — 모듈명으로 orchestrator.main 종료(대시보드와 같은 사용자).
    패턴이 대시(-)로 시작하면 pkill 이 옵션으로 오인하므로(invalid option) 'orchestrator\\.main' 로
    매칭한다. 대시보드는 orchestrator.dashboard 라 안 걸리고, pkill 은 자기 자신도 제외. 1건↑ 종료 시 True."""
    try:
        r = subprocess.run(["pkill", sig, "-f", r"orchestrator\.main"],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# 지난 실행 내역(회차 로그·라운드 상세·공격 그래프 스냅샷)을 runs_archive/<ts>/ 로 이관.
# 라이브 디렉토리를 비워 "지금 실행 중인 실험"만 남긴다. runs.jsonl·progress.json 은 보존.
_ARCHIVE_JSONL = ("rounds.jsonl", "episodes.jsonl", "events.jsonl", "attack_journal.jsonl")
_ARCHIVE_DIRS = ("round_detail", "defense_topology", "attack_graph")


def _archive_run_logs() -> Optional[str]:
    dest = _LOGS / "runs_archive" / time.strftime("%Y%m%d-%H%M%S")
    moved = False
    try:
        for name in _ARCHIVE_JSONL:
            src = _LOGS / name
            if src.exists() and src.stat().st_size > 0:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dest / name))
                moved = True
        for name in _ARCHIVE_DIRS:
            src = _LOGS / name
            if src.is_dir() and any(src.iterdir()):
                dest.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dest / name))
                moved = True
    except OSError:
        return None
    return str(dest) if moved else None


# ───────────── 조회 API ─────────────
@app.get("/api/rounds")
def rounds() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "rounds.jsonl"))


@app.get("/api/episodes")
def episodes() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "episodes.jsonl"))


@app.get("/api/runs")
def runs_list() -> JSONResponse:
    runs = _read_jsonl(_LOGS / "runs.jsonl")
    active = _run.get("id") if _running() else None
    for r in runs:
        r["status"] = "running" if r.get("id") == active else "done"
    runs.reverse()
    return JSONResponse(runs)


@app.get("/api/events")
def events(limit: int = 800) -> JSONResponse:
    evs = _read_jsonl(_LOGS / "events.jsonl")
    return JSONResponse(evs[-limit:] if limit and limit > 0 else evs)


@app.get("/api/attack_journal")
def attack_journal_feed(limit: int = 600) -> JSONResponse:
    """실시간 공격 저널(스트리머가 턴 중 미러한 스텝). 이벤트 로그(events.jsonl)와 소스 분리."""
    evs = _read_jsonl(_LOGS / "attack_journal.jsonl")
    return JSONResponse(evs[-limit:] if limit and limit > 0 else evs)


@app.get("/api/round/{episode}/{rnd}")
def round_detail(episode: int, rnd: int) -> JSONResponse:
    return JSONResponse(_read_json(_LOGS / "round_detail" / f"{episode}-{rnd}.json"))


@app.get("/api/topology/{episode}/{rnd}")
def topology(episode: int, rnd: int) -> JSONResponse:
    return JSONResponse(_read_json(_LOGS / "defense_topology" / f"{episode}-{rnd}.json"))


@app.get("/api/attack_graph/{episode}/{rnd}")
def attack_graph(episode: int, rnd: int) -> JSONResponse:
    return JSONResponse(_read_json(_LOGS / "attack_graph" / f"{episode}-{rnd}.json"))


@app.get("/api/status")
def live_status() -> JSONResponse:
    prog = _read_json(_LOGS / "progress.json") or {"status": "idle"}
    running = _running() or _external_running(prog)  # 대시보드 띄운 프로세스 + CLI 외부 실행
    started = _run["started"]
    if not running and prog.get("status") == "running":      # 오래 멈춘 running = 크래시/종료 보정
        prog["status"] = "stopped"
        prog["active"] = None
        prog["turn_started"] = None
    prog["running"] = running
    prog["run_elapsed"] = (time.time() - started) if started else 0
    prog["server_build"] = SERVER_BUILD      # 대시보드 버전 대조용(좌상단 v표시 + 재시작 필요 경고)
    return JSONResponse(prog)


# ───────────── 실험 제어 ─────────────
@app.post("/api/run")
def run_start(payload: dict = Body(default={})) -> JSONResponse:
    if _running():
        return JSONResponse({"ok": False, "error": "이미 실행 중"}, status_code=409)
    try:
        eps = max(1, int(payload.get("episodes", 1)))
        mr = max(1, int(payload.get("max_rounds", 1)))
        tl = max(30, int(payload.get("time_limit", 180)))
        _mt = payload.get("max_tokens", 1024)
        mt = None if _mt in (None, 0, "", "0") else max(64, int(_mt))   # 0·빈값·null = 무제한
    except (TypeError, ValueError):
        return JSONResponse({"ok": False, "error": "잘못된 파라미터"}, status_code=400)

    _LOGS.mkdir(parents=True, exist_ok=True)
    try:                                         # 묵은 중지 플래그 제거 — 새 런이 바로 종료되지 않게
        _STOP_FLAG.exists() and _STOP_FLAG.unlink()
    except OSError:
        pass
    archived = None
    if payload.get("fresh"):
        archived = _archive_run_logs()      # 지운다 아님 — 지난 실행을 runs_archive/ 로 보관 후 라이브 비움

    om = payload.get("objective_mode") or None               # asset|free (없으면 config 기본)
    ta = (payload.get("target_assets") or "").strip() or None  # 크라운 id CSV(예: crown-pii,crown-ops)
    en = (payload.get("exec_namespace") or "").strip() or None  # 발판 네임스페이스(대시보드 타깃→자동전환)
    epod = (payload.get("exec_pod") or "").strip() or None      # kubectl exec 대상(deploy/… 또는 파드명)
    dr = payload.get("attacker_db_roles")                       # DB 크라운 역할 스코핑(corp=빈값→[] / ShopFlow=appuser,legacy_admin)
    dlc = bool(payload.get("db_log_corp"))                      # corp 크라운은 corp-crown 로그 파일(-corp)을 읽음
    cmd = [sys.executable, "-u", "-m", "orchestrator.main",
           "--episodes", str(eps), "--max-rounds", str(mr),
           "--time-limit", str(tl)]
    if mt is not None:                      # None = 무제한(--max-tokens 생략 → config.dgx.max_tokens 기본)
        cmd += ["--max-tokens", str(mt)]
    if om:                                   # 대시보드 타깃 선택 → orchestrator 목표 전달
        cmd += ["--objective-mode", str(om)]
    if ta:
        cmd += ["--target-assets", str(ta)]
    if en:                                   # 발판까지 자동전환(exec_namespace/pod override → 공격자·baseline)
        cmd += ["--exec-namespace", str(en)]
    if epod:
        cmd += ["--exec-pod", str(epod)]
    if dr is not None:                       # DB 크라운 채점도 타깃 자동전환 — 역할 스코핑(빈값=스코핑 없음)
        cmd += ["--attacker-db-roles", str(dr)]
    if dlc:                                   # corp 크라운은 corp-crown 로그 파일(-corp)을 읽게
        cmd += ["--db-log-corp"]
    logf = open(_RUN_LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=str(_ROOT), stdout=logf,
                            stderr=subprocess.STDOUT, env=os.environ.copy())
    run_id = "run-" + time.strftime("%m%d-%H%M%S")
    started = time.time()
    _run.update(proc=proc, started=started, id=run_id,
                params={"episodes": eps, "max_rounds": mr, "time_limit": tl, "max_tokens": mt,
                        "objective_mode": om, "target": ta or "(config)", "foothold": en or "(config)",
                        "db_log": ("corp-crown" if dlc else "database"), "db_roles": (dr if dr is not None else "(config)")})
    try:
        with (_LOGS / "runs.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"id": run_id, "started": started,
                                "mode": str(payload.get("mode", "demo")),
                                "params": _run["params"]}, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return JSONResponse({"ok": True, "pid": proc.pid, "id": run_id, "params": _run["params"],
                         "archived": archived})


@app.post("/api/run/stop")
def run_stop(payload: dict = Body(default={})) -> JSONResponse:
    """실험 중지 — 버튼 한 번으로 확실히 멈춘다. SIGTERM(안전 종료 요청)을 보내고 몇 초(grace) 안에
    안 죽으면 SIGKILL(강제)로 escalate 한다. 공격 턴이 수백 초라 orchestrator 가 라운드 경계까지
    graceful 하게 안 끝나므로, grace 뒤에는 무조건 강제로 끊는다. force=true 면 유예 없이 즉시 SIGKILL."""
    force = bool(payload.get("force"))
    grace = 0.0 if force else 3.0
    flagged = _write_stop_flag()                 # 협조적 중지 플래그(라운드 경계까지 살아있으면 활용)
    via = ["flag"] if flagged else []

    p = _run["proc"]                             # 1) 대시보드가 띄운 프로세스
    if p and p.poll() is None:
        try:
            if force:
                p.kill()
            else:
                p.terminate()                     # SIGTERM(안전 종료 요청)
                try:
                    p.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    p.kill()                      # 유예 내 안 죽으면 강제
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            dead = p.poll() is not None
            via.append("signal")
            return JSONResponse({"ok": dead, "stopped": dead, "via": via,
                                 "detail": "대시보드 실행 종료" if dead else "종료 신호 전송(확인 필요)"})
        except OSError as e:
            return JSONResponse({"ok": flagged, "stopped": False, "via": via,
                                 "error": f"프로세스 신호 실패(플래그 기록됨): {e}"})

    # 2) 외부(CLI) 실행 — progress.json pid 를 /proc 로 검증 후 SIGTERM → 유예 → SIGKILL.
    prog = _read_json(_LOGS / "progress.json")
    pid = prog.get("pid")
    if isinstance(pid, int) and pid > 0 and _pid_is_orchestrator(pid):
        try:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            return JSONResponse({"ok": True, "stopped": True, "via": via, "detail": "이미 종료됨"})
        except PermissionError as e:
            return JSONResponse({"ok": flagged, "stopped": False, "external": True, "via": via,
                                 "error": f"pid {pid} 종료 권한 없음: {e}"})
        if not _wait_pid_dead(pid, grace):            # 유예 내 안 죽으면(또는 force=유예0) SIGKILL
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            _wait_pid_dead(pid, 3.0)                   # 강제 반영 대기
        via.append("signal")
        dead = not _pid_alive(pid)
        return JSONResponse({"ok": dead, "stopped": dead, "external": True, "via": via,
                             "detail": f"외부 실행 pid {pid} 종료" if dead
                                       else f"pid {pid} 종료 신호 전송(아직 살아있음)"})

    # 3) pkill 폴백 — TERM 후 유예, 그래도 남으면 KILL.
    hit = _pkill_orchestrator("-TERM")
    if hit and not force:
        time.sleep(grace)
    killed = _pkill_orchestrator("-KILL")        # 남아있으면 강제(없으면 returncode≠0)
    if hit or killed:
        via.append("pkill")
    ok = flagged or hit or killed
    return JSONResponse({"ok": ok, "stopped": killed or (hit and not force), "via": via, "external": True,
                         "error": None if ok else "중지 경로 모두 실패 — orchestrator.main 프로세스·권한 확인"})


@app.get("/api/run/status")
def run_status() -> JSONResponse:
    p = _run["proc"]
    managed = _running()
    prog = _read_json(_LOGS / "progress.json")
    external = (not managed) and _external_running(prog)   # CLI 외부 실행
    running = managed or external
    tail: list = []
    try:
        tail = _RUN_LOG.read_text(encoding="utf-8").splitlines()[-40:]
    except OSError:
        pass
    started = _run["started"]
    stopping = running and _STOP_FLAG.exists()    # 중지 플래그는 떨어졌는데 아직 라운드 진행 중
    return JSONResponse({
        "running": running, "external": external, "stopping": stopping,
        "params": _run["params"], "started": started,
        "elapsed": (time.time() - started) if started else 0,
        "returncode": (p.poll() if (p and not managed) else None), "log": tail,
    })


# ───────────── 정적 SPA ─────────────
@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(_STATIC / "index.html"))


if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def main() -> None:
    import uvicorn
    port = int(os.environ.get("PORT", "12345"))
    print(f"[*] 관제 대시보드 http://0.0.0.0:{port}  (logs={_LOGS})")
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
