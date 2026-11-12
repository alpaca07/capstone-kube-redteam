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


def _pkill_orchestrator() -> bool:
    """pid 없을 때 폴백 — 모듈명으로 orchestrator.main 종료(대시보드와 같은 사용자). 대시보드는
    orchestrator.dashboard 라 매칭 안 됨. 1건이라도 종료하면 True."""
    try:
        r = subprocess.run(["pkill", "-TERM", "-f", "-m orchestrator.main"],
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
    archived = None
    if payload.get("fresh"):
        archived = _archive_run_logs()      # 지운다 아님 — 지난 실행을 runs_archive/ 로 보관 후 라이브 비움

    cmd = [sys.executable, "-u", "-m", "orchestrator.main",
           "--episodes", str(eps), "--max-rounds", str(mr),
           "--time-limit", str(tl)]
    if mt is not None:                      # None = 무제한(--max-tokens 생략 → config.dgx.max_tokens 기본)
        cmd += ["--max-tokens", str(mt)]
    logf = open(_RUN_LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=str(_ROOT), stdout=logf,
                            stderr=subprocess.STDOUT, env=os.environ.copy())
    run_id = "run-" + time.strftime("%m%d-%H%M%S")
    started = time.time()
    _run.update(proc=proc, started=started, id=run_id,
                params={"episodes": eps, "max_rounds": mr, "time_limit": tl, "max_tokens": mt})
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
def run_stop() -> JSONResponse:
    p = _run["proc"]
    if p and p.poll() is None:               # 대시보드가 띄운 프로세스
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        return JSONResponse({"ok": True, "stopped": True})
    # 외부(CLI) 실행 — progress.json 의 pid 로 종료 시도(최신성 가드로 묵은 pid 오인 방지)
    prog = _read_json(_LOGS / "progress.json")
    if _external_running(prog):
        pid = prog.get("pid")
        if isinstance(pid, int) and pid > 0:
            try:
                os.kill(pid, signal.SIGTERM)
                return JSONResponse({"ok": True, "stopped": True, "external": True})
            except ProcessLookupError:
                pass                                  # 이미 죽음 → pkill 폴백으로
            except PermissionError as e:
                return JSONResponse({"ok": False, "stopped": False, "error": f"외부 실행 종료 권한 없음: {e}"})
        killed = _pkill_orchestrator()                # pid 없음(구버전 런) 또는 위 실패 — 모듈명 폴백
        return JSONResponse({"ok": killed, "stopped": killed, "external": True,
                             "error": None if killed else "orchestrator.main 프로세스를 찾지 못했습니다(권한·이름 확인)"})
    return JSONResponse({"ok": True, "stopped": False})


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
    return JSONResponse({
        "running": running, "external": external, "params": _run["params"], "started": started,
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
