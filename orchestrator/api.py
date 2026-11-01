"""FastAPI — 공수 공진화 대시보드 + 실험 관제 (VM C 서빙, god-view 전용).

rounds.jsonl / episodes.jsonl(채점기가 떨군 JSONL)을 읽어 JSON 제공 + 정적 대시보드 서빙 +
대시보드에서 실험(orchestrator.main)을 시작/중지하고 진행 로그를 라이브로 본다.
관리망에서만 열람(공격자 공격망에선 접근 불가).

실행:  python3 -m orchestrator.api            # 0.0.0.0:8090
       PORT=9000 python3 -m orchestrator.api  # 포트 변경
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_LOGS = Path(os.environ.get("CAPSTONE_LOGS", str(_HERE / "logs")))
_STATIC = _HERE / "static"
_RUN_LOG = _LOGS / "run.out"

app = FastAPI(title="K8s 공수 공진화 대시보드")

# ── 실험 프로세스 상태(단일 워커 전제: 한 번에 하나만) ──
_run: dict = {"proc": None, "started": None, "params": None, "id": None}


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
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
    """progress.json 같은 단일 JSON 객체를 안전하게 읽음(없거나 깨지면 빈 dict)."""
    try:
        with path.open(encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _running() -> bool:
    p = _run["proc"]
    return bool(p and p.poll() is None)


@app.get("/api/rounds")
def rounds() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "rounds.jsonl"))


@app.get("/api/episodes")
def episodes() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "episodes.jsonl"))


@app.get("/api/runs")
def runs_list() -> JSONResponse:
    """실험 런 레지스트리 — run_start 가 runs.jsonl 에 append 한 기록. 최신순,
    현재 실행 중인 런은 상태를 '진행 중'으로 반영."""
    runs = _read_jsonl(_LOGS / "runs.jsonl")
    active = _run.get("id") if _running() else None
    for r in runs:
        r["status"] = "진행 중" if r.get("id") == active else "완료"
    runs.reverse()
    return JSONResponse(runs)


@app.get("/api/status")
def live_status() -> JSONResponse:
    """진행 sink(progress.json) + 실행 여부를 합쳐 '지금 상태'를 반환 — 대시보드 라이브 소스.

    stdout 테일(run.out, /api/run/status)과 달리 구조화된 현재 phase/round/활성 에이전트/
    턴 시작시각을 준다 → 0~8 단계 표시기·턴 예산 바.
    """
    prog = _read_json(_LOGS / "progress.json") or {"status": "idle"}
    running = _running()
    started = _run["started"]
    # 프로세스는 죽었는데 sink가 'running'에 멈춰 있으면(크래시) 상태 보정.
    if not running and prog.get("status") == "running":
        prog["status"] = "stopped"
        prog["active"] = None
        prog["turn_started"] = None
    prog["running"] = running
    prog["run_elapsed"] = (time.time() - started) if started else 0
    return JSONResponse(prog)


@app.post("/api/run")
def run_start(payload: dict = Body(default={})) -> JSONResponse:
    """orchestrator.main 을 서브프로세스로 띄운다. fresh=true 면 로그 초기화."""
    if _running():
        return JSONResponse({"ok": False, "error": "이미 실행 중"}, status_code=409)
    try:
        eps = max(1, int(payload.get("episodes", 1)))
        mr = max(1, int(payload.get("max_rounds", 1)))
        tl = max(30, int(payload.get("time_limit", 180)))
        mt = max(64, int(payload.get("max_tokens", 1024)))
    except (TypeError, ValueError):
        return JSONResponse({"ok": False, "error": "잘못된 파라미터"}, status_code=400)

    _LOGS.mkdir(parents=True, exist_ok=True)
    if payload.get("fresh"):
        for f in ("rounds.jsonl", "episodes.jsonl"):
            try:
                (_LOGS / f).write_text("", encoding="utf-8")
            except OSError:
                pass

    cmd = [sys.executable, "-u", "-m", "orchestrator.main",
           "--episodes", str(eps), "--max-rounds", str(mr),
           "--time-limit", str(tl), "--max-tokens", str(mt)]
    logf = open(_RUN_LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=str(_ROOT), stdout=logf,
                            stderr=subprocess.STDOUT, env=os.environ.copy())
    run_id = "run-" + time.strftime("%m%d-%H%M%S")
    started = time.time()
    _run.update(proc=proc, started=started, id=run_id,
                params={"episodes": eps, "max_rounds": mr, "time_limit": tl, "max_tokens": mt})
    try:  # 런 레지스트리에 기록(/api/runs 소스). fresh 여도 runs.jsonl 은 보존.
        with (_LOGS / "runs.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"id": run_id, "started": started,
                                "mode": str(payload.get("mode", "demo")),
                                "params": _run["params"]}, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return JSONResponse({"ok": True, "pid": proc.pid, "id": run_id, "params": _run["params"]})


@app.post("/api/run/stop")
def run_stop() -> JSONResponse:
    p = _run["proc"]
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        return JSONResponse({"ok": True, "stopped": True})
    return JSONResponse({"ok": True, "stopped": False})


@app.get("/api/run/status")
def run_status() -> JSONResponse:
    p = _run["proc"]
    running = _running()
    tail: list[str] = []
    try:
        tail = _RUN_LOG.read_text(encoding="utf-8").splitlines()[-20:]
    except OSError:
        pass
    started = _run["started"]
    return JSONResponse({
        "running": running,
        "params": _run["params"],
        "started": started,
        "elapsed": (time.time() - started) if started else 0,
        "returncode": (p.poll() if (p and not running) else None),
        "log": tail,
    })


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(_STATIC / "dashboard.html"))


if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def main() -> None:
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8090")))


if __name__ == "__main__":
    main()
