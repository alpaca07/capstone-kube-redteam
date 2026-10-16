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
_run: dict = {"proc": None, "started": None, "params": None}


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


def _running() -> bool:
    p = _run["proc"]
    return bool(p and p.poll() is None)


@app.get("/api/rounds")
def rounds() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "rounds.jsonl"))


@app.get("/api/episodes")
def episodes() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "episodes.jsonl"))


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
    _run.update(proc=proc, started=time.time(),
                params={"episodes": eps, "max_rounds": mr, "time_limit": tl, "max_tokens": mt})
    return JSONResponse({"ok": True, "pid": proc.pid, "params": _run["params"]})


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
