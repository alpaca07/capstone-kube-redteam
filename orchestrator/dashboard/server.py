"""대시보드 FastAPI — 정적 SPA 서빙 + 로그 조회 API + 실험 제어 (VM C, god-view 전용).

기존 orchestrator/api.py(:8090)와 독립. 같은 로그 디렉토리를 읽으므로 나란히 돌아간다.
관리망에서만 열람(공격망에선 접근 불가). 읽기 전용 조회 + 실험 시작/중지.

실행:  PORT=12345 python3 -m orchestrator.dashboard
       CAPSTONE_LOGS=/path/to/logs PORT=12345 python3 -m orchestrator.dashboard
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

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
    running = _running()
    started = _run["started"]
    if not running and prog.get("status") == "running":      # 크래시 보정
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
        mt = max(64, int(payload.get("max_tokens", 1024)))
    except (TypeError, ValueError):
        return JSONResponse({"ok": False, "error": "잘못된 파라미터"}, status_code=400)

    _LOGS.mkdir(parents=True, exist_ok=True)
    if payload.get("fresh"):
        for f in ("rounds.jsonl", "episodes.jsonl", "events.jsonl"):
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
    try:
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
    tail: list = []
    try:
        tail = _RUN_LOG.read_text(encoding="utf-8").splitlines()[-40:]
    except OSError:
        pass
    started = _run["started"]
    return JSONResponse({
        "running": running, "params": _run["params"], "started": started,
        "elapsed": (time.time() - started) if started else 0,
        "returncode": (p.poll() if (p and not running) else None), "log": tail,
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
