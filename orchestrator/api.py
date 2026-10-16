"""FastAPI — 공수 공진화 대시보드 (VM C 서빙).

rounds.jsonl / episodes.jsonl(채점기가 떨군 JSONL)을 읽어 JSON 으로 제공하고,
정적 대시보드(static/dashboard.html, HTML+Chart.js)를 서빙한다. god-view 전용이므로
관리망에서만 열람(공격자 공격망에선 접근 불가).

실행:  python3 -m orchestrator.api            # 0.0.0.0:8090
       PORT=9000 python3 -m orchestrator.api  # 포트 변경
로그 경로 override:  CAPSTONE_LOGS=/path/to/logs python3 -m orchestrator.api
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_HERE = Path(__file__).resolve().parent
_LOGS = Path(os.environ.get("CAPSTONE_LOGS", str(_HERE / "logs")))
_STATIC = _HERE / "static"

app = FastAPI(title="K8s 공수 공진화 대시보드")


def _read_jsonl(path: Path) -> list[dict]:
    """JSONL 파일 → dict 리스트. 깨진 줄·없는 파일은 건너뜀(라이브 수집 중에도 안전)."""
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


@app.get("/api/rounds")
def rounds() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "rounds.jsonl"))


@app.get("/api/episodes")
def episodes() -> JSONResponse:
    return JSONResponse(_read_jsonl(_LOGS / "episodes.jsonl"))


@app.get("/api/status")
def status() -> JSONResponse:
    eps = _read_jsonl(_LOGS / "episodes.jsonl")
    rnds = _read_jsonl(_LOGS / "rounds.jsonl")
    return JSONResponse({"episodes": len(eps), "rounds": len(rnds),
                         "logs_dir": str(_LOGS)})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(_STATIC / "dashboard.html"))


if _STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


def main() -> None:
    import uvicorn
    port = int(os.environ.get("PORT", "8090"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
