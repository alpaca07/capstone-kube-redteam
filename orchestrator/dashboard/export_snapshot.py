#!/usr/bin/env python3
"""현재 대시보드 상태를 단일 자립형 HTML 로 스냅샷 — 로그 기반 정보 그대로, 서버 없이 공유.

실행 중인 Helix 대시보드(localhost:PORT)의 API 를 긁어 window.__SNAPSHOT__ 에 박고,
app.css·app.js·폰트를 한 파일에 인라인한다. 결과 HTML 은 네트워크 없이 열리고,
모든 탭·그래프·노드 상세를 그대로 클릭 탐색할 수 있다(폴링은 멈춘 정적 스냅샷).

  사용(VM C, 대시보드가 떠 있는 상태):
    python3 -m orchestrator.dashboard.export_snapshot ~/capstone/helix-snapshot.html
    python3 -m orchestrator.dashboard.export_snapshot out.html --port 12345 --no-fonts
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
STATIC = HERE / "static"


def _get(base: str, path: str):
    try:
        with urllib.request.urlopen(base + path, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:  # noqa: BLE001 — 한 경로 실패가 전체를 막지 않음
        print(f"[!] {path} 수집 실패: {e}", file=sys.stderr)
        return None


def collect(base: str) -> dict:
    snap: dict = {}
    for p in ("/api/rounds", "/api/episodes", "/api/runs", "/api/events", "/api/attack_journal"):
        snap[p] = _get(base, p) or []
    st = _get(base, "/api/status") or {}
    st["running"] = False                       # 스냅샷은 완료된 정적 상태로 고정(라이브 라운드 생성 방지)
    st["status"] = st.get("status") or "idle"
    snap["/api/status"] = st

    rounds = snap["/api/rounds"] or []
    for r in rounds:
        ep, rnd = r.get("episode", 1), r.get("round")
        if rnd is None:
            continue
        for p in (f"/api/attack_graph/{ep}/{rnd}", f"/api/round/{ep}/{rnd}"):
            if p not in snap:
                snap[p] = _get(base, p)
    if rounds:
        last = rounds[-1]
        p = f"/api/topology/{last.get('episode', 1)}/{last.get('round', 1)}"
        snap[p] = _get(base, p)
    return snap


def build_html(snap: dict, *, with_fonts: bool = True) -> str:
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    html = (STATIC / "index.html").read_text(encoding="utf-8")

    if with_fonts:                              # 폰트 base64 인라인(한글 렌더 일관 — 오프라인 자립)
        for woff in sorted(STATIC.glob("fonts/*.woff")):
            b64 = base64.b64encode(woff.read_bytes()).decode()
            css = css.replace(f'url("/static/fonts/{woff.name}")', f'url("data:font/woff;base64,{b64}")')

    snap_js = "window.__SNAPSHOT__ = " + json.dumps(snap, ensure_ascii=False)
    snap_js = snap_js.replace("</", "<\\/") + ";"   # 데이터 속 </script> 로 인한 조기 종료 방지

    html = html.replace('<link rel="stylesheet" href="/static/app.css">', "<style>\n" + css + "\n</style>")
    html = html.replace('<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">', "")
    html = html.replace('<script src="/static/app.js"></script>',
                        "<script>" + snap_js + "</script>\n<script>\n" + js + "\n</script>")
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description="Helix 대시보드 → 단일 자립형 HTML 스냅샷")
    ap.add_argument("out", nargs="?", default="helix-snapshot.html", help="출력 HTML 경로")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=12345)
    ap.add_argument("--no-fonts", action="store_true", help="폰트 인라인 생략(용량↓, 시스템 폰트로 대체)")
    args = ap.parse_args()

    base = f"http://{args.host}:{args.port}"
    snap = collect(base)
    html = build_html(snap, with_fonts=not args.no_fonts)

    out = pathlib.Path(args.out)
    out.write_text(html, encoding="utf-8")
    kb = out.stat().st_size // 1024
    print(f"[✓] 스냅샷 저장: {out}  ({kb} KB · 라운드 {len(snap.get('/api/rounds', []))}개 · "
          f"회차 {len(snap.get('/api/episodes', []))}개)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
