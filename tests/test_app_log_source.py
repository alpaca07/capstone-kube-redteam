"""앱 통로(AppLogSource) 스모크 — 크라운 자백 파싱 + kubectl --prefix 접두어 처리.

플래그리스 라이브 검증에서 드러난 버그 회귀 방지: kubectl logs --prefix 는 JSON 줄 앞에
"[pod/name/container] " 접두어를 붙이는데, 줄 전체를 json.loads 하면 깨진다 → 첫 '{' 부터 파싱.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.app_signals import CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS  # noqa: E402
from orchestrator.app_log_source import AppLogSource  # noqa: E402


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _win() -> tuple[float, float]:
    now = time.time()
    return now - 3600, now + 3600


def _crown_line(svc: str, target: str, *, prefix: bool) -> str:
    body = (f'{{"ts":"{_now_iso()}","src":"app","svc":"{svc}",'
            f'"event":"crown_exfil","target":"{target}","via":"/x","status":200}}')
    return f"[pod/{svc}-abc/{svc}] {body}" if prefix else body


def test_crown_plain_json():
    lines = [_crown_line("catalog-api", CROWN_INTERNAL_SECRETS, prefix=False)]
    t0, t1 = _win()
    assert AppLogSource(lambda: iter(lines)).crowns_in_window(since_ts=t0, until_ts=t1) == \
        {CROWN_INTERNAL_SECRETS}


def test_crown_kubectl_prefix():
    # kubectl logs --prefix 접두어가 붙어도 파싱돼야 한다(회귀 방지)
    lines = [_crown_line("order-api", CROWN_CUSTOMERS_PII, prefix=True)]
    t0, t1 = _win()
    assert AppLogSource(lambda: iter(lines)).crowns_in_window(since_ts=t0, until_ts=t1) == \
        {CROWN_CUSTOMERS_PII}


def test_techniques_and_crown_separate():
    # 기법 시도 줄(web)과 크라운 자백 줄은 별개 축 — 서로 안 섞임
    ts = _now_iso()
    lines = [
        f'[pod/catalog-api-x/catalog-api] {{"ts":"{ts}","src":"app","svc":"catalog-api",'
        f'"path":"/api/products","query":"q=\' UNION SELECT","status":200}}',
        _crown_line("catalog-api", CROWN_INTERNAL_SECRETS, prefix=True),
    ]
    t0, t1 = _win()
    src = AppLogSource(lambda: iter(lines))
    assert src.techniques_in_window(since_ts=t0, until_ts=t1) == {"WEB_SQLI"}
    assert src.crowns_in_window(since_ts=t0, until_ts=t1) == {CROWN_INTERNAL_SECRETS}


def test_noise_ignored():
    lines = ["werkzeug: 127.0.0.1 - - [GET] 200", "   ", "not json at all"]
    t0, t1 = _win()
    src = AppLogSource(lambda: iter(lines))
    assert src.crowns_in_window(since_ts=t0, until_ts=t1) == set()
    assert src.techniques_in_window(since_ts=t0, until_ts=t1) == set()


def test_window_excludes_outside():
    # 창 밖(1시간 전) 자백은 제외
    old = ('{"ts":"2026-01-01T00:00:00+00:00","src":"app","svc":"catalog-api",'
           '"event":"crown_exfil","target":"internal_secrets","via":"/x","status":200}')
    t0, t1 = _win()
    assert AppLogSource(lambda: iter([old])).crowns_in_window(since_ts=t0, until_ts=t1) == set()


def test_crowns_by_channel_app():
    # 앱 통로는 자기 이름("app") 아래로 크라운을 묶어 돌려줘야 한다(표시용)
    lines = [_crown_line("catalog-api", CROWN_INTERNAL_SECRETS, prefix=True)]
    t0, t1 = _win()
    got = AppLogSource(lambda: iter(lines)).crowns_by_channel_in_window(since_ts=t0, until_ts=t1)
    assert got == {"app": {CROWN_INTERNAL_SECRETS}}


def test_crowns_by_channel_composite_splits_app_db():
    # 핵심: 앱 통로(SQLi 자백)와 DB 통로(직접 접속)가 통로별로 갈라져 나온다.
    # 판정용 합집합(crowns_in_window)은 그대로 — 통로 분리는 '표시 축'일 뿐 판정 불변.
    from orchestrator.app_log_source import CompositeLogSource
    from orchestrator.db_log_source import DbLogSource
    app_lines = [_crown_line("catalog-api", CROWN_INTERNAL_SECRETS, prefix=True)]
    pg = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:23] + " UTC"
    db_lines = [f"{pg} [42] LOG:  statement: SELECT ssn,email FROM customers"]
    t0, t1 = _win()
    comp = CompositeLogSource(AppLogSource(lambda: iter(app_lines)),
                              DbLogSource(lambda: iter(db_lines)))
    assert comp.crowns_in_window(since_ts=t0, until_ts=t1) == \
        {CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII}
    got = {k: set(v) for k, v in
           comp.crowns_by_channel_in_window(since_ts=t0, until_ts=t1).items()}
    assert got == {"app": {CROWN_INTERNAL_SECRETS}, "db": {CROWN_CUSTOMERS_PII}}


# ───────────────────── 자체 러너 ─────────────────────
def _run() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  \033[32m✓\033[0m {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  \033[31m✗\033[0m {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed  (총 {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── 앱 통로 스모크 ──")
    sys.exit(_run())
