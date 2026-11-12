"""신규 취약점 주기 수집 파이프라인(knowledge/ingest.py) 스모크 — 네트워크·LLM·yaml 없이.

이음새(FakeNvdFeed·FakeAuthor·DryRunSession)로 수집→필터→1단/2단 반영을 순수 검증.
검증 범위:
  1) 허용목록 필터: 우리 제품 CPE 만 통과, 그 외 CVE 는 버림
  2) run_ingest: 매칭·저작·거절 집계, 1단(CVE)·2단(핵심층)·매핑(EXPLOITED_BY) 반영
  3) 적재 스키마: DryRunSession 경유 merge 가 schema.check_* 를 태움(무사통과=스키마 OK)
  4) 워터마크: 첫 실행은 창(window)으로, 다음 실행은 저장된 lastMod 이후만 / dry-run 은 전진 안 함
  5) 창 클램프(120일 상한) + 상태 저장·로드 왕복
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from knowledge import authoring, graph_writer, ingest  # noqa: E402

_PREFIXES = frozenset({"cpe:2.3:a:apache:struts", "cpe:2.3:a:postgresql:postgresql"})
_NOW = "2026-11-11T00:00:00.000Z"


def _entry(cve_id: str, cpe: str, cwe: str = "CWE-755") -> dict:
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} remote code execution"}],
        "weaknesses": [{"description": [{"value": cwe}]}],
        "references": [{"url": f"https://example.test/{cve_id}", "tags": ["Exploit"]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe}]}]}],
    }}


_STRUTS = _entry("CVE-2017-5638", "cpe:2.3:a:apache:struts:2.5.10:*:*:*:*:*:*:*")
_PG = _entry("CVE-2019-9193", "cpe:2.3:a:postgresql:postgresql:11.2:*:*:*:*:*:*:*", cwe="CWE-78")
_WINDOWS = _entry("CVE-2099-0001", "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*")


def _feed(*entries):
    return ingest.FakeNvdFeed({"vulnerabilities": list(entries)})


def _tmp_state():
    d = tempfile.mkdtemp()
    return str(Path(d) / "state.json"), str(Path(d) / "auto")


# ───────────── 필터 ─────────────
def test_allowlist_filter_keeps_only_our_products():
    assert ingest.cve_hits_allowlist(_STRUTS, _PREFIXES) is True
    assert ingest.cve_hits_allowlist(_PG, _PREFIXES) is True
    assert ingest.cve_hits_allowlist(_WINDOWS, _PREFIXES) is False


# ───────────── run_ingest ─────────────
def test_run_ingest_matches_authors_and_loads():
    state, out = _tmp_state()
    report = ingest.run_ingest(
        feed=_feed(_STRUTS, _PG, _WINDOWS), author=authoring.FakeAuthor(),
        session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
        state_path=state, out_dir=out, now_iso=_NOW)
    assert report.fetched == 3
    assert report.matched == 2          # windows 걸러짐
    assert report.authored == 2
    assert report.rejected == []
    assert report.bottom_nodes > 0      # nvd KnowledgeSource + CVE 2
    assert report.core_nodes > 0        # llm KnowledgeSource + EvidenceType + ④⑤
    assert report.mapping_rels == 2     # CVE→기법 EXPLOITED_BY 2건(각 env technique)
    assert report.advanced_to == _NOW


def test_run_ingest_writes_env_files():
    state, out = _tmp_state()
    ingest.run_ingest(feed=_feed(_STRUTS), author=authoring.FakeAuthor(),
                      session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
                      state_path=state, out_dir=out, now_iso=_NOW)
    files = list(Path(out).glob("*.json"))
    assert len(files) == 1


def test_run_ingest_rejects_invalid_authoring():
    state, out = _tmp_state()
    bad = {"env": "", "procedure": {}}   # 게이트에서 걸릴 무효 env
    author = authoring.FakeAuthor(by_cve={"CVE-2017-5638": bad})
    report = ingest.run_ingest(
        feed=_feed(_STRUTS, _PG), author=author,
        session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
        state_path=state, out_dir=out, now_iso=_NOW)
    assert report.matched == 2
    assert report.authored == 1                         # pg 만 통과
    assert [c for c, _ in report.rejected] == ["CVE-2017-5638"]


def test_merge_runs_schema_check():
    # DryRunSession 경유 merge 가 schema.check_node/check_rel 를 태운다 → 무사 통과면 스키마 OK.
    report = ingest.run_ingest(
        feed=_feed(_STRUTS, _PG), author=authoring.FakeAuthor(),
        session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
        state_path=_tmp_state()[0], now_iso=_NOW)
    assert report.authored == 2   # 여기 도달 = merge 중 ValueError(잘못된 라벨) 없었음


# ───────────── 워터마크 ─────────────
def test_watermark_first_run_uses_window_then_advances():
    state, out = _tmp_state()
    feed = _feed(_STRUTS)
    r1 = ingest.run_ingest(feed=feed, author=authoring.FakeAuthor(),
                           session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
                           state_path=state, out_dir=out, now_iso=_NOW, window_days=120)
    # 첫 실행: 상태 없으니 창(120일 전)부터
    assert feed.calls[0][0] == "2026-07-14T00:00:00.000Z"
    assert r1.advanced_to == _NOW
    assert ingest.load_state(state) == {"last_mod": _NOW}

    # 다음 실행: 저장된 lastMod 이후만
    later = "2026-11-12T00:00:00.000Z"
    ingest.run_ingest(feed=feed, author=authoring.FakeAuthor(),
                      session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
                      state_path=state, out_dir=out, now_iso=later)
    assert feed.calls[1][0] == _NOW


def test_dry_run_does_not_advance_watermark():
    state, out = _tmp_state()
    report = ingest.run_ingest(
        feed=_feed(_STRUTS), author=authoring.FakeAuthor(),
        session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
        state_path=state, out_dir=out, now_iso=_NOW, dry_run=True)
    assert report.advanced_to is None
    assert ingest.load_state(state) == {}     # 저장 안 됨


def test_since_override_wins():
    state, out = _tmp_state()
    feed = _feed(_STRUTS)
    ingest.run_ingest(feed=feed, author=authoring.FakeAuthor(),
                      session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
                      state_path=state, out_dir=out, now_iso=_NOW,
                      since_override="2026-11-01T00:00:00.000Z")
    assert feed.calls[0][0] == "2026-11-01T00:00:00.000Z"


# ───────────── 창 클램프 + 상태 왕복 ─────────────
def test_window_clamp_over_120_days():
    state, out = _tmp_state()
    feed = _feed()
    report = ingest.run_ingest(
        feed=feed, author=authoring.FakeAuthor(),
        session=graph_writer.DryRunSession(), prefixes=_PREFIXES,
        state_path=state, out_dir=out, now_iso=_NOW,
        since_override="2020-01-01T00:00:00.000Z", window_days=120)
    assert report.clamped is True
    assert feed.calls[0][0] == "2026-07-14T00:00:00.000Z"   # now-120일로 당겨짐


def test_state_save_load_roundtrip():
    state, _ = _tmp_state()
    ingest.save_state(state, _NOW)
    assert ingest.load_state(state) == {"last_mod": _NOW}


def test_missing_prefixes_and_path_errors():
    try:
        ingest.run_ingest(feed=_feed(), author=authoring.FakeAuthor(),
                          session=graph_writer.DryRunSession(),
                          state_path=_tmp_state()[0], now_iso=_NOW)
    except ValueError:
        return
    raise AssertionError("prefixes·allowlist_path 둘 다 없는데 ValueError 안 남")


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
    print("── 신규 취약점 주기 수집 파이프라인 스모크 ──")
    sys.exit(_run())
