"""베이스라인 스냅샷 캡처(재베이스라인) — config의 호스트 스냅샷 에이전트로 저장.

실행 중인 VM B(취약 클러스터 + 방어 서버)를 '라이브 스냅샷'으로 떠서 clean-baseline에
저장한다. 오케스트레이터는 에피소드마다 이걸로 revert → 매번 같은 취약 상태 + 서버가
떠 있는 상태로 복원된다. 코드/환경이 바뀌면 이 스크립트로 다시 떠야 한다.

전제: 호스트 데스크톱 세션에서 snapshot_agent.py가 떠 있어야 함(config의 snapshot_agent_url).
      VM B는 원하는 베이스라인 상태(취약 복원 + 방어 서버 기동)로 있어야 함.

    python3 scripts/baseline.py            # clean-baseline 캡처(기존 것 덮어씀)
    python3 scripts/baseline.py --list     # 현재 스냅샷 목록만
    python3 scripts/baseline.py --name x   # 다른 이름으로 저장

주의: 라이브 스냅샷은 메모리까지 뜨므로 수십 초~수 분 걸리고, 그동안 VM B가 잠깐 멈출 수
있다(정상). 완료될 때까지 기다린다.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.config import load_config                          # noqa: E402
from orchestrator.http_snapshot import HttpSnapshotManager     # noqa: E402
from orchestrator.vmrun_snapshot import SnapshotError          # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="베이스라인 스냅샷 캡처(호스트 에이전트)")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--name", default=None, help="스냅샷 이름(기본: config의 baseline_snapshot)")
    ap.add_argument("--list", action="store_true", help="저장 안 하고 현재 목록만 출력")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    url = cfg.vmware.snapshot_agent_url
    if not url:
        print("[!] config의 vmware.snapshot_agent_url 이 비어 있음(method=agent + URL 필요).")
        return 2
    name = args.name or cfg.vmware.baseline_snapshot

    sm = HttpSnapshotManager(url, token=cfg.network.shared_token)
    print(f"[*] 호스트 에이전트 = {url}")

    try:
        if args.list:
            print(f"    현재 스냅샷: {sm.list()}")
            return 0
        print(f"[*] '{name}' 캡처 중… (라이브 스냅샷이라 수십 초~수 분, VM B 잠깐 멈출 수 있음)")
        t0 = time.time()
        sm.save(name)
        print(f"[✓] 캡처 완료 ({time.time() - t0:.0f}s). 현재 스냅샷: {sm.list()}")
        return 0
    except SnapshotError as e:
        print(f"[!] 스냅샷 실패: {e}")
        return 1
    except Exception as e:  # noqa: BLE001 — 연결 거부 등(에이전트 꺼짐/호스트 미로그인)
        print(f"[!] 에이전트 호출 실패: {type(e).__name__}: {e}")
        print("    → 호스트 데스크톱 세션에서 snapshot_agent.py가 떠 있는지 확인.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
