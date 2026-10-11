"""k8s 감사/Falco 로그 공통 파싱 — VM C(log_source)와 VM B(observer)가 공유.

둘 다 같은 로그 포맷(k3s 감사 JSON, Falco JSON)의 타임스탬프를 읽으므로 여기로 모은다.
기법 매핑(god-view)·구조화(방어자)는 각자 다르니 소비자 쪽에 둔다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def parse_rfc3339(s: str) -> Optional[float]:
    """RFC3339(…Z, 나노초 포함)를 epoch 초로. 실패 시 None."""
    if not s:
        return None
    t = s.strip().replace("Z", "+00:00")
    if "." in t:                      # 소수부 7자리+(Falco 나노초)면 6자리로 절단
        head, _, tail = t.partition(".")
        frac = ""
        tzpart = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                tzpart = tail[i:]
                break
        frac = frac[:6]
        t = f"{head}.{frac}{tzpart}" if frac else head + tzpart
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def audit_ts(ev: dict) -> Optional[float]:
    """k3s 감사 이벤트의 시각(requestReceivedTimestamp 우선, 없으면 stageTimestamp)."""
    return parse_rfc3339(ev.get("requestReceivedTimestamp") or ev.get("stageTimestamp") or "")


def falco_ts(ev: dict) -> Optional[float]:
    """Falco 이벤트의 시각(time)."""
    return parse_rfc3339(ev.get("time", ""))


__all__ = ["parse_rfc3339", "audit_ts", "falco_ts"]
