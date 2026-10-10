"""③ 검증 엔진 — pre/post 리플레이 + 상태검증 + 판정.

pre 실패면 post 건너뛰고 상태검증으로. 판정 enum: BLOCKED / FAKE_PATCH / INCONCLUSIVE.
재생은 VM A에 위임(replay_request), 상태검증 쿼리는 플래그 정의(god-view)에서 생성.
판정 우선순위: success 지표 → 정규화 해시 보조 → 상태검증 안전망.
(구현 예정)
"""
