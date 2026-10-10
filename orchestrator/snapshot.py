"""② 스냅샷 매니저 — VMware API(pyvmomi 또는 govc 래핑).

revert_baseline / save / revert / cleanup. 작업 완료 폴링(원자성).
에피소드당 1개(clean 베이스라인) + 라운드당 2개(공격후·패치후 임시).
(구현 예정)
"""
