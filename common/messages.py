"""공통 인터페이스 — 메시지 10종 스키마 (VM A/B/C HTTP 통신).

전송: HTTP(FastAPI). VM C = 중심 클라이언트(요청 주도), VM A·B = 서버(대기).
공통 필드: type + msg_id + episode + round + timestamp + payload (응답엔 status).
인증: 관리망 격리라 공유 토큰 정도로 가볍게.

========================= 메시지 10종 =========================
  attack_turn_start    C→A  공격 턴 시작
                            payload: time_limit_sec, foothold(첫 라운드만), episode, round
  attack_turn_result   A→C  공격 결과 + 리플레이 대본
                            payload: end_reason(flag|timeout|deadend), flags_obtained[],
                                     replay_script, attack_summary, elapsed_sec
  defense_turn_start   C→B  방어 턴 시작
                            payload: time_limit_sec
  defense_turn_result  B→C  방어 결과
                            payload: patch_applied, end_reason, detected[], patch_set[],
                                     healthcheck_passed, elapsed_sec
  replay_request       C→A  리플레이 재생 요청 (검증용)
                            payload: replay_script, phase(pre|post), target
  replay_result        A→C  재생 결과
                            payload: phase, steps_result[], overall_success, flags_reached[]
  state_query          C→B  상태 검증 쿼리 (②보강)
                            payload: checks[] (check_id, query)
  state_query_result   B→C  상태 응답 (사실만, 판정은 VM C)
                            payload: results[] (check_id, vulnerable)
  health_check         C→B  가용성 확인
                            payload: service → 응답 {healthy, response_time_ms}
  agent_status         A/B→C 하트비트·에러
                            payload: agent, state(idle|running|error), error
==============================================================

정보 비대칭 (스키마에 박힘):
- 공격 보고(A→C)는 상세 OK — 심판이라 god-view 유출 아님
- 방어 턴 시작(C→B)은 공격 정보 0 — 방어자는 스스로 관측
- state_query_result는 vulnerable 사실만 — 판정은 VM C

리플레이 재생은 VM A가 수행(execute_action 로직 보유), VM C는 스냅샷만 맞추고 요청만.
검증의 주관·판정·스냅샷·시퀀스는 VM C(verifier), VM A/B 모드는 그 실행 손발.
"""

# TODO: pydantic BaseModel 로 각 메시지 타입 정의 (구현 예정)
#   - 공통 Envelope(type, msg_id, episode, round, timestamp, payload, status)
#   - 타입별 payload 모델 10종
#   - 직렬화/역직렬화 헬퍼
