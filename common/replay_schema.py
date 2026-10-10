"""replay_script 스키마 — 검증 불능 예방의 핵심.

공격 하네스(execute_action)가 기록하고, 오케스트레이터(verifier)가 VM A에 재생 위임.
VM C가 이것만 보고 이해 없이 재현 가능해야 한다.

===================== 구조 =====================
replay_script = {
  session_id, round, episode, base_snapshot,
  steps: [ step, ... ]
}

step = {
  "step": 7,
  "command": {
    "tool": "kubectl",
    "args": ["get", "secrets", "-n", "database", "-o", "json"],  # 방안1: 구조화 출력(-o json)
    "payload_ref": "payloads/step7.yaml"   # 큰 페이로드는 파일로 고정 (null 가능)
  },
  "inputs": {                              # ★ 동적값 의존관계 (①예방의 구현)
    "token": {
      "source": "step_output",            # step_output | static | foothold
      "from_step": 5,
      "extract": {"method": "jsonpath", "path": ".data.token"}  # jsonpath 우선(안정성)
    }
  },
  "produces": {                            # 다음 스텝이 참조할 값
    "sa_token": {"extract": {"method": "jsonpath", "path": "..."}}
  },
  "result": {                              # baseline 확보용 (원래 통했나)
    "exit_code": 0,
    "success": true,                       # ← 판정 1순위 지표
    "stdout_hash": "sha256:...",           # 정규화된 stdout 해시 (보조 비교)
    "stdout_excerpt": "...",               # 판정 근거 발췌
    "stdout_full": null                    # 플래그 등 중요 스텝만 채움
  },
  "flag_check": {"flag_id": "flag-2-rbac", "obtained": true},
  "determinism": "depends_on_prior"        # deterministic | depends_on_prior | nondeterministic
}
=================================================

핵심 메커니즘:
- inputs/produces 로 동적값(토큰 등) 의존성 재실행 — 녹음된 만료 토큰 대신
  재생 중 선행 스텝에서 새로 얻은 값 주입.
- determinism 등급은 LLM 아니라 execute_action(코드)이 규칙 기반 자동 판정.
  애매하면 보수적으로 nondeterministic → ②상태검증으로 라우팅.

검증 정밀도 (해시 노이즈 대응):
- 방안1: 명령을 구조화 출력(kubectl -o json / nmap -oJ / psql CSV·JSON)으로 짜게 유도
          → jsonpath로 의미 필드만 추출, 타임스탬프 등 노이즈 필드 무시.
- 정규화: 해시 걸기 전 출력의 변동 요소(타임스탬프·랜덤ID·동적토큰) 마스킹.
- 판정 우선순위: ① success 지표(불린) → ② 정규화 해시 보조 → ③ 상태검증 안전망.
- 해시 대상: 각 스텝 stdout(정규화본)에만. 비교 3벌 = 공격원본(=VM C 복사본)·pre·post.
  ①원본 vs ②pre = 재현 확인, ②pre vs ③post = 방어 판정.
"""

# TODO: pydantic BaseModel 로 ReplayScript / Step / Command / Inputs / Produces / Result 정의
# TODO: determinism 규칙 기반 분류 함수 (classify_determinism)
# TODO: stdout 정규화 함수 (normalize_output) + jsonpath/regex 추출기
