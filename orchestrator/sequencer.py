"""① 턴 시퀀서 — 0~8단계 루프 제어 (오케스트레이터의 지휘자).

검증 엔진·채점기·클라이언트·스냅샷을 조립해 한 회차를 돌린다. 순수 제어 로직이라
fake 이음새로 회차 전체를 테스트할 수 있다(실제 VM/네트워크 불필요).

라운드 0~8:
  0 회차 init: VM B를 clean 베이스라인으로 revert
  1 공격 턴 (C→A): 탈옥 LLM ReAct → 결과 + 리플레이 대본
  ★ 게이팅: 2·3·4~5는 공격이 크라운(중요자산)을 반출한 라운드에서만 실행. 미반출이면 전부 생략하고
    바로 다음 라운드로 간다(공격 히스토리는 하네스가 라운드 간 자동 이월 → 이어서 더 깊이 판다).
    근거: 검증은 '성공한 공격이 막혔는지'를 재생으로 판정하므로, 성공한 공격이 없으면 pre 재생이
    목표에 도달 못 해 판정이 구조적으로 INCONCLUSIVE — 스냅샷·재생 비용만 들고 신호가 없다.
  2 공격후 스냅샷 저장 (검증의 pre 상태)
  3 방어 턴 (C→B): 공격정보 0 → 관측·트리아지·패치
  4~5 검증: pre/post 재생 + 상태검증 → 판정 (스냅샷 전환은 검증엔진 내부)
  5.5 god-view 정답 기록 (로그·값대조로 '실제 무슨 공격'을 TruthLog에) — 생략 라운드도 기록
  6 채점: 정답 대조 → 라운드 기록(JSONL)
  7 종료조건 검사 → 다음 라운드
  8 회차 종료: 요약 + 라운드 임시 스냅샷 정리

복구/안전:
- 타임아웃은 장애 아님(하네스가 end_reason=timeout로 정상 종료). 요청 타임아웃은 백스톱.
- 크래시(예외/연결 끊김)는 그 턴 1회 재시도 → 또 실패면 회차 중단(ABORTED).
  라운드 중간 상태는 오염되므로 다음 회차 init의 clean revert로 리셋.
- 킬스위치 훅: 범위 이탈·폭주 감지 콜백이 True면 즉시 중단(KILLED).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from common.messages import (
    AttackEndReason, AttackTurnResult, AttackTurnStart, DefenseEndReason,
    DefenseTurnResult, DefenseTurnStart, Foothold,
)

from .attack_stream import AttackJournalStreamer
from .clients import AttackerClient, DefenderClient
from .events import EventSink, record_round_events
from .flags import FlagRegistry
from .logs import LogSource
from .round_detail import write_round_detail
from .objectives import ObjectiveRegistry, DEFAULT_ASSET_GOAL
from .scorer import EpisodeSummary, Scorer
from .snapshot import SnapshotManager
from .truth_log import TruthEntry, TruthEvent, TruthLog
from .verifier import VerificationEngine, VerificationResult, Verdict

from common.off_kg import (
    AttackerClaim, GodView, Hint, OffKgSink, Procedure, ReplayRef,
    RecordId, Target, Trigger, build_off_kg_record, procstep_from_replay,
)


class EpisodeEndReason(str, Enum):
    CONSECUTIVE_DEFENSE = "consecutive_defense"  # N라운드 연속 방어 성공 → 안정화
    MAX_ROUNDS = "max_rounds"                    # 최대 라운드 도달
    ABORTED = "aborted"                          # 크래시 복구 실패 → 중단
    KILLED = "killed"                            # 킬스위치 발동


@dataclass
class RunParams:
    """실험 파라미터(파일 로더와 분리 — 시퀀서는 이 값만 알면 됨)."""
    episodes: int = 1
    max_rounds: int = 20
    n_consecutive_defense: int = 3
    time_limit_sec: int = 300
    max_tokens: Optional[int] = None             # 공격 생성 토큰 상한(실험 파라미터; None=하네스 config 기본)
    baseline_snapshot: str = "clean-baseline"
    attack_endpoint: Optional[str] = None        # 첫 라운드 발판
    goal: str = DEFAULT_ASSET_GOAL               # 공격자에게 줄 '무엇을'(asset 전체 선택 시 기본)
    ready_timeout_sec: float = 180.0             # revert 후 VM B 응답 대기 상한(일시정지·재개 지연 흡수)
    ready_interval_sec: float = 3.0              # ready 폴링 간격
    crown_sync_grace_sec: float = 0.0            # 공격 턴 직후 크라운 게이트 읽기 전 유예(초) — 0=즉시(테스트 기본).
    #   vmc-sync-dblog(kubectl logs -f) 스트리밍 지연이 막판 크라운 줄을 VM-C 파일에 밀어넣을 시간(production=config 주입).
    crown_skew_pad_sec: float = 0.0              # 크라운 창 since 경계 스큐 패드(초) — VM-B↔VM-C 클럭 오차 흡수.
    skip_revert: bool = False                    # True면 회차 init revert 생략(라이브 클러스터 그대로).
    #   vmrun 라이브 스냅샷 revert 가 k3s exec 경로를 느리게(재시도 백오프) 만드는 인프라 이슈 회피용 —
    #   라이브 클러스터가 이미 베이스라인(취약) 상태일 때 단발 포획·디버그에 쓴다. 다중 회차 리셋은 불가.
    force_crown: bool = False                     # (스모크 전용) 게이트 강제 — god-view 크라운 미검출이어도
    #   방어 턴→검증→패치 누적 배관을 매 라운드 돌린다. 크라운 관측 통로(DB 감사로그)가 아직 안 깔렸을 때
    #   루프 기계가 end-to-end 도는지 확인하는 용도. 진짜 공진화 아님(가짜 게이트) — 통로 live 되면 끈다.
    run_id: str = ""                              # 실험 식별자(off-KG 저널 레코드에 기록)
    attacker_model: str = ""                      # 공격 모델명(off-KG 저널 레코드에 기록)


@dataclass
class RoundOutcome:
    round: int
    verdict: Verdict
    defense_succeeded: bool
    flags_reached: list[str] = field(default_factory=list)
    flag_found: bool = False          # 플래그리스: 이 라운드에 크라운(중요자산)이 반출됐나 — 심판이
    #                                   god-view 접근기록으로 판단(공격자 자기보고 아님). 게이팅 키:
    #                                   True 면 방어·검증이 실제로 돌았다. (필드명은 대시보드/채점기 호환 유지)


class RoundAbort(Exception):
    """턴 재시도까지 실패 → 라운드/회차 중단 신호."""


class TurnSequencer:
    def __init__(self, *, attacker: AttackerClient, defender: DefenderClient,
                 snapshots: SnapshotManager, verifier: VerificationEngine,
                 logs: LogSource, registry: FlagRegistry,
                 objectives: ObjectiveRegistry, truth: TruthLog,
                 params: RunParams, sink: Optional[Callable[[dict], None]] = None,
                 off_kg_sink: Optional[OffKgSink] = None,
                 progress: Optional[Callable[[dict], None]] = None,
                 events: Optional[EventSink] = None, detail_dir: Optional[str] = None,
                 kill_switch: Optional[Callable[[], bool]] = None,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        self.attacker = attacker
        self.defender = defender
        self.snapshots = snapshots
        self.verifier = verifier
        self.logs = logs
        self.registry = registry
        self.objectives = objectives
        self.truth = truth
        self.params = params
        self.sink = sink
        self.off_kg_sink = off_kg_sink    # off-KG 포획 저널 sink(off_kg.jsonl) — 없으면 무시
        self.progress = progress          # 실시간 진행 sink(/api/status 소스) — 없으면 무시
        self.events = events              # 행위 이벤트 sink(events.jsonl) — 없으면 무시
        self.detail_dir = detail_dir      # 라운드 상세 출력 디렉토리(round_detail/) — 없으면 무시
        self.kill_switch = kill_switch
        self._sleep = sleeper              # 테스트에서 주입 가능(실제론 time.sleep)

    # ───────────── public ─────────────
    def run_experiment(self) -> list[EpisodeSummary]:
        """회차 여러 번 반복(통계용). 각 회차는 독립(baseline에서 시작)."""
        self._emit(status="running", total_episodes=self.params.episodes,
                   max_rounds=self.params.max_rounds,
                   time_limit_sec=self.params.time_limit_sec)
        summaries = [self.run_episode(e) for e in range(1, self.params.episodes + 1)]
        self._emit(status="done", phase=5, active=None, turn_started=None)
        return summaries

    def _log(self, msg: str) -> None:
        """진행 로그 — 벽시계 시각(HH:MM:SS) 프리픽스. 장시간 실행 가시성용."""
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    def _emit(self, **fields) -> None:
        """실시간 진행 sink 로 현재 상태 조각을 흘린다(없으면 무시). 모니터링 보조."""
        if self.progress is not None:
            try:
                self.progress(fields)
            except Exception:              # noqa: BLE001 — 모니터링 실패가 실험을 멈추면 안 됨
                pass

    def run_episode(self, episode: int) -> EpisodeSummary:
        self._emit(status="running", episode=episode, round=0, phase=0, active=None,
                   turn_started=None, last_verdict=None,
                   flags_reached=[], crowns_reached=[], crowns_by_channel={}, goals_reached=[])
        # 0. init — clean 베이스라인으로 리셋(이전 회차 오염 제거)
        if self.params.skip_revert:
            # vmrun revert 가 k3s exec 경로를 느리게 만드는 인프라 이슈 회피 — 라이브(이미 베이스라인
            # 상태인) 클러스터를 그대로 공격한다. 단발 포획·디버그용(다중 회차 리셋 안 됨).
            self._log(f"[ep{episode}] 0. revert 생략(--no-revert) — 라이브 클러스터 그대로 사용")
        else:
            self._log(f"[ep{episode}] 0. 베이스라인 revert → {self.params.baseline_snapshot} …")
            _t = time.time()
            self.snapshots.revert_to(self.params.baseline_snapshot)
            self._log(f"[ep{episode}]    → revert 완료 ({time.time() - _t:.0f}s)")
        scorer = Scorer(self.truth, episode, self.objectives, sink=self.sink)
        created_snaps: list[str] = []
        consecutive = 0
        attacker_broke_through = False   # 이 회차에서 공격자가 한 번이라도 크라운을 반출했나(게이팅 사다리 기준)
        end_reason = EpisodeEndReason.MAX_ROUNDS

        # 0.5 revert 후 VM B 재개/기동 대기. 라이브 스냅샷 revert는 VM을 잠깐 일시정지로
        #     두거나 재개가 늦을 수 있어, 방어 하네스가 /status로 응답할 때까지 폴링한다.
        #     상한 내 안 뜨면 이 회차는 못 돌리므로 크래시 대신 ABORTED로 깔끔히 종료.
        self._log(f"[ep{episode}] 0.5 VM B 준비 대기(revert 후 재개)…")
        _t = time.time()
        if not self._ready():
            self._log(f"[ep{episode}] ✗ VM B 준비 안 됨(상한 초과, {time.time() - _t:.0f}s) → ABORTED")
            return scorer.summary(end_reason=EpisodeEndReason.ABORTED.value)
        self._log(f"[ep{episode}] ✓ VM B 준비됨({time.time() - _t:.0f}s). 라운드 시작")

        try:
            for rnd in range(1, self.params.max_rounds + 1):
                if self.kill_switch is not None and self.kill_switch():
                    end_reason = EpisodeEndReason.KILLED
                    break
                try:
                    outcome = self._run_round(episode, rnd, scorer, created_snaps)
                except RoundAbort as e:
                    self._log(f"[ep{episode} R{rnd}] ✗ 라운드 중단: {e} → 회차 ABORTED")
                    end_reason = EpisodeEndReason.ABORTED
                    break

                # 게이팅 사다리: 크라운 반출(방어 개입) 라운드는 검증 판정으로 증감,
                # 크라운 미반출 라운드는 '과거에 한 번이라도 뚫린 적 있으면' 방어가 막아낸 것으로 +1
                # (아직 한 번도 못 뚫었으면 공격자 탐색중 → 카운터 불변).
                if outcome.flag_found:
                    attacker_broke_through = True
                    consecutive = consecutive + 1 if outcome.defense_succeeded else 0
                elif attacker_broke_through:
                    consecutive += 1
                if consecutive >= self.params.n_consecutive_defense:
                    end_reason = EpisodeEndReason.CONSECUTIVE_DEFENSE
                    break
        finally:
            for name in created_snaps:        # 8. 라운드 임시 스냅샷 정리
                try:
                    self.snapshots.delete(name)
                except Exception:             # noqa: BLE001 — 정리는 best-effort
                    pass

        return scorer.summary(end_reason=end_reason.value)

    # ───────────── revert 후 대상 준비 대기 ─────────────
    def _ready(self) -> bool:
        """VM B(방어 하네스)가 /status로 응답할 때까지 폴링. 상한 초과면 False(→ 회차 중단).

        revert→start 후 Workstation이 VM을 즉시 재개 못 하거나(일시정지) 서버 기동이 늦을 수
        있다. 응답을 확인하고 턴을 시작해야 'VM 안 깨어남'으로 공격·방어 턴이 헛도는 걸 막는다.
        """
        deadline = time.time() + self.params.ready_timeout_sec
        while True:
            try:
                self.defender.status()
                return True
            except Exception:              # noqa: BLE001 — 아직 미기동(연결거부·타임아웃 등)
                if time.time() >= deadline:
                    return False
                self._sleep(self.params.ready_interval_sec)

    # ───────────── 라운드 ─────────────
    def _run_round(self, episode: int, rnd: int, scorer: Scorer,
                   created_snaps: list[str]) -> RoundOutcome:
        t0 = time.time()

        # 1. 공격 턴 (발판=고정 진입점, 매 라운드 제공 — 대상은 매 라운드 baseline으로 revert돼
        #    엔드포인트가 불변. 라운드 간 기억만으로 공격자가 진입점을 잊는 문제를 막음)
        foothold = (Foothold(attack_endpoint=self.params.attack_endpoint)
                    if self.params.attack_endpoint else None)
        start = AttackTurnStart(time_limit_sec=self.params.time_limit_sec,
                                goal=self.params.goal,
                                foothold=foothold, max_tokens=self.params.max_tokens)
        self._emit(round=rnd, phase=1, active="attacker", turn_started=time.time())
        self._log(f"[ep{episode} R{rnd}] 1. 공격 턴…")
        _t = time.time()
        # 공격 턴 중 공격자 저널을 실시간 미러(attack_journal.jsonl) — 대시보드 '공격 저널' 스트리밍.
        _out_root = str(Path(self.detail_dir).parent) if self.detail_dir else None
        with AttackJournalStreamer(self.attacker, _out_root, episode=episode, round=rnd, log=self._log):
            attack: AttackTurnResult = self._call(
                lambda: self.attacker.attack_turn(start, episode=episode, round=rnd), "attack_turn")
        self._log(f"[ep{episode} R{rnd}]    → 공격 종료={attack.end_reason.value} "
                  f"대본={len(attack.replay_script.steps) if attack.replay_script else 0}스텝 "
                  f"({time.time() - _t:.0f}s)")

        # ── 게이팅: 공격이 크라운(최종 침해)에 도달했을 때만 방어+검증(값비싼 재생)을 돌린다.
        #    공격자 보고가 아니라 god-view 접근기록(공격 창의 crowns)으로 판단 — 판정과 동일 기준.
        #    미도달이면 2·3·4~5를 전부 생략하고 다음 라운드로(히스토리는 하네스가 자동 이월).
        #    크라운 줄은 공격 턴 막판에 떨어지는데 vmc-sync-dblog(kubectl logs -f) 스트리밍이 수 초 지연 →
        #    읽기 전 유예를 두고(막판 줄 도착 대기) 창 since 경계에 스큐 패드를 더해, 동기화 경합·클럭 오차로
        #    실제 반출된 크라운을 놓쳐 방어를 건너뛰는 일을 막는다(관측 통로는 정상 — 경합만 보정).
        if self.params.crown_sync_grace_sec > 0:
            time.sleep(self.params.crown_sync_grace_sec)
        attack_crowns = self.logs.crowns_in_window(
            since_ts=_t - self.params.crown_skew_pad_sec, until_ts=time.time())
        flag_found = bool(self.objectives.reached_goals({"crown": {"asset": attack_crowns}}))

        # (스모크 전용) force_crown: 크라운 통로가 아직 안 깔린 상태에서도 방어+검증 배관을 돌려본다.
        if self.params.force_crown and not flag_found:
            self._log(f"[ep{episode} R{rnd}] ⚠ force-crown(스모크): 크라운 미검출이나 게이트 강제 "
                      f"→ 방어+검증 실행(진짜 공진화 아님)")
            flag_found = True

        if flag_found:
            # 2. 방어 턴 (공격정보 0). A2: 공격후 VM 스냅샷 불필요 — verify 가 '패치된 라이브'에
            #    공격 대본을 재생(POST-only)할 뿐 리셋하지 않으므로 stun 유발 스냅샷이 없다.
            self._emit(phase=2, active="defender", turn_started=time.time())
            self._log(f"[ep{episode} R{rnd}] 2. 방어 턴(관측→추론→패치)…")
            _t = time.time()
            defense = self._call(
                lambda: self.defender.defense_turn(
                    DefenseTurnStart(time_limit_sec=self.params.time_limit_sec),
                    episode=episode, round=rnd), "defense_turn")
            self._log(f"[ep{episode} R{rnd}]    → 방어 종료={defense.end_reason.value} "
                      f"패치={defense.patch_applied} 탐지={len(defense.detected)}개 "
                      f"health={defense.healthcheck_passed} ({time.time() - _t:.0f}s)")

            # 3. 검증 (대본 있을 때만). POST-only: 검증엔진이 '패치된 라이브'에 공격 대본을 재생 →
            #    도달 성공=FAKE_PATCH / 실패=BLOCKED. 리셋 안 함 → 패치가 라이브에 남아 다음 라운드가
            #    누적된 방어를 상대한다(공진화). 회차 경계 리셋만 시퀀서 init 이 담당.
            script = attack.replay_script
            if script is not None and script.steps:
                self._emit(phase=3, active=None, turn_started=time.time())
                self._log(f"[ep{episode} R{rnd}] 3. 검증(POST 재생: 패치된 라이브에 공격 재생)…")
                _t = time.time()
                verification = self._call(
                    lambda: self.verifier.verify(
                        script, episode=episode, round=rnd,
                        target=self.params.attack_endpoint), "verify")
                self._log(f"[ep{episode} R{rnd}]    → 판정={verification.verdict.value} ({time.time() - _t:.0f}s)")
            else:
                verification = VerificationResult(
                    verdict=Verdict.INCONCLUSIVE, method="none",
                    detail="크라운 도달했으나 재생 대본이 비어 검증 불가")
                self._log(f"[ep{episode} R{rnd}] 3. 검증 생략(대본 없음) → 판정={verification.verdict.value}")
        else:
            # 크라운 미반출 → 방어·검증·공격후 스냅샷 전부 생략. 합성 결과로 라운드 기록만 남긴다.
            defense = DefenseTurnResult(
                patch_applied=False, end_reason=DefenseEndReason.SKIPPED,
                patch_note="크라운 미반출 → 방어 미개입(게이팅)")
            verification = VerificationResult(
                verdict=Verdict.INCONCLUSIVE, method="skipped",
                detail="크라운 미반출 → 방어·검증 생략, 히스토리 이월 후 다음 라운드")
            self._log(f"[ep{episode} R{rnd}] 2~3. 방어·검증 생략"
                      f"(크라운 미반출) → 히스토리 이월, 다음 라운드")

        t1 = time.time()

        # 5.5 god-view 정답 기록 → 6. 채점 (생략 라운드도 기록 — 공격 활동/타임라인 보존)
        truth_entry = self._build_truth(episode, rnd, attack, t0=t0, t1=t1)
        self.truth.record(truth_entry)
        self._capture_off_kg(episode, rnd, attack, truth_entry, flag_found)   # off-KG 포획
        scorer.score_round(round=rnd, attack_result=attack,
                           defense_result=defense, verification=verification)
        self._log(f"[ep{episode} R{rnd}] 6. 채점 완료 (라운드 총 {time.time() - t0:.0f}s)")
        all_flags = self.truth.flags_up_to(episode, rnd)
        crowns = sorted(f for f in all_flags if self.objectives.get(f))   # flags 중 크라운 objective
        crown_ch = self.truth.crown_channels_up_to(episode, rnd)          # 어느 통로로 빠졌나(표시)
        self._emit(phase=4, active=None, turn_started=None,
                   last_verdict=verification.verdict.value,
                   flags_reached=sorted(all_flags),
                   crowns_reached=crowns,   # 실시간 크라운(어느 자산이 빠졌나) — 대시보드 소스
                   crowns_by_channel={k: sorted(v) for k, v in crown_ch.items()},
                   goals_reached=sorted({self.objectives.get(f).goal for f in crowns}))

        # 대시보드 계측(보조): 행위 이벤트 스트림 + 라운드 상세 원자료. 생략 라운드도 공격 활동 기록.
        self._record_round(episode, rnd, attack, defense, verification)

        return RoundOutcome(round=rnd, verdict=verification.verdict,
                            defense_succeeded=verification.defense_succeeded(),
                            flags_reached=verification.flags_still_reachable,
                            flag_found=flag_found)

    # ───────────── 대시보드 계측(이벤트·상세) — 보조, 실패해도 라운드 불변 ─────────────
    def _record_round(self, episode: int, rnd: int, attack, defense, verification) -> None:
        try:
            record_round_events(self.events, episode=episode, round=rnd,
                                attack=attack, defense=defense, verification=verification)
        except Exception:                  # noqa: BLE001 — 계측 실패가 실험을 멈추면 안 됨
            pass
        write_round_detail(self.detail_dir, episode, rnd,
                           attack=attack, defense=defense, verification=verification)

    # ───────────── god-view 정답 구축 ─────────────
    def _build_truth(self, episode: int, rnd: int, attack: AttackTurnResult,
                     *, t0: float, t1: float) -> TruthEntry:
        """'실제로 무슨 공격이 일어났나'를 심판 관점으로. 공격자 주장 안 믿고 사실로.

        크라운(최종 침해): 공격자 보고값 대조가 아니라 god-view 접근기록(crowns)으로 직접 판정
          — 민감 자산이 실제로 빠질 때 남는 자백 줄(app·db 통로)을 objectives 조건표로 해석.
        ①②③(상태/로그 기반): god-view 로그에서 관측된 기법 → 플래그 매핑(기존 유지).
        """
        events: dict[tuple[str, Optional[str]], TruthEvent] = {}
        flags: set[str] = set()

        crowns = self.logs.crowns_in_window(since_ts=t0, until_ts=t1)   # 접근기록 자백(판정용 합집합)
        # 통로별 맵(표시 전용) — 판정은 위 합집합이, '어느 통로로 빠졌나'는 이 맵이 담당.
        by_ch = getattr(self.logs, "crowns_by_channel_in_window", None)
        crown_ch = by_ch(since_ts=t0, until_ts=t1) if by_ch else {}
        for oid in self.objectives.reached_objectives({"crown": {"asset": crowns}}):
            spec = self.objectives.get(oid)
            mitre = spec.mitre if spec else "?"
            assets = ({c.expected for c in spec.conditions
                       if c.channel == "crown" and c.field == "asset" and c.operator == "eq"}
                      if spec else set())
            chans = tuple(sorted(ch for ch, a in crown_ch.items() if a & assets))
            events[(mitre, oid)] = TruthEvent(
                technique=mitre, flag_id=oid, detail="crown-exfil", channels=chans)
            flags.add(oid)

        for tech in self.logs.techniques_in_window(since_ts=t0, until_ts=t1):  # ①②③ 로그
            fid = self.registry.flag_for_technique(tech)
            events.setdefault((tech, fid), TruthEvent(
                technique=tech, flag_id=fid, detail="log-observed"))
            if fid:
                flags.add(fid)

        return TruthEntry(episode=episode, round=rnd,
                          events=list(events.values()), flags_reached=sorted(flags))

    # ───────────── off-KG 포획(저널) ─────────────
    def _capture_off_kg(self, episode: int, rnd: int, attack: AttackTurnResult,
                        truth_entry: TruthEntry, crown: bool) -> None:
        """VM A가 표시한 off-KG 침해(KG에 절차 없는 기법으로 달성)에 god-view를 붙여
        off_kg.jsonl 저널에 남긴다. 승격(knowledge/promote.py)은 개발기 별도 단계.

        outcome: 심판이 그 기법을 관측했으면 PROGRESS, 크라운까지면 CROWN, 아니면 UNCONFIRMED.
        """
        if self.off_kg_sink is None:
            return
        findings = getattr(attack, "off_kg_findings", None) or []
        if not findings:
            return
        script = attack.replay_script
        by_sid = {s.step_id: s for s in (script.steps if script else [])}
        techs = truth_entry.techniques()
        channels = sorted({c for e in truth_entry.events for c in e.channels})
        stages = sorted(truth_entry.flags_reached)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ref = ReplayRef(session_id=(script.session_id if script else ""),
                        episode=episode, round=rnd)
        for of in findings:
            steps = [procstep_from_replay(by_sid[sid]) for sid in of.step_ids if sid in by_sid]
            confirmed = bool(of.technique_hint and of.technique_hint in techs)
            gv = GodView(confirmed=confirmed or crown, crown=crown,
                         progress_stages=stages, techniques_observed=sorted(techs),
                         evidence_channels=channels)
            proc_failed = (attack.end_reason == AttackEndReason.DEADEND
                           and not confirmed and not crown)
            rec = build_off_kg_record(
                rec_id=RecordId(run_id=self.params.run_id, episode=episode, round=rnd,
                                intent_id=str(of.finding_id), ts=ts,
                                attacker_model=self.params.attacker_model),
                trigger=Trigger(missing_info=([f"no KG procedure for {of.technique_hint}"]
                                              if of.technique_hint else ["no technique"]),
                                reason=of.summary),
                target=Target(cpe=of.cpe, service_type=of.service_type,
                              endpoint=of.endpoint, preconditions=list(of.preconditions)),
                hint=Hint(technique_id=of.technique_hint or None),
                procedure=Procedure(replay_ref=ref, steps=steps),
                attacker_claim=AttackerClaim(reached_flag=crown, claimed_outcome=of.summary),
                godview=gv, proc_failed=proc_failed)
            try:
                self.off_kg_sink(rec)
            except Exception:  # noqa: BLE001 — 포획 실패가 라운드를 멈추면 안 됨
                pass

    # ───────────── 호출 복구(재시도 1회 → 중단) ─────────────
    def _call(self, fn: Callable[[], object], label: str):
        last: Optional[Exception] = None
        for attempt in (1, 2):
            try:
                return fn()
            except Exception as e:              # noqa: BLE001 — 크래시 감지
                last = e
        raise RoundAbort(f"{label} 재시도 실패: {last}") from last


__all__ = ["EpisodeEndReason", "RunParams", "RoundOutcome", "RoundAbort", "TurnSequencer"]
