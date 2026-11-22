"""설정 로더 — config.yaml 을 읽어 타입 검증된 객체로.

config.example.yaml 을 config.yaml 로 복사해 값을 채운다. config.yaml 은 .gitignore 됨
(DGX 주소·IP·토큰 등 민감정보). 탐색 순서:
  1) load_config(path) 인자
  2) 환경변수 CAPSTONE_CONFIG
  3) 저장소 루트의 config.yaml
pydantic 검증 — 오타·누락은 실행 전에 바로 터지게(실험 중 조용한 실패 방지).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


# ───────────────────────── 섹션 모델 ─────────────────────────
class DgxConfig(BaseModel):
    attacker_host: str                 # 공격 모델 서빙 GPU 서버 (부하 분산 위해 역할별 분리)
    defender_host: str                 # 방어 모델 서빙 GPU 서버
    port: int = 11434                  # Ollama 기본 포트(두 서버 공통)
    attacker_model: str                # 탈옥 모델(공격자)
    defender_model: str                # 일반 모델(방어자)
    temperature: float = 0.0           # 재현성 위해 0 고정
    # 단일 LLM 호출 HTTP 타임아웃(초). None/0 이면 턴 예산(experiment.time_limit_sec)을 그대로 씀
    # — 느린 로컬 모델·콜드스타트(첫 호출 모델 로딩)가 기본 120초를 넘겨 ReadTimeout 나던 걸 방지.
    request_timeout_sec: Optional[float] = None
    # LLM 생성 토큰 상한. None=무제한. 로컬 모델이 장황해 호출이 느리면 1024~2048로 제한해 단축.
    max_tokens: Optional[int] = None

    # OpenAI 호환 엔드포인트 베이스(OllamaClient 가 /chat/completions·/models 를 붙임).
    @property
    def attacker_base_url(self) -> str:
        return f"http://{self.attacker_host}:{self.port}/v1"

    @property
    def defender_base_url(self) -> str:
        return f"http://{self.defender_host}:{self.port}/v1"


class NetworkConfig(BaseModel):
    attacker_url: str                  # VM A 공격 하네스
    defender_url: str                  # VM B 방어 하네스
    shared_token: str = "CHANGE_ME"    # 관리망 통신용 공유 토큰
    # [Wave2] 공격 하네스 재시작용 ssh 대상(예: "vm-a@192.168.16.129" 또는 ssh config alias).
    # baseline.reset_to_clean() 가 매 라운드 reset 시 ATTEMPTS/closure 등 '프로세스 메모리'에 남은
    # 라운드 간 지식을 wipe 하기 위해 ssh 로 `sudo systemctl restart attack-harness` 실행한다.
    # Neo4j 는 안 건드림(KG 영구 지식 보존). Asset 노드는 (episode, name) 키라 새 episode 는
    # 자연 분리됨. None/빈문자열이면 재시작 skip(best-effort) — 공진화는 돌긴 돌되 라운드 간
    # 공격자 '실패 기억'이 쌓여 재탐색이 위축될 수 있음(수동 systemctl restart 로 대체 가능).
    # 전제: VM C → VM A 가 ssh 키 기반 로그인(BatchMode) + sudo NOPASSWD 로 systemctl 가능.
    attacker_ssh: Optional[str] = None


class TargetConfig(BaseModel):
    attack_endpoint: str               # 공격망에서 본 대상(발판용)
    kubeconfig: str                    # VM C god-view 조회용
    # 타깃 구성도(대시보드)에 열거할 네임스페이스. 미지정이면 현 corp 시나리오 기본 5종만
    # 깔끔하게 표시. 명시적으로 빈 목록([])을 주면 클러스터에서 자동 탐색(인프라·구시나리오 포함).
    topo_namespaces: list[str] = Field(
        default_factory=lambda: ["corp-ext", "corp-dmz", "corp-internal", "corp-crown", "corp-defense"])


class AttackConfig(BaseModel):
    """공격자 실행 위치 설정 — '웹 계층 침해' 발판을 클러스터 내부 파드로 구현.

    exec_mode=False(기본): VM A 로컬 subprocess 실행(개발·테스트·flat 외부 공격).
    exec_mode=True: 모든 공격 명령을 frontend ns 발판 파드 안에서 kubectl exec 로 '투명하게'
      실행 → 공격자가 .svc.cluster.local·ClusterIP·k8s API 로 내부 서비스에 도달(킬체인 ①③④).
      LLM 은 이 래핑을 모른 채 평범한 셸 명령을 치고, 하네스가 파드 안에서 돌린다.
    """
    exec_mode: bool = False
    exec_kubeconfig: str = ""                       # frontend exec 전용 kubeconfig 경로(VM A)
    exec_namespace: str = "frontend"                # 발판 파드 네임스페이스
    exec_pod: str = "deploy/attacker-foothold"      # kubectl exec 대상(deploy/… 또는 파드 이름)
    # ── 병렬 워커(ARTEX식) 설정 ──
    # mode="single"(기본): 단일 ReAct 루프. mode="parallel": 플래너(정렬 모델)+워커 N(탈옥).
    mode: str = "single"                            # single | parallel
    n_workers: int = 2                              # 병렬 워커 수(탈옥 모델 1개 공유 → 2~3 권장)
    intent_budget_sec: float = 120.0               # 의도 하나당 ReAct 시간 예산
    intent_max_steps: int = 20                     # 의도 하나당 최대 스텝
    max_waves: int = 6                              # 라운드당 플래너 웨이브 상한
    graph_backend: str = "memory"                   # memory | neo4j (탐색 그래프 저장소)


class VmwareConfig(BaseModel):
    method: str = "govc"               # govc | pyvmomi | vmrun(Workstation SSH) | agent(호스트 에이전트)
    vcenter_or_esxi: str = "HOST"      # govc 전용(GOVC_URL)
    target_vm_name: str = "VM-B-target"
    baseline_snapshot: str = "clean-baseline"
    # ── vmrun(VMware Workstation) 전용 (method="vmrun") ──
    vmx_path: str = ""                 # 호스트의 VM B .vmx 경로
    ssh_target: str = ""               # VM C→호스트 SSH 대상(user@host); 비우면 로컬 vmrun
    vmrun_path: str = "vmrun"          # 호스트 vmrun 실행 경로(PATH에 없으면 전체 경로)
    ssh_opts: str = ""                 # 추가 ssh 옵션(공백 구분, 예: "-i /home/vmc/.ssh/id_host")
    # ── 호스트 스냅샷 에이전트 (method="agent") ──
    # SSH로는 vmrun이 VM을 '재개(start)'하지 못함(데스크톱 세션 필요) → 호스트 데스크톱
    # 세션에서 돌리는 에이전트에 HTTP로 스냅샷/재개를 위임. VM C는 이 URL만 호출한다.
    snapshot_agent_url: str = ""       # 예: http://192.168.16.1:8010


class ExperimentConfig(BaseModel):
    time_limit_sec: int = 300          # 턴당 제한 시간 T (공수 공통)
    max_rounds: int = 20               # 회차당 최대 라운드
    episodes: int = 50                 # 반복 회차 수(통계용)
    n_consecutive_defense: int = 3     # N라운드 연속 방어 성공 시 종료
    # ── 목표 설정: 두 모드, 분리해서 각각 사용(CLI 로 덮어쓰기 가능) ──
    #   free : 목표 문구를 사람이 자유 입력(objective) → 크라운 채점 없음(탐색·데모용).
    #   asset: 크라운 자산을 골라(target_assets) god-view 가 자산별로 채점. 목표 문구는 선택 자산에서 자동 생성.
    objective_mode: str = "asset"                           # free | asset
    objective: str = ""                                     # free 모드 전용: 공격자에게 줄 자유 목표 문구
    target_assets: list[str] = Field(default_factory=list)  # asset 모드 전용: 크라운 objective_id 목록(비면 전체)
    crown_sync_grace_sec: float = 5.0  # 공격 턴 직후 크라운 게이트 읽기 전 유예 — vmc-sync-dblog(kubectl logs -f) 스트리밍 지연 흡수
    crown_skew_pad_sec: float = 3.0    # 크라운 창 since 경계 스큐 패드 — VM-B(postgres 로그)↔VM-C 클럭 오차 흡수


class FlagsConfig(BaseModel):
    format: str = "FLAG{...}"          # 값 기반 플래그 형식(값·위치는 비공개)


class ObservabilityConfig(BaseModel):
    # VM C가 god-view로 직접 읽는 로그 경로(관리망으로 마운트/동기 전제).
    audit_log_path: str = "/var/lib/rancher/k3s/server/logs/audit.log"
    falco_log_path: str = "/var/log/falco/events.txt"   # Falco file_output 설정 필요
    # 방어 B층 — corp 서비스 로그(source → 경로). `kubectl logs --timestamps` 를 파일로 수집 전제.
    # 예: {"postgres": "/var/log/corp/postgres.log", "samba": "...", "waf": "..."}. 비면 미수집.
    service_log_paths: dict = Field(default_factory=dict)
    # [Phase A] 취약 서비스 파드 stdout(JSON 앱 감사 로그) 동기 파일 — AppLogSource 가 읽음.
    # vmc-sync-applog.sh 가 kubectl logs 로 생성(catalog/order/admin).
    app_log_path: str = "/var/log/capstone/app-requests.log"
    # [B] 직접 DB 접속 크라운 — postgres statement 로그(log_statement=all). DbLogSource 가 읽음.
    # vmc-sync-dblog.sh 가 kubectl logs 로 생성(database/postgres). 앱을 안 거치는 ④ 경로 커버.
    db_log_path: str = "/var/log/capstone/db-statements.log"
    # DB 크라운 actor 스코핑(선택): 이 role 로 접속한 쿼리만 크라운으로 센다(유출 크레덴셜 전용 role).
    # ShopFlow 처럼 앱이 민감 테이블을 상시 조회하는 환경에서 거짓 크라운 방지. 켤 땐 postgres
    # log_line_prefix 에 '%u@%d' 필요. 빈 목록이면 스코핑 없이 쿼리 패턴만(VulHub 단독 등).
    attacker_db_roles: list[str] = Field(default_factory=list)


# ───────────────────────── 루트 ─────────────────────────
class Neo4jConfig(BaseModel):
    """병렬 워커 탐색 그래프 영속화용 Neo4j(attack.graph_backend=neo4j일 때만).

    VM-A 로컬 Neo4j 권장(확정 배포). database는 Community면 보통 'neo4j' 하나뿐이라 생략 가능.
    """
    uri: str = "bolt://127.0.0.1:7687"
    user: str = "neo4j"
    password: str = ""
    database: Optional[str] = None


class RefinerConfig(BaseModel):
    """하네스² 자동개량 메타층 설정(독립 프로세스, ablation on/off).

    편집자(제안 생성)는 정렬 모델 — 서빙 여유 있는 '두 번째 엔드포인트'에 태운다
    (editor_host 비우면 dgx.defender_host 재사용). 시험실행 피험자는 탈옥 모델 동일본으로,
    유일 탈옥 엔드포인트(dgx.attacker_*)를 에피소드 경계 시간분리로 쓴다 — 여기선 주소를
    새로 두지 않는다. 탈옥 희소 → 상위 probe_top_k 만 실측.
    """
    enabled: bool = False                          # 켜야 메타 프로세스가 개량 수행(ablation 축)
    editor_host: str = ""                          # 정렬 편집자 서빙 주소(비면 defender_host 재사용)
    editor_model: str = ""                         # 편집자 모델(비면 defender_model 재사용)
    n_candidates: int = 4                          # 편집자가 낼 수정안 수
    probe_top_k: int = 2                           # 그중 탈옥으로 실측할 상위 수(탈옥 희소 → 작게)
    probe_basis: str = "clean"                     # clean(베이스라인·통제안정) | patched(현 방어돌파)
    min_gain: float = 0.02                         # 기준선 대비 이만큼 넘어야 승급(확률노이즈 거름)
    cadence: str = "episode"                        # episode | round (개량 주기)


class Config(BaseModel):
    dgx: DgxConfig
    network: NetworkConfig
    target: TargetConfig
    vmware: VmwareConfig = Field(default_factory=VmwareConfig)
    experiment: ExperimentConfig = Field(default_factory=ExperimentConfig)
    flags: FlagsConfig = Field(default_factory=FlagsConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    refiner: RefinerConfig = Field(default_factory=RefinerConfig)


# ───────────────────────── 로더 ─────────────────────────
def _repo_root() -> Path:
    # common/config.py → 저장소 루트는 한 단계 위.
    return Path(__file__).resolve().parent.parent


def find_config(path: Optional[str | os.PathLike] = None) -> Path:
    """설정 파일 경로 결정(위 탐색 순서). 못 찾으면 FileNotFoundError."""
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    env = os.environ.get("CAPSTONE_CONFIG")
    if env:
        candidates.append(Path(env))
    candidates.append(_repo_root() / "config.yaml")

    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(
        "config.yaml 을 찾지 못함. config.example.yaml 을 복사해 만들거나 "
        "CAPSTONE_CONFIG 로 경로를 지정하세요. 찾아본 곳: "
        + ", ".join(str(c) for c in candidates)
    )


def load_config(path: Optional[str | os.PathLike] = None) -> Config:
    """config.yaml 을 읽어 검증된 Config 로 반환."""
    cfg_path = find_config(path)
    with open(cfg_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return Config.model_validate(raw)


__all__ = [
    "DgxConfig", "NetworkConfig", "TargetConfig", "AttackConfig", "VmwareConfig",
    "ExperimentConfig", "FlagsConfig", "ObservabilityConfig", "Neo4jConfig",
    "RefinerConfig", "Config", "find_config", "load_config",
]
