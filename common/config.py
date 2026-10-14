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


class TargetConfig(BaseModel):
    attack_endpoint: str               # 공격망에서 본 대상(발판용)
    kubeconfig: str                    # VM C god-view 조회용


class VmwareConfig(BaseModel):
    method: str = "govc"               # govc | pyvmomi
    vcenter_or_esxi: str = "HOST"
    target_vm_name: str = "VM-B-target"
    baseline_snapshot: str = "clean-baseline"


class ExperimentConfig(BaseModel):
    time_limit_sec: int = 300          # 턴당 제한 시간 T (공수 공통)
    max_rounds: int = 20               # 에피소드당 최대 라운드
    episodes: int = 50                 # 반복 에피소드 수(통계용)
    n_consecutive_defense: int = 3     # N라운드 연속 방어 성공 시 종료


class FlagsConfig(BaseModel):
    format: str = "FLAG{...}"          # 값 기반 플래그 형식(값·위치는 비공개)


class ObservabilityConfig(BaseModel):
    # VM C가 god-view로 직접 읽는 로그 경로(관리망으로 마운트/동기 전제).
    audit_log_path: str = "/var/lib/rancher/k3s/server/logs/audit.log"
    falco_log_path: str = "/var/log/falco/events.txt"   # Falco file_output 설정 필요


# ───────────────────────── 루트 ─────────────────────────
class Config(BaseModel):
    dgx: DgxConfig
    network: NetworkConfig
    target: TargetConfig
    vmware: VmwareConfig = Field(default_factory=VmwareConfig)
    experiment: ExperimentConfig = Field(default_factory=ExperimentConfig)
    flags: FlagsConfig = Field(default_factory=FlagsConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)


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
    "DgxConfig", "NetworkConfig", "TargetConfig", "VmwareConfig",
    "ExperimentConfig", "FlagsConfig", "ObservabilityConfig", "Config",
    "find_config", "load_config",
]
