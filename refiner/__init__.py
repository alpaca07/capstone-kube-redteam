"""하네스² 자동개량 메타층 — 공격 하네스를 '제안·시험실행·합성'으로 자가개량.

구글 Harness²(고정 모델 주위 하네스의 재귀 자기개량) 기법·구조 차용. 모델 가중치는
안 건드리고 겉옷(시스템 프롬프트·도구 안내 등)만 편집해 공격력을 올린다.

설계 확정(2026-11-16):
- 독립 메타 프로세스(라이브 공수 루프와 격리, ablation on/off = 프로세스 기동 여부).
- 편집자(제안 생성)=정렬 모델, 서빙 여유 있는 '두 번째 엔드포인트'에 태운다.
- 시험실행 피험자(실제 공격 수행)=탈옥 모델 동일본. 복제 불가라 유일 탈옥 엔드포인트를
  에피소드 경계(라이브 유휴)에서 시간분리로 빌려 쓴다.
- 탈옥 희소 → 편집자(정렬)가 수정안 N개를 내고 자체 순위로 상위 k만 탈옥으로 실측(fork 가).
- 시험실행 기준 스냅샷=clean 베이스라인(순수 공격력, 통제 안정), 동률만 패치 상태로 가름.
- 개량 주기=에피소드 경계.

이 패키지는 순수 조율 로직 + 이음새(Editor/ProbeRunner/HarnessStore)만 담는다. 실제
정렬-LLM·스냅샷·공격 하네스 호출은 어댑터 층(다음 단계)이 이음새를 구현한다.
"""
from __future__ import annotations

from refiner.models import (
    Component, Harness, HarnessEdit, ProbeScore, RefineResult,
)
from refiner.refiner import refine
from refiner.seams import Editor, ProbeRunner, HarnessStore
from refiner.probe import HarnessProbe

__all__ = [
    "Component", "Harness", "HarnessEdit", "ProbeScore", "RefineResult",
    "refine", "Editor", "ProbeRunner", "HarnessStore", "HarnessProbe",
]
