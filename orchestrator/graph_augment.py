"""god-view 확정 크라운을 공격 추론 그래프에 '발견(finding)' 노드로 주입.

공격 추론 그래프(목표→의도→사실→발견)는 공격자(VM A) 자기보고다 — 공격자가 스스로 finding 으로
결론지어야 발견 노드가 생긴다. 그래서 심판이 god-view(DB·앱 로그 접근기록)로 '실제 반출'을
확정해도, 공격자가 그걸 finding 으로 안 남기면 그래프엔 사실만 쌓이고 발견 노드가 0이다
(고객정보 유출을 해냈는데 발견 노드가 없는 현상의 원인).

여기서 심판이 확정한 크라운을 발견 노드로 그래프에 얹는다 — 출처를 'god-view(judge)'로 분명히
표시해 공격자 자기주장 발견과 구분하고, 그 크라운과 관련된 사실 노드에서 proves(입증) 엣지로 잇는다.
표시 전용 — 판정·채점엔 영향 없음(원본 스냅샷 불변, 사본을 반환).
"""
from __future__ import annotations

from typing import Optional

# 크라운 → 사람이 읽는 라벨(대시보드 crownLabel 과 일치).
_CROWN_LABEL = {
    "crown-pii": "고객정보 유출",
    "crown-secrets": "내부 비밀 유출",
    "crown-ops": "운영 비밀 유출",
    "crown-resource-hijack": "연산 자원 탈취",
    "crown-container-deploy": "악성 컨테이너 배포",
}
# 크라운 → 대표 MITRE(프런트 findingCvss 가 crown_id 로 직접 확정 등급 매칭. technique 는 보조).
_CROWN_MITRE = {
    "crown-pii": "T1213", "crown-secrets": "T1213",
    "crown-resource-hijack": "T1496", "crown-container-deploy": "T1610",
}
# 관련 사실 노드 탐색용 키워드(사실 요약·타깃·증거·전술에서 매칭). 없으면 말단 사실/목표에 연결.
_CROWN_KEYS = {
    "crown-pii": ("pii", "고객", "개인정보", "customer", "personal", "database", "shopflow", "주민", "email", "회원"),
    "crown-secrets": ("secret", "비밀", "credential", "자격", "internal_secret", "corp", "vault", "token", "password", "키"),
    "crown-ops": ("ops", "운영", "operation", "deploy", "pipeline", "ci", "cd"),
    "crown-resource-hijack": ("resource", "자원", "mining", "miner", "cpu", "hijack", "crypto", "xmrig"),
    "crown-container-deploy": ("container", "컨테이너", "deploy", "배포", "pod", "image", "runc", "privileged"),
}
# 크라운 → '확보한 데이터' 표본(표시 전용). 대상 DB 시드(k8s/services/database/11-postgres-initdb.yaml)에
# 실제로 심어둔 반출물의 대표 행 — 심판이 접근기록으로 '실제 반출' 확정한 자산. 채점·truth·refiner 와 무관.
_CROWN_LOOT_SAMPLE = {
    "crown-pii": {
        "table": "customers",
        "exfiltrated_rows": 12,
        "sample": [
            {"name": "김민준", "email": "minjun.kim@example.com", "phone": "010-2345-6781",
             "ssn": "900101-1xxxxxx", "address": "서울특별시 강남구 테헤란로 123", "tier": "vip"},
            {"name": "이서연", "email": "seoyeon.lee@example.com", "phone": "010-3456-7892",
             "ssn": "920214-2xxxxxx", "address": "부산광역시 해운대구 센텀로 45", "tier": "standard"},
            {"name": "박도윤", "email": "doyoon.park@example.com", "phone": "010-4567-8903",
             "ssn": "880330-1xxxxxx", "address": "인천광역시 연수구 송도로 7", "tier": "standard"},
        ],
    },
    "crown-secrets": {
        "table": "internal_secrets",
        "exfiltrated_rows": 1,
        "sample": [
            {"key": "master_db_backup_credential", "value": "FLAG{shopflow_••••••••}",
             "note": "④ 목표물 (값 기반 FLAG)"},
        ],
    },
}


def _crown_loot(cid: str, chans) -> Optional[dict]:
    """'확보한 데이터' = 반출 표본(시드 실데이터, 있으면) + 통로. 표시 전용 — 판정·채점 무관."""
    sample = _CROWN_LOOT_SAMPLE.get(cid)
    if sample:
        loot = dict(sample)
        if chans:
            loot["channel"] = list(chans)
        return loot
    return {"channel": list(chans)} if chans else None


def _label(cid: str) -> str:
    if cid in _CROWN_LABEL:
        return _CROWN_LABEL[cid]
    base = str(cid or "").replace("crown-", "").replace("crown_", "")
    return (base + " 유출") if base else "핵심정보 유출"


def _fact_text(n: dict) -> str:
    parts = [str(n.get(k, "")) for k in ("summary", "target", "evidence", "desc", "technique")]
    loot = n.get("loot")
    if loot:
        parts.append(str(loot))
    return " ".join(parts).lower()


def inject_godview_findings(snapshot: Optional[dict], crowns, cvss_by_crown,
                            channels_by_crown=None, round: Optional[int] = None) -> Optional[dict]:
    """공격자 스냅샷(nodes/edges)에 god-view 확정 크라운을 발견 노드로 추가한 '사본'을 반환.

    - crowns 가 비면 스냅샷을 그대로 돌려준다(무증강).
    - 각 크라운마다 finding 노드 1개 추가(godview=True, crown_id, 크라운 CVSS 동봉).
    - 관련 사실 노드 → proves(입증) 엣지. 매칭 없으면 말단 사실 → 최신 사실 → 목표 순 폴백.
    - 같은 크라운의 god-view 노드가 이미 있으면 중복 추가하지 않는다.
    """
    if not crowns:
        return snapshot
    snap = snapshot if isinstance(snapshot, dict) else {}
    nodes = [dict(n) for n in (snap.get("nodes") or [])]
    edges = [dict(e) for e in (snap.get("edges") or [])]
    channels_by_crown = channels_by_crown or {}

    ids = [n.get("id") for n in nodes if isinstance(n.get("id"), int)]
    next_id = (max(ids) + 1) if ids else 1

    facts = [n for n in nodes if n.get("kind") == "fact"]
    goal = next((n for n in nodes if n.get("kind") == "goal"), None)
    srcs_of = {e.get("src") for e in edges}          # 엣지 출발점이 된 노드 → '말단 사실' 판별
    have = {n.get("crown_id") for n in nodes if n.get("godview")}  # 재주입 시 중복 방지

    for cid in crowns:
        if cid in have:
            continue
        cv = (cvss_by_crown or {}).get(cid) or {}
        chans = list(channels_by_crown.get(cid) or [])
        fnode = {
            "id": next_id, "kind": "finding", "state": "done", "owner": "judge",
            "godview": True, "crown_id": cid,
            "technique": _CROWN_MITRE.get(cid, ""),
            "summary": _label(cid),
            "desc": ("심판 god-view 로 확정된 핵심 자산 침해입니다. 접근기록("
                     + ("·".join(chans) if chans else "DB·앱 로그")
                     + ")으로 '실제 반출'을 확인했습니다."),
            "severity": cv.get("severity", ""),
            "evidence": "god-view 접근기록 확정" + (" (" + ", ".join(chans) + " 통로)" if chans else ""),
            "loot": _crown_loot(cid, chans),
            "round": round,
            "cvss": ({k: cv.get(k) for k in ("score", "severity", "vector", "basis")} if cv else None),
        }
        next_id += 1
        nodes.append(fnode)

        keys = _CROWN_KEYS.get(cid, ())
        matched = [n for n in facts if any(k in _fact_text(n) for k in keys)] if keys else []
        if not matched:
            matched = [n for n in facts if n.get("id") not in srcs_of]   # 말단 사실(탐색 종착)
        if not matched and facts:
            matched = [max(facts, key=lambda n: n.get("id") or 0)]       # 최신 사실
        if not matched and goal:
            matched = [goal]
        for m in matched[:6]:                                            # 과도한 엣지 방지
            edges.append({"src": m.get("id"), "rel": "proves", "dst": fnode["id"]})

    return {"nodes": nodes, "edges": edges}


__all__ = ["inject_godview_findings"]
