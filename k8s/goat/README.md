# k8s/goat — Kubernetes Goat 배포 (환경 구축 1단계)

타깃 클러스터(VM B)의 **레벨 1 출발점**. 의도적으로 취약한 K8s 실습 환경
[Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)을 배포한다.

## 방식과 이유

Goat을 레포에 통째로 복사(vendoring)하지 **않는다**. 대신:

- 버전관리 대상 = **래퍼 스크립트 3개 + 고정 커밋**뿐 → 레포 경량 유지
- Goat 본체는 VM B 로컬(`~/goat-src/kubernetes-goat`)에 clone → 레포에 중첩 git 없음
- **고정 커밋**(`723a0db…`)으로 받으므로 언제 돌려도 동일한 취약 환경 재현(논문 재현성)
- Goat 실제 수정/이식은 **3단계**에서 우리가 쓸 시나리오만 골라서 → 그때 선택적 vendoring

## 사전 요구 (VM B)

| 항목 | 상태 | 비고 |
|------|------|------|
| k3s + kubectl 연결 | 0단계에서 완료 | `kubectl get nodes` → Ready |
| **helm CLI** | **설치 필요** | metadata-db가 helm chart. 없으면 setup이 멈추고 안내 |
| 인터넷 | 개발 단계 ON | 이미지 pull용. 실험 단계엔 스냅샷으로 대체 |

helm 설치:
```bash
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

## 실행

```bash
# VM B, 레포 루트에서
git pull
bash k8s/goat/setup-goat.sh        # 고정 커밋 clone → 배포
kubectl get pods -A                # 1~3분 뒤 전부 Running 확인
bash k8s/goat/access-goat.sh       # 포트포워딩 1230~1236
# 브라우저:  http://<VM B IP>:1234  → Goat home
```

## 배포되는 것

`setup-kubernetes-goat.sh`가 올리는 시나리오 (네임스페이스: `default`,
`big-monolith`, `secure-middleware`, `kube-system`):

| 시나리오 | 포트 | 취약점 | 우리 킬체인 |
|----------|------|--------|-------------|
| **build-code** | 1230 | 코드베이스에 하드코딩된 민감 키 | **① 하드코딩 크레덴셜 (T1552)** |
| **insecure-rbac** | — | `superadmin` → cluster-admin 바인딩 | **② 과권한 RBAC (T1078)** |
| internal-proxy | 1232 | SSRF로 내부 서비스/메타데이터 접근 | 측면 이동 참고 |
| system-monitor | 1233 | 컨테이너 탈출(호스트 접근) | T1611 참고 |
| poor-registry | 1235 | 사설 레지스트리 공격 | T1525 참고 |
| hunger-check | 1236 | 리소스 DoS | T1499 참고 |
| health-check | 1231 | DIND(docker.sock) 익스플로잇 | ⚠ k3s서 N/A (아래) |
| metadata-db | — | 메타데이터 DB (SSRF 타깃) | 데이터 접근 참고 |
| batch-check / cache-store / hidden-in-layers | — | Job·캐시·이미지 레이어 내 비밀 | 보조 |

> 정확한 MITRE 매핑과 플래그 배치는 **4단계**에서 확정한다. 위 표는 설계상 연관의 밑그림.

## k3s 주의점 (containerd 기반)

- **docker.sock 전제 시나리오(health-check=DIND)**: k3s는 containerd라 호스트에
  `docker.sock`이 없다. 파드는 정상 기동하나 그 소켓 익스플로잇 경로만 N/A
  (최신 Goat은 소켓 없으면 graceful 처리). **우리 메인 킬체인은 docker.sock에
  의존하지 않으므로 영향 없음.**
- **privileged / hostPath**: k3s 기본은 PodSecurity 미강제 → 그대로 배포됨.
  (나중에 PSA `restricted`를 켜면 Goat이 깨짐 — 이건 방어 실험 때 역으로 활용 가능)
- **PVC 없음** → 스토리지 의존성 없음 (k3s local-path 불필요).
- **Traefik**: Goat은 ingress 대신 port-forward를 쓰므로 무관.

## 정리

```bash
bash k8s/goat/teardown-goat.sh
```

완전한 clean 초기화는 VMware 스냅샷 복원이 가장 확실 (5단계에서 자동화 예정).

---
_pin: `madhuakula/kubernetes-goat@723a0db478f050d173d23b4ce5044b65bce0bdd0`_
