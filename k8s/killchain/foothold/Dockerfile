# 공격 발판 파드 이미지 — 침투 도구만 든 유휴 컨테이너(명령은 하네스가 kubectl exec 로 주입).
# 오프라인 실험 대비 도구를 '구워' 둔다(실험 중엔 apk/다운로드 불가). dev(인터넷 ON) 때 빌드.
#
# 빌드 & k3s 로 import (VM B, 인터넷 ON 상태에서):
#   docker build -t shopflow/attacker-foothold:latest k8s/killchain/foothold/
#   docker save shopflow/attacker-foothold:latest | sudo k3s ctr images import -
# (docker 없으면 podman/buildah 로 빌드 후 동일하게 save→import. 매니페스트는 IfNotPresent.)
FROM alpine:3.20

# curl(HTTP), nmap(스캔), netcat(포트 확인), postgresql-client(psql, ④ DB), bind-tools(dig/nslookup, DNS 열거), bash
RUN apk add --no-cache \
      curl \
      nmap \
      netcat-openbsd \
      postgresql16-client \
      bind-tools \
      bash

# kubectl — 파드 SA 권한 탐색(auth can-i)·API 조회용. 버전은 k3s 에 맞춰 조정.
ARG KUBECTL_VERSION=v1.30.5
RUN curl -fsSL -o /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl

# 유휴 유지(명령은 외부에서 exec 로 들어온다).
CMD ["tail", "-f", "/dev/null"]
