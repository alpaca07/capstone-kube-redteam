# attacker-toolkit — 자동 공격 하네스(VM A)가 frontend 발판 파드 안에서 kubectl exec 로
# 돌리는 '공격 도구 모음' 이미지. 기존 postgres:16-alpine(psql·wget·nc 만) 을 대체한다.
# 노선 B(장비를 갖춘 공격자) + 전달 2(커스텀 이미지). 대화형 툴(peirates·metasploit)은 제외.
#
# 실험 중 모델망 외 인터넷 OFF 라 모든 도구는 '빌드 시점'에 구워 넣는다(런타임 다운로드 없음).
# 빌드/적재 절차는 build-and-load.sh / README.md 참고 — VM B(개발 단계·인터넷 ON)에서 빌드.
FROM alpine:3.20

# ── 버전 핀(재현성). 다운로드가 404 면 여기 값을 해당 릴리스 페이지의 최신으로 올려라. ──
ARG KUBECTL_VERSION=v1.31.5         # k3s 서버 버전에 맞춰 ±1 마이너 권장(VM B: sudo k3s kubectl version)
ARG NUCLEI_VERSION=v3.3.7
ARG KDIGGER_VERSION=v1.6.0
ARG AMICONTAINED_VERSION=v0.4.9
ARG DEEPCE_REF=main
ARG SQLMAP_REF=master
ARG WITH_NUCLEI_TEMPLATES=true      # false 면 템플릿 없이 린 이미지(실험장 오프라인이면 true 권장)
ARG WITH_EXPLOITDB=true             # ExploitDB(searchsploit) 오프라인 미러 — 이미지 ~1GB↑
ARG EXPLOITDB_REF=main              # 고정 커밋/태그로 바꾸면 코퍼스 재현성↑(결정론 리플레이)

ENV HOME=/root
WORKDIR /opt/toolkit

# ── 1) apk 패키지(안정적으로 제공되는 것) ──
#   curl(HTTP)·jq(JSON)·nmap+NSE(스캔)·bind-tools(dig/nslookup)·psql(DB)·bash·python3(sqlmap)
#   libc6-compat/libseccomp = 다운로드한 바이너리를 musl alpine 에서 실행하기 위한 호환층
RUN apk add --no-cache \
      curl jq nmap nmap-scripts bind-tools postgresql16-client \
      bash coreutils grep ca-certificates python3 git unzip \
      libc6-compat libseccomp \
 && update-ca-certificates

# ── 2) 단일 바이너리 도구(빌드 시 다운로드 → 이미지에 상주) ──
# [T1] kubectl — K8s API(탈취 토큰과 함께 사용). -o json 구조화 출력이 정규화/해시에 이상적.
RUN curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
      -o /usr/local/bin/kubectl \
 && chmod +x /usr/local/bin/kubectl

# [T3] nuclei — 템플릿 기반 CVE 점검(projectdiscovery). VulHub/corp 웹 타깃용.
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" \
      -o /tmp/nuclei.zip \
 && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && chmod +x /usr/local/bin/nuclei \
 && rm -f /tmp/nuclei.zip

# [T2] kdigger — 파드 안에서 닿는 것·가진 권한 자동 열거(quarkslab).
#   릴리스 자산명(Linux_x86_64 등)이 버전마다 달라 GitHub API 로 linux/amd64 자산을 자동 해결.
RUN set -eux; \
    url="$(curl -fsSL https://api.github.com/repos/quarkslab/kdigger/releases/latest \
      | grep -o 'https://[^"]*' | grep -iE 'linux.*(amd64|x86_64)\.tar\.gz' | head -1)"; \
    test -n "$url"; \
    curl -fsSL "$url" -o /tmp/kdigger.tgz; \
    mkdir -p /tmp/kd && tar -xzf /tmp/kdigger.tgz -C /tmp/kd; \
    bin="$(find /tmp/kd -type f -name 'kdigger*' ! -name '*.sha256' ! -name '*.txt' ! -name '*.md' | head -1)"; \
    [ -n "$bin" ] || bin="$(find /tmp/kd -type f ! -name '*.md' ! -name '*.txt' ! -iname 'license*' | head -1)"; \
    test -n "$bin"; \
    install -m0755 "$bin" /usr/local/bin/kdigger; \
    rm -rf /tmp/kd /tmp/kdigger.tgz

# [T2] amicontained — 컨테이너 introspection(capability·seccomp 조사, jessfraz).
#   자산명이 버전마다 달라 GitHub API 로 linux-amd64 바이너리를 자동 해결.
RUN set -eux; \
    url="$(curl -fsSL https://api.github.com/repos/genuinetools/amicontained/releases/latest \
      | grep -o 'https://[^"]*' | grep -iE 'linux-amd64$' | head -1)"; \
    if [ -z "$url" ]; then \
      url="$(curl -fsSL https://api.github.com/repos/jessfraz/amicontained/releases/latest \
        | grep -o 'https://[^"]*' | grep -iE 'linux-amd64$' | head -1)"; \
    fi; \
    test -n "$url"; \
    curl -fsSL "$url" -o /usr/local/bin/amicontained; \
    chmod +x /usr/local/bin/amicontained

# [T2] deepce — 컨테이너 탈출 벡터 열거(bash 스크립트, stealthcopter). main/master 순서로 시도.
RUN set -eux; \
    ( curl -fsSL "https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh" -o /usr/local/bin/deepce \
      || curl -fsSL "https://raw.githubusercontent.com/stealthcopter/deepce/master/deepce.sh" -o /usr/local/bin/deepce ); \
    test -s /usr/local/bin/deepce; \
    chmod +x /usr/local/bin/deepce

# [T3] sqlmap — SQL 인젝션(--batch 비대화). git 배포가 정본이라 clone 후 wrapper 배선.
RUN (git clone --depth 1 --branch "${SQLMAP_REF}" https://github.com/sqlmapproject/sqlmap /opt/sqlmap \
      || git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap) \
 && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
 && chmod +x /usr/local/bin/sqlmap

# [T3] ExploitDB(searchsploit) — 검증된 PoC/익스플로잇 '오프라인 미러'. 실험 중 인터넷 OFF 라
#      빌드 시점에 받아 로컬 조회만 한다(런타임 네트워크 없음). EXPLOITDB_REF 고정 = 코퍼스
#      재현성(결정론 리플레이). wrapper 가 실경로 스크립트를 exec → DB 자동 탐색.
RUN if [ "$WITH_EXPLOITDB" = "true" ]; then \
      ( git clone --depth 1 --branch "${EXPLOITDB_REF}" https://gitlab.com/exploit-database/exploitdb /opt/exploitdb \
        || git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb ) ; \
      printf '#!/bin/sh\nexec /opt/exploitdb/searchsploit "$@"\n' > /usr/local/bin/searchsploit ; \
      chmod +x /usr/local/bin/searchsploit ; \
    fi

# ── 3) nuclei 템플릿을 빌드 시 받아 상주(실험장 오프라인 대비) ──
RUN if [ "$WITH_NUCLEI_TEMPLATES" = "true" ]; then \
      nuclei -update-templates -disable-update-check ; \
    fi

# ── 4) 스모크(핵심 도구 존재/실행 확인 — 실패 시 빌드 중단) ──
RUN set -e; \
    kubectl version --client >/dev/null; \
    nuclei -version -disable-update-check >/dev/null 2>&1; \
    nmap --version >/dev/null; curl --version >/dev/null; jq --version >/dev/null; \
    psql --version >/dev/null; sqlmap --version --batch >/dev/null 2>&1; \
    command -v kdigger >/dev/null; command -v amicontained >/dev/null; command -v deepce >/dev/null; \
    command -v dig >/dev/null; command -v nslookup >/dev/null; command -v wget >/dev/null; command -v nc >/dev/null; \
    if command -v searchsploit >/dev/null 2>&1; then searchsploit apache >/dev/null 2>&1 && echo "[attacker-toolkit] exploitdb ok"; fi; \
    echo "[attacker-toolkit] smoke ok"

LABEL org.opencontainers.image.title="capstone-attacker-toolkit" \
      app.kubernetes.io/part-of="capstone-killchain" \
      role="attacker-foothold"

# 유휴 대기(발판 파드에선 매니페스트 command 가 덮어씀; 단독 실행 대비 기본값).
CMD ["sleep", "infinity"]
