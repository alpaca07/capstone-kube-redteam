# 취약 WAF — 엔진(libmodsecurity 3.0.5) + 룰(CRS 3.3.0) 둘 다 취약 버전.
#   엔진 DoS(CVE-2021-42717, ModSecurity<=3.0.5) + 룰 우회(CVE-2021-35368, CRS<=3.3.1).
# 베이스(owasp/modsecurity-crs:3.3-nginx-202308071108)는 엔진 3.0.8·CRS 3.3.5 라
#   둘 다 패치됨 → 엔진은 소스 빌드한 3.0.5 로, 룰은 3.3.0 으로 내린다.
# nginx·ModSecurity 커넥터는 베이스 그대로 재사용(엔진 so.3 ABI 호환) → nginx 재빌드 불필요.

# ── 1단계: libmodsecurity 3.0.5 소스 빌드 (debian 11 로 베이스 ABI 맞춤) ──
FROM debian:11 AS build
# debian 11(bullseye) EOL — 보안 저장소를 archive.debian.org 로 돌려 옛 .deb 를 받는다.
# (security 를 빼면 이미지에 이미 깔린 security 버전 라이브러리와 dev 패키지가 충돌한다.)
RUN sed -i 's|deb.debian.org/debian-security|archive.debian.org/debian-security|; s|security.debian.org|archive.debian.org|' /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential automake autoconf libtool pkg-config \
        libpcre3-dev libxml2-dev libyajl-dev liblua5.3-dev libgeoip-dev \
        libcurl4-openssl-dev libssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone -b v3.0.5 --depth 1 https://github.com/SpiderLabs/ModSecurity /src
WORKDIR /src
RUN git submodule update --init
RUN ./build.sh && ./configure && make -j"$(nproc)" && make install
# 산출물: /usr/local/modsecurity/lib/libmodsecurity.so.3.0.5 (+ so.3 심링크)

# ── 2단계: 베이스에 3.0.5 엔진 덮어쓰기 + CRS 3.3.0 룰 ──
FROM docker.io/owasp/modsecurity-crs:3.3-nginx-202308071108
# 베이스가 비권한 유저로 실행되므로 빌드 단계는 root 로.
USER root

# 엔진 교체: build 산출 lib 로 통째 덮어쓴다. so.3 심링크가 3.0.5 를 가리켜 커넥터가 로드.
COPY --from=build /usr/local/modsecurity/lib/ /usr/local/modsecurity/lib/
RUN set -eux; \
    rm -f /usr/local/modsecurity/lib/libmodsecurity.so.3.0.8; \
    ldconfig 2>/dev/null || true; \
    echo "[엔진 so 링크]"; ls -l /usr/local/modsecurity/lib/libmodsecurity.so.3; \
    # 3.0.5 엔진이 모르는 3.0.6+ 지시어(SecRequestBodyJsonDepthLimit)를 설정에서 제거 — 있으면 기동 실패.
    find /etc/nginx /etc/modsecurity.d -type f \( -name "*.conf" -o -name "*.template" \) \
      -exec sed -i '/SecRequestBodyJsonDepthLimit/d' {} + 2>/dev/null || true

# 룰 교체: CRS 3.3.0 룰·데이터만 내린다(crs-setup 은 3.3.x 호환이라 베이스 유지).
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.0.tar.gz /tmp/crs330.tar.gz
RUN set -eux; \
    tar xzf /tmp/crs330.tar.gz --no-same-owner --no-same-permissions -C /tmp; \
    RULESDIR=/opt/owasp-crs/rules; \
    test -d "$RULESDIR"; \
    rm -f "$RULESDIR"/*.conf "$RULESDIR"/*.data; \
    cp /tmp/coreruleset-3.3.0/rules/*.conf "$RULESDIR"/; \
    cp /tmp/coreruleset-3.3.0/rules/*.data "$RULESDIR"/; \
    rm -rf /tmp/coreruleset-3.3.0 /tmp/crs330.tar.gz; \
    echo "libmodsecurity 3.0.5 + CRS 3.3.0 교체 완료"
