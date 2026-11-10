# 취약 WAF — ModSecurity 엔진(베이스 최신) + CRS 3.3.0 룰로 교체.
# 목적: CRS 3.3.0 룰 우회(CVE-2021-35368) 재현 — 이 우회는 CRS 3.3.2 에서 패치됐다.
# 한계: 엔진은 베이스(최신)라 엔진 DoS(CVE-2021-42717, ModSecurity<=3.0.5)는 포함 안 됨.
#       거기까지 필요하면 ModSecurity 3.0.5 소스 빌드가 별도로 필요하다.
# 방식: 베이스의 nginx·ModSecurity 연동 틀은 그대로 두고 CRS 룰·설정만 3.3.0 으로 바꾼다.
#       (옛 CRS 3.3.0 공식 이미지는 Docker Hub 에서 사라져 베이스로 못 쓴다.)
FROM docker.io/owasp/modsecurity-crs:nginx

# 베이스가 비권한 유저로 실행되므로, 빌드 단계(파일 접근·시스템 경로 수정)는 root 로 수행한다.
USER root

ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.0.tar.gz /tmp/crs330.tar.gz
RUN set -eux; \
    tar xzf /tmp/crs330.tar.gz --no-same-owner --no-same-permissions -C /tmp; \
    SRC=/tmp/coreruleset-3.3.0; \
    RULESDIR="$(dirname "$(find / -path '*/rules/REQUEST-901-INITIALIZATION.conf' 2>/dev/null | head -1)")"; \
    test -n "$RULESDIR"; \
    echo "CRS 룰 디렉토리: $RULESDIR"; \
    rm -f "$RULESDIR"/*.conf "$RULESDIR"/*.data; \
    cp "$SRC"/rules/*.conf "$RULESDIR"/; \
    cp "$SRC"/rules/*.data "$RULESDIR"/ 2>/dev/null || true; \
    SETUP="$(find / -name 'crs-setup.conf' 2>/dev/null | head -1)"; \
    test -n "$SETUP" && cp "$SRC"/crs-setup.conf.example "$SETUP"; \
    rm -rf "$SRC" /tmp/crs330.tar.gz; \
    echo "CRS 3.3.0 교체 완료 (RULESDIR=$RULESDIR, SETUP=$SETUP)"
