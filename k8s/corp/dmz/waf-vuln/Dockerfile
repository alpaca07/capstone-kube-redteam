# 취약 WAF — CRS 3.3 베이스(3.3.5)에 룰만 CRS 3.3.0 으로 내려 룰 우회(CVE-2021-35368) 재현.
#   이 우회는 CRS 3.3.2 에서 패치됐으므로 3.3.0 룰이어야 열린다.
# 베이스를 CRS 4.x 가 아니라 3.3 계열로 둔 건 4.0 이 룰을 전면 재작성해 3.3.0 룰과
#   비호환이기 때문. 같은 3.3 구조라 룰 파일만 바꿔도 안정적이다.
# 한계: 엔진은 베이스(2023 빌드)라 엔진 DoS(CVE-2021-42717, ModSecurity<=3.0.5)는 미포함.
# CRS 경로(/opt/owasp-crs/rules)는 이 베이스에서 직접 확인한 실제 값.
FROM docker.io/owasp/modsecurity-crs:3.3-nginx-202308071108

# 베이스가 비권한 유저로 실행되므로 빌드 단계는 root 로 수행.
USER root

ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.0.tar.gz /tmp/crs330.tar.gz
RUN set -eux; \
    tar xzf /tmp/crs330.tar.gz --no-same-owner --no-same-permissions -C /tmp; \
    SRC=/tmp/coreruleset-3.3.0; \
    RULESDIR=/opt/owasp-crs/rules; \
    test -d "$RULESDIR"; \
    rm -f "$RULESDIR"/*.conf "$RULESDIR"/*.data; \
    cp "$SRC"/rules/*.conf "$RULESDIR"/; \
    cp "$SRC"/rules/*.data "$RULESDIR"/; \
    rm -rf "$SRC" /tmp/crs330.tar.gz; \
    echo "CRS 3.3.0 룰 교체 완료 ($RULESDIR)"
