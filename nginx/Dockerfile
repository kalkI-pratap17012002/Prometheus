# syntax=docker/dockerfile:1.6
FROM openresty/openresty:1.25.3.1-alpine

ARG MODSEC_VERSION=v3.0.12
ARG MODSEC_NGINX_VERSION=v1.0.3
ARG CRS_VERSION=v4.3.0
ARG PCRE_VERSION=8.45

ENV LUA_PATH="/usr/local/openresty/lualib/?.lua;;" \
    LUA_CPATH="/usr/local/openresty/lualib/?.so;;"

RUN apk add --no-cache \
        bash curl ca-certificates tzdata \
        git build-base linux-headers zlib-dev openssl-dev curl-dev \
        autoconf automake libtool make gcc g++ \
        libxml2-dev yajl-dev lmdb-dev geoip-dev libmaxminddb-dev \
        libstdc++ libxml2 yajl lmdb geoip libmaxminddb zlib openssl

# Build PCRE1 from source — ModSecurity v3.0.12 requires libpcre (PCRE1);
# recent Alpine releases ship pcre2 only and no longer provide pcre-config.
RUN cd /tmp \
 && curl -fsSL "https://sourceforge.net/projects/pcre/files/pcre/${PCRE_VERSION}/pcre-${PCRE_VERSION}.tar.gz/download" -o pcre.tar.gz \
 && tar -xzf pcre.tar.gz \
 && cd pcre-${PCRE_VERSION} \
 && ./configure --prefix=/usr/local --enable-utf8 --enable-unicode-properties --enable-jit \
 && make -j"$(nproc)" \
 && make install \
 && cd /tmp && rm -rf pcre-${PCRE_VERSION} pcre.tar.gz

# Build libmodsecurity v3
RUN cd /tmp \
 && git clone --depth 1 --branch ${MODSEC_VERSION} https://github.com/owasp-modsecurity/ModSecurity.git \
 && cd ModSecurity \
 && git submodule init && git submodule update \
 && ./build.sh \
 && ./configure --with-yajl --with-lmdb --with-pcre=/usr/local/bin/pcre-config \
 && make -j"$(nproc)" \
 && make install \
 && rm -rf /tmp/ModSecurity

# Build ModSecurity-nginx connector against OpenResty's bundled nginx source
RUN cd /tmp \
 && NGX_VERSION=$(/usr/local/openresty/nginx/sbin/nginx -v 2>&1 | sed 's|.*openresty/||' | cut -d. -f1-3) \
 && [ -n "$NGX_VERSION" ] || (echo "Failed to extract nginx version" && exit 1) \
 && curl -fsSL "http://nginx.org/download/nginx-${NGX_VERSION}.tar.gz" -o nginx.tar.gz \
 && tar -xzf nginx.tar.gz \
 && git clone --depth 1 --branch ${MODSEC_NGINX_VERSION} https://github.com/owasp-modsecurity/ModSecurity-nginx.git \
 && cd nginx-${NGX_VERSION} \
 && ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx \
 && make modules \
 && mkdir -p /usr/local/openresty/nginx/modules \
 && cp objs/ngx_http_modsecurity_module.so /usr/local/openresty/nginx/modules/ \
 && cd /tmp && rm -rf nginx-${NGX_VERSION} nginx.tar.gz ModSecurity-nginx

# OWASP Core Rule Set
RUN mkdir -p /etc/modsecurity/crs \
 && git clone --depth 1 --branch ${CRS_VERSION} https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs \
 && cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# Pull the upstream recommended unicode mapping + base config
RUN curl -fsSL https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/${MODSEC_VERSION}/unicode.mapping \
        -o /etc/modsecurity/unicode.mapping

# Strip build toolchain to keep the image small
RUN apk del git build-base linux-headers autoconf automake libtool make gcc g++ \
            zlib-dev openssl-dev curl-dev libxml2-dev yajl-dev lmdb-dev geoip-dev libmaxminddb-dev \
 && rm -rf /var/cache/apk/* /tmp/*

# Project config
COPY modsec/modsecurity.conf         /etc/modsecurity/modsecurity.conf
COPY modsec/modsec_custom_rules.conf /etc/modsecurity/modsec_custom_rules.conf
COPY nginx.conf                      /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/                            /usr/local/openresty/nginx/lua/

RUN mkdir -p /var/log/modsec /var/log/nginx \
 && ln -sf /dev/stdout /var/log/nginx/access.log \
 && ln -sf /dev/stderr /var/log/nginx/error.log

# Bake a self-signed cert for local dev. Production deployments mount a real
# cert over /etc/ssl/waf.{crt,key} via the ./nginx/ssl volume (see README).
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/waf.key -out /etc/ssl/waf.crt \
        -subj "/CN=waf.local/O=ML-WAF/C=IN"

EXPOSE 80 443

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1/_waf/health || exit 1

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
