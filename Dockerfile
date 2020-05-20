FROM golang:alpine as builder
WORKDIR /go/src
COPY runss.go ./runss/
RUN CGO_ENABLED=0 GOOS=linux \
    apk add --no-cache git build-base && \
    cd runss && \
    go get && \
    go build -a -installsuffix cgo -ldflags '-s' -o runss

FROM alpine:latest

COPY shadowsocks.patch /
COPY shadowsocksr.patch /
COPY --from=builder /go/src/runss/runss /usr/local/bin/
COPY --from=curve25519xsalsa20poly1305/aria2:latest /usr/bin/aria2c /usr/bin/

RUN echo "http://dl-4.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && apk upgrade \
    && apk add --no-cache bash curl wget git iptables libressl-dev openssl \
        pcre-dev libgcc libstdc++ gnutls expat sqlite-libs c-ares 3proxy jq \
    && apk add --no-cache --virtual .build-deps gettext-dev \
        automake build-base autoconf libtool linux-headers \
        c-ares-dev mbedtls-dev libev-dev udns-dev libsodium-dev zlib-dev \
    && git clone --depth 1 --recurse-submodules -j8 https://github.com/shadowsocks/simple-obfs.git \
    && git clone --depth 1 --recurse-submodules -j8 https://github.com/shadowsocks/shadowsocks-libev.git \
    && git clone --depth 1 --recurse-submodules -j8 https://github.com/shadowsocksrr/shadowsocksr-libev.git \
    && cd shadowsocksr-libev \
    && patch -p1 < /shadowsocksr.patch \
    && rm /shadowsocksr.patch \
    && ./configure --prefix=/usr --disable-documentation \
    && make install \
    && cd .. \
    && for f in /usr/bin/ss-*; do mv "$f" "${f/ss-/ssr-}"; done \
    && cd simple-obfs \
    && ./autogen.sh \
    && ./configure --prefix=/usr --disable-documentation \
    && make install -j8 \
    && cd .. \
    && cd shadowsocks-libev \
    && patch -p1 < /shadowsocks.patch \
    && rm /shadowsocks.patch \
    && ./autogen.sh \
    && ./configure --prefix=/usr --disable-documentation \
    && make install -j8 \
    && cd ..

RUN runDeps="$( \
        scanelf --needed --nobanner /usr/bin/ss-* \
            | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
            | xargs -r apk info --installed \
            | sort -u \
    )" \
    && apk add --no-cache --virtual .run-deps $runDeps

COPY entrypoint.sh /usr/local/bin/
COPY shadowsocks-up.sh /usr/local/bin/

RUN rm -rf simple-obfs shadowsocks-libev shadowsocksr-libev \
    && apk del .build-deps \
    && chmod +x \
        /usr/local/bin/entrypoint.sh \
        /usr/local/bin/shadowsocks-up.sh \
    && mkdir -p /etc/shadowsocks

# Shadowsocks/ShadowsocksR Options
ENV     SS_URI              ""
ENV     SS_VARIANT          "ssr"
ENV     SS_SERVER_ADDR      "0.0.0.0"
ENV     SS_SERVER_PORT      "1080"
ENV     SS_SERVER_PASS      ""
ENV     SS_METHOD           "chacha20-ietf-poly1305"
ENV     SS_TIMEOUT          "300"
ENV     SS_LOCAL_ADDR       "0.0.0.0"
ENV     SS_LOCAL_PORT       "1024"
ENV     SS_USER             ""
ENV     SS_FAST_OPEN        "false"
ENV     SS_MODE             "tcp_and_udp"
ENV     SS_NOFILE           "1024"
ENV     SS_MTU              ""
ENV     SS_MPTCP            "false"
ENV     SS_IPV6_FIRST       "false"
ENV     SS_UP               ""

# Shadowsocks Options
ENV     SS_PLUGIN           ""
ENV     SS_PLUGIN_OPTS      ""
ENV     SS_KEY              ""
ENV     SS_REUSE_PORT       "false"
ENV     SS_DSCP             ""
ENV     SS_USE_SYSLOG       "false"
ENV     SS_NO_DELAY         "false"

# ShadowsocksR Options
ENV     SS_PROTO            "origin"
ENV     SS_PROTO_PARAM      ""
ENV     SS_OBFS             "plain"
ENV     SS_OBFS_PARAM       ""

# aria2 Options
ENV     ARIA2_PORT          ""
ENV     ARIA2_PASS          ""
ENV     ARIA2_PATH          "."
ENV     ARIA2_ARGS          ""
ENV     ARIA2_UP            ""

# Proxy Options
ENV     PROXY_USER          ""
ENV     PROXY_PASS          ""
ENV     PROXY_UP            ""

# Proxy Ports Options
ENV     SOCKS5_PROXY_PORT   "1080"
ENV     HTTP_PROXY_PORT     "3128"

ENV     DAEMON_MODE         "false"

ENTRYPOINT [ "entrypoint.sh" ]
