# Shadowsocks/ShadowsocksR to SOCKS5/HTTP Proxy Docker Image

Convers Shadowsocks/ShadowsocksR connection to SOCKS5/HTTP proxy in Docker. This allows you to have multiple proxies on different ports connecting to different Shadowsocks/ShadowsocksR upstreams.

Supports latest Docker for both Windows, Linux, and MacOS.

## Related Projects

-   [OpenVPN](https://hub.docker.com/r/curve25519xsalsa20poly1305/openvpn/) ([GitHub](https://github.com/curve25519xsalsa20poly1305/docker-openvpn))
-   [WireGuard](https://hub.docker.com/r/curve25519xsalsa20poly1305/wireguard/) ([GitHub](https://github.com/curve25519xsalsa20poly1305/docker-wireguard))
-   [Shadowsocks/ShadowsocksR](https://hub.docker.com/r/curve25519xsalsa20poly1305/shadowsocks/) ([GitHub](https://github.com/curve25519xsalsa20poly1305/docker-shadowsocks))

## What it does?

1. It starts Shadowsocks/ShadowsocksR client mode `ss-redir` at default port of `1024`.
2. It starts [3proxy](https://3proxy.ru/) server and listen on container-scoped port 1080 for SOCKS5 and 3128 for HTTP proxy on default. Proxy authentication can be enabled with `PROXY_USER` and `PROXY_PASS` environment variables. `SOCKS5_PROXY_PORT` and `HTTP_PROXY_PORT` can be used to change the default ports. For multi-user support, use sequence of `PROXY_USER_1`, `PROXY_PASS_1`, `PROXY_USER_2`, `PROXY_PASS_2`, etc.
3. It optionally runs the executable defined by `PROXY_UP` when the proxy server is ready.
4. If `ARIA2_PORT` is defined, it starts an aria2 RPC server on the port, and optionally runs the executable defined by `ARIA2_UP`.
5. It setups iptables rules to redirect all internet traffics initiated inside the container through the Shadowsocks/ShadowsocksR connection.
6. It optionally runs the user specified CMD line from `docker run` positional arguments ([see Docker doc](https://docs.docker.com/engine/reference/run/#cmd-default-command-or-options)). The program will use the Shadowsocks/ShadowsocksR connection inside the container.
7. If user has provided CMD line, and `DAEMON_MODE` environment variable is not set to `true`, then after running the CMD line, it will shutdown the Shadowsocks/ShadowsocksR client and proxy server, then terminate the container.

## How to use?

Shadowsocks/ShadowsocksR connection options are specified through these container environment variables:

-   `SS_URI` (Default: `""`) - [SS (SIP002)](https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme) or [SSR](https://github.com/shadowsocksr-backup/shadowsocks-rss/wiki/SSR-QRcode-scheme) URI scheme. When set, will override all the following `SS_` options
-   `SS_VARIANT` (Default: `ssr`) - Specify the protocol variant as either `ss` or `ssr`
-   `SS_SERVER_ADDR` (Default: `"0.0.0.0"`) - Remote server address, can either be a domain name or IP address
-   `SS_SERVER_PORT` (Default: `"1080"`) - Remote server port
-   `SS_SERVER_PASS` (Default: `""`) - Remote server password
-   `SS_METHOD` (Default: `"chacha20-ietf-poly1305"`) - Encryption method cipher. Can be: `"aes-128-gcm"`, `"aes-192-gcm"`, `"aes-256-gcm"`, `"rc4-md5"`, `"aes-128-cfb"`, `"aes-192-cfb"`, `"aes-256-cfb"`, `"aes-128-ctr"`, `"aes-192-ctr"`, `"aes-256-ctr"`, `"bf-cfb"`, `"camellia-128-cfb"`, `"camellia-192-cfb"`, `"camellia-256-cfb"`, `"chacha20-ietf-poly1305"`, `"salsa20"`, `"chacha20 and chacha20-ietf"`
-   `SS_PLUGIN` (Default: `""`) - **[SS ONLY]** [SIP003](https://shadowsocks.org/en/spec/Plugin.html) plugin, Can be: `"obfs-local"`
-   `SS_PLUGIN_OPTS` (Default: `""`) - **[SS ONLY]** [SIP003](https://shadowsocks.org/en/spec/Plugin.html) plugin options, list of `keyonly` or `key=value` pairs separated by `;` e.g. `"obfs=tls;obfs-host=www.baidu.com;obfs-uri=/;http-method=GET;mptcp;fast-open"`, supported `obfs`: `tls`, `http`
-   `SS_PROTO` (Default: `"origin"`) - **[SSR ONLY]** [ShadowsocksR Protocol](https://github.com/shadowsocksr-backup/shadowsocks-rss/wiki/obfs) plugin enforcing data integrity, and perform segmentation to hide real data length. Can be: `"origin"`, `"auth_sha1"`, `"auth_sha1_v2"`, `"auth_sha1_v4"`, `"auth_aes128_md5"`, `"auth_aes128_sha1"`, `"auth_chain_a"`. `"origin"` will disable the protocol plugin.
-   `SS_PROTO_PARAM` (Default: `""`) - **[SSR ONLY]** [ShadowsocksR Protocol](https://github.com/shadowsocksr-backup/shadowsocks-rss/wiki/obfs) plugin parameters. Currently no protocol plugin is using it.
-   `SS_OBFS` (Default: `"plain"`) - **[SSR ONLY]** [ShadowsocksR Obfuscation](https://github.com/shadowsocksr-backup/shadowsocks-rss/wiki/obfs) plugin for data steganography. Can be `"plain"`, `"http_simple"`, `"http_post"`, and `"tls1.2_ticket_auth"`. `"plain"` will disable the obfuscation plugin.
-   `SS_OBFS_PARAM` (Default: `""`) - **[SSR ONLY]** [ShadowsocksR Obfuscation](https://github.com/shadowsocksr-backup/shadowsocks-rss/wiki/obfs) plugin parameters. Usually is the host names in the obfuscated data datagram's fields.
-   `SS_KEY` (Default: `""`) - **[SS ONLY]** Set the key directly. The key should be encoded with URL-safe Base64
-   `SS_TIMEOUT` (Default: `"300"`) - Set the socket timeout in seconds
-   `SS_USER` (Default: `""`) - Run as a specific user
-   `SS_FAST_OPEN` (Default: `"false"`) - Set to `"true"` for TCP fast open
-   `SS_REUSE_PORT` (Default: `"false"`) - **[SS ONLY]** Enable port reuse
-   `SS_NOFILE` (Default: `"1024"`) - Specify max number of open files, 1024 is the minimum possible value
-   `SS_DSCP` (Default: `""`) - **[SS ONLY]** A JSON object to specify additional TOS/DSCP listening ports
-   `SS_MODE` (Default: `"tcp_and_udp"`) - Can be `"tcp_only"`, `"tcp_and_udp"`, and `"udp_only"`
-   `SS_MTU` (Default: `""`) - Specify the MTU in integer of your network interface
-   `SS_MPTCP` (Default: `"false"`) - Enable Multipath TCP
-   `SS_IPV6_FIRST` (Default: `"false"`) - Resovle hostname to IPv6 address first
-   `SS_USE_SYSLOG` (Default: `"false"`) - **[SS ONLY]** Use Syslog
-   `SS_NO_DELAY` (Default: `"false"`) - **[SS ONLY]** Enable TCP_NODELAY
-   `SS_LOCAL_ADDR` (Default: `"0.0.0.0"`) - `ss-redir` local listening interface
-   `SS_LOCAL_PORT` (Default: `"1024"`) - `ss-redir` local listening port, must be different from `SOCKS5_PROXY_PORT`
-   `SS_UP` (Default: `""`) - optional command to be executed when Shadowsocks/ShadowsocksR connection becomes stable

Proxy server options are specified through these container environment variables:

-   `SOCKS5_PROXY_PORT` (Default: `"1080"`) - SOCKS5 server listening port
-   `HTTP_PROXY_PORT` (Default: `"3128"`) - HTTP proxy server listening port
-   `PROXY_USER` (Default: `""`) - Proxy server authentication username
-   `PROXY_PASS` (Default: `""`) - Proxy server authentication password
-   `PROXY_USER_<N>` (Default: `""`) - The `N`-th username for multi-user proxy authentication. `N` starts from 1.
-   `PROXY_PASS_<N>` (Default: `""`) - The `N`-th password for multi-user proxy authentication. `N` starts from 1.
-   `PROXY_UP` (Default: `""`) - optional command to be executed when proxy server becomes stable

Arai2 options are specified through these container environment variables:

-   `ARIA2_PORT` (Default: `""`) - JSON-RPC server listening port
-   `ARIA2_PASS` (Default: `""`) - `--rpc-secret` password
-   `ARIA2_PATH` (Default: `"."`) - The directory to store the downloaded file
-   `ARIA2_ARGS` (Default: `""`) - BASH-style escaped command line to append to the `aria2c` command
-   `ARIA2_UP` (Default: `""`) - optional command to be executed when aria2 JSON-RPC server becomes stable

Other container environment variables:

-   `DAEMON_MODE` (Default: `"false"`) - force enter daemon mode when CMD line is specified

### Simple Example

The following example will run `curl ifconfig.co/json` through Shadowsocks server `1.2.3.4` with other default settings.

```bash
docker run -it --rm --device=/dev/net/tun --cap-add=NET_ADMIN \
    -e SERVER_ADDR="1.2.3.4" \
    curve25519xsalsa20poly1305/shadowsocks \
    curl ifconfig.co/json
```

### Daemon Mode

You can leave the Shadowsocks connection running in background, exposing its SOCKS5 server port to host port, and later use `docker exec` to run your program inside the running container without ever closing and reopening your Shadowsocks connection multiple times. Just leave out the CMD line when you start the container with `docker run`, it will automatically enter daemon mode.

```bash
NAME="myss"
PORT="7777"
docker run --name "${NAME}" -dit --rm --device=/dev/net/tun --cap-add=NET_ADMIN \
    -e SERVER_ADDR="1.2.3.4" \
    -p "${PORT}":1080 \
    curve25519xsalsa20poly1305/shadowsocks
```

Then you run commads using `docker exec`:

```bash
NAME="myss"
docker exec -it "${NAME}" curl ifconfig.co/json
```

Or use the SOCKS5 server available on host machine:

```bash
curl ifconfig.co/json -x socks5h://127.0.0.1:7777
```

To stop the daemon, run this:

```bash
NAME="myss"
docker stop "${NAME}"
```

## Contributing

Please feel free to contribute to this project. But before you do so, just make
sure you understand the following:

1\. Make sure you have access to the official repository of this project where
the maintainer is actively pushing changes. So that all effective changes can go
into the official release pipeline.

2\. Make sure your editor has [EditorConfig](https://editorconfig.org/) plugin
installed and enabled. It's used to unify code formatting style.

3\. Use [Conventional Commits 1.0.0-beta.2](https://conventionalcommits.org/) to
format Git commit messages.

4\. Use [Gitflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow)
as Git workflow guideline.

5\. Use [Semantic Versioning 2.0.0](https://semver.org/) to tag release
versions.

## License

Copyright © 2019 curve25519xsalsa20poly1305 &lt;<curve25519xsalsa20poly1305@gmail.com>&gt;

This work is free. You can redistribute it and/or modify it under the
terms of the Do What The Fuck You Want To Public License, Version 2,
as published by Sam Hocevar. See the COPYING file for more details.
