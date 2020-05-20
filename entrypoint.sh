#!/usr/bin/env bash

function spawn {
    if [[ -z ${PIDS+x} ]]; then PIDS=(); fi
    "$@" &
    PIDS+=($!)
}

function join {
    if [[ ! -z ${PIDS+x} ]]; then
        for pid in "${PIDS[@]}"; do
            wait "${pid}"
        done
    fi
}

function on_kill {
    if [[ ! -z ${PIDS+x} ]]; then
        for pid in "${PIDS[@]}"; do
            kill "${pid}" 2> /dev/null
        done
    fi
    kill "${ENTRYPOINT_PID}" 2> /dev/null
}

function log {
    local LEVEL="$1"
    local MSG="$(date '+%D %T') [${LEVEL}] $2"
    case "${LEVEL}" in
        INFO*)      MSG="\x1B[94m${MSG}";;
        WARNING*)   MSG="\x1B[93m${MSG}";;
        ERROR*)     MSG="\x1B[91m${MSG}";;
        *)
    esac
    echo -e "${MSG}"
}

export ENTRYPOINT_PID="${BASHPID}"

trap "on_kill" EXIT
trap "on_kill" SIGINT

SS_CONFIG="/etc/shadowsocks/config.json"
PROXY_CONFIG="/etc/3proxy.cfg"
PROXY_LOG="/var/log/3proxy.log"

mkfifo /shadowsocks-fifo
spawn runss
log "INFO" "Spawn Shadowsocks"

declare -A PROXY_USERS

function check_and_add_proxy_user {
    local user="${!1}"
    local pass="${!2}"
    if [[ -z "${user}" ]]; then
        return 1
    fi
    if [[ -z "${pass}" ]]; then
        log "ERROR" "empty password for user ${user} is not allowed!"
        exit 1
    fi
    if [[ -n "${PROXY_USERS["${user}"]}" ]]; then
        log "WARNING" "duplicated user ${user}, overwriting previous password."
    fi
    PROXY_USERS["${user}"]="${pass}"
    log "INFO" "Add proxy user ${user}"
}

if [[ -n "${SOCKS5_PROXY_PORT}" || -n "${HTTP_PROXY_PORT}" ]]; then

    # single user short-hand
    check_and_add_proxy_user PROXY_USER PROXY_PASS

    # backward compatibility
    check_and_add_proxy_user SOCKS5_USER SOCKS5_PASS

    # multi-user support
    USER_SEQ="1"
    USER_SEQ_END="false"
    while [[ "${USER_SEQ_END}" != "true" ]]; do
        check_and_add_proxy_user "PROXY_USER_${USER_SEQ}" "PROXY_PASS_${USER_SEQ}"
        STATUS=$?
        if [[ "${STATUS}" != 0 ]]; then
            USER_SEQ_END="true"
        fi
        USER_SEQ=$(( "${USER_SEQ}" + 1 ))
    done

    echo "nscache 65536" > "${PROXY_CONFIG}"
    for PROXY_USER in "${!PROXY_USERS[@]}"; do
        echo "users \"${PROXY_USER}:$(mycrypt "$(openssl rand -hex 16)" "${PROXY_USERS["${PROXY_USER}"]}")\"" >> "${PROXY_CONFIG}"
    done
    echo "log \"${PROXY_LOG}\" D" >> "${PROXY_CONFIG}"
    echo "logformat \"- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T\"" >> "${PROXY_CONFIG}"
    echo "rotate 30" >> "${PROXY_CONFIG}"
    echo "external 0.0.0.0" >> "${PROXY_CONFIG}"
    echo "internal 0.0.0.0" >> "${PROXY_CONFIG}"
    if [[ "${#PROXY_USERS[@]}" -gt 0 ]]; then
        echo "auth strong" >> "${PROXY_CONFIG}"
    fi
    echo "flush" >> "${PROXY_CONFIG}"
    for PROXY_USER in "${!PROXY_USERS[@]}"; do
        echo "allow \"${PROXY_USER}\"" >> "${PROXY_CONFIG}"
    done
    echo "maxconn 384" >> "${PROXY_CONFIG}"
    if [[ -n "${SOCKS5_PROXY_PORT}" ]]; then
        echo "socks -p${SOCKS5_PROXY_PORT}" >> "${PROXY_CONFIG}"
    fi
    if [[ -n "${HTTP_PROXY_PORT}" ]]; then
        echo "proxy -p${HTTP_PROXY_PORT}" >> "${PROXY_CONFIG}"
    fi

    log "INFO" "Write 3proxy config"

    spawn 3proxy "${PROXY_CONFIG}"
    log "INFO" "Spawn 3proxy"

    PROXY_ENABLED="true"
fi

if [[ -n "${ARIA2_PORT}" ]]; then
    cmd=(aria2c --enable-rpc --disable-ipv6 --rpc-listen-all --rpc-listen-port="${ARIA2_PORT}")
    if [[ -n "${ARIA2_PASS}" ]]; then
        cmd+=(--rpc-secret "${ARIA2_PASS}")
    fi
    if [[ -n "${ARIA2_PATH}" ]]; then
        cmd+=(--dir "${ARIA2_PATH}")
    fi
    if [[ -n "${ARIA2_ARGS}" ]]; then
        eval cmd\+\=\( ${ARIA2_ARGS} \)
    fi
    spawn "${cmd[@]}"
    log "INFO" "Spawn aria2c"
    ARIA2_ENABLED="true"
fi

cat /shadowsocks-fifo > /dev/null
rm -f /shadowsocks-fifo
log "INFO" "Shadowsocks become stable"

SS_SERVER_IP="$(getent hosts "$(cat "${SS_CONFIG}" | jq -r '.server')" | awk '{ print $1 }')"
SS_LOCAL_PORT="$(cat "${SS_CONFIG}" | jq -r '.local_port')"

iptables -t nat -N SS_TCP
iptables -t nat -A SS_TCP -p tcp -d "${SS_SERVER_IP}" -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 0.0.0.0/8 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 10.0.0.0/8 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 127.0.0.0/8 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 169.254.0.0/16 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 172.16.0.0/12 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 192.168.0.0/16 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 224.0.0.0/4 -j RETURN
iptables -t nat -A SS_TCP -p tcp -d 240.0.0.0/4 -j RETURN
iptables -t nat -A SS_TCP -p tcp -j REDIRECT --to-ports "${SS_LOCAL_PORT}"
iptables -t nat -A OUTPUT -p tcp -j SS_TCP

ip route add local default dev lo table 100
ip rule add fwmark 1 lookup 100

iptables -t mangle -N SS_UDP
iptables -t mangle -A SS_UDP -p udp -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A SS_UDP -p udp -d 240.0.0.0/4 -j RETURN
iptables -t mangle -A SS_UDP -p udp -j DROP
iptables -t mangle -A SS_UDP -p udp -j TPROXY --on-port "${SS_LOCAL_PORT}" --tproxy-mark 0x01/0x01
iptables -t mangle -A PREROUTING -p udp -j SS_UDP

log "INFO" "Updated iptables"

if [[ "${ARIA2_ENABLED}" == "true" && -n "${ARIA2_UP}" ]]; then
    spawn "${ARIA2_UP}"
    log "INFO" "Spawn aria2 up script: ${ARIA2_UP}"
fi

if [[ "${PROXY_ENABLED}" == "true" && -n "${PROXY_UP}" ]]; then
    spawn "${PROXY_UP}"
    log "INFO" "Spawn proxy up script: ${PROXY_UP}"
fi

if [[ -n "${SS_UP}" ]]; then
    spawn "${SS_UP}"
    log "INFO" "Spawn Shadowsocks up script: ${SS_UP}"
fi

if [[ $# -gt 0 ]]; then
    log "INFO" "Execute command line: $@"
    "$@"
fi

if [[ $# -eq 0 || "${DAEMON_MODE}" == true ]]; then
    join
fi
