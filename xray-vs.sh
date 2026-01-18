#!/usr/bin/env bash
# =====================================================================
# 一键 Xray 安装脚本 - 四种模式（修复版，确保模式3完整执行）
# 1. VLESS Reality 直连落地机
# 2. Shadowsocks 2022 直连服务器
# 3. 中转 - 入站/落地型 (Reality落地 + 额外 SS 入站端口)
# 4. 中转 - 出站型 (只开 SS 端口，出站到下游 VLESS Reality)
# ======================================================================

set -euo pipefail

RED='\033[1;31m' GREEN='\033[1;32m' YELLOW='\033[1;33m' BLUE='\033[1;34m'
PURPLE='\033[1;35m' CYAN='\033[1;36m' NC='\033[0m'

info()    { echo -e "\( {GREEN}[INFO] \){NC} $*"; }
warn()    { echo -e "\( {YELLOW}[WARN] \){NC} $*"; }
error()   { echo -e "\( {RED}[ERROR] \){NC} $*" >&2; exit 1; }
success() { echo -e "\( {GREEN}[OK] \){NC} $*"; }

XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
XRAY_LOG="/var/log/xray"
SERVICE_FILE="/etc/systemd/system/xray.service"

SS_METHOD="2022-blake3-aes-128-gcm"
SS_PORT=8443
SS_PSK=""
VLESS_PORT=443
VLESS_SNI="www.microsoft.com"
VLESS_UUID=""
VLESS_PBK=""
VLESS_PRIVK=""
DOWN_IP=""
DOWN_PORT=""
DOWN_UUID=""
DOWN_PBK=""
DOWN_SNI=""

get_ip() {
    curl -s4 icanhazip.com 2>/dev/null || curl -s4 ifconfig.me || echo "你的服务器IP"
}

install_deps() {
    if command -v apt >/dev/null; then
        apt update -qq && apt install -y -qq curl unzip jq openssl ca-certificates
    elif command -v apk >/dev/null; then
        apk add --no-cache curl unzip jq openssl ca-certificates
    elif command -v dnf >/dev/null; then
        dnf install -y -q curl unzip jq openssl ca-certificates
    else
        warn "请手动安装 curl unzip jq openssl"
    fi
}

download_xray() {
    LATEST=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r .tag_name)
    [[ -z "$LATEST" || "$LATEST" = "null" ]] && error "获取 Xray 版本失败"
    ARCH=$(uname -m | sed 's/x86_64/64/;s/aarch64/arm64-v8a/;s/armv[78].*/arm32-v7a/')
    URL="https://github.com/XTLS/Xray-core/releases/download/$LATEST/Xray-linux-$ARCH.zip"
    curl -L -o /tmp/xray.zip "$URL" && unzip -o /tmp/xray.zip xray geoip.dat geosite.dat -d /usr/local/bin/
    chmod 755 "$XRAY_BIN"
    rm -f /tmp/xray.zip
}

gen_vless_keys() {
    VLESS_UUID=$($XRAY_BIN uuid)
    keypair=$($XRAY_BIN x25519)
    VLESS_PRIVK=$(echo "$keypair" | grep Private | awk '{print $3}')
    VLESS_PBK=$(echo "$keypair" | grep Public | awk '{print $3}')
}

gen_ss_psk() {
    SS_PSK=$(openssl rand -base64 16 | tr -d '=')
}

ask_mode() {
    echo -e "\n请选择模式："
    echo "1) VLESS Reality 直连落地机"
    echo "2) Shadowsocks 2022 直连服务器"
    echo "3) 中转 - 入站/落地型 (Reality落地 + 额外 SS 入站端口)"
    echo "4) 中转 - 出站型 (只开 SS 端口，出站到下游 VLESS Reality)"
    read -rp "输入 1/2/3/4: " MODE
    MODE=${MODE:-1}
}

ask_vless_basic() {
    read -rp "VLESS 端口 (默认 443): " tmp
    VLESS_PORT=${tmp:-443}
    read -rp "Reality SNI/伪装域名 (默认 www.microsoft.com): " tmp
    VLESS_SNI=${tmp:-"www.microsoft.com"}
}

ask_ss_basic() {
    read -rp "SS 端口 (默认 8443): " tmp
    SS_PORT=${tmp:-8443}
    read -rp "SS PSK (留空自动生成): " input
    if [[ -z "$input" ]]; then
        gen_ss_psk
        info "自动生成 PSK: $SS_PSK"
    else
        SS_PSK="$input"
    fi
}

ask_downstream_vless() {
    read -rp "下游落地机 IP/域名: " DOWN_IP
    [[ -z "$DOWN_IP" ]] && error "不能为空"
    read -rp "下游 VLESS 端口 (默认 443): " tmp
    DOWN_PORT=${tmp:-443}
    read -rp "下游 UUID: " DOWN_UUID
    [[ -z "$DOWN_UUID" ]] && error "不能为空"
    read -rp "下游 Public Key (pbk): " DOWN_PBK
    [[ -z "$DOWN_PBK" ]] && error "不能为空"
    read -rp "下游 SNI (默认 www.microsoft.com): " tmp
    DOWN_SNI=${tmp:-"www.microsoft.com"}
}

create_vless_direct() {
    cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {"loglevel": "warning", "access": "$XRAY_LOG/access.log", "error": "$XRAY_LOG/error.log"},
  "inbounds": [{
    "port": $VLESS_PORT,
    "protocol": "vless",
    "settings": {"clients": [{"id": "$VLESS_UUID", "flow": "xtls-rprx-vision"}]},
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "$VLESS_SNI:443",
        "serverNames": ["$VLESS_SNI"],
        "privateKey": "$VLESS_PRIVK",
        "publicKey": "$VLESS_PBK",
        "shortIds": [""]
      }
    },
    "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
  }],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "block"}],
  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]}
}
EOF
}

create_ss_direct() {
    cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {"loglevel": "warning", "access": "$XRAY_LOG/access.log", "error": "$XRAY_LOG/error.log"},
  "inbounds": [{
    "port": $SS_PORT,
    "protocol": "shadowsocks",
    "settings": {"method": "$SS_METHOD", "password": "$SS_PSK", "network": "tcp,udp"},
    "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
  }],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "block"}],
  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]}
}
EOF
}

create_relay_inbound() {
    cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {"loglevel": "warning", "access": "$XRAY_LOG/access.log", "error": "$XRAY_LOG/error.log"},
  "inbounds": [
    {
      "tag": "vless-in",
      "port": $VLESS_PORT,
      "protocol": "vless",
      "settings": {"clients": [{"id": "$VLESS_UUID", "flow": "xtls-rprx-vision"}]},
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$VLESS_SNI:443",
          "serverNames": ["$VLESS_SNI"],
          "privateKey": "$VLESS_PRIVK",
          "publicKey": "$VLESS_PBK",
          "shortIds": [""]
        }
      },
      "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
    },
    {
      "tag": "ss-in",
      "port": $SS_PORT,
      "protocol": "shadowsocks",
      "settings": {"method": "$SS_METHOD", "password": "$SS_PSK", "network": "tcp,udp"},
      "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
    }
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
  "routing": {"rules": [
    {"type": "field", "inboundTag": ["vless-in","ss-in"], "outboundTag": "direct"},
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}
  ]}
}
EOF
}

create_relay_outbound() {
    cat > "$XRAY_DIR/config.json" <<EOF
{
  "log": {"loglevel": "warning", "access": "$XRAY_LOG/access.log", "error": "$XRAY_LOG/error.log"},
  "inbounds": [{
    "port": $SS_PORT,
    "protocol": "shadowsocks",
    "settings": {"method": "$SS_METHOD", "password": "$SS_PSK", "network": "tcp,udp"},
    "sniffing": {"enabled": true, "destOverride": ["http","tls","quic"]}
  }],
  "outbounds": [
    {
      "tag": "vless-out",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "$DOWN_IP",
          "port": $DOWN_PORT,
          "users": [{"id": "$DOWN_UUID", "flow": "xtls-rprx-vision", "encryption": "none"}]
        }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$DOWN_SNI",
          "fingerprint": "chrome",
          "publicKey": "$DOWN_PBK",
          "shortId": ""
        }
      }
    },
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "routing": {"rules": [
    {"type": "field", "inboundTag": ["ss-in"], "outboundTag": "vless-out"},
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}
  ]}
}
EOF
}

setup_service() {
    mkdir -p "$XRAY_DIR" "$XRAY_LOG"
    chmod 600 "$XRAY_DIR/config.json" 2>/dev/null || true

    if [[ -d /etc/systemd/system ]]; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=$XRAY_BIN run -c $XRAY_DIR/config.json
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now xray || warn "启动服务失败，请手动检查"
    else
        warn "非 systemd 系统，请手动启动: $XRAY_BIN run -c $XRAY_DIR/config.json"
    fi
}

show_result() {
    local ip=$(get_ip)

    case $MODE in
        1)
            success "模式1：VLESS Reality 直连落地机 完成"
            echo "IP: $ip"
            echo "端口: $VLESS_PORT"
            echo "UUID: $VLESS_UUID"
            echo "pbk: $VLESS_PBK"
            echo "SNI: $VLESS_SNI"
            ;;
        2)
            success "模式2：Shadowsocks 2022 直连服务器 完成"
            echo "IP: $ip"
            echo "端口: $SS_PORT"
            echo "PSK: $SS_PSK"
            echo "加密: $SS_METHOD"
            ;;
        3)
            success "模式3：中转 - 入站/落地型 完成"
            echo "VLESS 落地端口: $VLESS_PORT  UUID: $VLESS_UUID  pbk: $VLESS_PBK  SNI: $VLESS_SNI"
            echo "额外 SS 入站端口（供上游中转连）：$SS_PORT  PSK: $SS_PSK"
            ;;
        4)
            success "模式4：中转 - 出站型 完成"
            echo "SS 入站端口（客户端连这里）：$SS_PORT  PSK: $SS_PSK"
            echo "出站目标：$DOWN_IP:$DOWN_PORT  UUID: $DOWN_UUID  pbk: $DOWN_PBK  SNI: $DOWN_SNI"
            ;;
    esac
}

main() {
    [[ $EUID -ne 0 ]] && error "请用 root 执行"

    install_deps
    download_xray
    ask_mode

    case $MODE in
        1)
            ask_vless_basic
            gen_vless_keys
            create_vless_direct
            ;;
        2)
            ask_ss_basic
            create_ss_direct
            ;;
        3)
            ask_vless_basic
            gen_vless_keys
            ask_ss_basic
            create_relay_inbound
            ;;
        4)
            ask_ss_basic
            ask_downstream_vless
            create_relay_outbound
            ;;
        *)
            error "无效模式，请输入 1/2/3/4"
            ;;
    esac

    setup_service
    show_result

    success "安装完成！日志路径: $XRAY_LOG/error.log"
    echo "查看服务状态: systemctl status xray"
    echo "更新 Xray: bash <(curl -Ls https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)"
}

main "$@"
