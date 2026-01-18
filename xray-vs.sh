#!/usr/bin/env bash
# =====================================================================
# 快速部署 Xray 的脚本（支持主流 Linux 发行版）
# 支持模式：
#   1. VLESS + Reality
#   2. Shadowsocks 2022
#   3. Shadowsocks 中转 → 出站 VLESS Reality
# 最后更新：2025/2026 常用写法
# =====================================================================

set -euo pipefail

# ======================== 颜色输出 =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

msg_info()  { echo -e "\( {GREEN}[INFO] \){NC} $*"  ; }
msg_warn()  { echo -e "\( {YELLOW}[WARN] \){NC} $*" ; }
msg_error() { echo -e "\( {RED}[ERROR] \){NC} $*" >&2; }

# ======================== 检测系统 & 安装依赖 =========================
install_dependencies() {
    if [[ -f /etc/debian_version ]] || grep -qiE 'ubuntu|debian' /etc/os-release 2>/dev/null; then
        PKG_MANAGER="apt"
        PKG_UPDATE="apt update -y"
        PKG_INSTALL="apt install -y"
    elif [[ -f /etc/alpine-release ]]; then
        PKG_MANAGER="apk"
        PKG_UPDATE="apk update"
        PKG_INSTALL="apk add"
    elif grep -qiE 'centos|red hat|rocky|almalinux' /etc/os-release 2>/dev/null; then
        PKG_MANAGER="dnf_or_yum"
        if command -v dnf >/dev/null; then
            PKG_UPDATE="dnf makecache -y"
            PKG_INSTALL="dnf install -y"
        else
            PKG_UPDATE="yum makecache -y"
            PKG_INSTALL="yum install -y"
        fi
    else
        msg_error "不支持的操作系统。当前仅支持 Debian/Ubuntu/Alpine/CentOS/Rocky/AlmaLinux"
        exit 1
    fi

    msg_info "正在更新软件源并安装必要工具..."
    $PKG_UPDATE
    $PKG_INSTALL curl unzip jq openssl ca-certificates
}

# ======================== 安装/更新 Xray =========================
install_xray() {
    if ! command -v xray >/dev/null; then
        msg_info "正在安装最新版 Xray..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --remove || true
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    else
        msg_info "Xray 已安装，正在尝试更新..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta || true
    fi

    # 确保目录存在
    mkdir -p /usr/local/etc/xray /usr/local/share/xray
    chmod 755 /usr/local/etc/xray

    # 检查服务文件是否存在
    if [[ ! -f /etc/systemd/system/xray.service ]]; then
        msg_warn "systemd 服务文件未找到，尝试手动创建基本服务文件..."
        cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
}

# ======================== 生成 Reality 密钥对 =========================
generate_reality_keypair() {
    local keys
    keys=$(xray x25519 2>/dev/null || /usr/local/bin/xray x25519)
    PRIVATE_KEY=$(echo "$keys" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$keys" | grep "Public key:" | awk '{print $3}')
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        msg_error "无法生成 Reality 密钥对"
        exit 1
    fi
}

# ======================== 模式 1：VLESS + Reality =========================
mode_vless_reality() {
    read -r -p "请输入监听端口 (建议 443/8443/2053 等): " PORT
    read -r -p "请输入 SNI (推荐可伪装的域名，如 www.microsoft.com): " SNI
    [[ -z "$PORT" || -z "$SNI" ]] && { msg_error "端口和 SNI 不能为空"; exit 1; }

    generate_reality_keypair
    UUID=$(xray uuid)

    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "$UUID"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$PRIVATE_KEY",
        "publicKey": "$PUBLIC_KEY",
        "shortIds": [""]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

    msg_info "VLESS + Reality 配置已生成"
    echo -e "UUID       : ${GREEN}\( UUID \){NC}"
    echo -e "端口       : ${GREEN}\( PORT \){NC}"
    echo -e "SNI        : ${GREEN}\( SNI \){NC}"
    echo -e "公钥       : ${GREEN}\( PUBLIC_KEY \){NC}"
    echo -e "分享链接示例:"
    echo "vless://$UUID@YOUR_IP:$PORT?security=reality&sni=$SNI&fp=chrome&type=tcp&pbk=$PUBLIC_KEY#VLESS-Reality"
}

# ======================== 模式 2：Shadowsocks 2022 =========================
mode_ss2022() {
    read -r -p "请输入监听端口: " PORT
    [[ -z "$PORT" ]] && { msg_error "端口不能为空"; exit 1; }

    PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)

    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $PORT,
    "protocol": "shadowsocks",
    "settings": {
      "method": "2022-blake3-aes-128-gcm",
      "password": "$PASSWORD",
      "network": "tcp,udp"
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

    msg_info "Shadowsocks-2022 配置已生成"
    echo -e "端口     : ${GREEN}\( PORT \){NC}"
    echo -e "密码     : ${GREEN}\( PASSWORD \){NC}"
    echo -e "分享链接示例:"
    echo "ss://2022-blake3-aes-128-gcm:$PASSWORD@YOUR_IP:$PORT#SS-2022"
}

# ======================== 模式 3：SS 中转 → VLESS Reality =========================
mode_ss_relay() {
    read -r -p "请输入 VLESS Reality 完整分享链接: " VLESS_LINK
    read -r -p "请输入本地 Shadowsocks 监听端口: " LOCAL_PORT
    [[ -z "$VLESS_LINK" || -z "$LOCAL_PORT" ]] && { msg_error "链接和端口不能为空"; exit 1; }

    # 简单解析 vless 链接（支持大多数标准格式）
    UUID=$(echo "$VLESS_LINK" | sed -E 's#^vless://([^@]+)@.*#\1#')
    ADDR_PORT=$(echo "$VLESS_LINK" | sed -E 's#^vless://[^@]+@(.*)(\?.*)?#\1#')
    ADDRESS=$(echo "$ADDR_PORT" | cut -d':' -f1)
    PORT=$(echo "$ADDR_PORT" | cut -d':' -f2)
    QUERY=$(echo "$VLESS_LINK" | sed -E 's#.*\?(.*)#\1#')
    SNI=$(echo "$QUERY" | grep -oP '(?<=sni=)[^&]+')
    PBK=$(echo "$QUERY" | grep -oP '(?<=pbk=)[^&]+')
    SID=$(echo "$QUERY" | grep -oP '(?<=sid=)[^&]+' || echo "")

    PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)

    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $LOCAL_PORT,
    "protocol": "shadowsocks",
    "settings": {
      "method": "aes-256-gcm",
      "password": "$PASSWORD",
      "network": "tcp,udp"
    },
    "tag": "ss-in"
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$ADDRESS",
        "port": $PORT,
        "users": [{"id": "$UUID", "encryption": "none", "flow": "xtls-rprx-vision"}]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "publicKey": "$PBK",
        "shortIds": ["$SID"]
      }
    },
    "tag": "proxy"
  },{
    "protocol": "freedom",
    "tag": "direct"
  }],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]},
      {"type": "field", "outboundTag": "direct", "ip": ["geoip:cn"]}
    ]
  }
}
EOF

    msg_info "Shadowsocks 中转配置已生成"
    echo -e "本地 SS 端口 : ${GREEN}\( LOCAL_PORT \){NC}"
    echo -e "密码         : ${GREEN}\( PASSWORD \){NC}"
    echo -e "加密方式     : \( {GREEN}aes-256-gcm \){NC}"
    echo -e "分享链接示例 :"
    echo "ss://aes-256-gcm:$PASSWORD@YOUR_SERVER_IP:$LOCAL_PORT#SS-to-Reality"
}

# ======================== 主逻辑 =========================
clear
echo -e "\( {GREEN}=== Xray 一键部署脚本（2025/2026 常用版） === \){NC}"
echo "支持系统：Ubuntu/Debian/Alpine/CentOS/Rocky/Alma"

install_dependencies
install_xray

echo -e "\n请选择模式："
echo "  1) VLESS + Reality"
echo "  2) Shadowsocks 2022"
echo "  3) Shadowsocks 中转 → VLESS Reality 出站"
echo -n "输入数字 (1-3): "
read -r CHOICE

case $CHOICE in
    1) mode_vless_reality ;;
    2) mode_ss2022 ;;
    3) mode_ss_relay ;;
    *) msg_error "无效选择"; exit 1 ;;
esac

# 重启服务
systemctl daemon-reload
systemctl restart xray || { /usr/local/bin/xray run -c /usr/local/etc/xray/config.json & }
systemctl enable xray 2>/dev/null || true

msg_info "配置完成！请检查服务状态："
echo "  systemctl status xray"
echo "  journalctl -u xray -n 30 -e"

echo -e "\n\( {GREEN}祝使用愉快！ \){NC}"
