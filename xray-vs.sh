#!/usr/bin/env bash
# =====================================================================
# Xray 一键部署脚本 - 优化版（2026常用）
# 支持：VLESS+Reality / SS2022 / SS中转到VLESS Reality
# =====================================================================

set -euo pipefail

# ======================== 颜色 & 输出函数 =========================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

err()  { echo -e "\( {RED}[ERROR] \){NC} $*" >&2; }
info() { echo -e "\( {GREEN}[INFO] \){NC} $*"; }
warn() { echo -e "\( {YELLOW}[WARN] \){NC} $*"; }

# ======================== 工具函数 =========================
check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限运行"
        err "请使用: sudo bash $0  或  su - 切换 root"
        exit 1
    fi
}

rand_uuid() {
    if [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        openssl rand -hex 16 2>/dev/null | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2-\3\4-\5\6-\7\8-\9\10\11\12\13\14\15\16/' || \
        head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | sed 's/\(..\)\{8\}/&-/;s/\(..\)\{4\}/&-/;s/\(..\)\{4\}/&-/;s/\(..\)\{4\}/&-/;s/$//'
    fi
}

rand_pass() {
    openssl rand -base64 16 2>/dev/null | tr -d '\n\r/+' | head -c 22 || \
    head -c 16 /dev/urandom | base64 | tr -d '\n\r/+' | head -c 22
}

rand_port() {
    shuf -i 10000-65535 -n 1 2>/dev/null || echo $((RANDOM % 55536 + 10000))
}

# ======================== 安装依赖 & Xray =========================
install_deps_and_xray() {
    info "检测系统并安装依赖..."

    if command -v apt >/dev/null; then
        apt update -y >/dev/null 2>&1 || true
        apt install -y curl unzip jq openssl ca-certificates >/dev/null 2>&1
    elif command -v apk >/dev/null; then
        apk update >/dev/null 2>&1
        apk add curl unzip jq openssl ca-certificates
    elif command -v yum >/dev/null || command -v dnf >/dev/null; then
        { yum makecache -y || dnf makecache -y; } >/dev/null 2>&1
        { yum install -y curl unzip jq openssl ca-certificates || dnf install -y curl unzip jq openssl ca-certificates; } >/dev/null 2>&1
    else
        err "不支持的包管理器"
        exit 1
    fi

    info "安装/更新 Xray 核心..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || \
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta

    if [ ! -x /usr/local/bin/xray ]; then
        err "Xray 安装失败：/usr/local/bin/xray 不存在"
        err "请检查网络或手动安装：https://github.com/XTLS/Xray-install"
        exit 1
    fi

    mkdir -p /usr/local/etc/xray
    chmod 755 /usr/local/etc/xray
}

# ======================== 模式 3：SS 中转到 VLESS Reality =========================
mode_ss_to_reality() {
    read -r -p "请输入 VLESS Reality 完整分享链接: " vless_link
    read -r -p "请输入本地 Shadowsocks 端口 (默认随机 10000-65535): " local_port
    local_port=\( {local_port:- \)(rand_port)}

    # 清理链接中的 # 标签部分
    vless_link_clean="${vless_link%%#*}"

    # 解析关键参数
    uuid=$(echo "$vless_link_clean" | sed -E 's#^vless://([^@]+)@.*#\1#')
    addr_port=$(echo "$vless_link_clean" | sed -E 's#^vless://[^@]+@(.*)(\?.*)?#\1#')
    address=$(echo "$addr_port" | cut -d':' -f1)
    port=$(echo "$addr_port" | cut -d':' -f2- | cut -d'?' -f1)
    query="${vless_link_clean#*\?}"
    sni=$(echo "$query" | grep -oP '(?<=sni=)[^&]+' || echo "")
    pbk=$(echo "$query" | grep -oP '(?<=pbk=)[^&]+' || echo "")
    sid=$(echo "$query" | grep -oP '(?<=sid=)[^&]+' || echo "")
    flow=$(echo "$query" | grep -oP '(?<=flow=)[^&]+' || echo "xtls-rprx-vision")

    if [[ -z "$uuid" || -z "$address" || -z "$port" || -z "$sni" || -z "$pbk" ]]; then
        err "VLESS 链接解析失败，请检查格式是否正确"
        exit 1
    fi

    password=$(rand_pass)

    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $local_port,
    "protocol": "shadowsocks",
    "settings": {
      "method": "aes-256-gcm",
      "password": "$password",
      "network": "tcp,udp"
    },
    "tag": "ss-in"
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$address",
        "port": $port,
        "users": [{"id": "$uuid", "encryption": "none", "flow": "$flow"}]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$sni:443",
        "xver": 0,
        "serverNames": ["$sni"],
        "publicKey": "$pbk",
        "shortIds": ["$sid"]
      }
    },
    "tag": "proxy"
  }, {
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

    info "配置已写入 /usr/local/etc/xray/config.json"
    echo ""
    echo -e "本地 SS 信息："
    echo -e "  端口     : ${GREEN}\( local_port \){NC}"
    echo -e "  密码     : ${GREEN}\( password \){NC}"
    echo -e "  加密     : aes-256-gcm"
    echo -e "  服务器   : 你的服务器IP"
    echo ""
    echo "分享链接示例： ss://aes-256-gcm:$password@你的IP:\( local_port#中转- \)(hostname)"
}

# ======================== 主逻辑 =========================
clear
check_root
install_deps_and_xray

echo -e "\n\( {GREEN}=== 选择模式（当前仅支持中转模式3，如需其他可后续扩展） === \){NC}"
echo "  3) Shadowsocks 中转 → VLESS Reality 出站"
echo -n "输入数字 (3): "
read -r choice

if [[ "$choice" != "3" ]]; then
    err "当前版本仅实现模式 3，如需 1/2 请回复需求"
    exit 1
fi

# 清理旧进程
pkill -f xray 2>/dev/null || true

mode_ss_to_reality

# 测试配置
if /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
    info "配置语法检查通过"
else
    err "配置测试失败！请检查链接格式或参数"
    cat /usr/local/etc/xray/config.json
    exit 1
fi

# 启动服务
if command -v systemctl >/dev/null; then
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart xray 2>/dev/null || {
        warn "systemctl restart 失败，尝试手动启动"
        /usr/local/bin/xray run -c /usr/local/etc/xray/config.json &
    }
    systemctl enable xray 2>/dev/null || true
    info "服务已通过 systemd 启动/重启"
    systemctl status xray --no-pager -l | head -n 15
else
    warn "无 systemd，使用 nohup 后台运行"
    nohup /usr/local/bin/xray run -c /usr/local/etc/xray/config.json >/var/log/xray.log 2>&1 &
    info "Xray 已后台运行，日志：tail -f /var/log/xray.log"
fi

echo ""
info "部署完成！如连接不上："
echo "  1. 检查防火墙是否放行 $local_port"
echo "  2. tail -f /var/log/xray.log 或 journalctl -u xray -e"
echo "  3. 确认 VLESS 出站节点是否可用"
