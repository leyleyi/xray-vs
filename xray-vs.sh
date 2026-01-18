#!/bin/bash

# =========================================================
# Xray 终极修复版 - 2024
# 特性：自动解析 VLESS 链接、内核防重复安装、Alpine/Debian 全兼容
# =========================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# --- 核心变量 ---
CONFIG_FILE="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

# --- 1. 环境检查与依赖安装 ---

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误：必须使用 root 用户运行此脚本！${PLAIN}"
        exit 1
    fi
}

check_sys() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}无法检测系统版本，停止运行。${PLAIN}"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${BLUE}1. 正在检查系统依赖...${PLAIN}"
    case "$OS" in
        ubuntu|debian)
            apt-get update -y >/dev/null 2>&1
            apt-get install -y curl wget jq openssl tar >/dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y curl wget jq openssl tar >/dev/null 2>&1
            ;;
        alpine)
            apk add curl wget jq openssl tar ca-certificates bash >/dev/null 2>&1
            ;;
    esac
    echo -e "${GREEN}依赖安装完成。${PLAIN}"
}

# --- 2. Xray 内核处理 (智能跳过) ---

install_xray() {
    echo -e "${BLUE}2. 检查 Xray 内核状态...${PLAIN}"
    if [ -f "$XRAY_BIN" ] && [ -x "$XRAY_BIN" ]; then
        CURRENT_VER=$($XRAY_BIN version | head -n 1 | awk '{print $2}')
        echo -e "${GREEN}检测到 Xray 已安装，版本: ${CURRENT_VER}。跳过安装。${PLAIN}"
        return
    fi

    echo -e "${YELLOW}未找到 Xray，开始安装...${PLAIN}"
    LATEST_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    [ -z "$LATEST_VER" ] && LATEST_VER="v1.8.6"

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) DOWNLOAD_ARCH="64" ;;
        aarch64) DOWNLOAD_ARCH="arm64-v8a" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    TEMP_DIR=$(mktemp -d)
    wget -qO "$TEMP_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$LATEST_VER/Xray-linux-$DOWNLOAD_ARCH.zip"
    
    mkdir -p /usr/local/bin /usr/local/etc/xray
    unzip -q "$TEMP_DIR/xray.zip" -d "$TEMP_DIR"
    mv "$TEMP_DIR/xray" "$XRAY_BIN"
    chmod +x "$XRAY_BIN"
    mv "$TEMP_DIR/geoip.dat" /usr/local/bin/ 2>/dev/null
    mv "$TEMP_DIR/geosite.dat" /usr/local/bin/ 2>/dev/null
    rm -rf "$TEMP_DIR"
    echo -e "${GREEN}Xray 安装成功！${PLAIN}"
}

# --- 3. 工具函数 ---

safe_base64() {
    if [[ "$OS" == "alpine" ]]; then
        base64 | tr -d '\n'
    else
        base64 -w 0
    fi
}

rand_port() {
    # 优先使用 shuf，没有则使用 $RANDOM
    if command -v shuf >/dev/null 2>&1; then
        shuf -i 10000-60000 -n 1
    else
        echo $((RANDOM % 50001 + 10000))
    fi
}

rand_uuid() {
    if [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        # 兼容简易环境
        od -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}'
    fi
}

# --- 4. 强大的 VLESS 解析器 (修复版) ---

parse_vless_link() {
    local link="$1"
    
    # 1. 移除 vless:// 前缀
    link=${link#*://}
    
    # 2. 移除尾部的 URL Fragment (#备注信息)
    link=${link%\#*}
    
    # 3. 提取 UUID (最前面的部分，直到 @)
    V_UUID=${link%%@*}
    
    # 4. 提取剩余部分 (地址:端口?参数)
    local remainder=${link#*@}
    
    # 5. 提取地址和端口 (直到 ?)
    local addr_port=${remainder%%\?*}
    V_ADDR=${addr_port%%:*}
    V_PORT=${addr_port##*:}
    
    # 6. 提取参数部分
    local params=${remainder#*\?}
    
    # 7. 循环解析参数 (兼容任意顺序)
    # 将 & 替换为空格以便 for 循环处理
    local old_ifs="$IFS"
    IFS='&'
    for param in $params; do
        key=${param%%=*}
        value=${param#*=}
        
        case "$key" in
            sni) V_SNI=$value ;;
            pbk) V_PBK=$value ;;
            sid) V_SID=$value ;;
            flow) V_FLOW=$value ;;
            type) V_TYPE=$value ;;
            serviceName) V_GRPC_NAME=$value ;;
            path) V_PATH=$value ;;
        esac
    done
    IFS="$old_ifs"
    
    # 默认值兜底
    [ -z "$V_SNI" ] && V_SNI="addons.mozilla.org"
    [ -z "$V_FLOW" ] && V_FLOW=""
    [ -z "$V_SID" ] && V_SID=""
}

# --- 5. 核心配置逻辑 ---

configure_relay() {
    echo -e "${BLUE}=== 步骤 1: 解析远端 VLESS 链接 ===${PLAIN}"
    echo -e "${YELLOW}提示: 请直接粘贴完整的 vless:// 链接，按回车确认${PLAIN}"
    read -r vless_input
    
    if [[ "$vless_input" != vless://* ]]; then
        echo -e "${RED}错误：输入的不是 vless:// 开头的链接！${PLAIN}"
        exit 1
    fi

    parse_vless_link "$vless_input"
    
    echo -e "------------------------------------------------"
    echo -e "解析成功:"
    echo -e "目标地址 (Addr): ${GREEN}$V_ADDR${PLAIN}"
    echo -e "目标端口 (Port): ${GREEN}$V_PORT${PLAIN}"
    echo -e "SNI: ${GREEN}$V_SNI${PLAIN}"
    echo -e "PublicKey: ${GREEN}$V_PBK${PLAIN}"
    echo -e "ShortId: ${GREEN}$V_SID${PLAIN}"
    echo -e "------------------------------------------------"
    
    if [ -z "$V_ADDR" ] || [ -z "$V_PBK" ]; then
        echo -e "${RED}严重错误: 链接中缺少 Address 或 PublicKey (pbk)。无法配置 Reality 中转。${PLAIN}"
        exit 1
    fi

    echo -e "${BLUE}=== 步骤 2: 配置本机入口 (Shadowsocks) ===${PLAIN}"
    echo -e "1) 2022-blake3-aes-128-gcm (高性能，推荐)"
    echo -e "2) aes-128-gcm (兼容性好)"
    read -p "请选择 (默认1): " ss_choice
    
    if [ "$ss_choice" == "2" ]; then
        IN_METHOD="aes-128-gcm"
        read -p "设置入口密码 (直接回车生成随机): " input_pass
        IN_PASS=${input_pass:-$(rand_port | md5sum | head -c 16)} # 简单的随机密码
    else
        IN_METHOD="2022-blake3-aes-128-gcm"
        echo -e "${YELLOW}正在生成 2022 专用密钥...${PLAIN}"
        IN_PASS=$(openssl rand -base64 16)
    fi

    read -p "设置入口端口 (直接回车生成随机): " input_port
    IN_PORT=${input_port:-$(rand_port)}
    
    # 写入配置
    cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": $IN_PORT,
      "protocol": "shadowsocks",
      "settings": {
        "method": "$IN_METHOD",
        "password": "$IN_PASS",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$V_ADDR",
            "port": $V_PORT,
            "users": [
              {
                "id": "$V_UUID",
                "flow": "$V_FLOW",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$V_SNI",
          "publicKey": "$V_PBK",
          "shortId": "$V_SID",
          "fingerprint": "chrome"
        }
      }
    }
  ]
}
EOF

    # 生成分享链接
    SS_BASE=$(echo -n "${IN_METHOD}:${IN_PASS}" | safe_base64)
    CURRENT_IP=$(curl -s ifconfig.me)
    SHARE_LINK="ss://${SS_BASE}@${CURRENT_IP}:${IN_PORT}#Relay_${V_ADDR}"
    
    echo -e "\n${GREEN}==============================================${PLAIN}"
    echo -e "${GREEN}      配置成功！请复制下方链接到客户端      ${PLAIN}"
    echo -e "${GREEN}==============================================${PLAIN}"
    echo -e "中转链路: 本机 [${IN_PORT}] -> 落地机 [${V_ADDR}:${V_PORT}]"
    echo -e ""
    echo -e "${YELLOW}${SHARE_LINK}${PLAIN}"
    echo -e ""
}

configure_vless_local() {
    # 简化的 VLESS Reality 逻辑
    echo -e "${BLUE}=== 配置 VLESS Reality 本地模式 ===${PLAIN}"
    read -p "端口 (默认随机): " p
    PORT=${p:-$(rand_port)}
    UUID=$(rand_uuid)
    KEYS=$($XRAY_BIN x25519)
    PRI=$(echo "$KEYS" | grep Private | awk '{print $3}')
    PUB=$(echo "$KEYS" | grep Public | awk '{print $3}')
    SID=$(openssl rand -hex 4)
    
    cat > $CONFIG_FILE <<EOF
{
  "inbounds":[{
    "port":$PORT,"protocol":"vless",
    "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":"addons.mozilla.org:443","serverNames":["addons.mozilla.org"],"privateKey":"$PRI","shortIds":["$SID"]}}
  }],
  "outbounds":[{"protocol":"freedom"}]
}
EOF
    echo -e "\n${GREEN}链接:${PLAIN} vless://$UUID@$(curl -s ifconfig.me):$PORT?security=reality&encryption=none&pbk=$PUB&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=addons.mozilla.org&sid=$SID#Reality_Local"
}

setup_service() {
    echo -e "${BLUE}3. 重启 Xray 服务...${PLAIN}"
    if command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray
After=network.target
[Service]
ExecStart=$XRAY_BIN run -c $CONFIG_FILE
Restart=always
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable xray
        systemctl restart xray
    elif [ -f /sbin/openrc-run ]; then
        # Alpine
        cat > /etc/init.d/xray <<EOF
#!/sbin/openrc-run
name="Xray"
command="$XRAY_BIN"
command_args="run -c $CONFIG_FILE"
command_background=true
pidfile="/run/xray.pid"
depend() { need net; }
EOF
        chmod +x /etc/init.d/xray
        rc-update add xray default
        rc-service xray restart
    fi
}

# --- 主入口 ---

check_root
check_sys
install_dependencies
install_xray

clear
echo -e "${GREEN}=== Xray 高级配置脚本 ===${PLAIN}"
echo -e "${YELLOW}本机 IP: $(curl -s ifconfig.me)${PLAIN}"
echo -e "1. VLESS Reality (本机直连)"
echo -e "2. Shadowsocks 2022 (本机直连)"
echo -e "3. Shadowsocks 中转 (输入 VLESS 链接 -> 生成中转 SS)"
echo -e "-------------------------"
read -p "请输入模式 [1-3]: " mode

case $mode in
    1) configure_vless_local ;;
    2) echo "暂未实装，请用模式3自建" ;; 
    3) configure_relay ;;
    *) echo -e "${RED}无效选择${PLAIN}"; exit 1 ;;
esac

setup_service
echo -e "${GREEN}服务已重启。如果连不上，请检查防火墙放行端口。${PLAIN}"
