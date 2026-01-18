```bash
#!/bin/bash

# This script installs and configures Xray on various Linux distributions.
# Supported: Ubuntu, Debian, Alpine, CentOS.
# It prompts the user to select a mode and configure accordingly.

# Function to detect the OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        echo "Unsupported OS."
        exit 1
    fi

    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt"
            ;;
        alpine)
            PKG_MANAGER="apk"
            ;;
        centos)
            PKG_MANAGER="yum"
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Function to install dependencies
install_deps() {
    case $PKG_MANAGER in
        apt)
            apt update -y
            apt install -y wget unzip curl jq
            ;;
        apk)
            apk update
            apk add wget unzip curl jq
            ;;
        yum)
            yum update -y
            yum install -y wget unzip curl jq epel-release
            ;;
    esac
}

# Function to install Xray
install_xray() {
    mkdir -p /usr/local/bin /etc/xray
    wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O xray.zip
    unzip xray.zip -d /usr/local/bin
    mv /usr/local/bin/xray /usr/local/bin/xray
    chmod +x /usr/local/bin/xray
    rm xray.zip
}

# Function to generate UUID
generate_uuid() {
    uuid=$(cat /proc/sys/kernel/random/uuid)
    echo $uuid
}

# Function to create systemd service
create_service() {
    cat << EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xray -config /etc/xray/config.json
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray
}

# Function for VLESS Reality mode
config_vless_reality() {
    read -p "Enter port: " port
    read -p "Enter SNI (e.g., www.example.com): " sni

    uuid=$(generate_uuid)

    cat << EOF > /etc/xray/config.json
{
  "inbounds": [
    {
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$sni:443",
          "xver": 0,
          "serverNames": ["$sni"],
          "privateKey": "your_private_key_here",  // Generate with xray x25519
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": [""]  // Optional short IDs
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

    # Note: User needs to generate and replace privateKey and publicKey using 'xray x25519'
    echo "VLESS Reality configured."
    echo "Client config: vless://$uuid@your_ip:$port?security=reality&sni=$sni&fp=chrome&type=tcp&flow=xtls-rprx-vision#VLESS-Reality"
}

# Function for Shadowsocks 2022 mode
config_ss2022() {
    read -p "Enter port: " port

    password=$(openssl rand -base64 16)

    cat << EOF > /etc/xray/config.json
{
  "inbounds": [
    {
      "port": $port,
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "$password",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

    echo "Shadowsocks 2022 configured."
    echo "Client config: ss://2022-blake3-aes-128-gcm:$password@your_ip:$port#SS2022"
}

# Function for Shadowsocks Relay mode
config_ss_relay() {
    read -p "Enter VLESS Reality config (e.g., vless://uuid@ip:port?...): " vless_config

    # Parse VLESS config (simplified parsing)
    uuid=$(echo $vless_config | sed -E 's/vless:\/\/([^@]+)@.*/\1/')
    address=$(echo $vless_config | sed -E 's/.*@([^:]+):.*/\1/')
    port=$(echo $vless_config | sed -E 's/.*:([0-9]+)\?.*/\1/')
    sni=$(echo $vless_config | grep -oP 'sni=\K[^&]+')

    read -p "Enter local SS port: " local_port
    ss_password=$(openssl rand -base64 16)

    cat << EOF > /etc/xray/config.json
{
  "inbounds": [
    {
      "port": $local_port,
      "protocol": "shadowsocks",
      "settings": {
        "method": "aes-256-gcm",
        "password": "$ss_password",
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
            "address": "$address",
            "port": $port,
            "users": [
              {
                "id": "$uuid",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$sni:443",
          "serverNames": ["$sni"]
        }
      }
    }
  ]
}
EOF

    echo "Shadowsocks Relay configured."
    echo "Relay config: ss://aes-256-gcm:$ss_password@your_local_ip:$local_port#SS-Relay"
}

# Main script
detect_os
install_deps
install_xray

echo "Select mode:"
echo "1. Vless Reality"
echo "2. Shadowsocks2022"
echo "3. Shadowsocks中转"
read -p "Enter number: " choice

case $choice in
    1)
        config_vless_reality
        ;;
    2)
        config_ss2022
        ;;
    3)
        config_ss_relay
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

create_service
echo "Xray service started. Replace 'your_ip' and 'your_private_key_here' as needed."
```
