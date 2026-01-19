# EXRAY使用教程

```
bash -c "$(curl -fsSL https://github.com/leyleyi/exray/raw/refs/heads/main/exray.sh)"
```

**必须以 root 权限执行**

## 安装完成后使用方式

下载sh文件 重命名为xray-vs.sh 

```
chmod +x xray-vs.sh
mv xray-vs.sh /usr/local/bin/exray
```

SSH直接输入

```
exray
```

命令进入管理面板



## 管理面板选项一览

text



```
1) VLESS Reality Vision
 2) Shadowsocks
 3) Trojan + Reality
 4) SS → VLESS Reality 中继
 5) 显示当前配置文件路径
 6) 开启 BBR 加速
 7) 重启 Xray 服务
 8) 停止 Xray 服务
 9) 卸载 Xray
 0) 退出程序
```

## 配置文件位置

```
/usr/local/etc/xray/config.json
```

## Shadowsocks 支持的加密方式

- 2022-blake3-aes-128-gcm（默认推荐）
- chacha20-ietf-poly1305
- aes-256-gcm
- aes-128-gcm

## 快速更新脚本

再次运行一键安装命令即可覆盖更新到最新版本：

```
bash -c "$(curl -fsSL https://github.com/leyleyi/exray/raw/refs/heads/main/exray.sh)"
```
