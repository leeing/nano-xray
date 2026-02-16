# nano-xray

单机多服务 Caddy 管理工具 — 一键部署 Xray 代理节点 + 通用服务反代。

## 特性

- **双协议**: VLESS+WS+TLS 和 VMess+WS+TLS 同时支持
- **共享配置**: 所有节点共用 UUID 和路径，客户端只需配一次
- **自动 TLS**: Caddy + Cloudflare DNS-01 自动申请和续期证书
- **自动 DNS**: 添加/删除节点时自动操作 Cloudflare DNS 记录
- **零停机**: `reload` 命令热加载 Caddy 配置
- **零依赖**: 仅需 Python 3 (Debian 自带) + Docker

## 前提

1. Debian 服务器，已安装 `docker` 和 `docker compose`
2. 域名 DNS 托管在 Cloudflare
3. Cloudflare API Token (权限: `Zone DNS: Edit` + `Zone: Zone: Read`)

## 快速开始

```bash
# 克隆
git clone <repo> && cd nano-xray

# 配置 .env
cp .env.example .env
# 编辑 .env，填入 CF_API_TOKEN

# 初始化（自动读取 .env）
python3 deploy.py init

# 添加代理节点（自动创建 DNS 记录）
python3 deploy.py add-proxy -d uk.example.com
python3 deploy.py add-proxy -d jp.example.com

# 一键启动
python3 deploy.py up
```

## 命令

| 命令 | 说明 |
|------|------|
| `init` | 初始化 (自动检测 IP、生成默认 UUID 和路径) |
| `add-proxy -d <域名>` | 添加代理节点 (自动创建 DNS) |
| `add-service -d <域名> -t <目标>` | 添加服务反代 |
| `remove -d <域名>` | 删除绑定 (自动删除 DNS) |
| `list` | 列出所有服务 |
| `up` | 生成配置 + 启动 Docker (首次) |
| `reload` | 生成配置 + 热加载 (日常) |
| `generate` | 仅生成配置文件 |
| `check-traffic` | 检查当月流量，超限自动封端口 |
| `update-ips -d <域名>` | 管理服务 IP 白名单 |

### init 参数

| 参数 | 说明 |
|------|------|
| `-t, --token` | Cloudflare API Token (也可在 .env 中配置) |
| `-r, --redirect` | 默认重定向 URL (也可在 .env 中配置) |
| `-u, --uuid` | 指定默认 UUID (也可在 .env 中配置) |
| `--vless-ws-path` | 指定 VLESS WS 路径 (也可在 .env 中配置) |
| `--vmess-ws-path` | 指定 VMess WS 路径 (也可在 .env 中配置) |

### 通用参数

| 参数 | 适用命令 | 说明 |
|------|---------|------|
| `-f, --force` | add-proxy, add-service | 域名已存在时强制覆盖 |
| `--no-dns` | add-proxy, add-service | 跳过自动 DNS 创建 |
| `--keep-dns` | remove | 删除时保留 DNS 记录 |
| `--new-uuid` | add-proxy | 强制生成新 UUID |
| `--allow-ips` | add-service | IP 白名单，逗号分隔 (如 `1.2.3.0/24,5.6.7.8`) |

### IP 白名单示例

```bash
# 初始设置白名单
python3 deploy.py add-service -d admin.example.com -t localhost:8080 --allow-ips 1.2.3.0/24,5.6.7.8

# 追加 IP
python3 deploy.py update-ips -d admin.example.com --add 10.0.0.0/8

# 删除 IP
python3 deploy.py update-ips -d admin.example.com --remove 5.6.7.8

# 查看当前白名单
python3 deploy.py update-ips -d admin.example.com --list

# 不限制 IP
python3 deploy.py add-service -d api.example.com -t localhost:9090
```

## .env 配置

从 `.env.example` 复制并编辑：

```bash
CF_API_TOKEN=xxx              # 必填
DEFAULT_UUID=                 # 可选，init 时自动生成
DEFAULT_VLESS_WS_PATH=        # 可选，init 时自动生成
DEFAULT_VMESS_WS_PATH=        # 可选，init 时自动生成
REDIRECT_URL=                 # 可选，默认 https://www.qadmlee.com

# 流量监控
TRAFFIC_LIMIT_GB=180          # 流量阈值 (GB)，check-traffic 必填
TELEGRAM_BOT_TOKEN=           # 可选，告警通知
TELEGRAM_CHAT_ID=             # 可选，告警通知
```

优先级：**CLI 参数 > 环境变量 > `.env` 文件**

## 流量监控

防止 GCP 等云服务流量超额计费。基于 vnstat + ufw，支持 Telegram 告警。

### 前提

```bash
apt install vnstat    # 流量统计
ufw enable            # 防火墙已启用
```

### 配置 cron

```bash
# 每小时检查一次
crontab -e
0 * * * * cd /root/nano-xray && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1
```

### 工作原理

1. 读取 vnstat 当月出站流量 (tx)
2. 流量 ≥ 阈值 → `ufw deny 443` 封端口 + Telegram 告警
3. 流量 < 阈值且端口被封 → 自动解封 + Telegram 通知
4. vnstat 不可用 → Telegram 告警
5. 封禁后每小时重新检查并强制执行封禁（幂等）

## 文件结构

```
nano-xray/
├── deploy.py              ← 管理脚本 (零依赖单文件)
├── .env                   ← 环境配置 (不提交 Git)
├── .env.example           ← 配置模板
├── services.json          ← 服务注册表 (自动生成)
└── generated/             ← 自动生成的部署文件
    ├── Caddyfile
    ├── docker-compose.yml
    └── xray/*/config.json
```
