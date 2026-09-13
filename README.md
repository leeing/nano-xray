# nano-xray

零第三方 Python 运行依赖的 Caddy + Xray 部署脚本。全部生产运行代码都集成在一个 `deploy.py` 中，适合直接下载到 Debian 服务器运行。

项目提供两组能力：

- **单机部署**：在一台服务器上管理多个 VLESS/VMess 代理域名和普通 HTTPS 反向代理。这部分可以直接用于服务器部署。
- **Node + Link 控制面**：在管理机上登记多台 VPS、导入已有服务、创建有向 Link，并生成 host-l3 节点配置和部署计划。当前只生成和校验计划，不会修改远程节点网络。

Node 是完整且可独立使用的 VPS；Link 是额外、显式的有向中转关系。创建 `hk1 → us1` 不会取消 HK1 或 US1 的独立代理，也不会自动创建反向 Link 或隐式三跳。

## 目录

- [特性](#特性)
- [运行要求](#运行要求)
- [单文件下载安装](#单文件下载安装)
- [单机首次部署](#单机首次部署)
- [日常单机管理](#日常单机管理)
- [普通服务反代](#服务反代示例)
- [客户端配置参数](#客户端配置参数)
- [流量监控](#流量监控)
- [Node + Link 使用流程](#v2-node--link-基础功能)
- [当前实现边界](#当前实现边界)
- [文件与数据目录](#文件结构)
- [常见问题](#常见问题)
- [开发验证](#开发验证)

## 特性

- **双协议**: VLESS+WS+TLS 和 VMess+WS+TLS 同时支持
- **默认共享配置**: 单机模式新增代理默认共用初始化时的 UUID 和路径，也可为某个代理单独指定
- **自动 TLS**: Caddy + Cloudflare DNS-01 自动申请和续期证书
- **自动 DNS**: 添加/删除节点时自动操作 Cloudflare DNS 记录
- **按需更新**: 容器集合不变时，`reload` 热加载 Caddy；容器变化时自动执行 Compose 更新
- **单文件交付**: 远程服务器只需下载 `deploy.py`，无需安装本项目或 Python package
- **零 Python 依赖**: 只使用 Python 标准库；运行容器服务时需要 Docker
- **拓扑控制面**: 支持版本化 Node/Link、稳定资源分配、tombstone 和可审查 Plan

## 运行要求

### 单机部署

1. Debian 12 或相近 Debian 环境。
2. Python 3.11 或更高版本。
3. root 权限；`prepare` 会安装并配置系统组件。
4. 域名 DNS 托管在 Cloudflare。
5. Cloudflare API Token，权限至少为 `Zone DNS: Edit` 和 `Zone: Zone: Read`。
6. 公网 TCP 80、TCP 443 和 UDP 443 可达。

Docker 无需预装，`prepare` 会安装 Docker Engine 和 Compose 插件。

### Node + Link 管理

1. 管理机安装 Python 3.11 或更高版本。
2. 通过 SSH 导入节点时，需要 OpenSSH 客户端和已经核对的 SSH host key。
3. 仅执行 `node add`、本地文件导入、`link` 和 `plan` 时不需要 root。

## 单文件下载安装

`deploy.py` 所在目录就是运行目录，后续的 `.env`、`services.json`、`generated/`、`inventory/` 和 `state/` 都会创建在这里。不要从临时目录运行。

```bash
sudo mkdir -p /root/nano-xray
cd /root/nano-xray

sudo curl -fL https://your-download-host.example/deploy.py -o deploy.py
sudo chmod 0755 deploy.py
python3 deploy.py --help
```

把示例 URL 替换为实际发布地址。更新时只需备份并覆盖这个文件：

```bash
cd /root/nano-xray
cp deploy.py deploy.py.bak
curl -fL https://your-download-host.example/deploy.py -o deploy.py
chmod 0755 deploy.py
python3 deploy.py --help
```

覆盖脚本不会主动删除现有 `.env`、`services.json`、`generated/`、`inventory/` 或 `state/`。

## 单机首次部署

### 1. 初始化服务器

```bash
# 服务器初始化（安装 Docker/BBR/UFW/fail2ban，生成 .env）
python3 deploy.py prepare
```

`prepare` 必须由 root 执行。它会安装基础工具、vnstat、nftables、Docker、UFW 和 fail2ban，应用 BBR/TCP 参数，放行 SSH/HTTP/HTTPS/HTTP3 端口，并添加每小时一次及开机时执行的流量检查 cron。已有 `.env` 不会被覆盖。

`prepare` 只创建 `.env` 模板，不会在模板尚未填写时尝试安装公钥。root 公钥在后续 `init` 阶段读取和配置。

`--configure-ssh-password-auth` 是独立的兼容选项：

```bash
python3 deploy.py prepare --configure-ssh-password-auth
```

该选项会通过受管 drop-in 启用 root、密码和键盘交互认证，并在 reload 前完成配置校验。默认不使用该参数时，`prepare` 保留现有密码认证策略。

### 2. 配置 `.env`

至少填写 Cloudflare Token 和重定向地址，并建议同时填写一个管理公钥：

```dotenv
CF_API_TOKEN=your-cloudflare-api-token
REDIRECT_URL=https://www.example.com
SSH_KEY_1=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@mac
```

多个管理员可以继续增加：

```dotenv
SSH_KEY_2=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin2
SSH_KEY_3=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... emergency
```

### 3. 初始化服务注册表和 SSH 公钥

```bash
python3 deploy.py init
```

`init` 会读取 `.env` 中严格命名为 `SSH_KEY_1`、`SSH_KEY_2` 等的公钥，将它们原子写入 `/root/.ssh/authorized_keys`，并把目录和文件权限分别设置为 `0700`、`0600`。随后创建 `/etc/ssh/sshd_config.d/00-nano-xray.conf`：

```text
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin prohibit-password
```

脚本会先运行 `sshd -t`，再用 `sshd -T` 核对最终生效值，成功后优先 reload `sshd.service`，并兼容回退到 `ssh.service`。校验或 reload 失败会恢复原 drop-in。未配置任何 `SSH_KEY_N` 时，`init` 不会改写现有 `authorized_keys` 或 sshd 策略。

除 SSH 配置外，`init` 还会检测公网 IPv4，生成或采用指定的 UUID 与 WebSocket 路径，写入 `services.json`，并验证 Cloudflare Token。如果 `services.json` 已存在，`init` 会先完成幂等的 SSH 公钥检查，再询问是否覆盖服务注册表；选择不覆盖不会撤销已经完成的 SSH 修复。已有生产节点不要随意覆盖 `services.json`。

也可以用命令行明确指定参数：

```bash
python3 deploy.py init \
  --token 'your-cloudflare-api-token' \
  --redirect 'https://www.example.com' \
  --uuid '00000000-0000-4000-8000-000000000000' \
  --vless-ws-path '/vless-secret-path' \
  --vmess-ws-path '/vmess-secret-path'
```

### 4. 添加代理并启动

```bash
python3 deploy.py add-proxy --domain hk.example.com
python3 deploy.py add-proxy --domain jp.example.com
python3 deploy.py up --generate
```

`add-proxy` 默认使用初始化时的 UUID 和路径，创建 DNS-only Cloudflare A 记录，并只更新源配置。首次启动必须使用 `up --generate`。

常用变体：

```bash
# 指定 UUID
python3 deploy.py add-proxy -d hk.example.com -u 'UUID'

# 单独生成新 UUID
python3 deploy.py add-proxy -d hk.example.com --new-uuid

# DNS 由其他系统管理
python3 deploy.py add-proxy -d hk.example.com --no-dns

# 覆盖同域名服务，并允许更新不同 IP 的 DNS 记录
python3 deploy.py add-proxy -d hk.example.com --force
```

## 命令

| 命令 | 说明 |
|------|------|
| `prepare` | 安装 Docker/UFW/fail2ban/nftables、创建 `.env`；可选配置密码认证策略 |
| `init` | 从 `.env` 安装 root 公钥、验证 sshd，并初始化服务注册表 |
| `add-proxy -d <域名>` | 添加代理节点 (自动创建 DNS) |
| `add-service -d <域名> -t <目标>` | 添加服务反代 (localhost 自动转为 host.docker.internal) |
| `remove -d <域名>` | 删除绑定 (自动删除 DNS) |
| `list` | 列出所有服务 |
| `up` | 使用现有配置启动 Docker，不重新生成配置 |
| `up --generate` | 重新生成配置并启动 Docker（首次部署或更新源配置后） |
| `reload` | 重新生成配置；容器集合不变时热加载 Caddy，否则更新 Compose |
| `generate` | 仅生成配置文件 |
| `check-traffic` | 检查当月流量，超限后除 TCP 22 外锁定入站、出站和转发流量 |
| `update-ips -d <域名>` | 管理服务 IP 白名单 |
| `node add/import/list/update/remove/detach` | 管理 v2 Node 期望配置 |
| `link add/list/enable/disable/remove` | 管理 v2 有向 Link 期望配置 |
| `plan` | 生成 v2 影响范围与发布计划，不修改远程节点 |
| `apply --plan <文件>` | 校验计划；WG L3 发布闸门通过前会安全拒绝远程应用 |

## 日常单机管理

### 查看服务

```bash
python3 deploy.py list
```

输出包含代理域名、容器名、UUID、VLESS/VMess 路径和普通反代目标。

### 删除服务

```bash
# 删除源配置，并尝试删除 Cloudflare DNS 记录
python3 deploy.py remove --domain hk.example.com

# 删除源配置，但保留 DNS 记录
python3 deploy.py remove --domain hk.example.com --keep-dns

# 让删除结果生效
python3 deploy.py reload
```

### 配置生成与启动语义

| 命令 | 是否重新生成 `generated/` | 是否操作容器 |
|---|---:|---:|
| `generate` | 是 | 否 |
| `up` | 否 | 执行 `docker compose up -d` |
| `up --generate` | 是 | 执行 `docker compose up -d` |
| `reload` | 是 | 容器集合变化时 compose up，否则热加载 Caddy |

持久修改应写入 `.env`、`services.json` 或通过脚本命令完成。`generate`、`up --generate` 和 `reload` 会覆盖脚本管理的生成文件。

### 查看容器和日志

```bash
docker compose -f generated/docker-compose.yml ps
docker logs caddy --tail 100
docker logs xray-hk --tail 100
```

## v2 Node + Link 基础功能

### 当前模型

- **Node** 是一台完整、可独立提供代理服务的 VPS。
- **Service** 是 Node 上的 Xray 代理或普通反向代理。
- **Link** 是明确的有向中转关系，例如 `hk1 → us1`。

创建 `hk1 → us1` 只增加一个经 US1 出口的入口身份，不取消 HK1 和 US1 的本机直出。存在 `hk1 → us1` 和 `us1 → de1` 时，也不会自动产生 `hk1 → us1 → de1`。

所有部署运行代码均内嵌在 `deploy.py`。Node + Link 控制面数据写在管理目录中：

```text
inventory/topology.json
inventory/nodes/<node-id>/services.json
state/staging/<topology-hash>/<node-id>/
plans/*.json
```

这些文件可能含有 UUID、Cloudflare Token 或节点信息，默认不提交 Git；仍需自行限制访问并备份。

### 登记新 Node

```bash
python3 deploy.py node add hk1 \
  --host root@203.0.113.10 \
  --endpoint 203.0.113.10 \
  --domain hk.example.com \
  --remote-dir /root/nano-xray \
  --network-profile host-l3 \
  --ssh-key ~/.ssh/nano_xray_ed25519
```

参数说明：

| 参数 | 说明 |
|---|---|
| `node_id` | 小写 Node ID，只允许小写字母、数字和连字符 |
| `--host` | OpenSSH 目标，例如 `root@203.0.113.10` |
| `--endpoint` | WireGuard 公网地址；省略时取 `--host` 中 `@` 后的部分 |
| `--domain` | 新 Node 的默认代理域名；`node add` 时必需 |
| `--remote-dir` | 远程项目目录，默认 `/root/nano-xray` |
| `--network-profile` | `bridge` 或 `host-l3`，默认 `bridge` |
| `--ssh-key` | OpenSSH 私钥文件路径 |

`node add` 只修改管理机上的期望配置，并为该 Node 创建包含随机 UUID 和路径的本地 `services.json`。它不会连接 VPS、创建 Cloudflare DNS 或启动远程容器。

### 导入已有 Node

通过 SSH 读取远程 `services.json`：

```bash
python3 deploy.py node import hk1 \
  --host root@203.0.113.10 \
  --remote-dir /root/nano-xray \
  --network-profile host-l3 \
  --ssh-key ~/.ssh/nano_xray_ed25519
```

OpenSSH 使用 `BatchMode=yes` 和正常的 `known_hosts` 校验。首次导入前应手工连接并核对 host key：

```bash
ssh -i ~/.ssh/nano_xray_ed25519 root@203.0.113.10
```

也可以从本地备份导入，不发起 SSH：

```bash
python3 deploy.py node import hk1 \
  --host root@203.0.113.10 \
  --services-file ./backups/hk1-services.json \
  --network-profile host-l3
```

导入会保留原服务域名、UUID、WebSocket 路径和容器名，并为 host-l3 代理服务持久分配互不冲突的 loopback 端口。

### 查看和更新 Node

```bash
python3 deploy.py node list

python3 deploy.py node update hk1 \
  --host root@203.0.113.20 \
  --endpoint 203.0.113.20 \
  --remote-dir /root/nano-xray \
  --network-profile host-l3 \
  --ssh-key ~/.ssh/nano_xray_ed25519
```

`node update` 只需填写要修改的字段。它同样只修改本地期望配置。

### 创建有向 Link

两端 Node 必须已经登记并使用 `host-l3`。`--entry-service` 必须对应 source Node 的 proxy Service；可填写完整域名、域名第一段、容器名，或去掉 `xray-` 前缀后的名字。

```bash
python3 deploy.py node list
cat inventory/nodes/hk1/services.json

python3 deploy.py link add hk1 us1 \
  --id hk1-us1 \
  --entry-service xray-hk \
  --protocol both \
  --transport wg-l3
```

`--protocol` 可选 `vmess`、`vless` 或 `both`，默认 `both`。脚本会稳定分配 `/30` 地址、`nxNNNN` 接口名、WG UDP 端口、socket mark、路由表、规则优先级和 Link 专属 UUID。后续新增其他 Link 不会改变已有分配。

### 管理 Link 生命周期

```bash
python3 deploy.py link list
python3 deploy.py link disable hk1-us1
python3 deploy.py link enable hk1-us1
python3 deploy.py link remove hk1-us1
```

- `disable` 保留 Link 和资源，但渲染时不提供该 Link 的客户端和出站。
- `enable` 使用原资源恢复期望配置。
- `remove` 将 Link 转为 tombstone，避免旧地址、端口、mark 和 UUID 被立即复用。

这些命令目前只修改期望配置，不会立即改变远程服务器。

### 从 Node 移除 Link 关系

```bash
# 移除所有指向 us1 的 Link
python3 deploy.py node detach us1 --incoming

# 移除所有从 hk1 发出的 Link
python3 deploy.py node detach hk1 --outgoing

# 移除 hk1 的全部入向和出向 Link
python3 deploy.py node detach hk1 --all-links
```

detach 不删除 Node 的独立服务。删除 Node 前必须先移除活动 Link；存在待清理 tombstone 时，`node remove` 也会拒绝：

```bash
python3 deploy.py node remove hk1
```

### 生成并检查 Plan

```bash
# 全拓扑
mkdir -p plans
python3 deploy.py plan --save plans/all.json

# 指定 Link；自动包含两端 Node
python3 deploy.py plan --links hk1-us1 --save plans/hk1-us1.json

# 指定一个或多个 Node
python3 deploy.py plan --nodes hk1,us1 --save plans/hk-us.json
```

选择 Link 时会包含它的两端；选择 Node 时会包含与该 Node 直接相连的 Link 及另一端，但不会递归扩展为未声明的多跳拓扑。

Plan 记录 topology SHA-256、受影响 Node/Link、tombstone 清理动作、staging 目录和每个生成文件的 SHA-256。host-l3 产物示例：

```text
state/staging/<topology-hash-prefix>/<node-id>/
├── .env
├── caddy/Caddyfile
├── docker-compose.yml
├── node-manifest.json
└── xray/<service-id>/config.json
```

生成的 Xray 配置保留原用户本机直出，并为启用的 Link 增加专属用户、按 email 匹配的路由、`sendThrough` 和 socket mark。Caddy/Xray 使用 host networking 和持久分配的 loopback 端口。

### 当前 apply 行为

```bash
python3 deploy.py apply --plan plans/hk1-us1.json
```

`apply` 会先确认 Plan 的 topology hash 仍与当前期望配置一致。拓扑在 Plan 生成后发生变化时会报告 Plan 已过期。

当前 Plan 明确包含 `apply_supported: false`，因此未过期的 Plan 也会安全拒绝远程执行。WireGuard、策略路由、NAT、防火墙和远程回滚必须先在隔离 Debian 环境通过发布闸门；当前命令不会修改生产节点网络。

## 单机参数与反代示例

### 启动已有配置

```bash
# 使用 generated/ 中的现有配置启动，不覆盖手工修改
python3 deploy.py up

# 明确重新生成配置后启动（保留原 up 的行为）
python3 deploy.py up --generate
```

普通 `up` 不读取 `services.json`，也不要求项目根目录存在 `.env`。
如果 `generated/docker-compose.yml` 不存在，会报错退出，不会自动生成。
首次部署或通过 `add-proxy` 等命令修改源配置后，使用 `up --generate`。

`--generate` 会覆盖生成目录中的配置。`generate` 和 `reload` 的行为保持不变，
仍会重新生成配置，因此仍可能覆盖手工修改。
`up` 不保证运行中的 Xray 重新读取手工修改的配置；本次调整仅分离配置生成与启动。

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

### prepare 的 SSH 参数

| 参数 | 说明 |
|---|---|
| `--configure-ssh-password-auth` | 显式启用 root 密码和键盘交互认证；默认保留现有密码认证策略 |

### 服务反代示例

```bash
# 反代宿主机服务（localhost 会自动转为 host.docker.internal）
python3 deploy.py add-service -d api.example.com -t localhost:8317

# 也可以直接指定 host.docker.internal
python3 deploy.py add-service -d api.example.com -t host.docker.internal:8317

# 设置 IP 白名单
python3 deploy.py add-service -d admin.example.com -t localhost:8080 --allow-ips 1.2.3.0/24,5.6.7.8

# 追加 / 删除 / 查看 IP
python3 deploy.py update-ips -d admin.example.com --add 10.0.0.0/8
python3 deploy.py update-ips -d admin.example.com --remove 5.6.7.8
python3 deploy.py update-ips -d admin.example.com --list
```

> **注意**: Caddy 运行在 Docker 容器内，`localhost` 指向容器自身而非宿主机。脚本会自动将 `localhost` / `127.0.0.1` 转为 `host.docker.internal`，并在 docker-compose.yml 中添加 `extra_hosts` 映射。

## .env 配置

`prepare` 命令会自动生成 `.env` 模板，编辑填入即可：

```dotenv
CF_API_TOKEN=xxx              # 必填
DEFAULT_UUID=                 # 可选，init 时自动生成
DEFAULT_VLESS_WS_PATH=        # 可选，init 时自动生成
DEFAULT_VMESS_WS_PATH=        # 可选，init 时自动生成
REDIRECT_URL=                 # 必填，非 WS 路径重定向目标

# SSH 公钥（支持多个：SSH_KEY_1, SSH_KEY_2, ...）
SSH_KEY_1=ssh-rsa AAAA... user1
SSH_KEY_2=ssh-ed25519 AAAA... user2

# 流量监控 (check-traffic 命令)
TRAFFIC_LIMIT_GB=180          # 流量阈值 (GB)，check-traffic 必填
VNSTAT_IFACE=ens4             # 可选，指定网卡（默认自动跳过 docker0/lo）
TELEGRAM_BOT_TOKEN=           # 可选，告警通知
TELEGRAM_CHAT_ID=             # 可选，告警通知
```

优先级：**CLI 参数 > 环境变量 > `.env` 文件**

正常顺序是先运行 `prepare` 创建模板，再编辑 `.env`，最后运行 `init`。`init` 会合并当前进程环境和 `.env` 中严格命名为 `SSH_KEY_1`、`SSH_KEY_2` 等的变量，并根据 key type 与 base64 key body 去重；同一个 key 仅评论不同不会重复添加。再次运行 `init` 时，已有 key 不会重复写入。

`.env` 和 `services.json` 包含敏感信息，不要提交到公开仓库。项目的 `.gitignore` 已默认忽略它们。

## 客户端配置参数

先取得当前节点的实际参数：

```bash
python3 deploy.py list
```

VLESS 客户端参数：

| 字段 | 值 |
|---|---|
| 服务器 | 代理域名，例如 `hk.example.com` |
| 端口 | `443` |
| UUID | `list` 输出的 UUID |
| 传输 | WebSocket |
| WebSocket Path | `list` 输出的 VLESS 路径 |
| TLS | 开启 |
| SNI / Host | 代理域名 |
| 加密 | `none` |

VMess 客户端参数：

| 字段 | 值 |
|---|---|
| 服务器 | 代理域名，例如 `hk.example.com` |
| 端口 | `443` |
| UUID | `list` 输出的 UUID |
| 传输 | WebSocket |
| WebSocket Path | `list` 输出的 VMess 路径 |
| TLS | 开启 |
| SNI / Host | 代理域名 |

同一域名上的 VLESS 与 VMess 使用不同 WebSocket 路径。不要把两个路径互换。

## 流量监控

防止 GCP 等云服务持续产生超额流量。该功能使用 vnstat 统计用量，并通过 nano-xray 独占的 nftables 表实施紧急网络锁，同时支持 Telegram 告警。检查是周期性的，因此阈值不是云账单的绝对上限；两次检查之间仍可能产生额外流量。

紧急网络锁只保留标准 TCP 22。若服务器 SSH 使用其他端口，超量后该 SSH 连接也会被阻断；启用流量保护前应确保 TCP 22 可以作为管理入口。

### 前提

```bash
apt install vnstat    # 流量统计
apt install nftables  # 全局流量锁；prepare 已自动安装
```

### 配置 cron

```cron
# 每小时检查一次，并在重启后立即重新检查
0 * * * * cd /root/nano-xray && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1
@reboot cd /root/nano-xray && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1
```

### 日志格式

```
2026-02-16 16:00 oregon | 1.10/180 GB | OK
2026-02-16 17:00 oregon | 182.30/180 GB | BLOCKED
2026-02-17 00:00 oregon | 0.05/180 GB | UNBLOCKED
```

### 工作原理

1. 自动识别真实网卡（跳过 docker0/lo/veth），也可通过 `VNSTAT_IFACE` 指定
2. 读取 vnstat 当月出站流量 (tx)，用 GB (10⁹) 计算
3. 流量 ≥ 阈值 → 先尝试发送 Telegram 告警，再启用紧急网络锁
4. 网络锁只允许 loopback、TCP 22 的 SSH 服务/客户端流量，以及维持 IPv6 SSH 所需的邻居发现控制报文
5. 其他主机入站、主机出站和 Docker/路由转发流量全部丢弃
6. 流量回落到阈值以下 → 删除 nano-xray 独占的 nftables 表，恢复单机服务所需的 80/443 UFW 规则，并发送 Telegram 通知
7. vnstat 或 nftables 不可用时报告错误，不会虚假输出 `BLOCKED`
8. 重复检查不会重复添加 nftables 表
9. 兼容 vnstat 2.6 (KiB) 和 2.10+ (bytes) JSON 格式

`VNSTAT_IFACE` 必须精确匹配 vnstat 中的接口名。未设置时，脚本会自动跳过 `lo`、Docker、bridge、veth、WireGuard 和 `nx*` 等虚拟接口，选择已有 vnstat 数据的真实网卡。

查看当前网络锁：

```bash
sudo nft list table inet nano_xray_traffic_guard
```

需要人工紧急解除时：

```bash
sudo nft delete table inet nano_xray_traffic_guard
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
```

如果当月用量仍高于阈值，下一次 `check-traffic` 会再次启用网络锁。应先停掉导致流量的服务或调整监控策略，再人工解除。

## 当前实现边界

已经可以直接使用：

- 旧版单机 Caddy/Xray 部署和管理。
- 普通 HTTPS 反代和来源 IP 白名单。
- Cloudflare DNS A 记录管理和 DNS-01 TLS。
- vnstat/nftables 全局流量保护，并兼容清理旧版 UFW 80/443 DENY 规则。
- Node 新增、导入、更新、查看、detach 和删除约束。
- Link 新增、查看、启用、停用和删除。
- 版本化 topology、严格校验、稳定资源分配和 tombstone。
- host-l3 Caddy/Xray/Compose 渲染、影响范围计算和 Plan 保存。
- 单独复制 `deploy.py` 后独立运行。

尚未开放：

- 自动复制 staging 配置到远程 Node。
- WireGuard 密钥生成和双方 peer 发布。
- 远程策略路由、fail-closed、NAT 和 UFW/nftables 规则应用。
- 多节点 prepare/commit/rollback。
- Link doctor、Surge 导出和 Link 流量配额联动。

成功生成 Plan 表示配置已经通过本地数据校验和渲染，不表示链路已经在远程服务器生效。

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

作为 Node + Link 管理目录时还会出现：

```text
nano-xray/
├── deploy.py
├── inventory/
│   ├── topology.json
│   └── nodes/<node-id>/services.json
├── state/
│   └── staging/<topology-hash>/<node-id>/...
└── plans/*.json
```

生产服务器运行只需要 `deploy.py`。仓库中的 `tests/`、`pyproject.toml`、`uv.lock`、CI 配置和设计文档只用于开发与验证，不是运行时依赖。

## 常见问题

### `generated/docker-compose.yml 不存在`

首次启动需要生成配置：

```bash
python3 deploy.py up --generate
```

### Cloudflare Token 验证失败或 DNS 没有创建

检查 Token 是否属于正确账号和 Zone，并具有 DNS Edit 与 Zone Read 权限。确认 `init` 检测到了正确的公网 IPv4，且命令没有使用 `--no-dns`。如果 DNS 由其他系统管理，可以自行创建 DNS-only A 记录。

### Caddy 无法签发证书

```bash
docker logs caddy --tail 200
```

常见原因是 Cloudflare Token 权限不足、域名不在 Token 覆盖的 Zone、系统时间错误或 DNS 尚未传播。

### 普通反代返回 502

先在宿主机确认后端可访问：

```bash
curl -v http://127.0.0.1:8317/
docker logs caddy --tail 100
```

目标如果是另一个 Docker 容器，需要填写 Caddy 容器实际可达的地址；不要假定任意容器名都能跨 Docker 网络解析。

### 修改 `generated/` 后没有生效

普通 `up` 不会覆盖文件，但也不保证运行中的进程重新读取文件。`reload` 会先重新生成配置，因此会覆盖脚本管理的手工修改。Xray 配置变化时应使用 `up --generate` 明确重建所需容器。

### `node import` SSH 失败

先用相同参数直接测试：

```bash
ssh -o BatchMode=yes -i ~/.ssh/nano_xray_ed25519 \
  root@203.0.113.10 \
  'cat -- /root/nano-xray/services.json'
```

确认用户名、私钥权限、远程路径和 `known_hosts` 后再重新导入。

### `prepare` 后公钥仍不能登录

先检查文件和权限：

```bash
sudo ls -ld /root/.ssh
sudo ls -l /root/.ssh/authorized_keys
sudo cat /root/.ssh/authorized_keys
```

期望目录为 `0700`、文件为 `0600`。然后检查语法和最终生效值：

```bash
sudo sshd -t
sudo sshd -T | grep -E '^(pubkeyauthentication|authorizedkeysfile|permitrootlogin|passwordauthentication) '
sudo systemctl status sshd.service
sudo journalctl -u sshd.service -n 100 --no-pager
```

默认公钥模式应看到 `pubkeyauthentication yes`、`.ssh/authorized_keys`，以及 `permitrootlogin without-password` 或 `prohibit-password`。脚本优先 reload `sshd.service`；系统只提供 `ssh.service` 时会自动回退。如果 `init` 提示没有 `SSH_KEY_*`，请编辑 `.env` 后重新执行 `init`。

### 创建 Link 时报 `必须先切换为 host-l3 profile`

```bash
python3 deploy.py node update hk1 --network-profile host-l3
python3 deploy.py node update us1 --network-profile host-l3
```

这只更新本地期望配置。当前版本不会自动迁移远程容器网络。

### `apply` 报告暂不支持

这是当前版本的预期行为。可以继续检查 Plan 和 staging 产物，但远程网络应用尚未开放。

## 开发验证

远程运行不需要安装这些依赖。只有修改源码或运行测试时才需要：

```bash
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest tests/ -v
```

测试中包含单文件交付验证：在空临时目录中只复制 `deploy.py`，确认帮助命令、Node 创建和 topology 写入都不依赖项目内其他 Python 文件。
