# nano-xray

`nano-xray` 是一个零第三方 Python 运行依赖的 Caddy + Xray 部署脚本。全部生产运行代码都集成在单个 `deploy.py` 中，适合直接下载到 Debian 服务器部署。

当前代码提供两组能力：

- **单机服务管理**：在一台服务器上管理多个 VLESS/VMess 代理域名和普通 HTTPS 反向代理。
- **本机 Xray Link**：把当前服务器作为 source，只导入目标节点的 `services.json`，再为本机增加一条经目标节点出站的代理链路。

现在的 Link 流程不使用 SSH 连接目标节点，也不远程发布配置。以 TW → JP 为例，只需在 TW 上导入一份手工复制来的 JP `services.json`，然后执行：

```bash
python3 deploy.py node import jp --services-file ./imports/jp-services.json
python3 deploy.py link add jp
python3 deploy.py apply --link tw-jp
```

本机 Node 名、Link ID 和入口 Service 都由脚本推导，无需重复填写：

```text
tw.qadmlee.com  → 本机 Node tw
tw + jp         → Link ID tw-jp
本机 Node tw    → entry_service xray-tw
```

创建 Link 只修改 TW 本机的 Xray 配置。JP 继续作为独立代理运行，不需要增加配置或重启；删除 Link 也不会删除 TW、JP 或其他 Link。

## 功能概览

- VLESS + WebSocket + TLS 与 VMess + WebSocket + TLS。
- Caddy 使用 Cloudflare DNS-01 自动签发和续期证书。
- 添加和删除服务时可自动管理 Cloudflare DNS A 记录。
- 一台服务器可运行多个代理域名和多个普通反向代理。
- 普通反向代理支持来源 IP 白名单。
- `prepare` 安装 Docker、UFW、fail2ban、vnstat、nftables，并启用 BBR 等系统参数。
- `init` 从 `.env` 安装 root SSH 公钥，并校验 sshd 的最终生效配置。
- 月出站流量超限时，使用 nftables 阻断除 TCP 22 外的所有主机入站、主机出站和转发流量。
- Link 使用目标节点已有的 VLESS/VMess + WebSocket + TLS 服务，不依赖 WireGuard。
- Link 应用前使用固定版本 Xray 镜像校验配置；应用时备份、原子替换并重建对应容器；失败自动回滚。
- 所有运行代码只需一个 `deploy.py`，无需安装本项目或 Python package。

## 运行要求

### 服务器部署

1. Debian 12 或相近的 Debian 环境。
2. Python 3.11 或更高版本。
3. root 权限；`prepare` 需要安装和配置系统组件。
4. 使用自动 DNS 和自动 TLS 时，域名 DNS 托管在 Cloudflare。
5. Cloudflare API Token 至少具有 `Zone DNS: Edit` 和 `Zone: Zone: Read` 权限。
6. 公网 TCP 80、TCP 443 和 UDP 443 可达。

Docker 无需预装，`prepare` 会安装 Docker Engine 和 Compose 插件。

### Link 管理

- `node import` 只读取本机文件，不需要 SSH。
- `node import`、`node list`、`link add`、`link list` 和 `plan` 不需要 root。
- `apply` 必须在 Link 的 source 服务器执行，且当前用户必须能够操作 Docker。以正常的 root 部署方式运行即可满足要求。
- target 必须已经运行一个可从 source 访问的 VLESS 或 VMess WebSocket + TLS 服务。

## 单文件下载安装

`deploy.py` 所在目录就是项目运行目录。`.env`、`services.json`、`generated/`、`inventory/` 和 `state/` 都会在这里创建，因此不要从临时目录运行。

```bash
sudo mkdir -p /root/nano-xray
cd /root/nano-xray

sudo curl -fL https://your-download-host.example/deploy.py -o deploy.py
sudo chmod 0755 deploy.py
python3 deploy.py --help
```

把示例 URL 替换为实际发布地址。更新程序时可以先备份再覆盖单文件：

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
cd /root/nano-xray
python3 deploy.py prepare
```

`prepare` 必须由 root 执行。它会：

1. 创建 `.env` 模板；已有文件不会覆盖。
2. 安装基础工具、OpenSSH Server、vnstat 和 nftables。
3. 设置 `Asia/Shanghai` 时区。
4. 安装 Docker Engine 和 Compose 插件。
5. 应用 BBR/TCP 参数。
6. 配置 UFW，放行 TCP 22、TCP 80、TCP 443 和 UDP 443。
7. 安装并配置 fail2ban。
8. 添加每小时一次和开机时运行的 `check-traffic` cron。

`prepare` 只创建 `.env` 模板，此时模板还没有公钥内容，所以不会安装 SSH 公钥。公钥由后续 `init` 从填写后的 `.env` 读取。

默认情况下，`prepare` 保留系统现有的 SSH 密码认证策略。如果明确需要启用 root 密码及键盘交互认证，可执行：

```bash
python3 deploy.py prepare --configure-ssh-password-auth
```

脚本会写入受管 sshd drop-in，在 reload 前完成语法与有效配置校验。

### 2. 编辑 `.env`

```bash
nano .env
```

至少填写 Cloudflare Token 和默认重定向地址。建议同时填写一个管理公钥：

```dotenv
CF_API_TOKEN=your-cloudflare-api-token
REDIRECT_URL=https://www.example.com

SSH_KEY_1=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@mac

# 可选；留空时 init 自动生成
# DEFAULT_UUID=
# DEFAULT_VLESS_WS_PATH=
# DEFAULT_VMESS_WS_PATH=

# 可选的月出站流量保护
TRAFFIC_LIMIT_GB=180
# VNSTAT_IFACE=ens4
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
```

多个管理员可以继续增加严格编号的变量：

```dotenv
SSH_KEY_2=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin2
SSH_KEY_3=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... emergency
```

配置值的优先级是：命令行参数、当前进程环境变量、`.env` 文件。

### 3. 初始化服务注册表和 SSH 公钥

```bash
python3 deploy.py init
```

`init` 会完成以下操作：

- 从 `.env` 和当前进程环境读取 `SSH_KEY_1`、`SSH_KEY_2` 等公钥。
- 校验公钥类型和 base64 key body，并按真实 key identity 去重。
- 保留已有 `authorized_keys` 内容，只追加尚不存在的公钥。
- 原子写入 `/root/.ssh/authorized_keys`，目录权限设为 `0700`，文件权限设为 `0600`。
- 写入 `/etc/ssh/sshd_config.d/00-nano-xray.conf`，启用公钥认证和 root 公钥登录。
- 依次运行 `sshd -t` 和 `sshd -T`，确认最终有效配置正确。
- 优先 reload `sshd.service`，在系统只提供 `ssh.service` 时自动回退。
- 检测公网 IPv4，初始化 UUID 和 WebSocket path，并写入 `services.json`。
- 验证 Cloudflare API Token。

公钥模式下受管 sshd 配置为：

```text
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin prohibit-password
```

如果校验或 reload 失败，脚本会恢复原来的 drop-in。未配置任何 `SSH_KEY_N` 时，`init` 不修改现有 `authorized_keys` 或 sshd 策略。

如果 `services.json` 已存在，`init` 会先执行幂等的 SSH 公钥检查，再询问是否覆盖服务注册表。已有生产节点通常应选择保留，避免更换默认 UUID 和 path。

也可以通过参数提供初始化值：

```bash
python3 deploy.py init \
  --token 'your-cloudflare-api-token' \
  --redirect 'https://www.example.com' \
  --uuid '00000000-0000-4000-8000-000000000000' \
  --vless-ws-path '/vless-secret-path' \
  --vmess-ws-path '/vmess-secret-path'
```

### 4. 添加代理

```bash
python3 deploy.py add-proxy --domain tw.qadmlee.com
python3 deploy.py up --generate
```

`add-proxy` 默认使用 `init` 创建的 UUID 和 path，创建 Cloudflare DNS-only A 记录，并更新 `services.json`。首次启动必须使用 `up --generate`。

容器名由域名第一段生成：

```text
tw.qadmlee.com → xray-tw
```

这条命名规则也用于自动识别本机 Node。要使用简化 Link 流程，本机第一个 proxy 域名应有清晰且唯一的第一段，例如 `tw.qadmlee.com`、`hk1.example.com`。

常用变体：

```bash
# 指定该代理 UUID
python3 deploy.py add-proxy -d tw.qadmlee.com -u 'UUID'

# 为该代理单独生成新 UUID
python3 deploy.py add-proxy -d tw.qadmlee.com --new-uuid

# DNS 由其他系统管理
python3 deploy.py add-proxy -d tw.qadmlee.com --no-dns

# 覆盖同域名服务，并允许更新不同 IP 的 DNS 记录
python3 deploy.py add-proxy -d tw.qadmlee.com --force
```

## 日常单机管理

### 查看服务

```bash
python3 deploy.py list
```

输出包含代理域名、容器名、UUID、VLESS/VMess path 和普通反代目标。

### 添加普通 HTTPS 反向代理

```bash
# 反代宿主机服务；localhost 会自动转换
python3 deploy.py add-service \
  --domain api.example.com \
  --target localhost:8317

# 增加来源 IP 白名单
python3 deploy.py add-service \
  --domain admin.example.com \
  --target localhost:8080 \
  --allow-ips 1.2.3.0/24,5.6.7.8

python3 deploy.py reload
```

Caddy 运行在 Docker 容器内，容器中的 `localhost` 不是宿主机。脚本会把 `localhost` 或 `127.0.0.1` 转成 `host.docker.internal`，并在 Compose 中添加宿主机映射。

管理已有白名单：

```bash
python3 deploy.py update-ips -d admin.example.com --list
python3 deploy.py update-ips -d admin.example.com --add 10.0.0.0/8
python3 deploy.py update-ips -d admin.example.com --remove 5.6.7.8
python3 deploy.py reload
```

白名单为空表示允许所有来源。

### 删除服务

```bash
# 删除 services.json 中的服务，并尝试删除 Cloudflare DNS 记录
python3 deploy.py remove --domain api.example.com

# 删除服务但保留 DNS 记录
python3 deploy.py remove --domain api.example.com --keep-dns

python3 deploy.py reload
```

### 生成、启动和 reload 的区别

| 命令 | 是否重写 `generated/` | 对容器的操作 |
|---|---:|---|
| `generate` | 是 | 不操作容器 |
| `up` | 否 | 使用现有配置执行 `docker compose up -d` |
| `up --generate` | 是 | 生成后执行 `docker compose up -d` |
| `reload` | 是 | 容器集合变化时 Compose 更新；否则只热加载 Caddy |

`generated/` 是脚本管理的生成目录。持久修改应写入 `.env`、`services.json` 或通过脚本命令完成。`generate`、`up --generate` 和 `reload` 都会覆盖其中的手工修改。

普通 `up` 不读取 `.env` 或 `services.json`，也不重新生成配置。如果 `generated/docker-compose.yml` 不存在，它会要求先执行：

```bash
python3 deploy.py up --generate
```

`reload` 在容器集合没有变化时只热加载 Caddy，不会让 Xray 进程重新读取配置。Link 变更必须使用对应的 `apply --link <ID>`。

只要当前 `services.json` 能识别出本机 Node，后续 `generate`、`up --generate` 和 `reload` 生成 Xray 文件时都会保留 inventory 中已启用的本机 Link，不会把 Link 配置覆盖丢失。但生成文件不等于让正在运行的 Xray 重读文件；Link 状态发生变化后仍应执行 `apply`。

### 查看容器和日志

```bash
docker compose -f generated/docker-compose.yml ps
docker logs caddy --tail 100
docker logs xray-tw --tail 100
```

## 客户端配置

### 节点直连

先读取当前代理的参数：

```bash
python3 deploy.py list
```

VLESS 配置：

| 字段 | 值 |
|---|---|
| 服务器 | 当前代理域名，例如 `tw.qadmlee.com` |
| 端口 | `443` |
| UUID | `list` 输出的 UUID |
| 传输 | WebSocket |
| WebSocket Path | `list` 输出的 VLESS path |
| TLS | 开启 |
| SNI / Host | 当前代理域名 |
| 加密 | `none` |

VMess 配置：

| 字段 | 值 |
|---|---|
| 服务器 | 当前代理域名，例如 `tw.qadmlee.com` |
| 端口 | `443` |
| UUID | `list` 输出的 UUID |
| 传输 | WebSocket |
| WebSocket Path | `list` 输出的 VMess path |
| TLS | 开启 |
| SNI / Host | 当前代理域名 |

同一域名上的 VLESS 和 VMess 使用不同 WebSocket path，不要混用。

### Link 客户端

`link add jp` 会打印 Link 专属客户端 UUID。配置 TW → JP 客户端时：

| 字段 | 值 |
|---|---|
| 服务器 | source 的代理域名，例如 `tw.qadmlee.com` |
| 端口 | `443` |
| UUID | `link add jp` 输出的客户端 UUID |
| VLESS/VMess | 由 `--protocol` 决定，默认两者都支持 |
| WebSocket Path | source 对应协议原有的 path |
| TLS、SNI、Host | 开启并填写 source 代理域名 |

Link UUID 与 source 原有直连 UUID 不同。Xray 根据 Link UUID 识别该用户，并把流量转给 JP；使用原直连 UUID 时仍从 TW 本机直接出站。

项目目前没有 Surge 自动导出命令，需要按上述字段手工创建客户端条目。Link UUID 持久保存在 `inventory/topology.json`，不要公开或随意修改该文件。

## 本机 Node + Link

### 工作模型

每台服务器都是独立 Node。Link 只是 source Xray 中的一条额外路由：

```text
直连账号：客户端 → TW Caddy → TW Xray → Internet

Link 账号：客户端 → TW Caddy → TW Xray
          → VLESS/VMess + WebSocket + TLS
          → JP Caddy → JP Xray → Internet
```

当前方案不使用 WireGuard、隧道地址、策略路由或 NAT。它复用 target 已经存在的公网 Xray 服务，因此无需登录、配置或重启 target。

Link 是显式单跳关系。即使 inventory 中同时存在 `tw → jp` 和 `jp → us`，`tw → jp` 也不会自动变成 `tw → jp → us`。

### 本机 Node 如何识别

执行 `node list`、`link add`、`link del` 或 `apply` 时，脚本读取当前目录的 `services.json`：

1. 找到第一个 `type=proxy` 的 Service。
2. 取其域名第一段作为本机 Node ID。
3. 要求其容器名为 `xray-<Node ID>`。
4. 把本机 `services.json` 同步到 `inventory/nodes/<Node ID>/services.json`。

例如：

```text
domain:         tw.qadmlee.com
Node ID:        tw
entry_service:  xray-tw
```

因此本机不需要执行 `node import tw`，也不需要在命令中填写 source、Link ID 或 entry service。

如果当前 `services.json` 没有 proxy，或第一个 proxy 的容器名不符合 `xray-<域名前缀>`，简化 Link 命令会拒绝继续，并给出明确错误。

### TW → JP 完整流程

#### 1. 在 JP 确认代理可用

JP 应先完成自己的单机部署：

```bash
# 在 JP 上
python3 deploy.py list
docker compose -f generated/docker-compose.yml ps
```

#### 2. 把 JP 的 `services.json` 复制到 TW

复制方式由你决定。`deploy.py` 不发起 SSH，也不读取远程服务器。建议在 TW 上保留一个容易识别的导入文件：

```text
/root/nano-xray/imports/jp-services.json
```

#### 3. 在 TW 导入 JP

```bash
# 在 TW 的 nano-xray 目录
python3 deploy.py node import jp \
  --services-file ./imports/jp-services.json
```

脚本会校验 JSON，并把副本写到：

```text
inventory/nodes/jp/services.json
```

后续修改或删除 `./imports/jp-services.json` 不会改变 inventory 中的副本。

`node_id` 只允许小写字母、数字和连字符。建议使用 target 域名前缀，例如 `jp`、`us1`。

查看当前 inventory：

```bash
python3 deploy.py node list
```

该命令也会自动同步本机 Node。

#### 4. 创建 Link

```bash
python3 deploy.py link add jp
```

假设当前第一个 proxy 是 `tw.qadmlee.com`，脚本自动创建：

```text
source:          tw
target:          jp
Link ID:         tw-jp
entry_service:   xray-tw
exit_service:    JP 唯一的 proxy Service
客户端协议:      VLESS 和 VMess
TW 连接 JP 协议: VLESS + WebSocket + TLS
```

同一台 source 到同一 target 最多存在一条 Link。重复运行 `link add jp` 会报告 `Link 已存在`，不会重复添加或更换 UUID。

如果 JP 有多个 proxy Service，脚本无法替你判断应使用哪一个，需要明确选择：

```bash
python3 deploy.py link add jp \
  --exit-service xray-jp-main
```

完整可选参数：

```bash
python3 deploy.py link add jp \
  --protocol both \
  --exit-protocol vless \
  --exit-service xray-jp-main
```

| 参数 | 默认值 | 作用 |
|---|---|---|
| `target` | 必填 | 目标 Node，例如 `jp` |
| `--protocol` | `both` | Link 专属 UUID 允许客户端使用 `vless`、`vmess` 或两者 |
| `--exit-protocol` | `vless` | source Xray 连接 target 时使用 `vless` 或 `vmess` |
| `--exit-service` | 自动选择 | target 有多个 proxy 时选择其中一个 |
| `--transport` | `xray` | 当前唯一可选值，用于 inventory schema |

#### 5. 应用 Link

```bash
python3 deploy.py apply --link tw-jp
```

`apply` 必须在 TW 本机执行。它会：

1. 重新从当前 `services.json` 确认本机确实是 `tw`。
2. 使用 TW 的全部已启用出向 Link 生成 Xray 配置。
3. 将待应用配置暂存到 `state/apply-staging/<拓扑哈希>/`。
4. 使用 `ghcr.io/xtls/xray-core:26.2.6` 在隔离网络中运行配置校验。
5. 再次核对 topology hash，防止校验期间期望配置被并发修改。
6. 将当前 Xray 配置备份到 `state/backups/<时间>-tw-jp/config.json`。
7. 原子替换 `generated/xray/xray-tw/config.json`。
8. 只强制重建 `xray-tw` 容器，并检查它是否处于 Running 状态。
9. 失败时恢复旧配置并重新启动原容器。

运行配置权限为 `0644`，使固定镜像中的非 root Xray 用户能够读取 bind mount；`state/backups/` 中的备份仍为 `0600`。如果旧版 `apply` 后容器日志出现 `open /etc/xray/config.json: permission denied`，先执行 `chmod 0644 generated/xray/xray-tw/config.json` 恢复服务，再更新 `deploy.py`。

`apply` 不修改 Caddy、其他 Xray 容器或 JP。如果本机还没有生成运行配置，会要求先执行：

```bash
python3 deploy.py up --generate
python3 deploy.py apply --link tw-jp
```

#### 6. 配置客户端并验证出口

使用 `link add jp` 打印的 Link UUID，连接地址仍是 `tw.qadmlee.com:443`，path 仍使用 TW 对应协议的原有 path。连接后检查公网出口应为 JP。

TW 原来的 UUID 继续从 TW 本机直出，不受 Link 影响。

### 更新 target 信息

如果 JP 更换了代理域名、UUID 或 WebSocket path，把最新的 JP `services.json` 再次复制到 TW，然后执行：

```bash
python3 deploy.py node import jp \
  --services-file ./imports/jp-services.json
python3 deploy.py apply --link tw-jp
```

重复导入会更新 JP 的 inventory 副本，但保留现有 Link ID 和 Link 客户端 UUID。`apply` 后 TW 才会使用 JP 的新连接参数。

### 启用、停用和删除 Link

查看 Link：

```bash
python3 deploy.py link list
```

临时停用并应用：

```bash
python3 deploy.py link disable tw-jp
python3 deploy.py apply --link tw-jp
```

停用保留 Link 和客户端 UUID，但 Xray 配置不再接受该 Link 身份或生成对应 outbound。

重新启用并应用：

```bash
python3 deploy.py link enable tw-jp
python3 deploy.py apply --link tw-jp
```

删除本机到 JP 的 Link：

```bash
python3 deploy.py link del jp
python3 deploy.py apply --link tw-jp
```

`link del jp` 自动推导本机 source 和内部 Link ID，只删除 `tw → jp`。它不会影响：

- TW 原来的直连账号。
- JP 自己的服务。
- TW 到其他 target 的 Link。
- 其他服务器上存在的任何 Link。

删除时会在 topology 中留下临时 tombstone，使已经运行的 Link 能通过随后一次 `apply --link tw-jp` 从 Xray 配置中安全移除。应用成功后 tombstone 自动清理。

旧 inventory 如果存在同一 source 到同一 target 的多条自定义 ID Link，`link del jp` 会拒绝猜测；此时可使用兼容命令：

```bash
python3 deploy.py link remove <旧Link-ID>
python3 deploy.py apply --link <旧Link-ID>
```

### 可选 Plan

正常新增或删除 Link 不需要 `plan`。如果希望在应用前保存一份只读审查结果，可以执行：

```bash
mkdir -p plans
python3 deploy.py plan --links tw-jp --save plans/tw-jp.json
```

Plan 会记录 topology SHA-256、受影响的 source Node、Link、清理动作和生成文件哈希，并把独立的兼容审查草稿写到：

```text
state/staging/<拓扑哈希>/tw/
```

这些草稿来自旧 topology renderer，与实际 `apply` 的暂存目录分开。它们不会修改 `generated/` 或运行中的容器，也不是 `apply` 将要安装的精确配置；当前简化流程可直接跳过 Plan。

### 兼容的 inventory 管理命令

CLI 仍保留 `node add`、`node update`、`node detach`、`node remove` 和 `link remove`，用于读取或整理旧版 topology。当前“本机自动 source + 手工文件导入 target”的日常流程不需要 `node add`、`node update` 或 `node detach`。

需要删除已不再使用的 target Node 时，应先删除指向它的 Link、完成 tombstone apply，再执行：

```bash
python3 deploy.py node remove jp
```

存在活动 Link 或待应用 tombstone 时，`node remove` 会拒绝删除，避免留下损坏的引用。

## 流量监控与紧急网络锁

`check-traffic` 使用 vnstat 读取当月出站流量 `tx`，按十进制 GB（10⁹ bytes）与 `TRAFFIC_LIMIT_GB` 比较。`prepare` 默认配置每小时一次和开机检查：

```cron
0 * * * * cd /root/nano-xray && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1
@reboot cd /root/nano-xray && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1
```

运行一次检查：

```bash
python3 deploy.py check-traffic
```

示例输出：

```text
2026-02-16 16:00 tw | 1.10/180 GB | OK
2026-02-16 17:00 tw | 182.30/180 GB | BLOCKED
2026-03-01 00:00 tw | 0.05/180 GB | UNBLOCKED
```

超限时，脚本会启用独占 nftables 表 `inet nano_xray_traffic_guard`：

- 允许 loopback。
- 允许 TCP 22 的 SSH 入站和出站，以及其已建立连接的反向流量。
- 允许维持 IPv6 SSH 所需的邻居发现控制报文。
- 丢弃其他所有主机入站。
- 丢弃其他所有主机出站。
- 丢弃全部 Docker/路由转发流量。

因此网络锁覆盖的不只是 80/443 入站，也能停止普通进程、容器和转发产生的其他出站流量。通知会在锁定前发送，因为锁定后 Telegram 也无法访问。

如果服务器 SSH 使用的不是 TCP 22，超限后该 SSH 端口也会被阻断。启用流量保护前应确保 TCP 22 可作为管理入口。

低于阈值时，脚本删除自己的 nftables 表，恢复单机服务使用的 UFW 80/443 规则，并发送恢复通知。升级自旧版本时，它也会清理旧的 UFW 80/443 DENY 规则。

其他行为：

- 重复检查不会重复叠加 nftables 规则。
- vnstat 或 nftables 不可用时返回错误，不会虚假报告 `BLOCKED`。
- 兼容 vnstat 2.6 的 KiB JSON 和 vnstat 2.10+ 的 bytes JSON。
- 未指定 `VNSTAT_IFACE` 时，会跳过 `lo`、Docker、bridge、veth、WireGuard 和 `nx*` 等虚拟接口，选择已有 vnstat 数据的真实网卡。
- 检查是周期性的，所以流量阈值不是云账单的绝对上限；两次检查之间仍可能产生额外流量。

查看网络锁：

```bash
sudo nft list table inet nano_xray_traffic_guard
```

人工紧急解除：

```bash
sudo nft delete table inet nano_xray_traffic_guard
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
```

如果 vnstat 的当月用量仍高于阈值，下一次 `check-traffic` 会重新锁定网络。应先停止流量来源或调整阈值，再人工解除。

## 命令速查

| 命令 | 说明 |
|---|---|
| `prepare` | 安装和配置系统组件，创建 `.env` 模板 |
| `init` | 安装 `.env` 中的 root 公钥，验证 sshd，初始化 `services.json` |
| `add-proxy -d <域名>` | 添加 VLESS/VMess 代理，可自动创建 DNS |
| `add-service -d <域名> -t <目标>` | 添加普通 HTTPS 反向代理 |
| `remove -d <域名>` | 删除 proxy 或普通反代，可自动删除 DNS |
| `list` | 查看当前 `services.json` 中的服务和连接参数 |
| `generate` | 重新生成配置，不操作容器 |
| `up` | 使用现有 `generated/` 启动容器 |
| `up --generate` | 重新生成配置并启动容器 |
| `reload` | 重新生成；容器集合变化时更新 Compose，否则只 reload Caddy |
| `update-ips` | 查看或修改普通反代的来源 IP 白名单 |
| `check-traffic` | 检查月出站流量，超限时除 TCP 22 外锁定网络 |
| `node import <target> --services-file <文件>` | 从本地文件导入或刷新 target |
| `node list` | 自动同步并列出本机和已导入 target |
| `link add <target>` | 自动建立本机到 target 的 Link 期望配置 |
| `link del <target>` | 删除本机到 target 的 Link 期望配置 |
| `link list` | 查看活动 Link |
| `link enable/disable <ID>` | 启用或停用 Link 期望配置 |
| `apply --link <ID>` | 在本机校验并应用该 source 的全部 Link；失败自动回滚 |
| `plan` | 可选生成独立审查草稿，不修改运行配置 |

所有子命令都可以使用 `--help` 查看当前参数：

```bash
python3 deploy.py --help
python3 deploy.py link add --help
python3 deploy.py apply --help
```

## 文件结构和敏感数据

单机部署会产生：

```text
nano-xray/
├── deploy.py
├── .env
├── services.json
└── generated/
    ├── .env
    ├── Caddyfile
    ├── docker-compose.yml
    └── xray/<container>/config.json
```

Node + Link 会另外产生：

```text
nano-xray/
├── inventory/
│   ├── topology.json
│   └── nodes/<node-id>/services.json
├── state/
│   ├── apply-staging/<topology-hash>/xray/...
│   ├── backups/<time>-<link-id>/config.json
│   └── staging/<topology-hash>/<node-id>/...
└── plans/*.json
```

`.env`、`services.json`、`inventory/`、`state/` 和 `plans/` 可能包含 Cloudflare Token、代理 UUID、Link UUID、域名和其他敏感信息。项目 `.gitignore` 默认忽略这些路径；还应限制服务器文件权限并自行备份。

服务器运行时只需要 `deploy.py`。仓库中的 `tests/`、`pyproject.toml`、`uv.lock`、CI 和设计文档只用于开发验证，不是远程部署依赖。

## 当前实现范围

已经实现：

- 单机 Caddy/Xray 代理和普通反向代理管理。
- Cloudflare DNS A 记录管理和 DNS-01 TLS。
- SSH 公钥安装、sshd 有效配置检查、服务名兼容和失败恢复。
- vnstat + nftables 全局流量保护。
- 从本机文件导入 target Service，不使用 SSH。
- 自动识别并同步本机 Node。
- `link add <target>`、`link del <target>`、Link 启用/停用和去重。
- VLESS/VMess over WebSocket + TLS 的单跳 Xray Link。
- 本机 source-only apply、配置校验、备份、原子替换、容器重建和失败回滚。
- 可选 Plan、版本化 topology、稳定 Link UUID 和删除 tombstone。
- 单文件 `deploy.py` 独立交付。

当前没有：

- 远程多节点发布或 SSH 导入。
- WireGuard 数据面。
- 自动多跳路由。
- Surge 配置自动导出。
- Link doctor 或 Link 独立流量配额。

## 常见问题

### `generated/docker-compose.yml` 不存在

首次启动或尚未生成配置时执行：

```bash
python3 deploy.py up --generate
```

### Cloudflare Token 验证失败或 DNS 没创建

确认 Token 属于正确账号和 Zone，且具有 DNS Edit 与 Zone Read 权限。检查 `init` 是否检测到正确公网 IPv4，以及命令是否使用了 `--no-dns`。DNS 由其他系统管理时，可以自行创建 DNS-only A 记录。

### Caddy 无法签发证书

```bash
docker logs caddy --tail 200
```

常见原因包括 Cloudflare Token 权限不足、域名不在 Token 覆盖的 Zone、系统时间错误或 DNS 尚未传播。

### 普通反向代理返回 502

先在宿主机确认后端可访问：

```bash
curl -v http://127.0.0.1:8317/
docker logs caddy --tail 100
```

目标是另一个 Docker 容器时，应填写 Caddy 容器实际可达的地址，不能假定任意容器名都能跨网络解析。

### 修改 `generated/` 后没有生效

普通 `up` 不会覆盖文件，但也不保证已经运行的进程重新读取文件。`reload` 会先重新生成并覆盖脚本管理的文件，且在容器集合不变时只 reload Caddy。

持久的单机修改应写入源配置；Link 修改应通过 `link` 命令完成并执行 `apply --link <ID>`。

### `node import` 无法读取文件

确认文件已经复制到当前服务器，并检查路径、权限和 JSON：

```bash
ls -l ./imports/jp-services.json
python3 -m json.tool ./imports/jp-services.json
python3 deploy.py node import jp --services-file ./imports/jp-services.json
```

### `link add jp` 提示 target 尚未导入

先导入 JP：

```bash
python3 deploy.py node import jp --services-file ./imports/jp-services.json
```

本机 TW 不需要导入。

### `link add jp` 提示 target 有多个 proxy Service

查看 target 的导入文件或 inventory 副本，再明确选择出口：

```bash
python3 deploy.py link add jp --exit-service xray-jp-main
```

target 只有一个 proxy 时会自动选择。

### `apply` 提示 Link source 与当前机器不一致

`tw-jp` 必须在从当前 `services.json` 识别为 `tw` 的服务器上应用：

```bash
python3 deploy.py apply --link tw-jp
```

不要把 TW 的整个 inventory 拷到 JP 后执行同一条 apply。

### `prepare` 后公钥仍不能登录

`prepare` 不安装公钥。先在 `.env` 填写 `SSH_KEY_1`，再以 root 执行：

```bash
python3 deploy.py init
```

然后检查权限和最终有效配置：

```bash
sudo ls -ld /root/.ssh
sudo ls -l /root/.ssh/authorized_keys
sudo sshd -t
sudo sshd -T | grep -E '^(pubkeyauthentication|authorizedkeysfile|permitrootlogin|passwordauthentication) '
sudo systemctl status sshd.service
sudo journalctl -u sshd.service -n 100 --no-pager
```

期望 `/root/.ssh` 为 `0700`，`authorized_keys` 为 `0600`。默认公钥模式应看到 `pubkeyauthentication yes`、`.ssh/authorized_keys`，以及 `permitrootlogin without-password` 或 `prohibit-password`。系统只提供 `ssh.service` 时脚本会自动回退。

## 开发验证

远程服务器不需要安装开发依赖。只有修改源码或运行测试时才需要：

```bash
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest tests/ -v
```

测试包含单文件交付验证：在空临时目录中只复制 `deploy.py`，确认 CLI、Node/Link 状态和配置生成不依赖仓库内其他 Python 文件。
