#!/usr/bin/env python3
"""nano-xray — 单机多服务 Caddy 管理工具 (零外部依赖)"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  常量
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CADDY_IMAGE = "caddybuilds/caddy-cloudflare:latest"

SCRIPT_DIR = Path(__file__).resolve().parent
GENERATED_DIR = SCRIPT_DIR / "generated"
SERVICES_FILE = SCRIPT_DIR / "services.json"
ENV_FILE = SCRIPT_DIR / ".env"

VLESS_WS_PORT = 2001
VMESS_WS_PORT = 2002
CF_API = "https://api.cloudflare.com/client/v4"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  内嵌配置文件（替代 git clone 获取的外部文件）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_FAIL2BAN_CONF = """\
[sshd]
enabled = true
port = 22
maxretry = 2
bantime = 2592000
"""

_ENV_TEMPLATE = """\
# Cloudflare API Token (必填，权限: Zone DNS: Edit + Zone: Zone: Read)
CF_API_TOKEN=

# 重定向目标 URL (必填，非 WS 路径的请求会被重定向到此 URL)
REDIRECT_URL=

# 以下为可选，init 时自动生成。如需固定值可在此指定
# DEFAULT_UUID=
# DEFAULT_VLESS_WS_PATH=
# DEFAULT_VMESS_WS_PATH=

# SSH 公钥（每行一个，支持多个: SSH_KEY_1, SSH_KEY_2, ...)
# SSH_KEY_1=ssh-rsa AAAA... user1
# SSH_KEY_2=ssh-ed25519 AAAA... user2

# 流量监控 (check-traffic 命令)
# TRAFFIC_LIMIT_GB=180
# VNSTAT_IFACE=ens4
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
"""

_SYSCTL_PARAMS = [
    # BBR 拥塞控制
    "net.core.default_qdisc=fq",
    "net.ipv4.tcp_congestion_control=bbr",
    # TCP Fast Open（加速 TLS 握手）
    "net.ipv4.tcp_fastopen=3",
    # 空闲后不重置拥塞窗口
    "net.ipv4.tcp_slow_start_after_idle=0",
    # 自动探测 MTU，避免分片
    "net.ipv4.tcp_mtu_probing=1",
    # 连接队列上限
    "net.ipv4.tcp_max_syn_backlog=8192",
    "net.core.somaxconn=8192",
    # TCP 缓冲区（最大 64MB，适合高带宽代理）
    "net.ipv4.tcp_rmem=4096 87380 67108864",
    "net.ipv4.tcp_wmem=4096 65536 67108864",
    "net.core.rmem_max=67108864",
    "net.core.wmem_max=67108864",
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  终端颜色
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class Color:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    NC = "\033[0m"


def info(msg: str) -> None:
    print(f"{Color.GREEN}[INFO]{Color.NC}  {msg}")


def warn(msg: str) -> None:
    print(f"{Color.YELLOW}[WARN]{Color.NC}  {msg}")


def error(msg: str) -> None:
    print(f"{Color.RED}[ERROR]{Color.NC} {msg}", file=sys.stderr)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  .env 文件解析
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def load_dotenv() -> dict[str, str]:
    """解析 .env 文件，返回键值对（不会覆盖已有环境变量）"""
    env_vars: dict[str, str] = {}
    if not ENV_FILE.exists():
        return env_vars

    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if value:
            env_vars[key] = value

    return env_vars


def get_env(key: str, cli_value: str = "", dotenv: dict[str, str] | None = None) -> str:
    """优先级: CLI 参数 > 环境变量 > .env 文件"""
    if cli_value:
        return cli_value
    if os.environ.get(key):
        return os.environ[key]
    if dotenv and dotenv.get(key):
        return dotenv[key]
    return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  数据模型
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@dataclass
class Registry:
    cf_api_token: str = ""
    redirect_url: str = ""
    server_ip: str = ""
    cf_zone_id: str = ""
    default_uuid: str = ""
    default_vless_ws_path: str = ""
    default_vmess_ws_path: str = ""
    services: list[dict] = field(default_factory=list)

    def save(self) -> None:
        SERVICES_FILE.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls) -> Registry:
        if not SERVICES_FILE.exists():
            error("services.json 不存在，请先运行: deploy.py init")
            sys.exit(1)
        data = json.loads(SERVICES_FILE.read_text())
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def find_domain(self, domain: str) -> dict | None:
        return next((s for s in self.services if s["domain"] == domain), None)

    def add_service(self, service: dict) -> None:
        self.services.append(service)
        self.save()

    def replace_service(self, domain: str, service: dict) -> None:
        self.services = [s for s in self.services if s["domain"] != domain]
        self.services.append(service)
        self.save()

    def remove_service(self, domain: str) -> dict | None:
        svc = self.find_domain(domain)
        if svc:
            self.services = [s for s in self.services if s["domain"] != domain]
            self.save()
        return svc

    @property
    def proxies(self) -> list[dict]:
        return [s for s in self.services if s.get("type") == "proxy"]

    @property
    def reverse_proxies(self) -> list[dict]:
        return [s for s in self.services if s.get("type") == "service"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  工具函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_random_path() -> str:
    return f"/{secrets.token_hex(4)}"


def send_telegram(bot_token: str, chat_id: str, message: str) -> bool:
    """发送 Telegram 消息，失败静默返回 False。"""
    if not bot_token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = json.dumps(
        {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    ).encode()
    req = Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except (HTTPError, URLError, OSError):
        return False


def get_vnstat_monthly_tx_gb(dotenv: dict[str, str] | None = None) -> float | None:
    """读取 vnstat 当月出站流量 (tx)，单位 GB。返回 None 表示不可用。

    阿里云 CDT 对 ECS 按出向流量计费，因此只统计 tx。
    """
    try:
        result = subprocess.run(
            ["vnstat", "--json", "m"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)

        # 找到真实网卡（跳过 docker0, lo, veth*, br-* 等虚拟接口）
        virtual_prefixes = ("docker", "lo", "veth", "br-", "virbr")
        iface = None
        override = get_env("VNSTAT_IFACE", "", dotenv)
        for itf in data.get("interfaces", []):
            name = itf.get("name", "")
            if override and name == override:
                iface = itf
                break
            if not any(name.startswith(p) for p in virtual_prefixes):
                iface = itf
                break

        if iface is None:
            return None

        traffic = iface.get("traffic", {})
        # vnstat 2.6 用 "months", 2.10+ 用 "month"
        months = traffic.get("month", traffic.get("months", []))
        if not months:
            return 0.0

        latest = months[-1]
        tx_val = latest.get("tx", 0)

        # vnstat JSON v1 (<2.10): 单位为 KiB
        # vnstat JSON v2 (>=2.10): 单位为 bytes
        json_ver = str(data.get("jsonversion", "1"))
        if json_ver == "1":
            tx_bytes = tx_val * 1024
        else:
            tx_bytes = tx_val

        return tx_bytes / 1_000_000_000  # GB
    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        KeyError,
        IndexError,
    ):
        return None


def _has_ufw() -> bool:
    """检查 ufw 是否可用。"""
    return shutil.which("ufw") is not None


def ufw_block_ports() -> None:
    """封锁 80/443 端口。"""
    if not _has_ufw():
        return
    for rule in ["deny 80/tcp", "deny 443/tcp", "deny 443/udp"]:
        subprocess.run(["ufw", *rule.split()], capture_output=True)


def ufw_allow_ports() -> None:
    """放行 80/443 端口。"""
    if not _has_ufw():
        return
    for rule in ["allow 80/tcp", "allow 443/tcp", "allow 443/udp"]:
        subprocess.run(["ufw", *rule.split()], capture_output=True)


def detect_public_ip() -> str:
    urls = [
        "https://ifconfig.me",
        "https://api.ipify.org",
        "https://icanhazip.com",
    ]
    for url in urls:
        try:
            req = Request(url, headers={"User-Agent": "curl/7.0"})
            with urlopen(req, timeout=5) as resp:
                ip = resp.read().decode().strip()
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return ip
        except (URLError, OSError):
            continue
    return ""


def extract_root_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:])


def confirm_prompt(message: str) -> bool:
    try:
        answer = input(f"{message} [y/N] ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def validate_ip_or_cidr(value: str) -> bool:
    """校验 IP 地址或 CIDR 格式是否合法。支持 1.2.3.4、1.2.3.0/24 等。"""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_ip_list(ips: list[str]) -> list[str]:
    """校验 IP 列表，返回无效 IP 列表。空列表表示全部合法。"""
    return [ip for ip in ips if not validate_ip_or_cidr(ip)]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Cloudflare API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class CloudflareClient:
    def __init__(self, token: str):
        self.token = token

    def _request(self, method: str, endpoint: str, data: dict | None = None) -> dict:
        url = f"{CF_API}{endpoint}"
        body = json.dumps(data).encode() if data else None
        req = Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            return json.loads(e.read().decode())
        except URLError as e:
            error(f"Cloudflare API 请求失败: {e}")
            return {"success": False, "errors": [{"message": str(e)}]}

    def verify_token(self) -> bool:
        result = self._request("GET", "/user/tokens/verify")
        return result.get("success", False)

    def get_zone_id(self, root_domain: str) -> str:
        result = self._request("GET", f"/zones?name={root_domain}&status=active")
        zones = result.get("result", [])
        return zones[0]["id"] if zones else ""

    def create_or_update_dns(
        self, zone_id: str, domain: str, ip: str, *, force: bool = False
    ) -> bool:
        """创建或更新 DNS A 记录（幂等）。

        - 记录不存在 → 创建
        - 记录已存在且 IP 相同 → 跳过（幂等）
        - 记录已存在但 IP 不同 → 报错（除非 force=True 强制覆盖）
        """
        result = self._request(
            "GET", f"/zones/{zone_id}/dns_records?type=A&name={domain}"
        )
        existing = result.get("result", [])

        record_data = {
            "type": "A",
            "name": domain,
            "content": ip,
            "ttl": 1,
            "proxied": False,
        }

        if existing:
            old_ip = existing[0]["content"]
            if old_ip == ip:
                info(f"DNS 记录已存在且一致: {domain} → {ip}，跳过")
                return True
            if not force:
                error(
                    f"DNS 记录已存在: {domain} → {old_ip}（期望 {ip}）。"
                    "使用 --force 强制覆盖"
                )
                return False
            record_id = existing[0]["id"]
            resp = self._request(
                "PUT", f"/zones/{zone_id}/dns_records/{record_id}", record_data
            )
            if resp.get("success"):
                info(f"已强制更新 DNS 记录: {domain} → {ip}（原: {old_ip}）")
                return True
        else:
            resp = self._request("POST", f"/zones/{zone_id}/dns_records", record_data)
            if resp.get("success"):
                info(f"已创建 DNS 记录: {domain} → {ip} (DNS only)")
                return True

        err_msg = resp.get("errors", [{}])[0].get("message", "未知错误")
        warn(f"DNS 操作失败: {err_msg}")
        return False

    def delete_dns(self, zone_id: str, domain: str) -> bool:
        result = self._request(
            "GET", f"/zones/{zone_id}/dns_records?type=A&name={domain}"
        )
        records = result.get("result", [])
        if not records:
            warn(f"DNS 记录不存在: {domain}")
            return True

        record_id = records[0]["id"]
        resp = self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
        if resp.get("success"):
            info(f"已删除 DNS 记录: {domain}")
            return True

        warn(f"DNS 删除失败: {resp.get('errors', [{}])[0].get('message', '未知错误')}")
        return False


def ensure_zone_id(registry: Registry, domain: str) -> str:
    if registry.cf_zone_id:
        return registry.cf_zone_id

    if not registry.cf_api_token:
        return ""

    root_domain = extract_root_domain(domain)
    cf = CloudflareClient(registry.cf_api_token)
    zone_id = cf.get_zone_id(root_domain)

    if zone_id:
        registry.cf_zone_id = zone_id
        registry.save()
    else:
        warn(f"无法获取 Zone ID: {root_domain}")

    return zone_id


def auto_create_dns(registry: Registry, domain: str, *, force: bool = False) -> None:
    if not registry.server_ip:
        warn("服务器 IP 未配置，跳过 DNS 记录创建")
        return
    if not registry.cf_api_token:
        warn("CF_API_TOKEN 未设置，跳过 DNS 记录创建")
        return

    zone_id = ensure_zone_id(registry, domain)
    if not zone_id:
        return

    cf = CloudflareClient(registry.cf_api_token)
    if not cf.create_or_update_dns(zone_id, domain, registry.server_ip, force=force):
        sys.exit(1)


def auto_delete_dns(registry: Registry, domain: str) -> None:
    if not registry.cf_api_token:
        return

    zone_id = ensure_zone_id(registry, domain)
    if not zone_id:
        return

    cf = CloudflareClient(registry.cf_api_token)
    cf.delete_dns(zone_id, domain)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  配置文件生成
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class ConfigGenerator:
    def __init__(self, registry: Registry):
        self.reg = registry

    def generate_all(self) -> None:
        # 不能 rmtree: Docker bind mount 绑定 inode，删除后重建的文件 inode 不同，
        # 容器看不到更新。改为就地覆盖写入，保持 inode 不变。
        GENERATED_DIR.mkdir(parents=True, exist_ok=True)

        # 清理已不再需要的 xray 子目录（已删除的代理节点）
        xray_dir = GENERATED_DIR / "xray"
        if xray_dir.exists():
            active_containers = {p["container_name"] for p in self.reg.proxies}
            for child in xray_dir.iterdir():
                if child.is_dir() and child.name not in active_containers:
                    shutil.rmtree(child)

        self._generate_env()
        self._generate_caddyfile()
        self._generate_compose()
        self._generate_xray_configs()

        info(f"配置文件已生成到 {GENERATED_DIR}/")

    def _generate_env(self) -> None:
        (GENERATED_DIR / ".env").write_text(f"CF_API_TOKEN={self.reg.cf_api_token}\n")

    def _generate_caddyfile(self) -> None:
        lines = [
            "{",
            "\tacme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}",
            "}",
        ]

        for svc in self.reg.services:
            lines.append("")
            domain = svc["domain"]

            if svc["type"] == "proxy":
                vless_path = svc["vless_ws_path"]
                vmess_path = svc["vmess_ws_path"]
                container = svc["container_name"]
                redirect = self.reg.redirect_url

                lines.extend(
                    [
                        f"{domain} {{",
                        "\ttls {",
                        "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}",
                        "\t}",
                        "",
                        f"\thandle {vless_path} {{",
                        f"\t\treverse_proxy {container}:{VLESS_WS_PORT}",
                        "\t}",
                        "",
                        f"\thandle {vmess_path} {{",
                        f"\t\treverse_proxy {container}:{VMESS_WS_PORT}",
                        "\t}",
                        "",
                        "\thandle {",
                        f"\t\tredir * {redirect} permanent",
                        "\t}",
                        "}",
                    ]
                )

            elif svc["type"] == "service":
                target = svc["target"]
                allowed_ips = svc.get("allowed_ips", [])
                if allowed_ips:
                    ips_str = " ".join(allowed_ips)
                    lines.extend(
                        [
                            f"{domain} {{",
                            "\ttls {",
                            "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}",
                            "\t}",
                            "",
                            f"\t@allowed remote_ip {ips_str}",
                            "\thandle @allowed {",
                            f"\t\treverse_proxy {target}",
                            "\t}",
                            "\trespond 403",
                            "}",
                        ]
                    )
                else:
                    lines.extend(
                        [
                            f"{domain} {{",
                            "\ttls {",
                            "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}",
                            "\t}",
                            "",
                            f"\treverse_proxy {target}",
                            "}",
                        ]
                    )

        (GENERATED_DIR / "Caddyfile").write_text("\n".join(lines) + "\n")

    def _generate_compose(self) -> None:
        lines = [
            "services:",
            "  caddy:",
            f"    image: {CADDY_IMAGE}",
            "    container_name: caddy",
            "    restart: always",
            "    ports:",
            '      - "80:80"',
            '      - "443:443"',
            '      - "443:443/udp"',
            "    environment:",
            "      - CLOUDFLARE_API_TOKEN=${CF_API_TOKEN}",
            "    volumes:",
            "      - ./Caddyfile:/etc/caddy/Caddyfile",
            "      - caddy_data:/data",
            "      - caddy_config:/config",
        ]

        # 如果有 service 使用 host.docker.internal，需要 extra_hosts 映射
        needs_host_gateway = any(
            "host.docker.internal" in s.get("target", "")
            for s in self.reg.reverse_proxies
        )
        if needs_host_gateway:
            lines.extend(
                [
                    "    extra_hosts:",
                    '      - "host.docker.internal:host-gateway"',
                ]
            )

        proxies = self.reg.proxies
        if proxies:
            lines.append("    depends_on:")
            for p in proxies:
                lines.append(f"      - {p['container_name']}")

        for p in proxies:
            cn = p["container_name"]
            lines.extend(
                [
                    "",
                    f"  {cn}:",
                    "    image: ghcr.io/xtls/xray-core:26.2.6",
                    f"    container_name: {cn}",
                    "    restart: always",
                    '    command: ["run", "-config", "/etc/xray/config.json"]',
                    "    volumes:",
                    f"      - ./xray/{cn}/config.json:/etc/xray/config.json",
                    "    expose:",
                    f'      - "{VLESS_WS_PORT}"',
                    f'      - "{VMESS_WS_PORT}"',
                ]
            )

        lines.extend(["", "volumes:", "  caddy_data:", "  caddy_config:"])
        (GENERATED_DIR / "docker-compose.yml").write_text("\n".join(lines) + "\n")

    def _generate_xray_configs(self) -> None:
        for p in self.reg.proxies:
            cn = p["container_name"]
            config_dir = GENERATED_DIR / "xray" / cn
            config_dir.mkdir(parents=True, exist_ok=True)

            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "listen": "0.0.0.0",
                        "port": VLESS_WS_PORT,
                        "protocol": "vless",
                        "settings": {
                            "clients": [{"id": p["uuid"]}],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "ws",
                            "security": "none",
                            "wsSettings": {"path": p["vless_ws_path"]},
                        },
                        "sniffing": {
                            "enabled": True,
                            "destOverride": ["http", "tls"],
                        },
                    },
                    {
                        "listen": "0.0.0.0",
                        "port": VMESS_WS_PORT,
                        "protocol": "vmess",
                        "settings": {
                            "clients": [{"id": p["uuid"]}],
                        },
                        "streamSettings": {
                            "network": "ws",
                            "security": "none",
                            "wsSettings": {"path": p["vmess_ws_path"]},
                        },
                        "sniffing": {
                            "enabled": True,
                            "destOverride": ["http", "tls"],
                        },
                    },
                ],
                "routing": {
                    "rules": [
                        {
                            "type": "field",
                            "protocol": ["bittorrent"],
                            "outboundTag": "blocked",
                        }
                    ]
                },
                "outbounds": [
                    {"protocol": "freedom", "settings": {}},
                    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
                ],
            }

            (config_dir / "config.json").write_text(
                json.dumps(config, indent=2, ensure_ascii=False) + "\n"
            )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Docker 操作
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def docker_compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=GENERATED_DIR,
        capture_output=False,
    )


def docker_exec(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", "exec", *args], capture_output=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI 命令
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _ensure_env() -> None:
    """检查 .env 文件是否存在，不存在则提示先执行 prepare。"""
    if not ENV_FILE.exists():
        error("请先运行: python3 deploy.py prepare")
        sys.exit(1)


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    """封装 subprocess.run，统一错误处理。"""
    return subprocess.run(cmd, **kwargs)  # noqa: S603


def cmd_prepare(args: argparse.Namespace) -> None:
    """服务器初始化（Python 化的 prepare.sh）。"""
    if os.geteuid() != 0:
        error("prepare 命令需要 root 权限，请使用 sudo 或 root 用户执行")
        sys.exit(1)

    # ── 0. 生成 .env ──
    if ENV_FILE.exists():
        info(".env 已存在，跳过生成")
    else:
        ENV_FILE.write_text(_ENV_TEMPLATE)
        info("已生成 .env 文件，请编辑填入 CF_API_TOKEN")

    # ── 1. 基础工具 ──
    info("安装基础工具...")
    _run(["apt", "update", "-y"])
    _run(
        [
            "apt",
            "install",
            "-y",
            "wget",
            "git",
            "curl",
            "tmux",
            "htop",
            "sysstat",
            "vnstat",
        ]
    )

    # ── 2. SSH 公钥 ──
    info("配置 SSH 公钥...")
    ssh_dir = Path("/root/.ssh")
    ssh_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.chmod(0o700)

    id_rsa = ssh_dir / "id_rsa"
    if not id_rsa.exists():
        _run(["ssh-keygen", "-t", "rsa", "-N", "", "-f", str(id_rsa)])
        info("  生成服务器密钥对 ✓")

    dotenv = load_dotenv()
    ssh_keys = [v for k, v in sorted(dotenv.items()) if k.startswith("SSH_KEY_")]

    if not ssh_keys:
        warn("SSH_KEY_* 未在 .env 中配置，跳过公钥写入")
    else:
        auth_keys = ssh_dir / "authorized_keys"
        existing_keys = auth_keys.read_text() if auth_keys.exists() else ""
        for key in ssh_keys:
            if key not in existing_keys:
                with auth_keys.open("a") as f:
                    f.write(key + "\n")
                tag = key.split()[-1] if key.split() else "unknown"
                info(f"  添加公钥: {tag}")
        auth_keys.chmod(0o600)

    # ── 3. 时区 ──
    info("设置时区 Asia/Shanghai...")
    _run(["timedatectl", "set-timezone", "Asia/Shanghai"])

    # ── 4. SSH 加固（sed 修改关键行，保留系统原始配置） ──
    info("配置 sshd...")
    _run(
        [
            "sed",
            "-i",
            "s/^[# ]*PermitRootLogin.*/PermitRootLogin yes/",
            "/etc/ssh/sshd_config",
        ]
    )
    _run(
        [
            "sed",
            "-i",
            "s/^[# ]*PasswordAuthentication.*/PasswordAuthentication yes/",
            "/etc/ssh/sshd_config",
        ]
    )
    _run(["systemctl", "restart", "sshd"])

    # ── 5. Docker ──
    if shutil.which("docker"):
        info("Docker 已安装，跳过")
    else:
        info("安装 Docker...")
        # 清理旧包
        old_pkgs = [
            "docker.io",
            "docker-compose",
            "docker-doc",
            "podman-docker",
            "containerd",
            "runc",
        ]
        for pkg in old_pkgs:
            _run(["apt", "remove", "-y", pkg], capture_output=True)  # 忽略不存在的包

        _run(["apt", "install", "-y", "ca-certificates", "curl"])

        keyrings_dir = Path("/etc/apt/keyrings")
        keyrings_dir.mkdir(parents=True, exist_ok=True)
        keyrings_dir.chmod(0o755)

        _run(
            [
                "curl",
                "-fsSL",
                "https://download.docker.com/linux/debian/gpg",
                "-o",
                "/etc/apt/keyrings/docker.asc",
            ]
        )
        Path("/etc/apt/keyrings/docker.asc").chmod(0o644)

        # 获取 VERSION_CODENAME
        codename = ""
        os_release = Path("/etc/os-release")
        if os_release.exists():
            for line in os_release.read_text().splitlines():
                if line.startswith("VERSION_CODENAME="):
                    codename = line.split("=", 1)[1].strip().strip('"')
                    break

        if not codename:
            error("无法检测 Debian 版本代号")
            sys.exit(1)

        docker_source = (
            "Types: deb\n"
            "URIs: https://download.docker.com/linux/debian\n"
            f"Suites: {codename}\n"
            "Components: stable\n"
            "Signed-By: /etc/apt/keyrings/docker.asc\n"
        )
        Path("/etc/apt/sources.list.d/docker.sources").write_text(docker_source)

        _run(["apt", "update"])
        _run(
            [
                "apt",
                "install",
                "-y",
                "docker-ce",
                "docker-ce-cli",
                "containerd.io",
                "docker-buildx-plugin",
                "docker-compose-plugin",
            ]
        )
        info("Docker 安装完成 ✓")

    # ── 6. 网络调优（BBR + 代理优化） ──
    info("配置网络参数...")
    sysctl_file = Path("/etc/sysctl.conf")
    sysctl_file.touch(exist_ok=True)
    existing_sysctl = sysctl_file.read_text()
    for param in _SYSCTL_PARAMS:
        if param not in existing_sysctl:
            with sysctl_file.open("a") as f:
                f.write(param + "\n")
    _run(["sysctl", "-p"])

    # ── 7. UFW 防火墙 ──
    info("配置 UFW...")
    _run(["apt", "install", "-y", "ufw"])
    _run(["ufw", "default", "deny", "incoming"])
    _run(["ufw", "default", "allow", "outgoing"])
    _run(["ufw", "allow", "22/tcp"])
    _run(["ufw", "allow", "80/tcp"])
    _run(["ufw", "allow", "443/tcp"])
    _run(["ufw", "allow", "443/udp"])

    result = _run(["ufw", "status"], capture_output=True, text=True)
    if "Status: active" not in (result.stdout or ""):
        _run(["bash", "-c", "yes | ufw enable"])
        info("  UFW 已启用 ✓")
    else:
        info("  UFW 已处于活跃状态，跳过启用")

    # ── 8. fail2ban ──
    info("配置 fail2ban...")
    _run(["apt", "install", "-y", "fail2ban"])
    jail_dir = Path("/etc/fail2ban/jail.d")
    jail_dir.mkdir(parents=True, exist_ok=True)
    (jail_dir / "defaults-debian.conf").write_text(_FAIL2BAN_CONF)
    _run(["systemctl", "restart", "fail2ban"])

    # ── 9. Crontab（流量监控） ──
    info("配置流量监控 crontab...")
    work_dir = Path.cwd().resolve()
    cron_job = f"0 * * * * cd {work_dir} && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1"

    result = _run(["crontab", "-l"], capture_output=True, text=True)
    existing_cron = result.stdout or ""

    if "check-traffic" in existing_cron:
        info("  流量监控 crontab 已存在，跳过")
    else:
        if existing_cron.strip():
            new_cron = existing_cron.rstrip("\n") + "\n" + cron_job + "\n"
        else:
            new_cron = cron_job + "\n"
        subprocess.run(
            ["crontab", "-"],
            input=new_cron,
            text=True,
            check=False,
        )

        # 验证
        verify = _run(["crontab", "-l"], capture_output=True, text=True)
        if "check-traffic" in (verify.stdout or ""):
            info("  已添加流量监控 crontab ✓")
        else:
            warn(f"  crontab 写入失败，请手动添加: {cron_job}")

    # ── 完成 ──
    print()
    info("=========================================")
    info("  服务器初始化完成 ✓")
    info("=========================================")

    tz_result = _run(
        ["timedatectl", "show", "-p", "Timezone", "--value"],
        capture_output=True,
        text=True,
    )
    docker_result = _run(["docker", "--version"], capture_output=True, text=True)
    bbr_result = _run(
        ["sysctl", "net.ipv4.tcp_congestion_control"],
        capture_output=True,
        text=True,
    )
    f2b_result = _run(
        ["systemctl", "is-active", "fail2ban"],
        capture_output=True,
        text=True,
    )

    info(f"  时区: {(tz_result.stdout or '').strip()}")
    info(f"  Docker: {(docker_result.stdout or '').strip()}")
    info(f"  BBR: {(bbr_result.stdout or '').strip()}")
    info(f"  fail2ban: {(f2b_result.stdout or '').strip()}")
    print()
    info("下一步: 编辑 .env 填入 CF_API_TOKEN，然后运行 python3 deploy.py init")


def cmd_init(args: argparse.Namespace) -> None:
    _ensure_env()
    dotenv = load_dotenv()

    if SERVICES_FILE.exists():
        warn("services.json 已存在")
        if not confirm_prompt("覆盖?"):
            info("已取消")
            return

    cf_token = get_env("CF_API_TOKEN", args.token, dotenv)
    default_uuid = get_env("DEFAULT_UUID", args.uuid, dotenv) or generate_uuid()
    redirect_url = get_env("REDIRECT_URL", args.redirect, dotenv)
    if not redirect_url:
        error("REDIRECT_URL 未配置。请在 .env 中设置 REDIRECT_URL= 或使用 -r 参数")
        sys.exit(1)
    vless_path = (
        get_env("DEFAULT_VLESS_WS_PATH", args.vless_ws_path, dotenv)
        or generate_random_path()
    )
    vmess_path = (
        get_env("DEFAULT_VMESS_WS_PATH", args.vmess_ws_path, dotenv)
        or generate_random_path()
    )

    # 检测公网 IP
    info("正在检测服务器公网 IP...")
    server_ip = detect_public_ip()
    if server_ip:
        info(f"检测到公网 IP: {server_ip}")
    else:
        warn("无法自动检测公网 IP，DNS 记录需手动创建")

    registry = Registry(
        cf_api_token=cf_token,
        redirect_url=redirect_url,
        server_ip=server_ip,
        default_uuid=default_uuid,
        default_vless_ws_path=vless_path,
        default_vmess_ws_path=vmess_path,
    )
    registry.save()

    info("已初始化 services.json")
    print()
    print(f"  {Color.CYAN}服务器 IP:{Color.NC}          {server_ip or '未检测到'}")
    print(f"  {Color.CYAN}默认 UUID:{Color.NC}          {default_uuid}")
    print(f"  {Color.CYAN}默认 VLESS WS 路径:{Color.NC} {vless_path}")
    print(f"  {Color.CYAN}默认 VMess WS 路径:{Color.NC} {vmess_path}")
    print()
    info("所有代理节点共用以上配置，客户端只需配一次")

    if cf_token:
        info("正在验证 Cloudflare API Token...")
        cf = CloudflareClient(cf_token)
        if cf.verify_token():
            info("Cloudflare API Token 验证通过 ✓")
        else:
            warn("API Token 验证失败，请检查权限")
    else:
        warn(
            "CF_API_TOKEN 未设置。请在 .env 文件中配置或运行: deploy.py init -t <token>"
        )


def cmd_add_proxy(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()

    existing = reg.find_domain(args.domain)
    if existing:
        if args.force:
            info(f"强制覆盖: {args.domain}")
            reg.remove_service(args.domain)
        elif confirm_prompt(f"域名 {args.domain} 已存在，是否覆盖?"):
            reg.remove_service(args.domain)
        else:
            info("已取消")
            return

    # 确定 UUID
    if args.uuid:
        svc_uuid = args.uuid
    elif args.new_uuid:
        svc_uuid = generate_uuid()
    else:
        svc_uuid = reg.default_uuid or generate_uuid()

    container_name = f"xray-{args.domain.split('.')[0]}"

    service = {
        "type": "proxy",
        "domain": args.domain,
        "uuid": svc_uuid,
        "vless_ws_path": reg.default_vless_ws_path or "/vless",
        "vmess_ws_path": reg.default_vmess_ws_path or "/vmess",
        "container_name": container_name,
    }
    reg.add_service(service)

    info(f"已添加代理节点: {args.domain}")
    print()
    print(f"  {Color.CYAN}域名:{Color.NC}            {args.domain}")
    print(f"  {Color.CYAN}UUID:{Color.NC}            {svc_uuid}")
    print(f"  {Color.CYAN}VLESS WS 路径:{Color.NC}   {service['vless_ws_path']}")
    print(f"  {Color.CYAN}VMess WS 路径:{Color.NC}   {service['vmess_ws_path']}")
    print(f"  {Color.CYAN}容器名:{Color.NC}          {container_name}")
    print()

    if not args.no_dns:
        auto_create_dns(reg, args.domain, force=args.force)

    warn("运行 'deploy.py up' 使配置生效")


def cmd_add_service(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()

    existing = reg.find_domain(args.domain)
    if existing:
        if args.force:
            info(f"强制覆盖: {args.domain}")
            reg.remove_service(args.domain)
        elif confirm_prompt(f"域名 {args.domain} 已存在，是否覆盖?"):
            reg.remove_service(args.domain)
        else:
            info("已取消")
            return

    allowed_ips = (
        [ip.strip() for ip in args.allow_ips.split(",") if ip.strip()]
        if args.allow_ips
        else []
    )
    if allowed_ips:
        invalid = validate_ip_list(allowed_ips)
        if invalid:
            error(f"无效的 IP 地址: {', '.join(invalid)}")
            sys.exit(1)

    # Docker 容器内 localhost 指向容器自身，自动转换为宿主机地址
    target = args.target
    if target.startswith(("localhost:", "127.0.0.1:")):
        original = target
        target = target.replace("localhost:", "host.docker.internal:", 1).replace(
            "127.0.0.1:", "host.docker.internal:", 1
        )
        info(
            f"已自动转换: {original} → {target} (Docker 容器内需通过 host.docker.internal 访问宿主机)"
        )

    service = {
        "type": "service",
        "domain": args.domain,
        "target": target,
        "allowed_ips": allowed_ips,
    }
    reg.add_service(service)

    info(f"已添加服务反代: {args.domain} → {args.target}")
    if allowed_ips:
        info(f"IP 白名单: {', '.join(allowed_ips)}")
    print()

    if not args.no_dns:
        auto_create_dns(reg, args.domain, force=args.force)

    warn("运行 'deploy.py reload' 使配置生效（零停机）")


def cmd_remove(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()

    svc = reg.remove_service(args.domain)
    if not svc:
        error(f"域名 {args.domain} 不存在")
        sys.exit(1)

    info(f"已删除: {args.domain}")

    if not args.keep_dns:
        auto_delete_dns(reg, args.domain)

    warn("运行 'deploy.py reload' 使配置生效")


def cmd_list(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()

    if not reg.services:
        info("还没有添加任何服务")
        print("  运行: deploy.py add-proxy -d <域名>")
        print("  运行: deploy.py add-service -d <域名> -t <目标>")
        return

    print()
    print(
        f"{Color.BOLD}{Color.CYAN}已注册的服务 (共 {len(reg.services)} 个):{Color.NC}"
    )
    if reg.server_ip:
        print(f"  服务器 IP: {reg.server_ip}")
    print()

    proxies = reg.proxies
    if proxies:
        print(f"  {Color.BOLD}▸ Xray 代理节点{Color.NC}")
        for p in proxies:
            print(
                f"    {Color.GREEN}●{Color.NC} {p['domain']}  ({p['container_name']})"
            )
            print(f"      UUID: {p['uuid']}")
            print(
                f"      VLESS+WS: {p['vless_ws_path']}  |  VMess+WS: {p['vmess_ws_path']}"
            )
        print()

    services = reg.reverse_proxies
    if services:
        print(f"  {Color.BOLD}▸ 服务反代{Color.NC}")
        for s in services:
            print(f"    {Color.GREEN}●{Color.NC} {s['domain']} → {s['target']}")
        print()


def cmd_generate(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()
    ConfigGenerator(reg).generate_all()


def cmd_up(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()
    ConfigGenerator(reg).generate_all()

    print()
    info("正在启动 Docker 服务...")
    docker_compose("up", "-d")
    print()
    info("所有服务已启动 ✓")
    print()
    docker_compose("ps")


def cmd_reload(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()
    ConfigGenerator(reg).generate_all()
    print()

    needs_restart = False
    try:
        running = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}"],
            cwd=GENERATED_DIR,
            capture_output=True,
            text=True,
        )
        config = subprocess.run(
            ["docker", "compose", "config", "--services"],
            cwd=GENERATED_DIR,
            capture_output=True,
            text=True,
        )
        if set(running.stdout.strip().splitlines()) != set(
            config.stdout.strip().splitlines()
        ):
            needs_restart = True
    except FileNotFoundError:
        needs_restart = True

    if needs_restart:
        warn("检测到容器变更（新增/删除代理节点），需要 docker compose up")
        docker_compose("up", "-d")
        info("所有服务已更新 ✓")
    else:
        info("热加载 Caddy 配置...")
        docker_exec("caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile")
        info("Caddy 配置已热加载 ✓（零停机）")

    print()
    docker_compose("ps")


def cmd_check_traffic(args: argparse.Namespace) -> None:
    _ensure_env()
    from datetime import datetime

    dotenv = load_dotenv()
    limit_gb_str = get_env("TRAFFIC_LIMIT_GB", "", dotenv)
    bot_token = get_env("TELEGRAM_BOT_TOKEN", "", dotenv)
    chat_id = get_env("TELEGRAM_CHAT_ID", "", dotenv)
    host = socket.gethostname()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    if not limit_gb_str:
        print(f"{ts} {host} | ERROR: TRAFFIC_LIMIT_GB not set")
        sys.exit(1)

    try:
        limit_gb = float(limit_gb_str)
    except ValueError:
        print(f"{ts} {host} | ERROR: TRAFFIC_LIMIT_GB invalid: {limit_gb_str}")
        sys.exit(1)

    tx_gb = get_vnstat_monthly_tx_gb(dotenv)
    if tx_gb is None:
        print(f"{ts} {host} | ERROR: vnstat unavailable")
        msg = f"⚠️ *nano-xray 流量监控*\n主机: `{host}`\nvnstat 未运行或不可用，无法监控流量！"
        send_telegram(bot_token, chat_id, msg)
        sys.exit(1)

    usage = f"{tx_gb:.2f}/{limit_gb:.0f} GB"

    if tx_gb >= limit_gb:
        ufw_block_ports()
        print(f"{ts} {host} | {usage} | BLOCKED")
        msg = (
            f"🚨 *nano-xray 流量超限*\n"
            f"主机: `{host}`\n"
            f"当月出站: `{tx_gb:.2f} GB` / `{limit_gb:.0f} GB`\n"
            f"已自动封锁 80/443 端口"
        )
        send_telegram(bot_token, chat_id, msg)
    else:
        if _has_ufw():
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
            )
            ports_blocked = "443/tcp" in result.stdout and "DENY" in result.stdout
        else:
            ports_blocked = False
        if ports_blocked:
            ufw_allow_ports()
            print(f"{ts} {host} | {usage} | UNBLOCKED")
            msg = (
                f"✅ *nano-xray 流量恢复*\n"
                f"主机: `{host}`\n"
                f"当月出站: `{tx_gb:.2f} GB` / `{limit_gb:.0f} GB`\n"
                f"已自动解封 80/443 端口"
            )
            send_telegram(bot_token, chat_id, msg)
        else:
            print(f"{ts} {host} | {usage} | OK")


def cmd_update_ips(args: argparse.Namespace) -> None:
    _ensure_env()
    reg = Registry.load()
    svc = reg.find_domain(args.domain)

    if not svc:
        error(f"域名 {args.domain} 不存在")
        sys.exit(1)

    if svc["type"] != "service":
        error(f"{args.domain} 是代理节点，不支持 IP 白名单")
        sys.exit(1)

    current_ips: list[str] = svc.get("allowed_ips", [])

    # --list
    if args.list_ips:
        if current_ips:
            info(f"{args.domain} 当前白名单:")
            for ip in current_ips:
                print(f"  - {ip}")
        else:
            info(f"{args.domain} 无 IP 白名单（允许所有）")
        return

    changed = False

    # --add
    if args.add:
        new_ips = [ip.strip() for ip in args.add.split(",") if ip.strip()]
        invalid = validate_ip_list(new_ips)
        if invalid:
            error(f"无效的 IP 地址: {', '.join(invalid)}")
            sys.exit(1)
        for ip in new_ips:
            if ip not in current_ips:
                current_ips.append(ip)
                info(f"已添加: {ip}")
                changed = True
            else:
                warn(f"已存在: {ip}")

    # --remove
    if args.remove:
        rm_ips = [ip.strip() for ip in args.remove.split(",") if ip.strip()]
        for ip in rm_ips:
            if ip in current_ips:
                current_ips.remove(ip)
                info(f"已删除: {ip}")
                changed = True
            else:
                warn(f"不存在: {ip}")

    if changed:
        svc["allowed_ips"] = current_ips
        reg.save()
        info(
            f"当前白名单: {', '.join(current_ips) if current_ips else '无（允许所有）'}"
        )
        warn("运行 'deploy.py reload' 使配置生效")
    elif not args.add and not args.remove:
        error("请指定 --add、--remove 或 --list")
        sys.exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI 入口
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deploy.py",
        description="nano-xray — 单机多服务 Caddy 管理工具",
    )
    sub = parser.add_subparsers(dest="command", help="可用命令")

    # prepare
    p_prepare = sub.add_parser(
        "prepare", help="服务器初始化（安装 Docker/BBR/UFW/fail2ban 等）"
    )
    p_prepare.set_defaults(func=cmd_prepare)

    # init
    p_init = sub.add_parser("init", help="初始化项目")
    p_init.add_argument(
        "-t", "--token", default="", help="Cloudflare API Token (也可在 .env 中配置)"
    )
    p_init.add_argument(
        "-r", "--redirect", default="", help="默认重定向 URL (也可在 .env 中配置)"
    )
    p_init.add_argument(
        "-u", "--uuid", default="", help="指定默认 UUID (也可在 .env 中配置)"
    )
    p_init.add_argument(
        "--vless-ws-path", default="", help="指定 VLESS WS 路径 (也可在 .env 中配置)"
    )
    p_init.add_argument(
        "--vmess-ws-path", default="", help="指定 VMess WS 路径 (也可在 .env 中配置)"
    )
    p_init.set_defaults(func=cmd_init)

    # add-proxy
    p_proxy = sub.add_parser("add-proxy", help="添加 Xray 代理节点")
    p_proxy.add_argument("-d", "--domain", required=True, help="节点域名")
    p_proxy.add_argument(
        "-u", "--uuid", default="", help="UUID (默认: 使用 init 时设定的值)"
    )
    p_proxy.add_argument("--new-uuid", action="store_true", help="强制生成新 UUID")
    p_proxy.add_argument("--no-dns", action="store_true", help="不自动创建 DNS 记录")
    p_proxy.add_argument(
        "-f", "--force", action="store_true", help="域名已存在时强制覆盖"
    )
    p_proxy.set_defaults(func=cmd_add_proxy)

    # add-service
    p_svc = sub.add_parser("add-service", help="添加通用服务反代")
    p_svc.add_argument("-d", "--domain", required=True, help="服务域名")
    p_svc.add_argument(
        "-t",
        "--target",
        required=True,
        help="后端地址 (如 localhost:8317，localhost 会自动转为 host.docker.internal)",
    )
    p_svc.add_argument("--no-dns", action="store_true", help="不自动创建 DNS 记录")
    p_svc.add_argument(
        "-f", "--force", action="store_true", help="域名已存在时强制覆盖"
    )
    p_svc.add_argument(
        "--allow-ips", default="", help="IP 白名单，逗号分隔 (如 1.2.3.0/24,5.6.7.8)"
    )
    p_svc.set_defaults(func=cmd_add_service)

    # remove
    p_rm = sub.add_parser("remove", help="删除绑定")
    p_rm.add_argument("-d", "--domain", required=True, help="域名")
    p_rm.add_argument("--keep-dns", action="store_true", help="保留 DNS 记录")
    p_rm.set_defaults(func=cmd_remove)

    # list
    p_ls = sub.add_parser("list", help="列出所有绑定")
    p_ls.set_defaults(func=cmd_list)

    # generate
    p_gen = sub.add_parser("generate", help="生成配置文件（不启动）")
    p_gen.set_defaults(func=cmd_generate)

    # up
    p_up = sub.add_parser("up", help="生成配置并启动 Docker 服务")
    p_up.set_defaults(func=cmd_up)

    # reload
    p_reload = sub.add_parser("reload", help="重新生成配置并热加载（零停机）")
    p_reload.set_defaults(func=cmd_reload)

    # check-traffic
    p_traffic = sub.add_parser("check-traffic", help="检查当月流量，超限自动封端口")
    p_traffic.set_defaults(func=cmd_check_traffic)

    # update-ips
    p_ips = sub.add_parser("update-ips", help="管理服务 IP 白名单")
    p_ips.add_argument("-d", "--domain", required=True, help="服务域名")
    p_ips.add_argument("--add", default="", help="添加 IP，逗号分隔")
    p_ips.add_argument("--remove", default="", help="删除 IP，逗号分隔")
    p_ips.add_argument(
        "--list", dest="list_ips", action="store_true", help="列出当前白名单"
    )
    p_ips.set_defaults(func=cmd_update_ips)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
