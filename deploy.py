#!/usr/bin/env python3
"""nano-xray — 单机多服务 Caddy 管理工具 (零外部依赖)"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
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
    redirect_url: str = "https://www.qadmlee.com"
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Cloudflare API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CloudflareClient:
    def __init__(self, token: str):
        self.token = token

    def _request(self, method: str, endpoint: str, data: dict | None = None) -> dict:
        url = f"{CF_API}{endpoint}"
        body = json.dumps(data).encode() if data else None
        req = Request(url, data=body, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })
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

    def create_or_update_dns(self, zone_id: str, domain: str, ip: str) -> bool:
        result = self._request("GET", f"/zones/{zone_id}/dns_records?type=A&name={domain}")
        existing = result.get("result", [])

        record_data = {
            "type": "A",
            "name": domain,
            "content": ip,
            "ttl": 1,
            "proxied": False,
        }

        if existing:
            record_id = existing[0]["id"]
            resp = self._request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", record_data)
            if resp.get("success"):
                info(f"已更新 DNS 记录: {domain} → {ip} (DNS only)")
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
        result = self._request("GET", f"/zones/{zone_id}/dns_records?type=A&name={domain}")
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


def auto_create_dns(registry: Registry, domain: str) -> None:
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
    cf.create_or_update_dns(zone_id, domain, registry.server_ip)


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
        if GENERATED_DIR.exists():
            shutil.rmtree(GENERATED_DIR)
        GENERATED_DIR.mkdir(parents=True)

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

                lines.extend([
                    f"{domain} {{",
                    "\ttls {",
                    "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}",
                    "\t}",
                    "",
                    f"\treverse_proxy {vless_path} {container}:{VLESS_WS_PORT}",
                    f"\treverse_proxy {vmess_path} {container}:{VMESS_WS_PORT}",
                    "",
                    "\t@not_ws {",
                    f"\t\tnot path {vless_path}",
                    f"\t\tnot path {vmess_path}",
                    "\t}",
                    f"\tredir @not_ws {redirect}{{uri}} permanent",
                    "}",
                ])

            elif svc["type"] == "service":
                target = svc["target"]
                lines.extend([
                    f"{domain} {{",
                    "\ttls {",
                    "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}",
                    "\t}",
                    "",
                    f"\treverse_proxy {target}",
                    "}",
                ])

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

        proxies = self.reg.proxies
        if proxies:
            lines.append("    depends_on:")
            for p in proxies:
                lines.append(f"      - {p['container_name']}")

        for p in proxies:
            cn = p["container_name"]
            lines.extend([
                "",
                f"  {cn}:",
                "    image: ghcr.io/xtls/xray-core:latest",
                f"    container_name: {cn}",
                "    restart: always",
                '    command: ["run", "-config", "/etc/xray/config.json"]',
                "    volumes:",
                f"      - ./xray/{cn}/config.json:/etc/xray/config.json",
                "    expose:",
                f'      - "{VLESS_WS_PORT}"',
                f'      - "{VMESS_WS_PORT}"',
            ])

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

def cmd_init(args: argparse.Namespace) -> None:
    dotenv = load_dotenv()

    if SERVICES_FILE.exists():
        warn("services.json 已存在")
        if not confirm_prompt("覆盖?"):
            info("已取消")
            return

    # 从 CLI > 环境变量 > .env 文件 读取
    cf_token = get_env("CF_API_TOKEN", args.token, dotenv)
    default_uuid = get_env("DEFAULT_UUID", args.uuid, dotenv) or generate_uuid()
    vless_path = get_env("DEFAULT_VLESS_WS_PATH", "", dotenv) or generate_random_path()
    vmess_path = get_env("DEFAULT_VMESS_WS_PATH", "", dotenv) or generate_random_path()

    # 检测公网 IP
    info("正在检测服务器公网 IP...")
    server_ip = detect_public_ip()
    if server_ip:
        info(f"检测到公网 IP: {server_ip}")
    else:
        warn("无法自动检测公网 IP，DNS 记录需手动创建")

    registry = Registry(
        cf_api_token=cf_token,
        redirect_url=args.redirect,
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
        warn("CF_API_TOKEN 未设置。请在 .env 文件中配置或运行: deploy.py init -t <token>")


def cmd_add_proxy(args: argparse.Namespace) -> None:
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
        auto_create_dns(reg, args.domain)

    warn("运行 'deploy.py up' 使配置生效")


def cmd_add_service(args: argparse.Namespace) -> None:
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

    service = {
        "type": "service",
        "domain": args.domain,
        "target": args.target,
    }
    reg.add_service(service)

    info(f"已添加服务反代: {args.domain} → {args.target}")
    print()

    if not args.no_dns:
        auto_create_dns(reg, args.domain)

    warn("运行 'deploy.py reload' 使配置生效（零停机）")


def cmd_remove(args: argparse.Namespace) -> None:
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
    reg = Registry.load()

    if not reg.services:
        info("还没有添加任何服务")
        print("  运行: deploy.py add-proxy -d <域名>")
        print("  运行: deploy.py add-service -d <域名> -t <目标>")
        return

    print()
    print(f"{Color.BOLD}{Color.CYAN}已注册的服务 (共 {len(reg.services)} 个):{Color.NC}")
    if reg.server_ip:
        print(f"  服务器 IP: {reg.server_ip}")
    print()

    proxies = reg.proxies
    if proxies:
        print(f"  {Color.BOLD}▸ Xray 代理节点{Color.NC}")
        for p in proxies:
            print(f"    {Color.GREEN}●{Color.NC} {p['domain']}  ({p['container_name']})")
            print(f"      UUID: {p['uuid']}")
            print(f"      VLESS+WS: {p['vless_ws_path']}  |  VMess+WS: {p['vmess_ws_path']}")
        print()

    services = reg.reverse_proxies
    if services:
        print(f"  {Color.BOLD}▸ 服务反代{Color.NC}")
        for s in services:
            print(f"    {Color.GREEN}●{Color.NC} {s['domain']} → {s['target']}")
        print()


def cmd_generate(args: argparse.Namespace) -> None:
    reg = Registry.load()
    ConfigGenerator(reg).generate_all()


def cmd_up(args: argparse.Namespace) -> None:
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
    reg = Registry.load()
    ConfigGenerator(reg).generate_all()
    print()

    needs_restart = False
    try:
        running = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}"],
            cwd=GENERATED_DIR, capture_output=True, text=True,
        )
        config = subprocess.run(
            ["docker", "compose", "config", "--services"],
            cwd=GENERATED_DIR, capture_output=True, text=True,
        )
        if set(running.stdout.strip().splitlines()) != set(config.stdout.strip().splitlines()):
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI 入口
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deploy.py",
        description="nano-xray — 单机多服务 Caddy 管理工具",
    )
    sub = parser.add_subparsers(dest="command", help="可用命令")

    # init
    p_init = sub.add_parser("init", help="初始化项目")
    p_init.add_argument("-t", "--token", default="", help="Cloudflare API Token (也可在 .env 中配置)")
    p_init.add_argument("-r", "--redirect", default="https://www.qadmlee.com", help="默认重定向 URL")
    p_init.add_argument("-u", "--uuid", default="", help="指定默认 UUID (也可在 .env 中配置)")
    p_init.set_defaults(func=cmd_init)

    # add-proxy
    p_proxy = sub.add_parser("add-proxy", help="添加 Xray 代理节点")
    p_proxy.add_argument("-d", "--domain", required=True, help="节点域名")
    p_proxy.add_argument("-u", "--uuid", default="", help="UUID (默认: 使用 init 时设定的值)")
    p_proxy.add_argument("--new-uuid", action="store_true", help="强制生成新 UUID")
    p_proxy.add_argument("--no-dns", action="store_true", help="不自动创建 DNS 记录")
    p_proxy.add_argument("-f", "--force", action="store_true", help="域名已存在时强制覆盖")
    p_proxy.set_defaults(func=cmd_add_proxy)

    # add-service
    p_svc = sub.add_parser("add-service", help="添加通用服务反代")
    p_svc.add_argument("-d", "--domain", required=True, help="服务域名")
    p_svc.add_argument("-t", "--target", required=True, help="后端地址 (如 localhost:8317)")
    p_svc.add_argument("--no-dns", action="store_true", help="不自动创建 DNS 记录")
    p_svc.add_argument("-f", "--force", action="store_true", help="域名已存在时强制覆盖")
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
