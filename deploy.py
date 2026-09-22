#!/usr/bin/env python3
"""nano-xray — 单机多服务 Caddy 管理工具 (零外部依赖)"""

from __future__ import annotations

import argparse
import base64
import binascii
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

import fcntl
import hashlib
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, cast

SCHEMA_VERSION = 1
NODE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
LINK_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")


class ValidationError(ValueError):
    """Raised when desired topology data is inconsistent."""


@dataclass(slots=True)
class Node:
    id: str
    host: str
    endpoint: str = ""
    remote_dir: str = "/root/nano-xray"
    domain: str = ""
    network_profile: str = "bridge"
    ssh_key: str = ""
    imported_services: str = ""
    services_hash: str = ""
    service_ports: dict[str, dict[str, int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.endpoint and self.host:
            self.endpoint = self.host.rsplit("@", 1)[-1]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Node:
        return cls(
            id=str(data.get("id", "")),
            host=str(data.get("host", "")),
            endpoint=str(data.get("endpoint", "")),
            remote_dir=str(data.get("remote_dir", "/root/nano-xray")),
            domain=str(data.get("domain", "")),
            network_profile=str(data.get("network_profile", "bridge")),
            ssh_key=str(data.get("ssh_key", "")),
            imported_services=str(data.get("imported_services", "")),
            services_hash=str(data.get("services_hash", "")),
            service_ports={
                str(service_id): {
                    "vless": int(ports["vless"]),
                    "vmess": int(ports["vmess"]),
                }
                for service_id, ports in data.get("service_ports", {}).items()
            },
        )

    def validate(self) -> None:
        if not NODE_ID_RE.fullmatch(self.id):
            raise ValidationError(f"非法 Node ID: {self.id}")
        if self.host and any(char.isspace() for char in self.host):
            raise ValidationError(f"Node {self.id} 的 SSH host 无效")
        if self.endpoint and any(char.isspace() for char in self.endpoint):
            raise ValidationError(f"Node {self.id} 的公网 endpoint 无效")
        if self.network_profile not in {"bridge", "host-l3"}:
            raise ValidationError(f"Node {self.id} 的 network_profile 无效")
        if not self.remote_dir.startswith("/"):
            raise ValidationError(f"Node {self.id} 的 remote_dir 必须是绝对路径")
        if self.services_hash and not re.fullmatch(r"[0-9a-f]{64}", self.services_hash):
            raise ValidationError(f"Node {self.id} 的 services_hash 无效")
        ports = [
            port
            for allocation in self.service_ports.values()
            for port in allocation.values()
        ]
        if len(ports) != len(set(ports)) or any(
            port < 1 or port > 65535 for port in ports
        ):
            raise ValidationError(f"Node {self.id} 的 Service 端口分配冲突")
        if any(set(item) != {"vless", "vmess"} for item in self.service_ports.values()):
            raise ValidationError(f"Node {self.id} 的 Service 端口字段无效")


@dataclass(slots=True)
class Link:
    id: str
    source: str
    target: str
    entry_service: str
    exit_service: str = ""
    protocol: str = "both"
    exit_protocol: str = "vless"
    transport: str = "xray"
    enabled: bool = True
    client_uuid: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Link:
        values = dict(data)
        # Read the earlier WG-L3 schema so an existing inventory can be migrated
        # by simply saving it again.
        allocation = values.pop("allocation", None)
        if not values.get("client_uuid") and allocation:
            values["client_uuid"] = allocation.get("client_uuid", "")
        if values.get("transport") == "wg-l3":
            values["transport"] = "xray"
        return cls(**values)

    def validate(self) -> None:
        if not LINK_ID_RE.fullmatch(self.id):
            raise ValidationError(f"非法 Link ID: {self.id}")
        if self.source == self.target:
            raise ValidationError(f"Link {self.id} 不能连接同一 Node")
        if self.protocol not in {"vmess", "vless", "both"}:
            raise ValidationError(f"Link {self.id} 的 protocol 无效")
        if self.exit_protocol not in {"vmess", "vless"}:
            raise ValidationError(f"Link {self.id} 的 exit_protocol 无效")
        if self.transport != "xray":
            raise ValidationError(f"Link {self.id} 的 transport 无效")
        if not self.entry_service:
            raise ValidationError(f"Link {self.id} 缺少 entry_service")
        if not self.exit_service:
            raise ValidationError(f"Link {self.id} 缺少 exit_service")
        try:
            uuid.UUID(self.client_uuid)
        except ValueError as exc:
            raise ValidationError(f"Link {self.id} 的 client_uuid 无效") from exc


@dataclass(slots=True)
class LinkTombstone:
    id: str
    source: str
    target: str
    client_uuid: str
    removed_at: str
    entry_service: str = ""

    @classmethod
    def from_link(cls, link: Link) -> LinkTombstone:
        return cls(
            id=link.id,
            source=link.source,
            target=link.target,
            client_uuid=link.client_uuid,
            removed_at=datetime.now(timezone.utc).isoformat(),
            entry_service=link.entry_service,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LinkTombstone:
        return cls(
            id=str(data["id"]),
            source=str(data["source"]),
            target=str(data["target"]),
            client_uuid=str(
                data.get("client_uuid")
                or data.get("allocation", {}).get("client_uuid", "")
            ),
            removed_at=str(data["removed_at"]),
            entry_service=str(data.get("entry_service") or f"xray-{data['source']}"),
        )

    def validate(self) -> None:
        if not LINK_ID_RE.fullmatch(self.id):
            raise ValidationError(f"非法 tombstone Link ID: {self.id}")
        if self.source == self.target:
            raise ValidationError(f"tombstone {self.id} 两端不能相同")
        try:
            uuid.UUID(self.client_uuid)
        except ValueError as exc:
            raise ValidationError(f"tombstone {self.id} 的 client_uuid 无效") from exc


@dataclass(slots=True)
class Topology:
    schema_version: int = SCHEMA_VERSION
    nodes: list[Node] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    tombstones: list[LinkTombstone] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Topology:
        version = data.get("schema_version", 0)
        if version != SCHEMA_VERSION:
            raise ValidationError(f"不支持的 topology schema_version: {version}")
        return cls(
            schema_version=version,
            nodes=[Node.from_dict(item) for item in data.get("nodes", [])],
            links=[Link.from_dict(item) for item in data.get("links", [])],
            tombstones=[
                LinkTombstone.from_dict(item) for item in data.get("tombstones", [])
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def node(self, node_id: str) -> Node | None:
        return next((node for node in self.nodes if node.id == node_id), None)

    def link(self, link_id: str) -> Link | None:
        return next((link for link in self.links if link.id == link_id), None)

    def validate(self) -> None:
        node_ids = [node.id for node in self.nodes]
        link_ids = [link.id for link in self.links]
        if len(node_ids) != len(set(node_ids)):
            raise ValidationError("Node ID 重复")
        if len(link_ids) != len(set(link_ids)):
            raise ValidationError("Link ID 重复")
        tombstone_ids = [item.id for item in self.tombstones]
        if len(tombstone_ids) != len(set(tombstone_ids)):
            raise ValidationError("tombstone Link ID 重复")
        if set(link_ids) & set(tombstone_ids):
            raise ValidationError("活动 Link ID 不能同时存在于 tombstone")
        for node in self.nodes:
            node.validate()
        for link in self.links:
            link.validate()
            if link.source not in node_ids or link.target not in node_ids:
                raise ValidationError(f"Link {link.id} 引用了不存在的 Node")
        for tombstone in self.tombstones:
            tombstone.validate()
            if tombstone.source not in node_ids or tombstone.target not in node_ids:
                raise ValidationError(f"tombstone {tombstone.id} 引用了不存在的 Node")

        client_uuids = [link.client_uuid for link in self.links]
        if len(client_uuids) != len(set(client_uuids)):
            raise ValidationError("Link client_uuid 冲突")


class TopologyStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock_path = path.with_suffix(path.suffix + ".lock")

    @contextmanager
    def locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield

    def load(self) -> Topology:
        if not self.path.exists():
            return Topology()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"无法读取拓扑文件 {self.path}: {exc}") from exc
        topology = Topology.from_dict(data)
        self._migrate_legacy_links(topology)
        topology.validate()
        return topology

    def _migrate_legacy_links(self, topology: Topology) -> None:
        """Resolve the target service omitted by the former WG Link schema."""
        root = self.path.parent.parent
        for link in topology.links:
            if link.exit_service:
                continue
            target = topology.node(link.target)
            if target is None or not target.imported_services:
                raise ValidationError(
                    f"旧 Link {link.id} 缺少 exit_service，且无法读取 target Service"
                )
            try:
                data = json.loads(
                    (root / target.imported_services).read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise ValidationError(
                    f"旧 Link {link.id} 无法读取 target Service: {exc}"
                ) from exc
            proxies = [
                service
                for service in data.get("services", [])
                if service.get("type") == "proxy"
            ]
            if len(proxies) != 1:
                raise ValidationError(
                    f"旧 Link {link.id} 缺少 exit_service，target 必须恰有一个 proxy Service"
                )
            link.exit_service = str(
                proxies[0].get("container_name") or proxies[0].get("domain") or ""
            )

    def save(self, topology: Topology) -> None:
        topology.validate()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = json.dumps(topology.to_dict(), indent=2, ensure_ascii=False) + "\n"
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)


def allocate(topology: Topology) -> str:
    """Allocate only the source-side client identity needed by an Xray Link."""
    used = {link.client_uuid for link in topology.links}
    used.update(item.client_uuid for item in topology.tombstones)
    while True:
        candidate = str(uuid.uuid4())
        if candidate not in used:
            return candidate


def topology_hash(topology: Topology) -> str:
    payload = json.dumps(topology.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def build_plan(
    topology: Topology, node_ids: list[str], link_ids: list[str]
) -> dict[str, Any]:
    selected_nodes = set(node_ids)
    selected_links = set(link_ids)
    explicitly_selected_nodes = set(node_ids)
    for link in topology.links:
        if link.id in selected_links or (
            explicitly_selected_nodes and link.source in explicitly_selected_nodes
        ):
            selected_nodes.add(link.source)
            selected_links.add(link.id)
    if not node_ids and not link_ids:
        selected_nodes.update(node.id for node in topology.nodes)
        selected_links.update(link.id for link in topology.links)
    cleanup = []
    for tombstone in topology.tombstones:
        if (
            (not node_ids and not link_ids)
            or tombstone.id in selected_links
            or tombstone.source in explicitly_selected_nodes
        ):
            selected_nodes.add(tombstone.source)
            selected_links.add(tombstone.id)
            cleanup.append(
                {
                    "action": "cleanup-link",
                    "link": tombstone.id,
                    "node": tombstone.source,
                    "client_uuid": tombstone.client_uuid,
                }
            )
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "topology_hash": topology_hash(topology),
        "affected_nodes": sorted(selected_nodes),
        "affected_links": sorted(selected_links),
        "actions": cleanup
        + [{"action": "render", "node": node_id} for node_id in sorted(selected_nodes)],
    }


CADDY_IMAGE = "caddybuilds/caddy-cloudflare:latest"
XRAY_IMAGE = "ghcr.io/xtls/xray-core:26.2.6"


def _read_services(root: Path, node: Node) -> dict[str, Any]:
    if not node.imported_services:
        raise ValidationError(f"Node {node.id} 没有 Service 源配置")
    path = root / node.imported_services
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"无法读取 Node {node.id} Service 配置: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        raise ValidationError(f"Node {node.id} Service 配置格式无效")
    return data


def _service_id(service: dict[str, Any]) -> str:
    return str(service.get("container_name") or service.get("domain") or "")


def _matches_entry(service: dict[str, Any], entry_service: str) -> bool:
    domain = str(service.get("domain", ""))
    container = str(service.get("container_name", ""))
    candidates = {
        domain,
        domain.split(".", 1)[0],
        container,
        container.removeprefix("xray-"),
    }
    return entry_service in candidates


def _links_for_service(
    topology: Topology, node: Node, service: dict[str, Any]
) -> list[Link]:
    return [
        link
        for link in topology.links
        if link.enabled
        and link.source == node.id
        and _matches_entry(service, link.entry_service)
    ]


def _proxy_services(root: Path, node: Node) -> list[dict[str, Any]]:
    return [
        service
        for service in _read_services(root, node)["services"]
        if service.get("type") == "proxy"
    ]


def _find_proxy_service(root: Path, node: Node, service_name: str) -> dict[str, Any]:
    for service in _proxy_services(root, node):
        if _matches_entry(service, service_name):
            return service
    raise ValidationError(f"Node {node.id} 不存在 proxy Service: {service_name}")


def _service_public_port(service: dict[str, Any]) -> int:
    """Return the public TLS port advertised by an imported proxy Service."""
    value = service.get("public_port", 443)
    if isinstance(value, bool):
        raise ValidationError("proxy Service 的 public_port 必须是 1-65535 的整数")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            "proxy Service 的 public_port 必须是 1-65535 的整数"
        ) from exc
    if port < 1 or port > 65535:
        raise ValidationError("proxy Service 的 public_port 必须是 1-65535 的整数")
    return port


def _link_outbound(
    root: Path, topology: Topology, link: Link, tag: str
) -> dict[str, Any]:
    target = topology.node(link.target)
    if target is None:
        raise ValidationError(f"Node 不存在: {link.target}")
    service = _find_proxy_service(root, target, link.exit_service)
    domain = str(service.get("domain", ""))
    if not domain:
        raise ValidationError(f"Node {target.id} 的出口 Service 缺少 domain")
    user: dict[str, Any] = {"id": service["uuid"]}
    if link.exit_protocol == "vless":
        user["encryption"] = "none"
    else:
        user["security"] = "auto"
    return {
        "tag": tag,
        "protocol": link.exit_protocol,
        "settings": {
            "vnext": [
                {
                    "address": domain,
                    "port": _service_public_port(service),
                    "users": [user],
                }
            ]
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {"serverName": domain},
            "wsSettings": {"path": service[f"{link.exit_protocol}_ws_path"]},
        },
    }


def _render_xray(
    root: Path,
    topology: Topology,
    service: dict[str, Any],
    ports: dict[str, int],
    links: list[Link],
) -> dict[str, Any]:
    vless_clients = [{"id": service["uuid"]}]
    vmess_clients = [{"id": service["uuid"]}]
    rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "blocked",
        }
    ]
    outbounds: list[dict[str, Any]] = [
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    ]
    for link in links:
        email = f"link.{link.id}"
        client = {"id": link.client_uuid, "email": email}
        inbound_tags = []
        if link.protocol in {"vless", "both"}:
            vless_clients.append(client)
            inbound_tags.append("vless-in")
        if link.protocol in {"vmess", "both"}:
            vmess_clients.append(client)
            inbound_tags.append("vmess-in")
        rules.append(
            {
                "type": "field",
                "inboundTag": inbound_tags,
                "user": [email],
                "outboundTag": email,
            }
        )
        outbounds.append(_link_outbound(root, topology, link, email))

    def inbound(protocol: str, clients: list[dict[str, str]]) -> dict[str, Any]:
        path_key = f"{protocol}_ws_path"
        settings: dict[str, Any] = {"clients": clients}
        if protocol == "vless":
            settings["decryption"] = "none"
        return {
            "tag": f"{protocol}-in",
            "listen": "127.0.0.1",
            "port": ports[protocol],
            "protocol": protocol,
            "settings": settings,
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": service[path_key]},
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            inbound("vless", vless_clients),
            inbound("vmess", vmess_clients),
        ],
        "routing": {"rules": rules},
        "outbounds": outbounds,
    }


def _render_caddy(
    data: dict[str, Any], node: Node, proxies: list[dict[str, Any]]
) -> str:
    proxy_by_id = {_service_id(service): service for service in proxies}
    lines = ["{", "\tacme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}", "}"]
    for service in data["services"]:
        domain = service["domain"]
        lines.extend(
            [
                "",
                f"{domain} {{",
                "\ttls {",
                "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}",
                "\t}",
            ]
        )
        if service.get("type") == "proxy":
            service_id = _service_id(service)
            if service_id not in proxy_by_id or service_id not in node.service_ports:
                raise ValidationError(f"Service {service_id} 缺少端口分配")
            ports = node.service_ports[service_id]
            lines.extend(
                [
                    "",
                    f"\thandle {service['vless_ws_path']} {{",
                    f"\t\treverse_proxy 127.0.0.1:{ports['vless']}",
                    "\t}",
                    "",
                    f"\thandle {service['vmess_ws_path']} {{",
                    f"\t\treverse_proxy 127.0.0.1:{ports['vmess']}",
                    "\t}",
                    "",
                    "\thandle {",
                    f"\t\tredir * {data.get('redirect_url', 'https://www.example.com')} permanent",
                    "\t}",
                ]
            )
        elif service.get("type") == "service":
            target = str(service["target"]).replace("host.docker.internal", "127.0.0.1")
            allowed_ips = service.get("allowed_ips", [])
            if allowed_ips:
                lines.extend(
                    [
                        "",
                        f"\t@allowed remote_ip {' '.join(allowed_ips)}",
                        "\thandle @allowed {",
                        f"\t\treverse_proxy {target}",
                        "\t}",
                        "\trespond 403",
                    ]
                )
            else:
                lines.extend(["", f"\treverse_proxy {target}"])
        else:
            raise ValidationError(f"Node {node.id} 存在未知 Service 类型")
        lines.append("}")
    return "\n".join(lines) + "\n"


def _render_compose(proxies: list[dict[str, Any]]) -> str:
    lines = [
        "services:",
        "  caddy:",
        f"    image: {CADDY_IMAGE}",
        "    container_name: caddy",
        "    restart: always",
        "    network_mode: host",
        "    environment:",
        "      - CLOUDFLARE_API_TOKEN=${CF_API_TOKEN}",
        "    volumes:",
        "      - ./caddy:/etc/caddy:ro",
        "      - caddy_data:/data",
        "      - caddy_config:/config",
    ]
    if proxies:
        lines.append("    depends_on:")
        lines.extend(f"      - {_service_id(service)}" for service in proxies)
    for service in proxies:
        service_id = _service_id(service)
        lines.extend(
            [
                "",
                f"  {service_id}:",
                f"    image: {XRAY_IMAGE}",
                f"    container_name: {service_id}",
                "    restart: always",
                "    network_mode: host",
                '    command: ["run", "-config", "/etc/xray/config.json"]',
            ]
        )
        lines.extend(
            [
                "    volumes:",
                f"      - ./xray/{service_id}:/etc/xray:ro",
            ]
        )
    lines.extend(["", "volumes:", "  caddy_data:", "  caddy_config:"])
    return "\n".join(lines) + "\n"


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def render_node(
    root: Path, topology: Topology, node_id: str, destination: Path
) -> dict[str, str]:
    node = topology.node(node_id)
    if node is None:
        raise ValidationError(f"Node 不存在: {node_id}")
    data = _read_services(root, node)
    proxies = [
        service for service in data["services"] if service.get("type") == "proxy"
    ]
    source_links = [link for link in topology.links if link.source == node.id]

    files: dict[Path, str] = {
        Path(".env"): f"CF_API_TOKEN={data.get('cf_api_token', '')}\n",
        Path("caddy/Caddyfile"): _render_caddy(data, node, proxies),
        Path("docker-compose.yml"): _render_compose(proxies),
    }
    for service in proxies:
        service_id = _service_id(service)
        ports = node.service_ports.get(service_id)
        if ports is None:
            raise ValidationError(f"Service {service_id} 缺少端口分配")
        config = _render_xray(
            root,
            topology,
            service,
            ports,
            _links_for_service(topology, node, service),
        )
        files[Path("xray") / service_id / "config.json"] = (
            json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        )

    outgoing_links: list[dict[str, Any]] = [
        {
            "id": link.id,
            "target": link.target,
            "exit_service": link.exit_service,
            "exit_protocol": link.exit_protocol,
            "enabled": link.enabled,
            "client_uuid": link.client_uuid,
        }
        for link in source_links
    ]
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "node": node.id,
        "network_profile": node.network_profile,
        "outgoing_links": outgoing_links,
        "incoming_links": [],
    }
    files[Path("node-manifest.json")] = (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )

    hashes: dict[str, str] = {}
    for relative, content in files.items():
        _write_private(destination / relative, content)
        hashes[str(relative)] = hashlib.sha256(content.encode()).hexdigest()
    return hashes


def _store(root: Path) -> TopologyStore:
    return TopologyStore(root / "inventory" / "topology.json")


def _save_services(root: Path, node_id: str, payload: str) -> Path:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"services.json 不是有效 JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services", []), list):
        raise ValidationError("services.json 缺少 services 列表")
    destination = root / "inventory" / "nodes" / node_id / "services.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    os.chmod(destination, 0o600)
    return destination


def _create_default_services(root: Path, node: Node) -> Path:
    if not node.domain:
        raise ValidationError("新增独立 Node 必须提供 --domain")
    default_uuid = str(uuid.uuid4())
    vless_path = f"/{secrets.token_hex(4)}"
    vmess_path = f"/{secrets.token_hex(4)}"
    payload = {
        "schema_version": 1,
        "cf_api_token": "",
        "redirect_url": "https://www.example.com",
        "server_ip": "",
        "cf_zone_id": "",
        "default_uuid": default_uuid,
        "default_vless_ws_path": vless_path,
        "default_vmess_ws_path": vmess_path,
        "services": [
            {
                "type": "proxy",
                "domain": node.domain,
                "uuid": default_uuid,
                "vless_ws_path": vless_path,
                "vmess_ws_path": vmess_path,
                "container_name": f"xray-{node.id}",
            }
        ],
    }
    return _save_services(root, node.id, json.dumps(payload))


def _inventory_service_id(service: dict[str, Any]) -> str:
    return str(service.get("container_name") or service.get("domain") or "")


def _allocate_service_ports(node: Node, payload: str) -> None:
    data = json.loads(payload)
    proxies = [item for item in data.get("services", []) if item.get("type") == "proxy"]
    next_port = 2001
    used = {
        port
        for allocation in node.service_ports.values()
        for port in allocation.values()
    }
    for service in proxies:
        service_id = _inventory_service_id(service)
        if not service_id:
            raise ValidationError("proxy Service 缺少 container_name/domain")
        if service_id in node.service_ports:
            continue
        while next_port in used or next_port + 1 in used:
            next_port += 10
        node.service_ports[service_id] = {
            "vless": next_port,
            "vmess": next_port + 1,
        }
        used.update((next_port, next_port + 1))


def _entry_service_exists(root: Path, node: Node, entry_service: str) -> bool:
    if not node.imported_services:
        return False
    data = json.loads((root / node.imported_services).read_text(encoding="utf-8"))
    for service in data.get("services", []):
        if service.get("type") != "proxy":
            continue
        domain = str(service.get("domain", ""))
        container = str(service.get("container_name", ""))
        if entry_service in {
            domain,
            domain.split(".", 1)[0],
            container,
            container.removeprefix("xray-"),
        }:
            return True
    return False


def _select_exit_service(root: Path, node: Node, requested: str) -> str:
    proxies = _proxy_services(root, node)
    if requested:
        return _service_id(_find_proxy_service(root, node, requested))
    if len(proxies) == 1:
        return _service_id(proxies[0])
    if not proxies:
        raise ValidationError(f"Node {node.id} 没有可用的 proxy Service")
    raise ValidationError(
        f"Node {node.id} 有多个 proxy Service，请使用 --exit-service 指定"
    )


def _node_from_args(args: argparse.Namespace) -> Node:
    endpoint = args.endpoint or (args.host.rsplit("@", 1)[-1] if args.host else "")
    return Node(
        id=args.node_id,
        host=args.host,
        endpoint=endpoint,
        remote_dir=args.remote_dir,
        domain=args.domain,
        network_profile=args.network_profile,
        ssh_key=args.ssh_key,
    )


def _sync_local_node(root: Path, topology: Topology) -> tuple[Node, str]:
    if not SERVICES_FILE.is_file():
        raise ValidationError("本机 services.json 不存在，请先运行 init 和 add-proxy")
    try:
        payload = SERVICES_FILE.read_text(encoding="utf-8")
        data = json.loads(payload)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"无法读取本机 services.json: {exc}") from exc
    proxies = [
        service
        for service in data.get("services", [])
        if service.get("type") == "proxy"
    ]
    if not proxies:
        raise ValidationError(
            "本机 services.json 没有 proxy Service，请先运行 add-proxy"
        )
    primary = proxies[0]
    domain = str(primary.get("domain", ""))
    node_id = domain.split(".", 1)[0].lower()
    if not NODE_ID_RE.fullmatch(node_id):
        raise ValidationError(f"无法从本机代理域名推导 Node 名称: {domain}")
    entry_service = f"xray-{node_id}"
    if not _matches_entry(primary, entry_service):
        raise ValidationError(
            f"本机主 proxy Service 必须命名为 {entry_service}，"
            f"当前为 {_service_id(primary) or '未命名'}"
        )

    node = topology.node(node_id)
    if node is None:
        node = Node(id=node_id, host="", domain=domain)
        topology.nodes.append(node)
    destination = _save_services(root, node_id, payload)
    node.domain = domain
    node.imported_services = str(destination.relative_to(root))
    node.services_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
    active_services = {
        _inventory_service_id(service)
        for service in proxies
        if _inventory_service_id(service)
    }
    node.service_ports = {
        service_id: ports
        for service_id, ports in node.service_ports.items()
        if service_id in active_services
    }
    _allocate_service_ports(node, payload)
    node.validate()
    return node, entry_service


def _local_links_to_target(
    topology: Topology, source_id: str, target_id: str
) -> list[Link]:
    return [
        link
        for link in topology.links
        if link.source == source_id and link.target == target_id
    ]


def cmd_node(args: argparse.Namespace) -> None:
    root = Path(args.project_root)
    store = _store(root)
    if args.node_action == "list":
        with store.locked():
            topology = store.load()
            if SERVICES_FILE.is_file():
                _sync_local_node(root, topology)
                store.save(topology)
        for node in topology.nodes:
            incoming = sum(link.target == node.id for link in topology.links)
            outgoing = sum(link.source == node.id for link in topology.links)
            print(
                f"{node.id}\t{node.host}\t{node.network_profile}"
                f"\tout={outgoing}\tin={incoming}"
            )
        return

    with store.locked():
        topology = store.load()
        if args.node_action in {"add", "import"}:
            existing_node = topology.node(args.node_id)
            if args.node_action == "add" and existing_node:
                raise ValidationError(f"Node 已存在: {args.node_id}")
            if args.node_action == "import":
                node = existing_node or Node(id=args.node_id, host="")
                try:
                    payload = Path(args.services_file).read_text(encoding="utf-8")
                except OSError as exc:
                    raise ValidationError(
                        f"无法读取 services.json: {args.services_file}: {exc}"
                    ) from exc
                destination = _save_services(root, node.id, payload)
                node.imported_services = str(destination.relative_to(root))
                imported = json.loads(payload)
                proxy = next(
                    (
                        service
                        for service in imported.get("services", [])
                        if service.get("type") == "proxy"
                    ),
                    None,
                )
                if proxy:
                    node.domain = str(proxy.get("domain", ""))
            else:
                node = _node_from_args(args)
                destination = _create_default_services(root, node)
                node.imported_services = str(destination.relative_to(root))
                payload = destination.read_text(encoding="utf-8")
            imported_data = json.loads(payload)
            active_services = {
                _inventory_service_id(service)
                for service in imported_data.get("services", [])
                if service.get("type") == "proxy"
            }
            node.service_ports = {
                service_id: ports
                for service_id, ports in node.service_ports.items()
                if service_id in active_services
            }
            node.services_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
            _allocate_service_ports(node, payload)
            node.validate()
            if existing_node is None:
                topology.nodes.append(node)
            store.save(topology)
            action = "已重新导入" if existing_node else "已登记"
            print(f"Node {action}: {node.id}")
            return

        if args.node_action == "update":
            current_node = topology.node(args.node_id)
            if current_node is None:
                raise ValidationError(f"Node 不存在: {args.node_id}")
            if args.host:
                current_node.host = args.host
            if args.endpoint:
                current_node.endpoint = args.endpoint
            if args.domain is not None:
                current_node.domain = args.domain
            if args.remote_dir:
                current_node.remote_dir = args.remote_dir
            if args.network_profile:
                current_node.network_profile = args.network_profile
            if args.ssh_key is not None:
                current_node.ssh_key = args.ssh_key
            store.save(topology)
            print(f"Node 已更新: {current_node.id}")
            return

        if args.node_action == "detach":
            if topology.node(args.node_id) is None:
                raise ValidationError(f"Node 不存在: {args.node_id}")
            removed: list[Link] = []
            kept: list[Link] = []
            for link in topology.links:
                matches = (
                    (args.all_links and args.node_id in {link.source, link.target})
                    or (args.outgoing and link.source == args.node_id)
                    or (args.incoming and link.target == args.node_id)
                )
                (removed if matches else kept).append(link)
            topology.links = kept
            for link in removed:
                if not any(item.id == link.id for item in topology.tombstones):
                    topology.tombstones.append(LinkTombstone.from_link(link))
            store.save(topology)
            print(f"已从期望配置移除 {len(removed)} 条 Link")
            return

        if args.node_action == "remove":
            if topology.node(args.node_id) is None:
                raise ValidationError(f"Node 不存在: {args.node_id}")
            links = [
                link.id
                for link in topology.links
                if args.node_id in {link.source, link.target}
            ]
            if links:
                raise ValidationError(
                    "Node 仍有关联 Link，请先 detach: " + ", ".join(links)
                )
            pending = [
                item.id
                for item in topology.tombstones
                if args.node_id in {item.source, item.target}
            ]
            if pending:
                raise ValidationError(
                    "Node 仍有待清理 Link，请先完成 apply: " + ", ".join(pending)
                )
            topology.nodes = [
                node for node in topology.nodes if node.id != args.node_id
            ]
            store.save(topology)
            print(f"Node 已从期望配置移除: {args.node_id}")


def cmd_link(args: argparse.Namespace) -> None:
    root = Path(args.project_root)
    store = _store(root)
    if args.link_action == "list":
        topology = store.load()
        for link in topology.links:
            status = "enabled" if link.enabled else "disabled"
            print(
                f"{link.id}\t{link.source} -> {link.target}\t{link.protocol}\t{status}"
            )
        return

    if args.link_action == "show":
        topology = store.load()
        selected = topology.link(args.link)
        if selected is None:
            matches = [link for link in topology.links if link.target == args.link]
            if len(matches) == 1:
                selected = matches[0]
            elif len(matches) > 1:
                raise ValidationError(
                    f"有多条 Link 指向 {args.link}，请改用完整 Link ID"
                )
        if selected is None:
            raise ValidationError(f"Link 不存在: {args.link}")

        source = topology.node(selected.source)
        target = topology.node(selected.target)
        if source is None or target is None:
            raise ValidationError(f"Link {selected.id} 引用了不存在的 Node")
        entry = _find_proxy_service(root, source, selected.entry_service)
        exit_proxy = _find_proxy_service(root, target, selected.exit_service)
        source_domain = str(entry.get("domain", ""))
        target_domain = str(exit_proxy.get("domain", ""))
        if not source_domain or not target_domain:
            raise ValidationError(f"Link {selected.id} 的 Service 缺少 domain")

        print(f"Link: {selected.id} ({selected.source} -> {selected.target})")
        print(f"状态: {'enabled' if selected.enabled else 'disabled'}")
        print("客户端连接 source:")
        print(f"  服务器: {source_domain}")
        print(f"  端口: {_service_public_port(entry)}")
        print(f"  UUID: {selected.client_uuid}")
        print(f"  协议: {selected.protocol}")
        if selected.protocol in {"vless", "both"}:
            print(f"  VLESS WS path: {entry['vless_ws_path']}")
        if selected.protocol in {"vmess", "both"}:
            print(f"  VMess WS path: {entry['vmess_ws_path']}")
        print(f"  TLS/SNI/Host: {source_domain}")
        print("source 连接 target:")
        print(f"  服务器: {target_domain}")
        print(f"  端口: {_service_public_port(exit_proxy)}")
        print(f"  协议: {selected.exit_protocol}")
        print(f"  WS path: {exit_proxy[f'{selected.exit_protocol}_ws_path']}")
        print(f"  TLS/SNI/Host: {target_domain}")
        return

    with store.locked():
        topology = store.load()
        if args.link_action == "add":
            source, entry_service = _sync_local_node(root, topology)
            target = topology.node(args.target)
            if target is None:
                raise ValidationError(
                    f"目标 Node 尚未导入: {args.target}；请先执行 "
                    f"node import {args.target} --services-file <文件>"
                )
            link_id = f"{source.id}-{target.id}"
            existing = _local_links_to_target(topology, source.id, target.id)
            if existing:
                raise ValidationError(f"Link 已存在: {existing[0].id}")
            if topology.link(link_id) or any(
                item.id == link_id for item in topology.tombstones
            ):
                raise ValidationError(f"Link ID 已存在或已被保留: {link_id}")
            if not _entry_service_exists(root, source, entry_service):
                raise ValidationError(
                    f"Node {source.id} 不存在 proxy Service: {entry_service}"
                )
            exit_service = _select_exit_service(root, target, args.exit_service)
            link = Link(
                id=link_id,
                source=source.id,
                target=target.id,
                entry_service=entry_service,
                exit_service=exit_service,
                protocol=args.protocol,
                exit_protocol=args.exit_protocol,
                transport=args.transport,
                client_uuid=allocate(topology),
            )
            link.validate()
            topology.links.append(link)
            store.save(topology)
            print(f"Link 已登记: {link.id} ({link.source} -> {link.target})")
            print(f"入口 Service: {link.entry_service}")
            print(f"出口 Service: {link.exit_service} ({link.exit_protocol})")
            print(f"客户端 UUID: {link.client_uuid}")
            print(f"下一步: python3 deploy.py apply --link {link.id}")
            return

        if args.link_action == "del":
            source, _ = _sync_local_node(root, topology)
            matches = _local_links_to_target(topology, source.id, args.target)
            if not matches:
                raise ValidationError(f"Link 不存在: {source.id}-{args.target}")
            if len(matches) > 1:
                raise ValidationError(
                    f"存在多条旧版 Link 指向 {args.target}，请使用 link remove <ID>"
                )
            deleted_link = matches[0]
            topology.links = [
                item for item in topology.links if item.id != deleted_link.id
            ]
            if not any(item.id == deleted_link.id for item in topology.tombstones):
                topology.tombstones.append(LinkTombstone.from_link(deleted_link))
            store.save(topology)
            print(f"Link 已删除: {deleted_link.id}")
            print(f"下一步: python3 deploy.py apply --link {deleted_link.id}")
            return

        current_link = topology.link(args.link_id)
        if current_link is None:
            raise ValidationError(f"Link 不存在: {args.link_id}")
        if args.link_action == "remove":
            topology.links = [
                item for item in topology.links if item.id != current_link.id
            ]
            if not any(item.id == current_link.id for item in topology.tombstones):
                topology.tombstones.append(LinkTombstone.from_link(current_link))
        else:
            current_link.enabled = args.link_action == "enable"
        store.save(topology)
        labels = {"enable": "启用", "disable": "禁用", "remove": "移除"}
        print(f"Link 已{labels[args.link_action]}: {current_link.id}")


def cmd_plan(args: argparse.Namespace) -> None:
    root = Path(args.project_root)
    topology = _store(root).load()
    node_ids = [item for item in args.nodes.split(",") if item]
    link_ids = [item for item in args.links.split(",") if item]
    unknown_nodes = sorted(set(node_ids) - {node.id for node in topology.nodes})
    known_links = {link.id for link in topology.links} | {
        item.id for item in topology.tombstones
    }
    unknown_links = sorted(set(link_ids) - known_links)
    if unknown_nodes or unknown_links:
        raise ValidationError(
            "未知资源: " + ", ".join([*unknown_nodes, *unknown_links])
        )
    plan = build_plan(topology, node_ids, link_ids)
    staging = root / "state" / "staging" / plan["topology_hash"][:16]
    artifacts: dict[str, Any] = {}
    for node_id in plan["affected_nodes"]:
        node = topology.node(node_id)
        if node is None:
            raise ValidationError(f"Node 不存在: {node_id}")
        artifacts[node_id] = {
            "profile": node.network_profile,
            "directory": str(staging / node_id),
            "files": render_node(root, topology, node_id, staging / node_id),
        }
    plan["artifacts"] = artifacts
    payload = json.dumps(plan, indent=2, ensure_ascii=False) + "\n"
    if args.save:
        destination = Path(args.save)
        if not destination.is_absolute():
            destination = root / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload, encoding="utf-8")
        os.chmod(destination, 0o600)
        print(f"Plan 已保存: {destination}")
    else:
        print(payload, end="")


def _validate_xray_file(config_path: Path) -> None:
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={config_path.resolve()},dst=/etc/xray/config.json,readonly",
            XRAY_IMAGE,
            "run",
            "-test",
            "-config",
            "/etc/xray/config.json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValidationError(f"Xray 配置校验失败: {detail or '未知错误'}")


def _restart_xray_container(container: str) -> bool:
    result = docker_compose("up", "-d", "--force-recreate", container)
    if result.returncode:
        return False
    status = _run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        capture_output=True,
        text=True,
    )
    return status.returncode == 0 and status.stdout.strip() == "true"


def _replace_file(source: Path, destination: Path) -> None:
    """Atomically install a config readable by the non-root Xray container."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".nano-xray.tmp")
    shutil.copyfile(source, temporary)
    os.chmod(temporary, 0o644)
    os.replace(temporary, destination)


def cmd_apply(args: argparse.Namespace) -> None:
    root = Path(args.project_root)
    store = _store(root)
    with store.locked():
        topology = store.load()
        local_source, _ = _sync_local_node(root, topology)
        link = topology.link(args.link_id)
        tombstone = next(
            (item for item in topology.tombstones if item.id == args.link_id), None
        )
        if link is None and tombstone is None:
            raise ValidationError(f"Link 不存在: {args.link_id}")
        if link is not None:
            source_id = link.source
            entry_service = link.entry_service
        else:
            if tombstone is None:  # Defensive narrowing for static type checking.
                raise ValidationError(f"Link 不存在: {args.link_id}")
            source_id = tombstone.source
            entry_service = tombstone.entry_service
        if source_id != local_source.id:
            raise ValidationError(
                f"Link {args.link_id} 的 source 是 {source_id}，"
                f"当前机器从 services.json 识别为 {local_source.id}"
            )
        store.save(topology)
    expected_topology_hash = topology_hash(topology)
    source = local_source

    registry = Registry.load()
    local_service = next(
        (
            service
            for service in registry.proxies
            if _matches_entry(service, entry_service)
        ),
        None,
    )
    if local_service is None:
        raise ValidationError(
            f"本机不存在 Link {args.link_id} 的入口 Service: {entry_service}"
        )
    container = _service_id(local_service)
    staging = root / "state" / "apply-staging" / topology_hash(topology)[:16]
    generator = ConfigGenerator(
        registry,
        output_dir=staging,
        topology=topology,
        source_node=source,
        topology_root=root,
    )
    generator.generate_xray_only()
    staged_config = staging / "xray" / container / "config.json"
    _validate_xray_file(staged_config)
    if topology_hash(store.load()) != expected_topology_hash:
        raise ValidationError("Link 配置在校验期间发生变化，请重新执行 apply")

    current_config = GENERATED_DIR / "xray" / container / "config.json"
    if not current_config.is_file():
        raise ValidationError(
            f"当前配置不存在: {current_config}；请先运行 deploy.py up --generate"
        )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = root / "state" / "backups" / f"{stamp}-{args.link_id}" / "config.json"
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(current_config, backup)
    os.chmod(backup, 0o600)

    _replace_file(staged_config, current_config)
    if not _restart_xray_container(container):
        _replace_file(backup, current_config)
        restored = _restart_xray_container(container)
        suffix = "，旧配置已恢复" if restored else "，且旧配置恢复后容器仍未正常运行"
        raise ValidationError(f"应用 Link {args.link_id} 失败{suffix}")

    if tombstone is not None:
        with store.locked():
            latest = store.load()
            latest.tombstones = [
                item for item in latest.tombstones if item.id != tombstone.id
            ]
            store.save(latest)
    info(f"Link 状态已应用到本机: {args.link_id}")
    info(f"已重建 Xray 容器: {container}")
    info(f"旧配置备份: {backup}")


def add_topology_parsers(
    sub: argparse._SubParsersAction[argparse.ArgumentParser], root: Path
) -> None:
    def common_node(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("node_id")
        parser.add_argument("--host", default="")
        parser.add_argument(
            "--endpoint",
            default="",
            help="Node 公网 IP/主机名（默认取 --host 的 @ 后部分）",
        )
        parser.add_argument("--remote-dir", default="/root/nano-xray")
        parser.add_argument("--domain", default="")
        parser.add_argument(
            "--network-profile", choices=("bridge", "host-l3"), default="bridge"
        )
        parser.add_argument("--ssh-key", default="")

    node = sub.add_parser("node", help="管理 v2 Node 期望配置")
    node.set_defaults(project_root=str(root), func=cmd_node)
    node_sub = node.add_subparsers(dest="node_action", required=True)
    common_node(node_sub.add_parser("add", help="登记独立 Node"))
    imported = node_sub.add_parser(
        "import", help="从本地 services.json 文件导入现有 Node"
    )
    imported.add_argument("node_id")
    imported.add_argument(
        "--services-file", required=True, help="本地 services.json 文件路径"
    )
    update = node_sub.add_parser("update", help="更新 Node")
    update.add_argument("node_id")
    update.add_argument("--host", default="")
    update.add_argument("--endpoint", default="")
    update.add_argument("--remote-dir", default="")
    update.add_argument("--domain", default=None)
    update.add_argument("--network-profile", choices=("bridge", "host-l3"), default="")
    update.add_argument("--ssh-key", default=None)
    node_sub.add_parser("list", help="列出 Node")
    detach = node_sub.add_parser("detach", help="移除 Node 关联的 Link 期望配置")
    detach.add_argument("node_id")
    direction = detach.add_mutually_exclusive_group(required=True)
    direction.add_argument("--incoming", action="store_true")
    direction.add_argument("--outgoing", action="store_true")
    direction.add_argument("--all-links", action="store_true")
    remove = node_sub.add_parser("remove", help="删除无 Link 的 Node 期望配置")
    remove.add_argument("node_id")

    link = sub.add_parser("link", help="管理 v2 有向 Link 期望配置")
    link.set_defaults(project_root=str(root), func=cmd_link)
    link_sub = link.add_subparsers(dest="link_action", required=True)
    add = link_sub.add_parser("add", help="登记只修改 source 的 Xray Link")
    add.add_argument("target")
    add.add_argument("--protocol", choices=("vmess", "vless", "both"), default="both")
    add.add_argument("--exit-service", default="")
    add.add_argument("--exit-protocol", choices=("vmess", "vless"), default="vless")
    add.add_argument("--transport", choices=("xray",), default="xray")
    delete = link_sub.add_parser("del", help="删除本机到目标 Node 的 Link")
    delete.add_argument("target")
    for action in ("enable", "disable", "remove"):
        action_parser = link_sub.add_parser(action)
        action_parser.add_argument("link_id")
    link_sub.add_parser("list")
    show = link_sub.add_parser("show", help="显示一条 Link 的完整连接参数")
    show.add_argument("link", help="target Node ID 或完整 Link ID")

    plan = sub.add_parser("plan", help="生成可选审查计划，不修改运行配置")
    plan.add_argument("--nodes", default="", help="逗号分隔的 Node ID")
    plan.add_argument("--links", default="", help="逗号分隔的 Link ID")
    plan.add_argument("--save", default="")
    plan.set_defaults(func=cmd_plan, project_root=str(root))

    apply_parser = sub.add_parser("apply", help="在本机应用指定 Link")
    apply_parser.add_argument("--link", dest="link_id", required=True)
    apply_parser.set_defaults(func=cmd_apply, project_root=str(root))


def run_safely(func: Any, args: argparse.Namespace) -> None:
    try:
        func(args)
    except (ValidationError, ValueError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


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

# root SSH 登录公钥（支持多个: SSH_KEY_1, SSH_KEY_2, ...)
# init 会写入 /root/.ssh/authorized_keys，并验证 sshd drop-in 后 reload。
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
    services: list[dict[str, Any]] = field(default_factory=list)

    def save(self) -> None:
        SERVICES_FILE.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls) -> Registry:
        if not SERVICES_FILE.exists():
            error("services.json 不存在，请先运行: deploy.py init")
            sys.exit(1)
        data = json.loads(SERVICES_FILE.read_text())
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def find_domain(self, domain: str) -> dict[str, Any] | None:
        return next((s for s in self.services if s["domain"] == domain), None)

    def add_service(self, service: dict[str, Any]) -> None:
        self.services.append(service)
        self.save()

    def replace_service(self, domain: str, service: dict[str, Any]) -> None:
        self.services = [s for s in self.services if s["domain"] != domain]
        self.services.append(service)
        self.save()

    def remove_service(self, domain: str) -> dict[str, Any] | None:
        svc = self.find_domain(domain)
        if svc:
            self.services = [s for s in self.services if s["domain"] != domain]
            self.save()
        return svc

    @property
    def proxies(self) -> list[dict[str, Any]]:
        return [s for s in self.services if s.get("type") == "proxy"]

    @property
    def reverse_proxies(self) -> list[dict[str, Any]]:
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
            return int(resp.status) == 200
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

        # 找到公网网卡（跳过容器、loopback 和 WireGuard 等虚拟接口）
        virtual_prefixes = ("docker", "lo", "veth", "br-", "virbr", "wg", "nx")
        iface = None
        override = get_env("VNSTAT_IFACE", "", dotenv)
        interfaces = data.get("interfaces", [])
        if override:
            iface = next(
                (itf for itf in interfaces if itf.get("name", "") == override),
                None,
            )
        else:
            iface = next(
                (
                    itf
                    for itf in interfaces
                    if not any(
                        itf.get("name", "").startswith(prefix)
                        for prefix in virtual_prefixes
                    )
                ),
                None,
            )

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

        return float(tx_bytes) / 1_000_000_000  # GB
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


TRAFFIC_GUARD_TABLE = "nano_xray_traffic_guard"
TRAFFIC_GUARD_RULESET = f"""\
table inet {TRAFFIC_GUARD_TABLE} {{
    chain input {{
        type filter hook input priority -100; policy accept;
        iifname "lo" accept
        tcp dport 22 accept
        ct state established tcp sport 22 accept
        meta nfproto ipv6 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept
        counter drop
    }}

    chain output {{
        type filter hook output priority -100; policy accept;
        oifname "lo" accept
        tcp dport 22 accept
        ct state established tcp sport 22 accept
        meta nfproto ipv6 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept
        counter drop
    }}

    chain forward {{
        type filter hook forward priority -100; policy drop;
    }}
}}
"""


def _has_nft() -> bool:
    """检查 nftables 命令是否可用。"""
    return shutil.which("nft") is not None


def traffic_guard_is_active() -> bool:
    """检查 nano-xray 的全局流量锁是否已经加载。"""
    if not _has_nft():
        return False
    result = subprocess.run(
        ["nft", "list", "table", "inet", TRAFFIC_GUARD_TABLE],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def traffic_guard_enable() -> bool:
    """除 SSH 和 loopback 外，阻断主机及转发流量。"""
    if not _has_nft():
        warn("未找到 nft 命令，无法启用紧急网络锁")
        return False
    if traffic_guard_is_active():
        return True
    result = subprocess.run(
        ["nft", "-f", "-"],
        input=TRAFFIC_GUARD_RULESET,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        warn(f"启用紧急网络锁失败: {result.stderr.strip() or 'nft 执行失败'}")
    return result.returncode == 0


def traffic_guard_disable() -> bool:
    """删除 nano-xray 独占的流量锁，不触碰其他 nftables 表。"""
    if not _has_nft() or not traffic_guard_is_active():
        return True
    result = subprocess.run(
        ["nft", "delete", "table", "inet", TRAFFIC_GUARD_TABLE],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        warn(f"解除紧急网络锁失败: {result.stderr.strip() or 'nft 执行失败'}")
    return result.returncode == 0


def _remove_legacy_ufw_denies() -> None:
    """清理旧版本 check-traffic 添加的 80/443 DENY 规则。"""
    if not _has_ufw():
        return
    for rule in ["deny 80/tcp", "deny 443/tcp", "deny 443/udp"]:
        subprocess.run(
            ["ufw", "--force", "delete", *rule.split()],
            capture_output=True,
            text=True,
        )


def ufw_allow_ports() -> None:
    """恢复 nano-xray 单机服务正常需要的 80/443 端口。"""
    if not _has_ufw():
        return
    _remove_legacy_ufw_denies()
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
                ip = str(resp.read().decode().strip())
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

    def _request(
        self, method: str, endpoint: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
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
                return cast(dict[str, Any], json.loads(resp.read().decode()))
        except HTTPError as e:
            return cast(dict[str, Any], json.loads(e.read().decode()))
        except URLError as e:
            error(f"Cloudflare API 请求失败: {e}")
            return {"success": False, "errors": [{"message": str(e)}]}

    def verify_token(self) -> bool:
        result = self._request("GET", "/user/tokens/verify")
        return bool(result.get("success", False))

    def get_zone_id(self, root_domain: str) -> str:
        result = self._request("GET", f"/zones?name={root_domain}&status=active")
        zones = result.get("result", [])
        return str(zones[0]["id"]) if zones else ""

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


def _detect_local_link_context(root: Path) -> tuple[Topology, Node] | None:
    topology_path = root / "inventory" / "topology.json"
    local_services = root / "services.json"
    if not topology_path.exists() or not local_services.exists():
        return None
    topology = TopologyStore(topology_path).load()
    if not topology.links:
        return None
    try:
        data = json.loads(local_services.read_text(encoding="utf-8"))
        primary = next(
            service
            for service in data.get("services", [])
            if service.get("type") == "proxy"
        )
    except (OSError, json.JSONDecodeError, StopIteration) as exc:
        raise ValidationError(f"无法从本机 services.json 识别 Node: {exc}") from exc
    node_id = str(primary.get("domain", "")).split(".", 1)[0].lower()
    local_node = topology.node(node_id)
    if local_node is None:
        raise ValidationError(
            f"本机 Node {node_id or '未知'} 尚未自动登记；请先执行 link add <目标Node>"
        )
    return topology, local_node


class ConfigGenerator:
    def __init__(
        self,
        registry: Registry,
        *,
        output_dir: Path | None = None,
        topology: Topology | None = None,
        source_node: Node | None = None,
        topology_root: Path | None = None,
    ):
        self.reg = registry
        self.output_dir = output_dir or GENERATED_DIR
        self.topology_root = topology_root or SCRIPT_DIR
        if topology is None and source_node is None:
            detected = _detect_local_link_context(self.topology_root)
            topology, source_node = detected if detected else (None, None)
        self.topology = topology
        self.source_node = source_node

    def generate_all(self) -> None:
        # 不能 rmtree: Docker bind mount 绑定 inode，删除后重建的文件 inode 不同，
        # 容器看不到更新。改为就地覆盖写入，保持 inode 不变。
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 清理已不再需要的 xray 子目录（已删除的代理节点）
        xray_dir = self.output_dir / "xray"
        if xray_dir.exists():
            active_containers = {p["container_name"] for p in self.reg.proxies}
            for child in xray_dir.iterdir():
                if child.is_dir() and child.name not in active_containers:
                    shutil.rmtree(child)

        self._generate_env()
        self._generate_caddyfile()
        self._generate_compose()
        self._generate_xray_configs()

        info(f"配置文件已生成到 {self.output_dir}/")

    def generate_xray_only(self) -> None:
        """Render Xray configs for a local Link apply without staging secrets."""
        (self.output_dir / "xray").mkdir(parents=True, exist_ok=True)
        self._generate_xray_configs()

    def _generate_env(self) -> None:
        (self.output_dir / ".env").write_text(f"CF_API_TOKEN={self.reg.cf_api_token}\n")

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

        (self.output_dir / "Caddyfile").write_text("\n".join(lines) + "\n")

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
        (self.output_dir / "docker-compose.yml").write_text("\n".join(lines) + "\n")

    def _generate_xray_configs(self) -> None:
        for p in self.reg.proxies:
            cn = p["container_name"]
            config_dir = self.output_dir / "xray" / cn
            config_dir.mkdir(parents=True, exist_ok=True)

            links = (
                _links_for_service(self.topology, self.source_node, p)
                if self.topology is not None and self.source_node is not None
                else []
            )
            config: dict[str, Any] = {
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
            if links and self.topology is not None:
                config = _render_xray(
                    self.topology_root,
                    self.topology,
                    p,
                    {"vless": VLESS_WS_PORT, "vmess": VMESS_WS_PORT},
                    links,
                )
                for inbound in config["inbounds"]:
                    inbound["listen"] = "0.0.0.0"

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
        text=True,
    )


def docker_exec(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", "exec", *args], capture_output=False, text=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI 命令
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _ensure_env() -> None:
    """检查 .env 文件是否存在，不存在则提示先执行 prepare。"""
    if not ENV_FILE.exists():
        error("请先运行: python3 deploy.py prepare")
        sys.exit(1)


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """封装 subprocess.run，统一错误处理。"""
    return cast(
        subprocess.CompletedProcess[str],
        subprocess.run(cmd, **kwargs),  # noqa: S603
    )


SSHD_DROP_IN = Path("/etc/ssh/sshd_config.d/00-nano-xray.conf")
ROOT_SSH_DIR = Path("/root/.ssh")
SSH_KEY_TYPE_RE = re.compile(
    r"^(?:sk-)?(?:ssh-[A-Za-z0-9@._+-]+|ecdsa-sha2-[A-Za-z0-9@._+-]+)$"
)
SSH_ENV_KEY_RE = re.compile(r"^SSH_KEY_[1-9][0-9]*$")


def _ssh_key_identity(public_key: str) -> tuple[str, str]:
    """返回 authorized_keys 行中的 key type 和 base64 key body。"""
    fields = public_key.strip().split()
    for index, key_type in enumerate(fields[:-1]):
        if not SSH_KEY_TYPE_RE.fullmatch(key_type):
            continue
        body = fields[index + 1]
        normalized_body = body.rstrip("=")
        padded_body = normalized_body + "=" * (-len(normalized_body) % 4)
        try:
            decoded = base64.b64decode(padded_body.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise ValidationError("SSH 公钥的 base64 内容无效") from exc
        if len(decoded) < 16:
            raise ValidationError("SSH 公钥内容过短")
        return key_type, normalized_body
    raise ValidationError("SSH 公钥格式无效或类型不受支持")


def _collect_ssh_public_keys(dotenv: dict[str, str]) -> list[str]:
    """从 .env 和进程环境收集公钥，并按 key identity 去重。"""
    merged = dict(dotenv)
    merged.update(
        {
            key: value
            for key, value in os.environ.items()
            if SSH_ENV_KEY_RE.fullmatch(key)
        }
    )
    candidates = [
        value
        for key, value in sorted(merged.items())
        if SSH_ENV_KEY_RE.fullmatch(key) and value.strip()
    ]

    unique: dict[tuple[str, str], str] = {}
    for candidate in candidates:
        identity = _ssh_key_identity(candidate)
        unique.setdefault(identity, candidate.strip())
    return list(unique.values())


def _install_authorized_keys(
    public_keys: list[str], ssh_dir: Path = ROOT_SSH_DIR
) -> int:
    """把新 key 原子写入 authorized_keys，保留已有行和选项。"""
    ssh_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    if os.geteuid() == 0:
        os.chown(ssh_dir, 0, 0)
    authorized_keys = ssh_dir / "authorized_keys"
    if not public_keys:
        return 0
    existing_lines = (
        authorized_keys.read_text(encoding="utf-8").splitlines()
        if authorized_keys.exists()
        else []
    )
    identities: set[tuple[str, str]] = set()
    for line in existing_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            identities.add(_ssh_key_identity(line))
        except ValidationError:
            # 保留用户已有的未知格式行，但不拿它做去重依据。
            continue

    added = 0
    for public_key in public_keys:
        identity = _ssh_key_identity(public_key)
        if identity in identities:
            continue
        existing_lines.append(public_key.strip())
        identities.add(identity)
        added += 1

    temporary = authorized_keys.with_name("authorized_keys.nano-xray.tmp")
    temporary.write_text(
        "\n".join(existing_lines).rstrip("\n") + "\n", encoding="utf-8"
    )
    os.chmod(temporary, 0o600)
    if os.geteuid() == 0:
        os.chown(temporary, 0, 0)
    os.replace(temporary, authorized_keys)
    return added


def _sshd_binary() -> str:
    binary = shutil.which("sshd")
    if binary:
        return binary
    fallback = Path("/usr/sbin/sshd")
    if fallback.is_file():
        return str(fallback)
    raise ValidationError("未找到 sshd；请先安装 openssh-server")


def _reload_sshd() -> bool:
    """优先使用 sshd.service，同时兼容使用 ssh.service 的系统。"""
    for unit in ("sshd.service", "ssh.service"):
        try:
            result = _run(["systemctl", "reload", unit], capture_output=True, text=True)
        except OSError:
            return False
        if result.returncode == 0:
            return True
    return False


def _configure_sshd(*, allow_password_auth: bool, have_public_keys: bool) -> bool:
    """写入受管 drop-in，验证成功后 reload；失败时恢复旧文件。"""
    if not allow_password_auth and not have_public_keys:
        return False
    binary = _sshd_binary()
    lines = [
        "# Managed by nano-xray deploy.py",
        "PubkeyAuthentication yes",
        "AuthorizedKeysFile .ssh/authorized_keys",
    ]
    if allow_password_auth:
        lines.extend(
            [
                "PermitRootLogin yes",
                "PasswordAuthentication yes",
                "KbdInteractiveAuthentication yes",
            ]
        )
    else:
        lines.append("PermitRootLogin prohibit-password")
    content = "\n".join(lines) + "\n"

    SSHD_DROP_IN.parent.mkdir(parents=True, exist_ok=True)
    previous = (
        SSHD_DROP_IN.read_text(encoding="utf-8") if SSHD_DROP_IN.exists() else None
    )
    temporary = SSHD_DROP_IN.with_suffix(".conf.nano-xray.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, SSHD_DROP_IN)

    def restore_previous() -> None:
        if previous is None:
            SSHD_DROP_IN.unlink(missing_ok=True)
        else:
            SSHD_DROP_IN.write_text(previous, encoding="utf-8")
            os.chmod(SSHD_DROP_IN, 0o600)

    validation = _run([binary, "-t"], capture_output=True, text=True)
    if validation.returncode != 0:
        restore_previous()
        raise ValidationError(
            "sshd 配置校验失败，已恢复原配置: "
            + (validation.stderr.strip() or "sshd -t 返回错误")
        )

    effective = _run(
        [binary, "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"],
        capture_output=True,
        text=True,
    )
    settings = {
        line.split(None, 1)[0]: line.split(None, 1)[1]
        for line in effective.stdout.splitlines()
        if len(line.split(None, 1)) == 2
    }
    root_login_values = (
        {"yes"} if allow_password_auth else {"without-password", "prohibit-password"}
    )
    effective_valid = (
        effective.returncode == 0
        and settings.get("pubkeyauthentication") == "yes"
        and ".ssh/authorized_keys" in settings.get("authorizedkeysfile", "").split()
        and settings.get("permitrootlogin") in root_login_values
        and (
            not allow_password_auth
            or (
                settings.get("passwordauthentication") == "yes"
                and settings.get("kbdinteractiveauthentication") == "yes"
            )
        )
    )
    if not effective_valid:
        restore_previous()
        raise ValidationError(
            "sshd 有效配置未采用 nano-xray 设置；请检查 "
            "/etc/ssh/sshd_config 的 Include 顺序"
        )
    if not _reload_sshd():
        restore_previous()
        _reload_sshd()
        raise ValidationError("无法 reload sshd.service/ssh.service，已恢复原配置")
    return True


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
            "openssh-server",
            "sysstat",
            "vnstat",
            "nftables",
        ]
    )

    # ── 2. 时区 ──
    info("设置时区 Asia/Shanghai...")
    _run(["timedatectl", "set-timezone", "Asia/Shanghai"])

    # ── 3. 可选 SSH 密码策略 ──
    if args.configure_ssh_password_auth:
        warn("按显式参数启用 root 与密码 SSH 登录")
        _configure_sshd(allow_password_auth=True, have_public_keys=False)
        info(f"  sshd 配置已验证并 reload：{SSHD_DROP_IN}")
    else:
        info("保留现有 SSH 密码认证策略；公钥将在 init 阶段配置")

    # ── 4. Docker ──
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

    # ── 5. 网络调优（BBR + 代理优化） ──
    info("配置网络参数...")
    sysctl_file = Path("/etc/sysctl.conf")
    sysctl_file.touch(exist_ok=True)
    existing_sysctl = sysctl_file.read_text()
    for param in _SYSCTL_PARAMS:
        if param not in existing_sysctl:
            with sysctl_file.open("a") as f:
                f.write(param + "\n")
    _run(["sysctl", "-p"])

    # ── 6. UFW 防火墙 ──
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

    # ── 7. fail2ban ──
    info("配置 fail2ban...")
    _run(["apt", "install", "-y", "fail2ban"])
    jail_dir = Path("/etc/fail2ban/jail.d")
    jail_dir.mkdir(parents=True, exist_ok=True)
    (jail_dir / "defaults-debian.conf").write_text(_FAIL2BAN_CONF)
    _run(["systemctl", "restart", "fail2ban"])

    # ── 8. Crontab（流量监控） ──
    info("配置流量监控 crontab...")
    work_dir = Path.cwd().resolve()
    cron_jobs = [
        f"0 * * * * cd {work_dir} && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1",
        f"@reboot cd {work_dir} && python3 deploy.py check-traffic >> /var/log/nano-xray-traffic.log 2>&1",
    ]

    result = _run(["crontab", "-l"], capture_output=True, text=True)
    existing_cron = result.stdout or ""

    existing_lines = set(existing_cron.splitlines())
    missing_jobs = [job for job in cron_jobs if job not in existing_lines]
    if not missing_jobs:
        info("  每小时和开机流量监控 crontab 已存在，跳过")
    else:
        prefix = existing_cron.rstrip("\n")
        new_cron = "\n".join([item for item in [prefix, *missing_jobs] if item]) + "\n"
        subprocess.run(
            ["crontab", "-"],
            input=new_cron,
            text=True,
            check=False,
        )

        # 验证
        verify = _run(["crontab", "-l"], capture_output=True, text=True)
        verified_lines = set((verify.stdout or "").splitlines())
        if all(job in verified_lines for job in cron_jobs):
            info("  已添加每小时和开机流量监控 crontab ✓")
        else:
            warn("  crontab 写入失败，请手动添加每小时和 @reboot 检查")

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
    info(
        "下一步: 编辑 .env 填入 CF_API_TOKEN、REDIRECT_URL 和 SSH_KEY_1，"
        "然后运行 python3 deploy.py init"
    )


def cmd_init(args: argparse.Namespace) -> None:
    _ensure_env()
    dotenv = load_dotenv()
    ssh_keys = _collect_ssh_public_keys(dotenv)
    if ssh_keys:
        if os.geteuid() != 0:
            raise ValidationError(
                "init 检测到 SSH_KEY_*，配置 /root/.ssh 和 sshd 需要 root 权限"
            )
        info("正在配置 root SSH 公钥...")
        added_keys = _install_authorized_keys(ssh_keys)
        preserve_password_auth = (
            SSHD_DROP_IN.exists()
            and "PasswordAuthentication yes"
            in SSHD_DROP_IN.read_text(encoding="utf-8").splitlines()
        )
        _configure_sshd(
            allow_password_auth=preserve_password_auth,
            have_public_keys=True,
        )
        info(
            f"authorized_keys 已校验：新增 {added_keys} 个，"
            f"已有 {len(ssh_keys) - added_keys} 个"
        )
        info(f"sshd 配置已验证并 reload：{SSHD_DROP_IN}")
    else:
        info(".env 未配置 SSH_KEY_*，保留现有 authorized_keys 和 sshd 策略")

    if SERVICES_FILE.exists():
        warn("services.json 已存在")
        if not confirm_prompt("覆盖?"):
            info("已保留 services.json；SSH 公钥检查已完成")
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

    warn("运行 'deploy.py up --generate' 使配置生效")


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
    if args.generate:
        _ensure_env()
        reg = Registry.load()
        ConfigGenerator(reg).generate_all()

    if not (GENERATED_DIR / "docker-compose.yml").is_file():
        error(
            "generated/docker-compose.yml 不存在，请先运行: python3 deploy.py up --generate"
        )
        sys.exit(1)

    print()
    info("正在启动 Docker 服务（使用现有配置）...")
    try:
        result = docker_compose("up", "-d")
    except FileNotFoundError:
        error("未找到 Docker，请先安装 Docker 并确保 docker 命令可用")
        sys.exit(1)
    if result.returncode:
        error("Docker 服务启动失败")
        sys.exit(result.returncode)
    print()
    info("所有服务已启动 ✓")
    print()
    result = docker_compose("ps")
    if result.returncode:
        sys.exit(result.returncode)


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
        was_active = traffic_guard_is_active()
        if not was_active:
            warning_msg = (
                f"🚨 *nano-xray 流量超限*\n"
                f"主机: `{host}`\n"
                f"当月出站: `{tx_gb:.2f} GB` / `{limit_gb:.0f} GB`\n"
                "即将启用紧急网络锁，仅保留 TCP 22"
            )
            # 锁定后 HTTPS 也会被阻断，因此必须在安装规则前发送通知。
            send_telegram(bot_token, chat_id, warning_msg)
        if not traffic_guard_enable():
            print(f"{ts} {host} | {usage} | ERROR: traffic guard failed")
            sys.exit(1)
        print(f"{ts} {host} | {usage} | BLOCKED")
    else:
        if traffic_guard_is_active():
            if not traffic_guard_disable():
                print(f"{ts} {host} | {usage} | ERROR: traffic guard release failed")
                sys.exit(1)
            ufw_allow_ports()
            print(f"{ts} {host} | {usage} | UNBLOCKED")
            msg = (
                f"✅ *nano-xray 流量恢复*\n"
                f"主机: `{host}`\n"
                f"当月出站: `{tx_gb:.2f} GB` / `{limit_gb:.0f} GB`\n"
                "已解除紧急网络锁并恢复 80/443 服务端口"
            )
            send_telegram(bot_token, chat_id, msg)
        else:
            # 升级自旧版本后，即使当前没有 nftables 流量锁，也清理其遗留规则。
            _remove_legacy_ufw_denies()
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
    p_prepare.add_argument(
        "--configure-ssh-password-auth",
        action="store_true",
        help="显式启用 root 与密码 SSH 登录（默认保留现有密码认证策略）",
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
    p_up = sub.add_parser("up", help="使用现有配置启动 Docker 服务（默认不生成配置）")
    p_up.add_argument(
        "--generate",
        action="store_true",
        help="启动前重新生成配置（覆盖 generated 中的配置）",
    )
    p_up.set_defaults(func=cmd_up)

    # reload
    p_reload = sub.add_parser("reload", help="重新生成配置并热加载（零停机）")
    p_reload.set_defaults(func=cmd_reload)

    # check-traffic
    p_traffic = sub.add_parser(
        "check-traffic", help="检查当月流量，超限后除 TCP 22 外锁定网络"
    )
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

    add_topology_parsers(sub, SCRIPT_DIR)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    run_safely(args.func, args)


if __name__ == "__main__":
    main()
