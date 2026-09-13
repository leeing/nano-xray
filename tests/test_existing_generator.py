from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import deploy


class ExistingGeneratorTests(unittest.TestCase):
    def test_dual_protocol_and_reverse_proxy_are_preserved(self) -> None:
        registry = deploy.Registry(
            cf_api_token="test",
            redirect_url="https://www.example.com",
            services=[
                {
                    "type": "proxy",
                    "domain": "hk.example.com",
                    "uuid": "1fa17010-cc45-4f02-99d1-8611d5f313a9",
                    "vless_ws_path": "/vless",
                    "vmess_ws_path": "/vmess",
                    "container_name": "xray-hk",
                },
                {
                    "type": "service",
                    "domain": "api.example.com",
                    "target": "host.docker.internal:8317",
                    "allowed_ips": ["192.0.2.0/24"],
                },
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory) / "generated"
            with patch.object(deploy, "GENERATED_DIR", generated):
                deploy.ConfigGenerator(registry).generate_all()
            config = json.loads(
                (generated / "xray" / "xray-hk" / "config.json").read_text()
            )
            caddy = (generated / "Caddyfile").read_text()
            compose = (generated / "docker-compose.yml").read_text()
        self.assertEqual(
            [item["protocol"] for item in config["inbounds"]],
            ["vless", "vmess"],
        )
        self.assertIn("reverse_proxy xray-hk:2001", caddy)
        self.assertIn("reverse_proxy xray-hk:2002", caddy)
        self.assertIn("remote_ip 192.0.2.0/24", caddy)
        self.assertIn("host.docker.internal:host-gateway", compose)


if __name__ == "__main__":
    unittest.main()
