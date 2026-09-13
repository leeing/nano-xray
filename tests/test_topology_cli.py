from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from deploy import add_topology_parsers, run_safely


class TopologyCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.parser = argparse.ArgumentParser()
        sub = self.parser.add_subparsers(dest="command", required=True)
        add_topology_parsers(sub, self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, *arguments: str) -> None:
        args = self.parser.parse_args(arguments)
        run_safely(args.func, args)

    def test_node_link_and_plan_lifecycle(self) -> None:
        self.run_command(
            "node",
            "add",
            "hk1",
            "--host",
            "root@192.0.2.1",
            "--domain",
            "hk.example.com",
            "--network-profile",
            "host-l3",
        )
        self.run_command(
            "node",
            "add",
            "us1",
            "--host",
            "root@192.0.2.2",
            "--domain",
            "us.example.com",
            "--network-profile",
            "host-l3",
        )
        self.run_command(
            "link",
            "add",
            "hk1",
            "us1",
            "--id",
            "hk1-us1",
            "--entry-service",
            "xray-hk1",
        )
        self.run_command("plan", "--links", "hk1-us1", "--save", "plans/link.json")

        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        plan = json.loads((self.root / "plans" / "link.json").read_text())
        services = json.loads(
            (self.root / "inventory" / "nodes" / "hk1" / "services.json").read_text()
        )
        self.assertEqual(len(topology["nodes"]), 2)
        self.assertEqual(topology["links"][0]["id"], "hk1-us1")
        self.assertEqual(plan["affected_nodes"], ["hk1", "us1"])
        self.assertEqual(services["services"][0]["domain"], "hk.example.com")
        self.assertEqual(
            (self.root / "inventory" / "topology.json").stat().st_mode & 0o777,
            0o600,
        )
        hk_bundle = Path(plan["artifacts"]["hk1"]["directory"])
        us_bundle = Path(plan["artifacts"]["us1"]["directory"])
        xray = json.loads((hk_bundle / "xray" / "xray-hk1" / "config.json").read_text())
        self.assertEqual(
            {inbound["listen"] for inbound in xray["inbounds"]}, {"127.0.0.1"}
        )
        self.assertEqual(len(xray["inbounds"][0]["settings"]["clients"]), 2)
        self.assertEqual(len(xray["inbounds"][1]["settings"]["clients"]), 2)
        self.assertIn("link.hk1-us1", {item["tag"] for item in xray["outbounds"]})
        self.assertIn(
            "network_mode: host", (hk_bundle / "docker-compose.yml").read_text()
        )
        self.assertIn("NET_ADMIN", (hk_bundle / "docker-compose.yml").read_text())
        self.assertIn(
            "reverse_proxy 127.0.0.1:2001",
            (hk_bundle / "caddy" / "Caddyfile").read_text(),
        )
        us_manifest = json.loads((us_bundle / "node-manifest.json").read_text())
        self.assertNotIn("client_uuid", us_manifest["incoming_links"][0]["allocation"])

        self.run_command("link", "disable", "hk1-us1")
        self.run_command("plan", "--links", "hk1-us1", "--save", "plans/disabled.json")
        disabled_plan = json.loads((self.root / "plans" / "disabled.json").read_text())
        disabled_bundle = Path(disabled_plan["artifacts"]["hk1"]["directory"])
        disabled_xray = json.loads(
            (disabled_bundle / "xray" / "xray-hk1" / "config.json").read_text()
        )
        self.assertEqual(len(disabled_xray["inbounds"][0]["settings"]["clients"]), 1)
        self.run_command("link", "enable", "hk1-us1")
        self.run_command("node", "detach", "us1", "--incoming")
        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        self.assertEqual(topology["links"], [])
        self.assertEqual(topology["tombstones"][0]["id"], "hk1-us1")
        self.run_command("plan", "--links", "hk1-us1", "--save", "plans/cleanup.json")
        cleanup = json.loads((self.root / "plans" / "cleanup.json").read_text())
        self.assertEqual(cleanup["affected_nodes"], ["hk1", "us1"])
        self.assertEqual(cleanup["actions"][0]["action"], "cleanup-link")

    def test_node_remove_refuses_live_links(self) -> None:
        for node_id in ("hk1", "us1"):
            self.run_command(
                "node",
                "add",
                node_id,
                "--host",
                f"root@{node_id}",
                "--domain",
                f"{node_id}.example.com",
                "--network-profile",
                "host-l3",
            )
        self.run_command(
            "link",
            "add",
            "hk1",
            "us1",
            "--id",
            "hk1-us1",
            "--entry-service",
            "xray-hk1",
        )
        with self.assertRaises(SystemExit):
            self.run_command("node", "remove", "us1")

    def test_link_rejects_unknown_entry_service(self) -> None:
        for node_id in ("hk1", "us1"):
            self.run_command(
                "node",
                "add",
                node_id,
                "--host",
                f"root@{node_id}",
                "--domain",
                f"{node_id}.example.com",
                "--network-profile",
                "host-l3",
            )
        with self.assertRaises(SystemExit):
            self.run_command(
                "link",
                "add",
                "hk1",
                "us1",
                "--id",
                "hk1-us1",
                "--entry-service",
                "missing",
            )


if __name__ == "__main__":
    unittest.main()
