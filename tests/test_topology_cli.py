from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import deploy
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
        with patch.object(deploy, "SERVICES_FILE", self.root / "services.json"):
            run_safely(args.func, args)

    @staticmethod
    def services(node: str, service_uuid: str) -> dict[str, object]:
        return {
            "services": [
                {
                    "type": "proxy",
                    "domain": f"{node}.example.com",
                    "uuid": service_uuid,
                    "vless_ws_path": f"/{node}-vless",
                    "vmess_ws_path": f"/{node}-vmess",
                    "container_name": f"xray-{node}",
                }
            ]
        }

    def test_node_import_only_needs_a_local_services_file(self) -> None:
        source = self.root / "jp-services.json"
        source.write_text(
            json.dumps(
                {
                    "services": [
                        {
                            "type": "proxy",
                            "domain": "jp.example.com",
                            "uuid": "b2295c90-b109-4451-92be-e9c40e37c15b",
                            "vless_ws_path": "/vless-jp",
                            "vmess_ws_path": "/vmess-jp",
                            "container_name": "xray-jp",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        self.run_command("node", "import", "jp", "--services-file", str(source))

        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        imported = json.loads(
            (self.root / "inventory" / "nodes" / "jp" / "services.json").read_text()
        )
        self.assertEqual(topology["nodes"][0]["host"], "")
        self.assertEqual(topology["nodes"][0]["domain"], "jp.example.com")
        first_services_hash = topology["nodes"][0]["services_hash"]
        self.assertEqual(imported["services"][0]["container_name"], "xray-jp")

        replacement = json.loads(source.read_text())
        replacement["services"][0]["uuid"] = "4934209e-2345-40ea-802d-31232680c184"
        source.write_text(json.dumps(replacement), encoding="utf-8")
        self.run_command("node", "import", "jp", "--services-file", str(source))
        refreshed = json.loads(
            (self.root / "inventory" / "nodes" / "jp" / "services.json").read_text()
        )
        refreshed_topology = json.loads(
            (self.root / "inventory" / "topology.json").read_text()
        )
        self.assertEqual(
            refreshed["services"][0]["uuid"],
            "4934209e-2345-40ea-802d-31232680c184",
        )
        self.assertNotEqual(
            refreshed_topology["nodes"][0]["services_hash"], first_services_hash
        )

    def test_node_link_and_plan_lifecycle(self) -> None:
        local_services = self.root / "services.json"
        target_services = self.root / "us1-services.json"
        local_services.write_text(
            json.dumps(self.services("hk1", "34374f8a-5f2e-44e7-9002-1c72fb473bbb"))
        )
        target_services.write_text(
            json.dumps(self.services("us1", "aee492de-7dbe-4d2f-b891-6aa0dfb1297b"))
        )
        self.run_command(
            "node", "import", "us1", "--services-file", str(target_services)
        )
        self.run_command("link", "add", "us1")
        with self.assertRaises(SystemExit):
            self.run_command("link", "add", "us1")
        self.run_command("plan", "--links", "hk1-us1", "--save", "plans/link.json")

        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        plan = json.loads((self.root / "plans" / "link.json").read_text())
        services = json.loads(
            (self.root / "inventory" / "nodes" / "hk1" / "services.json").read_text()
        )
        us_services = json.loads(
            (self.root / "inventory" / "nodes" / "us1" / "services.json").read_text()
        )
        self.assertEqual(len(topology["nodes"]), 2)
        self.assertEqual(topology["links"][0]["id"], "hk1-us1")
        self.assertEqual(topology["links"][0]["entry_service"], "xray-hk1")
        self.assertEqual(plan["affected_nodes"], ["hk1"])
        self.assertEqual(services["services"][0]["domain"], "hk1.example.com")
        self.assertEqual(
            (self.root / "inventory" / "topology.json").stat().st_mode & 0o777,
            0o600,
        )
        hk_bundle = Path(plan["artifacts"]["hk1"]["directory"])
        xray = json.loads((hk_bundle / "xray" / "xray-hk1" / "config.json").read_text())
        self.assertEqual(
            {inbound["listen"] for inbound in xray["inbounds"]}, {"127.0.0.1"}
        )
        self.assertEqual(len(xray["inbounds"][0]["settings"]["clients"]), 2)
        self.assertEqual(len(xray["inbounds"][1]["settings"]["clients"]), 2)
        self.assertIn("link.hk1-us1", {item["tag"] for item in xray["outbounds"]})
        link_outbound = next(
            item for item in xray["outbounds"] if item["tag"] == "link.hk1-us1"
        )
        self.assertEqual(link_outbound["protocol"], "vless")
        self.assertEqual(
            link_outbound["settings"]["vnext"][0]["address"], "us1.example.com"
        )
        self.assertEqual(
            link_outbound["settings"]["vnext"][0]["users"][0]["id"],
            us_services["services"][0]["uuid"],
        )
        self.assertEqual(
            link_outbound["streamSettings"]["wsSettings"]["path"],
            us_services["services"][0]["vless_ws_path"],
        )
        self.assertIn(
            "network_mode: host", (hk_bundle / "docker-compose.yml").read_text()
        )
        self.assertNotIn("NET_ADMIN", (hk_bundle / "docker-compose.yml").read_text())
        self.assertIn(
            "reverse_proxy 127.0.0.1:2001",
            (hk_bundle / "caddy" / "Caddyfile").read_text(),
        )
        self.assertNotIn("us1", plan["artifacts"])

        self.run_command("link", "disable", "hk1-us1")
        self.run_command("plan", "--links", "hk1-us1", "--save", "plans/disabled.json")
        disabled_plan = json.loads((self.root / "plans" / "disabled.json").read_text())
        disabled_bundle = Path(disabled_plan["artifacts"]["hk1"]["directory"])
        disabled_xray = json.loads(
            (disabled_bundle / "xray" / "xray-hk1" / "config.json").read_text()
        )
        self.assertEqual(len(disabled_xray["inbounds"][0]["settings"]["clients"]), 1)
        self.run_command("link", "enable", "hk1-us1")
        self.run_command("link", "del", "us1")
        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        self.assertEqual(topology["links"], [])
        self.assertEqual(topology["tombstones"][0]["id"], "hk1-us1")
        self.run_command("plan", "--links", "hk1-us1", "--save", "plans/cleanup.json")
        cleanup = json.loads((self.root / "plans" / "cleanup.json").read_text())
        self.assertEqual(cleanup["affected_nodes"], ["hk1"])
        self.assertEqual(cleanup["actions"][0]["action"], "cleanup-link")
        self.assertEqual(cleanup["actions"][0]["node"], "hk1")

    def test_node_remove_refuses_live_links(self) -> None:
        (self.root / "services.json").write_text(
            json.dumps(self.services("hk1", "34374f8a-5f2e-44e7-9002-1c72fb473bbb"))
        )
        target = self.root / "us1-services.json"
        target.write_text(
            json.dumps(self.services("us1", "aee492de-7dbe-4d2f-b891-6aa0dfb1297b"))
        )
        self.run_command("node", "import", "us1", "--services-file", str(target))
        self.run_command("link", "add", "us1")
        with self.assertRaises(SystemExit):
            self.run_command("node", "remove", "us1")

    def test_link_del_target_keeps_other_local_links(self) -> None:
        (self.root / "services.json").write_text(
            json.dumps(self.services("tw", "34374f8a-5f2e-44e7-9002-1c72fb473bbb"))
        )
        for target, service_uuid in (
            ("jp", "aee492de-7dbe-4d2f-b891-6aa0dfb1297b"),
            ("us", "9938905a-352f-4749-aa9f-967e9900b3a5"),
        ):
            source = self.root / f"{target}-services.json"
            source.write_text(json.dumps(self.services(target, service_uuid)))
            self.run_command("node", "import", target, "--services-file", str(source))
            self.run_command("link", "add", target)

        self.run_command("link", "del", "jp")

        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        self.assertEqual([item["id"] for item in topology["links"]], ["tw-us"])
        self.assertEqual([item["id"] for item in topology["tombstones"]], ["tw-jp"])

        generated = self.root / "generated"
        current = generated / "xray" / "xray-tw" / "config.json"
        current.parent.mkdir(parents=True)
        current.write_text('{"old": true}\n')
        (generated / "docker-compose.yml").write_text("services: {}\n")
        args = self.parser.parse_args(("apply", "--link", "tw-jp"))
        with (
            patch.object(deploy, "SERVICES_FILE", self.root / "services.json"),
            patch.object(deploy, "GENERATED_DIR", generated),
            patch.object(deploy, "_validate_xray_file"),
            patch.object(deploy, "_restart_xray_container", return_value=True),
        ):
            run_safely(args.func, args)

        applied = json.loads(current.read_text())
        outbound_tags = {item.get("tag") for item in applied["outbounds"]}
        self.assertNotIn("link.tw-jp", outbound_tags)
        self.assertIn("link.tw-us", outbound_tags)
        topology = json.loads((self.root / "inventory" / "topology.json").read_text())
        self.assertEqual(topology["tombstones"], [])

    def test_apply_link_updates_only_local_xray_and_keeps_backup(self) -> None:
        tw_services = self.root / "services.json"
        jp_services = self.root / "jp-services.json"

        tw_services.write_text(
            json.dumps(self.services("tw", "34374f8a-5f2e-44e7-9002-1c72fb473bbb"))
        )
        jp_services.write_text(
            json.dumps(self.services("jp", "aee492de-7dbe-4d2f-b891-6aa0dfb1297b"))
        )
        self.run_command("node", "import", "jp", "--services-file", str(jp_services))
        self.run_command("link", "add", "jp")

        generated = self.root / "generated"
        current = generated / "xray" / "xray-tw" / "config.json"
        current.parent.mkdir(parents=True)
        current.write_text('{"old": true}\n')
        (generated / "docker-compose.yml").write_text("services: {}\n")

        args = self.parser.parse_args(("apply", "--link", "tw-jp"))
        with (
            patch.object(deploy, "SERVICES_FILE", tw_services),
            patch.object(deploy, "GENERATED_DIR", generated),
            patch.object(deploy, "_validate_xray_file") as validate,
            patch.object(
                deploy, "_restart_xray_container", return_value=True
            ) as restart,
        ):
            run_safely(args.func, args)

        applied = json.loads(current.read_text())
        outbound = next(
            item for item in applied["outbounds"] if item.get("tag") == "link.tw-jp"
        )
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], "jp.example.com")
        validate.assert_called_once()
        restart.assert_called_once_with("xray-tw")
        backups = list((self.root / "state" / "backups").glob("*/config.json"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(json.loads(backups[0].read_text()), {"old": True})

        regenerated = self.root / "regenerated"
        with (
            patch.object(deploy, "SCRIPT_DIR", self.root),
            patch.object(deploy, "SERVICES_FILE", tw_services),
            patch.object(deploy, "GENERATED_DIR", regenerated),
        ):
            deploy.ConfigGenerator(deploy.Registry.load()).generate_all()
        regenerated_config = json.loads(
            (regenerated / "xray" / "xray-tw" / "config.json").read_text()
        )
        self.assertIn(
            "link.tw-jp",
            {item.get("tag") for item in regenerated_config["outbounds"]},
        )

        before_failed_apply = current.read_text()
        with (
            patch.object(deploy, "SERVICES_FILE", tw_services),
            patch.object(deploy, "GENERATED_DIR", generated),
            patch.object(deploy, "_validate_xray_file"),
            patch.object(
                deploy, "_restart_xray_container", side_effect=[False, True]
            ) as restart_with_rollback,
            self.assertRaises(SystemExit),
        ):
            run_safely(args.func, args)
        self.assertEqual(current.read_text(), before_failed_apply)
        self.assertEqual(restart_with_rollback.call_count, 2)

    def test_link_rejects_target_that_was_not_imported(self) -> None:
        (self.root / "services.json").write_text(
            json.dumps(self.services("hk1", "34374f8a-5f2e-44e7-9002-1c72fb473bbb"))
        )
        with self.assertRaises(SystemExit):
            self.run_command("link", "add", "us1")


if __name__ == "__main__":
    unittest.main()
