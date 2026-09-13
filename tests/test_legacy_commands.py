from __future__ import annotations

import argparse
import json
import unittest
from unittest.mock import Mock, call, patch

import deploy


class LegacyCommandTests(unittest.TestCase):
    def test_up_without_generate_does_not_load_or_generate(self) -> None:
        compose = Mock(side_effect=[Mock(returncode=0), Mock(returncode=0)])
        with (
            patch.object(deploy, "_ensure_env"),
            patch.object(deploy, "GENERATED_DIR") as generated,
            patch.object(deploy.Registry, "load") as load,
            patch.object(deploy.ConfigGenerator, "generate_all") as generate,
            patch.object(deploy, "docker_compose", compose),
        ):
            generated.__truediv__.return_value.is_file.return_value = True
            deploy.cmd_up(argparse.Namespace(generate=False))
        load.assert_not_called()
        generate.assert_not_called()

    def test_vnstat_override_must_match_exactly(self) -> None:
        result = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "jsonversion": "2",
                    "interfaces": [
                        {
                            "name": "ens4",
                            "traffic": {"month": [{"tx": 9_000_000_000}]},
                        }
                    ],
                }
            ),
        )
        with patch.object(deploy.subprocess, "run", return_value=result):
            value = deploy.get_vnstat_monthly_tx_gb({"VNSTAT_IFACE": "ens5"})
        self.assertIsNone(value)

    def test_vnstat_auto_discovery_skips_wireguard(self) -> None:
        result = Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "jsonversion": "2",
                    "interfaces": [
                        {
                            "name": "wg0",
                            "traffic": {"month": [{"tx": 9_000_000_000}]},
                        },
                        {
                            "name": "ens4",
                            "traffic": {"month": [{"tx": 2_000_000_000}]},
                        },
                    ],
                }
            ),
        )
        with patch.object(deploy.subprocess, "run", return_value=result):
            value = deploy.get_vnstat_monthly_tx_gb({})
        self.assertEqual(value, 2.0)

    def test_traffic_guard_only_keeps_ssh_and_loopback(self) -> None:
        ruleset = deploy.TRAFFIC_GUARD_RULESET
        self.assertIn('iifname "lo" accept', ruleset)
        self.assertIn('oifname "lo" accept', ruleset)
        self.assertEqual(ruleset.count("tcp dport 22 accept"), 2)
        self.assertEqual(ruleset.count("ct state established tcp sport 22 accept"), 2)
        self.assertIn("chain forward", ruleset)
        self.assertIn("policy drop", ruleset)
        self.assertNotIn("dport 80 accept", ruleset)
        self.assertNotIn("dport 443 accept", ruleset)

    def test_traffic_guard_enable_is_idempotent(self) -> None:
        run = Mock()
        with (
            patch.object(deploy, "_has_nft", return_value=True),
            patch.object(deploy, "traffic_guard_is_active", return_value=True),
            patch.object(deploy.subprocess, "run", run),
        ):
            enabled = deploy.traffic_guard_enable()
        self.assertTrue(enabled)
        run.assert_not_called()

    def test_traffic_guard_uses_an_isolated_nftables_table(self) -> None:
        result = Mock(returncode=0, stderr="")
        with (
            patch.object(deploy, "_has_nft", return_value=True),
            patch.object(deploy, "traffic_guard_is_active", return_value=False),
            patch.object(deploy.subprocess, "run", return_value=result) as run,
        ):
            enabled = deploy.traffic_guard_enable()
        self.assertTrue(enabled)
        run.assert_called_once_with(
            ["nft", "-f", "-"],
            input=deploy.TRAFFIC_GUARD_RULESET,
            capture_output=True,
            text=True,
        )

    def test_traffic_guard_disable_only_deletes_its_own_table(self) -> None:
        result = Mock(returncode=0, stderr="")
        with (
            patch.object(deploy, "_has_nft", return_value=True),
            patch.object(deploy, "traffic_guard_is_active", return_value=True),
            patch.object(deploy.subprocess, "run", return_value=result) as run,
        ):
            disabled = deploy.traffic_guard_disable()
        self.assertTrue(disabled)
        run.assert_called_once_with(
            ["nft", "delete", "table", "inet", deploy.TRAFFIC_GUARD_TABLE],
            capture_output=True,
            text=True,
        )

    def test_traffic_limit_does_not_claim_blocked_when_guard_fails(self) -> None:
        with (
            patch.object(deploy, "_ensure_env"),
            patch.object(
                deploy,
                "load_dotenv",
                return_value={"TRAFFIC_LIMIT_GB": "1"},
            ),
            patch.object(deploy, "get_vnstat_monthly_tx_gb", return_value=2.0),
            patch.object(deploy, "traffic_guard_is_active", return_value=False),
            patch.object(deploy, "traffic_guard_enable", return_value=False),
            patch.object(deploy, "send_telegram"),
            self.assertRaises(SystemExit) as raised,
        ):
            deploy.cmd_check_traffic(argparse.Namespace())
        self.assertEqual(raised.exception.code, 1)

    def test_traffic_alert_is_sent_before_network_is_locked(self) -> None:
        parent = Mock()
        parent.attach_mock(Mock(return_value=True), "notify")
        parent.attach_mock(Mock(return_value=True), "enable")
        with (
            patch.object(deploy, "_ensure_env"),
            patch.object(
                deploy,
                "load_dotenv",
                return_value={
                    "TRAFFIC_LIMIT_GB": "1",
                    "TELEGRAM_BOT_TOKEN": "token",
                    "TELEGRAM_CHAT_ID": "chat",
                },
            ),
            patch.object(deploy, "get_vnstat_monthly_tx_gb", return_value=2.0),
            patch.object(deploy, "traffic_guard_is_active", return_value=False),
            patch.object(deploy, "send_telegram", parent.notify),
            patch.object(deploy, "traffic_guard_enable", parent.enable),
        ):
            deploy.cmd_check_traffic(argparse.Namespace())
        self.assertEqual([item[0] for item in parent.mock_calls], ["notify", "enable"])
        self.assertEqual(parent.mock_calls[1], call.enable())

    def test_traffic_recovery_removes_guard_before_restoring_ports(self) -> None:
        parent = Mock()
        parent.attach_mock(Mock(return_value=True), "disable")
        parent.attach_mock(Mock(), "allow")
        with (
            patch.object(deploy, "_ensure_env"),
            patch.object(
                deploy,
                "load_dotenv",
                return_value={"TRAFFIC_LIMIT_GB": "10"},
            ),
            patch.object(deploy, "get_vnstat_monthly_tx_gb", return_value=2.0),
            patch.object(deploy, "traffic_guard_is_active", return_value=True),
            patch.object(deploy, "traffic_guard_disable", parent.disable),
            patch.object(deploy, "ufw_allow_ports", parent.allow),
            patch.object(deploy, "send_telegram"),
        ):
            deploy.cmd_check_traffic(argparse.Namespace())
        self.assertEqual(parent.mock_calls[:2], [call.disable(), call.allow()])


if __name__ == "__main__":
    unittest.main()
