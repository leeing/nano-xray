from __future__ import annotations

import argparse
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

import deploy


class LegacyCommandTests(unittest.TestCase):
    @staticmethod
    def _public_key(comment: str = "user@example") -> str:
        body = base64.b64encode(b"a valid test public key payload").decode()
        return f"ssh-ed25519 {body} {comment}"

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

    def test_collect_ssh_keys_merges_sources_and_deduplicates_identity(self) -> None:
        key = self._public_key()
        second_key = self._public_key("same-key-different-comment")
        third_key = (
            f"ssh-rsa {base64.b64encode(b'another valid key payload').decode()} cli"
        )
        with tempfile.TemporaryDirectory() as directory:
            key_file = Path(directory) / "keys.pub"
            key_file.write_text(f"# managed keys\n{third_key}\n", encoding="utf-8")
            with patch.dict(os.environ, {"SSH_KEY_2": key}, clear=True):
                keys = deploy._collect_ssh_public_keys(
                    {
                        "SSH_KEY_1": second_key,
                        "SSH_KEY_3": third_key,
                        "SSH_KEY_FILE": str(key_file),
                    }
                )
        self.assertEqual(keys, [second_key, third_key])

    def test_install_authorized_keys_is_atomic_and_preserves_existing_lines(
        self,
    ) -> None:
        existing = self._public_key("existing")
        new_key = (
            f"ssh-rsa {base64.b64encode(b'a different valid key payload').decode()} new"
        )
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir()
            authorized_keys = ssh_dir / "authorized_keys"
            authorized_keys.write_text(f"# keep this comment\n{existing}\n")
            with patch.object(deploy.os, "geteuid", return_value=501):
                added = deploy._install_authorized_keys(
                    [self._public_key("duplicate"), new_key], ssh_dir
                )
            content = authorized_keys.read_text(encoding="utf-8")
            self.assertEqual(added, 1)
            self.assertIn("# keep this comment", content)
            self.assertIn(existing, content)
            self.assertIn(new_key, content)
            self.assertFalse((ssh_dir / "authorized_keys.nano-xray.tmp").exists())
            self.assertEqual(authorized_keys.stat().st_mode & 0o777, 0o600)

    def test_install_authorized_keys_does_not_rewrite_without_new_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir()
            authorized_keys = ssh_dir / "authorized_keys"
            authorized_keys.write_text("custom existing content", encoding="utf-8")
            os.chmod(authorized_keys, 0o640)
            with patch.object(deploy.os, "geteuid", return_value=501):
                added = deploy._install_authorized_keys([], ssh_dir)
            self.assertEqual(added, 0)
            self.assertEqual(
                authorized_keys.read_text(encoding="utf-8"), "custom existing content"
            )
            self.assertEqual(authorized_keys.stat().st_mode & 0o777, 0o640)

    def test_configure_sshd_validates_effective_settings_before_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            drop_in = Path(directory) / "00-nano-xray.conf"
            validation = Mock(returncode=0, stdout="", stderr="")
            effective = Mock(
                returncode=0,
                stdout=(
                    "pubkeyauthentication yes\n"
                    "authorizedkeysfile .ssh/authorized_keys\n"
                    "permitrootlogin without-password\n"
                    "passwordauthentication no\n"
                ),
                stderr="",
            )
            with (
                patch.object(deploy, "SSHD_DROP_IN", drop_in),
                patch.object(deploy, "_sshd_binary", return_value="/usr/sbin/sshd"),
                patch.object(deploy, "_run", side_effect=[validation, effective]),
                patch.object(deploy, "_reload_sshd", return_value=True) as reload_sshd,
            ):
                configured = deploy._configure_sshd(
                    allow_password_auth=False, have_public_keys=True
                )
            self.assertTrue(configured)
            self.assertIn("PubkeyAuthentication yes", drop_in.read_text())
            self.assertIn("PermitRootLogin prohibit-password", drop_in.read_text())
            reload_sshd.assert_called_once_with()

    def test_configure_sshd_restores_previous_file_when_effective_config_differs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            drop_in = Path(directory) / "00-nano-xray.conf"
            drop_in.write_text("# previous\n", encoding="utf-8")
            validation = Mock(returncode=0, stdout="", stderr="")
            ineffective = Mock(
                returncode=0,
                stdout=(
                    "pubkeyauthentication no\n"
                    "authorizedkeysfile .ssh/authorized_keys\n"
                    "permitrootlogin no\n"
                ),
                stderr="",
            )
            with (
                patch.object(deploy, "SSHD_DROP_IN", drop_in),
                patch.object(deploy, "_sshd_binary", return_value="/usr/sbin/sshd"),
                patch.object(deploy, "_run", side_effect=[validation, ineffective]),
                patch.object(deploy, "_reload_sshd") as reload_sshd,
                self.assertRaises(deploy.ValidationError),
            ):
                deploy._configure_sshd(allow_password_auth=False, have_public_keys=True)
            self.assertEqual(drop_in.read_text(encoding="utf-8"), "# previous\n")
            reload_sshd.assert_not_called()

    def test_reload_sshd_prefers_sshd_service_and_falls_back(self) -> None:
        failed = Mock(returncode=1)
        succeeded = Mock(returncode=0)
        with patch.object(deploy, "_run", side_effect=[failed, succeeded]) as run:
            reloaded = deploy._reload_sshd()
        self.assertTrue(reloaded)
        self.assertEqual(
            [item.args[0][:3] for item in run.call_args_list],
            [
                ["systemctl", "reload", "sshd.service"],
                ["systemctl", "reload", "ssh.service"],
            ],
        )

    def test_init_installs_env_public_keys_and_configures_sshd(self) -> None:
        key = self._public_key()
        args = argparse.Namespace(
            token="",
            redirect="https://www.example.com",
            uuid="00000000-0000-4000-8000-000000000000",
            vless_ws_path="/vless",
            vmess_ws_path="/vmess",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(deploy, "_ensure_env"),
                patch.object(deploy, "SERVICES_FILE", root / "services.json"),
                patch.object(deploy, "SSHD_DROP_IN", root / "00-nano-xray.conf"),
                patch.object(deploy, "load_dotenv", return_value={"SSH_KEY_1": key}),
                patch.object(deploy.os, "geteuid", return_value=0),
                patch.object(
                    deploy, "_install_authorized_keys", return_value=1
                ) as install,
                patch.object(deploy, "_configure_sshd", return_value=True) as configure,
                patch.object(deploy, "detect_public_ip", return_value=""),
                patch.object(deploy.Registry, "save"),
            ):
                deploy.cmd_init(args)
        install.assert_called_once_with([key])
        configure.assert_called_once_with(
            allow_password_auth=False,
            have_public_keys=True,
        )

    def test_init_syncs_ssh_before_declining_services_overwrite(self) -> None:
        key = self._public_key()
        args = argparse.Namespace(
            token="",
            redirect="",
            uuid="",
            vless_ws_path="",
            vmess_ws_path="",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            services = root / "services.json"
            services.write_text("{}", encoding="utf-8")
            with (
                patch.object(deploy, "_ensure_env"),
                patch.object(deploy, "SERVICES_FILE", services),
                patch.object(deploy, "SSHD_DROP_IN", root / "00-nano-xray.conf"),
                patch.object(deploy, "load_dotenv", return_value={"SSH_KEY_1": key}),
                patch.object(deploy.os, "geteuid", return_value=0),
                patch.object(
                    deploy, "_install_authorized_keys", return_value=1
                ) as install,
                patch.object(deploy, "_configure_sshd", return_value=True) as configure,
                patch.object(deploy, "confirm_prompt", return_value=False),
                patch.object(deploy.Registry, "save") as save,
            ):
                deploy.cmd_init(args)
        install.assert_called_once_with([key])
        configure.assert_called_once_with(
            allow_password_auth=False,
            have_public_keys=True,
        )
        save.assert_not_called()

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
