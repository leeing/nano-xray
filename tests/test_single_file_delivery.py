from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import deploy


class SingleFileDeliveryTests(unittest.TestCase):
    def test_deploy_py_runs_without_project_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standalone = root / "deploy.py"
            shutil.copy2(Path(deploy.__file__), standalone)

            help_result = subprocess.run(  # noqa: S603 - trusted local test command
                [sys.executable, str(standalone), "--help"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("node", help_result.stdout)
            self.assertIn("link", help_result.stdout)

            add_result = subprocess.run(  # noqa: S603 - trusted local test command
                [
                    sys.executable,
                    str(standalone),
                    "node",
                    "add",
                    "hk1",
                    "--host",
                    "root@192.0.2.1",
                    "--domain",
                    "hk.example.com",
                    "--network-profile",
                    "host-l3",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(add_result.returncode, 0, add_result.stderr)
            topology = json.loads((root / "inventory" / "topology.json").read_text())
            self.assertEqual(topology["nodes"][0]["id"], "hk1")
            self.assertFalse((root / "nano_xray").exists())


if __name__ == "__main__":
    unittest.main()
