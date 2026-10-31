from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from appsbx import install
from appsbx.paths import state_root


class InstallTests(unittest.TestCase):
    def test_detect_package_manager_uses_supported_precedence(self):
        available = {"dnf": "/usr/bin/dnf", "pacman": "/usr/bin/pacman"}
        self.assertEqual(install.detect_package_manager(available.get), "dnf")
        self.assertIsNone(install.detect_package_manager(lambda _name: None))

    def test_package_plan_and_command_are_distro_specific(self):
        packages = install.package_plan("apt")
        self.assertIn("bubblewrap", packages)
        self.assertIn("nftables", packages)
        self.assertEqual(install.package_command("apt", ("bubblewrap",))[0:3], ["sudo", "apt-get", "install"])
        self.assertEqual(install.package_plan(None), [])

    def test_state_root_defaults_and_rejects_relative_override(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(state_root().name, "sandbox-state")
        with mock.patch.dict(os.environ, {"APPSBX_STATE_ROOT": "relative"}, clear=True):
            with self.assertRaisesRegex(ValueError, "absolute"):
                state_root()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"APPSBX_STATE_ROOT": directory}, clear=True):
                self.assertEqual(state_root(), Path(directory).resolve())

    def test_copy_verifies_bundled_payload_and_creates_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            executable = source / "apps/zaap.AppDir/zaap"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"\x7fELF\x02minimal-payload")
            executable.chmod(0o700)
            destination = base / "installed"
            state = base / "state"
            install.install_user_copy(source, destination, state)
            self.assertTrue((destination / "apps/zaap.AppDir/zaap").is_file())
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertTrue((destination / install.INSTALL_MARKER).is_file())
            self.assertTrue((state / install.STATE_MARKER).is_file())

    def test_copy_can_install_engine_without_a_proprietary_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            destination = base / "installed"
            install.install_user_copy(source, destination, base / "state", allow_missing_payload=True)
            self.assertTrue((destination / install.INSTALL_MARKER).is_file())

    def test_uninstall_refuses_unmanaged_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                install.uninstall(Path(directory) / "not-appsbx", Path(directory) / "state", remove_state=False, dry_run=True)

    def test_dry_run_does_not_copy_or_create_venv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            with mock.patch.object(install, "PROJECT_ROOT", Path(__file__).parents[1]):
                exit_code = install.main([
                    "install", "--prefix", str(root), "--state-dir", str(Path(directory) / "state"),
                    "--dry-run", "--skip-system-packages", "--skip-network-helper",
                ])
            self.assertEqual(exit_code, 0)
            self.assertFalse(root.exists())

    def test_launcher_uses_explicit_state_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            launchers = install.write_launchers(
                base / "app", base / "state", dry_run=False,
                local_bin=base / "bin", data_home=base / "data",
            )
            self.assertIn("APPSBX_STATE_ROOT=" + str(base / "state"), launchers[0].read_text(encoding="utf-8"))
            self.assertIn(install.LAUNCHER_MARKER, launchers[0].read_text(encoding="utf-8"))
            self.assertTrue(launchers[1].is_file())


if __name__ == "__main__":
    unittest.main()
