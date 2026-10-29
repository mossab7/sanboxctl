from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock

from appsbx.cli import parser
from appsbx.identity import identity_report
from appsbx.instances import BUNDLED_APP_ROOT, InstanceStore, active_interface_users, discover_egresses, instance_app_root
from appsbx.network import EgressDefinition, _live_interface_definition
import ipaddress
from appsbx.profile import ProfileError, load_profile
from appsbx import gui


ROOT = Path(__file__).parents[1]
PROFILE = load_profile(ROOT / "profiles" / "example.toml")


class InstanceStoreTests(unittest.TestCase):
    def test_create_persists_generated_identity_and_unique_instance_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            store = InstanceStore(Path(directory) / "instances", ROOT / "profiles", PROFILE)
            first = store.create("wifi")
            second = store.create("wifi")
            self.assertNotEqual(first.key, second.key)
            self.assertNotEqual(first.profile_id, second.profile_id)
            identity = store.ensure_identity(first)
            again = store.ensure_identity(first)
            self.assertEqual(identity.machine_id, again.machine_id)
            self.assertNotEqual(identity.hardware.hardware_class, "legacy")
            self.assertTrue(all(identity_report(identity)["consistency"].values()))
            self.assertEqual({item.key for item in store.list()}, {first.key, second.key})

    def test_display_backend_is_persistent_and_old_metadata_defaults_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            store = InstanceStore(root, ROOT / "profiles", PROFILE)
            record = store.create("wifi")
            self.assertEqual(record.display_backend, "host")
            record.display_backend = "host"
            store.update(record)
            self.assertEqual(store.list()[0].display_backend, "host")
            raw = json.loads(store.metadata_path.read_text(encoding="utf-8"))
            raw[0].pop("display_backend")
            store.metadata_path.write_text(json.dumps(raw), encoding="utf-8")
            self.assertEqual(store.list()[0].display_backend, "isolated")

    def test_active_interface_users_ignores_stopped_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            store = InstanceStore(root, ROOT / "profiles", PROFILE)
            first = store.create("wifi")
            second = store.create("wifi")
            second.state = "Running"
            store.update(second)
            self.assertEqual(active_interface_users(first, store.list()), [second])
            second.state = "Stopped"
            store.update(second)
            self.assertEqual(active_interface_users(first, store.list()), [])

    def test_delete_is_scoped_to_managed_instance_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "instances"
            store = InstanceStore(root, ROOT / "profiles", PROFILE)
            record = store.create("wifi")
            instance_dir = root / record.key
            self.assertTrue(instance_dir.is_dir())
            store.delete(record)
            self.assertFalse(instance_dir.exists())
            self.assertEqual(store.list(), [])

    def test_egress_discovery_skips_invalid_definitions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "wifi.conf").write_text(
                "name=wifi\ntype=interface\ninterface=wlan0\ndns=192.0.2.53\nipv6=false\n",
                encoding="utf-8",
            )
            (path / "broken.conf").write_text("name=broken\ntype=stub\n", encoding="utf-8")
            with mock.patch("appsbx.instances.discover_dynamic_egresses", return_value=()):
                self.assertEqual(discover_egresses(path), [("wifi", "Wi-Fi (Wi-Fi: wlan0)")])

    def test_egress_discovery_adds_live_interface_without_config_file(self):
        detected = EgressDefinition(
            "auto-enp7s0", "enp7s0", ipaddress.IPv4Address("192.0.2.1"),
            (ipaddress.IPv4Address("192.0.2.53"),), False,
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "appsbx.instances.discover_dynamic_egresses", return_value=(detected,)
        ):
            result = discover_egresses(Path(directory))
        self.assertEqual(result, [("auto-enp7s0", "enp7s0 (detected interface)")])

    def test_automatic_egress_is_revalidated_at_launch(self):
        detected = EgressDefinition(
            "auto-enp7s0", "enp7s0", ipaddress.IPv4Address("192.0.2.1"),
            (ipaddress.IPv4Address("192.0.2.53"),), False,
        )
        with mock.patch("appsbx.network._live_interface_definition", return_value=detected):
            from appsbx.network import load_egress_definition
            self.assertEqual(load_egress_definition("auto-enp7s0").interface, "enp7s0")

    def test_live_interface_detection_accepts_ipv4_default_route(self):
        outputs = iter((
            "2: enp7s0: <UP>\n    inet 192.0.2.10/24 scope global enp7s0\n",
            "default via 192.0.2.1 dev enp7s0\n",
        ))
        def read_text(path, encoding="utf-8"):
            if str(path).endswith("/operstate"):
                return "up\n"
            return "nameserver 192.0.2.53\n"
        with mock.patch("appsbx.network.Path.read_text", read_text), mock.patch(
            "appsbx.network.shutil.which", side_effect=lambda name: "/sbin/ip" if name == "ip" else None
        ), mock.patch("appsbx.network.subprocess.run", side_effect=lambda *a, **k: type(
            "Result", (), {"stdout": next(outputs)}
        )()):
            definition = _live_interface_definition("enp7s0")
        self.assertIsNotNone(definition)
        self.assertEqual(definition.name, "auto-enp7s0")
        self.assertEqual(definition.dns_servers, (ipaddress.IPv4Address("192.0.2.1"),))

    def test_explicit_invalid_app_root_does_not_fallback(self):
        with mock.patch.dict("os.environ", {"APPSBX_APP_ROOT": "/does/not/exist"}):
            with self.assertRaises(ProfileError):
                instance_app_root()

    def test_default_app_root_is_project_relative_and_cwd_independent(self):
        with mock.patch.dict("os.environ", {}, clear=True), tempfile.TemporaryDirectory() as directory:
            with mock.patch("os.getcwd", return_value=directory):
                self.assertEqual(instance_app_root(), BUNDLED_APP_ROOT.resolve())

    def test_explicit_app_root_requires_zaap_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ProfileError, "does not contain the Zaap executable"):
                instance_app_root(directory)

    def test_cli_app_root_is_optional(self):
        args = parser().parse_args(["run", "--profile", "example", "--", "/opt/app/zaap"])
        self.assertIsNone(args.app_root)

    @unittest.skipUnless(gui.QT_AVAILABLE, "PySide6 is not installed for this Python")
    def test_gui_renders_persisted_instances_on_startup(self):
        """Regression: initial rendering must not wait for New Instance."""
        app = gui.QApplication.instance() or gui.QApplication([])
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(gui, "GUI_STATE", Path(directory) / "instances"), \
             mock.patch.object(gui, "discover_egresses", return_value=[("wifi", "Wi-Fi")]):
            store = InstanceStore(gui.GUI_STATE, ROOT / "profiles", PROFILE)
            store.create("wifi")
            window = gui.MainWindow()
            try:
                self.assertEqual(window.list_widget.count(), 1)
            finally:
                window.controller.shutdown()
                window.close()
        app.processEvents()


if __name__ == "__main__":
    unittest.main()
