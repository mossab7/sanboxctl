from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor

from appsbx.identity import (
    PROFILE_HOME_MARKER,
    PROFILE_HOME_MARKER_CONTENT,
    ensure_identity,
    create_auto_identity,
    identity_report,
)
from appsbx.hardware import generate_hardware, validate_hardware
from appsbx.cli import _instance_profile
from appsbx.display import (
    DISPLAY_MARKER_CONTENT,
    OWNER_FILE,
    SESSION_MARKER,
    LocalVNCService,
    create_private_display,
    validate_private_display,
    vnc_viewer_command,
)
from appsbx.elf import (
    ELFError,
    RuntimeBundle,
    VNCBundle,
    _write_private_xdg_open,
    prepare_runtime_bundle,
    prepare_vnc_bundle,
    synthetic_df_script,
)
from appsbx.locking import LockBusy, profile_lock
from appsbx.network import (
    NetworkError,
    build_plan,
    dns_resolv_conf,
    load_egress_definition,
    nft_rules,
    resource_names,
    subnet_overlaps,
    write_dns_resolv_conf,
)
from appsbx.profile import Profile, ProfileError, load_profile
from appsbx.probe import category_report, current_observations, host_denylist, leak_categories
from appsbx.rootfs import inspect_appimage, extraction_command
from appsbx.runtime import build_vnc_bridge_command, execute, prepare_plan
from appsbx.state import StateError, record_egress, require_egress_consistency


EXAMPLE = Path(__file__).parents[1] / "profiles" / "example.toml"


class ProfileTests(unittest.TestCase):
    def test_example_profile_validates(self):
        profile = load_profile(EXAMPLE)
        self.assertEqual(profile.profile_id, 1)
        self.assertEqual(profile.synthetic_hostname, "appsbx-example")
        self.assertEqual(profile.synthetic_disk_mb, 102400)

    def test_invalid_mac_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text(EXAMPLE.read_text().replace("02:00:00:00:00:01", "00:00:00:00:00:01"))
            with self.assertRaises(ProfileError):
                load_profile(path)

    def test_invalid_synthetic_disk_capacity_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text(EXAMPLE.read_text().replace("synthetic_disk_mb = 102400", "synthetic_disk_mb = 32"))
            with self.assertRaises(ProfileError):
                load_profile(path)

    def test_explicit_instance_id_derives_independent_profile_state(self):
        profile = load_profile(EXAMPLE)
        instance = _instance_profile(profile, 2)
        self.assertEqual(instance.name, "example-i2")
        self.assertEqual(instance.profile_id, 2)
        self.assertEqual(instance.synthetic_hostname, profile.synthetic_hostname)
        self.assertIs(_instance_profile(profile, profile.profile_id), profile)


class IdentityTests(unittest.TestCase):
    def test_automatic_hardware_profiles_are_unique_and_consistent(self):
        first = generate_hardware("laptop")
        second = generate_hardware("random")
        validate_hardware(first)
        validate_hardware(second)
        self.assertNotEqual(first.mac, second.mac)
        self.assertNotEqual(first.hostname, second.hostname)
        self.assertGreaterEqual(first.logical_cpus, first.physical_cores)
        self.assertIn(first.cpu_model, first.cpu_model)

    def test_automatic_identity_uses_private_unique_state(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            first = create_auto_identity(profile, Path(directory), "workstation")
            second = create_auto_identity(profile, Path(directory), "workstation")
            self.assertNotEqual(first.state_dir, second.state_dir)
            self.assertNotEqual(first.machine_id, second.machine_id)
            self.assertNotEqual(first.hardware.disk_serial, second.hardware.disk_serial)
            self.assertEqual(first.hardware.hardware_class, "workstation")
            self.assertTrue(identity_report(first)["consistency"]["ram_file_matches"])

    def test_automatic_identity_generation_is_safe_for_concurrent_launches(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            with ThreadPoolExecutor(max_workers=8) as pool:
                identities = list(pool.map(
                    lambda _item: create_auto_identity(profile, Path(directory), "laptop"),
                    range(8),
                ))
            self.assertEqual(len({item.state_dir for item in identities}), 8)
            self.assertEqual(len({item.machine_id for item in identities}), 8)
            self.assertEqual(len({item.hardware.mac for item in identities}), 8)
            self.assertTrue(all(item.file_paths()["/etc/hostname"].read_text().strip() == item.hostname for item in identities))

    def test_persistent_identity_is_stable_and_synthetic(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            first = ensure_identity(profile, Path(directory))
            second = ensure_identity(profile, Path(directory))
            self.assertEqual(first.machine_id, second.machine_id)
            self.assertEqual(first.hostname, "appsbx-example")
            self.assertEqual(first.file_paths()["/etc/machine-id"].read_text().strip(), first.machine_id)
            self.assertEqual(first.file_paths()["/var/lib/dbus/machine-id"].read_text().strip(), first.machine_id)
            self.assertIn("model name", first.file_paths()["/proc/cpuinfo"].read_text())
            proc_stat = first.file_paths()["/proc/stat"].read_text()
            self.assertIn("cpu0 ", proc_stat)
            self.assertIn("cpu1 ", proc_stat)
            self.assertEqual(
                first.file_paths()["/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"].read_text().strip(),
                "1000000",
            )
            self.assertIn("/sys/class/dmi/id/product_name", first.file_paths())
            self.assertIn(first.hardware.platform, first.file_paths()["/sys/class/dmi/id/product_name"].read_text())

    def test_profile_home_is_persistent_private_and_initially_empty(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            first = ensure_identity(profile, Path(directory))
            self.assertTrue(first.home_dir.is_dir())
            self.assertEqual(first.home_dir.stat().st_mode & 0o777, 0o700)
            marker = first.state_dir / PROFILE_HOME_MARKER
            self.assertEqual(marker.read_text(encoding="ascii"), PROFILE_HOME_MARKER_CONTENT)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(first.home_dir.iterdir()), [])
            (first.home_dir / "created-in-profile").write_text("only this profile", encoding="utf-8")
            second = ensure_identity(profile, Path(directory))
            self.assertEqual((second.home_dir / "created-in-profile").read_text(encoding="utf-8"), "only this profile")


class RootfsTests(unittest.TestCase):
    def test_appimage_magic_and_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.AppImage"
            invalid = b"prefix" + b"hsqs" + (b"not-a-superblock" * 6)
            squashfs_values = (
                b"hsqs", 1, 0, 131072, 0, 1, 17, 0, 1, 4, 0,
            ) + (0, 96, 0, 0, 0, 0, 0, 0)
            valid = struct.pack("<4sIIIIHHHHHHQQQQQQQQ", *squashfs_values)
            payload = invalid + valid + b"payload"
            path.write_bytes(payload)
            info = inspect_appimage(path)
            self.assertEqual(info.squashfs_offset, len(invalid))
            self.assertEqual(info.sha256, hashlib.sha256(payload).hexdigest())
            command = extraction_command(path, Path(directory) / "out", info)
            self.assertIn("-no-xattrs", command)
            self.assertIn(str(len(invalid)), command)


class NetworkTests(unittest.TestCase):
    def test_names_are_scoped(self):
        names = resource_names(7)
        self.assertEqual(names.netns, "appsbx-7")
        self.assertEqual(names.host_veth, "appsbx-h7")
        self.assertEqual(names.nft_table, "appsbx_7")

    def test_subnet_overlap_rejected(self):
        self.assertTrue(subnet_overlaps(build_plan(3).subnet, ["10.200.3.0/24"]))
        with self.assertRaises(NetworkError):
            build_plan(3, host_routes=["10.200.3.0/24"])

    def test_real_plan_has_selected_route_and_fail_closed_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            egress_dir = Path(directory)
            (egress_dir / "wifi.conf").write_text(
                "name=wifi\n"
                "type=interface\n"
                "interface=wlan0\n"
                "gateway=192.0.2.1\n"
                "dns=192.0.2.53,198.51.100.53\n"
                "ipv6=false\n",
                encoding="utf-8",
            )
            plan = build_plan(7, "real", "wifi", egress_dir=egress_dir)
            self.assertEqual(plan.definition.interface, "wlan0")
            self.assertIn(("ip", "rule", "add", "pref", "1014", "from", "10.200.7.0/30", "table", "207"), plan.commands)
            self.assertIn(("ip", "rule", "add", "pref", "1015", "from", "10.200.7.0/30", "unreachable"), plan.commands)
            self.assertIn(("ip", "route", "add", "table", "207", "192.0.2.1/32", "dev", "wlan0"), plan.commands)
            rules = nft_rules(plan)
            self.assertIn('oifname "wlan0" accept', rules)
            self.assertIn('iifname "appsbx-h7" drop', rules)
            self.assertIn('oifname "wlan0" masquerade', rules)
            self.assertIn("priority 90", rules)
            self.assertIn("table ip6 appsbx_7_v6", rules)

    def test_real_dns_is_private_and_never_uses_host_resolver(self):
        with tempfile.TemporaryDirectory() as directory:
            egress_dir = Path(directory)
            (egress_dir / "vpn.conf").write_text(
                "name=vpn\ntype=vpn\ninterface=tun0\n"
                "dns=10.0.0.53\nipv6=false\n",
                encoding="utf-8",
            )
            plan = build_plan(8, "real", "vpn", egress_dir=egress_dir)
            self.assertEqual(dns_resolv_conf(plan.definition), "# appsbx: selected-egress DNS only\nnameserver 10.0.0.53\n")
            path = write_dns_resolv_conf(Path(directory) / "state", plan.definition)
            self.assertEqual(path.read_text(), dns_resolv_conf(plan.definition))
            self.assertNotIn("127.0.0.53", path.read_text())

    def test_real_egress_rejects_ipv6_until_policy_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cell.conf"
            path.write_text(
                "name=cell\ntype=usb\ninterface=wwan0\n"
                "dns=203.0.113.53\nipv6=true\n",
                encoding="utf-8",
            )
            with self.assertRaises(NetworkError):
                load_egress_definition("cell", Path(directory))

    def test_real_mode_requires_explicit_egress(self):
        with self.assertRaises(NetworkError):
            build_plan(1, "real")

    def test_cleanup_is_scoped_to_instance_resources(self):
        from appsbx import network_helper
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            return mock.Mock(stdout="", returncode=0)

        with mock.patch.object(network_helper, "_require_root"), mock.patch.object(network_helper, "_run", side_effect=fake_run):
            self.assertEqual(network_helper.cleanup(SimpleNamespace(profile_id=9)), 0)
        flattened = {item for call in calls for item in call}
        self.assertIn("appsbx_9", flattened)
        self.assertIn("appsbx-h9", flattened)
        self.assertIn("appsbx-9", flattened)
        self.assertNotIn("appsbx_10", flattened)

    def test_privileged_helper_rejects_namespace_and_mount_escalation(self):
        from appsbx import network_helper
        base = ["bwrap", "--die-with-parent", "--unshare-user", "--cap-drop", "ALL", "--clearenv", "--uid", "1000", "--gid", "1000"]
        with self.assertRaises(NetworkError):
            network_helper._check_bwrap_command(base + ["--unshare-net"])
        with self.assertRaises(NetworkError):
            network_helper._check_bwrap_command(base + ["--bind", "/", "/host"])
        with self.assertRaises(NetworkError):
            network_helper._bwrap_ids(base[:1] + ["--die-with-parent", "--unshare-user", "--cap-drop", "ALL", "--clearenv", "--uid", "0", "--gid", "0"])

    def test_privileged_helper_allows_only_marked_private_x11_bind(self):
        from appsbx import network_helper
        with tempfile.TemporaryDirectory() as directory:
            x11 = Path(directory) / "x11"
            x11.mkdir(mode=0o700)
            marker = x11 / network_helper.DISPLAY_MARKER
            marker.write_text(network_helper.DISPLAY_MARKER_CONTENT, encoding="ascii")
            os.chmod(marker, 0o600)
            base = [
                "bwrap", "--die-with-parent", "--unshare-user", "--cap-drop", "ALL", "--clearenv",
                "--uid", "1000", "--gid", "1000",
            ]
            with mock.patch.dict(os.environ, {}, clear=True):
                network_helper._check_bwrap_command(base + ["--bind", str(x11), "/tmp/.X11-unix"])
                with self.assertRaises(NetworkError):
                    network_helper._check_bwrap_command(base + ["--bind", str(x11), "/host"])

    def test_privileged_helper_allows_only_marked_private_profile_home_bind(self):
        from appsbx import network_helper
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "profile"
            state.mkdir(mode=0o700)
            home = state / "home"
            home.mkdir(mode=0o700)
            marker = state / network_helper.PROFILE_HOME_MARKER
            marker.write_text(network_helper.PROFILE_HOME_MARKER_CONTENT, encoding="ascii")
            os.chmod(marker, 0o600)
            base = [
                "bwrap", "--die-with-parent", "--unshare-user", "--cap-drop", "ALL", "--clearenv",
                "--uid", "1000", "--gid", "1000",
            ]
            with mock.patch.dict(os.environ, {}, clear=True):
                network_helper._check_bwrap_command(base + ["--bind", str(home), "/home/appsbx"])
                with self.assertRaises(NetworkError):
                    network_helper._check_bwrap_command(base + ["--bind", str(home), "/home/other"])
            marker.unlink()
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(NetworkError):
                    network_helper._check_bwrap_command(base + ["--bind", str(home), "/home/appsbx"])

    def test_helper_rejects_down_selected_egress(self):
        from appsbx import network_helper
        result = mock.Mock(stdout='[{"operstate":"DOWN"}]')
        with mock.patch.object(network_helper, "_run", return_value=result):
            with self.assertRaises(NetworkError):
                network_helper._interface_is_available("wlan0")

    def test_namespace_sysctl_uses_absolute_helper_path(self):
        from appsbx import network_helper
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            return mock.Mock(stdout="", returncode=0)

        with mock.patch.object(network_helper, "shutil_which", return_value="/usr/sbin/sysctl"):
            with mock.patch.object(network_helper, "_run", side_effect=fake_run):
                network_helper._sysctl_namespace("appsbx-1", "net.ipv6.conf.all.disable_ipv6", "1")
        self.assertEqual(
            calls,
            [("ip", "netns", "exec", "appsbx-1", "/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1")],
        )

    def test_namespace_child_drops_groups_before_application(self):
        from appsbx import network_helper
        with mock.patch.object(
            network_helper,
            "shutil_which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ):
            command = network_helper._child_command("appsbx-1", 1000, 1000, ["/usr/bin/bwrap", "--die-with-parent"])
        self.assertEqual(command[:4], ["/usr/bin/nsenter", "--net=/run/netns/appsbx-1", "--", "/usr/bin/setpriv"])
        self.assertIn("--reuid", command)
        self.assertIn("--regid", command)
        self.assertIn("--clear-groups", command)
        self.assertNotIn("--setuid", command)
        self.assertNotIn("--setgid", command)

    def test_docker_user_rules_preserve_selected_egress_and_fail_closed_drop(self):
        from appsbx import network_helper
        names = resource_names(9)
        rules = network_helper._docker_user_rule_specs(
            9,
            names,
            __import__("ipaddress").ip_network("10.200.9.0/30"),
            "wlan0",
        )
        self.assertEqual(
            rules[0],
            ("-i", "appsbx-h9", "-s", "10.200.9.0/30", "-o", "wlan0",
             "-m", "comment", "--comment", "appsbx:9:out", "-j", "ACCEPT"),
        )
        self.assertIn("ESTABLISHED,RELATED", rules[1])
        self.assertEqual(rules[2], ("-i", "appsbx-h9", "-m", "comment", "--comment", "appsbx:9:drop", "-j", "DROP"))

    def test_docker_cleanup_removes_only_tagged_profile_rules(self):
        from appsbx import network_helper
        calls = []
        listed = (
            "-N DOCKER-USER\n"
            "-A DOCKER-USER -i appsbx-h9 -m comment --comment appsbx:9:drop -j DROP\n"
            "-A DOCKER-USER -i appsbx-h10 -m comment --comment appsbx:10:drop -j DROP\n"
        )

        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            if "-S" in argv:
                return mock.Mock(stdout=listed, returncode=0)
            return mock.Mock(stdout="", returncode=0)

        with mock.patch.object(network_helper, "shutil_which", return_value="/usr/sbin/iptables"):
            with mock.patch.object(network_helper, "_run", side_effect=fake_run):
                network_helper._remove_docker_user_rules(9)
        deleted = [call for call in calls if "-D" in call]
        self.assertEqual(len(deleted), 1)
        self.assertIn("appsbx:9:drop", deleted[0])
        self.assertNotIn("appsbx:10:drop", deleted[0])


class RuntimeTests(unittest.TestCase):
    def test_stub_and_real_network_modes_are_distinct(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            os.chmod(app_root / "zaap", 0o755)
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state)
            stub = prepare_plan(profile, identity, app_root, ["/opt/app/zaap"], "stub", bundle)
            real = prepare_plan(profile, identity, app_root, ["/opt/app/zaap"], "real", bundle)
            self.assertIn("--unshare-net", stub.argv)
            self.assertIn("/dev/shm", stub.argv)
            self.assertNotIn("--unshare-net", real.argv)
            self.assertIn("--ro-bind", stub.argv)
            self.assertNotIn("--ro-bind-data", stub.argv)
            self.assertEqual(stub.pass_fds, ())
            self.assertEqual(len(stub.identity_files), 45)
            self.assertIn("--setenv", stub.argv)
            self.assertIn("FONTCONFIG_FILE", stub.argv)
            self.assertIn("ALSA_CONFIG_PATH", stub.argv)
            self.assertIn("DBUS_SESSION_BUS_ADDRESS", stub.argv)
            self.assertIn(("--bind", str(identity.home_dir), "/home/appsbx"), zip(stub.argv, stub.argv[1:], stub.argv[2:]))
            self.assertTrue(any(item.startswith(str(bundle.root) + "/") for item in stub.argv))
            self.assertTrue((bundle.root / "usr").is_dir() or (bundle.root / "lib").is_dir())
            self.assertTrue((bundle.root / "etc" / "appsbx-fonts.conf").is_file())
            for candidate in bundle.root.rglob("*"):
                if candidate.is_symlink():
                    self.assertTrue(candidate.exists(), f"broken staged symlink: {candidate.name}")
            with self.assertRaises(ValueError):
                from appsbx.runtime import execute
                execute(real)

    def test_identity_files_are_direct_binds_without_inherited_fds(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state)
            plan = prepare_plan(profile, identity, app_root, ["/opt/app/zaap"], "real", bundle)
            self.assertEqual(plan.pass_fds, ())
            self.assertEqual(len(plan.identity_files), 45)
            for destination, source in plan.identity_files.items():
                self.assertIn(("--ro-bind", str(source), destination), zip(
                    plan.argv, plan.argv[1:], plan.argv[2:]
                ))

    def test_runtime_bundle_stages_nss_modules_loaded_at_runtime(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            os.chmod(app_root / "zaap", 0o755)
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state)
            for library in (
                "libsoftokn3.so", "libfreebl3.so", "libfreeblpriv3.so",
                "libnssdbm3.so", "libnssckbi.so",
            ):
                self.assertTrue(any(path.name == library for path in bundle.root.rglob(library)), library)

    def test_runtime_bundle_contains_profile_controlled_synthetic_df(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            os.chmod(app_root / "zaap", 0o755)
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state, synthetic_disk_mb=51200)
            helper = bundle.root / "usr" / "bin" / "df"
            self.assertTrue(helper.is_file())
            self.assertTrue(os.access(helper, os.X_OK))
            self.assertIn("appsbxfs 52428800 0 52428800 0% /home/appsbx", helper.read_text())

    def test_runtime_bundle_contains_private_null_alsa_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            os.chmod(app_root / "zaap", 0o755)
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state)
            alsa = bundle.root / "etc" / "appsbx-alsa.conf"
            self.assertTrue(alsa.is_file())
            self.assertIn("type null", alsa.read_text(encoding="utf-8"))
            self.assertNotIn("/usr/share/alsa", alsa.read_text(encoding="utf-8"))

    def test_private_xdg_open_is_web_only_and_never_delegates_to_host_desktop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            browser = Path(directory) / "browser"
            browser.write_text("placeholder", encoding="ascii")
            helper = _write_private_xdg_open(root, browser)
            body = helper.read_text(encoding="utf-8")
            self.assertTrue(os.access(helper, os.X_OK))
            self.assertIn("http://*|https://*", body)
            self.assertIn("blocked non-web URL", body)
            self.assertIn("--password-store=basic", body)
            self.assertIn("--disable-setuid-sandbox", body)
            self.assertNotIn("gio open", body)
            self.assertNotIn("/usr/bin/xdg-open", body)
            self.assertNotIn("--no-sandbox", body)

    def test_synthetic_df_rejects_invalid_capacity(self):
        with self.assertRaises(ELFError):
            synthetic_df_script(1023)

    def test_xvfb_mode_is_fail_closed_without_a_staged_server(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state)
            with self.assertRaises(ValueError):
                prepare_plan(profile, identity, app_root, ["/opt/app/zaap"], "stub", bundle, "xvfb")

    def test_incomplete_xvfb_cache_is_rejected(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state, "xvfb")
            helper = bundle.root / "usr" / "bin" / "appsbx-xvfb-exec"
            self.assertTrue(helper.is_file())
            helper.unlink()
            with self.assertRaises(ELFError):
                prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state, "xvfb")

    def test_xvfb_plan_uses_only_private_display_environment(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state)
            script = bundle.root / "usr" / "bin" / "appsbx-xvfb-exec"
            script.write_text("#!/bin/sh\n", encoding="utf-8")
            display_bundle = RuntimeBundle(bundle.root, bundle.entrypoint, bundle.staged_libraries, script)
            plan = prepare_plan(
                profile, identity, app_root, ["/opt/app/zaap"], "stub", display_bundle, "xvfb",
            )
            self.assertIn(("--setenv", "DISPLAY", ":99"), zip(plan.argv, plan.argv[1:], plan.argv[2:]))
            self.assertIn(("--setenv", "LIBGL_ALWAYS_SOFTWARE", "1"), zip(plan.argv, plan.argv[1:], plan.argv[2:]))
            self.assertIn(("--setenv", "GSETTINGS_BACKEND", "memory"), zip(plan.argv, plan.argv[1:], plan.argv[2:]))
            self.assertIn(("--setenv", "GIO_USE_VFS", "local"), zip(plan.argv, plan.argv[1:], plan.argv[2:]))
            self.assertIn(("--setenv", "XDG_RUNTIME_DIR", "/run/appsbx"), zip(plan.argv, plan.argv[1:], plan.argv[2:]))
            self.assertIn(("--dir", "/run/appsbx"), zip(plan.argv, plan.argv[1:]))
            self.assertIn("/usr/bin/appsbx-xvfb-exec", plan.argv)
            self.assertNotIn("/tmp/.X11-unix", plan.argv)
            self.assertIn(("--uid", str(identity.runtime_uid)), zip(plan.argv, plan.argv[1:]))
            self.assertIn(("--gid", str(identity.runtime_gid)), zip(plan.argv, plan.argv[1:]))
            self.assertNotIn("--cap-add", plan.argv)

    def test_vnc_plan_binds_only_private_x_socket_and_bridge_is_offline(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            display = create_private_display(identity.state_dir)
            validate_private_display(display, identity.state_dir)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            os.chmod(app_root / "zaap", 0o755)
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state, "xvfb")
            plan = prepare_plan(
                profile, identity, app_root, ["/opt/app/zaap"], "stub", bundle, "xvfb",
                display_socket_dir=display.x11_dir, display_number=display.display_number,
            )
            self.assertIn(("--bind", str(display.x11_dir), "/tmp/.X11-unix"), zip(
                plan.argv, plan.argv[1:], plan.argv[2:],
            ))
            self.assertIn(("--setenv", "DISPLAY", display.display_name), zip(plan.argv, plan.argv[1:], plan.argv[2:]))
            vnc_root = Path(directory) / "vnc"
            (vnc_root / "usr/bin").mkdir(parents=True)
            server = vnc_root / "usr/bin/x11vnc"
            server.write_text("placeholder", encoding="ascii")
            bridge = build_vnc_bridge_command(
                VNCBundle(vnc_root, server, 0), display.x11_dir, display.display_number,
                identity.runtime_uid, identity.runtime_gid,
            )
            self.assertIn("--unshare-net", bridge)
            self.assertIn(("--ro-bind", str(display.x11_dir), "/tmp/.X11-unix"), zip(
                bridge, bridge[1:], bridge[2:],
            ))
            self.assertNotIn(str(app_root), bridge)

    def test_vnc_controller_is_loopback_only_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            display = create_private_display(state)
            service = LocalVNCService(display, state, ["/bin/cat"], viewer_command_factory=lambda port: ["/bin/true"])
            service.start()
            port = service.port
            self.assertEqual(service.endpoint, f"127.0.0.1::{port}")
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"rfb-test")
                self.assertEqual(client.recv(8), b"rfb-test")
            service.stop()
            self.assertFalse(display.root.exists())
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.2)

    def test_display_allocator_removes_a_dead_controller_session(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            stale = state / "displays" / "run-stale"
            stale.mkdir(parents=True, mode=0o700)
            (stale / SESSION_MARKER).write_text(DISPLAY_MARKER_CONTENT, encoding="ascii")
            os.chmod(stale / SESSION_MARKER, 0o600)
            (stale / OWNER_FILE).write_text(json.dumps({"pid": 999_999_999}) + "\n", encoding="ascii")
            os.chmod(stale / OWNER_FILE, 0o600)
            display = create_private_display(state)
            self.assertFalse(stale.exists())
            self.assertTrue(display.x11_dir.is_dir())

    def test_vnc_support_fails_closed_when_server_or_viewer_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("appsbx.elf.shutil.which", return_value=None):
                with self.assertRaises(ELFError):
                    prepare_vnc_bundle(Path(directory))
            with mock.patch("appsbx.display.shutil.which", return_value=None):
                with self.assertRaises(ValueError):
                    vnc_viewer_command(5900)

    @unittest.skipUnless(Path("/usr/bin/Xvfb").is_file(), "Xvfb is not installed")
    def test_xvfb_bundle_contains_private_keyboard_data(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/zaap"], state, "xvfb")
            self.assertEqual(bundle.display_script, bundle.root / "usr/bin/appsbx-xvfb-exec")
            self.assertTrue(bundle.display_script.is_file())
            self.assertTrue((bundle.root / "usr/share/X11/xkb/rules/evdev").is_file())
            self.assertTrue((bundle.root / "usr/share/X11/locale/locale.dir").is_file())
            self.assertTrue((bundle.root / "usr/share/glib-2.0/schemas/gschemas.compiled").is_file())
            self.assertTrue((bundle.root / "usr/share/locale/locale.alias").is_file())
            if Path("/usr/share/fonts/truetype/dejavu").is_dir():
                self.assertTrue((bundle.root / "usr/share/fonts/truetype/dejavu/DejaVuSans.ttf").is_file())
            self.assertFalse((bundle.root / "usr/share/locale/locale.alias").is_symlink())
            self.assertTrue((bundle.root / "usr/bin/xdg-settings").is_file())
            self.assertTrue((bundle.root / "bin/sh").is_file() or (bundle.root / "usr/bin/sh").is_file())
            self.assertTrue((bundle.root / "usr/bin/xkbcomp").is_file())
            self.assertTrue(any(bundle.root.glob("lib/*/libX11-xcb.so.1")))
            self.assertTrue(any(bundle.root.glob("lib/*/libudev.so.1")))
            helper = (bundle.root / "usr/bin/appsbx-xvfb-exec").read_text(encoding="utf-8")
            self.assertIn("--nnp", helper)
            self.assertNotIn("--reuid=", helper)
            self.assertNotIn("--regid=", helper)
            self.assertNotIn("--clear-groups", helper)

    @unittest.skipUnless(Path("/usr/bin/Xvfb").is_file(), "Xvfb is not installed")
    def test_xvfb_runs_with_a_per_run_host_private_socket_directory(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/true", app_root / "zaap")
            os.chmod(app_root / "zaap", 0o755)
            display = create_private_display(identity.state_dir)
            try:
                bundle = prepare_runtime_bundle(
                    app_root, ["/opt/app/zaap"], identity.state_dir, "xvfb", profile.synthetic_disk_mb,
                )
                plan = prepare_plan(
                    profile, identity, app_root, ["/opt/app/zaap"], "stub", bundle, "xvfb",
                    display_socket_dir=display.x11_dir, display_number=display.display_number,
                )
                self.assertEqual(execute(plan), 0)
            finally:
                from appsbx.display import remove_private_display
                remove_private_display(display, identity.state_dir)
            self.assertFalse(display.root.exists())

    def test_stub_runtime_persists_only_the_private_profile_home(self):
        profile = load_profile(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            identity = ensure_identity(profile, state)
            app_root = Path(directory) / "app"
            app_root.mkdir()
            shutil.copy2("/bin/sh", app_root / "write-home")
            os.chmod(app_root / "write-home", 0o755)
            bundle = prepare_runtime_bundle(app_root, ["/opt/app/write-home"], state)
            plan = prepare_plan(
                profile, identity, app_root,
                ["/opt/app/write-home", "-c", ": > \"$HOME/persisted-by-sandbox\""],
                "stub", bundle,
            )
            self.assertEqual(execute(plan), 0)
            self.assertTrue((identity.home_dir / "persisted-by-sandbox").is_file())


class ProbeTests(unittest.TestCase):
    def test_report_contains_categories_only(self):
        categories = leak_categories({"hostname": {"host.example"}}, {"hostname": "host.example"})
        output = category_report(categories)
        self.assertEqual(output, ["LEAK: hostname"])
        self.assertNotIn("host.example", output[0])

    def test_probe_tolerates_denied_interface_enumeration(self):
        observations = current_observations()
        self.assertIn("interfaces", observations)
        self.assertIsInstance(host_denylist(), dict)


class LifecycleTests(unittest.TestCase):
    def test_profile_lock_rejects_concurrent_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            with profile_lock(state):
                with self.assertRaises(LockBusy):
                    with profile_lock(state):
                        pass

    def test_egress_change_is_fail_closed_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            record_egress(state, "stub")
            with self.assertRaises(StateError):
                require_egress_consistency(state, "vpn")
            require_egress_consistency(state, "vpn", force=True)
            record_egress(state, "vpn")
            self.assertEqual((state / "last-egress").read_text().strip(), "vpn")


if __name__ == "__main__":
    unittest.main()
