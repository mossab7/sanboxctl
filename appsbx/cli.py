"""Command-line frontend for the unprivileged Phase 1 components."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys

from .capabilities import capability_dicts
from .display import LocalVNCService, create_private_display, remove_private_display, validate_private_display, vnc_viewer_command
from .elf import ELFError, prepare_runtime_bundle, prepare_vnc_bundle
from .identity import create_auto_identity, ensure_identity, identity_report, load_identity_for_inspection
from .host_display import HostDisplayError, detect_host_display
from .gpu import GpuError, detect_hardware_gpu
from .instances import instance_app_root
from .locking import profile_lock
from .network import (
    StubNetworkBackend, build_plan, discover_dynamic_egresses, load_egress_definition,
    resource_names, write_dns_resolv_conf,
)
from .paths import PROJECT_ROOT, state_root
from .profile import NAME_RE, ProfileError, load_profiles
from .probe import category_report, current_observations, host_denylist, leak_categories
from .rootfs import inspect_appimage
from .runtime import build_vnc_bridge_command, prepare_plan
from .state import record_egress, require_egress_consistency


PROFILES = PROJECT_ROOT / "profiles"
STATE = state_root()


def _gpu_flags(mode: str) -> list[str]:
    """Return optional Chromium flags; auto mode deliberately adds none."""
    if mode == "auto":
        return []
    if mode == "software":
        return [
            "--disable-gpu", "--disable-gpu-rasterization",
            "--disable-gpu-compositing", "--disable-gpu-vsync",
            "--disable-accelerated-2d-canvas",
        ]
    if mode == "hardware":
        # Desktop GL is the compatible path for this packaged X11-era
        # Electron build.  Refuse Chromium's silent SwiftShader fallback;
        # hardware mode must either initialize the selected render node or
        # surface a GPU startup failure for diagnosis.
        return [
            "--use-gl=desktop", "--enable-gpu-rasterization",
            "--disable-software-rasterizer",
        ]
    raise ProfileError(f"unsupported GPU mode: {mode}")


def _sandbox_compatibility_flags() -> list[str]:
    """Return flags required by the intentionally device-less audio policy."""
    # The sandbox deliberately provides no host /dev/snd, PipeWire, PulseAudio
    # socket, or microphone.  Chromium otherwise drives the ALSA null sink as
    # fast as possible, creating an expensive audio busy-loop with no audible
    # output.  Disable that unavailable feature instead of exposing host audio.
    return ["--disable-audio-output"]


def _profiles():
    return load_profiles(PROFILES)


def _profile(name: str):
    profiles = _profiles()
    if name not in profiles:
        raise ProfileError(f"unknown profile: {name}")
    return profiles[name]


def _instance_profile(profile, instance_id: int | None):
    """Derive independent state/resource names for an explicit instance ID."""
    if instance_id is None or instance_id == profile.profile_id:
        return profile
    if not 0 <= instance_id <= 253:
        raise ProfileError("--instance-id must be in [0, 253]")
    suffix = f"-i{instance_id}"
    if len(profile.name) + len(suffix) > 32:
        raise ProfileError("profile name is too long for an instance suffix")
    return replace(profile, name=profile.name + suffix, profile_id=instance_id)


def _named_instance_profile(profile, instance_id: int | None, profile_name: str | None):
    profile = _instance_profile(profile, instance_id)
    if profile_name is None:
        return profile
    # GUI-managed identities live outside profiles/. Preserve the base
    # profile's runtime policy while using the exact safe name recorded in
    # that identity, rather than reconstructing example-i<ID>.
    if not NAME_RE.fullmatch(profile_name):
        raise ProfileError("--profile-name is invalid")
    return replace(profile, name=profile_name)


def cmd_profile(args: argparse.Namespace) -> int:
    profiles = _profiles()
    if args.action == "list":
        for name, profile in profiles.items():
            print(f"{name}\tid={profile.profile_id}\tegress={profile.default_egress or '-'}")
        return 0
    profile = _profile(args.name)
    print(f"valid: {profile.name} id={profile.profile_id}")
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    profile = _profile(args.name)
    if args.action == "inspect":
        identity = load_identity_for_inspection(profile, Path(args.state_dir) if args.state_dir else STATE / profile.name)
        print(json.dumps(identity_report(identity), sort_keys=True, indent=2))
        return 0
    identity = ensure_identity(profile, STATE)
    print(json.dumps({
        "profile": identity.profile_name,
        "status": "ready",
        "hostname": identity.hostname,
        "mac": identity.mac,
        "cpu_count": identity.cpu_count,
        "ram_mb": identity.ram_mb,
        "state": "persistent-profile-state",
    }, sort_keys=True))
    return 0


def cmd_rootfs(args: argparse.Namespace) -> int:
    info = inspect_appimage(Path(args.appimage))
    print(json.dumps({"status": "inspected", "size": info.size, "sha256": info.sha256, "squashfs_offset": info.squashfs_offset}, sort_keys=True))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    profile = _profile(args.profile)
    if args.instance_id is not None and args.instance_id != profile.profile_id:
        conflict = next((item.name for item in _profiles().values() if item.profile_id == args.instance_id), None)
        if conflict is not None:
            raise ProfileError(f"--instance-id {args.instance_id} conflicts with configured profile {conflict}")
    profile = _named_instance_profile(profile, args.instance_id, args.profile_name)
    if args.identity_dir:
        try:
            identity_dir = Path(args.identity_dir).resolve(strict=True)
            identity_dir.relative_to(STATE.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ProfileError("--identity-dir must be an existing directory inside sandbox-state") from exc
        identity = load_identity_for_inspection(profile, identity_dir)
    elif args.identity == "auto":
        identity = create_auto_identity(profile, STATE, args.hardware_class or "random")
    else:
        if args.hardware_class is not None:
            raise ProfileError("--hardware-class requires --identity auto")
        identity = ensure_identity(profile, STATE)
    app_root = instance_app_root(args.app_root)
    egress_name = args.egress or profile.default_egress
    if args.mode == "real" and (not args.egress or egress_name == "stub"):
        # The GUI already discovers live interfaces. Keep the CLI convenient
        # without making an unsafe choice on a multi-homed host: automatic
        # selection is allowed only when exactly one interface has a usable
        # IPv4 address, default route, and per-link DNS source.
        discovered = discover_dynamic_egresses()
        if len(discovered) == 1:
            egress_name = discovered[0].name
        elif not discovered:
            raise ProfileError("no live egress interface was detected; use --egress NAME")
        else:
            names = ", ".join(item.name for item in discovered)
            raise ProfileError(f"multiple live egress interfaces detected ({names}); use --egress NAME")
    plan = build_plan(profile.profile_id, args.mode, egress_name)
    state_scope = identity.state_dir
    require_egress_consistency(state_scope, plan.egress, args.force_egress)
    definition = plan.definition
    profile_log = {
        "profile": profile.name,
        "hardware_class": identity.hardware.hardware_class,
        "cpu_brand": identity.hardware.cpu_model,
        "cpu_vendor": identity.hardware.cpu_vendor,
        "logical_cpus": identity.cpu_count,
        "ram_mb": identity.ram_mb,
        "network_mode": plan.mode,
        "egress": plan.egress,
        "interface": definition.interface if definition is not None else None,
        "gpu_mode": args.gpu_mode,
    }
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise ProfileError("run requires -- followed by an application command")
    command.extend(_gpu_flags(args.gpu_mode))
    command.extend(_sandbox_compatibility_flags())
    resolv_conf = None
    if plan.definition is not None:
        # The helper receives DNS addresses as arguments, while Bubblewrap
        # receives this private file. No host /etc/resolv.conf is mounted.
        resolv_conf = write_dns_resolv_conf(identity.state_dir, plan.definition)
    display_backend = "xvfb" if args.display == "xvfb-vnc" else args.display
    gpu_info = None
    if args.gpu_mode == "hardware":
        if display_backend != "host":
            raise ProfileError("--gpu-mode hardware requires --display host")
        try:
            gpu_info = detect_hardware_gpu()
        except GpuError as exc:
            raise ProfileError(str(exc)) from exc
    if gpu_info is not None:
        profile_log.update({
            "gpu_render_node": str(gpu_info.render_node),
            "gpu_kernel_driver": gpu_info.kernel_driver,
            "gpu_mesa_driver": gpu_info.mesa_driver,
        })
    print("[APPSBX PROFILE] " + json.dumps(profile_log, sort_keys=True), flush=True)
    host_display = None
    if display_backend == "host":
        try:
            host_display = detect_host_display()
        except HostDisplayError as exc:
            raise ProfileError(str(exc)) from exc
    url_broker = args.url_broker
    if url_broker == "auto":
        url_broker = "browser" if display_backend == "xvfb" else "off"
    if url_broker == "browser" and display_backend not in {"xvfb", "host"}:
        raise ProfileError("--url-broker browser requires --display host, xvfb, or xvfb-vnc")
    runtime_bundle = prepare_runtime_bundle(
        app_root, command, identity.state_dir, display_backend,
        identity.hardware.disk_size_mb, url_broker == "browser",
        gpu_info,
    )
    private_display = None
    vnc_service = None
    try:
        if args.display == "xvfb-vnc" and args.execute:
            # Check both external presentation programs before starting the
            # target. The server is staged into a separate private runtime;
            # the viewer remains a normal host-desktop client.
            vnc_bundle = prepare_vnc_bundle(identity.state_dir)
            vnc_viewer_command(5900)
            private_display = create_private_display(identity.state_dir)
            validate_private_display(private_display, identity.state_dir)
        runtime = prepare_plan(
            profile, identity, app_root, command, args.mode, runtime_bundle, display_backend,
            network_plan=plan, resolv_conf=resolv_conf,
            display_socket_dir=private_display.x11_dir if private_display else None,
            display_number=private_display.display_number if private_display else 99,
            host_display=host_display,
            gpu_mode=args.gpu_mode, gpu_info=gpu_info,
        )
        if private_display is not None:
            bridge = build_vnc_bridge_command(
                vnc_bundle, private_display.x11_dir, private_display.display_number,
                identity.runtime_uid, identity.runtime_gid,
            )
            vnc_service = LocalVNCService(private_display, identity.state_dir, bridge)
    except Exception:
        if private_display is not None:
            remove_private_display(private_display, identity.state_dir)
        raise
    if args.execute:
        from .runtime import execute
        with profile_lock(state_scope):
            record_egress(state_scope, plan.egress)
            return execute(runtime, vnc_service)
    safe_argv = [
        "<app-root>" if item == str(app_root) else
        ("<identity-state>" if str(STATE) in item else item)
        for item in runtime.argv
    ]
    print(json.dumps({
        "status": "dry-run",
        "network": {"mode": plan.mode, "subnet": str(plan.subnet), "netns": plan.names.netns},
        "display": {"backend": args.display, "vnc": args.display == "xvfb-vnc",
                    "host_session": host_display.backend if host_display else None},
        "url_broker": url_broker,
        "identity": identity_report(identity),
        "runtime": safe_argv,
    }, sort_keys=True))
    return 0


def cmd_network(args: argparse.Namespace) -> int:
    names = resource_names(args.id)
    if args.action == "up":
        result = StubNetworkBackend().up(args.id)
    elif args.action == "down":
        result = StubNetworkBackend().down(args.id)
    elif args.action == "status":
        result = StubNetworkBackend().status(args.id)
    elif args.action == "gc":
        result = {"status": "stub-only", "removed": [], "prefix": "appsbx-"}
    else:
        result = {"status": "stub-only", "netns": names.netns}
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    categories = leak_categories(host_denylist(), current_observations())
    for line in category_report(categories):
        print(line)
    if not categories:
        print("OK: no matched host values")
    return 1 if categories else 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    print(json.dumps(capability_dicts(), sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sandboxctl")
    sub = p.add_subparsers(dest="command", required=True)

    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="action", required=True)
    profile_sub.add_parser("list")
    validate = profile_sub.add_parser("validate")
    validate.add_argument("name")
    profile.set_defaults(func=cmd_profile)

    identity = sub.add_parser("identity")
    identity.add_argument("action", choices=["ensure", "inspect"])
    identity.add_argument("name")
    identity.add_argument("--state-dir", help="identity directory to inspect, including an automatic profile")
    identity.set_defaults(func=cmd_identity)

    rootfs = sub.add_parser("rootfs")
    rootfs.add_argument("action", choices=["inspect"])
    rootfs.add_argument("appimage")
    rootfs.set_defaults(func=cmd_rootfs)

    run = sub.add_parser("run")
    run.add_argument("--profile", required=True)
    run.add_argument("--profile-name", help=argparse.SUPPRESS)
    run.add_argument(
        "--instance-id", type=int,
        help="independent per-instance resource ID (0-253; use a unique value for concurrent runs)",
    )
    run.add_argument("--mode", choices=["stub", "real"], default="stub")
    run.add_argument(
        "--identity", choices=["persistent", "auto"], default="persistent",
        help="use the configured persistent identity or generate a fresh per-launch identity",
    )
    run.add_argument(
        "--identity-dir",
        help=argparse.SUPPRESS,
    )
    run.add_argument(
        "--hardware-class", choices=["laptop", "desktop", "gaming-desktop", "workstation", "random"],
        help="compatible hardware family for --identity auto",
    )
    run.add_argument("--egress")
    run.add_argument(
        "--app-root",
        help="override the bundled apps/zaap.AppDir (must contain an executable zaap)",
    )
    run.add_argument(
        "--display", choices=["none", "xvfb", "xvfb-vnc", "host"], default="none",
        help="use private Xvfb, loopback VNC, or explicitly expose host display sockets",
    )
    run.add_argument(
        "--url-broker", choices=["auto", "browser", "off"], default="auto",
        help="private HTTP(S) browser broker (auto enables it only with private Xvfb)",
    )
    run.add_argument(
        "--gpu-mode", choices=["auto", "software", "hardware"], default="auto",
        help="Electron rendering mode; hardware exposes only one DRM render node",
    )
    run.add_argument("--execute", action="store_true")
    run.add_argument("--force-egress", action="store_true")
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    net = sub.add_parser("net")
    net.add_argument("action", choices=["up", "down", "status", "gc"])
    net.add_argument("id", type=int, nargs="?", default=0)
    net.set_defaults(func=cmd_network)

    probe = sub.add_parser("probe")
    probe.set_defaults(func=cmd_probe)
    capabilities = sub.add_parser("capabilities")
    capabilities.set_defaults(func=cmd_capabilities)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        return int(args.func(args))
    except (ELFError, ProfileError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
