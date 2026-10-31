"""Portable installer and read-only host diagnostics for appsbx.

This module deliberately does not change sandbox policy.  It prepares a
per-user copy and Python environment, then offers an explicit, auditable
privileged step for the already-restricted real-network helper.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
from typing import Iterable

from .capabilities import capability_dicts
from .app_store import ApplicationStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_RELATIVE = Path("apps/zaap.AppDir")
HELPER_DESTINATION = Path("/usr/libexec/appsbx-net-helper")
HELPER_NETWORK_DESTINATION = Path("/usr/libexec/network.py")
MIN_PYTHON = (3, 10)
INSTALL_MARKER = ".appsbx-install"
STATE_MARKER = ".appsbx-state"
LAUNCHER_MARKER = "# Managed by appsbx installer\n"


@dataclass(frozen=True)
class Host:
    distribution: str
    version: str
    architecture: str
    package_manager: str | None
    python: str
    supported_payload: bool


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


PACKAGE_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "apt": {
        "core": ("python3", "python3-venv", "python3-pip", "bubblewrap", "iproute2", "nftables", "util-linux", "policykit-1"),
        "network": ("iptables", "network-manager"),
        "display": ("xvfb", "x11vnc", "tigervnc-viewer", "x11-xkb-utils"),
        "gpu": ("mesa-utils", "libgl1-mesa-dri", "libegl1", "libdrm2"),
    },
    "dnf": {
        "core": ("python3", "bubblewrap", "iproute", "nftables", "util-linux", "polkit"),
        "network": ("iptables-nft", "NetworkManager"),
        "display": ("xorg-x11-server-Xvfb", "x11vnc", "tigervnc"),
        "gpu": ("mesa-dri-drivers", "mesa-libGL", "mesa-libEGL", "libdrm"),
    },
    "pacman": {
        "core": ("python", "bubblewrap", "iproute2", "nftables", "util-linux", "polkit"),
        "network": ("iptables-nft", "networkmanager"),
        "display": ("xorg-server-xvfb", "x11vnc", "tigervnc"),
        "gpu": ("mesa", "libglvnd", "libdrm"),
    },
    "zypper": {
        "core": ("python311", "bubblewrap", "iproute2", "nftables", "util-linux", "polkit"),
        "network": ("iptables", "NetworkManager"),
        "display": ("xorg-x11-server", "x11vnc", "tigervnc"),
        "gpu": ("Mesa-dri", "Mesa-libGL1", "libdrm2"),
    },
}


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def detect_package_manager(which=shutil.which) -> str | None:
    for name, executable in (("apt", "apt-get"), ("dnf", "dnf"), ("pacman", "pacman"), ("zypper", "zypper")):
        if which(executable):
            return name
    return None


def detect_host(*, os_release: Path = Path("/etc/os-release"), which=shutil.which) -> Host:
    release = _os_release(os_release)
    architecture = platform.machine().lower()
    return Host(
        distribution=release.get("PRETTY_NAME", release.get("ID", "unknown Linux")),
        version=release.get("VERSION_ID", "unknown"),
        architecture=architecture,
        package_manager=detect_package_manager(which),
        python=".".join(map(str, sys.version_info[:3])),
        supported_payload=architecture in {"x86_64", "amd64"},
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_payload(root: Path) -> Check:
    executable = root / APP_RELATIVE / "zaap"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        return Check("bundled-app", "error", f"Zaap executable is missing or not executable: {executable}")
    try:
        with executable.open("rb") as handle:
            header = handle.read(5)
    except OSError as exc:
        return Check("bundled-app", "error", str(exc))
    if header[:4] != b"\x7fELF" or header[4] != 2:
        return Check("bundled-app", "error", "bundled Zaap payload is not a 64-bit ELF executable")
    return Check("bundled-app", "ok", f"x86-64 payload present; sha256={_sha256(executable)}")


def diagnostics(root: Path = PROJECT_ROOT) -> tuple[Host, list[Check]]:
    host = detect_host()
    checks: list[Check] = [
        Check("architecture", "ok" if host.supported_payload else "error",
              "bundled Zaap is x86-64" if host.supported_payload else f"unsupported architecture: {host.architecture}"),
        Check("python", "ok" if sys.version_info >= MIN_PYTHON else "error",
              f"requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+; found {host.python}"),
        Check("package-manager", "ok" if host.package_manager else "warning",
              host.package_manager or "no supported package manager detected"),
        validate_payload(root),
    ]
    for item in capability_dicts():
        if item["name"] in {"bwrap", "ip", "nft", "nsenter", "setpriv", "Xvfb", "x11vnc", "vncviewer", "google-chrome"}:
            checks.append(Check(f"tool:{item['name']}", "ok" if item["available"] else "warning", str(item["detail"])))
    render_nodes = sorted(Path("/dev/dri").glob("renderD*"))
    checks.append(Check("gpu-render-node", "ok" if render_nodes else "warning",
                        ", ".join(map(str, render_nodes)) or "no hardware GPU render node found; software mode remains available"))
    return host, checks


def package_plan(manager: str | None, *, include_optional: bool = True) -> list[str]:
    if manager not in PACKAGE_MAP:
        return []
    groups = ("core", "network", "display", "gpu") if include_optional else ("core",)
    return [package for group in groups for package in PACKAGE_MAP[manager][group]]


def package_command(manager: str, packages: Iterable[str]) -> list[str]:
    values = list(packages)
    if manager == "apt":
        return ["sudo", "apt-get", "install", "--yes", *values]
    if manager == "dnf":
        return ["sudo", "dnf", "install", "--assumeyes", *values]
    if manager == "pacman":
        return ["sudo", "pacman", "-S", "--needed", "--noconfirm", *values]
    if manager == "zypper":
        return ["sudo", "zypper", "--non-interactive", "install", *values]
    raise ValueError("unsupported package manager")


def default_data_dir() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "appsbx"


def default_state_dir() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "appsbx"


def _copy_ignore(_directory: str, names: list[str]) -> set[str]:
    ignored = {".git", ".venv", "my_pyside_env", "pyside-setup", "sandbox-state", "dist", "__pycache__"}
    return {name for name in names if name in ignored or name.endswith((".pyc", ".log", ".txt")) and name.startswith(("gui-", "hardware", "software"))}


def install_user_copy(source: Path, destination: Path, state_dir: Path, *, replace: bool = False,
                      allow_missing_payload: bool = False) -> None:
    if destination.exists():
        if not replace:
            raise ValueError(f"installation already exists: {destination}; use --update")
        marker = destination / INSTALL_MARKER
        if marker.read_text(encoding="ascii") != "appsbx installed application\n":
            raise ValueError("refusing to replace a directory not installed by appsbx")
        backup = destination.with_name(destination.name + ".previous")
        if backup.exists():
            backup_marker = backup / INSTALL_MARKER
            if backup_marker.is_file() and backup_marker.read_text(encoding="ascii") == "appsbx installed application\n":
                shutil.rmtree(backup)
            else:
                raise ValueError(f"refusing to remove unexpected previous installation: {backup}")
        destination.replace(backup)
    staging = destination.with_name(destination.name + ".new")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(source, staging, symlinks=True, ignore=_copy_ignore)
    payload = validate_payload(staging)
    if payload.status != "ok" and not allow_missing_payload:
        shutil.rmtree(staging)
        raise ValueError(payload.detail)
    source_executable = source / APP_RELATIVE / "zaap"
    staged_executable = staging / APP_RELATIVE / "zaap"
    if payload.status == "ok" and _sha256(source_executable) != _sha256(staged_executable):
        shutil.rmtree(staging)
        raise ValueError("copied Zaap payload integrity check failed")
    (staging / INSTALL_MARKER).write_text("appsbx installed application\n", encoding="ascii")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging.replace(destination)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    marker = state_dir / STATE_MARKER
    if not marker.exists():
        marker.write_text("appsbx persistent state\n", encoding="ascii")
        marker.chmod(0o600)


def create_venv(root: Path, *, dry_run: bool = False) -> list[list[str]]:
    venv = root / ".venv"
    commands = [[sys.executable, "-m", "venv", str(venv)], [str(venv / "bin" / "python"), "-m", "pip", "install", "--upgrade", "pip"], [str(venv / "bin" / "python"), "-m", "pip", "install", "-r", str(root / "requirements-gui.txt")]]
    if not dry_run:
        for command in commands:
            subprocess.run(command, check=True)
    return commands


def launcher_paths() -> tuple[Path, Path]:
    local_bin = Path(os.environ.get("XDG_BIN_HOME", Path.home() / ".local" / "bin"))
    desktop_dir = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "applications"
    return local_bin / "appsbx-gui", desktop_dir / "appsbx.desktop"


def write_launchers(root: Path, state_dir: Path, *, dry_run: bool = False) -> list[Path]:
    launcher, desktop = launcher_paths()
    body = f"#!/usr/bin/env bash\n{LAUNCHER_MARKER}set -euo pipefail\nexport APPSBX_STATE_ROOT={state_dir!s}\nexport PYTHONPATH={root!s}${{PYTHONPATH:+:$PYTHONPATH}}\nexec {root / '.venv/bin/python'!s} -m appsbx.gui \"$@\"\n"
    entry = LAUNCHER_MARKER + "[Desktop Entry]\nType=Application\nName=appsbx Zaap Instances\nComment=Manage isolated Zaap instances\nExec=" + str(launcher) + "\nTryExec=" + str(launcher) + "\nTerminal=false\nCategories=Game;Utility;\n"
    if not dry_run:
        launcher.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        desktop.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        launcher.write_text(body, encoding="utf-8")
        launcher.chmod(0o700)
        desktop.write_text(entry, encoding="utf-8")
    return [launcher, desktop]


def install_helper(root: Path, *, dry_run: bool = False) -> list[list[str]]:
    commands = [
        ["sudo", "install", "-D", "-o", "root", "-g", "root", "-m", "0755", str(root / "appsbx/network_helper.py"), str(HELPER_DESTINATION)],
        ["sudo", "install", "-D", "-o", "root", "-g", "root", "-m", "0644", str(root / "appsbx/network.py"), str(HELPER_NETWORK_DESTINATION)],
    ]
    if not dry_run:
        for command in commands:
            subprocess.run(command, check=True)
    return commands


def uninstall(root: Path, state_dir: Path, *, remove_state: bool, dry_run: bool) -> list[Path]:
    expected = [(root, INSTALL_MARKER, "appsbx installed application\n")]
    if remove_state:
        expected.append((state_dir, STATE_MARKER, "appsbx persistent state\n"))
    targets: list[Path] = []
    for target, marker_name, expected_content in expected:
        marker = target / marker_name
        try:
            valid = marker.is_file() and marker.read_text(encoding="ascii") == expected_content
        except OSError:
            valid = False
        if not valid:
            raise ValueError(f"refusing to remove an unmanaged directory: {target}")
        targets.append(target)
    launcher, desktop = launcher_paths()
    for path in (launcher, desktop):
        if path.exists():
            try:
                managed = LAUNCHER_MARKER in path.read_text(encoding="utf-8")
            except OSError:
                managed = False
            if not managed:
                raise ValueError(f"refusing to remove an unmanaged launcher: {path}")
            targets.append(path)
    if not dry_run:
        for target in targets:
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m appsbx.install")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check")
    plan = sub.add_parser("plan")
    plan.add_argument("--minimal", action="store_true")
    install = sub.add_parser("install")
    install.add_argument("--prefix", type=Path, default=default_data_dir() / "app")
    install.add_argument("--state-dir", type=Path, default=default_state_dir())
    install.add_argument("--update", action="store_true")
    install.add_argument("--skip-system-packages", action="store_true")
    install.add_argument("--skip-network-helper", action="store_true")
    install.add_argument("--dry-run", action="store_true")
    install.add_argument("--yes", action="store_true", help="allow requested package-manager and helper commands")
    install.add_argument("--launcher", type=Path, help="official Zaap AppDir or AppImage to stage into managed storage")
    install.add_argument("--no-launcher-prompt", action="store_true", help="do not offer an interactive launcher selection")
    install.add_argument("--skip-launcher-download", action="store_true", help="defer official launcher download to the GUI")
    remove = sub.add_parser("uninstall")
    remove.add_argument("--prefix", type=Path, default=default_data_dir() / "app")
    remove.add_argument("--state-dir", type=Path, default=default_state_dir())
    remove.add_argument("--purge-state", action="store_true")
    remove.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.action == "check":
        host, checks = diagnostics()
        print(json.dumps({"host": asdict(host), "checks": [asdict(item) for item in checks]}, indent=2, sort_keys=True))
        return 0 if all(item.status != "error" for item in checks) else 2
    host = detect_host()
    packages = package_plan(host.package_manager, include_optional=not getattr(args, "minimal", False))
    if args.action == "plan":
        print(json.dumps({"host": asdict(host), "packages": packages, "package_command": package_command(host.package_manager, packages) if host.package_manager else None}, indent=2, sort_keys=True))
        return 0
    if args.action == "uninstall":
        print(json.dumps({"removed": [str(item) for item in uninstall(args.prefix, args.state_dir, remove_state=args.purge_state, dry_run=args.dry_run)], "dry_run": args.dry_run}, sort_keys=True))
        return 0
    if not host.supported_payload:
        parser.error(f"the bundled Zaap payload supports x86-64 only; detected {host.architecture}")
    if sys.version_info < MIN_PYTHON:
        parser.error(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required")
    needs_privilege = (not args.skip_system_packages and bool(packages)) or not args.skip_network_helper
    if needs_privilege and not args.dry_run and not args.yes:
        parser.error("privileged setup needs confirmation; review `plan` then rerun with --yes, or skip the requested setup steps")
    launcher = args.launcher
    if not args.skip_system_packages and packages and not args.dry_run:
        subprocess.run(package_command(host.package_manager, packages), check=True)
    if not args.dry_run:
        # A distributable may intentionally omit Ankama's proprietary payload.
        # The GUI can stage the user's official copy after installation.
        install_user_copy(PROJECT_ROOT, args.prefix, args.state_dir, replace=args.update,
                          allow_missing_payload=True)
    commands = create_venv(args.prefix, dry_run=args.dry_run)
    launchers = write_launchers(args.prefix, args.state_dir, dry_run=args.dry_run)
    staged_launcher = None
    if not args.dry_run:
        application_store = ApplicationStore(args.state_dir)
        staged_launcher = (application_store.stage_launcher(launcher)
                           if launcher is not None
                           else None if args.skip_launcher_download
                           else application_store.download_and_stage_official_launcher())
    helper = []
    if not args.skip_network_helper:
        helper = install_helper(args.prefix, dry_run=args.dry_run)
    print(json.dumps({"installed": str(args.prefix), "state": str(args.state_dir), "venv_commands": commands, "launchers": [str(item) for item in launchers], "configured_launcher": str(staged_launcher) if staged_launcher else None, "helper_commands": helper, "dry_run": args.dry_run}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
