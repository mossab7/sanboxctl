#!/usr/bin/env python3
"""Small privileged executor for the selected-egress network backend.

Install this file as a root-owned, non-writable helper (normally
``/usr/libexec/appsbx-net-helper``) and grant only the required invocation via
sudoers. It never launches the application directly: it only launches a
Bubblewrap command that must retain the user namespace and capability drops.
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import os
from pathlib import Path
import signal
import shlex
import stat
import subprocess
import sys
import tempfile
import json

try:
    from .network import (
        EgressDefinition,
        NetworkError,
        NetworkPlan,
        ResourceNames,
        nft_rules,
        resource_names,
        validate_egress_name,
        validate_interface_name,
    )
except ImportError:  # direct root-owned installation beside network.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from network import (  # type: ignore[no-redef]
        EgressDefinition,
        NetworkError,
        NetworkPlan,
        ResourceNames,
        nft_rules,
        resource_names,
        validate_egress_name,
        validate_interface_name,
    )


RUN_DIR = Path("/run/appsbx")
DISPLAY_MARKER = ".appsbx-private-x11"
DISPLAY_MARKER_CONTENT = "appsbx private X11 socket directory\n"
PROFILE_HOME_MARKER = ".appsbx-private-home"
PROFILE_HOME_MARKER_CONTENT = "appsbx private per-profile home\n"


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise NetworkError(f"command failed: {' '.join(argv)}: {detail}") from exc


def _require_root() -> None:
    if os.geteuid() != 0:
        raise NetworkError("real networking requires the separately installed privileged helper")
    for binary in ("ip", "nft", "nsenter", "setpriv", "sysctl"):
        if not shutil_which(binary):
            raise NetworkError(f"required helper command is unavailable: {binary}")


def shutil_which(binary: str) -> str | None:
    # Avoid importing a broad helper framework in the privileged process.
    for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        candidate = Path(directory) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _safe_name(value: str, label: str) -> str:
    if not value or len(value) > 32 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in value):
        raise NetworkError(f"invalid {label}")
    return value


def _validate_private_display_bind(source: str, destination: str) -> None:
    """Permit only the controller-created writable bind used by Xvfb.

    The application needs to create its *own* Xvfb UNIX socket in this
    directory so that the unprivileged local VNC controller can attach.  A
    generic writable bind would defeat the filesystem boundary, therefore the
    helper accepts exactly this destination and an owner-only marked source.
    """
    if destination != "/tmp/.X11-unix":
        raise NetworkError("privileged helper rejects writable mounts outside private X11 socket path")
    path = Path(source)
    try:
        info = path.stat(follow_symlinks=False)
        marker = path / DISPLAY_MARKER
        marker_info = marker.stat(follow_symlinks=False)
        marker_content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise NetworkError("private X11 socket bind source is unavailable") from exc
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or not stat.S_ISREG(marker_info.st_mode)
        or marker_info.st_mode & 0o077
        or marker_content != DISPLAY_MARKER_CONTENT
    ):
        raise NetworkError("private X11 socket bind source is unsafe")
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is not None:
        try:
            expected_uid = int(sudo_uid)
        except ValueError as exc:
            raise NetworkError("invalid invoking-user identity") from exc
        if info.st_uid != expected_uid:
            raise NetworkError("private X11 socket bind source is not owned by the invoking user")


def _validate_private_home_bind(source: str, destination: str) -> None:
    """Permit the one persistent, per-profile writable application home.

    This is not a generic host-home bind.  The source must be an owner-only
    ``home`` directory whose unmounted parent contains the controller marker.
    The application can write the mounted directory but cannot forge or alter
    the marker that authorizes the next real-network launch.
    """
    if destination != "/home/appsbx":
        raise NetworkError("privileged helper rejects writable mounts outside private application home")
    path = Path(source)
    parent = path.parent
    try:
        info = path.stat(follow_symlinks=False)
        parent_info = parent.stat(follow_symlinks=False)
        marker = parent / PROFILE_HOME_MARKER
        marker_info = marker.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkError("private application-home bind source is unavailable") from exc
    if (
        not path.is_absolute()
        or path.name != "home"
        or path.is_symlink()
        or parent.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or info.st_mode & 0o077
        or parent_info.st_mode & 0o077
        or not stat.S_ISREG(marker_info.st_mode)
        or marker.is_symlink()
        or marker_info.st_mode & 0o077
    ):
        raise NetworkError("private application-home bind source is unsafe")
    try:
        marker_content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise NetworkError("private application-home marker is unavailable") from exc
    if marker_content != PROFILE_HOME_MARKER_CONTENT:
        raise NetworkError("private application-home bind source is unsafe")
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid is not None:
        try:
            expected_uid = int(sudo_uid)
        except ValueError as exc:
            raise NetworkError("invalid invoking-user identity") from exc
        if info.st_uid != expected_uid or parent_info.st_uid != expected_uid:
            raise NetworkError("private application-home bind source is not owned by the invoking user")


def _check_bwrap_command(command: list[str]) -> None:
    if not command or Path(command[0]).name != "bwrap":
        raise NetworkError("privileged helper accepts only a Bubblewrap command")
    required = {
        "--die-with-parent": False,
        "--unshare-user": False,
        "--cap-drop": False,
        "--clearenv": False,
        "--uid": False,
        "--gid": False,
    }
    for index, item in enumerate(command):
        if item in required:
            required[item] = True
        if item == "--unshare-net":
            raise NetworkError("real-mode Bubblewrap command must join the prepared namespace")
        if item in {"--dev-bind", "--dev-bind-try", "--bind-try"}:
            raise NetworkError("privileged helper rejects writable or device mounts")
        if item == "--bind":
            try:
                source, destination = command[index + 1], command[index + 2]
                if destination == "/tmp/.X11-unix":
                    _validate_private_display_bind(source, destination)
                elif destination == "/home/appsbx":
                    _validate_private_home_bind(source, destination)
                else:
                    raise NetworkError("privileged helper rejects writable mounts outside approved private paths")
            except IndexError as exc:
                raise NetworkError("Bubblewrap writable mount is malformed") from exc
    if any(not present for present in required.values()):
        raise NetworkError("Bubblewrap command is missing required isolation options")
    try:
        cap_index = command.index("--cap-drop")
        if command[cap_index + 1] != "ALL":
            raise NetworkError("Bubblewrap must drop all capabilities")
    except (ValueError, IndexError) as exc:
        raise NetworkError("Bubblewrap capability policy is invalid") from exc


def _bwrap_ids(command: list[str]) -> tuple[int, int]:
    try:
        uid = int(command[command.index("--uid") + 1])
        gid = int(command[command.index("--gid") + 1])
    except (ValueError, IndexError) as exc:
        raise NetworkError("Bubblewrap UID/GID policy is invalid") from exc
    if not 1 <= uid <= 65534 or not 1 <= gid <= 65534:
        raise NetworkError("Bubblewrap must use a non-root synthetic UID/GID")
    return uid, gid


def _interface_is_available(interface: str) -> None:
    validate_interface_name(interface)
    try:
        result = _run(["ip", "-j", "link", "show", "dev", interface])
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NetworkError(f"selected egress interface is unavailable: {interface}") from exc
    if not result.stdout.strip().startswith("[") or result.stdout.strip() == "[]":
        raise NetworkError(f"selected egress interface is unavailable: {interface}")
    # A VPN/tunnel can report UNKNOWN while carrying traffic. Explicit DOWN is
    # the only state rejected here; nft oifname rules enforce fail-closed use
    # if the interface later disappears or loses its carrier.
    try:
        state = __import__("json").loads(result.stdout)[0].get("operstate", "UNKNOWN")
    except (ValueError, IndexError, AttributeError) as exc:
        raise NetworkError("cannot inspect selected egress state") from exc
    if state == "DOWN":
        raise NetworkError(f"selected egress interface is down: {interface}")


def _check_forwarding() -> None:
    try:
        value = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise NetworkError("cannot inspect IPv4 forwarding state") from exc
    if value != "1":
        raise NetworkError("IPv4 forwarding is disabled; refusing to change host sysctl state")


def _sysctl_namespace(netns: str, key: str, value: str) -> None:
    sysctl = shutil_which("sysctl")
    if sysctl is None:
        raise NetworkError("required helper command is unavailable: sysctl")
    command = ["ip", "netns", "exec", netns, sysctl, "-q", "-w", f"{key}={value}"]
    try:
        _run(command)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NetworkError(f"cannot configure namespace sysctl: {key}") from exc


def _child_command(netns: str, exec_uid: int, exec_gid: int, command: list[str]) -> list[str]:
    """Build the non-root command that joins a prepared network namespace."""
    nsenter = shutil_which("nsenter")
    setpriv = shutil_which("setpriv")
    if nsenter is None or setpriv is None:
        raise NetworkError("required namespace transition helper is unavailable")
    return [
        nsenter, f"--net=/run/netns/{netns}", "--",
        setpriv, "--reuid", str(exec_uid), "--regid", str(exec_gid),
        "--clear-groups", "--no-new-privs", "--", *command,
    ]


def _pdeathsig() -> None:
    """Arrange cleanup if the privileged helper's invoking process dies."""
    try:
        libc = ctypes.CDLL(None)
        if libc.prctl(1, signal.SIGTERM) != 0:  # PR_SET_PDEATHSIG
            raise OSError("prctl failed")
    except (OSError, AttributeError):
        # Cleanup remains available through the explicit cleanup command. The
        # helper still uses --die-with-parent for the Bubblewrap child.
        return


def _nft_delete(table_family: str, table: str) -> None:
    _run(["nft", "delete", "table", table_family, table], check=False)


def _docker_user_chain_exists() -> bool:
    """Return whether Docker's documented user extension chain is active."""
    nft = shutil_which("nft")
    if nft is None:
        return False
    result = _run([nft, "list", "chain", "ip", "filter", "DOCKER-USER"], check=False)
    return result.returncode == 0


def _docker_user_rule_specs(
    profile_id: int,
    names: ResourceNames,
    subnet: ipaddress.IPv4Network,
    egress: str,
) -> tuple[tuple[str, ...], ...]:
    """Return Docker-USER rules that preserve the appsbx fail-closed policy.

    Docker evaluates its FORWARD base chain after appsbx's independent base
    chain. Its default DROP policy therefore still applies to an appsbx packet
    even after the earlier appsbx chain accepted it. Docker explicitly reserves
    DOCKER-USER for administrator rules that must run before Docker's own
    forwarding policy.  These rules remain limited to one veth/subnet/egress.
    """
    tag = f"appsbx:{profile_id}:"
    return (
        (
            "-i", names.host_veth, "-s", str(subnet), "-o", egress,
            "-m", "comment", "--comment", tag + "out", "-j", "ACCEPT",
        ),
        (
            "-i", egress, "-d", str(subnet), "-o", names.host_veth,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-m", "comment", "--comment", tag + "return", "-j", "ACCEPT",
        ),
        (
            "-i", names.host_veth,
            "-m", "comment", "--comment", tag + "drop", "-j", "DROP",
        ),
    )


def _iptables_nft() -> str:
    iptables = shutil_which("iptables")
    if iptables is None:
        raise NetworkError("Docker FORWARD policy requires the iptables-nft compatibility command")
    version = _run([iptables, "--version"])
    if "nf_tables" not in ((version.stdout or "") + (version.stderr or "")):
        raise NetworkError("Docker's nftables DOCKER-USER chain requires iptables-nft, not legacy iptables")
    return iptables


def _remove_docker_user_rules(profile_id: int) -> None:
    """Remove only rules tagged for one profile from Docker's user chain."""
    iptables = shutil_which("iptables")
    if iptables is None:
        return
    listed = _run([iptables, "-S", "DOCKER-USER"], check=False)
    if listed.returncode != 0:
        return
    tag = f"appsbx:{profile_id}:"
    for raw in listed.stdout.splitlines():
        try:
            tokens = shlex.split(raw)
        except ValueError:
            continue
        if len(tokens) < 3 or tokens[:2] != ["-A", "DOCKER-USER"]:
            continue
        try:
            comment_index = tokens.index("--comment")
            comment = tokens[comment_index + 1]
        except (ValueError, IndexError):
            continue
        if comment.startswith(tag):
            _run([iptables, "-D", "DOCKER-USER", *tokens[2:]], check=False)


def _install_docker_user_rules(
    profile_id: int,
    names: ResourceNames,
    subnet: ipaddress.IPv4Network,
    egress: str,
) -> None:
    """Allow this instance through Docker's documented user-policy hook."""
    iptables = _iptables_nft()
    _remove_docker_user_rules(profile_id)
    for spec in _docker_user_rule_specs(profile_id, names, subnet, egress):
        _run([iptables, "-A", "DOCKER-USER", *spec])


def _flush_policy_table(route_table: int) -> None:
    # Tables 200..453 are reserved for appsbx profile instances. Flushing only
    # the selected reserved table removes routes left by an interrupted setup
    # without touching the main table or any other profile.
    _run(["ip", "route", "flush", "table", str(route_table)], check=False)


def _connected_route(interface: str, gateway: ipaddress.IPv4Address) -> tuple[str, str | None] | None:
    try:
        result = _run(["ip", "-j", "-4", "route", "show", "table", "main", "dev", interface])
        routes = json.loads(result.stdout)
    except (NetworkError, ValueError, TypeError) as exc:
        raise NetworkError(f"cannot inspect routes for selected egress: {interface}") from exc
    for route in routes:
        destination = route.get("dst")
        if not destination or destination == "default" or route.get("scope") != "link":
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if gateway in network:
            return destination, route.get("prefsrc") or route.get("src")
    return None


def cleanup(args: argparse.Namespace) -> int:
    _require_root()
    names = resource_names(args.profile_id)
    _remove_docker_user_rules(args.profile_id)
    for family, table in (("inet", names.nft_table), ("ip", f"{names.nft_table}_nat"), ("ip6", f"{names.nft_table}_v6")):
        _nft_delete(family, table)
    _flush_policy_table(names.route_table)
    _run(["ip", "rule", "del", "pref", str(names.rule_priority)], check=False)
    _run(["ip", "rule", "del", "pref", str(names.rule_priority + 1)], check=False)
    _run(["ip", "link", "del", names.host_veth], check=False)
    _run(["ip", "netns", "del", names.netns], check=False)
    return 0


def run(args: argparse.Namespace) -> int:
    _require_root()
    _pdeathsig()
    names = resource_names(args.profile_id)
    _safe_name(args.netns, "network namespace")
    _safe_name(args.host_veth, "host veth")
    if args.netns != names.netns or args.host_veth != names.host_veth:
        raise NetworkError("network resource names do not match profile id")
    validate_egress_name(args.egress)
    validate_interface_name(args.interface)
    _interface_is_available(args.interface)
    _check_forwarding()
    if args.ipv6:
        raise NetworkError("IPv6 is disabled by policy; no IPv6 fallback is permitted")
    try:
        subnet = ipaddress.ip_network(args.subnet, strict=True)
    except ValueError as exc:
        raise NetworkError("invalid private subnet") from exc
    if not isinstance(subnet, ipaddress.IPv4Network) or subnet.prefixlen != 30:
        raise NetworkError("network helper requires an IPv4 /30 subnet")
    try:
        gateway = ipaddress.ip_address(args.gateway) if args.gateway else None
        dns_servers = tuple(ipaddress.ip_address(item) for item in args.dns)
    except ValueError as exc:
        raise NetworkError("invalid gateway or DNS address") from exc
    if gateway is not None and not isinstance(gateway, ipaddress.IPv4Address):
        raise NetworkError("gateway must be IPv4 while IPv6 is disabled")
    if any(not isinstance(item, ipaddress.IPv4Address) for item in dns_servers):
        raise NetworkError("DNS servers must be IPv4 while IPv6 is disabled")
    definition = EgressDefinition(
        args.egress,
        args.interface,
        gateway,
        dns_servers,
        False,
    )
    plan = NetworkPlan(args.profile_id, "real", subnet, names, args.egress, (), definition)
    if not definition.dns_servers:
        raise NetworkError("real mode requires at least one DNS server")
    for server in definition.dns_servers:
        if not isinstance(server, ipaddress.IPv4Address) or server.is_loopback:
            raise NetworkError("DNS servers must be non-loopback IPv4 addresses")

    _check_bwrap_command(args.command)
    exec_uid, exec_gid = _bwrap_ids(args.command)
    created = False
    nft_path: Path | None = None
    docker_user_rules = False
    child: subprocess.Popen[str] | None = None
    def stop_child(signum: int, _frame: object) -> None:
        if child is not None and child.poll() is None:
            child.terminate()
        raise SystemExit(128 + signum)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop_child)
    try:
        # Refuse collisions instead of adopting another instance's resources.
        existing_netns = _run(["ip", "netns", "list"], check=True).stdout.splitlines()
        if any(line.split()[0] == names.netns for line in existing_netns):
            raise NetworkError(f"network namespace already exists: {names.netns}")
        if _run(["ip", "-j", "link", "show", "dev", names.host_veth], check=False).stdout.strip() not in {"", "[]"}:
            raise NetworkError(f"host veth already exists: {names.host_veth}")
        host = str(subnet.network_address + 1)
        guest = str(subnet.network_address + 2)
        _run(["ip", "netns", "add", names.netns])
        created = True
        _run(["ip", "link", "add", names.host_veth, "type", "veth", "peer", "name", names.guest_veth, "netns", names.netns])
        _run(["ip", "addr", "add", f"{host}/30", "dev", names.host_veth])
        _run(["ip", "link", "set", names.host_veth, "up"])
        _run(["ip", "netns", "exec", names.netns, "ip", "link", "set", "lo", "up"])
        _run(["ip", "netns", "exec", names.netns, "ip", "addr", "add", f"{guest}/30", "dev", names.guest_veth])
        _run(["ip", "netns", "exec", names.netns, "ip", "link", "set", names.guest_veth, "up"])
        _run(["ip", "netns", "exec", names.netns, "ip", "route", "add", "default", "via", host, "dev", names.guest_veth])
        _sysctl_namespace(names.netns, "net.ipv6.conf.all.disable_ipv6", "1")
        _sysctl_namespace(names.netns, "net.ipv6.conf.default.disable_ipv6", "1")

        table = str(names.route_table)
        route = str(subnet)
        # Reclaim only stale routes in this profile's reserved table after an
        # interrupted previous setup; the namespace/veth collision checks above
        # still prevent adopting an active instance.
        _flush_policy_table(names.route_table)
        _run(["ip", "rule", "add", "pref", str(names.rule_priority), "from", route, "table", table])
        _run(["ip", "rule", "add", "pref", str(names.rule_priority + 1), "from", route, "unreachable"])
        _run(["ip", "route", "add", "table", table, route, "dev", names.host_veth, "src", host])
        if definition.gateway:
            connected = _connected_route(definition.interface, definition.gateway)
            if connected is None:
                raise NetworkError(f"gateway {definition.gateway} is not on a connected route for {definition.interface}")
            connected_destination, source = connected
            connected_command = ["ip", "route", "add", "table", table, connected_destination, "dev", definition.interface]
            if source:
                connected_command.extend(["src", source])
            _run(connected_command)
            _run(["ip", "route", "add", "table", table, f"{definition.gateway}/32", "dev", definition.interface])
            _run(["ip", "route", "add", "table", table, "default", "via", str(definition.gateway), "dev", definition.interface])
        else:
            _run(["ip", "route", "add", "table", table, "default", "dev", definition.interface])

        RUN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(RUN_DIR, 0o700)
        with tempfile.NamedTemporaryFile("w", prefix=f"{names.nft_table}.", suffix=".nft", dir=RUN_DIR, delete=False, encoding="utf-8") as handle:
            nft_path = Path(handle.name)
            handle.write(nft_rules(plan))
        os.chmod(nft_path, 0o600)
        _run(["nft", "-f", str(nft_path)])
        if _docker_user_chain_exists():
            _install_docker_user_rules(args.profile_id, names, subnet, definition.interface)
            docker_user_rules = True

        # Network setup above is the only root operation. Enter the prepared
        # network namespace while still privileged so setpriv can atomically
        # change real/effective IDs and clear supplementary groups. Doing the
        # group transition after nsenter's --setuid/--setgid would make
        # setpriv non-root and causes EPERM on setgroups(2).
        child_command = _child_command(names.netns, exec_uid, exec_gid, args.command)
        child = subprocess.Popen(child_command, text=True)
        return child.wait()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            child.wait()
        if nft_path is not None:
            if docker_user_rules:
                _remove_docker_user_rules(args.profile_id)
            _nft_delete("inet", names.nft_table)
            _nft_delete("ip", f"{names.nft_table}_nat")
            _nft_delete("ip6", f"{names.nft_table}_v6")
            nft_path.unlink(missing_ok=True)
        if created:
            _flush_policy_table(names.route_table)
            _run(["ip", "rule", "del", "pref", str(names.rule_priority)], check=False)
            _run(["ip", "rule", "del", "pref", str(names.rule_priority + 1)], check=False)
            _run(["ip", "link", "del", names.host_veth], check=False)
            _run(["ip", "netns", "del", names.netns], check=False)


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="appsbx-net-helper")
    sub = parser.add_subparsers(dest="action", required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--profile-id", type=int, required=True)
    run_parser.add_argument("--netns", required=True)
    run_parser.add_argument("--host-veth", required=True)
    run_parser.add_argument("--subnet", required=True)
    run_parser.add_argument("--egress", required=True)
    run_parser.add_argument("--interface", required=True)
    run_parser.add_argument("--gateway")
    run_parser.add_argument("--dns", action="append", default=[])
    run_parser.add_argument("--ipv6", action="store_true")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    run_parser.set_defaults(func=run)
    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("--profile-id", type=int, required=True)
    cleanup_parser.set_defaults(func=cleanup)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if hasattr(args, "command") and args.command and args.command[0] == "--":
            args.command = args.command[1:]
        return int(args.func(args))
    except (NetworkError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"appsbx-net-helper: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
