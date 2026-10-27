"""Per-instance network planning for stub and selected-egress real mode.

The planner is deliberately unprivileged. ``network_helper.py`` is the small,
separately installed privileged executor for the real-mode plan.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import tempfile
from typing import Iterable


EGRESS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
DEFAULT_EGRESS_DIR = Path(__file__).resolve().parents[1] / "etc" / "egress.d"


class NetworkError(ValueError):
    """Raised for invalid network plans or egress definitions."""


@dataclass(frozen=True)
class ResourceNames:
    netns: str
    host_veth: str
    guest_veth: str
    route_table: int
    rule_priority: int
    nft_table: str


@dataclass(frozen=True)
class EgressDefinition:
    name: str
    interface: str
    gateway: ipaddress.IPv4Address | None
    dns_servers: tuple[ipaddress.IPv4Address, ...]
    ipv6: bool = False


@dataclass(frozen=True)
class NetworkPlan:
    profile_id: int
    mode: str
    subnet: ipaddress.IPv4Network
    names: ResourceNames
    egress: str | None
    commands: tuple[tuple[str, ...], ...]
    definition: EgressDefinition | None = None


def validate_egress_name(name: str) -> str:
    if not isinstance(name, str) or not EGRESS_RE.fullmatch(name):
        raise NetworkError("invalid egress name")
    return name


def validate_interface_name(name: str) -> str:
    if not isinstance(name, str) or not IFACE_RE.fullmatch(name):
        raise NetworkError("invalid egress interface name")
    return name


def resource_names(profile_id: int) -> ResourceNames:
    if not isinstance(profile_id, int) or not 0 <= profile_id <= 253:
        raise NetworkError("profile id must be in [0, 253]")
    return ResourceNames(
        netns=f"appsbx-{profile_id}",
        host_veth=f"appsbx-h{profile_id}",
        guest_veth="eth0",
        route_table=200 + profile_id,
        rule_priority=1000 + profile_id * 2,
        nft_table=f"appsbx_{profile_id}",
    )


def subnet_for_id(profile_id: int, base: str = "10.200.0.0/16") -> ipaddress.IPv4Network:
    resource_names(profile_id)
    network = ipaddress.ip_network(base, strict=False)
    if network.version != 4 or network.prefixlen > 24:
        raise NetworkError("base network must be IPv4 with prefix length <= 24")
    candidate = ipaddress.ip_network(f"10.200.{profile_id}.0/30")
    if not candidate.subnet_of(network) and str(network) != "10.200.0.0/16":
        raise NetworkError("profile subnet is outside configured base")
    return candidate


def subnet_overlaps(candidate: ipaddress.IPv4Network, routes: Iterable[str]) -> bool:
    for route in routes:
        try:
            if candidate.overlaps(ipaddress.ip_network(route, strict=False)):
                return True
        except ValueError as exc:
            raise NetworkError(f"invalid host route: {route}") from exc
    return False


def _parse_bool(value: str, key: str) -> bool:
    value = value.strip().lower()
    if value in {"1", "yes", "true", "on", "enabled"}:
        return True
    if value in {"0", "no", "false", "off", "disabled"}:
        return False
    raise NetworkError(f"invalid boolean for {key}")


def _parse_ipv4(value: str, key: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise NetworkError(f"invalid IPv4 address for {key}") from exc
    if not isinstance(address, ipaddress.IPv4Address) or address.is_loopback or address.is_unspecified:
        raise NetworkError(f"{key} must be a non-loopback IPv4 address")
    return address


def load_egress_definition(name: str, directory: Path = DEFAULT_EGRESS_DIR) -> EgressDefinition:
    """Load a fixed-format egress definition without invoking a shell."""
    validate_egress_name(name)
    root = directory.resolve()
    path = directory / f"{name}.conf"
    try:
        path = path.resolve(strict=True)
        path.relative_to(root)
    except (OSError, ValueError) as exc:
        raise NetworkError(f"egress definition is unavailable: {name}") from exc
    values: dict[str, str] = {}
    try:
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "=" not in line:
                raise NetworkError(f"invalid egress definition line {line_number}")
            key, value = (part.strip() for part in line.split("=", 1))
            if key not in {"name", "type", "interface", "gateway", "dns", "ipv6"}:
                raise NetworkError(f"unsupported egress setting: {key}")
            values[key] = value
    except OSError as exc:
        raise NetworkError(f"cannot read egress definition: {name}") from exc
    if values.get("name", name) != name or values.get("type") not in {"interface", "physical", "vpn", "usb"}:
        raise NetworkError(f"egress {name} is not a real interface definition")
    interface = validate_interface_name(values.get("interface", ""))
    gateway = _parse_ipv4(values["gateway"], "gateway") if values.get("gateway") else None
    raw_dns = values.get("dns", "")
    dns_servers = tuple(_parse_ipv4(item, "dns") for item in raw_dns.split(",") if item.strip())
    if not dns_servers:
        raise NetworkError(f"egress {name} must define at least one DNS server")
    ipv6 = _parse_bool(values.get("ipv6", "false"), "ipv6")
    if ipv6:
        raise NetworkError("IPv6 real egress is disabled until an IPv6 route/NAT policy is configured")
    return EgressDefinition(name, interface, gateway, dns_servers, ipv6)


def dns_resolv_conf(definition: EgressDefinition) -> str:
    """Return a namespace-local resolver configuration."""
    lines = ["# appsbx: selected-egress DNS only"]
    lines.extend(f"nameserver {server}" for server in definition.dns_servers)
    return "\n".join(lines) + "\n"


def write_dns_resolv_conf(state_dir: Path, definition: EgressDefinition) -> Path:
    """Atomically create the private resolver file mounted into one profile."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = state_dir / f"resolv-{definition.name}.conf"
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=state_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(dns_resolv_conf(definition))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return destination


def nft_rules(plan: NetworkPlan) -> str:
    """Render scoped fail-closed IPv4/IPv6 filter and IPv4 NAT rules."""
    if plan.definition is None or plan.mode != "real":
        raise NetworkError("nft rules require a real egress definition")
    n = plan.names
    subnet = plan.subnet
    egress = plan.definition.interface
    return f"""table inet {n.nft_table} {{
    chain forward {{
        type filter hook forward priority -150; policy accept;
        iifname \"{n.host_veth}\" ip saddr {subnet} oifname \"{egress}\" accept
        iifname \"{egress}\" ip daddr {subnet} oifname \"{n.host_veth}\" ct state established,related accept
        iifname \"{n.host_veth}\" drop
    }}
}}
table ip {n.nft_table}_nat {{
    chain postrouting {{
        # Run just before the conventional srcnat (100) priority used by
        # Docker/iptables-nft. This gives the scoped appsbx masquerade rule a
        # deterministic first chance to map its private /30, without changing
        # NAT behavior for any non-appsbx traffic.
        type nat hook postrouting priority 90; policy accept;
        ip saddr {subnet} oifname \"{egress}\" masquerade
    }}
}}
table ip6 {n.nft_table}_v6 {{
    chain forward {{
        type filter hook forward priority -150; policy accept;
        iifname \"{n.host_veth}\" drop
    }}
}}
"""


def build_plan(
    profile_id: int,
    mode: str = "stub",
    egress: str | None = None,
    host_routes: Iterable[str] = (),
    egress_dir: Path = DEFAULT_EGRESS_DIR,
) -> NetworkPlan:
    if mode not in {"stub", "real"}:
        raise NetworkError("network mode must be stub or real")
    if egress is not None:
        validate_egress_name(egress)
    if mode == "real" and not egress:
        raise NetworkError("real network mode requires --egress")
    subnet = subnet_for_id(profile_id)
    if subnet_overlaps(subnet, host_routes):
        raise NetworkError(f"subnet {subnet} overlaps a host route")
    names = resource_names(profile_id)
    if mode == "stub":
        commands = (("bwrap", "--unshare-net", "# loopback-only stub"),)
        return NetworkPlan(profile_id, mode, subnet, names, egress, commands)

    definition = load_egress_definition(egress or "", egress_dir)
    guest = str(subnet.network_address + 2)
    host = str(subnet.network_address + 1)
    route = str(subnet)
    egress_routes = (
        (("ip", "route", "add", "table", str(names.route_table), f"{definition.gateway}/32", "dev", definition.interface),
         ("ip", "route", "add", "table", str(names.route_table), "default", "via", str(definition.gateway), "dev", definition.interface))
        if definition.gateway else
        (("ip", "route", "add", "table", str(names.route_table), "default", "dev", definition.interface),)
    )
    commands = (
        ("ip", "netns", "add", names.netns),
        ("ip", "link", "add", names.host_veth, "type", "veth", "peer", "name", names.guest_veth, "netns", names.netns),
        ("ip", "addr", "add", f"{host}/30", "dev", names.host_veth),
        ("ip", "link", "set", names.host_veth, "up"),
        ("ip", "netns", "exec", names.netns, "ip", "link", "set", "lo", "up"),
        ("ip", "netns", "exec", names.netns, "ip", "addr", "add", f"{guest}/30", "dev", names.guest_veth),
        ("ip", "netns", "exec", names.netns, "ip", "link", "set", names.guest_veth, "up"),
        ("ip", "netns", "exec", names.netns, "ip", "route", "add", "default", "via", host, "dev", names.guest_veth),
        ("ip", "rule", "add", "pref", str(names.rule_priority), "from", route, "table", str(names.route_table)),
        ("ip", "rule", "add", "pref", str(names.rule_priority + 1), "from", route, "unreachable"),
        ("ip", "route", "add", "table", str(names.route_table), route, "dev", names.host_veth, "src", host),
    )
    commands += egress_routes + (("nft", "-f", f"/run/appsbx/{names.nft_table}.nft"),)
    return NetworkPlan(profile_id, mode, subnet, names, egress, commands, definition)


class StubNetworkBackend:
    """No privileged operations; models a loopback-only network boundary."""

    def up(self, profile_id: int) -> dict[str, object]:
        plan = build_plan(profile_id, "stub")
        return {"status": "planned", "mode": "stub", "netns": plan.names.netns, "subnet": str(plan.subnet)}

    def down(self, profile_id: int) -> dict[str, object]:
        names = resource_names(profile_id)
        return {"status": "not-created", "mode": "stub", "netns": names.netns}

    def status(self, profile_id: int) -> dict[str, object]:
        names = resource_names(profile_id)
        return {"status": "stub-only", "netns": names.netns, "host_veth": names.host_veth}
