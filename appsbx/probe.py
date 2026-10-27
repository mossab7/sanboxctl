"""Category-only host-leak probes.

The deny-list is collected in memory and is never serialized. Probe output is
deliberately limited to ``LEAK: <category>`` or ``OK: <category>``.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import platform
import socket
from typing import Iterable


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def host_denylist() -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}

    def add(category: str, value: str | None) -> None:
        if value:
            values.setdefault(category, set()).add(value)

    add("hostname", socket.gethostname())
    add("hostname", platform.node())
    add("username", getpass.getuser())
    add("os-release", _read(Path("/etc/os-release")))
    add("machine-id", _read(Path("/etc/machine-id")))
    add("machine-id", _read(Path("/var/lib/dbus/machine-id")))
    add("kernel", platform.release())
    add("kernel", _read(Path("/proc/sys/kernel/osrelease")))
    add("cpu", _read(Path("/proc/cpuinfo")))
    add("memory", _read(Path("/proc/meminfo")))
    add("environment", "\n".join(f"{key}={value}" for key, value in os.environ.items()))
    try:
        interfaces = socket.if_nameindex()
    except OSError:
        interfaces = ()
    for _, interface in interfaces:
        add("interface", interface)
        add("interface", _read(Path("/sys/class/net") / interface / "address"))
    return values


def current_observations() -> dict[str, str | None]:
    try:
        interface_names = socket.if_nameindex()
    except OSError:
        interface_names = ()
    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os-release": _read(Path("/etc/os-release")),
        "machine-id": _read(Path("/etc/machine-id")),
        "dbus-machine-id": _read(Path("/var/lib/dbus/machine-id")),
        "kernel": platform.release(),
        "cpu": _read(Path("/proc/cpuinfo")),
        "memory": _read(Path("/proc/meminfo")),
        "environment": "\n".join(f"{key}={value}" for key, value in os.environ.items()),
        "interfaces": "\n".join(name for _, name in interface_names),
    }


def leak_categories(deny: dict[str, set[str]], observations: dict[str, str | None]) -> list[str]:
    findings: set[str] = set()
    for category, value in observations.items():
        if not value:
            continue
        for denied in deny.get(category, set()):
            if denied and (value == denied or denied in value):
                findings.add(category)
                break
    return sorted(findings)


def category_report(categories: Iterable[str]) -> list[str]:
    return [f"LEAK: {category}" for category in sorted(set(categories))]
