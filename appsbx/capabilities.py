"""Read-only host capability inventory used to explain backend selection."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import shutil
import subprocess


@dataclass(frozen=True)
class Capability:
    name: str
    available: bool
    detail: str


def _version(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        return "not installed"
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return "installed; version unavailable"
    line = (result.stdout or result.stderr).splitlines()
    return line[0][:120] if line else "installed; version unavailable"


def probe_capabilities() -> list[Capability]:
    results = []
    for binary, purpose in (
        ("bwrap", "unprivileged mount/user/pid namespace runtime"),
        ("strace", "diagnostic syscall tracing"),
        ("ip", "network namespace and routing administration"),
        ("nft", "firewall policy backend"),
        ("nsenter", "join the prepared network namespace before demotion"),
        ("setpriv", "drop helper credentials before Bubblewrap"),
        ("sysctl", "disable IPv6 inside the prepared namespace"),
        ("wg", "WireGuard backend"),
        ("tun2socks", "userspace proxy tunnel backend"),
        ("unsquashfs", "unprivileged AppImage extraction"),
        ("Xvfb", "private in-sandbox X11 display backend"),
        ("x11vnc", "private Xvfb-to-VNC bridge server"),
        ("vncviewer", "host-desktop VNC viewer for private displays"),
        ("xtigervncviewer", "alternate host-desktop VNC viewer"),
        ("google-chrome", "private staged HTTP(S) URL broker browser"),
        ("weston", "Wayland compositor backend"),
        ("Xwayland", "X11-on-Wayland display backend"),
    ):
        detail = _version(binary)
        results.append(Capability(binary, detail != "not installed", f"{purpose}; {detail}"))
    try:
        result = subprocess.run(["unshare", "-T", "true"], capture_output=True, text=True, timeout=2)
        detail = "available" if result.returncode == 0 else "blocked by current permission boundary"
    except (OSError, subprocess.SubprocessError):
        detail = "unavailable"
    results.append(Capability("time-namespace", detail == "available", detail))
    return results


def capability_dicts() -> list[dict[str, object]]:
    return [asdict(item) for item in probe_capabilities()]
