"""Validated, opt-in host display bindings.

Host display access is a capability and is never enabled by default. Only an
individual Wayland/X11 socket and, for X11, the authority cookie are exposed;
the host runtime and X11 directories are not mounted wholesale.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re


class HostDisplayError(ValueError):
    """Host display is unavailable or cannot be safely narrowed."""


@dataclass(frozen=True)
class HostDisplay:
    backend: str
    environment: tuple[tuple[str, str], ...]
    mounts: tuple[tuple[Path, str], ...]


def _socket(path: Path, description: str) -> Path:
    try:
        path = path.resolve(strict=True)
        if not path.is_socket():
            raise HostDisplayError(f"{description} is not a Unix socket")
    except OSError as exc:
        raise HostDisplayError(f"{description} is unavailable") from exc
    return path


def _authority(path_text: str) -> Path:
    """Validate an X11 cookie file without exposing its parent directory."""
    try:
        path = Path(path_text).resolve(strict=True)
        if not path.is_file():
            raise HostDisplayError("XAUTHORITY is not a regular file")
    except OSError as exc:
        raise HostDisplayError("XAUTHORITY is unavailable") from exc
    return path


def detect_host_display(environment: dict[str, str] | None = None) -> HostDisplay:
    """Prefer a local Wayland socket, then a local X11 display."""
    env = dict(os.environ if environment is None else environment)
    runtime = env.get("XDG_RUNTIME_DIR")
    wayland = env.get("WAYLAND_DISPLAY")
    if runtime and wayland and "/" not in wayland:
        socket = _socket(Path(runtime) / wayland, "Wayland display socket")
        mounts: list[tuple[Path, str]] = [(socket, "/run/appsbx/wayland-0")]
        values = [("WAYLAND_DISPLAY", "wayland-0"), ("XDG_RUNTIME_DIR", "/run/appsbx"),
                  ("XDG_SESSION_TYPE", "wayland")]
        # Keep Xwayland available as a fallback for Electron builds that do
        # not support native Wayland. Only the selected X socket/cookie is
        # exposed, never /tmp/.X11-unix or the host runtime directory.
        display = env.get("DISPLAY", "")
        match = re.fullmatch(r":(\d+)", display)
        if match:
            # Native Wayland remains usable if the compositor has no
            # Xwayland server. X11 is an optional compatibility fallback.
            try:
                x11 = _socket(Path("/tmp/.X11-unix") / f"X{int(match.group(1))}", "Xwayland display socket")
            except HostDisplayError:
                x11 = None
            if x11 is not None:
                mounts.append((x11, f"/tmp/.X11-unix/X{int(match.group(1))}"))
                values.append(("DISPLAY", display))
                values = [
                    (name, "x11" if name == "XDG_SESSION_TYPE" else value)
                    for name, value in values
                ]
                # The packaged Electron 16 build in the target application
                # is an X11-era build. When Xwayland is available, select it
                # explicitly instead of letting Ozone auto-select native
                # Wayland and fail with a SIGTRAP during startup.
                values.append(("ELECTRON_OZONE_PLATFORM_HINT", "x11"))
                if env.get("XAUTHORITY"):
                    authority = _authority(env["XAUTHORITY"])
                    mounts.append((authority, "/run/appsbx/xauthority"))
                    values.append(("XAUTHORITY", "/run/appsbx/xauthority"))
        return HostDisplay(
            "wayland",
            tuple(values), tuple(mounts),
        )

    display = env.get("DISPLAY", "")
    match = re.fullmatch(r":(\d+)", display)
    if not match:
        raise HostDisplayError("no local Wayland socket or local X11 DISPLAY was detected")
    number = int(match.group(1))
    socket = _socket(Path("/tmp/.X11-unix") / f"X{number}", "X11 display socket")
    mounts: list[tuple[Path, str]] = [(socket, f"/tmp/.X11-unix/X{number}")]
    values = [("DISPLAY", display), ("XDG_SESSION_TYPE", "x11")]
    values.append(("ELECTRON_OZONE_PLATFORM_HINT", "x11"))
    xauthority = env.get("XAUTHORITY")
    if xauthority:
        authority = _authority(xauthority)
        mounts.append((authority, "/run/appsbx/xauthority"))
        values.append(("XAUTHORITY", "/run/appsbx/xauthority"))
    return HostDisplay("x11", tuple(values), tuple(mounts))
