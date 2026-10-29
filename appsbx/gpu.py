"""Conservative host GPU discovery for the hardware-rendering backend.

This module deliberately exposes only a DRM *render* node.  It does not read
or mount the host GPU control nodes, sysfs tree, or arbitrary driver paths.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat


class GpuError(ValueError):
    """The host GPU cannot be exposed safely to a sandbox instance."""


@dataclass(frozen=True)
class GpuInfo:
    render_node: Path
    kernel_driver: str
    mesa_driver: str
    driver_library: Path
    sysfs_device: Path
    sysfs_render_node: Path


_RENDER_NODE = re.compile(r"^renderD[0-9]+$")
_DRIVER_MAP = {
    "i915": "iris",
    "amdgpu": "radeonsi",
    "nouveau": "nouveau",
    "vmwgfx": "vmwgfx",
    "virtio_gpu": "virtio_gpu",
}


def _valid_render_node(path: Path) -> bool:
    """Require a real DRM render node, never a symlink or card/control node."""
    if path.parent != Path("/dev/dri") or not _RENDER_NODE.fullmatch(path.name):
        return False
    try:
        info = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISCHR(info.st_mode)
        and os.major(info.st_rdev) == 226
        and os.minor(info.st_rdev) >= 128
        and not path.is_symlink()
        and os.access(path, os.R_OK | os.W_OK)
    )


def detect_hardware_gpu(
    *,
    dev_root: Path = Path("/dev/dri"),
    sys_root: Path = Path("/sys/class/drm"),
    library_roots: tuple[Path, ...] = (
        Path("/usr/lib/x86_64-linux-gnu/dri"),
        Path("/usr/lib/aarch64-linux-gnu/dri"),
    ),
) -> GpuInfo:
    """Discover one usable GPU without falling back to llvmpipe/SwiftShader."""
    nodes = sorted(dev_root.glob("renderD*"))
    node = next((item for item in nodes if _valid_render_node(item)), None)
    if node is None:
        raise GpuError("hardware GPU mode requires an accessible DRM render node")
    driver_link = sys_root / node.name / "device" / "driver"
    try:
        sysfs_device = (sys_root / node.name / "device").resolve(strict=True)
        kernel_driver = driver_link.resolve(strict=True).name
        sysfs_render_node = (sysfs_device / "drm" / node.name).resolve(strict=True)
    except OSError as exc:
        raise GpuError(f"cannot identify kernel driver for {node.name}") from exc
    mesa_driver = _DRIVER_MAP.get(kernel_driver)
    if mesa_driver is None:
        raise GpuError(f"unsupported GPU kernel driver for hardware mode: {kernel_driver}")
    library = next(
        (root / f"{mesa_driver}_dri.so" for root in library_roots
         if (root / f"{mesa_driver}_dri.so").is_file()),
        None,
    )
    if library is None:
        raise GpuError(f"Mesa DRI driver is unavailable: {mesa_driver}_dri.so")
    return GpuInfo(node, kernel_driver, mesa_driver, library, sysfs_device, sysfs_render_node)
