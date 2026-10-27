"""AppImage inspection and unprivileged extraction planning."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import subprocess


SQUASHFS_MAGIC = b"hsqs"
SQUASHFS_SUPERBLOCK_SIZE = 96


class RootfsError(ValueError):
    """Raised for invalid or unsupported application payloads."""


@dataclass(frozen=True)
class AppImageInfo:
    size: int
    sha256: str
    squashfs_offset: int


def inspect_appimage(path: Path) -> AppImageInfo:
    if not path.is_file():
        raise RootfsError("AppImage does not exist")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    offset = _find_squashfs_offset(path, size)
    return AppImageInfo(size=size, sha256=digest.hexdigest(), squashfs_offset=offset)


def _valid_squashfs_superblock(header: bytes, offset: int, file_size: int) -> bool:
    if len(header) < SQUASHFS_SUPERBLOCK_SIZE or header[:4] != SQUASHFS_MAGIC:
        return False
    try:
        fields = struct.unpack_from("<IIIIIHHHHHHQQQQQQQQ", header)
    except struct.error:
        return False
    _magic, inodes, _mkfs_time, block_size, _fragments, _compression, block_log, _flags, _no_ids, major, minor = fields[:11]
    bytes_used = fields[12]
    if inodes == 0 or major != 4 or minor != 0:
        return False
    if not 4096 <= block_size <= 1_048_576 or block_size & (block_size - 1):
        return False
    if block_log != block_size.bit_length() - 1:
        return False
    return SQUASHFS_SUPERBLOCK_SIZE <= bytes_used <= file_size - offset


def _find_squashfs_offset(path: Path, file_size: int) -> int:
    """Find a valid SquashFS superblock, not merely the first ``hsqs`` bytes."""
    carry = b""
    base = 0
    with path.open("rb") as scan, path.open("rb") as validate:
        while True:
            chunk = scan.read(1024 * 1024)
            if not chunk:
                break
            window = carry + chunk
            window_base = base - len(carry)
            position = 0
            while True:
                position = window.find(SQUASHFS_MAGIC, position)
                if position < 0:
                    break
                candidate = window_base + position
                validate.seek(candidate)
                header = validate.read(SQUASHFS_SUPERBLOCK_SIZE)
                if _valid_squashfs_superblock(header, candidate, file_size):
                    return candidate
                position += 1
            base += len(chunk)
            carry = window[-(len(SQUASHFS_MAGIC) - 1):]
    raise RootfsError("AppImage does not contain a valid SquashFS payload")


def extraction_command(appimage: Path, destination: Path, info: AppImageInfo | None = None) -> list[str]:
    metadata = info or inspect_appimage(appimage)
    return ["unsquashfs", "-quiet", "-no-xattrs", "-d", str(destination), "-o", str(metadata.squashfs_offset), str(appimage)]


def extract_appimage(appimage: Path, destination: Path) -> AppImageInfo:
    """Extract without FUSE; caller chooses a neutral destination."""
    info = inspect_appimage(appimage)
    if destination.exists() and any(destination.iterdir()):
        raise RootfsError("refusing to extract into a non-empty destination")
    destination.mkdir(parents=True, exist_ok=True, mode=0o755)
    subprocess.run(extraction_command(appimage, destination, info), check=True)
    return info
