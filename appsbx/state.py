"""Small atomic controller state files with fail-closed egress changes."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile


class StateError(ValueError):
    """Persisted controller state is invalid or conflicts with a request."""


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def require_egress_consistency(state_dir: Path, requested: str | None, force: bool = False) -> None:
    """Refuse an egress change for an existing profile unless explicitly forced."""
    if requested is None:
        return
    marker = state_dir / "last-egress"
    previous = marker.read_text(encoding="utf-8").strip() if marker.exists() else None
    if previous and previous != requested and not force:
        raise StateError(
            f"egress change from {previous!r} to {requested!r} requires explicit force; "
            "rerun with --force-egress after verifying the selected interface"
        )


def record_egress(state_dir: Path, requested: str | None) -> None:
    if requested is not None:
        _atomic_text(state_dir / "last-egress", requested + "\n")
