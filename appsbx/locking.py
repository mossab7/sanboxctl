"""Per-profile, advisory lifecycle lock for one local controller instance."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
from pathlib import Path
from typing import Iterator


class LockBusy(RuntimeError):
    """The profile is already owned by another controller process."""


@contextmanager
def profile_lock(state_dir: Path) -> Iterator[Path]:
    """Hold an exclusive lock without writing host-derived metadata.

    The lock file contains no PID or command line.  This keeps lifecycle
    state useful for coordination without turning it into a process log.
    """
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state_dir / "run.lock"
    handle = lock_path.open("a+")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("profile is already running") from exc
        yield lock_path
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
