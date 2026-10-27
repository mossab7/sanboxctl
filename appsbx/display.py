"""Private Xvfb display sessions and loopback-only VNC presentation.

The Electron process never receives a host X11 or Wayland socket.  Instead,
Xvfb creates one socket in a per-run, owner-only directory.  A tiny host-side
TCP acceptor listens only on 127.0.0.1 and starts a separately sandboxed
``x11vnc -inetd`` bridge for each local viewer connection.  The bridge has its
own network namespace and only sees the private X socket and a staged x11vnc
runtime closure.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import json
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Sequence


DISPLAY_MARKER = ".appsbx-private-x11"
DISPLAY_MARKER_CONTENT = "appsbx private X11 socket directory\n"
SESSION_MARKER = ".appsbx-display-session"
OWNER_FILE = ".appsbx-display-owner.json"


class DisplayError(ValueError):
    """Raised when a private display or local VNC presentation is unsafe."""


@dataclass(frozen=True)
class PrivateDisplay:
    """One run's host-private directory and X display number."""

    root: Path
    x11_dir: Path
    display_number: int

    @property
    def display_name(self) -> str:
        return f":{self.display_number}"

    @property
    def socket_path(self) -> Path:
        return self.x11_dir / f"X{self.display_number}"

    @property
    def bridge_log(self) -> Path:
        return self.root / "x11vnc.stderr"


def create_private_display(state_dir: Path) -> PrivateDisplay:
    """Create an owner-only directory which may contain one Xvfb socket."""
    displays_root = state_dir / "displays"
    displays_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(displays_root, 0o700)
    cleanup_orphaned_displays(state_dir)
    for _ in range(32):
        root = displays_root / f"run-{secrets.token_hex(16)}"
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            continue
        session_marker = root / SESSION_MARKER
        session_marker.write_text(DISPLAY_MARKER_CONTENT, encoding="ascii")
        os.chmod(session_marker, 0o600)
        owner = root / OWNER_FILE
        owner.write_text(json.dumps({"pid": os.getpid()}) + "\n", encoding="ascii")
        os.chmod(owner, 0o600)
        x11_dir = root / "x11"
        x11_dir.mkdir(mode=0o700)
        marker = x11_dir / DISPLAY_MARKER
        marker.write_text(DISPLAY_MARKER_CONTENT, encoding="ascii")
        os.chmod(marker, 0o600)
        # The socket directory, not merely the display number, separates
        # instances. A random number also keeps diagnostics unambiguous.
        display_number = 100 + secrets.randbelow(64_000)
        return PrivateDisplay(root, x11_dir, display_number)
    raise DisplayError("cannot allocate a private Xvfb display directory")


def validate_private_display(display: PrivateDisplay, state_dir: Path) -> None:
    """Ensure a bind source is a directory created by this controller."""
    try:
        state_root = state_dir.resolve(strict=True)
        displays_root = (state_root / "displays").resolve(strict=True)
        root = display.root.resolve(strict=True)
        x11_dir = display.x11_dir.resolve(strict=True)
        root.relative_to(displays_root)
        x11_dir.relative_to(root)
        root_stat = root.stat(follow_symlinks=False)
        directory_stat = x11_dir.stat(follow_symlinks=False)
        marker = x11_dir / DISPLAY_MARKER
        marker_stat = marker.stat(follow_symlinks=False)
        content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError, ValueError) as exc:
        raise DisplayError("private X11 socket directory is unavailable") from exc
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or not stat.S_ISDIR(directory_stat.st_mode)
        or not stat.S_ISREG(marker_stat.st_mode)
        or root_stat.st_mode & 0o077
        or directory_stat.st_mode & 0o077
        or marker_stat.st_mode & 0o077
        or content != DISPLAY_MARKER_CONTENT
    ):
        raise DisplayError("private X11 socket directory has unsafe permissions")
    if not 100 <= display.display_number <= 64_099:
        raise DisplayError("private X display number is invalid")


def remove_private_display(display: PrivateDisplay, state_dir: Path) -> None:
    """Remove only a validated per-run display directory."""
    try:
        state_root = state_dir.resolve(strict=True)
        displays_root = (state_root / "displays").resolve(strict=True)
        root = display.root.resolve(strict=True)
        root.relative_to(displays_root)
        root_stat = root.stat(follow_symlinks=False)
        marker = root / SESSION_MARKER
        marker_stat = marker.stat(follow_symlinks=False)
        marker_content = marker.read_text(encoding="ascii")
        valid = (
            stat.S_ISDIR(root_stat.st_mode)
            and stat.S_ISREG(marker_stat.st_mode)
            and not root_stat.st_mode & 0o077
            and not marker_stat.st_mode & 0o077
            and marker_content == DISPLAY_MARKER_CONTENT
        )
    except (OSError, UnicodeError, ValueError):
        valid = False
    if not valid:
        # Do not recursively remove a path that no longer has the expected
        # private shape. Leaving a stale directory is safer than deletion of
        # an operator-replaced path.
        return
    shutil.rmtree(display.root)


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # A process we cannot inspect is not safe to classify as orphaned.
        return True
    return True


def cleanup_orphaned_displays(state_dir: Path) -> None:
    """Remove a prior controller's private display directory when it is dead.

    Bubblewrap's ``--die-with-parent`` stops the application-side Xvfb and
    VNC bridge if a controller crashes. This best-effort sweep removes the
    remaining owner-only socket directory at the next launch without touching
    a session whose recorded controller PID is still alive.
    """
    displays_root = state_dir / "displays"
    try:
        root = displays_root.resolve(strict=True)
        entries = tuple(root.iterdir())
    except OSError:
        return
    for candidate in entries:
        try:
            if candidate.is_symlink() or not candidate.name.startswith("run-"):
                continue
            marker = candidate / SESSION_MARKER
            owner = candidate / OWNER_FILE
            marker_stat = marker.stat(follow_symlinks=False)
            owner_stat = owner.stat(follow_symlinks=False)
            data = json.loads(owner.read_text(encoding="ascii"))
            pid = data.get("pid")
            if (
                not stat.S_ISREG(marker_stat.st_mode)
                or not stat.S_ISREG(owner_stat.st_mode)
                or marker.read_text(encoding="ascii") != DISPLAY_MARKER_CONTENT
                or isinstance(pid, bool)
                or not isinstance(pid, int)
                or _pid_is_running(pid)
            ):
                continue
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            if resolved.stat(follow_symlinks=False).st_mode & 0o077:
                continue
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            continue
        shutil.rmtree(candidate)


def vnc_viewer_command(port: int) -> list[str]:
    """Return a standard local viewer command, or fail before app launch."""
    if not 1 <= port <= 65_535:
        raise DisplayError("VNC port is invalid")
    for name in ("vncviewer", "xtigervncviewer"):
        executable = shutil.which(name)
        if executable:
            candidate = Path(executable)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                # The port is allocated from a socket already bound to the
                # IPv4 loopback address. No URL or host input is accepted.
                return [str(candidate), f"127.0.0.1::{port}"]
    raise DisplayError("VNC display requires vncviewer or xtigervncviewer, but neither is installed")


def _stop_process(process: subprocess.Popen[object] | None, *, process_group: bool = True) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        if process_group:
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            if process_group:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=2)


class LocalVNCService:
    """Serve one private X display to local viewers for a single app run."""

    def __init__(
        self,
        display: PrivateDisplay,
        state_dir: Path,
        bridge_command: Sequence[str],
        viewer_command_factory=vnc_viewer_command,
    ) -> None:
        validate_private_display(display, state_dir)
        if not bridge_command:
            raise DisplayError("VNC bridge command is empty")
        self.display = display
        self.state_dir = state_dir
        self.bridge_command = list(bridge_command)
        self.viewer_command_factory = viewer_command_factory
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._children: set[subprocess.Popen[object]] = set()
        self._children_lock = threading.Lock()
        self._viewer: subprocess.Popen[object] | None = None
        self._log = None

    @property
    def port(self) -> int:
        if self._listener is None:
            raise DisplayError("VNC service has not been started")
        return int(self._listener.getsockname()[1])

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1::{self.port}"

    def start(self) -> None:
        if self._listener is not None:
            raise DisplayError("VNC service is already running")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(0.2)
            self._log = self.display.bridge_log.open("a", encoding="utf-8")
            os.chmod(self.display.bridge_log, 0o600)
        except OSError as exc:
            listener.close()
            raise DisplayError("cannot bind private loopback VNC endpoint") from exc
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, name="appsbx-vnc", daemon=True)
        self._thread.start()
        print(f"appsbx VNC: {self.endpoint} (loopback only)", file=sys.stderr, flush=True)

    def wait_for_xvfb(self, application: subprocess.Popen[object], timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                mode = self.display.socket_path.stat(follow_symlinks=False).st_mode
            except FileNotFoundError:
                mode = 0
            if stat.S_ISSOCK(mode):
                return
            if application.poll() is not None:
                raise DisplayError("application exited before its private Xvfb display became ready")
            time.sleep(0.05)
        raise DisplayError("private Xvfb display did not become ready")

    def open_viewer(self) -> None:
        if self._listener is None:
            raise DisplayError("VNC service has not been started")
        if self._viewer is not None:
            raise DisplayError("VNC viewer is already running")
        command = self.viewer_command_factory(self.port)
        try:
            self._viewer = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as exc:
            raise DisplayError("cannot start the local VNC viewer") from exc

    def _serve(self) -> None:
        listener = self._listener
        assert listener is not None
        while not self._stopping.is_set():
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                self._reap_children()
                continue
            except OSError:
                break
            # AF_INET and an explicit loopback bind should make this
            # redundant, but keep the defensive check if the socket is ever
            # refactored.
            if peer[0] != "127.0.0.1":
                connection.close()
                continue
            try:
                process = subprocess.Popen(
                    self.bridge_command,
                    stdin=connection,
                    stdout=connection,
                    stderr=self._log if self._log is not None else subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                )
                with self._children_lock:
                    self._children.add(process)
            except OSError:
                pass
            finally:
                connection.close()

    def _reap_children(self) -> None:
        with self._children_lock:
            self._children = {child for child in self._children if child.poll() is None}

    def stop(self) -> None:
        self._stopping.set()
        if self._listener is not None:
            try:
                self._listener.close()
            finally:
                self._listener = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        _stop_process(self._viewer, process_group=False)
        self._viewer = None
        with self._children_lock:
            children = tuple(self._children)
            self._children.clear()
        for child in children:
            _stop_process(child)
        if self._log is not None:
            self._log.close()
            self._log = None
        remove_private_display(self.display, self.state_dir)
