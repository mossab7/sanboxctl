"""Persistent instance records for the desktop controller.

This module owns only GUI metadata and per-instance identity directories. It
does not create namespaces or launch applications; those operations stay in
the existing CLI/runtime and privileged network helper.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from .identity import Identity, ensure_generated_identity
from .network import (
    DEFAULT_EGRESS_DIR,
    EgressDefinition,
    _live_interface_definition,
    discover_dynamic_egresses,
    load_egress_definition,
)
from .paths import PROJECT_ROOT, state_root
from .profile import Profile, ProfileError, load_profiles
from .rootfs import extract_appimage, inspect_appimage


INSTANCE_MARKER = ".appsbx-managed-instance"
INSTANCE_MARKER_CONTENT = "appsbx managed GUI instance\n"
INSTANCE_ID_MIN = 2
INSTANCE_ID_MAX = 253
GUI_STATE = state_root() / "gui-instances"
BUNDLED_APP_ROOT = PROJECT_ROOT / "apps" / "zaap.AppDir"


@dataclass
class InstanceRecord:
    key: str
    name: str
    profile_name: str
    profile_id: int
    network: str
    created_at: str
    display_backend: str = "isolated"
    state: str = "Stopped"
    pid: int | None = None
    vnc_endpoint: str | None = None
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "InstanceRecord":
        try:
            values = dict(data)
            # Metadata written before display selection was introduced uses
            # the safer private Xvfb/VNC backend.
            values.setdefault("display_backend", "isolated")
            record = cls(**values)
        except (TypeError, ValueError) as exc:
            raise ProfileError("invalid GUI instance metadata") from exc
        if not uuid.UUID(record.key) or not record.name or not record.profile_name:
            raise ProfileError("invalid GUI instance metadata")
        if not INSTANCE_ID_MIN <= record.profile_id <= INSTANCE_ID_MAX:
            raise ProfileError("GUI instance profile id is outside the managed range")
        if record.state not in {"Running", "Stopped", "Starting", "Error"}:
            raise ProfileError("invalid GUI instance state")
        if record.display_backend not in {"isolated", "host"}:
            raise ProfileError("invalid GUI display backend")
        if record.pid is not None and (isinstance(record.pid, bool) or record.pid <= 0):
            raise ProfileError("invalid GUI instance PID")
        return record


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class InstanceStore:
    """Owner-only persistent records and directories for GUI instances."""

    def __init__(self, root: Path, profiles_dir: Path, base_profile: Profile):
        self.root = root.resolve()
        self.profiles_dir = profiles_dir.resolve()
        self.base_profile = base_profile
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.metadata_path = self.root / "instances.json"

    def _instance_dir(self, key: str) -> Path:
        try:
            parsed = uuid.UUID(key)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ProfileError("invalid instance identifier") from exc
        path = (self.root / str(parsed)).resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ProfileError("instance path escapes managed state") from exc
        return path

    def _read(self) -> list[InstanceRecord]:
        if not self.metadata_path.exists():
            return []
        try:
            raw = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            records = [InstanceRecord.from_dict(item) for item in raw]
        except (OSError, ValueError, TypeError) as exc:
            raise ProfileError("cannot read GUI instance metadata") from exc
        keys = [item.key for item in records]
        ids = [item.profile_id for item in records]
        if len(set(keys)) != len(keys) or len(set(ids)) != len(ids):
            raise ProfileError("GUI instance metadata contains duplicate identifiers")
        return records

    def list(self) -> list[InstanceRecord]:
        return sorted(self._read(), key=lambda item: item.created_at)

    def save(self, records: list[InstanceRecord]) -> None:
        _atomic_json(self.metadata_path, [asdict(item) for item in records])

    def update(self, record: InstanceRecord) -> None:
        records = self._read()
        for index, item in enumerate(records):
            if item.key == record.key:
                records[index] = record
                self.save(records)
                return
        raise ProfileError("GUI instance does not exist")

    def profile_for(self, record: InstanceRecord) -> Profile:
        return replace(
            self.base_profile,
            name=record.profile_name,
            profile_id=record.profile_id,
        )

    def identity_dir(self, record: InstanceRecord) -> Path:
        path = self._instance_dir(record.key) / "identity"
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ProfileError("identity path escapes managed state") from exc
        return path

    def ensure_identity(self, record: InstanceRecord) -> Identity:
        return ensure_generated_identity(self.profile_for(record), self.identity_dir(record), "random")

    def create(self, network: str) -> InstanceRecord:
        records = self._read()
        configured_ids = {item.profile_id for item in load_profiles(self.profiles_dir).values()}
        used_ids = configured_ids | {item.profile_id for item in records}
        available = [item for item in range(INSTANCE_ID_MIN, INSTANCE_ID_MAX + 1) if item not in used_ids]
        if not available:
            raise ProfileError("no instance slots remain")
        if load_egress_definition(network, DEFAULT_EGRESS_DIR).name != network:
            raise ProfileError("selected network is not available")
        key = str(uuid.uuid4())
        instance_dir = self._instance_dir(key)
        instance_dir.mkdir(mode=0o700)
        (instance_dir / INSTANCE_MARKER).write_text(INSTANCE_MARKER_CONTENT, encoding="ascii")
        os.chmod(instance_dir / INSTANCE_MARKER, 0o600)
        profile_id = available[0]
        record = InstanceRecord(
            key=key,
            name=f"Zaap {len(records) + 1}",
            profile_name=f"{self.base_profile.name}-i{profile_id}",
            profile_id=profile_id,
            network=network,
            created_at=datetime.now(timezone.utc).isoformat(),
            display_backend="host",
        )
        self.ensure_identity(record)
        self.save(records + [record])
        return record

    def delete(self, record: InstanceRecord) -> None:
        instance_dir = self._instance_dir(record.key)
        marker = instance_dir / INSTANCE_MARKER
        try:
            if marker.read_text(encoding="ascii") != INSTANCE_MARKER_CONTENT:
                raise ProfileError("managed instance marker is invalid")
            if instance_dir.stat().st_mode & 0o077 or marker.stat().st_mode & 0o077:
                raise ProfileError("managed instance permissions are unsafe")
        except OSError as exc:
            raise ProfileError("managed instance directory is unavailable") from exc
        records = [item for item in self._read() if item.key != record.key]
        if len(records) == len(self._read()):
            raise ProfileError("GUI instance does not exist")
        self.save(records)
        shutil.rmtree(instance_dir)


def discover_egresses(directory: Path = DEFAULT_EGRESS_DIR) -> list[tuple[str, str]]:
    """Return configured and currently live egresses as (name, label).

    ``auto-*`` entries are ephemeral and are not written to configuration or
    persisted as identities.  They are revalidated at launch time.
    """
    result: list[tuple[str, str]] = []
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob("*.conf")):
        try:
            definition: EgressDefinition = load_egress_definition(path.stem, directory)
        except Exception:
            continue
        # A configured gateway is only valid while it is still connected to
        # the named interface.  DHCP networks can change gateways, so do not
        # present a stale entry that will inevitably fail in the privileged
        # helper.  The live interface will be offered below as auto-<name>.
        if definition.gateway is not None:
            live = _live_interface_definition(definition.interface)
            if live is None or live.gateway != definition.gateway:
                continue
        raw = path.read_text(encoding="utf-8").lower()
        if "type=vpn" in raw:
            kind = "VPN"
        elif "type=usb" in raw:
            kind = "USB tether"
        elif "type=physical" in raw or definition.interface.startswith(("eth", "enp", "eno")):
            kind = "Ethernet"
        else:
            kind = "Wi-Fi"
        display_name = "Wi-Fi" if definition.name.lower() in {"wifi", "wlan"} else definition.name.replace("_", " ").title()
        result.append((definition.name, f"{display_name} ({kind}: {definition.interface})"))
    configured_interfaces = {load_egress_definition(name, directory).interface for name, _ in result}
    for definition in discover_dynamic_egresses():
        if definition.interface in configured_interfaces:
            continue
        result.append((definition.name, f"{definition.interface} (detected interface)"))
    return result


def active_interface_users(record: InstanceRecord, records: list[InstanceRecord],
                           directory: Path = DEFAULT_EGRESS_DIR) -> list[InstanceRecord]:
    """Find active instances sharing the selected record's resolved interface."""
    try:
        selected = load_egress_definition(record.network, directory).interface
    except Exception:
        return []
    users: list[InstanceRecord] = []
    for other in records:
        if other.key == record.key or other.state not in {"Running", "Starting"}:
            continue
        try:
            interface = load_egress_definition(other.network, directory).interface
        except Exception:
            continue
        if interface == selected:
            users.append(other)
    return users


def _validate_app_root(root: Path, description: str) -> Path:
    root = root.resolve()
    executable = root / "zaap"
    if not root.is_dir() or not executable.is_file():
        raise ProfileError(
            f"{description} does not contain the Zaap executable: {root}"
        )
    if not os.access(executable, os.X_OK):
        raise ProfileError(f"Zaap executable is not executable: {executable}")
    return root


def instance_app_root(explicit: str | Path | None = None) -> Path:
    """Resolve and validate the AppDir used by the CLI and GUI.

    The checked-in/project-managed ``apps/zaap.AppDir`` is the default and is
    resolved from this module's location, not from the caller's cwd. An
    explicit argument is authoritative. The two environment variables remain
    supported as compatibility overrides for existing integrations, but are
    no longer required.
    """
    if explicit is not None:
        raw = str(explicit)
        if not raw.strip():
            raise ProfileError("--app-root cannot be empty")
    else:
        raw = os.environ.get("APPSBX_APP_ROOT") or os.environ.get("APPDIR")
    if raw:
        return _validate_app_root(Path(raw), "configured Zaap AppDir")

    if BUNDLED_APP_ROOT.exists():
        return _validate_app_root(BUNDLED_APP_ROOT, "bundled Zaap AppDir")

    # Keep migration compatibility for worktrees created before apps/zaap.AppDir
    # was introduced. These paths are not used when the managed bundle exists.
    extracted_candidates = (
        PROJECT_ROOT.parent / "dofus.AppDir",
        PROJECT_ROOT / "dofus.AppDir",
    )
    for candidate in extracted_candidates:
        if candidate.is_dir() and (candidate / "zaap").is_file():
            return _validate_app_root(candidate, "legacy extracted Zaap AppDir")

    appimage = PROJECT_ROOT.parent / "dofus"
    if not appimage.is_file():
        raise ProfileError(
            f"bundled Zaap AppDir is missing or incomplete: {BUNDLED_APP_ROOT}. "
            "Restore apps/zaap.AppDir or use --app-root with an extracted AppDir."
        )
    # Extraction is unprivileged and occurs only below managed GUI state. A
    # temporary sibling plus atomic rename prevents a partial AppDir from
    # being reused after an interrupted extraction.
    extraction_root = GUI_STATE / "app-root"
    target = extraction_root / "dofus.AppDir"
    if target.is_dir() and (target / "zaap").is_file():
        return _validate_app_root(target, "extracted Zaap AppDir")
    extraction_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(extraction_root, 0o700)
    try:
        inspect_appimage(appimage)
    except Exception as exc:
        raise ProfileError(f"fixed dofus AppImage is invalid: {exc}") from exc
    temporary = Path(tempfile.mkdtemp(prefix=".dofus.AppDir-", dir=extraction_root))
    try:
        extract_appimage(appimage, temporary)
        if not (temporary / "zaap").is_file():
            raise ProfileError("extracted dofus AppImage has no zaap executable")
        os.replace(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target.resolve()
