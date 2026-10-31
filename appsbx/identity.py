"""Persistent synthetic identity generation without host-derived inputs."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import secrets
import tempfile
import uuid

from .hardware import (
    HardwareProfile,
    generate_hardware,
    validate_hardware,
)
from .profile import Profile, ProfileError


# This marker lives beside (rather than inside) the directory mounted at
# /home/appsbx.  The sandboxed application can freely change its own home,
# but it cannot change the controller-owned state-directory marker used to
# authorize the one writable bind in real-network mode.
PROFILE_HOME_MARKER = ".appsbx-private-home"
PROFILE_HOME_MARKER_CONTENT = "appsbx private per-profile home\n"


@dataclass(frozen=True)
class Identity:
    profile_name: str
    machine_id: str
    boot_id: str
    hardware: HardwareProfile
    runtime_uid: int
    runtime_gid: int
    state_dir: Path
    hardware_identity_uuid: str

    @property
    def cpu_count(self) -> int:
        return self.hardware.logical_cpus

    @property
    def ram_mb(self) -> int:
        return self.hardware.ram_mb

    @property
    def hostname(self) -> str:
        return self.hardware.hostname

    @property
    def mac(self) -> str:
        return self.hardware.mac

    @property
    def files_dir(self) -> Path:
        return self.state_dir / "files"

    @property
    def home_dir(self) -> Path:
        """The initially empty, persistent home for this synthetic profile."""
        return self.state_dir / "home"

    def file_paths(self) -> dict[str, Path]:
        paths = {
            "/etc/machine-id": self.files_dir / "etc-machine-id",
            "/var/lib/dbus/machine-id": self.files_dir / "dbus-machine-id",
            "/run/machine-id": self.files_dir / "run-machine-id",
            "/etc/hostname": self.files_dir / "hostname",
            "/etc/hosts": self.files_dir / "hosts",
            "/etc/os-release": self.files_dir / "os-release",
            "/etc/passwd": self.files_dir / "passwd",
            "/etc/group": self.files_dir / "group",
            "/etc/nsswitch.conf": self.files_dir / "nsswitch.conf",
            "/etc/resolv.conf": self.files_dir / "resolv.conf",
            "/proc/cpuinfo": self.files_dir / "proc-cpuinfo",
            "/proc/meminfo": self.files_dir / "proc-meminfo",
            "/proc/stat": self.files_dir / "proc-stat",
            "/proc/uptime": self.files_dir / "proc-uptime",
            "/proc/loadavg": self.files_dir / "proc-loadavg",
            "/proc/version": self.files_dir / "proc-version",
            "/proc/cmdline": self.files_dir / "proc-cmdline",
            "/proc/partitions": self.files_dir / "proc-partitions",
            "/proc/diskstats": self.files_dir / "proc-diskstats",
            "/proc/modules": self.files_dir / "proc-modules",
            "/proc/interrupts": self.files_dir / "proc-interrupts",
            "/proc/swaps": self.files_dir / "proc-swaps",
            "/proc/sys/kernel/random/boot_id": self.files_dir / "boot-id",
            "/proc/sys/kernel/hostname": self.files_dir / "kernel-hostname",
            "/proc/sys/kernel/osrelease": self.files_dir / "kernel-osrelease",
            "/sys/devices/system/cpu/online": self.files_dir / "cpu-online",
            "/sys/devices/system/cpu/possible": self.files_dir / "cpu-possible",
            "/sys/devices/system/cpu/present": self.files_dir / "cpu-present",
            "/sys/class/dmi/id/sys_vendor": self.files_dir / "dmi-sys-vendor",
            "/sys/class/dmi/id/product_name": self.files_dir / "dmi-product-name",
            "/sys/class/dmi/id/product_version": self.files_dir / "dmi-product-version",
            "/sys/class/dmi/id/board_vendor": self.files_dir / "dmi-board-vendor",
            "/sys/class/dmi/id/board_name": self.files_dir / "dmi-board-name",
            "/sys/class/dmi/id/product_serial": self.files_dir / "dmi-product-serial",
            "/sys/class/dmi/id/product_uuid": self.files_dir / "dmi-product-uuid",
            "/sys/class/dmi/id/board_serial": self.files_dir / "dmi-board-serial",
            "/sys/class/dmi/id/chassis_serial": self.files_dir / "dmi-chassis-serial",
            "/sys/class/dmi/id/bios_vendor": self.files_dir / "dmi-bios-vendor",
            "/sys/class/dmi/id/bios_version": self.files_dir / "dmi-bios-version",
            "/sys/class/dmi/id/bios_date": self.files_dir / "dmi-bios-date",
            "/sys/block/vda/device/model": self.files_dir / "disk-model",
            "/sys/block/vda/device/serial": self.files_dir / "disk-serial",
            "/sys/block/vda/size": self.files_dir / "disk-size-sectors",
        }
        for index in range(self.cpu_count):
            paths.update({
                f"/sys/devices/system/cpu/cpu{index}/tsc_freq_khz": self.files_dir / f"cpu{index}-tsc-freq-khz",
                f"/sys/devices/system/cpu/cpu{index}/cpufreq/scaling_cur_freq": self.files_dir / f"cpu{index}-scaling-cur-freq",
                f"/sys/devices/system/cpu/cpu{index}/cpufreq/scaling_max_freq": self.files_dir / f"cpu{index}-scaling-max-freq",
            })
        return paths


def _atomic_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
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


def _new_identity(profile: Profile, state_dir: Path, hardware: HardwareProfile | None = None) -> Identity:
    hardware = hardware or generate_hardware("random")
    return Identity(
        profile_name=profile.name,
        machine_id=secrets.token_hex(16),
        boot_id=str(uuid.UUID(bytes=secrets.token_bytes(16))),
        hardware=hardware,
        runtime_uid=profile.runtime_uid,
        runtime_gid=profile.runtime_gid,
        state_dir=state_dir,
        hardware_identity_uuid=str(uuid.UUID(bytes=secrets.token_bytes(16))),
    )


def _identity_json(identity: Identity, profile: Profile, mode: str) -> str:
    return json.dumps({
        "version": 2,
        "identity_mode": mode,
        "profile_name": identity.profile_name,
        "profile_id": profile.profile_id,
        "machine_id": identity.machine_id,
        "boot_id": identity.boot_id,
        "hardware_identity_uuid": identity.hardware_identity_uuid,
        "runtime_uid": identity.runtime_uid,
        "runtime_gid": identity.runtime_gid,
        "hardware": identity.hardware.to_dict(),
    }, sort_keys=True, indent=2) + "\n"


def _identity_from_json(data: dict, profile: Profile, state_dir: Path) -> Identity:
    expected = {
        "profile_name": profile.name,
        "runtime_uid": profile.runtime_uid,
        "runtime_gid": profile.runtime_gid,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ProfileError(f"persisted identity does not match profile field: {key}")
    machine_id = data.get("machine_id")
    boot_id = data.get("boot_id")
    if not isinstance(machine_id, str) or len(machine_id) != 32 or any(c not in "0123456789abcdef" for c in machine_id):
        raise ProfileError("persisted machine-id is invalid")
    try:
        uuid.UUID(boot_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProfileError("persisted boot_id is invalid") from exc
    hardware_data = data.get("hardware")
    if isinstance(hardware_data, dict):
        try:
            hardware = HardwareProfile.from_dict(hardware_data)
        except ValueError as exc:
            raise ProfileError(str(exc)) from exc
    else:
        raise ProfileError("persisted hardware profile is invalid")
    hardware_uuid = data.get("hardware_identity_uuid")
    try:
        uuid.UUID(hardware_uuid)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProfileError("persisted hardware identity UUID is invalid") from exc
    return Identity(state_dir=state_dir, machine_id=machine_id, boot_id=boot_id, hardware=hardware,
                    hardware_identity_uuid=hardware_uuid, **expected)


def _migrate_v1_identity(
    data: dict, raw: str, profile: Profile, state_dir: Path, identity_path: Path,
) -> Identity:
    """Upgrade an old field-only record without touching profile application data."""
    if data.get("version") != 1 or "hardware" in data:
        raise ProfileError("persisted identity is not a migratable version-1 record")
    expected = {
        "profile_name": profile.name,
        "runtime_uid": profile.runtime_uid,
        "runtime_gid": profile.runtime_gid,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ProfileError(f"persisted identity does not match profile field: {key}")
    machine_id = data.get("machine_id")
    boot_id = data.get("boot_id")
    if not isinstance(machine_id, str) or len(machine_id) != 32 or any(c not in "0123456789abcdef" for c in machine_id):
        raise ProfileError("legacy machine-id is invalid")
    try:
        uuid.UUID(boot_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProfileError("legacy boot_id is invalid") from exc

    hardware = generate_hardware("random")
    hostname = data.get("hostname")
    mac = data.get("mac")
    if isinstance(hostname, str) and hostname and len(hostname) <= 63:
        hardware = replace(hardware, hostname=hostname.lower())
    if isinstance(mac, str):
        hardware = replace(hardware, mac=mac.lower())
    try:
        validate_hardware(hardware)
    except ValueError as exc:
        raise ProfileError("legacy identity contains an unsafe hostname or MAC") from exc
    identity = Identity(
        profile_name=profile.name, machine_id=machine_id, boot_id=boot_id,
        hardware=hardware, runtime_uid=profile.runtime_uid,
        runtime_gid=profile.runtime_gid, state_dir=state_dir,
        hardware_identity_uuid=str(uuid.UUID(bytes=secrets.token_bytes(16))),
    )
    backup = identity_path.with_name("identity.v1.json.bak")
    if backup.exists():
        try:
            if backup.read_text(encoding="utf-8") != raw:
                raise ProfileError("legacy identity backup already exists and differs")
        except OSError as exc:
            raise ProfileError("legacy identity backup is unavailable") from exc
    else:
        _atomic_text(backup, raw)
    _atomic_text(identity_path, _identity_json(identity, profile, "persistent"))
    return identity


def _render_files(identity: Identity, profile: Profile) -> dict[str, str]:
    cpu_lines = []
    for index in range(identity.cpu_count):
        # Keep Linux's topology fields coherent with the persisted platform:
        # one package, physical cores repeated for SMT threads.  This is a
        # synthetic file view only; the actual scheduler topology remains a
        # kernel property and is documented separately.
        core_index = index % identity.hardware.physical_cores
        cpu_lines.extend([
            f"processor\t: {index}\n", f"vendor_id\t: {identity.hardware.cpu_vendor}\n",
            f"cpu family\t: {identity.hardware.cpu_family}\n", f"model\t\t: {identity.hardware.cpu_model_id}\n",
            f"model name\t: {identity.hardware.cpu_model}\n", f"stepping\t: {identity.hardware.cpu_stepping}\n",
            f"cpu MHz\t\t: {identity.hardware.cpu_mhz:.3f}\n", f"cache size\t: {identity.hardware.cache_kb} KB\n",
            f"physical id\t: 0\n", f"siblings\t: {identity.cpu_count}\n",
            f"core id\t\t: {core_index}\n",
            f"cpu cores\t: {identity.hardware.physical_cores}\n",
            "flags\t\t: appsbx\n", "\n",
        ])
    mem_kib = identity.ram_mb * 1024
    proc_stat = "cpu  " + " ".join([str(identity.cpu_count * 100)] + ["0"] * 9) + "\n"
    proc_stat += "".join(
        f"cpu{index} " + " ".join(["100"] + ["0"] * 9) + "\n"
        for index in range(identity.cpu_count)
    )
    proc_stat += "intr 0\nctxt 0\nbtime 0\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n"
    files = {
        "etc-machine-id": identity.machine_id + "\n",
        "dbus-machine-id": identity.machine_id + "\n",
        "run-machine-id": identity.machine_id + "\n",
        "hostname": identity.hostname + "\n",
        "hosts": f"127.0.0.1 localhost {identity.hostname}\n::1 localhost {identity.hostname}\n",
        "os-release": 'NAME="Linux"\nID=linux\nPRETTY_NAME="Linux"\n',
        "passwd": f"root:x:0:0:appsbx root:/root:/bin/sh\nappsbx:x:{identity.runtime_uid}:{identity.runtime_gid}:appsbx user:/home/appsbx:/bin/sh\n",
        "group": f"root:x:0:\nappsbx:x:{identity.runtime_gid}:\n",
        "nsswitch.conf": "passwd: files\ngroup: files\nhosts: files dns\n",
        "resolv.conf": "# appsbx stub: configured by the selected network backend\n",
        "proc-cpuinfo": "".join(cpu_lines),
        "proc-meminfo": f"MemTotal:       {mem_kib} kB\nMemFree:        {mem_kib // 2} kB\nMemAvailable:   {mem_kib // 2} kB\nBuffers:            0 kB\nCached:             0 kB\n",
        "proc-stat": proc_stat,
        "proc-uptime": "0.00 0.00\n",
        "proc-loadavg": "0.00 0.00 0.00 1/1 1\n",
        "proc-version": "Linux version appsbx-synthetic (appsbx) #1 SMP\n",
        "proc-cmdline": "appsbx\n",
        "proc-partitions": "major minor  #blocks  name\n",
        "proc-diskstats": "",
        "proc-modules": "",
        "proc-interrupts": "           CPU0\n",
        "proc-swaps": "Filename\t\t\tType\t\tSize\tUsed\tPriority\n",
        "boot-id": identity.boot_id + "\n",
        "kernel-hostname": identity.hostname + "\n",
        "kernel-osrelease": "appsbx-synthetic\n",
        "cpu-online": f"0-{identity.cpu_count - 1}\n",
        "cpu-possible": f"0-{identity.cpu_count - 1}\n",
        "cpu-present": f"0-{identity.cpu_count - 1}\n",
        "dmi-sys-vendor": identity.hardware.bios_vendor + "\n",
        "dmi-product-name": identity.hardware.platform + "\n",
        "dmi-product-version": identity.hardware.catalog_id + "\n",
        "dmi-board-vendor": identity.hardware.bios_vendor + "\n",
        "dmi-board-name": identity.hardware.motherboard + "\n",
        "dmi-product-serial": identity.hardware.system_serial + "\n",
        "dmi-product-uuid": identity.hardware_identity_uuid + "\n",
        "dmi-board-serial": identity.hardware.board_serial + "\n",
        "dmi-chassis-serial": identity.hardware.chassis_serial + "\n",
        "dmi-bios-vendor": identity.hardware.bios_vendor + "\n",
        "dmi-bios-version": identity.hardware.bios_version + "\n",
        "dmi-bios-date": identity.hardware.bios_date + "\n",
        "disk-model": identity.hardware.disk_model + "\n",
        "disk-serial": identity.hardware.disk_serial + "\n",
        "disk-size-sectors": str(identity.hardware.disk_size_mb * 2048) + "\n",
    }
    for index in range(identity.cpu_count):
        frequency_khz = identity.hardware.cpu_mhz * 1000
        files[f"cpu{index}-tsc-freq-khz"] = f"{frequency_khz}\n"
        files[f"cpu{index}-scaling-cur-freq"] = f"{frequency_khz}\n"
        files[f"cpu{index}-scaling-max-freq"] = f"{frequency_khz}\n"
    return files


def ensure_profile_home(identity: Identity) -> Path:
    """Create and validate the profile-private writable home directory.

    This is intentionally a fresh directory per profile; no host HOME,
    browser profile, keyring, or application data is copied into it.  It lets
    an application retain only the data it creates while running in this
    profile (including an authentication session it obtains itself).
    """
    state_dir = identity.state_dir
    try:
        state_info = state_dir.stat(follow_symlinks=False)
    except OSError as exc:
        raise ProfileError("profile state directory is unavailable") from exc
    if state_dir.is_symlink() or not state_dir.is_dir() or state_info.st_mode & 0o077:
        raise ProfileError("profile state directory has unsafe permissions")
    marker = state_dir / PROFILE_HOME_MARKER
    if marker.exists():
        try:
            marker_info = marker.stat(follow_symlinks=False)
        except OSError as exc:
            raise ProfileError("profile-home marker is unavailable") from exc
        if (
            marker.is_symlink()
            or not marker.is_file()
            or marker_info.st_mode & 0o077
        ):
            raise ProfileError("profile-home marker is unsafe")
        try:
            marker_content = marker.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise ProfileError("profile-home marker is unavailable") from exc
        if marker_content != PROFILE_HOME_MARKER_CONTENT:
            raise ProfileError("profile-home marker is unsafe")
    else:
        _atomic_text(marker, PROFILE_HOME_MARKER_CONTENT)

    home = identity.home_dir
    try:
        home.mkdir(mode=0o700)
    except FileExistsError:
        pass
    try:
        home_info = home.stat(follow_symlinks=False)
    except OSError as exc:
        raise ProfileError("profile-private home is unavailable") from exc
    if home.is_symlink() or not home.is_dir() or home_info.st_mode & 0o077:
        raise ProfileError("profile-private home has unsafe permissions")
    os.chmod(home, 0o700)
    return home


def ensure_identity(profile: Profile, state_root: Path) -> Identity:
    state_dir = state_root / profile.name
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    identity_path = state_dir / "identity.json"
    if identity_path.exists():
        try:
            raw_identity = identity_path.read_text(encoding="utf-8")
            data = json.loads(raw_identity)
        except (OSError, ValueError) as exc:
            raise ProfileError(f"invalid persisted identity for {profile.name}") from exc
        if data.get("version") == 1 and "hardware" not in data:
            identity = _migrate_v1_identity(data, raw_identity, profile, state_dir, identity_path)
        else:
            identity = _identity_from_json(data, profile, state_dir)
    else:
        identity = _new_identity(profile, state_dir)
        _atomic_text(identity_path, _identity_json(identity, profile, "persistent"))
    files_dir = identity.files_dir
    files_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    rendered = _render_files(identity, profile)
    for key, value in rendered.items():
        target = files_dir / key
        try:
            current = target.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError, OSError):
            current = None
        if current != value:
            _atomic_text(target, value)
    ensure_profile_home(identity)
    return identity


def create_auto_identity(profile: Profile, state_root: Path, hardware_class: str = "random") -> Identity:
    """Create a fresh, isolated identity directory for one launch."""
    if hardware_class not in ("laptop", "desktop", "gaming-desktop", "workstation", "random"):
        raise ProfileError("invalid hardware class")
    auto_root = state_root / ".auto"
    auto_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(auto_root, 0o700)
    for _ in range(32):
        state_dir = auto_root / f"{profile.name}-{secrets.token_hex(12)}"
        try:
            state_dir.mkdir(mode=0o700)
        except FileExistsError:
            continue
        identity = _new_identity(profile, state_dir, generate_hardware(hardware_class))
        _atomic_text(state_dir / "identity.json", json.dumps({
            "version": 2,
            "identity_mode": "auto",
            "profile_name": identity.profile_name,
            "profile_id": profile.profile_id,
            "machine_id": identity.machine_id,
            "boot_id": identity.boot_id,
            "hardware_identity_uuid": identity.hardware_identity_uuid,
            "runtime_uid": identity.runtime_uid,
            "runtime_gid": identity.runtime_gid,
            "hardware": identity.hardware.to_dict(),
        }, sort_keys=True, indent=2) + "\n")
        files_dir = identity.files_dir
        files_dir.mkdir(mode=0o700)
        for key, value in _render_files(identity, profile).items():
            _atomic_text(files_dir / key, value)
        ensure_profile_home(identity)
        return identity
    raise ProfileError("could not allocate a unique automatic identity state directory")


def ensure_generated_identity(profile: Profile, state_dir: Path, hardware_class: str = "random") -> Identity:
    """Create or reload one persistent generated identity at an exact path.

    This is used by the desktop controller, which owns a directory per named
    instance rather than the CLI's one-shot automatic identity directories.
    """
    if hardware_class not in ("laptop", "desktop", "gaming-desktop", "workstation", "random"):
        raise ProfileError("invalid hardware class")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    identity_path = state_dir / "identity.json"
    if identity_path.exists():
        try:
            data = json.loads(identity_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProfileError("invalid generated identity") from exc
        identity = _identity_from_json(data, profile, state_dir)
    else:
        identity = _new_identity(profile, state_dir, generate_hardware(hardware_class))
        _atomic_text(identity_path, json.dumps({
            "version": 2,
            "identity_mode": "auto",
            "profile_name": identity.profile_name,
            "profile_id": profile.profile_id,
            "machine_id": identity.machine_id,
            "boot_id": identity.boot_id,
            "hardware_identity_uuid": identity.hardware_identity_uuid,
            "runtime_uid": identity.runtime_uid,
            "runtime_gid": identity.runtime_gid,
            "hardware": identity.hardware.to_dict(),
        }, sort_keys=True, indent=2) + "\n")
    return _materialize_generated_identity(identity, profile)


def _materialize_generated_identity(identity: Identity, profile: Profile) -> Identity:
    files_dir = identity.files_dir
    files_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for key, value in _render_files(identity, profile).items():
        target = files_dir / key
        try:
            current = target.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError, OSError):
            current = None
        if current != value:
            _atomic_text(target, value)
    ensure_profile_home(identity)
    return identity


def identity_report(identity: Identity) -> dict:
    hardware = identity.hardware.to_dict()
    return {
        "profile": identity.profile_name,
        "state_dir": str(identity.state_dir),
        "machine_id": identity.machine_id,
        "boot_id": identity.boot_id,
        "hardware": hardware,
        "consistency": {
            "logical_cpus_match": hardware["logical_cpus"] == identity.cpu_count,
            "ram_file_matches": identity.file_paths()["/proc/meminfo"].read_text().startswith(f"MemTotal:       {identity.ram_mb * 1024} kB"),
            "hostname_file_matches": identity.file_paths()["/etc/hostname"].read_text().strip() == hardware["hostname"],
            "mac_is_local_unicast": not (int(hardware["mac"][:2], 16) & 1) and bool(int(hardware["mac"][:2], 16) & 2),
        },
    }


def load_identity_for_inspection(profile: Profile, state_dir: Path) -> Identity:
    """Load an existing persistent or automatic identity without creating it."""
    try:
        data = json.loads((state_dir / "identity.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProfileError("cannot read identity state for inspection") from exc
    return _identity_from_json(data, profile, state_dir)
