"""Bubblewrap command construction; execution is opt-in and unprivileged."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import Sequence

from .elf import RuntimeBundle, VNCBundle
from .identity import Identity, ensure_profile_home
from .network import NetworkPlan
from .profile import Profile


@dataclass
class LaunchPlan:
    argv: list[str]
    pass_fds: tuple[int, ...]
    identity_files: dict[str, Path]
    network_mode: str
    runtime_root: Path | None = None
    network_plan: NetworkPlan | None = None


IDENTITY_DESTINATIONS = (
    "/etc/machine-id", "/var/lib/dbus/machine-id", "/run/machine-id",
    "/etc/hostname", "/etc/hosts", "/etc/os-release", "/etc/passwd",
    "/etc/group", "/etc/nsswitch.conf", "/etc/resolv.conf",
    "/proc/cpuinfo", "/proc/meminfo", "/proc/stat", "/proc/uptime",
    "/proc/loadavg", "/proc/version", "/proc/cmdline", "/proc/partitions",
    "/proc/diskstats", "/proc/modules", "/proc/interrupts", "/proc/swaps",
    "/proc/sys/kernel/random/boot_id", "/proc/sys/kernel/hostname",
    "/proc/sys/kernel/osrelease", "/sys/devices/system/cpu/online",
    "/sys/devices/system/cpu/possible", "/sys/devices/system/cpu/present",
    "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/product_version", "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/board_name", "/sys/class/dmi/id/bios_vendor",
    "/sys/class/dmi/id/bios_version", "/sys/class/dmi/id/bios_date",
    "/sys/block/vda/device/model", "/sys/block/vda/device/serial", "/sys/block/vda/size",
)


def _identity_destinations(cpu_count: int) -> tuple[str, ...]:
    cpu_files = tuple(
        path
        for index in range(cpu_count)
        for path in (
            f"/sys/devices/system/cpu/cpu{index}/tsc_freq_khz",
            f"/sys/devices/system/cpu/cpu{index}/cpufreq/scaling_cur_freq",
            f"/sys/devices/system/cpu/cpu{index}/cpufreq/scaling_max_freq",
        )
    )
    return IDENTITY_DESTINATIONS + cpu_files


def _minimal_host_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def _dest_parent_args(cpu_count: int) -> list[str]:
    args = [
        "--dir", "/etc", "--dir", "/var", "--dir", "/var/lib", "--dir", "/var/lib/dbus",
        "--tmpfs", "/run", "--dir", "/run/appsbx", "--tmpfs", "/home", "--dir", "/home/appsbx", "--dir", "/opt",
        "--dir", "/opt/app", "--tmpfs", "/tmp", "--tmpfs", "/sys", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/dev/shm",
        "--dir", "/sys/devices", "--dir", "/sys/devices/system", "--dir", "/sys/devices/system/cpu",
        "--dir", "/sys/class", "--dir", "/sys/class/dmi", "--dir", "/sys/class/dmi/id",
        "--dir", "/sys/block", "--dir", "/sys/block/vda", "--dir", "/sys/block/vda/device",
        "--dir", "/usr", "--dir", "/lib", "--dir", "/lib64",
    ]
    for index in range(cpu_count):
        args.extend([
            "--dir", f"/sys/devices/system/cpu/cpu{index}",
            "--dir", f"/sys/devices/system/cpu/cpu{index}/cpufreq",
        ])
    return args


def _runtime_mount_args(runtime_root: Path) -> list[str]:
    mounts: list[str] = []
    for relative, destination in (
        ("bin", "/bin"), ("lib", "/lib"), ("lib64", "/lib64"), ("usr", "/usr"),
        # Do not mount a read-only /opt over the /opt/app destination created
        # for the payload.  The private browser is mounted only at its own
        # nested path, leaving the independently read-only AppDir intact.
        ("opt/google", "/opt/google"),
    ):
        source = runtime_root / relative
        if source.is_dir():
            mounts.extend(["--ro-bind", str(source), destination])
    if not mounts:
        raise ValueError("runtime dependency bundle has no staged library directories")
    return mounts


def _compatibility_mount_args(runtime_root: Path) -> list[str]:
    """Mount generated compatibility policy, never host desktop settings."""
    policies = (
        ("appsbx-fonts.conf", "fonts.conf", "FONTCONFIG_FILE"),
        ("appsbx-alsa.conf", "alsa.conf", "ALSA_CONFIG_PATH"),
    )
    args: list[str] = []
    present = [item for item in policies if (runtime_root / "etc" / item[0]).is_file()]
    if not present:
        return args
    args.extend(["--dir", "/etc/appsbx"])
    for source_name, destination_name, variable in present:
        args.extend([
            "--ro-bind", str(runtime_root / "etc" / source_name), f"/etc/appsbx/{destination_name}",
            "--setenv", variable, f"/etc/appsbx/{destination_name}",
        ])
    return args


def prepare_plan(
    profile: Profile,
    identity: Identity,
    app_root: Path,
    app_command: Sequence[str],
    network_mode: str = "stub",
    runtime_bundle: RuntimeBundle | None = None,
    display_backend: str = "none",
    network_plan: NetworkPlan | None = None,
    resolv_conf: Path | None = None,
    display_socket_dir: Path | None = None,
    display_number: int = 99,
) -> LaunchPlan:
    if network_mode not in {"stub", "real"}:
        raise ValueError("network_mode must be stub or real")
    if display_backend not in {"none", "xvfb"}:
        raise ValueError("display_backend must be none or xvfb")
    if not 0 <= display_number <= 65_535:
        raise ValueError("private X display number is invalid")
    if not app_command:
        raise ValueError("application command cannot be empty")
    if not app_root.is_dir():
        raise ValueError("app_root must be an extracted, read-only application directory")
    if runtime_bundle is None or not runtime_bundle.root.is_dir():
        raise ValueError("runtime dependency bundle is required")
    if network_mode == "real" and network_plan is not None and network_plan.mode != "real":
        raise ValueError("real runtime requires a real network plan")
    if network_plan is not None and network_plan.profile_id != profile.profile_id:
        raise ValueError("network plan profile does not match runtime profile")
    if network_mode == "real" and network_plan is not None and network_plan.names.netns == "":
        raise ValueError("real network plan has no namespace")
    if resolv_conf is not None and not resolv_conf.is_file():
        raise ValueError("private resolver configuration is missing")
    if display_backend == "xvfb":
        if runtime_bundle.display_script is None or not runtime_bundle.display_script.is_file():
            raise ValueError("xvfb display backend is unavailable in the runtime bundle")
        try:
            runtime_bundle.display_script.resolve().relative_to(runtime_bundle.root.resolve())
        except ValueError as exc:
            raise ValueError("xvfb helper must be inside the private runtime bundle") from exc
    if display_socket_dir is not None:
        try:
            socket_dir = display_socket_dir.resolve(strict=True)
        except OSError as exc:
            raise ValueError("private X11 socket directory is missing") from exc
        if not socket_dir.is_dir() or socket_dir.is_symlink():
            raise ValueError("private X11 socket directory is invalid")
    else:
        socket_dir = None

    argv = [
        "bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--cap-drop", "ALL",
        "--clearenv", "--hostname", identity.hostname,
    ]
    # Xvfb does not require root when it uses the private /tmp/.X11-unix
    # created inside this mount namespace.  Keep the display server and the
    # application at the configured synthetic UID/GID so Electron's own
    # sandbox remains usable and the target never starts as root.
    argv.extend(["--uid", str(identity.runtime_uid), "--gid", str(identity.runtime_gid)])
    if network_mode == "stub":
        argv.append("--unshare-net")
    argv.extend(_dest_parent_args(identity.cpu_count))
    if socket_dir is not None:
        # This is a per-run, owner-only directory created by display.py. It
        # contains only the sandbox's Xvfb socket; no host X11 socket is ever
        # mounted into the application namespace.
        argv.extend(["--dir", "/tmp/.X11-unix", "--bind", str(socket_dir), "/tmp/.X11-unix"])
    profile_home = ensure_profile_home(identity).resolve()
    runtime_root = runtime_bundle.root
    argv.extend(_runtime_mount_args(runtime_root))
    argv.extend(_compatibility_mount_args(runtime_root))
    # The payload is read-only. Its source path is intentionally kept out of
    # generated reports; mountinfo exposure remains a documented residual until
    # the pinned minimal-rootfs backend is implemented.
    argv.extend(["--ro-bind", str(app_root), "/opt/app"])
    argv.extend([
        # The one writable host-backed directory is the controller-created,
        # profile-private home. It starts empty and never contains copied host
        # credentials, configuration, browser data, or identity files.
        "--bind", str(profile_home), "/home/appsbx",
        "--setenv", "HOME", "/home/appsbx", "--setenv", "USER", "appsbx",
        "--setenv", "LOGNAME", "appsbx", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "LANG", profile.locale, "--setenv", "LC_ALL", profile.locale,
        "--setenv", "TZ", profile.timezone, "--setenv", "XDG_RUNTIME_DIR", "/run/appsbx",
        "--setenv", "XDG_CONFIG_HOME", "/home/appsbx/.config",
        "--setenv", "XDG_CACHE_HOME", "/home/appsbx/.cache", "--setenv", "XDG_DATA_HOME", "/home/appsbx/.local/share",
        # Keep GLib settings self-contained.  In particular, do not let it
        # seek a host dconf database or session bus while initializing GTK.
        "--setenv", "GSETTINGS_BACKEND", "memory", "--setenv", "GIO_USE_VFS", "local",
        # These are deliberately non-existent paths inside the private /run
        # tmpfs. They prevent GLib/Chromium from consulting an inherited host
        # bus while making the no-desktop-service policy explicit.
        "--setenv", "DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/appsbx/disabled-session-bus",
        "--setenv", "DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/appsbx/disabled-system-bus",
        "--setenv", "NO_AT_BRIDGE", "1",
        "--setenv", "APPSBX_EXEC_UID", str(identity.runtime_uid),
        "--setenv", "APPSBX_EXEC_GID", str(identity.runtime_gid),
        "--setenv", "XKB_CONFIG_ROOT", "/usr/share/X11/xkb",
        "--setenv", "XLOCALEDIR", "/usr/share/X11/locale",
        "--chdir", "/home/appsbx", "--",
    ])
    if display_backend == "xvfb":
        # The helper and X server run inside this same mount/PID/network
        # boundary.  No host DISPLAY, Wayland socket, or Xauthority is used.
        separator = argv.index("--")
        argv[separator:separator] = [
            "--setenv", "DISPLAY", f":{display_number}",
            "--setenv", "APPSBX_X_DISPLAY", f":{display_number}",
            "--setenv", "LIBGL_ALWAYS_SOFTWARE", "1",
        ]
        argv.extend(["/usr/bin/appsbx-xvfb-exec", *app_command])
    else:
        argv.extend(app_command)

    identity_files: dict[str, Path] = {}
    paths = identity.file_paths()
    for destination in _identity_destinations(identity.cpu_count):
        source = paths.get(destination)
        if source is None:
            continue
        identity_files[destination] = source
    # Insert direct read-only file mounts immediately before the application
    # separator.  The files are synthetic and private; passing them through
    # inherited descriptors is unnecessary and caused EBADF failures when
    # bubblewrap/Python disagreed about descriptor lifetime.
    separator = argv.index("--")
    mounts: list[str] = []
    for destination, source in identity_files.items():
        mounts.extend(["--ro-bind", str(source), destination])
    if resolv_conf is not None:
        mounts.extend(["--ro-bind", str(resolv_conf), "/etc/resolv.conf"])
    argv[separator:separator] = mounts
    return LaunchPlan(
        argv=argv,
        pass_fds=(),
        identity_files=identity_files,
        network_mode=network_mode,
        runtime_root=runtime_root,
        network_plan=network_plan,
    )


def build_vnc_bridge_command(
    bundle: VNCBundle,
    x11_socket_dir: Path,
    display_number: int,
    runtime_uid: int,
    runtime_gid: int,
) -> list[str]:
    """Build an x11vnc-inetd bridge isolated from host mounts and network.

    The controller owns the only host TCP listener. This process receives one
    accepted loopback connection through stdin/stdout, and can only connect to
    the paired sandbox's Xvfb UNIX socket.
    """
    if not bundle.root.is_dir() or not bundle.server.is_file():
        raise ValueError("VNC runtime bundle is incomplete")
    if not 100 <= display_number <= 64_099:
        raise ValueError("private X display number is invalid")
    try:
        socket_dir = x11_socket_dir.resolve(strict=True)
        socket_dir.relative_to(x11_socket_dir.parent.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ValueError("private X11 socket directory is invalid") from exc
    if not socket_dir.is_dir() or socket_dir.is_symlink():
        raise ValueError("private X11 socket directory is invalid")
    try:
        server_path = "/" + str(bundle.server.resolve().relative_to(bundle.root.resolve()))
    except ValueError as exc:
        raise ValueError("VNC server must be inside the private runtime bundle") from exc

    argv = [
        "bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--unshare-net",
        "--cap-drop", "ALL", "--clearenv", "--uid", str(runtime_uid), "--gid", str(runtime_gid),
        "--tmpfs", "/tmp", "--dir", "/tmp/.X11-unix", "--proc", "/proc", "--dev", "/dev",
        "--dir", "/usr", "--dir", "/lib", "--dir", "/lib64",
    ]
    argv.extend(_runtime_mount_args(bundle.root))
    argv.extend([
        "--ro-bind", str(socket_dir), "/tmp/.X11-unix",
        "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C",
        "--setenv", "DISPLAY", f":{display_number}", "--",
        server_path, "-display", f":{display_number}", "-inetd", "-nopw",
        "-noshm", "-noxrecord", "-noxfixes", "-noxdamage",
    ])
    return argv


def _execution_command(plan: LaunchPlan) -> list[str]:
    # No synthetic identity descriptors are inherited. All identity sources
    # are mounted directly by bubblewrap from the private state directory.
    if plan.network_mode == "stub":
        return plan.argv
    if plan.network_plan is None or plan.network_plan.definition is None:
        raise ValueError("real network execution requires a prepared network plan")
    helper = Path(os.environ.get("APPSBX_NETWORK_HELPER", "/usr/libexec/appsbx-net-helper"))
    try:
        helper = helper.resolve(strict=True)
    except OSError as exc:
        raise ValueError("real networking helper is not installed") from exc
    stat = helper.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise ValueError("real networking helper must be root-owned and not group/other writable")
    network = plan.network_plan
    definition = network.definition
    command = [
        str(helper), "run", "--profile-id", str(network.profile_id),
        "--netns", network.names.netns, "--host-veth", network.names.host_veth,
        "--subnet", str(network.subnet), "--egress", definition.name,
        "--interface", definition.interface,
    ]
    if definition.gateway is not None:
        command.extend(["--gateway", str(definition.gateway)])
    for server in definition.dns_servers:
        command.extend(["--dns", str(server)])
    command.extend(["--", *plan.argv])
    if os.geteuid() != 0:
        # The helper is root-owned and independently validates the Bubblewrap
        # command. Allow the normal sudo authentication prompt; deployments
        # may replace this with a narrowly scoped NOPASSWD rule.
        command = ["sudo", *command]
    return command


def execute(plan: LaunchPlan, vnc_service=None) -> int:
    """Execute a plan, optionally presenting its private Xvfb via VNC."""
    command = _execution_command(plan)
    if vnc_service is None:
        return subprocess.call(command, env=_minimal_host_env(), pass_fds=())
    vnc_service.start()
    process: subprocess.Popen[object] | None = None
    try:
        process = subprocess.Popen(command, env=_minimal_host_env(), pass_fds=())
        vnc_service.wait_for_xvfb(process)
        vnc_service.open_viewer()
        return process.wait()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        vnc_service.stop()
