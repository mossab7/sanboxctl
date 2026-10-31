# appsbx

`appsbx` runs the Electron AppImage in a per-profile filesystem, identity,
process, and network boundary. Stub mode is fully unprivileged. Real mode uses
a separately installed, root-owned network helper for only the namespace,
veth, routing, and firewall operations; this checkout does not install or
invoke that helper automatically.

## Install on another Linux machine

The portable release contains the existing x86-64 Zaap AppDir and the
unchanged sandbox engine. It supports Linux hosts with Python 3.10+, a
supported package manager (`apt`, `dnf`, `pacman`, or `zypper`), and an x86-64
CPU. It does not download Zaap from a third party: the distributor must supply
the bundled `apps/zaap.AppDir` payload they are permitted to distribute.

Extract the release, inspect the machine and planned packages, then install:

```bash
./install.sh check
./install.sh plan
./install.sh --yes
appsbx-gui
```

`--yes` is intentionally required before the installer invokes the system
package manager or installs the root-owned, narrowly validated real-network
helper. The GUI and app files are installed per user below
`$XDG_DATA_HOME/appsbx/app` (normally `~/.local/share/appsbx/app`); mutable
profiles, logs, game downloads, and credentials remain below
`$XDG_STATE_HOME/appsbx` (normally `~/.local/state/appsbx`) with owner-only
permissions. The installer writes a desktop launcher in
`$XDG_DATA_HOME/applications` and an `appsbx-gui` launcher in
`$XDG_BIN_HOME`/`~/.local/bin`.

For a dry-run that makes no changes:

```bash
./install.sh --dry-run --skip-system-packages --skip-network-helper
```

Use `./install.sh --update --yes` to replace installed code while retaining
state. Use `python3 -m appsbx.install uninstall` to remove installed code; add
`--purge-state` only when intentionally deleting every persistent profile and
its local application data. The installer never grants the Electron app root,
never enables host forwarding, and never changes the selected egress policy.

`xvfb`/VNC are installed as optional fallback display tools. Hardware mode
still requires a usable host DRM render node and Mesa stack; the installer
reports a clear warning when either is absent. The private OAuth browser broker
additionally requires a locally installed Google Chrome compatible with the
existing runtime; it is not silently downloaded or configured by this project.

## What is implemented

- strict TOML profiles with synthetic hostname, MAC, CPU count, RAM, disk
  capacity, locale, timezone, UID, and GID;
- optional automatic, per-launch coherent hardware profiles selected from
  laptop, desktop, and workstation platform families;
- persistent synthetic machine and boot IDs, rendered identity files, and
  atomic state writes;
- an initially empty, persistent per-profile application home; it is never
  initialized from the host user home, browser profile, keyring, or tokens;
- AppImage inspection and optional unprivileged SquashFS extraction planning;
- validated SquashFS-offset detection and selective ELF interpreter/library
  staging for the extracted executable;
- bubblewrap launch-plan generation with user, PID, IPC, UTS, cgroup, mount,
  and (stub mode) network namespaces;
- optional Xvfb execution entirely inside the Bubblewrap boundary; host X11
  and Wayland sockets are never mounted;
- optional visible `xvfb-vnc` presentation through a per-instance Xvfb
  display and a loopback-only VNC endpoint;
- optional private HTTP(S) URL brokering for Electron authentication flows;
- a PySide6 desktop controller for multiple persistent Zaap instances;
- a loopback-only network stub and a replaceable network-plan interface;
- real-mode per-instance veth/netns policy-routing and nftables plans, with a
  fail-closed privileged executor and namespace-local DNS;
- per-profile lifecycle locking and fail-closed egress changes;
- category-only host-leak probes and read-only capability inventory;
- tests for profile validation, identity persistence, plan construction,
  overlap checks, ELF staging, direct synthetic identity-file mounts without
  inherited descriptors, lifecycle locking, atomic state, and redacted probe
  output.

## Safe local checks

For the complete operator procedure and the exact files to return for
inspection, read [TESTING-GUIDE.md](TESTING-GUIDE.md).

From this directory:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py' -v
./sandboxctl profile list
./sandboxctl profile validate example
./sandboxctl capabilities
./sandboxctl rootfs inspect /path/to/application.AppImage
```

The test command is the portable form if the test script does not have an
executable bit in a copied checkout:

```text
bash tests/run-tests.sh
```

Create identity state only where you intend to keep the profile state:

```text
./sandboxctl identity ensure example
```

Inspect the persistent identity and its consistency checks:

```text
./sandboxctl identity inspect example
```

An automatic launch prints its state path in the dry-run identity report. That
path can be inspected later without creating or changing it:

```text
./sandboxctl identity inspect example --state-dir sandbox-state/.auto/example-<token>
```

To generate a fresh identity for one launch, use `--identity auto`. The
identity is allocated below `sandbox-state/.auto/<profile>-<random-token>`
using cryptographically secure randomness, so concurrent launches do not
share machine IDs, boot IDs, hostnames, MACs, disk serials, or mutable home
directories. Select a coherent platform family, or let the catalog choose
one:

The default application is the project-managed `apps/zaap.AppDir`. It is
resolved from the project files, so commands work from any current directory;
no `APPDIR` variable or path edit is required. The bundled AppDir must contain
the executable `zaap`. Use `--app-root /path/to/other.AppDir` only for an
intentional override; that directory is validated before any sandbox is
created.

```text
./sandboxctl run --profile example --identity auto --hardware-class laptop \
  --mode stub --display xvfb --execute -- /opt/app/zaap

./sandboxctl run --profile example --identity auto --hardware-class random \
  --mode stub -- /opt/app/zaap
```

New persistent identities and `--identity auto` identities both use the
versioned catalog. `--hardware-class` is intentionally rejected unless
`--identity auto` is selected. The GUI always creates a persistent catalog
identity. A platform variant is selected first, then only its compatible RAM,
storage, firmware, and unique identity values are used; fields are never
independently mixed. See [hardware identity details](docs/HARDWARE_IDENTITY.md).

The generated profile is rendered into the existing synthetic views:
`/proc/cpuinfo`, `/proc/meminfo`, CPU frequency files, DMI files under
`/sys/class/dmi/id`, a synthetic `/sys/block/vda` model/serial/size, and the
synthetic `/etc` identity files. These are filesystem replacements inside the
Bubblewrap mount namespace. They do not spoof CPUID, physical GPU/DRM queries,
kernel ioctls, timing, or other hardware-backed APIs. The automatic profile is
a compatibility layer, not a virtual machine.

Inspect a launch plan without running the application:

```text
./sandboxctl run --profile example --mode stub -- /opt/app/zaap
```

For a GUI application, request the isolated display backend explicitly:

```text
./sandboxctl run --profile example --mode stub --display xvfb \
  --execute -- /opt/app/zaap
```

This requires `/usr/bin/Xvfb`. The server, its staged dependencies, and the
application run inside the same Bubblewrap boundary. If Xvfb is unavailable,
the command fails closed; `DISPLAY`, Wayland sockets, and host Xauthority are
not used as fallbacks.

To interact with the private display on the host desktop, use `xvfb-vnc`:

```text
./sandboxctl run --profile example --mode stub --display xvfb-vnc \
  --execute -- /opt/app/zaap
```

This requires `x11vnc` plus either `vncviewer` or `xtigervncviewer` to be
installed by the operator. `sandboxctl` does not install packages. It fails
before launching the application when either program is absent. For each run,
the controller allocates a fresh X display number, private socket directory,
and an ephemeral VNC port bound strictly to `127.0.0.1`. It starts the viewer
automatically and tears down the listener, viewer, bridge, X socket directory,
and Bubblewrap descendants when the application exits. `x11vnc` uses inetd
mode and has no TCP listener of its own; its bridge Bubblewrap has no network
and no application or host root filesystem mount.

`--display xvfb` remains the headless private-display mode for automated
smoke tests. `--display xvfb-vnc` is the interactive mode.

For performance-sensitive interactive use, an explicitly requested host
display backend is also available:

```text
./sandboxctl run --profile example --mode stub --display host \
  --execute -- /opt/app/zaap
```

`host` first validates the current session's local Wayland socket and exposes
only that individual socket inside the sandbox. When `DISPLAY` identifies a
local Xwayland server, that one X socket (and its explicitly selected
`XAUTHORITY` cookie, if present) is also exposed and selected explicitly for
the packaged X11-era Electron build. This avoids Ozone choosing native
Wayland and crashing before the application window opens. If no Xwayland
socket exists, native Wayland remains the available path. Remote/TCP displays
and missing sockets are rejected. The host
runtime directory, `/tmp/.X11-unix` directory, host D-Bus, credentials, and
desktop filesystem are not mounted wholesale. Electron receives
`ELECTRON_OZONE_PLATFORM_HINT=auto`, so whether it selects native Wayland or
Xwayland is determined by the packaged Electron build and the available
session.

This mode is a performance optimization, not display isolation. A host
Wayland compositor or X server is a privileged application capability: the
application may be able to draw, receive input, obtain display metadata, or
capture content permitted by that protocol. Use `xvfb-vnc` when the strongest
display separation is required. All other Bubblewrap, synthetic identity,
filesystem, process, and network restrictions remain enabled in `host` mode.
The application command is not forced to use `--disable-gpu`; GPU flags are
an application-level choice. Verify actual Chromium GPU behavior from the
process command line and logs rather than assuming host display access enables
hardware acceleration.

GPU selection is explicit and opt-in: `--gpu-mode auto` (the default) adds no
Chromium GPU flags, while `--gpu-mode software` requests the measured
Xvfb-compatible software-rendering flags. For example:

```text
./sandboxctl run --profile example --mode stub --display xvfb \
  --gpu-mode software --execute -- /opt/app/zaap
```

For a host-display performance run, `--gpu-mode hardware` exposes only the
accessible DRM render node (for example `/dev/dri/renderD128`) and stages the
matching Mesa DRI module into the private runtime:

```text
./sandboxctl run --profile example --mode stub --display host \
  --gpu-mode hardware --execute -- /opt/app/zaap
```

Hardware mode is rejected with Xvfb because Xvfb is a software display server.
It does not mount `/dev/dri/card*`, DRM control nodes, general `/sys`, or host
library directories. Mesa receives the selected render node plus a generated,
GPU-only PCI/sysfs and udev compatibility view needed for DRM identification.
The view contains the GPU vendor/device and PCI topology needed by Mesa, but
not live host sysfs, DMI, CPU, disk, or unrelated PCI records. Hardware mode
also passes `--disable-software-rasterizer`, so a failed native-GL startup is
visible instead of silently becoming SwiftShader. The
render node is a shared physical-GPU interface, not
a GPU security boundary: driver/GPU fingerprints, shared-resource side
channels, and contention between instances remain possible. Keep `auto` or
`software` when display isolation is more important than rendering speed.
Verify acceleration from Chromium's GPU process command line and
`chrome://gpu`; selecting the mode alone does not prove the driver accepted
hardware rendering.

The GUI uses `auto` and does not silently force `--disable-gpu`. Whether that
mode uses hardware acceleration depends on the Electron build, display
backend, and host drivers; inspect the GPU child command line and Chromium
logs before comparing performance.

### External authentication URLs and first-run data

With a visible sandbox display (`xvfb`, `xvfb-vnc`, or `host`),
`--url-broker browser` installs a private `xdg-open` implementation into the
staged runtime. `auto` enables it for private Xvfb modes; the GUI explicitly
enables it for host-display launches. It
accepts exactly one `http://` or `https://` URL and opens it in a private copy
of `/opt/google/chrome`, displayed through the selected sandbox display as Zaap.
The browser uses its own profile beneath `/home/appsbx`; it does not see host
cookies, keyrings, desktop services, browser profiles, or a host network
namespace. It remains subject to `stub` offline networking or the selected
real-mode egress policy.

This needs an operator-installed Google Chrome package at
`/opt/google/chrome`. `sandboxctl` copies that package and its explicit
library closure into the profile runtime; it does not mount the host package.
The initial build is roughly 540 MiB in profile state. If Chrome is absent,
GUI launches fail closed with an actionable error. To block all external URL
dispatch explicitly, use `--url-broker off`.

The broker rejects `file:`, `data:`, JavaScript, custom schemes, relative
paths, and option-like arguments. Zaap 3.15.9 on Linux uses the loopback
callback `http://127.0.0.1:9001/authorized`; because the private browser runs
in the same sandbox network namespace, that callback reaches Zaap without a
host port forward. Independent instances may reuse port 9001 safely.
Custom-scheme callbacks are intentionally not brokered because forwarding
them to the host desktop would weaken the boundary.

### Downloaded game children

Zaap downloads its Linux game launcher below the private profile HOME (for
example `~/.config/Ankama/Retro/dofus1electron`). On a subsequent Zaap launch,
`sandboxctl` reads that known executable's ELF dependency declarations and
stages only the required system-library closure into a new immutable runtime
bundle. The game executable and its vendor libraries remain in the profile
home; host `/usr` and `/lib` are never mounted. A game update changes the
child executable stamp and causes another closure to be prepared at the next
launcher restart. If a game was downloaded during the current Zaap session,
close and relaunch Zaap once before pressing Play so the new child closure is
available.

Zaap's first launch may log absent repository, game-release, or API-key files.
Those are normal for an empty isolated profile. Files created by Zaap are now
retained in `sandbox-state/<profile>/home` for later launches; no host
configuration or credentials are imported to suppress first-run messages.

The runtime provides a private ALSA `null` configuration. It exposes no host
audio device or microphone. No host D-Bus socket is supplied. D-Bus diagnostics
that refer to `/run/appsbx/disabled-*-bus` are expected and are not evidence
of a host-bus fallback.

Run concurrent copies with different, unused instance IDs. Each gets separate
identity state, X display/socket directory, VNC port/viewer, profile lock, and
in real mode a separate veth/netns/routing/firewall resource set:

```text
./sandboxctl run --profile example --instance-id 2 --mode real --egress wifi \
  --force-egress --display xvfb-vnc --execute -- /opt/app/zaap
```

Instance IDs are `0` through `253` and must not collide with another configured
profile or active instance. Leaving `--instance-id` out retains the profile's
configured ID and original state.

`synthetic_disk_mb` is required in each profile. It controls the fixed
capacity returned by the private `/usr/bin/df` compatibility command. That
command reports no used space and does not execute or consult the host `df`,
mount table, or filesystem. Set it high enough for the application's intended
installations; it is a compatibility value, not a storage quota.

Real mode requires an explicit egress definition and a separately installed
root-owned helper:

```text
./sandboxctl run --profile example --mode real --egress wifi \
  --display xvfb --execute -- /opt/app/zaap
```

An egress definition in `etc/egress.d/wifi.conf` selects exactly one host
interface:

```text
name=wifi
type=interface
interface=wlan0
gateway=192.168.1.1
dns=1.1.1.1,9.9.9.9
ipv6=false
```

The helper creates one namespace/veth pair, a source policy table and an
unreachable guard rule, scoped nftables forwarding/NAT rules, and disables
IPv6 in the guest. If the selected interface disappears, the scoped firewall
drop and unreachable policy rule prevent fallback to another host interface.
It refuses to change the host forwarding sysctl; IPv4 forwarding must already
be enabled by an administrator. The helper must be installed root-owned and
non-writable, normally as `/usr/libexec/appsbx-net-helper`, with a narrow
sudoers rule. Do not run this repository's user-writable helper as root.

After upgrading this checkout, install the reviewed helper again before using
real mode. It now permits exactly two owner-only writable binds: the
controller-created X11 socket directory and the marker-validated per-profile
home at `/home/appsbx`. It still rejects generic writable, device, and host
filesystem binds.

## Phase boundary

This checkout does not install packages, alter the host, modify the AppImage,
create privileged objects, or configure routing/firewall state during tests.
Real mode is activated only after an administrator installs and authorizes the
separate helper. The design does not claim that JavaScript API replacement is
security isolation.

## Desktop GUI

The optional GUI is a non-privileged controller around the existing
`sandboxctl` backend. It uses the host desktop and hardware-GPU backend by
default; the network dropdown is the user-facing setting. The GUI automatically
manages generated hardware identity, private state, logs, lifecycle, and
settings-only cloning. It never runs the GUI or Electron with `sudo`.

The network dropdown also discovers live IPv4 interfaces automatically. An
interface with an address and its own default route appears as an ephemeral
entry such as `enp7s0 (detected interface)`; no configuration file is written.
The entry is refreshed while the GUI is open and revalidated at launch. If an
interface is unplugged or loses its route, launch fails closed rather than
falling back to another connection.
For automatically detected interfaces, DNS is taken from NetworkManager's
per-interface `IP4.DNS` data when available, with that interface's gateway as
a fallback. The host-wide resolver file is never copied, preventing DNS
requests from being directed to another active connection.

Install PySide6 for the Python interpreter used by the desktop session and
launch from any directory:

```text
# Use the distribution's PySide6 package or a dedicated virtual environment.
# Example for a user-owned Python environment:
python3 -m pip install --user PySide6
./appsbx-gui
```

For a desktop-menu entry, make the project launcher available on `PATH` (a
symlink preserves its project-relative root resolution), then install the
desktop file:

```text
mkdir -p ~/.local/bin ~/.local/share/applications
ln -sfn "$(pwd)/appsbx-gui" ~/.local/bin/appsbx-gui
cp appsbx.desktop ~/.local/share/applications/
```

The GUI uses `apps/zaap.AppDir` through the same project-relative resolver as
the CLI. It never searches for or accepts an arbitrary executable. An
explicit `--app-root` override is still supported by the CLI and is rejected
if its `zaap` executable is missing or not executable.

For real-mode launches, the GUI uses `pkexec` and the desktop authorization
agent because a background Qt process has no terminal for a `sudo` password
prompt. The authorization still applies only to the installed,
root-owned `appsbx-net-helper`; the GUI and Electron remain unprivileged. If
the desktop has no `pkexec` authorization agent, configure a reviewed narrow
`NOPASSWD` sudoers rule or use the CLI from an authenticated terminal.

The same command is represented by [`appsbx.desktop`](appsbx.desktop). Copy it
to `~/.local/share/applications/` if the desktop environment does not discover
it from the checkout. The GUI reads only valid real egress definitions from
`etc/egress.d/`; it does not silently fall back when the selected interface is
unavailable. Each instance gets a unique managed directory under
`sandbox-state/gui-instances/`, a persistent generated identity, a separate
profile ID/network namespace, and a per-instance `run.log`. GUI restarts use
the saved controller PID to recover status and can reconnect to a still-running
loopback-only VNC endpoint.

The GUI does not expose arbitrary executable or AppDir pickers. The fixed
command is `/opt/app/zaap`; all filesystem, display, network,
and privileged-helper restrictions remain implemented by the existing runtime.

Each launch writes a sanitized profile line to stdout (and therefore to the
GUI instance's `run.log`) before starting the application. It contains only
synthetic hardware and selected-network values, for example:

```text
[APPSBX PROFILE] {"cpu_brand": "11th Gen Intel(R) Core(TM) i5-1145G7", "cpu_vendor": "GenuineIntel", "egress": "wifi", "hardware_class": "laptop", "interface": "wlp61s0", "logical_cpus": 8, "network_mode": "real", "profile": "example-i2", "ram_mb": 16384}
```

Machine IDs, MAC addresses, usernames, credentials, and other host-derived
values are intentionally excluded from this summary.
