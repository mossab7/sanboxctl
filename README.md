# appsbx

`appsbx` runs the Electron AppImage in a per-profile filesystem, identity,
process, and network boundary. Stub mode is fully unprivileged. Real mode uses
a separately installed, root-owned network helper for only the namespace,
veth, routing, and firewall operations; this checkout does not install or
invoke that helper automatically.

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

```text
./sandboxctl run --profile example --identity auto --hardware-class laptop \
  --mode stub --display xvfb --app-root "$APPDIR" --execute -- /opt/app/zaap

./sandboxctl run --profile example --identity auto --hardware-class random \
  --mode stub --app-root "$APPDIR" -- /opt/app/zaap
```

The default remains the existing persistent TOML-profile identity for
backward compatibility. `--hardware-class` is intentionally rejected unless
`--identity auto` is selected. Automatic profiles choose a complete compatible
platform variant first, then compatible RAM, storage, firmware, and unique
instance identifiers; fields are not independently mixed.

The generated profile is rendered into the existing synthetic views:
`/proc/cpuinfo`, `/proc/meminfo`, CPU frequency files, DMI files under
`/sys/class/dmi/id`, a synthetic `/sys/block/vda` model/serial/size, and the
synthetic `/etc` identity files. These are filesystem replacements inside the
Bubblewrap mount namespace. They do not spoof CPUID, GPU driver queries,
`sysinfo(2)`, kernel ioctls, timing, or other native/kernel hardware APIs.
Electron/Node APIs that use those lower-level mechanisms can therefore still
observe inconsistencies; the automatic profile is a compatibility layer, not
a virtual machine.

Inspect a launch plan without running the application:

```text
./sandboxctl run --profile example --mode stub --app-root /path/to/extracted-AppDir -- /opt/app/zaap
```

For a GUI application, request the isolated display backend explicitly:

```text
./sandboxctl run --profile example --mode stub --display xvfb \
  --app-root /path/to/extracted-AppDir --execute -- /opt/app/zaap
```

This requires `/usr/bin/Xvfb`. The server, its staged dependencies, and the
application run inside the same Bubblewrap boundary. If Xvfb is unavailable,
the command fails closed; `DISPLAY`, Wayland sockets, and host Xauthority are
not used as fallbacks.

To interact with the private display on the host desktop, use `xvfb-vnc`:

```text
./sandboxctl run --profile example --mode stub --display xvfb-vnc \
  --app-root "$APPDIR" --execute -- /opt/app/zaap
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

### External authentication URLs and first-run data

With either private Xvfb display mode, `--url-broker auto` (the default)
installs a private `xdg-open` implementation into the staged runtime. It
accepts exactly one `http://` or `https://` URL and opens it in a private copy
of `/opt/google/chrome`, displayed through the same Xvfb/VNC session as Zaap.
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
paths, and option-like arguments. OAuth redirects using HTTP(S), including a
loopback callback in the same sandbox network namespace, are supported.
Custom-scheme callbacks are intentionally not brokered because forwarding
them to the host desktop would weaken the boundary.

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
  --force-egress --display xvfb-vnc --app-root "$APPDIR" --execute -- /opt/app/zaap
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
  --display xvfb --app-root "$APPDIR" --execute -- /opt/app/zaap
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
