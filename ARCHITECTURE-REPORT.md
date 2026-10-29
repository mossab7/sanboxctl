# appsbx architecture report

This report covers the unprivileged implementation in this directory and the
previous inspection of the packaged Electron application. It intentionally
contains no host machine IDs, host MAC addresses, hostnames, usernames,
public IP addresses, or raw environment values.

## Executive recommendation

The simplest reliable no-VM baseline is:

1. keep the original AppImage immutable;
2. extract it into a read-only application root when FUSE is unavailable or
   when deterministic inspection is needed;
3. launch the complete process tree through bubblewrap with a private mount,
   UTS, user, PID, IPC, cgroup, and network namespace;
4. provide synthetic identity files and a minimal environment from a
   per-profile state directory;
5. connect that network namespace only through a small, privileged helper
   that owns veth, routing, firewall, and selected-egress enforcement;
6. use a dedicated non-host filesystem view and private Xvfb display support;
   when interaction is needed, present it through a loopback-only VNC bridge
   rather than a host X11/Wayland socket.

This is strong practical containment with low overhead, but it is not a
hardware boundary. If the application must be prevented from learning real
CPU topology, kernel properties, timing, GPU characteristics, or other
microarchitectural signals against a hostile native component, a microVM or
VM is the dependable boundary. API overrides and ordinary containers do not
provide that guarantee.

## Observed application shape

The inspected artifact is an Electron AppImage containing a packaged Ankama
launcher. Static inspection found Electron 16, embedded Node 16, Chromium 96,
an ASAR archive, bundled/minified JavaScript, preload and renderer bundles,
and native-module entries. The application entry is a bundled main-process
JavaScript file. No source maps were available, so source locations are
generated bundle coordinates.

The successful observation run recorded main-process activity only. It
recorded calls to CPU, architecture, platform, release, memory,
network-interface, DNS, and child-process APIs. The main process executed a
shell command that reads Linux machine-ID files with a hostname fallback and
started a sibling executable named `dofus1electron`. The sibling process was
not covered by that injected tracer. DNS lookups included an external public-IP
check and application service names. No machine-specific filesystem read was
recorded by the injected JavaScript tracer during that session; that does not
prove that native code, Chromium, or the sibling missed those paths.

The static archive review also found native modules, `/proc` reads in an
active-window dependency, shell utilities, Linux power-supply checks,
Electron display/GPU access, persistent user-data paths, and child environment
inheritance. These are higher-priority containment concerns than adding more
JavaScript hooks.

## Architecture diagram

```text
                         privileged network helper
  selected egress ──> [appsbx helper: veth + route + firewall + fail-closed]
                              │
                              │ only explicit namespace handle
                              v
  host viewer <── 127.0.0.1-only VNC controller <── per-connection offline x11vnc bwrap
                                                       │ private X socket only
  controller ──> [bwrap namespace: private net + mounts + PID + UTS + user]
                         │
                         ├── read-only extracted AppImage root
                         ├── synthetic /etc, /proc subset, and identity files
                         ├── marker-validated per-profile /home/appsbx only
                         ├── private /run, /tmp, /sys, /dev view
                         └── Electron ──> dofus1electron and all descendants
```

`stub` mode creates a loopback-only network namespace without privileges. In
`real` mode the separately installed helper creates the prepared namespace and
executes Bubblewrap inside it; Bubblewrap does not create a second network
namespace.

In `xvfb-vnc` mode the application-side Xvfb server remains in that same
Bubblewrap boundary. The controller creates a new owner-only socket directory
and random display number per run, bind-mounts only that directory at the
sandbox's `/tmp/.X11-unix`, and starts the host viewer against an ephemeral
IPv4-loopback listener. Each accepted viewer connection starts `x11vnc` in a
second Bubblewrap with an unshared network namespace, no application root,
and only the staged x11vnc closure plus the read-only private X socket. No
host X11 socket, Wayland socket, Xauthority, display environment variable, or
host network is supplied to Electron or x11vnc.

An explicit `--display host` backend is available for performance experiments.
It validates a local Wayland socket first, but when a local Xwayland
`DISPLAY=:N` socket exists it also exposes only that socket and the selected
Xauthority cookie, and explicitly selects X11 for the packaged X11-era
Electron build. This avoids an incompatible native-Wayland Ozone choice. If
no Xwayland socket exists, native Wayland remains the available path. The host
runtime directory and
`/tmp/.X11-unix` directory are never mounted wholesale. This is a capability
trade-off: a host compositor/X server may expose display metadata, input, or
screen content according to its protocol. Xvfb/VNC remains the stronger
display-isolation choice; the other filesystem, PID/UTS/user, synthetic
identity, and network restrictions remain enabled in host mode.

### Hardware GPU backend

On a Linux host with an accessible DRM render node and supported Mesa driver,
`--display host --gpu-mode hardware` detects the kernel driver, stages only
the matching DRI module and its ELF dependencies, and adds one exact
`--dev-bind /dev/dri/renderD* /dev/dri/renderD*` to Bubblewrap. The privileged
helper accepts that bind only for a DRM character device (major 226, render
minor >= 128); card nodes, control nodes, optional binds, and arbitrary
devices remain rejected.

No host `/sys`, udev database, GPU control node, or host library directory is
mounted. Hardware mode adds no software-rendering flags, allowing Chromium to
select EGL/GL through the staged Mesa driver, and fails closed when the render
node, driver mapping, or DRI module is unavailable. Instances still share the
physical GPU and kernel driver, so GPU memory contention and fingerprinting
remain possible. A hostile application requires a stronger boundary such as a
VM or a separately assigned GPU.

When Xvfb is requested, the optional URL broker follows the application-side
branch, not the host-viewer branch. It stages a fixed installed Chrome package
into the private runtime, accepts only one HTTP(S) URL through a private
`xdg-open` script, and starts the browser in the application's existing
Bubblewrap namespace. Its cache/profile is inside the profile-private home,
so browser credentials created during a private login are isolated from host
credentials and remain bound to the profile's network policy. It never
dispatches through host `xdg-open`, host D-Bus, or a host browser.

## Why the layers are needed

| Layer | Hides or restricts | Does not guarantee |
|---|---|---|
| JavaScript tracer | Identifies Node API callers and generated stacks | Native code, Chromium internals, direct syscalls, children that miss injection |
| Synthetic files | Machine ID, hostname, passwd/group, selected proc/sys text | Arbitrary paths, DMI through native code, kernel answers, mount metadata |
| Mount namespace/rootfs | Host filesystem paths and writable state when the root is complete | A careless bind, device access, kernel interfaces, side channels |
| PID namespace | Host process listing and PID view | Kernel-wide timing and resource signals; misconfigured proc mounts |
| UTS namespace | Host hostname | CPU, kernel release, hardware, and external observations |
| Network namespace | Host interfaces/routes by default | Traffic through an intentionally connected backend; DNS/proxy/operator metadata |
| cgroup/resource limits | Exposed CPU and memory budget, process accounting scope | All hardware fingerprints; hostile kernel exploits |
| seccomp/device policy | Selected syscall/device capability | Correct policy is application-specific; bad policy breaks Electron |
| microVM/VM | Strongest kernel/hardware separation | External service and network identity unless separately controlled |

## Implemented interfaces

- `appsbx.profile`: strict profile loading; duplicate profile IDs and
  synthetic MACs are rejected.
- `appsbx.identity`: creates persistent random machine/boot IDs and synthetic
  regular files using atomic replacement and restrictive permissions. It also
  creates an empty marker-validated per-profile home. It never derives
  identity or initial application data from host values.
- `appsbx.rootfs`: inspects AppImage metadata and builds an `unsquashfs`
  extraction command without modifying the source image. It validates the
  SquashFS superblock, avoiding false matches on arbitrary `hsqs` bytes.
- `appsbx.elf`: reads the selected ELF's interpreter and direct dependency
  closure, then stages only approved system-library files and symlinks into a
  private per-profile bundle. The host root, `/usr`, and `/lib` are never
  mounted wholesale.
- `appsbx.runtime`: builds a bubblewrap command with private writable
  locations, a minimal environment, synthetic hostname/UID/GID, and explicit
  identity-file mounts. The extracted AppDir and staged runtime libraries are
  read-only. Synthetic identity files are mounted directly from the private
  profile state as read-only regular files; no identity descriptors are
  inherited by the application or bubblewrap, avoiding descriptor-lifetime
  and cleanup failures. `/home/appsbx` is the one persistent writable bind;
  it is profile-specific and has no host parent visible inside the namespace.
- `appsbx.elf`: when the private URL broker is requested for Xvfb, stages the
  fixed Chrome package and its ELF closure into the runtime, generates a
  HTTP(S)-only `xdg-open`, and generates a null ALSA policy. It does not stage
  host browser profiles, host `xdg-open`, host D-Bus configuration, or audio
  devices.
- `appsbx.network`: validates egress definitions, creates deterministic /30
  veth/policy-route plans, renders scoped nftables rules, and writes private
  DNS configuration. `StubNetworkBackend` performs no privileged operation.
- `appsbx.network_helper`: root-only executor. It checks the selected link and
  existing host IPv4 forwarding state, creates one namespace/veth pair, adds
  the profile source policy table plus an unreachable fallback guard, applies
  scoped IPv4 NAT/filter and IPv6-drop rules, disables IPv6 in the guest, runs
  the required Bubblewrap command inside the namespace, and removes all
  resources in a `finally` path.
- `appsbx.locking` and `appsbx.state`: prevent concurrent profile runs and
  refuse an egress change unless explicitly forced; writes are atomic.
- `appsbx.probe`: gathers a deny-list only in memory and emits category names,
  never values.
- `appsbx.capabilities`: reports availability of relevant local tools and
  whether the current boundary permits a time namespace.

## Real network backend

The selected interface is a validated profile configuration, not an arbitrary
application argument. The implemented helper:

- create one named network namespace and veth pair per profile;
- put the guest side in the namespace and assign a profile-specific private
  subnet;
- requires host IPv4 forwarding to already be enabled; it does not alter the
  host sysctl;
- use a dedicated route table and policy rule per profile;
- install firewall rules that accept only the veth path and the selected
  egress, with an explicit drop when the egress disappears;
- handle IPv4 and IPv6 separately, disabling IPv6 in the namespace unless an
  equivalent selected-interface policy exists;
- provides only configured, non-loopback IPv4 DNS servers through a private
  `/etc/resolv.conf` bind;
- disables IPv6 rather than allowing an unconfigured IPv6 fallback;
- refuses an interface that is absent or explicitly down and keeps the nft
  output-interface match scoped to the selected interface.

“Bind to interface” alone is insufficient: ordinary route metrics can choose
another interface after link loss. Policy routing plus an explicit drop rule
is required for fail-closed behavior. A proxy/tun2socks backend can avoid
host routing changes, but it must be treated as another privileged or
trusted component and must also fail closed on proxy loss.

## Host capability inventory

The inspection environment had an unprivileged bubblewrap runtime, Python,
AppImage extraction tooling, syscall tracing, and basic namespace utilities.
The current execution boundary blocked netlink and the time-namespace probe.
Firewall/WireGuard/userspace-proxy tooling was not available in that audit
environment. These observations are environmental, not assumptions about the
user's desktop; run `./sandboxctl capabilities` on the target system before
selecting a backend.

No package installation, privileged command, network change, system setting,
AppImage modification, or host identity modification was performed while
implementing or testing this backend.

## Highest-priority investigation points

1. Main-process machine-info aggregation and its machine-ID shell fallback.
2. The spawned `dofus1electron` process and its descendants; verify whether
   they inherit the tracer and whether they use native/Chromium paths.
3. Electron GPU/display and persistent user-data access.
4. Native addons and the active-window dependency's `/proc` and X11 utility
   access.
5. DNS and public-IP checks, including IPv6 behavior.
6. Filesystem visibility of DMI, `/proc`, `/sys`, mounts, devices, and parent
   processes inside the final bwrap root.

## Residual risks and verification status

The Phase 1 runtime plan is not a completed security boundary until it is
tested on a normal desktop with the exact Electron build. In particular:

- direct read-only regular-file mounts and the synthetic proc/sys overlay must
  be validated against the target bubblewrap version;
- a minimal private Fontconfig policy is staged and selected with
  `FONTCONFIG_FILE`; it prevents a host `/etc/fonts` fallback but does not
  provide a complete font catalog;
- the staged Chrome broker uses `--disable-setuid-sandbox`, not
  `--no-sandbox`: a copied browser payload cannot safely use the host-root
  setuid Chrome helper. Browser processes still run inside the mandatory
  outer Bubblewrap mount/user/PID/IPC/UTS/cgroup/network boundary, but this
  is not a claim that Chrome's inner sandbox layers are identical to a native
  host-browser launch;
- the private D-Bus addresses intentionally have no daemon or host services,
  and ALSA is a null sink. Desktop integrations that require a real portal,
  notification service, keyring, microphone, or sound device are not covered;
- direct ELF dependencies are staged, but libraries loaded later with
  `dlopen`, graphics drivers, fonts, NSS modules, plugins, and helper
  executables may require additional explicitly reviewed staging rules;
- the extracted AppImage may require carefully selected read-only runtime
  resources; broad host binds would weaken the result;
- the application can learn timing, locale, timezone, display/GPU details,
  kernel behavior, resource limits, and the external network endpoint;
- native addons and direct syscalls can bypass JavaScript replacement;
- a child can escape the intended environment if it gains a host file
  descriptor, socket, device, or overly broad bind;
- the real backend requires an administrator-installed root-owned helper and
  pre-enabled host IPv4 forwarding; this checkout does not perform those
  privileged setup steps;
- there is no seccomp allowlist or GPU isolation, and no claim of hiding all
  CPU/RAM/kernel characteristics;
- the inspection tracer was injected after startup in one successful run, so
  early startup calls and processes that did not inherit it may be absent.

The correct acceptance test is therefore behavioral: run the whole tree in
the final namespace, inspect only category-level results, and confirm that
the application cannot reach host identity files, host interfaces, host
processes, DMI, or an unselected egress after link failure.

## Phase boundary and rollback

The helper must be installed root-owned and non-writable, normally at
`/usr/libexec/appsbx-net-helper`, and authorized through a narrow sudoers
entry. This repository does not install it or execute privileged operations.
The explicit `cleanup --profile-id N` action removes only the corresponding
`appsbx-` namespace, veth, policy rules, and nftables tables.
