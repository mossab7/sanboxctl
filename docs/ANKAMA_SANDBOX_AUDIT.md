# Ankama Zaap/Dofus sandbox security and privacy audit

**Scope:** static audit of the `sandboxctl` implementation, the bundled Zaap
`app.asar`, and the checked-in local hardware-run evidence. This is not an
audit of Ankama servers, account policy, anti-cheat, or undisclosed Ankama
telemetry. No assertion below means that Ankama collects a given value; it
means the value is available to the local Zaap/Dofus process or could be sent
by it.

**Audit date:** 2026-10-29

## Executive summary

`sandboxctl` is a meaningful containment layer for Zaap and Dofus, especially
in stub-network plus private-Xvfb mode. It isolates the application from the
host home, host filesystem tree, host PID namespace, host network interfaces,
host D-Bus sockets, host audio sockets, disks, and most sysfs. It also gives
each managed GUI instance a separate private home, identity directory, and
real-network namespace.

It is **not** a virtual machine and does not make an instance appear to be a
separate physical computer. The implementation replaces selected files but
does not virtualize kernel system calls, CPU instructions, the real GPU, or
the external network identity. In particular, native code can still obtain
the real CPU architecture, real kernel/ABI characteristics, and potentially
real memory/CPU data through syscalls rather than the replaced `/proc` files.
Hardware mode intentionally exposes the real GPU render node, PCI IDs, PCI
address, driver, and OpenGL renderer. Real network mode intentionally makes
the selected host egress's public IP visible to remote services.

The highest practical privacy risk is host-display mode with X11/Xwayland: the
sandbox receives a real X11 socket and cookie. Traditional X11 authorization
is not per-window, so a compromised or malicious launcher can generally
observe/input-inject into other windows attached to that X server. Use private
Xvfb/VNC when display confidentiality matters. Hardware GPU mode is a second
intentional trade-off: it is performance-oriented and exposes a stable GPU
fingerprint and a shared driver/kernel attack surface.

No critical escape or direct host-file read was demonstrated by this audit.
The privileged network helper has a narrow command/mount validator. However,
there is no seccomp policy, no cgroup resource policy, and several visible
container/user-namespace markers. Zaap/Dofus can therefore distinguish this
environment from an ordinary desktop without needing an undocumented Ankama
collection mechanism.

## Evidence classification

| Label | Meaning |
| --- | --- |
| **Verified, source** | Directly established by the cited implementation. |
| **Verified, runtime** | Present in checked-in local launch/measurement evidence. |
| **Possible** | Available through a Linux/Electron interface but not shown to be used by Zaap/Dofus in this audit. |
| **Untested** | Requires a controlled live run, game launch, or server-side observation. |

The bundled `apps/zaap.AppDir/resources/app.asar` is minified. Static string
and module inspection found a `node-machine-id` dependency at byte offsets
256766, 892508, and 3941180, `openExternal` calls, and the localhost OAuth
callback text `127.0.0.1:9001`. Dependency presence alone does **not** prove a
machine-ID read or transmission. The extracted main-process code does
demonstrate use of Node's `os.arch()` to store an `OS_ARCHITECTURE` application
setting and configures its Linux game path below `os.homedir()/.config/Ankama`.

## Architecture overview

```text
Zaap / Dofus child
  └─ Bubblewrap: user, PID, IPC, UTS, cgroup and mount namespaces
       ├─ /opt/app: read-only bundled AppDir
       ├─ /home/appsbx: one persistent, owner-only profile home
       ├─ staged /usr, /lib, /bin: selected ELF dependency closure
       ├─ tmpfs /sys, /run, /tmp, /dev/shm; synthetic identity file binds
       ├─ stub mode: separate loopback-only network namespace
       └─ real mode: pre-created veth/network namespace → selected host egress

Optional capabilities:
  host display  → selected Wayland/X11 socket (+ Xauthority for X11)
  hardware GPU  → one /dev/dri/renderD* node + generated GPU PCI/sysfs view
  OAuth broker  → private staged Chrome in the same sandbox namespace
  Xvfb/VNC      → private display and loopback-only VNC listener
```

The Bubblewrap command uses `--unshare-user`, `--unshare-pid`,
`--unshare-ipc`, `--unshare-uts`, and `--unshare-cgroup`, drops all
capabilities, clears the environment, and uses a non-root synthetic UID/GID
([`appsbx/runtime.py:202`](../appsbx/runtime.py:202)). Stub mode additionally
uses `--unshare-net` ([`appsbx/runtime.py:212`](../appsbx/runtime.py:212)).
Real mode joins a helper-created network namespace rather than creating a
second one.

## Verified security strengths

### Filesystem, process, and namespace boundary

- **Verified, source:** `/home`, `/tmp`, `/run`, `/sys`, and `/dev/shm` start
  as private tmpfs locations; `/proc` is a new proc mount. The AppDir and
  staged dependency closure are read-only. See
  [`appsbx/runtime.py:69-102`](../appsbx/runtime.py:69) and
  [`appsbx/runtime.py:271-306`](../appsbx/runtime.py:271).
- **Verified, source:** only the profile-owned `home` directory is a writable
  host-backed bind. It is checked for owner-only permissions and a controller
  marker before use ([`appsbx/identity.py:255-303`](../appsbx/identity.py:255)).
- **Verified, source:** the helper rejects arbitrary writable mounts, optional
  device binds, root IDs, and network unsharing for real mode
  ([`appsbx/network_helper.py:175-239`](../appsbx/network_helper.py:175)).
- **Verified, source:** a PID namespace prevents Zaap/Dofus from enumerating
  normal host processes through its own `/proc`; the process view is still not
  a privacy boundary against the same host user outside the sandbox.

### Synthetic identity and selected file views

- **Verified, source:** machine ID, boot ID, hostname, passwd/group identity,
  locale, timezone, selected `/proc` values, DMI strings, and a synthetic
  `vda` disk model/serial are generated without host-derived identity inputs
  ([`appsbx/identity.py:137-147`](../appsbx/identity.py:137) and
  [`appsbx/identity.py:185-251`](../appsbx/identity.py:185)).
- **Verified, source:** these generated files are direct read-only mounts over
  the corresponding paths ([`appsbx/runtime.py:347-364`](../appsbx/runtime.py:347)).
- **Verified, source:** persistent profiles reuse the same `identity.json`;
  automatic identities create a separate random state directory. GUI instances
  allocate a UUID directory and unique profile ID
  ([`appsbx/identity.py:306-342`](../appsbx/identity.py:306),
  [`appsbx/instances.py:154-190`](../appsbx/instances.py:154)).

### Network, DNS, and egress enforcement

- **Verified, source:** stub mode is loopback-only. Real mode requires an
  explicit egress definition and rejects IPv6 rather than falling back
  ([`appsbx/network.py:333-378`](../appsbx/network.py:333),
  [`appsbx/network_helper.py:449-452`](../appsbx/network_helper.py:449)).
- **Verified, source:** real mode uses a per-profile `/30`, veth pair,
  namespace routing rule, nftables forwarding rules, and source NAT only on
  the selected interface. Packets from the veth that do not match that egress
  are dropped ([`appsbx/network.py:299-330`](../appsbx/network.py:299)).
- **Verified, source:** `/etc/resolv.conf` is generated only from the selected
  egress definition, not mounted from host resolver state
  ([`appsbx/network.py:272-296`](../appsbx/network.py:272)).
- **Verified, runtime:** previous captured network checks showed a sandbox
  namespace ping and HTTPS request succeeding through the selected Wi-Fi
  interface after the Docker `DOCKER-USER` compatibility rules were present.
  This verifies that routing worked in that run, not that remote services see
  a unique identity.

### Private desktop services and OAuth

- **Verified, source:** D-Bus environment variables point to nonexistent
  sockets in private `/run`; GLib is set to memory settings and local VFS
  ([`appsbx/runtime.py:287-301`](../appsbx/runtime.py:287)). The host system
  bus, session bus, PipeWire, PulseAudio, and `/dev/snd` are not mounted.
- **Verified, source:** the VNC listener binds only `127.0.0.1` and the
  bridge's display socket is private ([`appsbx/display.py:276-339`](../appsbx/display.py:276),
  [`appsbx/runtime.py:375-422`](../appsbx/runtime.py:375)).
- **Verified, static application evidence:** Zaap's bundled main process has
  `openExternal` code and allows HTTPS URLs before delegating them. The
  sandbox broker permits only HTTP(S) and runs a staged browser inside the
  sandbox display/network namespace. The discovered callback text is
  `http://127.0.0.1:9001/authorized`; a namespace-local callback does not
  require a host listening port.

## Ankama-specific information exposure matrix

| Information/capability | Zaap/Dofus availability | Evidence | Assessment |
| --- | --- | --- | --- |
| Synthetic machine ID, hostname, DMI serials, synthetic disk strings | Available as synthetic values through the mounted file paths | Source | Strong protection for ordinary file readers, including `node-machine-id` if it reads `/etc/machine-id`. Not proof against native alternatives. |
| Zaap Linux data path and settings | Private per profile at `/home/appsbx/.config/Ankama` and Electron user data | Source + static Zaap code | Strong profile separation. Zaap explicitly derives Linux game path from `os.homedir()`, which becomes `/home/appsbx`. |
| Authentication cookies/settings/downloaded game files | Persistent inside the same profile home | Source | Intentionally stable per profile; can correlate launches of that profile. It is not shared between managed profiles. |
| CPU model/count/RAM through replaced files | Synthetic | Source | Good for `/proc` and staged tools. |
| CPU architecture, CPUID, scheduler and memory facts through native APIs | Potentially real | Source + Linux semantics | Not virtualized. Electron/Node `process.arch`, `process.platform`, `process.version`, `os.arch()`, `os.release()`, `os.totalmem()`, native `uname(2)`, `sysinfo(2)`, CPUID, and timing are outside the file replacement scheme. Zaap statically calls `os.arch()`. |
| Kernel/namespace/container markers | Available | Source | `/proc/self/status`, namespace links, mountinfo, cgroup information, user-namespace UID mapping, and most unmasked `/proc/sys` remain available. |
| Real GPU model/vendor/PCI address/driver/renderer | Available in hardware mode | Source + runtime | Intentional for acceleration. `gui-hardware-v40.txt` and `v41` show no SwiftShader flag, open `/dev/dri/renderD128`, and mapped `iris_dri.so`. |
| Host DMI, disks, other PCI devices, DRM card/control nodes | Restricted | Source | `/sys` is tmpfs and only generated identity paths plus selected GPU topology are mounted. No `/dev/dri/card*` is added. |
| Physical NIC MAC/name and host routing table | Hidden from the app namespace | Source | Real-mode application sees guest `eth0` and `/30`, not selected physical interface. The helper does not set its MAC to profile synthetic MAC, so its veth MAC is kernel-generated and is not tied to the synthetic identity. |
| Public IP, DNS resolver, remote TLS/browser fingerprint | Available to remote Ankama services in real mode | Source | NAT uses selected egress; remote endpoint sees its public IP. Private DNS is selected-interface DNS, so DNS/provider geography can be externally visible. |
| Host display/X11 session | Exposed only in host display mode | Source | Wayland/X11 socket and Xauthority are intentionally mounted. X11 is a substantial trusted capability. |
| Host browser profile/host D-Bus | Restricted | Source | OAuth broker is a sandbox-staged browser; no host browser profile or D-Bus bind is present. |
| Zaap use of `node-machine-id` | **Untested use; dependency verified** | Static app.asar evidence | Do not infer collection/transmission from the dependency. The synthetic machine-ID mount should cover ordinary module behavior. |
| Dofus native child behavior | Partly architecture-backed, not fully runtime verified | Source | It inherits the same process/mount/network namespace when launched from Zaap; this audit did not complete an authenticated game-launch measurement. |

## Ranked weaknesses and isolation gaps

### High — host display mode grants a real desktop capability

**Exposure:** a selected Wayland socket or an X11/Xwayland socket, plus the
Xauthority cookie when configured.

**How it occurs:** `detect_host_display()` validates and mounts a single
socket; for X11 it also mounts the authority file
([`appsbx/host_display.py:48-105`](../appsbx/host_display.py:48)). The runtime
adds those mounts in host-display mode
([`appsbx/runtime.py:279-281`](../appsbx/runtime.py:279)).

**Ankama relevance:** Zaap's Electron renderer and any native child with
display access can use that display protocol. On X11, an authenticated client
is generally not limited to its own window, so this weakens host desktop
confidentiality and integrity even if filesystem isolation remains intact.
Wayland is generally narrower but compositor-specific; the socket still gives
the client display metadata and whatever input/clipboard/screencast protocols
the compositor permits.

**Evidence/verification:** launch with `--display host`, then inspect the
generated plan or `/proc/self/mountinfo` inside the sandbox for only the
selected display socket and `/run/appsbx/xauthority`. Do not use host X11 for
privacy-sensitive runs. This is source-verified; cross-window behavior is a
property of the host X server/compositor and was not actively tested.

**Recommendation:** make private Xvfb/VNC the privacy default; label host
display as a trusted-desktop mode. Prefer native Wayland where supported, but
do not describe it as a complete display isolation boundary.

### High — synthetic hardware does not cover native kernel APIs

**Exposure:** real kernel version/ABI, CPU architecture, CPUID features,
actual allowed CPU topology, memory facts via `sysinfo(2)`, timer behavior,
and other kernel-derived information.

**How it occurs:** the implementation replaces selected files only
([`appsbx/identity.py:65-117`](../appsbx/identity.py:65)); no syscall filter,
LD_PRELOAD interception, CPU virtualization, or memory/cpu cgroup limit is
created in the launch plan ([`appsbx/runtime.py:202-214`](../appsbx/runtime.py:202)).

**Ankama relevance:** the bundled Zaap main code demonstrably calls Node
`os.arch()` and records `OS_ARCHITECTURE`. Other Electron/native modules can
use equivalent system APIs. This does not establish that Dofus or Ankama sends
those values to a server.

**Verification:** compare, from a benign diagnostic program launched under
the same plan, file results (`/proc/meminfo`, `/etc/os-release`) with
`uname(2)`, `sysinfo(2)`, `process.arch`, `os.totalmem()`, and CPUID. No code
or Ankama binary modification is needed.

**Recommendation:** document synthetic identity as a compatibility layer,
not a security identity boundary. A VM is required to reliably virtualize
CPUID, kernel identity, timing, and many syscall-derived observations.

### High — hardware GPU mode exposes a stable real GPU fingerprint

**Exposure:** render node major/minor, PCI BDF, vendor/device/subsystem IDs,
revision, class, modalias, kernel driver, Mesa module, OpenGL/EGL renderer,
and GPU behavior/driver bugs.

**How it occurs:** hardware mode binds exactly one real DRM render node and
adds generated GPU topology ([`appsbx/runtime.py:218-264`](../appsbx/runtime.py:218)).
The generated view intentionally copies identification fields and a
sanitized 64-byte PCI header ([`appsbx/elf.py:614-663`](../appsbx/elf.py:614)).

**Verified runtime evidence:** `gui-hardware-v40.txt` records a GPU child with
`--use-gl=desktop`, no `swiftshader` substring, multiple descriptors for
`/dev/dri/renderD128`, and a mapping for `iris_dri.so`. This verifies hardware
Mesa use for Zaap in that captured run, not Dofus rendering.

**Impact:** profiles can be correlated by the same physical GPU; GPU APIs can
also expose driver version and renderer strings. GPU sharing is not a security
isolation boundary.

**Recommendation:** retain software/private-display mode for stronger privacy
needs. In hardware mode, state plainly that real GPU identity is intentionally
visible; do not try to claim GPU anonymity.

### High — external services see selected egress identity

**Exposure:** public IPv4 address, provider/ASN/geolocation inference, DNS
resolver/provider characteristics, traffic timing, TLS/browser fingerprint,
and account/session identifiers generated by Zaap itself.

**How it occurs:** real mode source-NATs the profile `/30` through the chosen
interface ([`appsbx/network.py:299-329`](../appsbx/network.py:299)). Multiple
instances may deliberately share one interface; the GUI only warns, it does
not prohibit this ([`appsbx/instances.py:251-268`](../appsbx/instances.py:251)).

**Impact:** separate profiles do not imply separate public IPs or separate
physical machines. This is expected network behavior, not a routing bypass.

**Verification:** use a benign HTTPS endpoint from each instance and compare
reported public IPs; repeat after an interface change. Verify that traffic
fails when the selected egress loses route/carrier.

**Recommendation:** use different egresses only when the network actually
provides distinct external identities; describe this as traffic selection,
not identity isolation.

### Medium — visible sandbox and user-namespace markers

**Exposure:** an application can recognize a Bubblewrap/user namespace and
synthetic environment through mount topology, `/proc/self/status`, namespace
links, cgroup data, empty/minimal `/sys`, synthetic OS string, fixed user name
`appsbx`, disabled D-Bus paths, and the CPU flag text `appsbx`.

**How it occurs:** the source explicitly sets `PRETTY_NAME="appsbx isolated
Linux"`, user/group names, and synthetic CPU flags
([`appsbx/identity.py:203-246`](../appsbx/identity.py:203)); it uses a new
user namespace and clear environment ([`appsbx/runtime.py:202-205`](../appsbx/runtime.py:202)).

**Impact:** Zaap/Dofus can distinguish a sandboxed session. That is not proof
of any Ankama policy response, but it makes the environment non-native.

**Recommendation:** do not present this project as detection-resistant. If
normal-desktop indistinguishability is a requirement, use a separately managed
VM and avoid synthetic markers—subject to application terms and policy.

### Medium — host source paths can leak through mount metadata

**Exposure:** absolute host paths used as Bubblewrap bind sources, potentially
including the local account name and project/state directory.

**How it occurs:** the AppDir, runtime bundle, profile home, and synthetic
files are bound from host paths. The source itself acknowledges mountinfo as a
residual ([`appsbx/runtime.py:275-278`](../appsbx/runtime.py:275)). A captured
host process command line in `gui-hardware.txt` also contains these paths.

**Ankama relevance:** inside the namespace, `/proc/self/mountinfo` is the
relevant non-invasive check; whether the exact source path is visible depends
on kernel/mount behavior. The host-side captured command line does not prove
that Zaap sees it.

**Recommendation:** treat this as an information leak to test on target
kernels. A fully private root filesystem assembled without host-path bind
sources is the stronger design, but is outside the current engine.

### Medium — no seccomp or resource-control policy

**Exposure:** broad Linux syscall surface and potential CPU/RAM exhaustion of
the user session.

**How it occurs:** the Bubblewrap plan drops capabilities but does not add a
`--seccomp` filter or cgroup CPU/memory constraints
([`appsbx/runtime.py:202-214`](../appsbx/runtime.py:202)). Existing observed
Zaap software-rendering runs consumed very high CPU; hardware evidence is
better but does not add resource limits.

**Impact:** this is primarily containment/availability risk, not evidence of
an Ankama data collection mechanism. GPU and graphics libraries also remain a
large native attack surface by design in hardware mode.

**Recommendation:** add optional resource limits at the launcher/controller
level and evaluate a narrowly tested seccomp profile. Do not add one blindly:
Electron and graphics stacks require many syscalls.

### Medium — `/proc` is only partially synthetic

**Exposure:** many procfs entries outside the explicitly over-mounted set,
including process status, namespace metadata, cgroup data, generic sysctl
values, and potentially host-kernel configuration signals.

**How it occurs:** `--proc /proc` mounts procfs, then only selected files are
replaced ([`appsbx/runtime.py:73`](../appsbx/runtime.py:73),
[`appsbx/runtime.py:347-364`](../appsbx/runtime.py:347)).

**Impact:** this is an incomplete machine-information boundary even without
native syscalls.

**Verification:** from a harmless sandbox diagnostic, enumerate readable
`/proc/sys`, `/proc/self`, `/proc/1`, `/proc/cgroups`, and mountinfo; compare
against the intended allowlist. Do not run host probes from inside Zaap.

**Recommendation:** explicitly mask or supply a narrow procfs view for
nonessential system information, after compatibility testing. This cannot
replace virtualization for syscall information.

### Medium — persistent profiles are separate but not hostile-user isolation

**Exposure:** any process running as the same host user can read that user's
owner-only state directories; an authenticated profile contains session state
and downloaded game data it created.

**How it occurs:** profile homes are `0700`, which protects against other host
users but not the same account ([`appsbx/identity.py:291-303`](../appsbx/identity.py:291)).

**Impact:** Profile A cannot see Profile B *from inside Bubblewrap* because
only its own home is mounted. This is not protection against other software
running under the desktop user.

**Recommendation:** use separate OS accounts or encrypted storage where the
threat model includes other processes under the same user. Never log or copy
tokens from profile homes.

## Multi-instance analysis

| Resource | Isolation status | Notes |
| --- | --- | --- |
| Persistent state and login/session storage | Isolated for managed GUI instances | Each has a UUID-backed identity/home directory. Same named CLI profile intentionally reuses state. |
| Machine/DMI synthetic files | Isolated for generated GUI instances | Stable within an instance; generated identities differ across instances. Native/system-call values remain shared host facts. |
| PID/process view | Isolated within each Bubblewrap PID namespace | Host processes are not normally enumerable from the sandbox; same-user host processes remain outside this guarantee. |
| Real network namespace and private IPv4 | Isolated | Each real instance uses profile-ID-derived netns, veth and `/30`; collision is rejected. |
| Physical egress/public IP | Intentionally shareable | Same selected interface normally means same public IP. Different interfaces may still share an IP upstream. |
| DNS | Per selected egress configuration | Resolver list is private, but resolver/provider itself can be a fingerprint. |
| Display | Private in Xvfb/VNC mode; shared trust domain in host display mode | VNC listener is loopback-only. Host X11 is not per-instance isolation. |
| GPU | Shared physical resource in hardware mode | Each receives one render node but shares physical GPU/driver and fingerprint. |
| OAuth callback | Namespace-local and independent in real/stub network namespaces | Reusing `127.0.0.1:9001` is safe across separate network namespaces. Full Google-login/game-launch flow was not rerun in this audit. |

## Intended versus actual isolation

| Intended claim | Actual boundary |
| --- | --- |
| Synthetic CPU/RAM/OS identity | Accurate for explicitly mounted files; incomplete for `uname`, `sysinfo`, CPUID, timing, Node/Electron native APIs, and unmasked procfs. |
| Synthetic network hardware identity | The physical NIC is hidden in real mode, but guest veth MAC is not set from the synthetic profile MAC. Remote identity is the egress public IP, not the synthetic MAC. |
| Minimal GPU exposure | Correctly avoids card/control nodes and whole sysfs, but intentionally reveals selected real GPU identity and driver behavior. |
| Host display access without broad filesystem access | Correct as an mount-scope statement; X11 protocol access itself remains broad. |
| Per-instance isolation | Strong for mounted homes, namespace state, and veths; incomplete for shared GPU, shared host account, external public IP, host display, and kernel-level facts. |

## Prioritized recommendations

1. **Use Xvfb/VNC for privacy-sensitive profiles** — high impact, low code
   complexity. Treat host X11 as an explicit trusted-desktop option.
2. **Document native/system-call identity leakage in the GUI and CLI** — high
   impact, low complexity. Avoid language implying a virtual machine or
   hardware anonymity.
3. **Add an auditable runtime self-check** for mounts, `/dev/dri/card*`, DMI,
   procfs exceptions, display mounts, and selected network namespace — high
   impact, medium complexity.
4. **Optionally apply cgroup resource limits** to prevent one Electron/game
   instance from exhausting CPU/RAM — medium impact, medium complexity.
5. **Evaluate a compatibility-tested seccomp policy** — medium containment
   impact, high complexity; retain a documented fallback for Electron/GPU.
6. **Narrow or mask additional procfs fields** after testing Zaap/Dofus —
   medium privacy impact, medium/high compatibility risk.
7. **Set a per-profile guest-veth MAC only if needed for internal consistency**
   — low privacy impact because it is not externally visible after NAT;
   validate that it does not weaken real-network routing.
8. **Use a VM for strong machine identity separation** — highest impact and
   highest operational cost. It is the realistic boundary for kernel, CPUID,
   timing, driver, and many hardware observations.

## Remaining limitations requiring virtualization or a stronger boundary

- No namespace/container design can reliably hide the host kernel version,
  CPU instruction set, timing behavior, scheduler behavior, and many syscall
  results from arbitrary native code.
- Hardware acceleration necessarily exposes the real GPU driver and a portion
  of the GPU's hardware identity; a render node is not a virtual GPU.
- A remote service necessarily sees network-level identity signals such as the
  egress public IP and traffic timing.
- X11 cannot provide per-application display confidentiality with a shared
  X server. Wayland improves the model but is compositor/protocol dependent.
- Profiles are not separate physical machines or independent Ankama account
  identities. Application account policy, server-side correlation, and session
  expiry are outside this sandbox.

## Overall assessment

For Zaap/Dofus, `sandboxctl` is best characterized as **strong host filesystem
and network-namespace containment with controlled compatibility views**, not
as hardware anonymization. Stub mode plus Xvfb/VNC offers the clearest privacy
boundary. Real networking adds reliable selected-egress enforcement but
intentionally reveals public-network identity. Host display and hardware GPU
mode are valid performance choices with explicit privacy costs. The project
should continue to make those trade-offs visible rather than attempting to
conceal them or claim that a profile is a separate physical machine.
