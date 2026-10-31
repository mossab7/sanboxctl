# Hardware identity mediation

This is an evidence-based description of the Linux backend. It does not claim
a virtual-machine boundary or assert that Ankama collects any specific value.

## Implemented per-profile mediation

| Attribute | Interfaces | Sandbox result | Status |
| --- | --- | --- | --- |
| Hostname | `/etc/hostname`, `/proc/sys/kernel/hostname`, `uname`, Node `os.hostname()` | Persistent profile hostname | Mediated |
| Machine/boot ID | machine-ID files and boot-ID file | Persistent synthetic values | Mediated for file readers |
| Kernel strings | staged `/proc`, `uname`, Node `os.release()` | Synthetic Linux strings | Mediated |
| CPU model/topology/frequency | staged `/proc/cpuinfo` and CPU sysfs | Persisted catalog model, cores, threads and MHz | Mediated for file readers |
| Logical CPU count | staged files and `sched_getaffinity` | Persisted logical-thread count | Mediated observation |
| RAM | `/proc/meminfo`, `sysinfo`, common Node memory paths | Persisted profile RAM | Mediated where listed |
| DMI/disk strings | staged DMI and `/sys/block/vda` | Persisted catalog values | Mediated for file readers |
| Network hardware | private network namespace | guest veth, private resolver | Isolated from normal host enumeration |

`native/syscall_guard.c` uses seccomp user notifications for `uname(2)`,
`sysinfo(2)`, and `sched_getaffinity(2)`. It covers libc and direct syscalls,
and normal fork/exec inheritance into Electron, Chromium, and Dofus children.

The synthetic affinity is only an observation layer: it does not alter the
real scheduler or make unavailable CPUs usable. A delegated cpuset cgroup is
needed for actual scheduler topology control and is intentionally not assumed
by this unprivileged backend.

## Unavoidable or unmediated surfaces

| Surface | Why it remains | Severity |
| --- | --- | --- |
| CPUID, RDTSC/RDTSCP, ISA flags | Physical instructions require VM/instruction emulation to virtualize. | High correlation value |
| `sysconf`, `get_nprocs`, cgroups/scheduler state | Library paths can consult live kernel state outside the mediated calls. | Medium |
| ABI, `process.arch`, Electron/Node version | Must match the actual x86-64 shipped payload. | Medium |
| DRM, EGL, GL, ANGLE, Vulkan | Hardware mode intentionally exposes one physical render node and supporting GPU PCI metadata. | High correlation value |
| Battery/camera/audio/USB/gamepad browser APIs | Device mounts are restricted, but browser/runtime paths require live verification. | Medium |
| Public IP, DNS, timing, configured locale/timezone | Required or intentionally configured runtime properties. | Medium |

Do not spoof GL/EGL/ANGLE/Vulkan renderer strings: that does not hide DRM
ioctls and can break hardware acceleration.

## Live diagnostic run

```bash
./scripts/trace-sandbox-hardware.sh /tmp/zaap-hardware-trace -- \
  ./sandboxctl run --profile example --mode real --egress wifi --force-egress \
  --display host --gpu-mode hardware --execute -- /opt/app/zaap
```

The trace includes controller, Bubblewrap and payload PIDs. Correlate payload
PIDs with `ps -eo pid,ppid,args`; a controller-side host read is not evidence
of a Zaap/Dofus read. `strace` establishes syscall use, not JavaScript callers
or network transmission. `scripts/diagnose-hardware-inside-sandbox.sh` is a
token-free payload diagnostic. Browser `navigator.*`, WebGL and Electron GPU
feature status require a live DevTools/preload diagnostic; this project does
not inject code into the packaged Ankama app.

## Current verification

`tests/test_syscall_guard.py` verifies libc/direct `uname`, `sysinfo`, and
`sched_getaffinity`, including fork/exec inheritance. `tests/test_appsbx.py`
verifies that staged CPU count, physical core count, siblings and frequency
derive from one persisted hardware record. No Zaap/Dofus process was running
during this implementation pass, so launcher-specific syscall use and GPU
feature status remain unverified.
