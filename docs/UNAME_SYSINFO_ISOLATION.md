# Native identity syscall isolation

`sandboxctl` uses a UTS namespace for the hostname, but Linux does not
namespace the remaining `uname(2)` fields or `sysinfo(2)` memory counters.
Neither a cgroup namespace nor a cgroup v2 memory limit changes those syscall
results. Filesystem replacements under `/proc` do not affect direct syscalls.

## Implementation

Each runtime bundle contains a small x86-64 shared object,
`/usr/lib/appsbx/libappsbx-syscall-guard.so`. Bubblewrap sets `LD_PRELOAD` only
for the payload exec, never for Bubblewrap itself. Its constructor installs a
seccomp user-notification filter for `uname`, `sysinfo`, and
`sched_getaffinity`, then forks
a private broker in the same PID/user namespace. The broker writes a synthetic
`struct utsname` or `struct sysinfo` to the caller with `process_vm_writev` and
returns the normal syscall result. Invalid target pointers return `EFAULT`.

The filter is inherited by Electron, Chromium, Dofus, and ordinary child
processes. Consequently both libc wrappers and explicit `syscall(SYS_uname)` /
`syscall(SYS_sysinfo)` calls receive the same result.

| Interface | Result |
|---|---|
| `uname.sysname` | `Linux` |
| `uname.nodename` | persistent synthetic profile hostname |
| `uname.release` | `appsbx-synthetic` |
| `uname.version` | `#1 SMP appsbx` |
| `uname.machine` | `x86_64` (the supported payload ABI) |
| `uname.domainname` | `appsbx.local` |
| `sysinfo.totalram` | profile RAM MiB × 1,048,576 |
| `sysinfo.freeram` | one half of profile RAM |
| `sysinfo.uptime`, swap, high memory | zero |
| `sysinfo.procs` / `mem_unit` | `1` / `1` |
| `sched_getaffinity` CPU mask | profile logical-thread count |

## Verification

`tests/fixtures/syscall_guard_probe.c` exercises libc, direct-syscall, fork,
and exec paths. `tests/test_syscall_guard.py` verifies the values and the
synthetic affinity mask. A Bubblewrap
smoke test can be run with the probe staged as the app payload.

## Requirements and limitations

The implementation is x86-64 Linux and needs kernel seccomp user-notification
support plus a C compiler when creating a runtime bundle. It fails closed if
either is unavailable. A packaged release should ship a prebuilt shared object
for each supported ABI to remove the compiler requirement.

The affinity response changes what a process observes; it does not restrict or
expand the actual scheduler CPU set. This does not virtualize CPUID,
architecture-specific timing instructions, DRM/OpenGL information,
cgroup/scheduler observations beyond `sched_getaffinity`, or arbitrary kernel
interfaces. `uname.machine` remains the real supported ABI by design; claiming
a different architecture would make the x86-64 Electron/Dofus payload
inconsistent.
