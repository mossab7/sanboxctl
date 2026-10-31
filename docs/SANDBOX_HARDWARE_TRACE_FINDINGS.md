# Sandboxed Zaap hardware-trace findings

**Capture:** `sandbox-state/example/home/hardware-trace.*`  
**Duration:** 2026-10-29 16:17:43–16:20:17 local time (about 154 seconds)  
**Mode:** `sandboxctl` real networking, host display, hardware GPU, opt-in
payload `strace`. This is a filesystem/syscall observation, not a statement
about collection or network transmission.

## Verified observations

| Surface | Evidence | Observed value / result | Assessment |
| --- | --- | --- | --- |
| `sysinfo(2)` | `hardware-trace.10:312` | `totalram=68719476736`, `freeram=34359738368`, `mem_unit=1` | The existing guard returned the profile's 64 GiB total and 32 GiB free values. |
| `sched_getaffinity(2)` | `hardware-trace.10:314` | CPUs `0` through `19` | The existing guard returned the profile's 20 logical CPU mask. |
| `uname(2)` | `hardware-trace.103:1` | `nodename="appsbx-example"` | The UTS namespace/guard path returned the synthetic hostname. |
| staged CPU/memory files | `hardware-trace.5:919`, `.5:921`, `.5:923` | `/proc/meminfo` and `/proc/cpuinfo` opened | This proves the files were used in this run; their staged values are governed by the persisted profile. |
| DRM topology | `hardware-trace.37:96-101`, `.155-168`, `.331-352` | PCI vendor/device paths and `iris_dri.so` opened | Real selected-GPU IDs are deliberately exposed as a dependency of Mesa/libdrm discovery. |
| render device | `hardware-trace.37:229` | `/dev/dri/renderD128` opened `O_RDWR` | The selected render node is used. No DRM control/card node was observed in this capture. |
| machine/DMI/disk files | all capture files, path search | no `/etc/machine-id`, `/sys/class/dmi`, or `/sys/block/vda` read | Not observed in this 154-second run; absence is not a proof of permanent inaccessibility. |

The trace file records a process-local trace number, not a Chromium role. The
PCI reads occur within `hardware-trace.37`, immediately after the process
starts and before its render-node open. This sequence is consistent with
Mesa/libdrm driver selection, but **does not prove** that it is a Chromium GPU
child, application JavaScript, or that the values crossed the network.

## CPU-count discrepancy

An earlier launcher information panel showed eight logical processors. The
prior native observation of the unsandboxed Zaap main process records
`uv_cpu_info` opening and reading `/proc/cpuinfo` in
`native-analysis-output/live-20261029-ankama/zaap-main-frida.ndjson`. That is
direct evidence that the Node/libuv CPU-info path is used, but not proof that
the panel specifically used it. At the time of that panel, the old profile
and/or old staged topology may have been in use.

The current sandbox syscall trace verifies only the 20-CPU affinity mask and
the file reads. It does **not** prove the values returned by each of:

- `navigator.hardwareConcurrency`;
- `os.cpus().length` / `os.availableParallelism()`;
- `sysconf(_SC_NPROCESSORS_ONLN)` or `get_nprocs()`;
- CPUID topology instructions.

`native_analysis/frida_host_info.js` now has an opt-in, read-only observer for
the libc count APIs and graphics query APIs. Run it against the main,
renderer, and GPU processes separately while Zaap is live. CPUID is an inline
CPU instruction, so it remains outside these hooks and would require a VM or
instruction-emulation boundary to virtualize reliably.

## GPU information that remains real

Hardware mode intentionally exposes exactly the selected GPU's render node,
minimal PCI topology required by Mesa, `iris_dri.so`, and graphics APIs. Mesa,
EGL/GL, ANGLE/Chromium WebGL, libdrm ioctls, and any process using the render
node can therefore observe some or all of the real vendor/device IDs, driver,
renderer string, and driver capabilities. This is required for native
acceleration and is not solved by changing staged `/sys` text files.

The observer distinguishes an internal graphics initialization call from an
application-visible graphics API query, but it cannot infer JavaScript use or
network transmission from either event. It defaults to redacting the real
renderer string; `--capture-gpu-values` is an explicit local diagnostic mode.

## Production impact

The new Frida hooks are **not** loaded by `sandboxctl`, the GUI, or a normal
launcher run. They introduce no production startup, CPU, memory, or rendering
overhead. A before/after performance comparison is therefore not applicable:
the production launch path was not changed. Measure only a separate
diagnostic-attached run if its observer overhead needs quantifying.

## Required live verification

Start one sandboxed Zaap instance and use the procedure in
`native_analysis/README.md` to attach to its main process, each renderer, and
the `--type=gpu-process` process. That is required to resolve role attribution
and to verify browser-facing values. Do not publish the optional GPU-value
output because it contains real renderer identifiers.
