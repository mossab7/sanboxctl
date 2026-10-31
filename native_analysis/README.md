# Native Zaap/Dofus host-information observer

This directory is separate from `appsbx/`. It is an optional, read-only diagnostic tool for **unsandboxed** official Zaap/Dofus processes. It does not patch target binaries, modify return values, alter authentication, or run inside `sandboxctl`.

## Safety model

The Frida agent observes selected libc boundaries and writes redacted NDJSON. It records categories (for example `machine-id`, `dmi`, `proc-cpu`, `drm-device`) and native call stacks, never file contents, environment values, cookies, tokens, full command arguments, or remote addresses. Event caps and rotation are on by default.

Frida and `strace` both need ptrace, so run them as **separate reproducible passes**. On this host unprivileged BPF and perf are disabled; the toolkit records that limitation rather than attempting privilege escalation.

## Validate the observer first

```bash
cd /home/blackstar/Downloads/sandbox/sandboxctl
./native_analysis/run-fixture.sh
```

This compiles a tiny non-Ankama fixture in a new output directory, traces it for three seconds, and produces:

- `native-host-analysis.json`
- `native-host-analysis.html`
- `sandbox-gap-report.md`
- `trace-coverage.md`

Before a runtime pass, capture a static ELF snapshot. This establishes only
potential native dependencies; it does not establish runtime behavior:

```bash
python3 native_analysis/recon.py --target /absolute/path/to/zaap \
  --output native-analysis-output/zaap-recon.json
```

## Official-client workflow (you control the interaction)

Start Zaap normally, log in or launch Dofus as needed, then attach a Frida pass to a selected PID:

```bash
./native_analysis/run-frida.sh --pid "$(pgrep -n -x zaap)" \
  --duration 300 --level focus \
  --output native-analysis-output/zaap-frida.ndjson

# Capture the process tree, mapped graphics libraries, and open device classes
# while the same client is still running. This does not record command-line
# arguments, file paths, or descriptor targets.
python3 native_analysis/snapshot.py --pid "$(pgrep -n -x zaap)" \
  --output native-analysis-output/zaap-processes.ndjson
```

For a startup-only Frida pass, put every observer option before `--spawn`, then provide the target arguments last: `./native_analysis/run-frida.sh --output native-analysis-output/start.ndjson --duration 300 --spawn /absolute/path/to/zaap`. A spawned client resumes immediately after hooks load. Do not run this with `strace` concurrently.

Repeat the same user action in a distinct syscall pass:

```bash
NATIVE_ANALYSIS_OUT="$PWD/native-analysis-output/zaap-strace" \
  ./native_analysis/run-strace.sh --pid "$(pgrep -n -x zaap)"
```

Stop `strace` with Ctrl-C after the action. Then create a combined report:

```bash
python3 native_analysis/analyze.py \
  --frida native-analysis-output/zaap-frida.ndjson \
  --snapshot native-analysis-output/zaap-processes.ndjson \
  --strace native-analysis-output/zaap-strace/syscalls.* \
  --out-dir native-analysis-output/zaap-report
```

Attach separately to the actual Dofus process after Zaap launches it. A process tree is not automatically followed because global Frida spawn gating can affect unrelated host processes.

## Sandboxed GPU and CPU pass

This pass remains observation-only. Start a hardware-mode sandbox instance,
wait for its normal window, then attach independently to **each** relevant
process (main, renderer, and `--type=gpu-process`). Do not use the outer
`strace` wrapper: ptracing the controller breaks `sudo`'s setuid validation.

```bash
# List the application's sandboxed processes without printing their full args.
ps -eo pid=,comm=,args= | grep '[z]aap' | sed 's/ --/\n  --/g'

# Replace PID with one process at a time. This records API calls and origins,
# but redacts GPU strings by default.
./native_analysis/run-frida.sh --pid PID --duration 120 --level all \
  --categories pci-or-drm-topology,drm-device,drm-sysfs,graphics-api,cpu-api \
  --output sandbox-analysis/PID.ndjson

# Use only when comparing the renderer string is necessary. The resulting
# local file contains real GPU vendor/renderer strings; do not publish it.
./native_analysis/run-frida.sh --pid PID --duration 120 --level all \
  --categories graphics-api --capture-gpu-values \
  --output sandbox-analysis/PID-gpu-values.ndjson
```

`glGetString` and `eglQueryString` establish whether a process receives a
renderer/vendor string. `drmGet*` establishes libdrm discovery, while an open
of `/sys/dev/char/226:128/device/{vendor,device}` plus `iris_dri.so` is Mesa
driver initialization evidence. None of those observations proves that Zaap
JavaScript read or transmitted the value.

The observer reports `sysconf`, `get_nprocs`, and `get_nprocs_conf` counts.
It cannot observe `navigator.hardwareConcurrency` directly; use Electron
DevTools on a renderer only if the packaged client makes it available. CPUID
is an instruction and is likewise outside libc/Frida API interception.

The output report labels ordinary Electron/Chromium infrastructure only when its recorded origin module or process role supports that attribution. It never infers Ankama collection or transmission from a local read alone.

## Interpretation

An event proves that the traced process accessed an API or attempted to access a category of resource. It does **not** prove collection, fingerprinting, correlation, or transmission. Use connection metadata plus application-side evidence before making those claims.
