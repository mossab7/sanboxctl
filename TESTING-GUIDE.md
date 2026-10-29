# appsbx testing and log-collection guide

This guide is for validating Phase 1 on a normal Linux desktop and for
collecting evidence that can be inspected in a later turn. It does not ask
for root, package installation, firewall changes, network changes, or edits to
the AppImage.

The most important distinction is:

| Test | What it proves | What it does not prove |
|---|---|---|
| Unit tests | The Python modules and validation rules behave as designed | That bubblewrap can start this AppImage on this desktop |
| Capability inventory | Which local tools and namespace operations are available | That a privileged backend is safe or configured |
| Dry-run | The selected profile produces a bounded launch plan | That the plan can mount every runtime dependency |
| Stub execution | The process can start inside the unprivileged plan | That real egress is isolated; stub mode is loopback-only |
| AppImage run | The target application starts with the selected root/namespace | That Chromium/native code cannot bypass the boundary |
| Host tracer | JavaScript API calls and stacks observed by the tracer | Native, Chromium-internal, early-startup, or un-injected children |

## 1. Prepare a clean test directory

Run these commands from the `sandboxctl` directory. The commands do not print
the complete environment and do not alter system-wide state.

```bash
cd /home/blackstar/Downloads/sandbox/sandboxctl

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$PWD"

./sandboxctl profile validate example
./sandboxctl capabilities
```

The target application is managed at `apps/zaap.AppDir` and is resolved from
the project root. All launch commands below therefore work without an
`APPDIR` variable or an `--app-root` option. To intentionally use another
extracted AppDir, add `--app-root /path/to/other.AppDir`; it must contain an
executable `zaap` and is validated before the sandbox starts.

Save the output only if it contains no sensitive local additions. The normal
capability output contains tool availability and versions, not host IDs or
network addresses.

## 2. Run the automated tests

Preferred command:

```bash
./tests/run-tests.sh 2>&1 | tee phase1-tests.log
```

Portable equivalent:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. \
  python3 -m unittest discover -s tests -p 'test_*.py' -v \
  2>&1 | tee phase1-tests.log
```

Expected final lines:

```text
Ran 21 tests in ...
OK
```

If a test fails, keep the complete `phase1-tests.log`. Do not edit the
traceback; it identifies the failing module and assertion needed for repair.

## 3. Use the safe collection script

The repository includes `tests/collect-phase1.sh`. It runs the unit tests,
profile checks, capability inventory, category-only probe, network stub
status, and optional AppImage inspection. Each command gets separate stdout,
stderr, and exit-status files.

Basic collection:

```bash
./tests/collect-phase1.sh
```

The script prints the local collection directory. It does not dump
`/proc`, `/etc`, the environment, network addresses, or machine IDs.

To include an AppImage inspection, set its path for that invocation:

```bash
APPSBX_APPIMAGE=/home/blackstar/Downloads/sandbox/dofus \
  ./tests/collect-phase1.sh
```

To include a dry-run of the runtime plan, point the script at an already
extracted AppImage directory:

```bash
APPSBX_APPIMAGE=/home/blackstar/Downloads/sandbox/dofus \
APPSBX_APP_ROOT=/path/to/extracted-AppDir \
  ./tests/collect-phase1.sh
```

The dry-run command is safe: it constructs JSON and does not start Electron.
The generated command line redacts the application-root and persistent-state
paths in its JSON output.

## 4. Inspect the collection results

The files to share for inspection are:

```text
manifest.txt
unit-tests.stdout
unit-tests.stderr
unit-tests.status
capabilities.stdout
capabilities.stderr
profile-validate.stdout
profile-validate.stderr
run-plan.stdout                 # uses apps/zaap.AppDir unless overridden
run-plan.stderr
run-plan.status
rootfs-inspect.stdout           # if APPSBX_APPIMAGE was supplied
rootfs-inspect.stderr
probe.stdout
probe.status
network-status.stdout
network-status.status
```

The category-only probe may return status `1` when run outside a sandbox. That
is expected: it compares the current process with an in-memory deny-list made
from the same host and therefore detects the host values. It is a smoke test
for redacted reporting, not an isolation verdict. Do not treat `probe.status`
as a pass/fail result for the host itself.

If the collection directory is inside the shared workspace, tell me its exact
directory name in the next message. I can inspect the files directly. If it
is outside the workspace, upload or paste the relevant files instead.

## 5. Inspect an AppImage without modifying it

First inspect the original package:

```bash
./sandboxctl rootfs inspect /home/blackstar/Downloads/sandbox/dofus
```

For a read-only extraction into a temporary directory:

```bash
APPIMAGE=/home/blackstar/Downloads/sandbox/dofus
APPDIR=$(mktemp -d /tmp/appsbx-appdir.XXXXXX)
OFFSET=$("$APPIMAGE" --appimage-offset)

unsquashfs -quiet -no-xattrs -d "$APPDIR" -o "$OFFSET" "$APPIMAGE"
printf 'extracted AppDir is ready for this shell only\n'
```

This does not modify the original AppImage. Keep the extraction directory
until the dry-run or execution test is complete.

For this application, the extracted executable is normally at:

```text
<extracted-AppDir>/zaap
```

The current Phase 1 runtime mounts the extracted directory at `/opt/app` in
the generated plan, so the corresponding command is:

```bash
./sandboxctl run \
  --profile example \
  --mode stub \
  -- /opt/app/zaap
```

This is a dry-run unless `--execute` is added.

## 6. Read the dry-run output

A healthy dry-run should contain:

- `status: "dry-run"`;
- `network.mode: "stub"`;
- the profile-scoped network namespace name;
- `--unshare-user`, `--unshare-pid`, `--unshare-ipc`, `--unshare-uts`,
  `--unshare-cgroup`, and `--unshare-net`;
- `--clearenv`, `--cap-drop ALL`, `--hostname`, and synthetic UID/GID;
- `--ro-bind` for the application root;
- additional `--ro-bind` entries for private staged interpreter/library
  directories;
- direct `--ro-bind` entries for synthetic identity files, with no
  `pass_fds`/inherited identity descriptors;
- `FONTCONFIG_FILE` pointing to the private staged policy;
- private tmpfs locations for `/home`, `/run`, and `/tmp`.

The real backend is deliberately not exercised by this test guide because it
changes host networking. It requires an administrator-installed, root-owned
`/usr/libexec/appsbx-net-helper`; the repository's unit tests only inspect its
generated commands and rules.

To create a real egress definition, copy the following shape to
`etc/egress.d/wifi.conf` and replace the values with the selected interface's
actual gateway and DNS servers:

```text
name=wifi
type=interface
interface=wlan0
gateway=192.168.1.1
dns=1.1.1.1,9.9.9.9
ipv6=false
```

Then inspect the plan without executing it:

```bash
./sandboxctl run --profile example --mode real --egress wifi \
  -- /opt/app/zaap
```

Real execution requires IPv4 forwarding to already be enabled and a narrow
sudoers rule for the root-owned helper. The helper disables IPv6 in the guest,
uses only the configured DNS servers, drops all non-selected egress traffic,
and cleans up the namespace/veth/rules after the child exits. Do not test it
on a production host until the administrator has reviewed the generated plan.

The desktop GUI uses `pkexec` so authorization can be shown by the desktop
policy agent. A plain `sudo` password prompt cannot work inside the GUI's
background `QProcess`; if no policy agent is installed, use a reviewed
narrow `NOPASSWD` sudoers rule or authenticate `sudo` in a terminal before a
CLI launch.

## 7. Attempt the stub execution

Only do this after the dry-run is captured:

```bash
./sandboxctl run \
  --profile example \
  --mode stub \
  --execute \
  -- /opt/app/zaap \
  > sandbox-execute.stdout \
  2> sandbox-execute.stderr
printf '%s\n' "$?" > sandbox-execute.status
```

The application may fail to start for reasons unrelated to isolation:

- the current host may deny creation of a network namespace;
- the extracted application may require runtime libraries not yet mounted;
- the current runtime intentionally clears `DISPLAY`, Wayland, tracing, and
  other host environment variables;
- GUI support requires `--display xvfb`; this starts a private Xvfb inside
  Bubblewrap and fails closed if Xvfb is not installed;
- the target Electron build may require a desktop session or FUSE.

The runtime now stages the selected executable's ELF interpreter and direct
shared-library closure into private state. It does not mount the host root,
`/usr`, or `/lib` wholesale. A later failure mentioning a library loaded by
`dlopen`, a GPU driver, a font, NSS, or an external helper is a dependency
gap to report, not a reason to add an unrestricted host bind.

For Xvfb mode the bundle also contains private XKB/locale data, GLib schemas,
Fontconfig data, and a scalable default font. This is required by Chromium's
native startup path; a missing font can otherwise produce a native Electron
trap before JavaScript startup. The bundle includes a private no-op
`xdg-settings` helper so protocol registration cannot modify the host desktop.

Keep all three files if it fails. The exact stderr and numeric status are the
most useful evidence for the next adjustment. Do not retry with `sudo`; that
would test a different security model and is outside Phase 1.

For this Electron GUI application, the headless safe execution form is:

```bash
./sandboxctl run \
  --profile example --mode stub --display xvfb \
  --execute -- /opt/app/zaap \
  > sandbox-execute.stdout 2> sandbox-execute.stderr
printf '%s\n' "$?" > sandbox-execute.status
```

Do not replace this with `DISPLAY=$DISPLAY`, a bind of `/tmp/.X11-unix`, a
Wayland socket mount, or `--mode real`; those test a different and weaker
boundary.

### Visible interactive GUI through VNC

The interactive display mode keeps Xvfb inside the application Bubblewrap.
It does **not** mount the host X11/Wayland socket. Instead, each execution
creates an owner-only socket directory for that one Xvfb server. A local
controller listens on an ephemeral `127.0.0.1` VNC port, and starts one
network-isolated `x11vnc -inetd` bridge for each viewer connection. The VNC
viewer is the only component that uses the host desktop.

First inspect availability; no package is installed by `sandboxctl`:

```text
./sandboxctl capabilities
```

`Xvfb`, `x11vnc`, and either `vncviewer` or `xtigervncviewer` must be
available. Then run:

```text
./sandboxctl run \
  --profile example --mode real --egress wifi --force-egress \
  --display xvfb-vnc --execute -- /opt/app/zaap --disable-gpu
```

The command prints an endpoint such as `appsbx VNC: 127.0.0.1::54321` and
opens the viewer automatically. That endpoint is bound only to IPv4 loopback;
it is not reachable from the selected egress interface, LAN, VPN, or the
sandbox network namespace. Closing the application closes the listener and
viewer and removes the private socket directory. Do not forward that local
port or run a VNC server against the host display.

To run another copy concurrently, choose an unused instance ID:

```text
./sandboxctl run --profile example --instance-id 2 --mode real --egress wifi \
  --force-egress --display xvfb-vnc --execute -- /opt/app/zaap
```

The selected ID becomes the isolated network/resource ID and a suffix in the
private state directory. Do not reuse an active ID or an ID belonging to a
configured profile.

### Private URL broker and first-run data

Zaap uses `xdg-open` for some external authentication flows. In a host-style
desktop session, that would delegate into the host browser and could expose
existing browser cookies or bypass the selected network namespace. The GUI
runtime instead enables `--url-broker auto` by default. With `xvfb` or
`xvfb-vnc`, it stages an installed Google Chrome package into the private
runtime and provides a narrow `xdg-open` replacement.

The broker accepts only a single HTTP(S) URL. It rejects `file:`, `data:`,
JavaScript, arbitrary custom schemes, and non-URL command arguments. The
browser profile is empty on first use and is stored only in the isolated
profile home. It shares the application's Xvfb display and namespace, so in
real mode it remains subject to the selected-egress firewall. In stub mode it
cannot obtain Internet access.

Check the dependency without installing anything:

```bash
test -x /opt/google/chrome/chrome && echo 'private URL broker dependency: available'
```

Then use the normal interactive form; `auto` selects the broker because a
private display is present:

```bash
./sandboxctl run \
  --profile example --mode real --egress wifi --force-egress \
  --display xvfb-vnc --url-broker auto --execute -- /opt/app/zaap --disable-gpu
```

The first matching profile runtime build copies the browser package and may
need roughly 540 MiB. It is a private staged copy, not a bind mount of host
`/opt/google` or any host browser profile. If Google Chrome is unavailable,
the command fails before launching Zaap. Use `--url-broker off` only when you
intend to block external URL opening; it does not fall back to host
`xdg-open`.

Fresh profiles legitimately log missing files such as `repositories.json`,
`information.json`, `release.json`, `zaap.yml`, or a stored API key. They are
application bootstrap state, not host data that should be imported. The
runtime retains only application-created data in:

```text
sandbox-state/<profile>/home
```

Do not copy the host `~/.config`, `~/.cache`, browser profile, keyring, or
Zaap directory into that location. Authenticate inside the private VNC
session if an account session is needed.

ALSA uses a generated null output policy, with no `/dev/snd` or host ALSA
configuration. Host session/system D-Bus sockets are also absent by design.
Messages referring to `/run/appsbx/disabled-session-bus` or
`/run/appsbx/disabled-system-bus` confirm that the runtime has no host-bus
fallback; do not add a host D-Bus bind merely to hide those diagnostics.

For real mode, install the updated root-owned helper after reviewing it. The
helper rejects generic writable/device binds and permits only the
controller-created, owner-only Xvfb socket directory at `/tmp/.X11-unix` and
the marker-validated, per-profile application home at `/home/appsbx`:

```text
sudo install -o root -g root -m 0755 appsbx/network_helper.py /usr/libexec/appsbx-net-helper
sudo install -o root -g root -m 0644 appsbx/network.py /usr/libexec/network.py
```

For a bounded GUI smoke test, status `124` from `timeout` is expected when the
application reaches its event loop. Confirm startup by checking for
`[APP] setup done`, `[MAIN] App ready`, and `Zaap main window is Ready`, and
confirm that stderr contains neither `SIGTRAP` nor the earlier `.model`
exception:

```bash
set +e
timeout 8s ./sandboxctl run \
  --profile example --mode stub --display xvfb \
  --execute -- /opt/app/zaap \
  --disable-gpu --disable-software-rasterizer \
  --enable-logging=stderr --v=1 \
  > sandbox-smoke.stdout 2> sandbox-smoke.stderr
status=$?
printf 'smoke status: %s\n' "$status"
grep -E '\[APP\] setup done|\[MAIN\] App ready|Zaap main window is Ready|SIGTRAP|Cannot read properties of undefined \(reading .model.\)' \
  sandbox-smoke.stdout sandbox-smoke.stderr
```

Do not add Electron's `--no-sandbox` flag. The runtime keeps Bubblewrap's
outer user/PID/mount/network boundary and Electron's own sandbox enabled.

The application is intentionally offline in `stub` mode, so a normal
`navigator-online-changed false`/`We are now offline` message is expected.

## 8. Combining the application tracer

The existing tracer outside `sandboxctl` is the JavaScript observation tool.
Its NDJSON output is designed to redact arguments and return values. When the
runtime environment is explicitly passed through in a later revision, the
target run should use a separate trace file, for example:

```bash
export HOST_TRACE_LOG="$PWD/host-trace-sandbox.ndjson"
export HOST_TRACE_STDERR=0
```

At the current Phase 1 boundary, `runtime.execute()` deliberately supplies a
minimal environment and does not pass those variables into Electron. This is
intentional until an explicit, reviewed environment/display interface is
added. Therefore, do not infer “no trace events” from a missing file during a
current sandbox execution; that result means the tracer environment was not
yet connected.

For the current iteration, share the dry-run files and the direct tracer log
from the previously working inspector launch separately. The tracer log is
the useful file for JavaScript API findings; launcher stderr is useful for
inspector failures but may contain local paths and should be reviewed before
sharing.

## 9. What to report with the logs

Include:

```text
Linux distribution family and desktop session type (not the hostname)
whether the command ran as a normal user
the collection directory name
the command that failed, if any
the numeric exit status
whether the AppImage was mounted or extracted
whether GUI display support was expected
```

Do not include:

- `/etc/machine-id` contents;
- host MAC addresses, public IP addresses, usernames, or complete
  environment variables;
- raw `/proc` or `/sys` dumps;
- unredacted `strace` output;
- authentication headers, cookies, tokens, or account data.

## 10. How I will use the results

I will classify the result into one of these buckets:

1. profile/configuration error;
2. Python module or test regression;
3. bubblewrap capability or permission failure;
4. missing application runtime dependency;
5. missing GUI/display integration;
6. missing tracer propagation;
7. actual isolation leak;
8. application-specific native/Chromium bypass.

Only after the evidence identifies a concrete missing boundary will the next
revision change the runtime. The first likely follow-up areas are explicit
runtime-library mounts, a controlled display socket interface, tracer
environment propagation, or a dry-run-only privileged network helper.

## 11. Cleanup and rollback

Phase 1 creates only local profile state and temporary extraction/test files.
To discard a temporary extraction, remove the exact directory you created.
Do not remove the original AppImage or any host identity file.

To avoid persistent profile state during experiments, use the automated tests;
they create temporary state directories and clean them up automatically. The
CLI `identity ensure` and `run --execute` use the repository's
`sandbox-state/` directory and intentionally persist the synthetic identity
for that profile.

## 12. Hardware GPU verification

Inspect the host without changing it:

```sh
ls -l /dev/dri
glxinfo -B
eglinfo --device
```

Run the hardware path only with the host display backend:

```sh
./sandboxctl run --profile example --mode stub --display host \
  --gpu-mode hardware --execute -- /opt/app/zaap
```

The startup line reports the selected render node and Mesa driver. Verify the
child GPU command line and the application's Chromium GPU diagnostics. A
successful sandbox launch is not sufficient: `SwiftShader`, `llvmpipe`,
`MESA: Failed to query drm device`, or an exited GPU process means that this
Electron/display combination is still software-rendered. Do not broaden the
device or `/sys` mounts to suppress those messages; hardware mode intentionally
fails to provide complete GPU isolation and should remain a measured opt-in.
