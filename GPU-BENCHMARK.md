# GPU backend verification

## Host inspected

The host exposes `/dev/dri/renderD128` with Intel i915, Mesa 22.3.6, and an
Intel UHD Graphics 620 (KBL GT2). Host `glxinfo -B` reports direct rendering
and acceleration. The sandbox previously mounted no DRM node, and the Zaap
GPU command line consequently selected SwiftShader.

## Existing software-rendering baseline

The supplied process measurements for the host-display run showed the Zaap
renderer at roughly 300–357% CPU, the main process at roughly 100–130%, and a
GPU process around 20–47% CPU. The audio utility was also observed around
65–76% CPU. These measurements are a baseline, not a claim that every launch
has identical load.

## Hardware-mode verification

The implementation was verified with:

* a dry-run that selected `/dev/dri/renderD128`, i915, and Mesa `iris`;
* helper validation that accepted an exact render-node bind and rejected
  `/dev/dri/card0`;
* a real Bubblewrap smoke test using a temporary `/bin/true` AppDir, exit 0;
* a bounded Zaap launch that reached `App ready` and `Zaap main window is
  Ready` without modifying the Zaap payload; it ended with timeout status 124;
* a synthetic GPU-only sysfs/udev view and the GTK/GDK-pixbuf runtime data
  staged without broad `/sys` or `/run/udev` mounts.

On this host, Chromium and the independent `glxinfo -B` probe still exit or
fail during Xwayland DRI3/GLX initialization (`MESA: Failed to query drm
device`, `glx: failed to create dri3 screen`). Therefore hardware acceleration
is **not verified** and no CPU reduction is claimed. Hardware mode now passes
`--disable-software-rasterizer`, so it cannot silently turn this failure into a
SwiftShader success. The code intentionally does not broaden access to
`/dev/dri/card0`, unrestricted `/sys`, or host library directories to hide the
failure.

The remaining likely boundary is the legacy Electron/Xwayland GLX stack's
device discovery (including libdrm/udev behavior) rather than the render-node
permission: a full read-only host `/sys` test accelerated successfully, while
the narrow synthetic view did not. Native Wayland was also re-tested with the
staged loader cache and icon data. The bundled Electron still aborts before
creating a window because this host's GTK/GDK-pixbuf runtime has no usable PNG
loader for its embedded `image-missing.png` resource
(`gdk-pixbuf-error-quark`). That is a separate GTK resource compatibility
failure, not evidence of GPU acceleration.

For a future before/after run, keep the same profile and workload and collect:

```sh
pidstat -u -r -d -w 1 10
ps -eLo pid,tid,pcpu,rss,comm,args --forest
grep -E 'SwiftShader|llvmpipe|Mesa Intel|iris|GPU process' run.stderr
```

Run one, two, and three instances only when resources permit. Compare the
renderer/main/GPU CPU, RSS/PSS, and GPU-process command lines; a successful
process launch or a mounted device alone is not evidence of hardware GL.
