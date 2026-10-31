#!/usr/bin/env bash
# Run this as the payload command of a sandboxctl diagnostic launch. It emits
# only hardware/namespace observations; it intentionally does not read home,
# cookies, application state, or environment secrets.
set -euo pipefail

section() { printf '\n== %s ==\n' "$1"; }
read_if_present() { [ -r "$1" ] && { printf '%s: ' "$1"; head -c 512 "$1"; printf '\n'; } || true; }

section "identity files"
for path in /etc/hostname /etc/machine-id /proc/sys/kernel/random/boot_id /proc/meminfo /proc/cpuinfo; do
  read_if_present "$path"
done

section "native interfaces"
uname -a || true
getconf _NPROCESSORS_ONLN 2>/dev/null || true
getconf _NPROCESSORS_CONF 2>/dev/null || true
nproc 2>/dev/null || true

section "CPU topology"
grep -E '^(processor|model name|physical id|siblings|core id|cpu cores|cpu MHz)' /proc/cpuinfo 2>/dev/null || true
for path in /sys/devices/system/cpu/{online,possible,present}; do read_if_present "$path"; done

section "graphics and devices"
find /dev/dri -maxdepth 1 -printf '%f %y\n' 2>/dev/null || true
glxinfo -B 2>/dev/null | grep -E 'direct rendering|OpenGL renderer|OpenGL vendor|OpenGL version' || true
for path in /sys/class/dmi/id/{sys_vendor,product_name,product_serial,product_uuid,board_serial,chassis_serial}; do
  read_if_present "$path"
done

section "Node (only if staged by this runtime)"
if command -v node >/dev/null 2>&1; then
  node - <<'NODE'
const os = require('os');
console.log(JSON.stringify({
  arch: process.arch, platform: process.platform, version: process.version,
  cpus: os.cpus().length, availableParallelism: os.availableParallelism?.(),
  totalmem: os.totalmem(), hostname: os.hostname(), release: os.release(),
}));
NODE
else
  echo 'node is not staged; Electron renderer APIs require a live DevTools diagnostic.'
fi
