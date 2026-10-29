#!/usr/bin/env bash
set -u

duration=60
label=run
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) duration="$2"; shift 2 ;;
    --label) label="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--duration seconds] [--label hardware|software]"
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

declare -a roots=()
# ``ps args`` includes the controller command line, which itself contains
# ``-- /opt/app/zaap``.  Checking it made Python, the network helper, and
# Bubblewrap look like Electron main processes.  Inspect argv[0] directly so
# this report starts only at a real Zaap executable.
for proc in /proc/[0-9]*; do
  pid=${proc##*/}
  [[ -r "$proc/cmdline" ]] || continue
  # Electron changes its process title after startup, which can replace the
  # original NUL-separated argv in /proc/<pid>/cmdline.  /proc/<pid>/exe is
  # maintained by the kernel and therefore remains the reliable identity.
  executable=$(readlink "$proc/exe" 2>/dev/null || true)
  case "$executable" in
    */zaap) ;;
    *) continue ;;
  esac
  cmd=$(tr '\0' ' ' < "$proc/cmdline")
  [[ "$cmd" != *"--type="* ]] || continue
  roots+=("$pid")
done

if [[ ${#roots[@]} -eq 0 ]]; then
  echo "[$label] no /opt/app/zaap root process found" >&2
  exit 1
fi

descendants() {
  local parent="$1" child
  echo "$parent"
  while read -r child; do
    [[ -n "$child" ]] || continue
    descendants "$child"
  done < <(pgrep -P "$parent" 2>/dev/null || true)
}

declare -a all=()
for root in "${roots[@]}"; do
  while read -r pid; do all+=("$pid"); done < <(descendants "$root")
done
# Multiple roots can share a wrapper ancestor only in a malformed launch, but
# de-duplicate defensively so pidstat never double-counts a process.
declare -A seen=()
declare -a unique=()
for pid in "${all[@]}"; do
  [[ -n "${seen[$pid]:-}" ]] && continue
  seen[$pid]=1
  unique+=("$pid")
done
all=("${unique[@]}")

printf '[%s] roots: %s\n' "$label" "${roots[*]}"
printf '[%s] process tree and GPU command lines\n' "$label"
for pid in "${all[@]}"; do
  [[ -r "/proc/$pid/cmdline" ]] || continue
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline")
  case "$cmd" in
    *"--type=gpu-process"*) kind=GPU ;;
    *"--type=renderer"*) kind=renderer ;;
    *"--type=utility"*) kind=utility ;;
    */dofus*|*Dofus*) kind=game ;;
    *"--type="*) kind=child ;;
    *) kind=main ;;
  esac
  flag=ok
  [[ "$cmd" == *swiftshader* ]] && flag=SWIFTSHADER
  printf '[%s] pid=%s type=%s gpu_flag=%s cmd=%s\n' "$label" "$pid" "$kind" "$flag" "$cmd"
done

printf '[%s] render-node, Iris, and VA-API mappings\n' "$label"
for pid in "${all[@]}"; do
  [[ -d "/proc/$pid/fd" ]] || continue
  fds=$(find "/proc/$pid/fd" -maxdepth 1 -type l -lname '/dev/dri/renderD*' -printf '%f=%l ' 2>/dev/null || true)
  maps=$(grep -F 'iris_dri.so' "/proc/$pid/maps" 2>/dev/null | head -1 || true)
  vaapi=$(grep -E '/(iHD|i965)_drv_video\.so' "/proc/$pid/maps" 2>/dev/null | head -1 || true)
  if [[ -n "$fds" || -n "$maps" || -n "$vaapi" ]]; then
    printf '[%s] pid=%s fds=%s iris=%s vaapi=%s\n' "$label" "$pid" "${fds:-none}" "${maps:-none}" "${vaapi:-none}"
  fi
done

if command -v pidstat >/dev/null 2>&1; then
  printf '[%s] pidstat -u -t for %ss\n' "$label" "$duration"
  pidlist=$(IFS=,; echo "${all[*]}")
  pidstat -u -t -p "$pidlist" "$duration" 1 || true
else
  echo "[$label] pidstat unavailable; install sysstat to collect the requested sample" >&2
fi

echo "[$label] repeat with --label software after stopping this instance; compare with:"
echo "  diff -u <(sed 's/^\[hardware\]/[run]/' hardware-gpu.txt) <(sed 's/^\[software\]/[run]/' software-gpu.txt)"
