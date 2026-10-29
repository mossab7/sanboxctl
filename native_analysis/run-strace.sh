#!/usr/bin/env bash
# A separate syscall pass. Do not run concurrently with Frida: both use ptrace.
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT="${NATIVE_ANALYSIS_OUT:-$PWD/native-analysis-output/strace-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
if [[ "${1:-}" == "--pid" ]]; then
  [[ $# -eq 2 ]] || { echo "usage: $0 --pid PID" >&2; exit 2; }
  exec strace -ff -ttt -s 160 -p "$2" -e trace=openat,openat2,read,readlink,readlinkat,stat,newfstatat,statx,access,uname,sysinfo,getdents64,ioctl,socket,connect,getsockname,clone,clone3,fork,vfork,execve,mmap -o "$OUT/syscalls"
fi
[[ $# -gt 0 ]] || { echo "usage: $0 -- TARGET [ARG...]" >&2; exit 2; }
[[ "$1" == "--" ]] && shift
exec strace -ff -ttt -s 160 -e trace=openat,openat2,read,readlink,readlinkat,stat,newfstatat,statx,access,uname,sysinfo,getdents64,ioctl,socket,connect,getsockname,clone,clone3,fork,vfork,execve,mmap -o "$OUT/syscalls" "$@"
