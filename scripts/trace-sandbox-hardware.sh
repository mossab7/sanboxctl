#!/usr/bin/env bash
# Ask sandboxctl to trace only the payload. Tracing the controller makes sudo
# reject its setuid transition, so network setup must stay outside ptrace.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 TRACE_DIRECTORY -- sandboxctl run ..." >&2
  exit 64
fi
trace_dir=$1
shift
[ "$1" = "--" ] || { echo "expected -- before sandboxctl command" >&2; exit 64; }
shift
mkdir -p "$trace_dir"
command=("$@")
inserted=false
for index in "${!command[@]}"; do
  if [ "${command[$index]}" = "--" ]; then
    command=("${command[@]:0:$index}" --trace-hardware "${command[@]:$index}")
    inserted=true
    break
  fi
done
if [ "$inserted" != true ]; then
  echo "sandboxctl command has no -- application separator" >&2
  exit 64
fi
echo "payload traces will be written to the profile-private home; sandboxctl prints the exact path." >&2
exec "${command[@]}"
