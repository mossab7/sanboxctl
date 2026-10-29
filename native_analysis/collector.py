#!/usr/bin/env python3
"""Attach Frida's read-only observer and persist redacted NDJSON events."""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

try:
    import frida
except ModuleNotFoundError as exc:
    raise SystemExit("Frida Python bindings are unavailable. Use run-frida.sh or set FRIDA_PYTHON to Frida's venv Python.") from exc


class RotatingNdjson:
    def __init__(self, path: Path, megabytes: int, copies: int):
        self.path, self.limit, self.copies = path, megabytes * 1024 * 1024, copies
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("a", encoding="utf-8")

    def write(self, event: dict) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        if self.handle.tell() + len(line.encode()) > self.limit:
            self.handle.close()
            for number in range(self.copies - 1, 0, -1):
                older, newer = self.path.with_suffix(self.path.suffix + f".{number}"), self.path.with_suffix(self.path.suffix + f".{number + 1}")
                if older.exists(): older.replace(newer)
            if self.path.exists(): self.path.replace(self.path.with_suffix(self.path.suffix + ".1"))
            self.handle = self.path.open("w", encoding="utf-8")
        self.handle.write(line); self.handle.flush()

    def close(self) -> None: self.handle.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pid", type=int, help="Attach to an existing same-user process.")
    source.add_argument("--spawn", nargs=argparse.REMAINDER, help="Spawn this one target under Frida (arguments follow --spawn).")
    parser.add_argument("--agent", type=Path, default=Path(__file__).with_name("frida_host_info.js"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--level", choices=("focus", "all"), default="focus")
    parser.add_argument("--categories", help="Comma-separated event categories to retain (for example machine-id,proc-cpu,drm-device).")
    parser.add_argument("--max-events", type=int, default=4000)
    parser.add_argument("--rotate-mb", type=int, default=16)
    parser.add_argument("--rotate-count", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.spawn is not None and not args.spawn:
        raise SystemExit("--spawn requires an executable after it")
    writer = RotatingNdjson(args.output, args.rotate_mb, args.rotate_count)
    device = frida.get_local_device()
    spawned = args.spawn is not None
    pid = device.spawn(args.spawn) if spawned else args.pid
    session = device.attach(pid)
    script = session.create_script(args.agent.read_text(encoding="utf-8"))
    def on_message(message: dict, data: bytes | None) -> None:
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            writer.write(message["payload"])
        else:
            writer.write({"kind": "frida-message", "timestamp_ms": int(time.time() * 1000), "pid": pid, "message_type": message.get("type"), "description": str(message.get("description", ""))[:400]})
    script.on("message", on_message); script.load()
    categories = [item.strip() for item in (args.categories or "").split(",") if item.strip()]
    script.exports_sync.configure({"level": args.level, "maxEvents": args.max_events, "categories": categories})
    if spawned: device.resume(pid)
    stop = False
    def stop_handler(_signum: int, _frame: object) -> None:
        nonlocal stop; stop = True
    signal.signal(signal.SIGINT, stop_handler); signal.signal(signal.SIGTERM, stop_handler)
    deadline = time.monotonic() + args.duration if args.duration > 0 else None
    while not stop and (deadline is None or time.monotonic() < deadline): time.sleep(0.2)
    # A short-lived target may exit before the requested duration. Frida then
    # destroys the script/session; that is a successful observation outcome.
    try: script.unload()
    except frida.InvalidOperationError: pass
    try: session.detach()
    except frida.InvalidOperationError: pass
    writer.close()
    return 0

if __name__ == "__main__": raise SystemExit(main())
