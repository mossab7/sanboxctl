#!/usr/bin/env python3
"""Generate redacted JSON, HTML, gap, and coverage reports from observer passes."""
from __future__ import annotations
import argparse, collections, html, json, re
from pathlib import Path

SENSITIVE = {"machine-id", "hostname", "dmi", "pci-or-drm-topology", "drm-sysfs", "drm-device", "disk-device", "udev", "proc-cpu", "proc-memory", "proc-network", "mounts", "proc-other", "os-release"}
SOURCE_MAP = [
    ("Synthetic identity files", "appsbx/runtime.py:271-306; appsbx/identity.py", "filesystem-level identity is staged per profile; native APIs remain outside this toolkit's scope until traced."),
    ("GPU access", "appsbx/runtime.py:218-264; appsbx/gpu.py; appsbx/elf.py", "hardware mode intentionally exposes one render node and a narrow GPU topology."),
    ("Host display", "appsbx/host_display.py:48-105", "host X11/Wayland integration is an explicit host-session boundary."),
    ("Network egress", "appsbx/network.py; appsbx/network_helper.py", "routing is isolated, but remote services see the selected interface's public egress."),
]
def lines(paths):
    for path in paths:
        try:
            for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    value=json.loads(line)
                    if isinstance(value, dict): yield value
                except json.JSONDecodeError: pass
        except FileNotFoundError: pass
def strace_events(paths):
    quoted=re.compile(r'"([^"]+)"')
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            match=quoted.search(line)
            if not match: continue
            path_value=match.group(1)
            category=next((name for prefix,name in (("/etc/machine-id","machine-id"),("/etc/hostname","hostname"),("/sys/class/dmi","dmi"),("/sys/","sys"),("/dev/","device"),("/run/udev","udev"),("/proc/","proc")) if path_value.startswith(prefix)), None)
            if category: yield {"kind":"strace", "path_category":category, "operation":line.split("(",1)[0].split()[-1], "success":"= -1" not in line}
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--frida", nargs="*", default=[]); parser.add_argument("--strace", nargs="*", default=[]); parser.add_argument("--snapshot", nargs="*", default=[]); parser.add_argument("--out-dir", type=Path, required=True); args=parser.parse_args()
    events=list(lines(args.frida))+list(lines(args.snapshot))+list(strace_events(args.strace)); counts=collections.Counter(event.get("path_category", event.get("kind","unknown")) for event in events)
    processes=[event for event in events if event.get('kind') == 'process-snapshot']
    report={"schema_version":1,"redaction":"No host identifier values, environment values, buffers, or remote addresses are written.","event_count":len(events),"counts_by_category":dict(sorted(counts.items())),"events":events,"source_boundary_map":[{"area":a,"source":s,"boundary":b} for a,s,b in SOURCE_MAP]}
    args.out_dir.mkdir(parents=True,exist_ok=True); (args.out_dir/"native-host-analysis.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    rows="".join(f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>" for k,v in sorted(counts.items())) or "<tr><td colspan=2>No events. Run an opt-in Frida or strace pass.</td></tr>"
    tree=''.join(f"<li>PID {item['pid']} — {html.escape(str(item['name']))}; parent {html.escape(str(item['ppid']))}; mapped: {html.escape(', '.join(item['mapped_categories']) or 'none')}</li>" for item in processes) or '<li>No process snapshot supplied.</li>'
    (args.out_dir/"native-host-analysis.html").write_text(f"<!doctype html><meta charset=utf-8><title>Native host analysis</title><style>body{{font:16px system-ui;margin:2rem;background:#101512;color:#eef4eb}}table{{border-collapse:collapse}}td,th{{padding:.5rem;border:1px solid #405045}}code{{color:#d9f4a4}}</style><h1>Native host-information analysis</h1><p>Events: <b>{len(events)}</b>. Values are redacted by design.</p><h2>Process-tree snapshot</h2><ul>{tree}</ul><h2>Host-information access timeline / frequency</h2><table><tr><th>Observed category</th><th>Events</th></tr>{rows}</table><p>Correlate this pass with <code>sandbox-gap-report.md</code>; an observation is evidence of access, not evidence of collection or transmission.</p>",encoding="utf-8")
    gaps=["# Native observation / sandbox gap report","","## Scope","This report maps read-only native observations to sandbox boundaries. It does not claim that Zaap or Dofus collects, transmits, or uses an identifier unless an observed event and network evidence establish that.","","## Observed categories"]
    gaps += [f"- `{key}`: {value} event(s)" for key,value in sorted(counts.items())] or ["- No target events were supplied."]
    gaps += ["","## Relevant sandbox boundaries"] + [f"- **{a}** — `{s}`: {b}" for a,s,b in SOURCE_MAP]
    gaps += ["","## Interpretation","Filesystem emulation does not virtualize native kernel APIs, DRM ioctls, display-server protocols, or a public network egress. Validate each claimed gap with a target-specific trace before changing a boundary."]
    (args.out_dir/"sandbox-gap-report.md").write_text("\n".join(gaps)+"\n",encoding="utf-8")
    coverage=["# Trace coverage","","## Captured","- Frida: libc host APIs, selected machine-information file operations, environment *names*, graphics library loads, `connect`, and `execve`.","- strace (separate pass): selected filesystem, host-info, socket, ioctl, and process syscalls.","","## Deliberately redacted","- Host identifier contents, environment values, file buffers, cookies/tokens, and remote addresses.","","## Limits","- Frida and strace both rely on ptrace and must run in separate passes.","- This host has unprivileged BPF disabled and `perf_event_paranoid=3`; eBPF/perf attribution is unavailable without an explicitly authorized privileged host setup.","- Static app bundle strings show potential APIs, not execution or exfiltration.","- Native code may issue direct syscalls or use runtime-specific paths that these hooks miss; strace complements but cannot recover JavaScript call stacks."]
    (args.out_dir/"trace-coverage.md").write_text("\n".join(coverage)+"\n",encoding="utf-8")
if __name__=="__main__": main()
