#!/usr/bin/env python3
"""Capture a redacted /proc process-tree snapshot for a selected native target."""
from __future__ import annotations
import argparse, json, os, time
from pathlib import Path

GRAPHICS = ("dri", "libgl", "libegl", "libdrm", "vulkan", "iris", "i965")
def read_status(pid: int) -> dict[str, str]:
    data = {}
    try:
        for line in (Path('/proc') / str(pid) / 'status').read_text(errors='replace').splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                if key in {'Name','State','PPid','Threads','VmRSS'}: data[key] = value.strip()
    except (FileNotFoundError, PermissionError): pass
    return data
def descendants(root: int) -> list[int]:
    parent = {}; pids = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        status=read_status(int(entry.name)); ppid=status.get('PPid','').split()[0]
        if ppid.isdigit(): parent.setdefault(int(ppid), []).append(int(entry.name))
    todo=[root]
    while todo:
        pid=todo.pop(0); pids.append(pid); todo.extend(sorted(parent.get(pid,[])))
    return pids
def map_categories(pid: int) -> list[str]:
    found=set()
    try:
        for line in (Path('/proc') / str(pid) / 'maps').read_text(errors='replace').splitlines():
            candidate=line.rsplit(' ',1)[-1].lower()
            for item in GRAPHICS:
                if item in candidate: found.add('graphics-driver-or-library'); break
    except (FileNotFoundError, PermissionError): pass
    return sorted(found)
def fd_categories(pid: int) -> list[str]:
    found=set(); directory=Path('/proc')/str(pid)/'fd'
    try:
        for entry in directory.iterdir():
            try: target=os.readlink(entry)
            except OSError: continue
            if target.startswith('/dev/dri/'): found.add('drm-device')
            elif target.startswith('/dev/'): found.add('other-device')
    except (FileNotFoundError, PermissionError): pass
    return sorted(found)
def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--pid',required=True,type=int); parser.add_argument('--output',required=True,type=Path); args=parser.parse_args()
    processes=[]
    for pid in descendants(args.pid):
        status=read_status(pid)
        if status: processes.append({'kind':'process-snapshot','timestamp_ms':int(time.time()*1000),'pid':pid,'name':status.get('Name','unknown'),'ppid':status.get('PPid','?'),'state':status.get('State','?'),'threads':status.get('Threads','?'),'rss':status.get('VmRSS','?'),'mapped_categories':map_categories(pid),'fd_categories':fd_categories(pid)})
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text('\n'.join(json.dumps(item,sort_keys=True) for item in processes)+'\n',encoding='utf-8')
    print(f'wrote {len(processes)} redacted process records to {args.output}')
    return 0
if __name__=='__main__': raise SystemExit(main())
