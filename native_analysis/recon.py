#!/usr/bin/env python3
"""Record a redacted static ELF reconnaissance snapshot of a native target."""
from __future__ import annotations
import argparse, json, shutil, subprocess
from pathlib import Path

def command(*args: str) -> str:
    tool=shutil.which(args[0])
    if not tool: return "unavailable"
    result=subprocess.run([tool,*args[1:]],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=False)
    return result.stdout[:20000]
def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--target',type=Path,required=True); parser.add_argument('--output',type=Path,required=True); args=parser.parse_args()
    target=args.target.resolve()
    if not target.is_file(): raise SystemExit('target is not a regular file')
    dynamic=command('readelf','-d',str(target)); headers=command('readelf','-h',str(target)); libraries=command('ldd',str(target))
    needed=[]
    for line in dynamic.splitlines():
        if '(NEEDED)' in line and '[' in line and ']' in line: needed.append(line.split('[',1)[1].split(']',1)[0])
    interpreter=next((line.strip() for line in command('readelf','-l',str(target)).splitlines() if 'Requesting program interpreter' in line), 'not reported')
    result={'schema_version':1,'target_basename':target.name,'target_size_bytes':target.stat().st_size,'elf_header':headers,'interpreter':interpreter,'needed_libraries':needed,'ldd_output':libraries,'redaction':'Target path is intentionally omitted; this snapshot contains no environment, identifiers, process arguments, or credentials.'}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(f'wrote reconnaissance snapshot to {args.output}')
    return 0
if __name__=='__main__': raise SystemExit(main())
