"""Build and stage the direct-syscall uname/sysinfo guard for a runtime bundle."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess

from .paths import PROJECT_ROOT

GUARD_SOURCE = PROJECT_ROOT / "native" / "syscall_guard.c"
GUARD_NAME = "libappsbx-syscall-guard.so"

class SyscallGuardError(ValueError): pass

def build_guard(destination: Path) -> Path:
    """Compile the architecture-specific, libc-only guard into ``destination``."""
    if platform.machine() != "x86_64":
        raise SyscallGuardError("uname/sysinfo isolation currently requires x86_64 Linux")
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        raise SyscallGuardError("uname/sysinfo isolation requires a C compiler (set CC or install gcc/clang)")
    source = GUARD_SOURCE.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    output = destination / "usr" / "lib" / "appsbx" / GUARD_NAME
    stamp = output.with_suffix(".sha256")
    if output.is_file() and stamp.is_file() and stamp.read_text(encoding="ascii").strip() == digest:
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".tmp")
    result = subprocess.run([compiler, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-std=c11", str(GUARD_SOURCE), "-o", str(temporary)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise SyscallGuardError("could not build uname/sysinfo guard: " + result.stderr.strip()[:500])
    temporary.chmod(0o555); temporary.replace(output); stamp.write_text(digest + "\n", encoding="ascii"); stamp.chmod(0o444)
    return output
