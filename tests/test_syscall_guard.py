from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from appsbx.syscall_guard import GUARD_NAME, build_guard


ROOT = Path(__file__).parents[1]
PROBE = ROOT / "tests" / "fixtures" / "syscall_guard_probe.c"


@unittest.skipUnless(shutil.which("cc"), "C compiler is required for syscall-guard integration test")
class SyscallGuardTests(unittest.TestCase):
    def test_libc_and_direct_syscalls_receive_identical_synthetic_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = build_guard(root)
            self.assertEqual(library.name, GUARD_NAME)
            executable = root / "probe"
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", str(PROBE), "-o", str(executable)], check=True)
            environment = os.environ | {
                "LD_PRELOAD": str(library),
                "APPSBX_UNAME_NODENAME": "appsbx-test-node",
                "APPSBX_UNAME_RELEASE": "appsbx-test-release",
                "APPSBX_UNAME_VERSION": "#1 SMP appsbx-test",
                "APPSBX_UNAME_MACHINE": "x86_64",
                "APPSBX_SYSINFO_TOTALRAM": str(8192 * 1024 * 1024),
            }
            output = subprocess.check_output([str(executable)], text=True, env=environment).strip().split("|")
            self.assertEqual(output[:4], ["appsbx-test-node", "appsbx-test-node", "appsbx-test-release", "appsbx-test-release"])
            self.assertEqual(output[4:], [str(8192 * 1024 * 1024)] * 2)

            child_output = subprocess.check_output([str(executable), "--child"], text=True, env=environment).strip().split("|")
            self.assertEqual(child_output[:4], ["appsbx-test-node", "appsbx-test-node", "appsbx-test-release", "appsbx-test-release"])
            self.assertEqual(child_output[4:], [str(8192 * 1024 * 1024)] * 2)
