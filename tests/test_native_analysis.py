from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
ANALYZER = ROOT / "native_analysis" / "analyze.py"
AGENT = ROOT / "native_analysis" / "frida_host_info.js"


class NativeAnalysisTests(unittest.TestCase):
    def test_agent_is_read_only_and_redacts_values(self):
        source = AGENT.read_text(encoding="utf-8")
        self.assertIn("path_category", source)
        self.assertIn("redacted-string", source)
        self.assertNotIn("Interceptor.replace", source)
        self.assertNotIn("Memory.write", source)

    def test_analyzer_generates_all_required_reports_without_identifier_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = root / "events.ndjson"
            events.write_text(json.dumps({
                "kind": "filesystem", "operation": "open", "path_category": "machine-id",
                "success": True, "result_kind": "file-descriptor", "pid": 12,
            }) + "\n", encoding="utf-8")
            output = root / "report"
            subprocess.run([sys.executable, str(ANALYZER), "--frida", str(events), "--out-dir", str(output)], check=True)
            for name in ("native-host-analysis.html", "native-host-analysis.json", "sandbox-gap-report.md", "trace-coverage.md"):
                self.assertTrue((output / name).is_file(), name)
            report = json.loads((output / "native-host-analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(report["counts_by_category"], {"machine-id": 1})
            self.assertNotIn("actual-machine-id", (output / "native-host-analysis.html").read_text(encoding="utf-8"))

