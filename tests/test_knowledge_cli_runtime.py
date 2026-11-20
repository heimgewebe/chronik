"""Installed CLI must use Chronik's existing runtime, not system python."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).parents[1] / "tools" / "knowledge_ledger.py"


class InstalledKnowledgeRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name) / "chronik"
        self.script = home / "releases" / "test" / "tools" / "knowledge_ledger.py"
        self.script.parent.mkdir(parents=True)
        self.script.write_bytes(SOURCE.read_bytes())
        self.runtime = home / "runtime-python" / "bin" / "python3"

    def test_prefer_existing_managed_python_before_imports(self):
        self.runtime.parent.mkdir(parents=True)
        self.runtime.write_text(
            "#!" + sys.executable + "\n"
            + "import json,sys\nprint(json.dumps(sys.argv))\n",
            encoding="utf-8",
        )
        self.runtime.chmod(0o700)
        p = subprocess.run(
            [sys.executable, str(self.script), "--data-dir", "dummy", "coverage"],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(json.loads(p.stdout), [
            str(self.runtime), str(self.script), "--data-dir", "dummy", "coverage",
        ])

    def test_missing_managed_python_fails_with_actionable_error(self):
        p = subprocess.run(
            [sys.executable, str(self.script), "--help"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("installed runtime unavailable", p.stderr)


if __name__ == "__main__":
    unittest.main()
