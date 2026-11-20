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

    def test_symlink_virtualenv_with_same_base_interpreter_is_not_skipped(self):
        # A venv often symlinks the same binary as base Python. Its sys.prefix
        # and package search path are still distinct.
        import venv

        runtime_root = self.runtime.parent.parent
        venv.EnvBuilder(system_site_packages=False, with_pip=False, symlinks=True).create(runtime_root)
        bootstrap = SOURCE.read_text(encoding="utf-8").split("ROOT =", 1)[0]
        self.script.write_text(
            bootstrap
            + "\nprint(json.dumps({'prefix': sys.prefix, 'base': sys.base_prefix}))\n",
            encoding="utf-8",
        )
        base_run = subprocess.run(
            [sys.executable, str(self.script)],
            capture_output=True, text=True, timeout=20, check=True,
        )
        self.assertEqual(Path(json.loads(base_run.stdout)["prefix"]).resolve(), runtime_root.resolve())
        managed_run = subprocess.run(
            [str(self.runtime), str(self.script)],
            capture_output=True, text=True, timeout=20, check=True,
        )
        self.assertEqual(Path(json.loads(managed_run.stdout)["prefix"]).resolve(), runtime_root.resolve())


if __name__ == "__main__":
    unittest.main()
