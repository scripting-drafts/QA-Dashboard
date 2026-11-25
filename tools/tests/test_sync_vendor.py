#!/usr/bin/env python3
"""Tests for tools/sync_vendor.py."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import sync_vendor  # noqa: E402


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


class SyncVendorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.source = base / "source"
        self.dashboard = base / "dashboard"
        self._make_source()
        self._make_dashboard()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _commit(self, root: Path, message: str) -> None:
        git(root, "add", "-A")
        git(root, "commit", "-qm", message)

    def _make_source(self) -> None:
        root = self.source
        git(root.parent, "init", "-q", str(root))
        git(root, "config", "user.email", "test@example.invalid")
        git(root, "config", "user.name", "Test")
        write(root / "sentinels" / "__init__.py",
              '"""QA Sentinels."""\n__version__ = "1.2.3"\n')
        write(root / "bin" / "qa", "#!/bin/sh\nexit 0\n", 0o755)
        write(root / "docs" / "RULES.md",
              "# QA Sentinels rules and checks\n\n"
              "This register describes QA Sentinels `1.2.3`.\n\n"
              "## Portable platform rules\n\n"
              "Implemented in `sentinels/platform_cycle.py`.\n")
        write(root / "debian" / "changelog",
              "qa-sentinels (1.2.3) jammy; urgency=medium\n\n"
              "  * Test release.\n\n"
              " -- Test <test@example.invalid>  Mon, 01 Jan 2026 00:00:00 +0000\n")
        write(root / "tests" / "test_sample.py", "def test_ok():\n    pass\n")
        write(root / "legal" / "manifest.json",
              json.dumps({"product": "QA Sentinels"}, indent=2) + "\n")
        write(root / "README.md", "# QA Sentinels\n")
        write(root / ".gitignore", "var/\n")
        self._commit(root, "source")
        git(root, "tag", "-a", "v1.2.3", "-m", "Release 1.2.3")

    def _make_dashboard(self) -> None:
        root = self.dashboard
        git(root.parent, "init", "-q", str(root))
        git(root, "config", "user.email", "test@example.invalid")
        git(root, "config", "user.name", "Test")
        write(root / "sentinels" / "sentinels" / "__init__.py",
              '__version__ = "1.2.2"\n')
        write(root / "sentinels" / "stale.py", "stale = True\n")
        write(root / "sentinels" / "var" / "keep.txt", "runtime\n")
        write(root / ".gitignore", "sentinels/var/\n")
        write(root / "legal" / "manifest.json", json.dumps({
            "reviewedComponents": {"qa-sentinels": "1.2.2"},
            "components": [
                {"id": "qa-dashboard", "version": "0.1.0"},
                {"id": "qa-sentinels", "name": "QA Sentinels",
                 "version": "1.2.2"},
            ],
        }, indent=2) + "\n")
        write(root / "contracts" / "versions.json", json.dumps({
            "qa_dashboard": "0.1.0",
            "qa_sentinels": "1.2.2",
        }, indent=2) + "\n")
        write(root / "docs" / "RULES.md",
              "# QA Sentinels rules\n\nQA Sentinels `1.2.2`.\n\n"
              "## Portable platform rules (WIP)\n")
        write(root / "sentinels-vendor.json", json.dumps({
            "source": sync_vendor.DEFAULT_SOURCE,
            "version": "1.2.2",
            "commit": "0" * 40,
            "syncedAt": "2026-01-01",
        }, indent=2) + "\n")
        self._commit(root, "dashboard")

    def run_main(self, args: list[str], *, source: bool = True) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        command = list(args) + ["--root", str(self.dashboard)]
        if source:
            command += ["--source", str(self.source)]
        environment = dict(os.environ)
        environment.pop("QA_SENTINELS_SOURCE", None)
        with mock.patch.dict(os.environ, environment, clear=True):
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                code = sync_vendor.main(command)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_write_and_check(self) -> None:
        code, _, stderr = self.run_main(
            ["--write", "--ref", "v1.2.3"])
        self.assertEqual(code, 0, stderr)

        vendor = self.dashboard / "sentinels"
        self.assertIn(
            '__version__ = "1.2.3"',
            (vendor / "sentinels" / "__init__.py").read_text(encoding="utf-8"))
        self.assertTrue((vendor / "tests" / "test_sample.py").is_file())
        self.assertFalse((vendor / "stale.py").exists())
        self.assertTrue((vendor / "var" / "keep.txt").is_file())
        if os.name != "nt":
            self.assertTrue(os.access(vendor / "bin" / "qa", os.X_OK))

        marker = json.loads(
            (self.dashboard / "sentinels-vendor.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["version"], "1.2.3")
        self.assertEqual(marker["tag"], "v1.2.3")
        self.assertEqual(marker["commit"], git(self.source, "rev-parse", "HEAD"))
        self.assertTrue((self.dashboard / "sentinels-vendor.manifest").is_file())

        legal = json.loads(
            (self.dashboard / "legal" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(legal["reviewedComponents"]["qa-sentinels"], "1.2.3")
        component = next(
            item for item in legal["components"]
            if item["id"] == "qa-sentinels")
        self.assertEqual(component["version"], "1.2.3")
        contracts = json.loads(
            (self.dashboard / "contracts" / "versions.json").read_text(
                encoding="utf-8"))
        self.assertEqual(contracts["qa_sentinels"], "1.2.3")
        rules = (self.dashboard / "docs" / "RULES.md").read_text(encoding="utf-8")
        self.assertTrue(rules.startswith("# QA Sentinels rules\n"))
        self.assertIn("## Portable platform rules (WIP)", rules)

        code, stdout, stderr = self.run_main(["--check"])
        self.assertEqual(code, 0, stderr)
        self.assertIn("is aligned", stdout)

        code, stdout, stderr = self.run_main(["--check"], source=False)
        self.assertEqual(code, 0, stderr)
        self.assertIn("manifest and registers only", stdout)

    def test_check_detects_content_change(self) -> None:
        self.assertEqual(self.run_main(["--write", "--ref", "v1.2.3"])[0], 0)
        target = self.dashboard / "sentinels" / "sentinels" / "__init__.py"
        target.write_text('__version__ = "9.9.9"\n', encoding="utf-8")
        code, _, stderr = self.run_main(["--check"])
        self.assertEqual(code, 1)
        self.assertIn("content differs: sentinels/__init__.py", stderr)

    def test_check_detects_extra_file(self) -> None:
        self.assertEqual(self.run_main(["--write", "--ref", "v1.2.3"])[0], 0)
        write(self.dashboard / "sentinels" / "extra.py", "extra = True\n")
        code, _, stderr = self.run_main(["--check"], source=False)
        self.assertEqual(code, 1)
        self.assertIn("unrecorded vendored file: extra.py", stderr)

    def test_write_rejects_unexpected_file(self) -> None:
        write(self.dashboard / "sentinels" / "extra.py", "extra = True\n")
        code, _, stderr = self.run_main(["--write", "--ref", "v1.2.3"])
        self.assertEqual(code, 1)
        self.assertIn("unexpected vendored files: extra.py", stderr)

    def test_check_detects_manifest_tamper(self) -> None:
        self.assertEqual(self.run_main(["--write", "--ref", "v1.2.3"])[0], 0)
        manifest = self.dashboard / "sentinels-vendor.manifest"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("  sentinels/", "  sentinels/x", 1),
                            encoding="utf-8")
        code, _, stderr = self.run_main(["--check"], source=False)
        self.assertEqual(code, 1)
        self.assertIn("missing vendored file", stderr)

    def test_write_rejects_tag_version_mismatch(self) -> None:
        git(self.source, "tag", "-a", "v9.9.9", "-m", "Wrong")
        code, _, stderr = self.run_main(["--write", "--ref", "v9.9.9"])
        self.assertEqual(code, 1)
        self.assertIn("does not match source version", stderr)

    def test_write_requires_ref(self) -> None:
        code, _, stderr = self.run_main(["--write"])
        self.assertEqual(code, 1)
        self.assertIn("requires --ref", stderr)


if __name__ == "__main__":
    unittest.main()
