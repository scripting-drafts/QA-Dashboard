"""External crash feed ingestion and component capture."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import classify, config, db, ingest


class CrashFeedIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="qa-crash-feed-"))
        self.feed = self.temp / "crashes.jsonl"
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(db.SCHEMA)
        self.patch_enabled = mock.patch.object(
            config, "CRASH_FEED_ENABLED", True)
        self.patch_paths = mock.patch.object(
            config, "CRASH_FEED_PATHS", (self.feed,))
        self.patch_enabled.start()
        self.patch_paths.start()

    def tearDown(self) -> None:
        self.patch_paths.stop()
        self.patch_enabled.stop()
        import shutil

        shutil.rmtree(self.temp, ignore_errors=True)

    def _write(self, *records: dict) -> None:
        with self.feed.open("a", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record) + "\n")

    def _record(self, incident_id: str, **overrides) -> dict:
        record = {
            "schema": "faultlab.crash.qa/1",
            "id": incident_id,
            "fingerprint": f"crash-feed|{incident_id}",
            "ts": "2026-11-20T12:00:00Z",
            "kind": "mce",
            "severity": "critical",
            "attribution": "direct",
            "faultcore_involved": 1,
            "pid": None,
            "comm": "",
            "exe": "",
            "component": "kernel",
            "sig": "mce",
            "cpus_allowed": "2",
            "corefile": "/var/log/faultlab/crashes/x",
            "incident_dir": "/var/log/faultlab/crashes/x",
            "context": "mce: [Hardware Error]: CPU: 2 Machine Check",
        }
        record.update(overrides)
        return record

    def test_disabled_feed_is_a_noop(self) -> None:
        with mock.patch.object(config, "CRASH_FEED_ENABLED", False), \
             mock.patch.object(config, "CRASH_FEED_PATHS", ()):
            self.assertEqual(ingest.ingest_crash_feed(self.conn), 0)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM crashes").fetchone()[0], 0)

    def test_ingest_captures_component_and_faultcore(self) -> None:
        self._write(
            self._record("inc-mce"),
            self._record(
                "inc-stress",
                kind="coredump",
                attribution="direct",
                comm="stress-ng",
                exe="/usr/bin/stress-ng",
                component="stress-ng",
                sig="SIGSEGV",
                context=(
                    "size=1M\n  PID: 10 (stress-ng)\n  Signal: 11 (SEGV)\n"
                    "  Stack trace of thread 10:\n"
                    "  #0 0x0 n/a (stress-ng + 0x1)\n"
                ),
            ),
            self._record(
                "inc-gnome",
                kind="coredump",
                attribution="none",
                faultcore_involved=0,
                comm="gnome-shell",
                exe="/usr/bin/gnome-shell",
                component="gnome-shell",
                sig="SIGTRAP",
                cpus_allowed="0-1,3-7,9-11",
                context=(
                    "size=1M\n  PID: 20 (gnome-shell)\n  Signal: 5 (TRAP)\n"
                    "  Stack trace of thread 20:\n"
                    "  #0 0x0 raise (libc.so.6 + 0x1)\n"
                ),
            ),
        )
        added = ingest.ingest_crash_feed(self.conn)
        self.assertEqual(added, 3)
        rows = {
            row["comm"]: dict(row)
            for row in self.conn.execute("SELECT * FROM crashes")
        }
        self.assertEqual(rows["kernel"]["component"], "linux (Ubuntu)")
        self.assertEqual(rows["kernel"]["faultcore_involved"], 1)
        self.assertEqual(rows["stress-ng"]["component"], "CPU / platform")
        self.assertEqual(rows["stress-ng"]["faultcore_involved"], 1)
        self.assertEqual(rows["gnome-shell"]["component"], "gnome-shell")
        self.assertEqual(rows["gnome-shell"]["faultcore_involved"], 0)

    def test_cursor_does_not_replay_and_reads_new_lines(self) -> None:
        self._write(self._record("inc-1"))
        self.assertEqual(ingest.ingest_crash_feed(self.conn), 1)
        self.assertEqual(ingest.ingest_crash_feed(self.conn), 0)
        self._write(self._record("inc-2"))
        self.assertEqual(ingest.ingest_crash_feed(self.conn), 1)

    def test_upsert_keeps_occurrence_context(self) -> None:
        self._write(self._record("inc-1"))
        ingest.ingest_crash_feed(self.conn)
        self._write(self._record("inc-1", occurrences=3))
        ingest.ingest_crash_feed(self.conn)
        row = self.conn.execute(
            "SELECT context FROM crashes WHERE fingerprint=?",
            ("crash-feed|inc-1",),
        ).fetchone()
        self.assertIn("occurrences=3", row["context"])

    def test_component_helper_handles_known_owner(self) -> None:
        vendor, component = classify.crash_component(
            "gnome-shell", "/usr/bin/gnome-shell", "SIGTRAP",
            "Stack trace of thread 1:\n#0 0x0 raise (libc.so.6 + 0x1)",
            0,
        )
        self.assertEqual(vendor, "gnome")
        self.assertEqual(component, "gnome-shell")

    def test_backfill_populates_old_rows(self) -> None:
        self.conn.execute(
            "INSERT INTO crashes(ts,pid,comm,exe,sig,corefile,cpus_allowed,"
            "faultcore_involved,context,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "2026-11-20T12:00:00Z", 1, "gnome-shell",
                "/usr/bin/gnome-shell", "SIGTRAP", "present",
                "0-1,3-7,9-11", 0,
                "Stack trace of thread 1:\n#0 0x0 raise (libc.so.6 + 0x1)",
                "old-fp",
            ),
        )
        self.assertEqual(ingest.backfill_crash_components(self.conn), 1)
        row = self.conn.execute(
            "SELECT component FROM crashes WHERE fingerprint='old-fp'"
        ).fetchone()
        self.assertEqual(row["component"], "gnome-shell")

    def test_explicit_component_drives_the_ticket_label(self) -> None:
        issue = {"vendor": "hardware", "rows": [{
            "component": "CPU / platform",
            "comm": "stress-ng", "exe": "/usr/bin/stress-ng",
            "sig": "SIGSEGV",
        }]}
        self.assertEqual(classify.component_for_issue(issue), "CPU / platform")


class CrashFeedConfigTests(unittest.TestCase):
    """QA stays standalone; feed discovery is automatic and optional."""

    def _run(self, extra: dict, home: Path) -> str:
        repo = Path(__file__).resolve().parents[1]
        env = {
            key: value for key, value in os.environ.items()
            if key not in {
                "QA_CRASH_FEED", "QA_CRASH_FEED_USER",
                "QA_FAULTLAB_CRASH_RESULTS", "QA_FAULTLAB_CRASH_USER_RESULTS",
                "QA_FAULT_CORE_CPUS", "QA_FAULT_CPUS", "QA_CORE2_CPUS",
                "QA_FAULT_CORE_ENABLE", "QA_FAULTLAB_CONFIG",
                "QA_CRASH_FEED_DEFAULT", "QA_CRASH_FEED_USER_DEFAULT",
                "HOME",
            }
        }
        env.update({
            "PYTHONPATH": str(repo),
            "PYTHONDONTWRITEBYTECODE": "1",
            "QA_SENTINELS_HOME": str(repo),
            "QA_FAULTLAB_CONFIG": "/nonexistent",
            "QA_CRASH_FEED_DEFAULT": str(home / "system.jsonl"),
            "QA_CRASH_FEED_USER_DEFAULT": str(home / "user.jsonl"),
            "HOME": str(home),
        })
        env.update(extra)
        code = (
            "from sentinels import config; "
            "print(config.CRASH_FEED_ENABLED, len(config.CRASH_FEED_PATHS))"
        )
        return subprocess.check_output(
            [sys.executable, "-c", code], cwd=repo, env=env, text=True
        ).strip()

    def test_no_faultlab_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._run({}, Path(tmp)), "False 0")

    def test_explicit_feed_enables_without_faultlab(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "feed.jsonl"
            self.assertEqual(
                self._run({"QA_CRASH_FEED": str(feed)}, Path(tmp)), "True 1")

    def test_fault_core_config_enables_default_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                self._run({"QA_FAULT_CORE_CPUS": "2,8"}, Path(tmp)),
                "True 2",
            )


if __name__ == "__main__":
    unittest.main()
