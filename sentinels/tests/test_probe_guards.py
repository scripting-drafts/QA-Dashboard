"""Probe timing and provenance guards.

Each test here corresponds to a ticket that reached the raise queue from a
probe read at the wrong point: a one-minute recovery reboot counted as a
silent stop, a per-init firmware notice counted as a fault, a ten-day-old PID
sample supplying affinity, and a persistent pstore archive counted on every
hardware run.
"""
from __future__ import annotations

import pathlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from sentinels import boot, classify, config, correlate, db, hardware, ingest
from sentinels import raise_ticket, tickets
from sentinels.util import iso, parse_iso, utcnow


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(db.SCHEMA)
    return conn


def _insert_boot(conn, boot_id, last_ts, *, start_ts=None, clean=0,
                 maintenance=0):
    conn.execute(
        "INSERT INTO boots(boot_id, seq, span, start_ts, last_ts, ended_clean,"
        " maintenance, markers, last_message, scans, pstore, kexec_loaded,"
        " crashkernel, vmcores, captured_ts)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (boot_id, -1, "span", start_ts, last_ts, clean, maintenance,
         "", "last line", "{}", "[]", 0, "", 0, last_ts),
    )


def _insert_event(conn, boot_id, ts, message, fingerprint, count=1):
    conn.execute(
        "INSERT INTO events(ts,boot_id,source,severity,unit,pid,comm,message,"
        "fingerprint,raw,count,last_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, boot_id, "journal", "warning", "kernel", 1, "x", message,
         fingerprint, "{}", count, ts),
    )


class BootBoundaryTests(unittest.TestCase):
    def test_span_start_uses_the_numeric_stamp(self):
        span = "Sun 2026-11-22 10:06:49 CET Sun 2026-11-22 10:07:48 CET"
        expected = datetime.strptime(
            "2026-11-22 10:06:49", "%Y-%m-%d %H:%M:%S"
        ).astimezone(timezone.utc)
        self.assertEqual(boot._span_start(span), iso(expected))
        self.assertIsNone(boot._span_start("no timestamp here"))

    def test_recovery_menu_exit_is_clean_and_maintenance(self):
        record = {
            "index": -1,
            "boot_id": "recovery",
            "span": "Sun 2026-11-22 10:06:49 CET Sun 2026-11-22 10:07:48 CET",
        }
        tail = (
            "2026-11-22T10:07:48+01:00 host systemd[1]: "
            "friendly-recovery.service: Deactivated successfully.\n"
            "2026-11-22T10:07:48+01:00 host systemd[1]: "
            "friendly-recovery.service: Unit process 2067 (bash) remains running.\n"
        )
        with mock.patch.object(boot, "_journal", return_value=tail), \
             mock.patch.object(boot, "_scan_output", return_value=""), \
             mock.patch.object(boot, "_last_epoch",
                               return_value="2026-11-22T09:07:48Z"), \
             mock.patch.object(boot, "_pstore_archives", return_value=[]):
            scanned = boot.scan_boot(record)
        self.assertEqual(scanned["ended_clean"], 1)
        self.assertEqual(scanned["maintenance"], 1)
        self.assertEqual(scanned["start_ts"],
                         iso(datetime.strptime(
                             "2026-11-22 10:06:49",
                             "%Y-%m-%d %H:%M:%S").astimezone(timezone.utc)))
        self.assertIn("friendly-recovery", scanned["markers"])

    def test_reboot_target_is_a_clean_shutdown(self):
        record = {"index": -1, "boot_id": "reboot", "span": "span"}
        tail = "2026-11-03T09:00:00Z host systemd[1]: Reached target reboot.target - System Reboot.\n"
        with mock.patch.object(boot, "_journal", return_value=tail), \
             mock.patch.object(boot, "_scan_output", return_value=""), \
             mock.patch.object(boot, "_last_epoch",
                               return_value="2026-11-03T09:00:00Z"), \
             mock.patch.object(boot, "_maintenance_boot", return_value=False):
            self.assertEqual(boot.scan_boot(record)["ended_clean"], 1)

    def test_maintenance_boot_never_becomes_an_unclean_finding(self):
        conn = _conn()
        _insert_boot(conn, "maint", iso(utcnow()), maintenance=1)
        self.assertEqual(boot.findings(conn, "2026-11-01T00:00:00Z"), [])


class CorrelationWindowTests(unittest.TestCase):
    def test_short_boot_has_no_death_window(self):
        conn = _conn()
        stop = iso(utcnow())
        start = iso(parse_iso(stop) - timedelta(seconds=59))
        _insert_boot(conn, "short", stop, start_ts=start)
        ts = iso(parse_iso(start) + timedelta(seconds=1))
        _insert_event(conn, "short", ts,
                      "Bluetooth: hci0: HCI LE Coded PHY feature bit is set, "
                      "but its usage is not supported.", "fp")
        row = dict(conn.execute("SELECT * FROM boots").fetchone())
        self.assertEqual(correlate.clusters_for_boot(conn, row), [])

    def test_maintenance_boot_is_excluded(self):
        conn = _conn()
        stop = iso(utcnow())
        start = iso(parse_iso(stop) - timedelta(hours=6))
        _insert_boot(conn, "maint", stop, start_ts=start, maintenance=1)
        _insert_event(conn, "maint", iso(parse_iso(stop) - timedelta(minutes=1)),
                      "NVRM: Xid (PCI:0000:01:00): 79", "fp")
        row = dict(conn.execute("SELECT * FROM boots").fetchone())
        self.assertEqual(correlate.clusters_for_boot(conn, row), [])

    def test_startup_events_are_outside_the_death_window(self):
        conn = _conn()
        stop = iso(utcnow())
        start = iso(parse_iso(stop) - timedelta(hours=6))
        _insert_boot(conn, "long", stop, start_ts=start)
        early = iso(parse_iso(start) + timedelta(seconds=30))
        late = iso(parse_iso(stop) - timedelta(minutes=1))
        _insert_event(conn, "long", early,
                      "ata3.00: supports DRM functions and may not be fully accessible",
                      "fp-ata")
        _insert_event(conn, "long", late, "NVRM: Xid 79", "fp-xid")
        row = dict(conn.execute("SELECT * FROM boots").fetchone())
        clusters = correlate.clusters_for_boot(conn, row)
        self.assertEqual([c["signature"] for c in clusters], ["NVRM: Xid N"])

    def test_reclassified_clean_boot_loses_its_stale_rows(self):
        conn = _conn()
        stop = iso(utcnow())
        _insert_boot(conn, "clean", stop, start_ts=stop, clean=1)
        conn.execute(
            "INSERT INTO correlations(boot_id, vendor, component, signature,"
            " display, occurrences, crashes, window_start, window_end, created)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("clean", "canonical-kernel", "kernel", "NOHZ tick-stop error",
             "NOHZ tick-stop error", 5, 0, stop, stop, stop),
        )
        correlate.correlate(conn, days=30, notify=False)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM correlations").fetchone()[0], 0)
        self.assertEqual(correlate.rows_for_signature(
            conn, "NOHZ tick-stop error"), [])

    def test_maintenance_is_not_counted_as_an_unclean_stop(self):
        conn = _conn()
        stop = iso(utcnow())
        _insert_boot(conn, "maint", stop, start_ts=stop, clean=0, maintenance=1)
        _insert_boot(conn, "real", stop, start_ts=stop, clean=0)
        summary = correlate.correlate(conn, days=30, notify=False)
        self.assertEqual(summary["unclean_boots"], 1)


class ProbeNoiseTests(unittest.TestCase):
    def test_per_init_notices_are_not_ticketworthy(self):
        for signature in (
            "Bluetooth: hci0: HCI LE Coded PHY feature bit is set, but its "
            "usage is not supported.",
            "ata3.00: supports DRM functions and may not be fully accessible",
            "ata13.N: supports DRM functions and may not be fully accessible",
            "usb: port power management may be unreliable",
            "nvidia: loading out-of-tree module taints kernel.",
            "File /var/log/journal/abc/system.journal corrupted or uncleanly "
            "shut down, renaming and replacing.",
            "File /var/log/journal/abc/user-1000.journal corrupted or uncleanly "
            "shut down, renaming and replacing.",
        ):
            self.assertFalse(
                classify.ticketworthy(signature, "correlation", "warning", 4),
                signature,
            )

    def test_coverage_finding_is_not_a_vendor_ticket(self):
        self.assertFalse(classify.ticketworthy(
            "hardware.coverage: hardware-sources: hardware sources limited: "
            "storage=needs-root", "finding", "warning", 200))
        self.assertTrue(classify.ticketworthy(
            "hardware.apei.pstore: pstore", "finding", "warning", 5))

    def test_real_correlation_is_still_ticketworthy(self):
        self.assertTrue(classify.ticketworthy(
            "NVRM: Xid (PCI:0000:01:00): 79", "correlation", "warning", 3))


class CrashProvenanceTests(unittest.TestCase):
    def _snapshot(self, conn, ts, pid, comm, exe, mask):
        conn.execute(
            "INSERT INTO proc_snap(ts,pid,ppid,comm,state,threads,rss_kb,"
            "cpu_ticks,last_cpu,cpus_allowed,exe) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (ts, pid, 1, comm, "S", 1, 100, 1, 0, mask, exe),
        )

    def test_stale_pid_sample_is_not_affinity_evidence(self):
        conn = _conn()
        crash_ts = "2026-11-19T00:39:41Z"
        stale = "2026-11-09T08:33:29Z"
        self._snapshot(conn, stale, 67438, "sleep", "/usr/bin/sleep", "0-11")
        self.assertIsNone(ingest._nearest_proc(
            conn, 67438, crash_ts, exe="/usr/bin/gnome-clocks"))

    def test_pid_reuse_with_a_different_executable_is_rejected(self):
        conn = _conn()
        crash_ts = "2026-11-19T00:39:41Z"
        recent = "2026-11-19T00:39:00Z"
        self._snapshot(conn, recent, 67438, "sleep", "/usr/bin/sleep", "0-11")
        self.assertIsNone(ingest._nearest_proc(
            conn, 67438, crash_ts, exe="/usr/bin/gnome-clocks"))

    def test_default_all_cpu_mask_is_not_a_faultcore_verdict(self):
        with mock.patch.object(config, "FAULT_CORE_CPUS", {2, 8}), \
             mock.patch.object(ingest.os, "cpu_count", return_value=12):
            self.assertEqual(ingest.faultcore_verdict(set(range(12))), 0)
            self.assertEqual(ingest.faultcore_verdict({2, 8}), 1)
            self.assertEqual(ingest.faultcore_verdict({0, 1, 3}), 0)

    def test_recent_matching_sample_supplies_the_mask(self):
        conn = _conn()
        crash_ts = "2026-11-19T00:39:41Z"
        recent = "2026-11-19T00:39:00Z"
        self._snapshot(conn, recent, 67438, "gnome-clocks",
                       "/usr/bin/gnome-clocks", "0,1,3")
        row = ingest._nearest_proc(
            conn, 67438, crash_ts, exe="/usr/bin/gnome-clocks")
        self.assertEqual(row["cpus_allowed"], "0,1,3")

    def test_sample_without_an_executable_is_not_affinity_evidence(self):
        conn = _conn()
        crash_ts = "2026-11-19T00:39:41Z"
        recent = "2026-11-19T00:39:00Z"
        self._snapshot(conn, recent, 67438, "gnome-clocks", "", "0,1,3")
        self.assertIsNone(ingest._nearest_proc(
            conn, 67438, crash_ts, exe="/usr/bin/gnome-clocks"))


class DistinctEvidenceTests(unittest.TestCase):
    def _finding(self, conn, fingerprint, ts, count):
        conn.execute(
            "INSERT INTO findings(fingerprint,ts,last_ts,rule,severity,subject,"
            "detail,count,status) VALUES(?,?,?,?,?,?,?,?,'open')",
            (fingerprint, ts, ts, "hardware.apei.pstore", "warning", "pstore",
             "pstore summary contains an error signature: Kernel panic", count),
        )

    def test_finding_runs_are_not_occurrences(self):
        conn = _conn()
        self._finding(conn, "fp-1", "2026-11-19T00:00:00Z", 50)
        self._finding(conn, "fp-2", "2026-11-20T00:00:00Z", 50)
        with mock.patch.object(tickets, "held_context", return_value=None):
            issues = tickets.collect_issues(conn, days=30)
        pstore = [i for i in issues
                  if i["signature"].startswith("hardware.apei.pstore")]
        self.assertEqual(len(pstore), 1)
        self.assertEqual(pstore[0]["count"], 2)

    def test_distinct_pstore_finding_remains_actionable(self):
        issue = {
            "key": "pstore", "vendor": "canonical-kernel",
            "signature": "hardware.apei.pstore: pstore",
            "kind": "finding", "severity": "warning", "count": 5,
            "first": iso(), "last": iso(),
            "rows": [{"ts": iso(), "severity": "warning",
                      "message": "hardware.apei.pstore: pstore: "
                                 "pstore summary contains an error signature: "
                                 "Kernel panic"}],
        }
        verdict = raise_ticket.assess(
            _conn(), {"issue_key": "pstore", "vendor": "canonical-kernel"}, issue)
        self.assertTrue(verdict["viable"], verdict)

    def test_coverage_issue_is_not_actionable(self):
        issue = {
            "key": "coverage", "vendor": "hardware",
            "signature": "hardware.coverage: hardware-sources",
            "kind": "finding", "severity": "warning", "count": 200,
            "first": iso(), "last": iso(),
            "rows": [{"ts": iso(), "severity": "warning",
                      "message": "hardware.coverage: hardware-sources: "
                                 "hardware sources limited: storage=needs-root"}],
        }
        verdict = raise_ticket.assess(
            _conn(), {"issue_key": "coverage", "vendor": "hardware"}, issue)
        self.assertFalse(verdict["viable"])
        self.assertIn("actionable",
                      [c["check"] for c in verdict["checks"] if not c["ok"]])


class BucketLifecycleTests(unittest.TestCase):
    def test_event_ticket_does_not_list_clean_boots_as_stops(self):
        conn = _conn()
        stop = iso(utcnow())
        _insert_boot(conn, "clean", stop, clean=1)
        _insert_boot(conn, "dirty", stop, clean=0, start_ts=stop)
        issue = {"signature": "NOHZ tick-stop error", "kind": "event"}
        rows = [{"boot_id": "clean"}, {"boot_id": "dirty"}]
        self.assertEqual(
            raise_ticket._stop_ids(conn, issue, rows), ["dirty"])

    def test_vendor_rename_does_not_count_as_a_manual_move(self):
        import json

        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp) / "canonical-kernel-ticket"
            (directory / "evidence").mkdir(parents=True)
            (directory / "evidence" / "manifest.json").write_text(
                json.dumps({"bucket": "raise", "vendor": "canonical-kernel"}),
                encoding="utf-8",
            )
            (directory / "evidence" / "lifecycle.jsonl").write_text(
                json.dumps({"event": "classified", "from": "", "to": "raise"}) + "\n"
                + json.dumps({"event": "renamed", "from": "hardware-ticket",
                              "to": directory.name}) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(raise_ticket._manual_bucket(directory, "raise"), "")


class PstoreArchiveTests(unittest.TestCase):
    def test_each_archive_is_one_finding_with_its_own_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for archive, stamp in (("179369479", 5938), ("179381869", 6527)):
                target = root / archive
                target.mkdir()
                (target / "summary.txt").write_text(
                    f"<0>[{stamp}.000000] Kernel panic - not syncing: "
                    "stack-protector: Kernel stack is corrupted in: __schedule\n",
                    encoding="utf-8",
                )
            items, findings, has_pstore = hardware._pstore_findings(root)
        self.assertTrue(has_pstore)
        self.assertEqual(len(items), 2)
        self.assertEqual(len(findings), 2)
        self.assertEqual(len({f["fingerprint"] for f in findings}), 2)
        self.assertEqual(findings[0]["ts"], hardware._archive_iso("179369479"))
        self.assertIn("stack-protector", findings[0]["detail"])
        self.assertEqual(
            classify.vendor_for_finding(
                "hardware.apei.pstore", "pstore", findings[0]["detail"]),
            "canonical-kernel",
        )


if __name__ == "__main__":
    unittest.main()
