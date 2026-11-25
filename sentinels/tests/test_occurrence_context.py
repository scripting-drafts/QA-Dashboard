"""Occurrence context: raw windows, correlation growth, no summary files."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import config, db, occurrence, raise_ticket, tickets


def _case_text(case_id: int, fingerprint: str, event_ts: str,
               signature: str, body_lines: int = 120) -> str:
    lines = [
        f"# Fault-core triage case {case_id}: {signature}",
        "",
        "- Verdict: **confirmed**",
        "- Status: **open**",
        "- Kind: crash",
        f"- Process/unit: `{signature.split()[0]}`",
        "- Allowed CPUs at the event: `0,1`",
        f"- Event time (UTC): `{event_ts}`",
        "",
        "## What was observed",
        "",
        "```",
        "size=3.4M",
        "           PID: 2700 (gnome-terminal-)",
        "        Signal: 11 (SEGV)",
        "     Timestamp: Sun 2026-11-08 08:02:30 CET",
        "  Command Line: /usr/libexec/gnome-terminal-server",
        "    Executable: /usr/libexec/gnome-terminal-server",
        "          Unit: user@1000.service",
        "       Boot ID: b5d93acc55824068918eb74c52cc61bf",
        "                Stack trace of thread 2700:",
        "                #0  0x0001 n/a (libcairo.so.2 + 0x9e080)",
    ]
    for index in range(body_lines):
        lines.append(f"                frame {index:03d} (libcairo.so.2 + 0x{index:x})")
    lines += [
        "```",
        "",
        "## Why this is in the side queue",
        "",
        "The affinity mask included CPUs 2,8.",
        "",
        "## Guardrail",
        "",
        "This case is not omitted from reports or vendor evidence.",
    ]
    return "\n".join(lines) + "\n"


class EmbedTests(unittest.TestCase):
    def test_inserts_before_requested_action(self):
        text = "## Evidence\n\n- Bundle: x\n\n## Requested action\n"
        result = occurrence.embed_context(text, ["raw line"])
        self.assertEqual(result.count("### Occurrence context"), 1)
        self.assertLess(result.index("### Occurrence context"), result.index("## Requested action"))
        self.assertIn("raw line", result)

    def test_replaces_existing_block_without_duplication(self):
        text = (
            "## Evidence\n\n"
            "### Occurrence context\n\nold line\n\n"
            "## Requested action\n"
        )
        result = occurrence.embed_context(text, [r"new line \1 \g<name>"])
        self.assertEqual(result.count("### Occurrence context"), 1)
        self.assertNotIn("old line", result)
        self.assertIn(r"new line \1 \g<name>", result)
        self.assertLess(result.index("### Occurrence context"), result.index("## Requested action"))

    def test_appends_when_no_anchor_heading(self):
        result = occurrence.embed_context("# Ticket\n", ["raw line"])
        self.assertIn("### Occurrence context", result)
        self.assertIn("raw line", result)


class DraftMechanicsTests(unittest.TestCase):
    def test_draft_always_embeds_occurrence_context(self):
        issue = {
            "key": "x", "vendor": "local",
            "signature": "event signature", "display": "event signature",
            "kind": "event", "count": 1,
            "first": "2026-11-23T00:00:00Z", "last": "2026-11-23T00:00:00Z",
            "rows": [{"message": "event signature", "ts": "2026-11-23T00:00:00Z"}],
        }
        with mock.patch.object(
                tickets.faultcore, "topology",
                return_value={"present": False, "state": "unavailable"}), \
             mock.patch.object(tickets, "_software_versions", return_value=[]), \
             mock.patch.object(tickets, "_environment", return_value=["- OS: test"]), \
             mock.patch.object(
                 tickets.occurrence, "ticket_context",
                 return_value=["RAW WINDOW"]):
            _title, body = tickets._draft(issue, {"path": "/tmp/x"}, {}, False)
        self.assertIn("### Occurrence context", body)
        self.assertIn("RAW WINDOW", body)
        self.assertEqual(body.count("### Occurrence context"), 1)


class WindowTests(unittest.TestCase):
    def test_minimum_window_and_section_growth(self):
        lines = ["# case", "", "## What was observed", ""]
        for index in range(300):
            lines.append(f"line {index:03d}")
        lines.append("## Next")
        lines.append("unrelated")
        text = "\n".join(lines)
        window = occurrence._text_window(text, ["line 150"])
        self.assertIsNotNone(window)
        _lines, start, end, anchor = window
        self.assertLessEqual(start, max(0, anchor - occurrence.MIN_CONTEXT_LINES))
        self.assertGreaterEqual(end, min(len(lines), anchor + occurrence.MIN_CONTEXT_LINES + 1))
        self.assertIn("line 000", "\n".join(lines[start:end]))
        self.assertIn("line 299", "\n".join(lines[start:end]))

    def test_short_source_is_not_padded(self):
        text = "alpha\nbeta\ngamma\n"
        window = occurrence._text_window(text, ["beta"])
        self.assertIsNotNone(window)
        lines, start, end, _anchor = window
        self.assertEqual(start, 0)
        self.assertEqual(end, len(lines))

    def test_no_total_cap(self):
        text = "\n".join(f"line {index:04d}" for index in range(800))
        window = occurrence._text_window(text, ["line 0400"])
        self.assertIsNotNone(window)
        lines, start, end, _anchor = window
        self.assertEqual(start, 0)
        self.assertEqual(end, len(lines))


class StagedRefreshTests(unittest.TestCase):
    def test_legacy_ticket_without_context_is_refreshed(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "ticket"
            (directory / "evidence").mkdir(parents=True)
            issue = {
                "key": "abc", "vendor": "systemd", "display": "display",
                "count": 1, "last": "2026-11-23T00:00:00Z",
            }
            manifest = {
                "issue_key": "abc", "vendor": "systemd", "display": "display",
                "bucket": "raise", "occurrences": 1,
                "last": "2026-11-23T00:00:00Z",
            }
            (directory / "evidence" / "manifest.json").write_text(json.dumps(manifest))
            for name in ("ticket.md", "HOWTO.md", "evidence/logs.json",
                         "evidence/trace.md"):
                (directory / name).write_text("x")
            self.assertFalse(raise_ticket._already_staged(directory, issue))
            (directory / "ticket.md").write_text("### Occurrence context\n")
            (directory / "evidence" / "trace.md").write_text("## Occurrence context\n")
            self.assertTrue(raise_ticket._already_staged(directory, issue))


class CorrelationContextTests(unittest.TestCase):
    def test_correlation_uses_its_own_boots_and_surrounding_rows(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        boot = "a00a0b41bbc9423ea33c92364cbafe88"
        conn.execute(
            "INSERT INTO correlations(boot_id,vendor,component,signature,"
            "occurrences,crashes,window_start,window_end,created,display)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (boot, "canonical-kernel", "linux (Ubuntu)",
             "ata7.N: supports DRM functions and may not be fully accessible",
             2, 0, "2026-11-22T08:10:30Z", "2026-11-22T08:40:30Z",
             "2026-11-23T00:00:00Z",
             "ata7.00: supports DRM functions and may not be fully accessible"),
        )
        rows = [
            ("2026-11-22T08:36:28Z", "before row"),
            ("2026-11-22T08:37:59Z", "ata7.00: supports DRM functions and may not be fully accessible"),
            ("2026-11-22T08:38:59Z", "after row"),
        ]
        for index, (stamp, message) in enumerate(rows):
            conn.execute(
                "INSERT INTO events(id,ts,boot_id,severity,unit,comm,message,fingerprint)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (index + 1, stamp, boot, "warning", "ident:kernel", "",
                 message, f"fp-{index}"),
            )
        issue = {
            "key": "key", "vendor": "canonical-kernel",
            "signature": "ata7.N: supports DRM functions and may not be fully accessible",
            "display": "ata7.00: supports DRM functions and may not be fully accessible",
            "kind": "correlation",
            "rows": [{
                "ts": "2026-11-22T08:40:30Z",
                "comm": "linux (Ubuntu)",
                "sig": "ata7.00: supports DRM functions and may not be fully accessible",
                "message": "ata7.00: supports DRM functions and may not be fully accessible",
            }],
        }
        text = "\n".join(occurrence.ticket_context(issue, None, conn))
        self.assertIn("live database:events", text)
        self.assertIn("correlation windows", text)
        self.assertIn("before row", text)
        self.assertIn("after row", text)
        self.assertIn("ata7.00: supports DRM", text)
        conn.close()


class HardwareProbeContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.bundle = self.evidence / "20261123-144204-startup"
        self.bundle.mkdir(parents=True)
        self.patches = [
            mock.patch.object(config, "ROOT", self.root),
            mock.patch.object(config, "EVIDENCE_DIR", self.evidence),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def _write_bundle(self):
        (self.bundle / "findings.json").write_text(json.dumps([{
            "id": 267,
            "fingerprint": "hardware|coverage|hardware.coverage|hardware-sources",
            "rule": "hardware.coverage",
            "subject": "hardware-sources",
            "detail": "hardware sources limited: storage=needs-root",
            "ts": "2026-11-06T20:38:55Z",
            "last_ts": "2026-11-23T15:30:03Z",
        }]), encoding="utf-8")
        detail = "\n".join([
            "# storage",
            "# smartctl nvme0n1",
            "{",
            '  "smartctl": {',
            '    "messages": [{"string": "Smartctl open device: /dev/nvme0n1 failed: Permission denied"}],',
            '    "exit_status": 2',
            "  }",
            "}",
            "# gpu",
            "gpu data",
        ])
        (self.bundle / "hardware.json").write_text(json.dumps({
            "run": {
                "id": 735,
                "ts": "2026-11-20T13:19:02Z",
                "status": "partial",
                "sources": '{"storage": "needs-root", "gpu": "ok"}',
                "detail": detail,
            },
            "items": [],
        }), encoding="utf-8")

    def _issue(self, rule="hardware.coverage"):
        return {
            "key": "key", "vendor": "hardware",
            "signature": f"{rule}: hardware-sources",
            "display": "hardware.coverage: hardware-sources: hardware sources limited: storage=needs-root",
            "kind": "finding",
            "rows": [{
                "id": 267,
                "fingerprint": "hardware|coverage|hardware.coverage|hardware-sources",
                "rule": rule,
                "subject": "hardware-sources",
                "detail": "hardware sources limited: storage=needs-root",
                "ts": "2026-11-06T20:38:55Z",
                "last_ts": "2026-11-23T15:30:03Z",
            }],
        }

    def test_hardware_coverage_shows_probe_sources_and_raw_detail(self):
        self._write_bundle()
        text = "\n".join(occurrence.ticket_context(
            self._issue(), {"path": str(self.bundle)}))
        self.assertIn("Finding 267", text)
        self.assertIn("storage=needs-root", text)
        self.assertIn("Hardware probe run 735", text)
        self.assertIn("Run sources:", text)
        self.assertIn("Permission denied", text)

    def test_non_probe_hardware_finding_does_not_add_run_context(self):
        self._write_bundle()
        text = "\n".join(occurrence.ticket_context(
            self._issue("hardware.apei.pstore"), {"path": str(self.bundle)}))
        self.assertNotIn("Hardware probe run", text)


class TicketContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.triage = self.root / "triage" / "faultcore"
        self.bundle = self.evidence / "20261108-070242-layer1-finding"
        self.bundle.mkdir(parents=True)
        self.triage.mkdir(parents=True)
        self.patches = [
            mock.patch.object(config, "ROOT", self.root),
            mock.patch.object(config, "EVIDENCE_DIR", self.evidence),
            mock.patch.object(config, "TRIAGE_DIR", self.triage),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def _issue(self):
        fingerprint = "ffd0c185e5747fcd63391746ac889342ae3a593a"
        event_ts = "2026-11-08T07:02:31Z"
        context = "\n".join([
            "size=3.4M",
            "        Signal: 11 (SEGV)",
            "     Boot ID: b5d93acc55824068918eb74c52cc61bf",
            "                Stack trace of thread 2700:",
            "                #0  0x0001 n/a (libcairo.so.2 + 0x9e080)",
        ])
        return {
            "key": "be253d2b1c7f8dce546c",
            "signature": "gnome-terminal- SIGSEGV",
            "display": "gnome-terminal- SIGSEGV",
            "rows": [{
                "fingerprint": fingerprint,
                "ts": event_ts,
                "comm": "gnome-terminal-",
                "sig": "SIGSEGV",
                "context": context,
            }],
        }

    def _write_case(self, path: Path, case_id: int, fingerprint: str,
                    event_ts: str, signature: str) -> None:
        path.write_text(
            _case_text(case_id, fingerprint, event_ts, signature),
            encoding="utf-8",
        )

    def test_snapshot_and_current_case_are_both_raw(self):
        issue = self._issue()
        fingerprint = issue["rows"][0]["fingerprint"]
        event_ts = issue["rows"][0]["ts"]
        signature = "gnome-terminal- SIGSEGV"
        case_key = occurrence.case_key("crash", fingerprint)
        self._write_case(
            self.bundle / "triage-case-0007.md", 7, fingerprint, event_ts, signature)
        self._write_case(
            self.triage / "case-0007.md", 7, fingerprint, event_ts, signature)
        (self.bundle / "triage-cases.json").write_text(json.dumps([{
            "id": 7,
            "case_key": case_key,
            "event_ts": event_ts,
            "signature": signature,
            "path": "triage/faultcore/case-0007.md",
        }]), encoding="utf-8")

        text = "\n".join(occurrence.ticket_context(issue, {"path": str(self.bundle)}))
        self.assertIn("Triage case 7 — bundle snapshot", text)
        self.assertIn("Triage case 7 — current", text)
        self.assertIn("Signal: 11 (SEGV)", text)
        self.assertIn("#0  0x0001", text)
        self.assertIn("frame 119", text)
        self.assertNotIn("Summary:", text)
        self.assertGreater(text.count("\n"), occurrence.MIN_CONTEXT_LINES)

    def test_event_chain_includes_surrounding_records(self):
        issue = self._issue()
        fingerprint = issue["rows"][0]["fingerprint"]
        boot = "b5d93acc55824068918eb74c52cc61bf"
        rows = []
        for index in range(120):
            rows.append({
                "id": index,
                "ts": f"2026-11-08T07:0{index // 60}:{index % 60:02d}Z",
                "boot_id": boot,
                "unit": "user@1000.service",
                "severity": "error",
                "fingerprint": fingerprint if index == 60 else f"other-{index}",
                "message": f"event {index:03d} line one\nevent {index:03d} line two",
            })
        (self.bundle / "events.json").write_text(json.dumps(rows), encoding="utf-8")
        text = "\n".join(occurrence.ticket_context(issue, {"path": str(self.bundle)}))
        self.assertIn("Journal / event chain", text)
        self.assertIn("event 000 line one", text)
        self.assertIn("event 119 line one", text)
        self.assertGreaterEqual(text.count("\n"), occurrence.MIN_CONTEXT_LINES)

    def test_finding_detail_is_raw(self):
        issue = self._issue()
        fingerprint = issue["rows"][0]["fingerprint"]
        issue["kind"] = "finding"
        issue["signature"] = "kernel.oops: test"
        issue["rows"] = [{
            "fingerprint": fingerprint,
            "ts": "2026-11-08T07:02:31Z",
            "rule": "kernel.oops",
            "subject": "test",
            "detail": "kernel.oops: test\nline two\nline three",
        }]
        (self.bundle / "findings.json").write_text(json.dumps([{
            "id": 99,
            "fingerprint": fingerprint,
            "rule": "kernel.oops",
            "subject": "test",
            "detail": "kernel.oops: test\nline two\nline three",
        }]), encoding="utf-8")
        text = "\n".join(occurrence.ticket_context(issue, {"path": str(self.bundle)}))
        self.assertIn("Finding 99 — kernel.oops", text)
        self.assertIn("line three", text)

    def test_no_match_is_explicit(self):
        issue = self._issue()
        issue["rows"][0]["context"] = ""
        text = "\n".join(occurrence.ticket_context(issue, {"path": str(self.bundle)}))
        self.assertIn("No occurrence context found", text)

    def test_missing_bundle_path_is_resolved_by_basename(self):
        issue = self._issue()
        fingerprint = issue["rows"][0]["fingerprint"]
        event_ts = issue["rows"][0]["ts"]
        signature = "gnome-terminal- SIGSEGV"
        self._write_case(
            self.bundle / "triage-case-0007.md", 7, fingerprint, event_ts, signature)
        (self.bundle / "triage-cases.json").write_text(json.dumps([{
            "id": 7,
            "case_key": occurrence.case_key("crash", fingerprint),
            "event_ts": event_ts,
            "signature": signature,
        }]), encoding="utf-8")
        text = "\n".join(occurrence.ticket_context(
            issue, {"path": "/home/<user>/QA-Sentinels/evidence/20261108-070242-layer1-finding"}))
        self.assertIn("Triage case 7 — bundle snapshot", text)


if __name__ == "__main__":
    unittest.main()
