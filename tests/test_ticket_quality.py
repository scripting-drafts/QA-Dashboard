"""Ticket quality rules: process anchoring, component choice and stack evidence.

Each test here corresponds to a defect seen in a real draft: a GNOME Shell
crash routed to Mozilla because SpiderMonkey symbols look like Firefox, a
WebRender component label on a mutter crash, Firefox reproduction steps on a
desktop crash, and redaction destroying the component name.
"""
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from sentinels import classify, crash, raise_ticket, tickets
from sentinels.util import iso, redact

# Trimmed from a real gnome-shell core: libmozjs makes it look like Mozilla,
# the signal handler makes frame #0 look like the fault, and the module dump
# would consume any fixed-size prefix of the context.
GNOME_SHELL_CONTEXT = """\
size=27.6M
           PID: 3836 (gnome-shell)
           UID: 1000 (<user>)
        Signal: 11 (SEGV)
     Timestamp: Tue 2026-11-17 17:59:41 CET (1min 5s ago)
  Command Line: /usr/bin/gnome-shell
    Executable: /usr/bin/gnome-shell
     Boot ID: 70e28b9b462a45b4b75955f47b57f681
     Message: Process 3836 (gnome-shell) dumped core.
                Found module libdbusmenu-glib.so.4 with build-id: 849f1b8d
                Found module libmozjs-91.so.0 with build-id: 7cb5cd49
                Found module libmutter-10.so.0 with build-id: a786cd78
                Stack trace of thread 3836:
                #0  0x00007b6d1ba9691c __pthread_kill_implementation (libc.so.6 + 0x9691c)
                #1  0x00007b6d1ba42406 __GI_raise (libc.so.6 + 0x42406)
                #2  0x000064b86be8b7aa n/a (gnome-shell + 0x37aa)
                #3  0x00007b6d1ba424b0 __restore_rt (libc.so.6 + 0x424b0)
                #4  0x00007b6d1be9c02b meta_compositor_get_laters (libmutter-10.so.0 + 0x9c02b)
                #5  0x00007b6d1bf0dc18 n/a (libmutter-10.so.0 + 0x10dc18)
                #6  0x00007b6d1d37ded1 g_object_unref (libgobject-2.0.so.0 + 0x22ed1)
                #7  0x00007b6d1c3185f3 n/a (libgjs.so.0 + 0x585f3)
                #8  0x00007b6d1a5a1f94 _Z5JS_GCP9JSContextN2JS8GCReasonE (libmozjs-91.so.0 + 0x1a1f94)
"""

FIREFOX_CONTEXT = """\
size=37.0M
           PID: 85009 (firefox-bin)
        Signal: 11 (SEGV)
     Timestamp: Wed 2026-11-11 12:16:08 CET
  Command Line: /usr/lib/firefox-esr/firefox-bin -contentproc
    Executable: /usr/lib/firefox-esr/firefox-bin
                Found module libxul.so with build-id: cb6222da
                Stack trace of thread 85009:
                #0  0x00007f00 gdk_window_process_updates (libgdk-3.so.0 + 0x1234)
                #1  0x00007f00 g_object_unref (libgobject-2.0.so.0 + 0x22ed1)
                #2  0x00007f00 n/a (libxul.so + 0xabc123)
"""

# A non-browser process that loads systemd, DBus and NVIDIA libraries. The
# old content fallback read the whole module dump and filed this as systemd,
# nvidia or kernel depending on which rule came first.
PYTHON_CONTEXT = """\
size=12.0M
           PID: 4242 (python3)
        Signal: 11 (SEGV)
     Timestamp: Tue 2026-11-17 18:00:00 CET
  Command Line: python3 /usr/bin/private-scanner
    Executable: /usr/bin/python3.10
                Found module libsystemd.so.0 with build-id: 11111111
                Found module libdbus-1.so.3 with build-id: 22222222
                Found module libnvidia-glcore.so.550.163.01 with build-id: 33333333
                Stack trace of thread 4242:
                #0  0x00007f00 XQueryExtension (libX11.so.6 + 0x38ab4)
                #1  0x00007f00 n/a (libffi.so.8 + 0x7e2e)
"""


def _crash_row(**overrides):
    row = {
        "ts": iso(),
        "comm": "gnome-shell",
        "exe": "/usr/bin/gnome-shell",
        "sig": "SIGSEGV",
        "cpus_allowed": "0,1,3,4,5,6,7,9,10,11",
        "faultcore_involved": 0,
        "context": GNOME_SHELL_CONTEXT,
    }
    row.update(overrides)
    return row


def _issue(vendor="gnome", rows=None, kind="crash"):
    rows = rows if rows is not None else [_crash_row()]
    return {
        "key": "b69b8d3a4350bd6987f6",
        "vendor": vendor,
        "signature": "gnome-shell SIGSEGV",
        "display": "gnome-shell SIGSEGV",
        "kind": kind,
        "count": len(rows),
        "severity": "critical",
        "first": rows[0]["ts"],
        "last": rows[-1]["ts"],
        "rows": rows,
        "held": {},
    }


class OwnershipTests(unittest.TestCase):
    def test_gnome_shell_spidermonkey_frames_are_not_mozilla(self):
        self.assertEqual(
            classify.vendor_for_crash(
                "gnome-shell", "/usr/bin/gnome-shell", "SIGSEGV",
                GNOME_SHELL_CONTEXT),
            "gnome",
        )
        self.assertEqual(
            classify.process_vendor("gnome-shell", "/usr/bin/gnome-shell"),
            "gnome",
        )

    def test_firefox_keeps_ownership_against_gtk_frames(self):
        self.assertEqual(
            classify.vendor_for_crash(
                "firefox-bin", "/usr/lib/firefox-esr/firefox-bin",
                "SIGSEGV", FIREFOX_CONTEXT),
            "mozilla",
        )

    def test_firefox_content_process_is_owned_by_its_executable(self):
        self.assertEqual(
            classify.vendor_for_crash(
                "Isolated Web Co", "/usr/lib/firefox-esr/firefox-bin",
                "SIGILL", "Found module libxul.so"),
            "mozilla",
        )

    def test_truncated_comm_still_matches(self):
        self.assertEqual(
            classify.process_vendor("gnome-terminal-",
                                    "/usr/libexec/gnome-terminal-server"),
            "gnome",
        )

    def test_faulting_driver_module_overrides_the_process(self):
        context = (
            "                Stack trace of thread 1:\n"
            "                #0  0x0000 n/a (libnvidia-glcore.so.550.163.01 + 0x1234)\n"
        )
        self.assertEqual(
            classify.vendor_for_crash(
                "firefox-bin", "/usr/lib/firefox-esr/firefox-bin",
                "SIGSEGV", context),
            "nvidia",
        )

    def test_module_list_does_not_override_ownership(self):
        # libnvidia appears in the module dump but the faulting frame is mutter.
        self.assertEqual(
            classify.vendor_for_crash(
                "gnome-shell", "/usr/bin/gnome-shell", "SIGSEGV",
                "Found module libnvidia-glcore.so.550.163.01\n" + GNOME_SHELL_CONTEXT),
            "gnome",
        )


class ComponentTests(unittest.TestCase):
    def test_component_follows_the_faulting_frame(self):
        self.assertEqual(
            classify.component_for(
                "gnome", GNOME_SHELL_CONTEXT, "libmutter-10.so.0",
                "gnome-shell", "/usr/bin/gnome-shell"),
            "mutter",
        )

    def test_component_falls_back_to_the_process(self):
        self.assertEqual(
            classify.component_for(
                "gnome", "size=3.5M\n#0 n/a (libcairo.so.2 + 0x9e0ed)",
                "libcairo.so.2", "gnome-terminal-",
                "/usr/libexec/gnome-terminal-server"),
            "gnome-terminal",
        )
        self.assertEqual(
            classify.component_for(
                "gnome", "Found module libgs_plugin_snap.so",
                "libgs_plugin_snap.so", "gnome-software", "/usr/bin/gnome-software"),
            "gnome-software",
        )

    def test_mozilla_component_is_not_always_webrender(self):
        self.assertEqual(
            classify.component_for("mozilla", FIREFOX_CONTEXT, "libxul.so"),
            "Firefox :: Untriaged",
        )
        self.assertEqual(
            classify.component_for(
                "mozilla", "Signature: webrender::scene_building::SceneBuilder", ""),
            "Core :: Graphics: WebRender",
        )


class ContentFallbackTests(unittest.TestCase):
    """The module dump is not ownership evidence."""

    def test_python_with_systemd_and_nvidia_libraries_stays_local(self):
        self.assertEqual(
            classify.vendor_for_crash(
                "python3", "/usr/bin/python3.10", "SIGSEGV", PYTHON_CONTEXT),
            "local",
        )

    def test_electron_with_dbus_and_systemd_libraries_stays_local(self):
        context = PYTHON_CONTEXT.replace("(python3)", "(electron)").replace(
            "/usr/bin/python3.10", "/opt/app/electron")
        self.assertEqual(
            classify.vendor_for_crash(
                "electron", "/opt/app/electron", "SIGTRAP", context),
            "local",
        )

    def test_faulting_nvidia_frame_still_reaches_nvidia(self):
        context = (
            "size=1M\n  PID: 1 (python3)\n  Signal: 11 (SEGV)\n"
            "  Stack trace of thread 1:\n"
            "  #0 0x0000 n/a (libnvidia-glcore.so.550.163.01 + 0x1234)\n"
        )
        self.assertEqual(
            classify.vendor_for_crash(
                "python3", "/usr/bin/python3.10", "SIGSEGV", context),
            "nvidia",
        )

    def test_header_still_identifies_the_vendor(self):
        minidump = "Firefox ESR main-process crash — WebRender scene-builder panic"
        self.assertEqual(
            classify.vendor_for_crash("", "", "SIGSEGV", minidump), "mozilla")
        coredump = (
            "size=1M\n  PID: 1 (nvidia-settings)\n  Signal: 6 (ABRT)\n"
            "  Executable: /usr/bin/nvidia-settings\n"
            "  Found module libnvidia-glcore.so.550.163.01\n"
        )
        self.assertEqual(
            classify.vendor_for_crash("", "", "SIGABRT", coredump), "nvidia")


class ComponentTotalityTests(unittest.TestCase):
    """Every issue gets a label; ``unknown`` is never returned."""

    def test_module_project_beats_the_process_for_local_issues(self):
        issue = {"vendor": "local", "rows": [{
            "comm": "python3", "exe": "/usr/bin/python3.10",
            "context": PYTHON_CONTEXT,
        }]}
        self.assertEqual(classify.component_for_issue(issue), "xorg-server")

    def test_process_names_a_local_crash_without_a_mapped_module(self):
        issue = {"vendor": "local", "rows": [{
            "comm": "python3", "exe": "/usr/bin/python3.10",
            "context": (
                "size=1M\n  PID: 1 (python3)\n  Signal: 11 (SEGV)\n"
                "  Stack trace of thread 1:\n"
                "  #0 0x0000 n/a (libpangoft2-1.0.so.0 + 0x1)\n"
            ),
        }]}
        self.assertEqual(classify.component_for_issue(issue), "python3.10")

    def test_event_unit_names_the_component(self):
        issue = {"vendor": "local", "rows": [{
            "unit": "systemd-coredump@0-116469-0.service",
            "message": "Process 116468 (python3) dumped core.",
        }]}
        self.assertEqual(classify.component_for_issue(issue), "systemd-coredump")

    def test_correlation_event_components_are_never_unknown(self):
        from sentinels import correlate

        self.assertEqual(
            correlate.component_for_event(None, "something odd happened"),
            ("local", "unassigned"),
        )
        self.assertEqual(
            correlate.component_for_event(
                "org.gnome.Shell@x11.service", "ATK Bridge is disabled"),
            ("gnome", "gnome-shell"),
        )
        self.assertEqual(
            correlate.component_for_event(
                "systemd-coredump@0-1-0.service", "Process dumped core"),
            ("systemd", "systemd-coredump"),
        )

    def test_finding_subject_and_rule_name_the_component(self):
        cases = [
            ({"rule": "crash.faultcore", "subject": "gnome-terminal-"},
             "gnome-terminal"),
            ({"rule": "journal.critical", "subject": "ident:kernel"}, "kernel"),
            ({"rule": "kernel.oops", "subject": "session-2"}, "kernel"),
            ({"rule": "systemd.shutdown", "subject": "user@1000"}, "systemd"),
            ({"rule": "journal.critical", "subject": "systemd-coredump@0-1-0.service"},
             "systemd-coredump"),
            ({"rule": "journal.critical", "subject": "smartmontools"}, "smartmontools"),
        ]
        for row, expected in cases:
            issue = {"vendor": "local", "rows": [row]}
            self.assertEqual(
                classify.component_for_issue(issue), expected, row)

    def test_last_resort_is_unassigned(self):
        for issue in (
            {"vendor": "local", "rows": []},
            {"vendor": "local", "rows": [{}]},
            {"vendor": "", "rows": [{"message": "nothing identifying"}]},
            {"vendor": "local", "rows": [{"unit": "user@1000.service",
                                          "message": "session message"}]},
        ):
            self.assertEqual(classify.component_for_issue(issue), "unassigned")

    def test_component_is_never_unknown_or_empty(self):
        issues = [
            {"vendor": "local", "rows": []},
            {"vendor": "local", "rows": [{"rule": "journal.critical",
                                          "subject": "user@1000"}]},
            {"vendor": "gnome", "rows": [_crash_row()]},
            {"vendor": "mozilla", "rows": [_crash_row(
                comm="firefox-bin", exe="/usr/lib/firefox-esr/firefox-bin",
                context=FIREFOX_CONTEXT)]},
            {"vendor": "systemd", "rows": [_crash_row(
                comm="python3", exe="/usr/bin/python3.10",
                context=PYTHON_CONTEXT)]},
        ]
        for issue in issues:
            label = classify.component_for_issue(issue)
            self.assertTrue(label)
            self.assertNotEqual(label.lower(), "unknown")

    def test_wrong_vendor_cannot_choose_the_component(self):
        # A mis-routed systemd ticket must not hide the Python/X11 evidence.
        issue = {"vendor": "systemd", "rows": [_crash_row(
            comm="python3", exe="/usr/bin/python3.10", context=PYTHON_CONTEXT)]}
        self.assertNotEqual(classify.component_for_issue(issue), "systemd")


class DigestTests(unittest.TestCase):
    def test_faulting_frame_skips_the_signal_handler(self):
        frame = crash.faulting_frame(GNOME_SHELL_CONTEXT)
        self.assertEqual(frame["index"], 4)
        self.assertTrue(frame["handler"])
        self.assertEqual(frame["symbol"], "meta_compositor_get_laters")
        self.assertEqual(frame["module"], "libmutter-10.so.0")

    def test_crash_without_a_handler_uses_frame_zero(self):
        context = (
            "                Stack trace of thread 7:\n"
            "                #0  0x0000 crash_here (libcairo.so.2 + 0x9e0ed)\n"
            "                #1  0x0000 n/a (n/a + 0x0)\n"
        )
        frame = crash.faulting_frame(context)
        self.assertEqual(frame["index"], 0)
        self.assertFalse(frame["handler"])

    def test_digest_keeps_the_stack_and_drops_the_module_dump(self):
        digest = crash.digest(GNOME_SHELL_CONTEXT)
        self.assertIn("#4 meta_compositor_get_laters (libmutter-10.so.0 + 0x9c02b)", digest)
        self.assertIn("#7 n/a (libgjs.so.0 + 0x585f3)", digest)
        self.assertNotIn("Found module", digest)
        self.assertIn("module lines omitted", digest)

    def test_minidump_text_is_not_truncated_to_an_empty_digest(self):
        text = "Firefox ESR main-process crash\nTop frames:\n  RustMozCrash\n"
        self.assertEqual(crash.digest(text), text)


class RedactionEvidenceTests(unittest.TestCase):
    def test_component_and_unit_names_survive(self):
        text = ("Core :: Graphics: WebRender; session "
                "org.gnome.Shell@x11.service; user@1000.service")
        out = redact(text)
        self.assertIn("Core :: Graphics", out)
        self.assertIn("org.gnome.Shell@x11.service", out)
        self.assertIn("user@1000.service", out)
        self.assertNotIn("<ip>", out)
        self.assertNotIn("<email>", out)

    def test_real_addresses_are_still_removed(self):
        out = redact("mail person@example.com ip ::1 mac aa:bb:cc:dd:ee:ff")
        self.assertNotIn("person@example.com", out)
        self.assertNotIn("::1", out)
        self.assertNotIn("aa:bb:cc", out)


class DraftQualityTests(unittest.TestCase):
    def _draft(self, issue):
        topo = {"present": None, "state": "retired", "logical": [],
                "physical_id": None, "configured": [2, 8], "degraded": [2, 8]}
        with mock.patch.object(tickets.faultcore, "topology", return_value=topo), \
             mock.patch.object(tickets, "_software_versions",
                               return_value=[{"package": "gnome-shell",
                                              "version": "42.9-0ubuntu2.4"}]), \
             mock.patch.object(tickets, "_environment",
                               return_value=["- OS: Ubuntu 22.04.5 LTS"]):
            return tickets._draft(issue, None, {}, False)

    def test_gnome_shell_draft_is_gnome_and_carries_the_stack(self):
        title, body = self._draft(_issue())
        self.assertTrue(title.startswith("[QA] mutter: gnome-shell SIGSEGV"), title)
        self.assertIn("Faulting frame: `#4 meta_compositor_get_laters", body)
        self.assertIn("signal handler re-raising", body)
        self.assertIn("## Classification", body)
        self.assertIn("SpiderMonkey", body)
        self.assertNotIn("[fault core", title)
        self.assertNotIn("fresh Firefox profile", body)
        self.assertNotIn("about:crashes", body)
        self.assertNotIn("WebRender", body.split("## Reproduction")[0])
        self.assertIn("Reproduction viability: **~70%**", body)

    def test_gnome_terminal_draft_names_gnome_terminal(self):
        row = _crash_row(
            comm="gnome-terminal-", exe="/usr/libexec/gnome-terminal-server",
            context=("size=3.5M\n  PID: 2600 (gnome-terminal-)\n"
                     "  Signal: 11 (SEGV)\n"
                     "  Stack trace of thread 2600:\n"
                     "  #0  0x0000 n/a (libcairo.so.2 + 0x9e0ed)\n"),
        )
        title, _body = self._draft(_issue(rows=[row]))
        self.assertTrue(title.startswith("[QA] gnome-terminal:"), title)

    def test_firefox_draft_keeps_the_browser_repro(self):
        row = _crash_row(
            comm="firefox-esr", exe="/usr/lib/firefox-esr/firefox-bin",
            context=FIREFOX_CONTEXT,
        )
        issue = _issue(vendor="mozilla", rows=[row])
        issue["signature"] = issue["display"] = "firefox-esr SIGSEGV"
        _title, body = self._draft(issue)
        self.assertIn("fresh Firefox profile", body)
        self.assertIn("about:crashes", body)

    def test_mozilla_event_does_not_get_browser_repro(self):
        row = {
            "ts": "2026-11-11T16:22:56Z",
            "comm": "firefox-bin",
            "message": "nsDBusRemoteServer: Unable to unregister root object",
        }
        issue = _issue(vendor="mozilla", rows=[row], kind="event")
        issue["signature"] = issue["display"] = "nsDBusRemoteServer unable to unregister"
        _title, body = self._draft(issue)
        self.assertNotIn("fresh Firefox profile", body)
        self.assertIn("Reproduce the action logged above", body)


class StagedVendorTests(unittest.TestCase):
    def test_vendor_prefix_is_realigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            directory = root / "mozilla-gnome-shell-sigsegv-c0d06bf6"
            (directory / "evidence").mkdir(parents=True)
            renamed = raise_ticket._align_vendor_name(directory, "gnome")
            self.assertEqual(renamed.name, "gnome-gnome-shell-sigsegv-c0d06bf6")
            self.assertTrue((renamed / "evidence" / "lifecycle.jsonl").exists())
            self.assertFalse(directory.exists())

    def test_staged_ticket_is_rewritten_after_rerouting(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp) / "mozilla-gnome-shell-sigsegv-c0d06bf6"
            (directory / "evidence").mkdir(parents=True)
            issue = _issue()
            (directory / "evidence" / "manifest.json").write_text(json.dumps({
                "issue_key": issue["key"],
                "vendor": "mozilla",
                "display": issue["display"],
                "bucket": "raise",
                "occurrences": issue["count"],
                "last": issue["last"],
            }))
            for name in ("ticket.md", "HOWTO.md", "evidence/logs.json",
                         "evidence/trace.md"):
                (directory / name).write_text("x")
            self.assertFalse(raise_ticket._already_staged(directory, issue))

    def test_run_reroutes_and_renames_a_staged_ticket(self):
        import sqlite3

        from sentinels import config, db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        issue = _issue()
        topo = {"present": None, "state": "retired", "logical": [],
                "physical_id": None, "configured": [2, 8], "degraded": [2, 8]}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            raise_dir = root / "raise"
            old = raise_dir / "mozilla-gnome-shell-sigsegv-c0d06bf6"
            (old / "evidence").mkdir(parents=True)
            (old / "evidence" / "manifest.json").write_text(json.dumps({
                "issue_key": "b69b8d3a4350bd6987f6",
                "vendor": "mozilla",
                "signature": "gnome-shell SIGSEGV",
                "display": "gnome-shell SIGSEGV",
                "kind": "crash",
                "bucket": "raise",
                "occurrences": 1,
                "first": issue["first"],
                "last": issue["last"],
                "generated": "2026-11-17T16:00:00Z",
                "viability": {},
                "evidence_files": {},
            }))
            (old / "ticket.md").write_text("# old mozilla ticket\n")
            draft_path = root / "draft.md"
            with mock.patch.object(tickets.faultcore, "topology", return_value=topo), \
                 mock.patch.object(tickets, "_software_versions", return_value=[]), \
                 mock.patch.object(tickets, "_environment", return_value=["- OS: test"]):
                _title, body = tickets._draft(issue, None, {}, False)
            draft_path.write_text(body)
            conn.execute(
                "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
                " VALUES(?,?,?,?,?)",
                ("2026-11-17T16:00:00Z", "gnome", str(draft_path),
                 "gnome-shell SIGSEGV", issue["key"]),
            )
            with mock.patch.object(config, "RAISE_DIR", raise_dir), \
                 mock.patch.object(config, "REJECT_DIR", root / "rejected"), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues",
                                   return_value=[issue]), \
                 mock.patch.object(raise_ticket.report, "append_journal"):
                result = raise_ticket.run(conn, notify_ready=False)

            self.assertEqual(result["viable"], 1, result)
            new = raise_dir / "gnome-gnome-shell-sigsegv-c0d06bf6"
            self.assertTrue(new.is_dir(), sorted(p.name for p in raise_dir.iterdir()))
            self.assertFalse(old.exists())
            manifest = json.loads((new / "evidence" / "manifest.json").read_text())
            self.assertEqual(manifest["vendor"], "gnome")
            staged = (new / "ticket.md").read_text()
            self.assertIn("## Classification", staged)
            self.assertIn("Faulting frame: `#4 meta_compositor_get_laters", staged)


if __name__ == "__main__":
    unittest.main()
