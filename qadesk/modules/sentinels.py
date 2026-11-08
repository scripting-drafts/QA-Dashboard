from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from ..core import parse_qa_status, path_uri
from ..ui.base import ModulePage


class SentinelsModule(ModulePage):
    id = "sentinels"
    title = "Sentinels"
    icon = "utilities-system-monitor-symbolic"
    description = "Routine evidence collection, findings, logs and evidence bundles."

    STATUS_KEYS = (
        "last sample", "last ingest", "last hardware", "last lsm", "lsm",
        "database", "critical", "inventory", "evidence", "ticket drafts",
        "core2 triage", "layer1", "boots", "notify", "layer2", "posture",
    )

    def __init__(self, app, config) -> None:
        super().__init__(app, config)
        self._lines: list[str] = []
        self.add_heading(
            "Routine monitoring, failure correlation and verifiable evidence. "
            "Commands run through the existing qa CLI."
        )

        self.status_card = self.card()
        self.status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.status_box.append(Gtk.Label(
            label="Refresh to read the current sentinel status.", xalign=0))
        self.status_card.append(self.status_box)

        self.refresh_button = self.action_button(
            "Refresh status", self.refresh, "Run qa status")
        self.cycle_button = self.action_button(
            "Run cycle", lambda: self.run_qa(["cycle"], "Running cycle"),
            "Run one routine sentinel pass")
        self.findings_button = self.action_button(
            "Findings", lambda: self.run_qa(["findings"], "Loading findings"))
        self.evidence_button = self.action_button(
            "Build evidence",
            lambda: self.run_qa(
                ["evidence", "--reason", "QA Desktop request", "--hours", "24"],
                "Building evidence bundle"),
            "Create a 24-hour hash-chained evidence bundle")
        self.logs_button = self.action_button(
            "Show logs", lambda: self.run_qa(["logs", "--lines", "300"],
                                             "Reading sentinel logs"))
        self.folder_button = self.action_button(
            "Open folder", self.open_folder, "Open the sentinel repository")
        self.stop_button = self.action_button(
            "Stop", self.stop_process, "Stop the running sentinel command")
        self.stop_button.set_sensitive(False)
        self.append(self.action_row(
            self.refresh_button, self.cycle_button, self.findings_button,
            self.evidence_button, self.logs_button, self.folder_button,
            self.stop_button))

        self.spinner = Gtk.Spinner()
        self.status_label = Gtk.Label(label="", xalign=0)
        self.status_label.set_wrap(True)
        self.status_label.add_css_class("dim")
        activity = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        activity.append(self.spinner)
        activity.append(self.status_label)
        self.append(activity)
        self.append(self.status_card)

        self.output_expander = Gtk.Expander(label="Command output")
        self.output_scroller, self.output_view = self.make_output(200)
        self.output_expander.set_child(self.output_scroller)
        self.append(self.output_expander)

        GLib.idle_add(self.refresh)

    def refresh(self) -> None:
        if not self._alive or self._runner.running():
            return
        self.run_qa(["status"], "Reading status")

    def run_qa(self, extra: list[str], message: str) -> None:
        if self._runner.running():
            self.set_status("A sentinel command is already running.", error=True)
            return
        binary = self.config.resolved_sentinels_bin()
        if not binary:
            self.set_status(
                "qa command not found. Set it in Settings or install Quality-Assurance-Sentinels.",
                error=True)
            return
        root = self.config.resolved_sentinels_root()
        self._lines = []
        self.clear_output(self.output_view)
        self.output_expander.set_expanded(bool(extra and extra[0] != "status"))
        self.set_busy(True, message)
        self.stop_button.set_sensitive(True)
        env = {"QA_SENTINELS_HOME": root} if root else None
        self.start_process(
            [binary] + extra,
            cwd=root or None,
            env=env,
            on_line=self._on_line,
            on_done=lambda rc: self._on_done(rc, extra),
        )

    def _on_line(self, line: str) -> None:
        self._lines.append(line)
        if len(self._lines) > 5000:
            self._lines = self._lines[-5000:]
        self.append_output(self.output_view, line)

    def _on_done(self, rc: int, extra: list[str]) -> None:
        self.set_busy(False)
        self.stop_button.set_sensitive(False)
        self.set_status(f"Command finished (exit {rc}).", error=rc != 0)
        if extra and extra[0] == "status":
            self.render_status("\n".join(self._lines))

    def render_status(self, text: str) -> None:
        while (child := self.status_box.get_first_child()) is not None:
            self.status_box.remove(child)
        values = parse_qa_status(text)
        if not values:
            label = Gtk.Label(
                label="No status values were returned. See the command output.",
                xalign=0)
            label.set_wrap(True)
            self.status_box.append(label)
            return
        ordered = [key for key in self.STATUS_KEYS if key in values]
        ordered.extend(key for key in values if key not in ordered)
        grid = Gtk.Grid(row_spacing=6, column_spacing=14)
        for row, key in enumerate(ordered):
            name = Gtk.Label(label=key, xalign=0, yalign=0)
            name.add_css_class("dim")
            value = Gtk.Label(label=values[key], xalign=0, yalign=0)
            value.set_wrap(True)
            value.set_selectable(True)
            value.set_hexpand(True)
            grid.attach(name, 0, row, 1, 1)
            grid.attach(value, 1, row, 1, 1)
        self.status_box.append(grid)

    def open_folder(self) -> None:
        root = self.config.resolved_sentinels_root()
        if not root:
            self.set_status("Sentinel repository folder is unknown.", error=True)
            return
        try:
            Gio.AppInfo.launch_default_for_uri(path_uri(root), None)
        except GLib.Error as exc:
            self.set_status(f"Could not open folder: {exc.message}", error=True)
