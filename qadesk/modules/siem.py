from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from ..core import http_json, read_token, service_state
from ..ui.base import ModulePage


class SiemModule(ModulePage):
    id = "siem"
    title = "SIEM"
    icon = "network-server-symbolic"
    description = "Local QA SIEM health, alerts, events and dashboard access."

    def __init__(self, app, config) -> None:
        super().__init__(app, config)
        self._loading = False
        self.add_heading(
            "Read the local QA SIEM API and acknowledge alerts. The bearer "
            "token is read from its protected file and is never displayed."
        )

        connection = self.card()
        grid = Gtk.Grid(row_spacing=8, column_spacing=12)
        self.url_entry = Gtk.Entry()
        self.url_entry.set_text(config.siem_url)
        self.url_entry.set_hexpand(True)
        self.token_file_entry = Gtk.Entry()
        self.token_file_entry.set_text(config.resolved_siem_token_file())
        self.token_file_entry.set_hexpand(True)
        self.token_entry = Gtk.Entry()
        self.token_entry.set_visibility(False)
        self.token_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.token_entry.set_placeholder_text("Optional bearer token (memory only)")
        self.token_entry.set_hexpand(True)
        for row, (label, widget) in enumerate((
                ("SIEM URL", self.url_entry),
                ("Token file", self.token_file_entry),
                ("Token override", self.token_entry))):
            name = Gtk.Label(label=label, xalign=0)
            name.add_css_class("dim")
            grid.attach(name, 0, row, 1, 1)
            grid.attach(widget, 1, row, 1, 1)
        connection.append(grid)
        self.append(connection)

        self.connect_button = self.action_button("Connect", self.refresh)
        self.dashboard_button = self.action_button(
            "Open dashboard", self.open_dashboard,
            "Open the local SIEM web dashboard")
        self.append(self.action_row(self.connect_button, self.dashboard_button))

        self.spinner = Gtk.Spinner()
        self.status_label = Gtk.Label(label="Not connected.", xalign=0)
        self.status_label.set_wrap(True)
        self.status_label.add_css_class("dim")
        activity = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        activity.append(self.spinner)
        activity.append(self.status_label)
        self.append(activity)

        self.status_card = self.card()
        self.status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.status_box.append(Gtk.Label(label="Connect to read SIEM state.",
                                         xalign=0))
        self.status_card.append(self.status_box)
        self.append(self.status_card)

        self.alerts_list = self._make_list_card("Open alerts", 180)
        self.events_list = self._make_list_card("Recent events", 220)
        GLib.idle_add(self.refresh)

    def _make_list_card(self, title: str, height: int) -> Gtk.ListBox:
        card = self.card()
        card.append(self.section_label(title))
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        listbox.set_show_separators(True)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(height)
        scroller.set_child(listbox)
        card.append(scroller)
        self.append(card)
        return listbox

    def refresh(self) -> None:
        if not self._alive or self._loading:
            return
        url = self.url_entry.get_text().strip()
        if not url:
            self.set_status("Enter the SIEM URL.", error=True)
            return
        token_file = self.token_file_entry.get_text().strip()
        override = self.token_entry.get_text().strip()
        token = override or read_token(token_file)
        self._loading = True
        self.set_busy(True, "Contacting QA SIEM\u2026")
        thread = threading.Thread(
            target=self._fetch, args=(url, token), daemon=True,
            name="qa-desktop-siem")
        thread.start()

    def _fetch(self, url: str, token: str) -> None:
        result = {
            "health": None, "stats": None, "alerts": [], "events": [],
            "service": service_state(), "error": "",
        }
        try:
            result["health"] = http_json(url, "/healthz", timeout=3.0)
        except Exception as exc:  # noqa: BLE001 - displayed in UI
            result["error"] = str(exc)
        if token:
            try:
                result["stats"] = http_json(url, "/api/v1/stats", token)
                result["alerts"] = http_json(
                    url, "/api/v1/alerts?status=open&limit=50", token)
                result["events"] = http_json(
                    url, "/api/v1/events?limit=50", token)
            except Exception as exc:  # noqa: BLE001 - displayed in UI
                result["error"] = str(exc)
        elif not result["error"]:
            result["error"] = (
                "No bearer token available. Set the token file or enter one.")
        GLib.idle_add(self._render, result)

    def _render(self, result: dict) -> None:
        if not self._alive:
            return
        self._loading = False
        self.set_busy(False)
        health = result.get("health") or {}
        stats = result.get("stats") or {}
        self._render_status(health, stats, result.get("service", "unknown"))
        self._render_alerts(result.get("alerts") or [])
        self._render_events(result.get("events") or [])
        error = result.get("error") or ""
        if error:
            self.set_status(error, error=True)
        else:
            self.set_status("Connected.", error=False)

    def _render_status(self, health: dict, stats: dict, service: str) -> None:
        while (child := self.status_box.get_first_child()) is not None:
            self.status_box.remove(child)
        values = [
            ("Service", service),
            ("Health", health.get("status", "unknown")),
            ("Version", health.get("version", "-")),
            ("Uptime", self._duration(health.get("uptime_s"))),
            ("Events", stats.get("events", "-")),
            ("Open alerts", stats.get("alerts_open", "-")),
            ("Alerts total", stats.get("alerts_total", "-")),
            ("Hosts", stats.get("hosts", "-")),
            ("Last event", stats.get("last_event_ts", "-")),
        ]
        grid = Gtk.Grid(row_spacing=5, column_spacing=14)
        for row, (key, value) in enumerate(values):
            name = Gtk.Label(label=key, xalign=0)
            name.add_css_class("dim")
            label = Gtk.Label(label=str(value), xalign=0)
            label.set_selectable(True)
            grid.attach(name, 0, row, 1, 1)
            grid.attach(label, 1, row, 1, 1)
        self.status_box.append(grid)

    @staticmethod
    def _duration(value) -> str:
        try:
            seconds = int(value)
        except (TypeError, ValueError):
            return "-"
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours}h {minutes}m {seconds}s"

    def _render_alerts(self, alerts: list) -> None:
        while (child := self.alerts_list.get_first_child()) is not None:
            self.alerts_list.remove(child)
        if not alerts:
            self.alerts_list.append(self._muted_row("No open alerts."))
            return
        for alert in alerts:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            box.set_margin_top(5)
            box.set_margin_bottom(5)
            top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            severity = str(alert.get("severity", ""))
            badge = Gtk.Label(label=severity or "alert")
            badge.add_css_class("badge")
            badge.add_css_class(f"badge-{severity.lower()}")
            top.append(badge)
            title = Gtk.Label(label=str(alert.get("rule", "alert")), xalign=0)
            title.set_hexpand(True)
            title.set_selectable(True)
            top.append(title)
            ack = Gtk.Button(label="Ack")
            ack.connect("clicked", lambda _button, ident=alert.get("id"):
                       self.ack(ident))
            top.append(ack)
            box.append(top)
            detail = Gtk.Label(
                label=f"host {alert.get('host_id', '-')} \u00b7 "
                      f"count {alert.get('count', '-')} \u00b7 "
                      f"last {alert.get('last_seen', '-')}",
                xalign=0)
            detail.add_css_class("dim")
            box.append(detail)
            row.set_child(box)
            self.alerts_list.append(row)

    def _render_events(self, events: list) -> None:
        while (child := self.events_list.get_first_child()) is not None:
            self.events_list.remove(child)
        if not events:
            self.events_list.append(self._muted_row("No recent events."))
            return
        for event in events:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            box.set_margin_top(4)
            box.set_margin_bottom(4)
            top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            severity = str(event.get("severity", ""))
            badge = Gtk.Label(label=severity or "event")
            badge.add_css_class("badge")
            badge.add_css_class(f"badge-{severity.lower()}")
            top.append(badge)
            title = Gtk.Label(label=str(event.get("event_type", "event")),
                              xalign=0)
            title.set_hexpand(True)
            title.set_selectable(True)
            top.append(title)
            timestamp = Gtk.Label(label=str(event.get("ts", "")), xalign=1)
            timestamp.add_css_class("dim")
            top.append(timestamp)
            box.append(top)
            detail = Gtk.Label(
                label=f"{event.get('rule', '-')} \u00b7 "
                      f"host {event.get('host_id', '-')} \u00b7 "
                      f"{event.get('subject') or event.get('detail') or ''}",
                xalign=0)
            detail.set_wrap(True)
            detail.add_css_class("dim")
            box.append(detail)
            row.set_child(box)
            self.events_list.append(row)

    def _muted_row(self, text: str) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        label = Gtk.Label(label=text, xalign=0)
        label.add_css_class("dim")
        label.set_margin_top(6)
        label.set_margin_bottom(6)
        row.set_child(label)
        return row

    def ack(self, alert_id) -> None:
        if alert_id is None:
            return
        url = self.url_entry.get_text().strip()
        token = self.token_entry.get_text().strip() or read_token(
            self.token_file_entry.get_text().strip())
        if not token:
            self.set_status("Cannot acknowledge without a bearer token.",
                            error=True)
            return
        self.set_status(f"Acknowledging alert {alert_id}\u2026")
        thread = threading.Thread(
            target=self._ack_worker, args=(url, token, alert_id),
            daemon=True, name="qa-desktop-siem-ack")
        thread.start()

    def _ack_worker(self, url: str, token: str, alert_id) -> None:
        try:
            http_json(url, "/api/v1/alerts/ack", token, method="POST",
                      payload={"id": alert_id})
        except Exception as exc:  # noqa: BLE001 - displayed in UI
            GLib.idle_add(lambda: self._alive and self.set_status(
                f"Ack failed: {exc}", error=True))
            return
        GLib.idle_add(self.refresh)

    def open_dashboard(self) -> None:
        url = self.url_entry.get_text().strip()
        if not url.lower().startswith(("http://", "https://")):
            self.set_status("Enter a valid http:// or https:// SIEM URL.",
                            error=True)
            return
        try:
            Gio.AppInfo.launch_default_for_uri(url.rstrip("/") + "/", None)
        except GLib.Error as exc:
            self.set_status(f"Could not open dashboard: {exc.message}",
                            error=True)
