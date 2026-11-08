from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import Callable, Optional

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402


class ProcessRunner:
    """Run a command without a shell and stream its output on the GTK thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen[str]] = None
        self._cancelled = False

    def start(self, args: list[str], *, cwd: Optional[str], env: dict[str, str],
              on_line: Callable[[str], None],
              on_done: Callable[[int], None]) -> None:
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                raise RuntimeError("a command is already running")
            self._cancelled = False
        thread = threading.Thread(
            target=self._run,
            args=(args, cwd, env, on_line, on_done),
            daemon=True,
            name="qa-desktop-command",
        )
        thread.start()

    def _run(self, args: list[str], cwd: Optional[str], env: dict[str, str],
             on_line: Callable[[str], None],
             on_done: Callable[[int], None]) -> None:
        proc: Optional[subprocess.Popen[str]] = None
        rc = -1
        try:
            with self._lock:
                if self._cancelled:
                    rc = 130
                    return
            proc = subprocess.Popen(
                args,
                cwd=cwd or None,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                close_fds=True,
                start_new_session=True,
            )
            with self._lock:
                self._proc = proc
            assert proc.stdout is not None
            for line in proc.stdout:
                if self._cancelled:
                    break
                GLib.idle_add(on_line, line.rstrip("\n"))
            rc = proc.wait()
        except Exception as exc:  # noqa: BLE001 - surfaced in the UI
            GLib.idle_add(on_line, f"error: {exc}")
            rc = -1
        finally:
            with self._lock:
                self._proc = None
            GLib.idle_add(on_done, rc)

    def stop(self) -> None:
        with self._lock:
            self._cancelled = True
            proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                return
        timer = threading.Timer(5.0, self._kill, args=(proc,))
        timer.daemon = True
        timer.start()

    @staticmethod
    def _kill(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    proc.kill()
                except OSError:
                    pass

    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None


class ModulePage(Gtk.Box):
    id = ""
    title = ""
    icon = ""
    description = ""

    def __init__(self, app, config) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app = app
        self.config = config
        self.set_margin_top(18)
        self.set_margin_bottom(18)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self._runner = ProcessRunner()
        self._alive = True
        self._busy = False
        self._buttons: list[Gtk.Button] = []

    def add_heading(self, subtitle: str = "") -> Gtk.Label:
        title = Gtk.Label(label=self.title, xalign=0)
        title.add_css_class("h1")
        self.append(title)
        if subtitle:
            label = Gtk.Label(label=subtitle, xalign=0)
            label.set_wrap(True)
            label.add_css_class("dim")
            self.append(label)
        return title

    def section_label(self, text: str) -> Gtk.Label:
        label = Gtk.Label(label=text, xalign=0)
        label.add_css_class("h2")
        return label

    def card(self) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.add_css_class("card")
        return box

    def action_button(self, label: str, callback: Callable[[], None],
                      tooltip: str = "") -> Gtk.Button:
        button = Gtk.Button(label=label)
        button.connect("clicked", lambda _button: callback())
        if tooltip:
            button.set_tooltip_text(tooltip)
        self._buttons.append(button)
        return button

    def action_row(self, *buttons: Gtk.Widget) -> Gtk.Grid:
        row = Gtk.Grid(column_spacing=8, row_spacing=8)
        row.set_halign(Gtk.Align.START)
        for index, button in enumerate(buttons):
            row.attach(button, index % 4, index // 4, 1, 1)
        return row

    def make_output(self, min_height: int = 160) -> tuple[Gtk.ScrolledWindow, Gtk.TextView]:
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(min_height)
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_cursor_visible(False)
        view.set_monospace(True)
        view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        view.add_css_class("mono")
        scroller.set_child(view)
        return scroller, view

    def append_output(self, view: Gtk.TextView, line: str, limit: int = 5000) -> None:
        buffer = view.get_buffer()
        end = buffer.get_end_iter()
        buffer.insert(end, line + "\n")
        if buffer.get_line_count() > limit:
            start = buffer.get_start_iter()
            cut = buffer.get_iter_at_line(buffer.get_line_count() - limit)
            buffer.delete(start, cut)
        buffer.place_cursor(buffer.get_end_iter())
        view.scroll_to_iter(buffer.get_end_iter(), 0.0, False, 0.0, 1.0)

    def clear_output(self, view: Gtk.TextView) -> None:
        view.get_buffer().set_text("")

    def set_status(self, text: str, *, error: bool = False) -> None:
        if hasattr(self, "status_label"):
            self.status_label.set_text(text)
            self.status_label.remove_css_class("error")
            if error:
                self.status_label.add_css_class("error")

    def set_busy(self, busy: bool, message: str = "") -> None:
        self._busy = busy
        for button in self._buttons:
            button.set_sensitive(not busy)
        if hasattr(self, "spinner"):
            if busy:
                self.spinner.start()
            else:
                self.spinner.stop()
        if message:
            self.set_status(message)

    def start_process(self, args: list[str], *, cwd: Optional[str] = None,
                      env: Optional[dict[str, str]] = None,
                      on_line: Callable[[str], None],
                      on_done: Callable[[int], None]) -> None:
        def line_callback(line: str) -> None:
            if self._alive:
                on_line(line)

        def done_callback(rc: int) -> None:
            if self._alive:
                on_done(rc)

        environment = os.environ.copy()
        environment.update({
            "NO_COLOR": "1",
            "TERM": "dumb",
            "PYTHONUNBUFFERED": "1",
        })
        if env:
            environment.update(env)
        self._runner.start(args, cwd=cwd, env=environment,
                           on_line=line_callback, on_done=done_callback)

    def stop_process(self) -> None:
        self._runner.stop()

    def refresh(self) -> None:
        pass

    def shutdown(self) -> None:
        self._alive = False
        self._runner.stop()
