from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, Gtk  # noqa: E402

from ..core import APP_VERSION, Config, MODULE_IDS
from ..modules import MODULE_CLASSES, MODULE_MAP

APP_ID = "org.scriptingdrafts.QADesktop"

CSS = """
.h1 { font-size: 22px; font-weight: 700; }
.h2 { font-size: 15px; font-weight: 700; }
.mono { font-family: monospace; }
.dim { opacity: 0.7; }
.error { color: #c01c28; }
.card { background-color: rgba(127,127,127,0.10); border-radius: 8px; padding: 10px; }
.badge { border-radius: 6px; padding: 1px 8px; font-weight: 700; }
.badge-clean, .badge-info { background-color: #2ec27e; color: #000000; }
.badge-suspicious, .badge-warning { background-color: #e5a50a; color: #000000; }
.badge-infected, .badge-critical, .badge-error { background-color: #c01c28; color: #ffffff; }
.badge-unknown { background-color: #77767b; color: #ffffff; }
"""


class QADesktopApp(Gtk.Application):
    def __init__(self, module_id: str = "suite") -> None:
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.module_id = module_id
        self.single_module = module_id in MODULE_IDS
        self.config = Config.load()
        self.window: Gtk.ApplicationWindow | None = None
        self.stack: Gtk.Stack | None = None
        self.modules: dict[str, object] = {}
        self.module_widgets: dict[str, Gtk.Widget] = {}
        self._css_installed = False
        self._install_actions()

    def _install_actions(self) -> None:
        for name, callback in (
            ("refresh", lambda _a, _p: self.refresh_current()),
            ("settings", lambda _a, _p: self.open_settings()),
            ("about", lambda _a, _p: self.open_about()),
            ("quit", lambda _a, _p: self.quit()),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def do_activate(self) -> None:
        if self.window is not None:
            self.window.present()
            return
        self._install_css()
        window_title = (MODULE_MAP[self.module_id].title
                        if self.single_module else "QA Desktop")
        self.window = Gtk.ApplicationWindow(application=self)
        self.window.set_title(window_title)
        self.window.set_default_size(1180, 820)

        header = Gtk.HeaderBar()
        title = Gtk.Label(label=window_title)
        title.add_css_class("h1")
        header.set_title_widget(title)
        menu = Gio.Menu()
        menu.append("Refresh module", "app.refresh")
        menu.append("Settings", "app.settings")
        menu.append("About", "app.about")
        menu.append("Quit", "app.quit")
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_menu_model(menu)
        header.pack_end(menu_button)
        self.window.set_titlebar(header)

        root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.stack = Gtk.Stack()
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        if not self.single_module:
            sidebar = Gtk.StackSidebar()
            sidebar.set_stack(self.stack)
            sidebar.set_size_request(190, -1)
            root.append(sidebar)
            root.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        root.append(self.stack)
        self.window.set_child(root)
        self.window.connect("close-request", self._on_close_request)
        self.reload_modules()
        self.window.present()

    def _install_css(self) -> None:
        if self._css_installed:
            return
        display = Gdk.Display.get_default()
        if display is None:
            return
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS.encode("utf-8"))
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self._css_installed = True

    def reload_modules(self) -> None:
        if self.stack is None:
            return
        current = self.stack.get_visible_child_name() or ""
        for module in self.modules.values():
            module.shutdown()
        for widget in self.module_widgets.values():
            self.stack.remove(widget)
        self.modules.clear()
        self.module_widgets.clear()
        classes = ((MODULE_MAP[self.module_id],) if self.single_module
                   else MODULE_CLASSES)
        for cls in classes:
            if not self.single_module and not self.config.enabled(cls.id):
                continue
            page = cls(self, self.config)
            scroller = Gtk.ScrolledWindow()
            scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            scroller.set_child(page)
            stack_page = self.stack.add_titled(scroller, page.id, page.title)
            if hasattr(stack_page, "set_icon_name"):
                stack_page.set_icon_name(page.icon)
            self.modules[page.id] = page
            self.module_widgets[page.id] = scroller
        if not self.modules:
            label = Gtk.Label(
                label="No modules are enabled. Enable at least one in Settings.",
                xalign=0)
            label.set_margin_top(24)
            label.set_margin_start(24)
            self.stack.add_titled(label, "empty", "No modules")
            self.module_widgets["empty"] = label
        preferred = (self.module_id if self.single_module
                     else self.module_id if self.module_id in self.modules
                     else current)
        if preferred not in self.modules:
            preferred = next(iter(self.modules), "empty")
        self.stack.set_visible_child_name(preferred)

    def refresh_current(self) -> None:
        if self.stack is None:
            return
        module_id = self.stack.get_visible_child_name() or ""
        module = self.modules.get(module_id)
        if module is not None:
            module.refresh()

    def open_settings(self) -> None:
        if self.window is None:
            return
        window = Gtk.Window(transient_for=self.window, modal=True,
                            title="QA Desktop Settings")
        window.set_default_size(700, 520)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        outer.set_margin_top(18)
        outer.set_margin_bottom(18)
        outer.set_margin_start(18)
        outer.set_margin_end(18)

        grid = Gtk.Grid(row_spacing=8, column_spacing=12)
        entries = {}
        fields = (
            ("sentinels_bin", "Sentinels command", self.config.sentinels_bin),
            ("sentinels_root", "Sentinels root", self.config.sentinels_root),
            ("malware_bin", "Malware Scan command", self.config.malware_bin),
            ("siem_url", "SIEM URL", self.config.siem_url),
            ("siem_token_file", "SIEM token file",
             self.config.siem_token_file),
        )
        for row, (key, label, value) in enumerate(fields):
            name = Gtk.Label(label=label, xalign=0)
            name.add_css_class("dim")
            entry = Gtk.Entry()
            entry.set_text(value)
            entry.set_hexpand(True)
            grid.attach(name, 0, row, 1, 1)
            grid.attach(entry, 1, row, 1, 1)
            entries[key] = entry
        outer.append(grid)

        outer.append(Gtk.Separator())
        outer.append(Gtk.Label(
            label="Enabled modules", xalign=0))
        modules_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        checks = {}
        for module_id in MODULE_IDS:
            check = Gtk.CheckButton(label=MODULE_MAP[module_id].title)
            check.set_active(self.config.enabled(module_id))
            modules_row.append(check)
            checks[module_id] = check
        outer.append(modules_row)

        error = Gtk.Label(label="", xalign=0)
        error.add_css_class("error")
        outer.append(error)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda _button: window.close())
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(save)
        outer.append(buttons)
        window.set_child(outer)

        def save_settings(_button) -> None:
            selected = [module_id for module_id in MODULE_IDS
                        if checks[module_id].get_active()]
            if not selected:
                error.set_text("Select at least one module.")
                return
            self.config.sentinels_bin = entries["sentinels_bin"].get_text().strip()
            self.config.sentinels_root = entries["sentinels_root"].get_text().strip()
            self.config.malware_bin = entries["malware_bin"].get_text().strip()
            self.config.siem_url = (
                entries["siem_url"].get_text().strip().rstrip("/")
                or "http://127.0.0.1:8088")
            self.config.siem_token_file = (
                entries["siem_token_file"].get_text().strip())
            self.config.enabled_modules = selected
            try:
                self.config.save()
            except OSError as exc:
                error.set_text(f"Could not save settings: {exc}")
                return
            window.close()
            self.reload_modules()

        save.connect("clicked", save_settings)
        window.present()

    def open_about(self) -> None:
        if self.window is None:
            return
        dialog = Gtk.AboutDialog()
        dialog.set_transient_for(self.window)
        dialog.set_modal(True)
        dialog.set_program_name("QA Desktop")
        dialog.set_version(APP_VERSION)
        dialog.set_comments(
            "Modular desktop access to Quality Assurance Sentinels, "
            "Malware Scan and QA SIEM.")
        dialog.set_license_type(Gtk.License.MIT_X11)
        dialog.present()

    def _on_close_request(self, _window) -> bool:
        for module in self.modules.values():
            module.shutdown()
        return False
