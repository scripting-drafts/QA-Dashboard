from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf, Gio, GLib  # noqa: E402

from .core import APP_VERSION

BUS_NAME = "org.scriptingdrafts.QADesktopTray"
ITEM_PATH = "/StatusNotifierItem"
MENU_PATH = "/MenuBar"
WATCHER_NAME = "org.kde.StatusNotifierWatcher"
WATCHER_PATH = "/StatusNotifierWatcher"

ITEM_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="i" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
    <method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
    <method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
    <method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
    <signal name="NewIcon"/>
    <signal name="NewStatus"><arg type="s"/></signal>
  </interface>
</node>
"""

MENU_XML = """
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg type="i" direction="in"/><arg type="i" direction="in"/>
      <arg type="as" direction="in"/>
      <arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg type="ai" direction="in"/><arg type="as" direction="in"/>
      <arg type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg type="i" direction="in"/><arg type="s" direction="in"/>
      <arg type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg type="i" direction="in"/><arg type="s" direction="in"/>
      <arg type="v" direction="in"/><arg type="u" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/>
    </method>
    <method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
    <method name="AboutToShowGroup">
      <arg type="ai" direction="in"/><arg type="ai" direction="out"/><arg type="ai" direction="out"/>
    </method>
    <signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})"/><arg type="a(ias)"/></signal>
    <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
    <signal name="ItemActivationRequested"><arg type="i"/><arg type="u"/></signal>
  </interface>
</node>
"""

TRAY_ICON_PATHS = (
    "/usr/share/icons/Adwaita/16x16/status/security-high-symbolic.symbolic.png",
    "/usr/share/icons/Adwaita/24x24/status/security-high-symbolic.symbolic.png",
    "/usr/share/icons/Adwaita/32x32/status/security-high-symbolic.symbolic.png",
    "/usr/share/icons/Adwaita/48x48/status/security-high-symbolic.symbolic.png",
    "/usr/share/icons/Adwaita/64x64/status/security-high-symbolic.symbolic.png",
    "/usr/share/icons/Adwaita/96x96/status/security-high-symbolic.symbolic.png",
)

FALLBACK_ICON_PATHS = (
    "/usr/share/icons/Adwaita/16x16/legacy/security-high.png",
    "/usr/share/icons/Adwaita/22x22/legacy/security-high.png",
    "/usr/share/icons/Adwaita/24x24/legacy/security-high.png",
    "/usr/share/icons/Adwaita/32x32/legacy/security-high.png",
    "/usr/share/icons/Adwaita/48x48/legacy/security-high.png",
)

MENU_ITEMS = (
    (1, "Sentinels", "sentinels"),
    (2, "Malware Scan", "malware"),
    (3, "SIEM", "siem"),
)


def _launcher() -> str:
    found = shutil.which("qa-desktop")
    if found:
        return found
    candidates = (
        Path(__file__).resolve().parents[2] / "bin" / "qa-desktop",
        Path.home() / ".local" / "bin" / "qa-desktop",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def _recolor_symbolic(path: str) -> tuple[int, int, bytes]:
    pixbuf = GdkPixbuf.Pixbuf.new_from_file(path)
    width = pixbuf.get_width()
    height = pixbuf.get_height()
    rowstride = pixbuf.get_rowstride()
    pixels = pixbuf.get_pixels()
    out = bytearray(width * height * 4)
    for y in range(height):
        for x in range(width):
            src = y * rowstride + x * 4
            dst = (y * width + x) * 4
            alpha = pixels[src + 3]
            if alpha:
                out[dst:dst + 4] = bytes((alpha, 0xDE, 0xDD, 0xDA))
    return width, height, bytes(out)


def _argb_pixmap(pixbuf: GdkPixbuf.Pixbuf) -> tuple[int, int, bytes]:
    width = pixbuf.get_width()
    height = pixbuf.get_height()
    rowstride = pixbuf.get_rowstride()
    pixels = pixbuf.get_pixels()
    out = bytearray(width * height * 4)
    for y in range(height):
        for x in range(width):
            src = y * rowstride + x * 4
            dst = (y * width + x) * 4
            red, green, blue, alpha = pixels[src:src + 4]
            out[dst:dst + 4] = bytes((alpha, red, green, blue))
    return width, height, bytes(out)


def tray_pixmaps() -> list[tuple[int, int, bytes]]:
    asset = Path(__file__).with_name("assets") / "qa-desktop-tray.svg"
    pixmaps = []
    if asset.is_file():
        for size in (16, 24, 32, 48, 64, 96):
            try:
                pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_size(
                    str(asset), size, size)
                pixmaps.append(_argb_pixmap(pixbuf))
            except Exception:
                continue
        if pixmaps:
            return pixmaps
    for path in TRAY_ICON_PATHS:
        try:
            pixmaps.append(_recolor_symbolic(path))
        except Exception:
            continue
    if pixmaps:
        return pixmaps
    for path in FALLBACK_ICON_PATHS:
        try:
            pixmaps.append(_argb_pixmap(GdkPixbuf.Pixbuf.new_from_file(path)))
        except Exception:
            continue
    return pixmaps


class QATray:
    def __init__(self) -> None:
        self.loop = GLib.MainLoop()
        self.connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.pixmaps = tray_pixmaps()
        self.icon_pixmap_variant = GLib.Variant("a(iiay)", self.pixmaps)
        self.registered = False

    def run(self) -> int:
        item_info = Gio.DBusNodeInfo.new_for_xml(ITEM_XML).lookup_interface(
            "org.kde.StatusNotifierItem")
        menu_info = Gio.DBusNodeInfo.new_for_xml(MENU_XML).lookup_interface(
            "com.canonical.dbusmenu")
        self.connection.register_object(
            ITEM_PATH, item_info, self._item_method, self._item_get, None)
        self.connection.register_object(
            MENU_PATH, menu_info, self._menu_method, self._menu_get, None)
        Gio.bus_own_name_on_connection(
            self.connection, BUS_NAME, Gio.BusNameOwnerFlags.NONE,
            self._name_acquired, self._name_lost)
        self.loop.run()
        return 0

    def _name_acquired(self, _connection, _name) -> None:
        Gio.bus_watch_name_on_connection(
            self.connection, WATCHER_NAME, Gio.BusNameWatcherFlags.NONE,
            self._watcher_appeared, self._watcher_vanished)

    def _name_lost(self, _connection, _name) -> None:
        self.loop.quit()

    def _watcher_appeared(self, _connection, _name, _owner) -> None:
        try:
            self.connection.call_sync(
                WATCHER_NAME, WATCHER_PATH, WATCHER_NAME,
                "RegisterStatusNotifierItem",
                GLib.Variant("(s)", (BUS_NAME,)),
                None, Gio.DBusCallFlags.NONE, -1, None)
            self.registered = True
        except Exception as exc:  # noqa: BLE001 - tray service is best effort
            self.registered = False
            print(f"qa-desktop-tray: cannot register with the tray watcher: {exc}",
                  file=sys.stderr, flush=True)

    def _watcher_vanished(self, _connection, _name) -> None:
        self.registered = False

    def _item_property(self, prop):
        return {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", "qa-desktop"),
            "Title": GLib.Variant("s", "QA Desktop"),
            "Status": GLib.Variant("s", "Active"),
            "WindowId": GLib.Variant("i", 0),
            "IconName": GLib.Variant("s", ""),
            "IconPixmap": self.icon_pixmap_variant,
            "OverlayIconName": GLib.Variant("s", ""),
            "AttentionIconName": GLib.Variant("s", ""),
            "AttentionMovieName": GLib.Variant("s", ""),
            "IconThemePath": GLib.Variant("s", ""),
            "ToolTip": GLib.Variant(
                "(sa(iiay)ss)",
                ("QA Desktop", self.pixmaps, "QA Desktop",
                 "Sentinels, Malware Scan and SIEM")),
            "ItemIsMenu": GLib.Variant("b", True),
            "Menu": GLib.Variant("o", MENU_PATH),
        }.get(prop, GLib.Variant("s", ""))

    def _item_get(self, _connection, _sender, _path, _interface, prop):
        return self._item_property(prop)

    def _item_method(self, _connection, _sender, _path, _interface, method,
                     _params, invocation) -> None:
        if method in ("Activate", "SecondaryActivate"):
            self._launch("sentinels")
        invocation.return_value(None)

    def _launch(self, module: str | None) -> None:
        launcher = _launcher()
        if not launcher:
            print("qa-desktop-tray: qa-desktop launcher was not found",
                  file=sys.stderr, flush=True)
            return
        args = [launcher]
        if module:
            args.extend(["--module", module])
        try:
            subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
                start_new_session=True)
        except OSError as exc:
            print(f"qa-desktop-tray: cannot launch QA Desktop: {exc}",
                  file=sys.stderr, flush=True)

    @staticmethod
    def _item_props(label: str | None) -> dict[str, GLib.Variant]:
        if label is None:
            return {"type": GLib.Variant("s", "separator"),
                    "visible": GLib.Variant("b", True)}
        return {
            "label": GLib.Variant("s", label),
            "type": GLib.Variant("s", "standard"),
            "enabled": GLib.Variant("b", True),
            "visible": GLib.Variant("b", True),
        }

    def _children(self) -> list[GLib.Variant]:
        children = []
        for item_id, label, _module in MENU_ITEMS:
            props = self._item_props(label)
            children.append(GLib.Variant("(ia{sv}av)", (item_id, props, [])))
        return children

    def _layout(self) -> GLib.Variant:
        root = (0, {"children-display": GLib.Variant("s", "submenu")},
                self._children())
        return GLib.Variant("(u(ia{sv}av))", (1, root))

    def _menu_props(self, item_id: int) -> dict[str, GLib.Variant]:
        if item_id == 0:
            return {"children-display": GLib.Variant("s", "submenu")}
        for ident, label, _module in MENU_ITEMS:
            if ident == item_id:
                return self._item_props(label)
        return {}

    def _menu_get(self, _connection, _sender, _path, _interface, prop):
        return {
            "Version": GLib.Variant("u", 3),
            "TextDirection": GLib.Variant("s", "ltr"),
            "Status": GLib.Variant("s", "normal"),
            "IconThemePath": GLib.Variant("as", []),
        }.get(prop, GLib.Variant("s", ""))

    def _menu_method(self, _connection, _sender, _path, _interface, method,
                     params, invocation) -> None:
        if method == "GetLayout":
            invocation.return_value(self._layout())
        elif method == "GetGroupProperties":
            ids, names = params.unpack()
            wanted = set(names)
            result = []
            for ident in ids:
                props = self._menu_props(ident)
                if wanted:
                    props = {key: value for key, value in props.items()
                             if key in wanted}
                result.append((ident, props))
            invocation.return_value(GLib.Variant("(a(ia{sv}))", (result,)))
        elif method == "GetProperty":
            ident, name = params.unpack()
            props = self._menu_props(ident)
            invocation.return_value(GLib.Variant(
                "(v)", (props.get(name, GLib.Variant("s", "")),)))
        elif method == "Event":
            ident, event_id, _data, _timestamp = params.unpack()
            if event_id == "clicked":
                self._activate_menu(ident)
            invocation.return_value(None)
        elif method == "EventGroup":
            for ident, event_id, _data, _timestamp in params.unpack()[0]:
                if event_id == "clicked":
                    self._activate_menu(ident)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            invocation.return_value(GLib.Variant("(b)", (False,)))
        elif method == "AboutToShowGroup":
            invocation.return_value(GLib.Variant("(aiai)", ([], [])))
        else:
            invocation.return_value(None)

    def _activate_menu(self, item_id: int) -> None:
        for ident, _label, module in MENU_ITEMS:
            if ident == item_id:
                self._launch(module)
                return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qa-desktop-tray")
    parser.add_argument("--version", action="version",
                        version=f"qa-desktop-tray {APP_VERSION}")
    parser.parse_args(argv)
    try:
        return QATray().run()
    except Exception as exc:  # noqa: BLE001 - keep autostart failures visible in logs
        print(f"qa-desktop-tray: startup failed: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
