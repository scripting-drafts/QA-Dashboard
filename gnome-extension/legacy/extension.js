"use strict";

const { Gio, GLib, St, Clutter } = imports.gi;
const Main = imports.ui.main;
const PanelMenu = imports.ui.panelMenu;
const ExtensionUtils = imports.misc.extensionUtils;

let indicator = null;

function launchDashboard() {
    let command = GLib.find_program_in_path("qa-dashboard");
    if (!command) {
        command = GLib.build_filenamev([
            GLib.get_home_dir(), ".local", "bin", "qa-dashboard",
        ]);
    }
    try {
        Gio.Subprocess.new([command, "--module=overview"],
            Gio.SubprocessFlags.NONE);
    } catch (error) {
        logError(error, "QA Dashboard launch failed");
    }
}

function init() {
}

function enable() {
    const extension = ExtensionUtils.getCurrentExtension();
    const icon = new St.Icon({
        gicon: new Gio.FileIcon({
            file: extension.dir.get_child("qa-dashboard.svg"),
        }),
        style_class: "system-status-icon",
    });
    indicator = new PanelMenu.Button(0.0, "QA Dashboard", true);
    indicator.add_child(icon);
    indicator.connect("button-press-event", () => {
        launchDashboard();
        return Clutter.EVENT_STOP;
    });
    Main.panel.addToStatusArea("qa-dashboard", indicator, 1, "right");
}

function disable() {
    if (indicator) {
        indicator.destroy();
        indicator = null;
    }
}
