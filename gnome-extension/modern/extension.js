"use strict";

import Gio from "gi://Gio";
import GLib from "gi://GLib";
import Clutter from "gi://Clutter";
import St from "gi://St";

import * as Main from "resource:///org/gnome/shell/ui/main.js";
import * as PanelMenu from "resource:///org/gnome/shell/ui/panelMenu.js";
import { Extension } from "resource:///org/gnome/shell/extensions/extension.js";

export default class QADashboardExtension extends Extension {
    enable() {
        const icon = new St.Icon({
            gicon: new Gio.FileIcon({
                file: this.dir.get_child("qa-dashboard.svg"),
            }),
            style_class: "system-status-icon",
        });
        this._indicator = new PanelMenu.Button(0.0, "QA Dashboard", true);
        this._indicator.add_child(icon);
        this._indicator.connect("button-press-event", () => {
            this._launchDashboard();
            return Clutter.EVENT_STOP;
        });
        Main.panel.addToStatusArea("qa-dashboard", this._indicator, 1, "right");
    }

    _launchDashboard() {
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

    disable() {
        if (this._indicator) {
            this._indicator.destroy();
            this._indicator = null;
        }
    }
}
