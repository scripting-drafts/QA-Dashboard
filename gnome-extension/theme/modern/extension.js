import Gio from "gi://Gio";
import GLib from "gi://GLib";

import * as Main from "resource:///org/gnome/shell/ui/main.js";
import { Extension } from "resource:///org/gnome/shell/extensions/extension.js";

const APP_ID = "qa-dashboard.desktop";

export default class QADashboardThemeExtension extends Extension {
    enable() {
        this._settings = new Gio.Settings({
            schema_id: "org.gnome.desktop.interface",
        });
        this._settingsSignal = this._settings.connect(
            "changed::color-scheme", () => this._schedule());
        this._schedule();
    }

    disable() {
        if (this._settings && this._settingsSignal)
            this._settings.disconnect(this._settingsSignal);
        if (this._timerId)
            GLib.source_remove(this._timerId);
        this._settings = null;
        this._settingsSignal = 0;
        this._timerId = 0;
        this._attempts = 0;
    }

    _iconName() {
        return this._settings &&
            this._settings.get_string("color-scheme") === "prefer-dark"
            ? "qa-dashboard-dark"
            : "qa-dashboard-light";
    }

    _tick() {
        this._timerId = GLib.timeout_add(
            GLib.PRIORITY_DEFAULT, 600, () => {
                this._timerId = 0;
                this._setDockIcon();
                this._attempts += 1;
                if (this._attempts < 20)
                    this._tick();
                return GLib.SOURCE_REMOVE;
            });
    }

    _schedule() {
        if (this._timerId)
            GLib.source_remove(this._timerId);
        this._attempts = 0;
        this._setDockIcon();
        this._tick();
    }

    _findIconTexture(actor, depth = 0) {
        if (!actor || depth > 5)
            return null;
        if (typeof actor.set_gicon === "function")
            return actor;
        if (actor.icon) {
            const found = this._findIconTexture(actor.icon, depth + 1);
            if (found)
                return found;
        }
        if (typeof actor.get_children === "function") {
            for (const child of actor.get_children()) {
                const found = this._findIconTexture(child, depth + 1);
                if (found)
                    return found;
            }
        }
        return null;
    }

    _setDockIcon() {
        const dash = Main.overview && Main.overview.dash;
        if (!dash || typeof dash.getAppIcons !== "function")
            return;

        const gicon = new Gio.ThemedIcon({ name: this._iconName() });
        for (const appIcon of dash.getAppIcons()) {
            if (!appIcon.app || appIcon.app.get_id() !== APP_ID)
                continue;

            const texture = this._findIconTexture(appIcon);
            if (texture)
                texture.set_gicon(gicon);
        }
    }
}
