"use strict";

const { Gio, GLib, Shell } = imports.gi;
const Main = imports.ui.main;

const APP_IDS = [
    "qa-dashboard.desktop",
    "qa-sentinels.desktop",
    "qa-siem.desktop",
];
let settings = null;
let settingsSignal = 0;
let appSystem = null;
let appSystemSignal = 0;
let timerId = 0;
let attempts = 0;

function iconName() {
    return settings &&
        settings.get_string("color-scheme") === "prefer-dark"
        ? "qa-dashboard-dark"
        : "qa-dashboard-light";
}

function findIconTexture(actor, depth) {
    if (!actor || depth > 5)
        return null;
    if (typeof actor.set_gicon === "function")
        return actor;
    if (actor.icon) {
        const found = findIconTexture(actor.icon, depth + 1);
        if (found)
            return found;
    }
    if (typeof actor.get_children === "function") {
        for (const child of actor.get_children()) {
            const found = findIconTexture(child, depth + 1);
            if (found)
                return found;
        }
    }
    return null;
}

function appIcons() {
    const icons = [];
    const seen = new Set();
    function walk(actor, depth) {
        if (!actor || depth > 12)
            return;
        if (actor.app && actor.icon &&
            typeof actor.app.get_id === "function" &&
            APP_IDS.indexOf(actor.app.get_id()) >= 0 &&
            !seen.has(actor)) {
            seen.add(actor);
            icons.push(actor);
        }
        if (typeof actor.get_children === "function") {
            for (const child of actor.get_children())
                walk(child, depth + 1);
        }
    }
    walk(Main.uiGroup, 0);
    return icons;
}

function setDockIcon() {
    const gicon = new Gio.ThemedIcon({ name: iconName() });
    for (const appIcon of appIcons()) {
        const texture = findIconTexture(appIcon, 0);
        if (texture)
            texture.set_gicon(gicon);
    }
}

function tick() {
    timerId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 600, () => {
        timerId = 0;
        setDockIcon();
        attempts += 1;
        if (attempts < 20)
            tick();
        return GLib.SOURCE_REMOVE;
    });
}

function schedule() {
    if (timerId)
        GLib.source_remove(timerId);
    attempts = 0;
    setDockIcon();
    tick();
}

function init() {
}

function enable() {
    settings = new Gio.Settings({ schema_id: "org.gnome.desktop.interface" });
    settingsSignal = settings.connect("changed::color-scheme", schedule);
    appSystem = Shell.AppSystem.get_default();
    appSystemSignal = appSystem.connect("app-state-changed", schedule);
    schedule();
}

function disable() {
    if (settings && settingsSignal)
        settings.disconnect(settingsSignal);
    if (appSystem && appSystemSignal)
        appSystem.disconnect(appSystemSignal);
    if (timerId)
        GLib.source_remove(timerId);
    settings = null;
    settingsSignal = 0;
    appSystem = null;
    appSystemSignal = 0;
    timerId = 0;
    attempts = 0;
}
