#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-dashboard"
BIN="$PREFIX/bin/qa-dashboard"
APPS="$PREFIX/share/applications"
ICONS="$PREFIX/share/icons/hicolor"
DOC="$PREFIX/share/doc/qa-dashboard"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
LEGACY_EXT_UUID="qa-dashboard@local"
LEGACY_EXT_DIR="$DATA/gnome-shell/extensions/$LEGACY_EXT_UUID"
THEME_EXT_UUID="qa-dashboard-theme@local"
THEME_EXT_DIR="$DATA/gnome-shell/extensions/$THEME_EXT_UUID"

# Stop Electron and any legacy Python tray/app.
ps -eo pid=,args= | awk -v app="$LIB" 'index($0, app) && $0 ~ /electron/ && $0 !~ /awk/ {print $1}' \
    | xargs -r kill 2>/dev/null || true
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk.tray" {print $1}' \
    | xargs -r kill 2>/dev/null || true
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk" {print $1}' \
    | xargs -r kill 2>/dev/null || true
sleep 1

if command -v gnome-extensions >/dev/null 2>&1; then
    gnome-extensions disable "$LEGACY_EXT_UUID" >/dev/null 2>&1 || true
    gnome-extensions disable "$THEME_EXT_UUID" >/dev/null 2>&1 || true
fi
rm -rf "$LEGACY_EXT_DIR" "$THEME_EXT_DIR"
if command -v gsettings >/dev/null 2>&1; then
    for uuid in "$LEGACY_EXT_UUID" "$THEME_EXT_UUID"; do
        ENABLED="$(gsettings get org.gnome.shell enabled-extensions 2>/dev/null || true)"
        if printf '%s' "$ENABLED" | grep -q "$uuid"; then
            UPDATED="$(printf '%s' "$ENABLED" \
                | sed "s/'$uuid', //; s/, '$uuid'//; s/'$uuid'//")"
            gsettings set org.gnome.shell enabled-extensions "$UPDATED" 2>/dev/null || true
        fi
        DISABLED="$(gsettings get org.gnome.shell disabled-extensions 2>/dev/null || true)"
        if printf '%s' "$DISABLED" | grep -q "$uuid"; then
            UPDATED_DISABLED="$(printf '%s' "$DISABLED" \
                | sed "s/'$uuid', //; s/, '$uuid'//; s/'$uuid'//")"
            gsettings set org.gnome.shell disabled-extensions "$UPDATED_DISABLED" 2>/dev/null || true
        fi
    done
    FAVORITES="$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || true)"
    if printf '%s' "$FAVORITES" | grep -q "'qa-dashboard.desktop'"; then
        UPDATED_FAVORITES="$(printf '%s' "$FAVORITES" \
            | sed "s/'qa-dashboard.desktop', //; s/, 'qa-dashboard.desktop'//; s/'qa-dashboard.desktop'//")"
        gsettings set org.gnome.shell favorite-apps "$UPDATED_FAVORITES" 2>/dev/null || true
    fi
fi

rm -f "$BIN"
rm -rf "$LIB" "$DOC"
rm -f "$PREFIX/bin/qa-desktop" "$PREFIX/bin/qa-desktop-tray"
rm -rf "$PREFIX/lib/qa-desktop" "$PREFIX/share/doc/qa-desktop"
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/qa-desktop.svg" \
      "$PREFIX/share/icons/hicolor/scalable/apps/qa-malware-scan.svg" \
      "$ICONS/scalable/apps/qa-dashboard.svg" \
      "$ICONS/256x256/apps/qa-dashboard.png" \
      "$ICONS/512x512/apps/qa-dashboard.png" \
      "$ICONS/256x256/apps/qa-dashboard-light.png" \
      "$ICONS/512x512/apps/qa-dashboard-light.png" \
      "$ICONS/256x256/apps/qa-dashboard-dark.png" \
      "$ICONS/512x512/apps/qa-dashboard-dark.png"
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICONS" >/dev/null 2>&1 || true
fi
rm -f "$AUTOSTART/qa-dashboard-tray.desktop" \
      "$AUTOSTART/qa-desktop-tray.desktop"
for file in qa-desktop qa-dashboard qa-sentinels qa-malware-scan qa-siem; do
    rm -f "$APPS/$file.desktop"
done
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "--purge-config" ]; then
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/qa-desktop/config.json"
fi
echo "QA Dashboard removed. Configuration is kept unless --purge-config was used."
