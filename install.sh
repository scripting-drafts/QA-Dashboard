#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-dashboard"
BIN="$PREFIX/bin/qa-dashboard"
APPS="$PREFIX/share/applications"
ICONS="$PREFIX/share/icons/hicolor/scalable/apps"
DOC="$PREFIX/share/doc/qa-dashboard"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
LEGACY_EXT_UUID="qa-dashboard@local"
LEGACY_EXT_DIR="$DATA/gnome-shell/extensions/$LEGACY_EXT_UUID"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "QA Dashboard requires Node.js and npm." >&2
    exit 1
fi

# Stop the previous Python tray/app and the previous Electron instance.
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk.tray" {print $1}' \
    | xargs -r kill 2>/dev/null || true
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk" {print $1}' \
    | xargs -r kill 2>/dev/null || true
ps -eo pid=,args= | awk -v app="$LIB" 'index($0, app) && $0 ~ /electron/ && $0 !~ /awk/ {print $1}' \
    | xargs -r kill 2>/dev/null || true
sleep 1

install -d -m 0755 "$LIB" "$PREFIX/bin" "$APPS" "$ICONS" "$DOC" "$AUTOSTART"
rm -rf "$LIB/electron" "$LIB/renderer" "$LIB/assets" "$LIB/node_modules"
cp -a "$ROOT/electron" "$ROOT/renderer" "$ROOT/assets" "$LIB/"
install -m 0644 "$ROOT/package.json" "$ROOT/package-lock.json" "$LIB/"
if [ -d "$ROOT/node_modules/electron" ]; then
    cp -a "$ROOT/node_modules" "$LIB/"
else
    (cd "$LIB" && npm ci --no-audit --no-fund >/dev/null)
fi
install -m 0755 "$ROOT/bin/qa-dashboard" "$BIN"
install -m 0644 "$ROOT/assets/qa-dashboard-icon.svg" "$ICONS/qa-dashboard.svg"
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
fi
install -m 0644 "$ROOT/README.md" "$ROOT/docs/ARCHITECTURE.md" \
    "$ROOT/docs/PORTING.md" "$DOC/"

# Remove the old GTK/Python launchers and menu entries.
rm -f "$PREFIX/bin/qa-desktop" "$PREFIX/bin/qa-desktop-tray"
rm -rf "$PREFIX/lib/qa-desktop" "$PREFIX/share/doc/qa-desktop"
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/qa-desktop.svg" \
      "$PREFIX/share/icons/hicolor/scalable/apps/qa-malware-scan.svg"
rm -f "$APPS/qa-desktop.desktop" "$APPS/qa-sentinels.desktop" \
      "$APPS/qa-malware-scan.desktop" "$APPS/qa-siem.desktop"

write_desktop() {
    local file=$1 title=$2 comment=$3 module=$4 icon=$5
    cat > "$APPS/$file.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$title
Comment=$comment
Exec="$BIN" --module=$module
Icon=$icon
Terminal=false
Categories=System;Security;Monitor;
StartupNotify=true
StartupWMClass=qa-dashboard
EOF
    chmod 0644 "$APPS/$file.desktop"
}

write_desktop qa-dashboard "QA Dashboard" \
    "Local QA operations dashboard" "overview" "qa-dashboard"
write_desktop qa-sentinels "QA Sentinels" \
    "Evidence collection and failure correlation" "sentinels" "qa-dashboard"
write_desktop qa-malware-scan "Malware Scan" \
    "Scan files and folders for malware indicators" "malware" "qa-dashboard"
write_desktop qa-siem "QA SIEM" \
    "Local QA SIEM dashboard and alerts" "siem" "qa-dashboard"

# Remove the former GNOME top-bar icon and tray autostart.
if command -v gnome-extensions >/dev/null 2>&1; then
    gnome-extensions disable "$LEGACY_EXT_UUID" >/dev/null 2>&1 || true
fi
rm -rf "$LEGACY_EXT_DIR"
if command -v gsettings >/dev/null 2>&1; then
    ENABLED="$(gsettings get org.gnome.shell enabled-extensions 2>/dev/null || true)"
    if printf '%s' "$ENABLED" | grep -q "$LEGACY_EXT_UUID"; then
        UPDATED="$(printf '%s' "$ENABLED" | sed "s/'$LEGACY_EXT_UUID', //; s/, '$LEGACY_EXT_UUID'//; s/'$LEGACY_EXT_UUID'//")"
        gsettings set org.gnome.shell enabled-extensions "$UPDATED" 2>/dev/null || true
    fi
    DISABLED="$(gsettings get org.gnome.shell disabled-extensions 2>/dev/null || true)"
    if printf '%s' "$DISABLED" | grep -q "$LEGACY_EXT_UUID"; then
        UPDATED_DISABLED="$(printf '%s' "$DISABLED" | sed "s/'$LEGACY_EXT_UUID', //; s/, '$LEGACY_EXT_UUID'//; s/'$LEGACY_EXT_UUID'//")"
        gsettings set org.gnome.shell disabled-extensions "$UPDATED_DISABLED" 2>/dev/null || true
    fi
fi
rm -f "$AUTOSTART/qa-desktop-tray.desktop" \
      "$AUTOSTART/qa-dashboard-tray.desktop"

# Point the existing QA Sentinels favourite at the Dashboard launcher.
if command -v gsettings >/dev/null 2>&1; then
    FAVORITES="$(gsettings get org.gnome.shell favorite-apps 2>/dev/null || true)"
    if printf '%s' "$FAVORITES" | grep -q "'qa-dashboard.desktop'"; then
        UPDATED_FAVORITES="$(printf '%s' "$FAVORITES" | sed "s/'qa-sentinels.desktop', //; s/, 'qa-sentinels.desktop'//; s/'qa-sentinels.desktop'//")"
    else
        UPDATED_FAVORITES="$(printf '%s' "$FAVORITES" | sed "s/'qa-sentinels.desktop'/'qa-dashboard.desktop'/")"
    fi
    if [ "$UPDATED_FAVORITES" != "$FAVORITES" ]; then
        gsettings set org.gnome.shell favorite-apps "$UPDATED_FAVORITES" 2>/dev/null || true
    fi
fi

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi

cat <<EOF
Installed QA Dashboard to $PREFIX
  dashboard : $APPS/qa-dashboard.desktop
  modules   : QA Sentinels, Malware Scan, QA SIEM launchers
  no tray   : use the favourite or standalone launchers
EOF
