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
EXT_UUID="qa-dashboard@local"
EXT_DIR="$DATA/gnome-shell/extensions/$EXT_UUID"

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

write_desktop qa-sentinels "QA Sentinels" \
    "Evidence collection and failure correlation" "sentinels" "qa-dashboard"
write_desktop qa-malware-scan "Malware Scan" \
    "Scan files and folders for malware indicators" "malware" "qa-dashboard"
write_desktop qa-siem "QA SIEM" \
    "Local QA SIEM dashboard and alerts" "siem" "qa-dashboard"

# Install the GNOME Shell top-bar icon. It launches the Overview on click and
# replaces the Electron tray, which opened an empty AppIndicator menu.
SHELL_MAJOR=""
if command -v gnome-shell >/dev/null 2>&1; then
    SHELL_MAJOR="$(gnome-shell --version 2>/dev/null | awk '{print $3}' | cut -d. -f1)"
fi
if [ -n "$SHELL_MAJOR" ] && [ "$SHELL_MAJOR" -ge 45 ] 2>/dev/null; then
    EXT_SRC="$ROOT/gnome-extension/modern"
else
    EXT_SRC="$ROOT/gnome-extension/legacy"
fi
EXT_WAS_PRESENT=0
[ -d "$EXT_DIR" ] && EXT_WAS_PRESENT=1
rm -rf "$EXT_DIR"
install -d -m 0755 "$EXT_DIR"
cp -a "$EXT_SRC/." "$EXT_DIR/"
install -m 0644 "$ROOT/assets/qa-dashboard.svg" "$EXT_DIR/qa-dashboard.svg"

rm -f "$AUTOSTART/qa-desktop-tray.desktop" \
      "$AUTOSTART/qa-dashboard-tray.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi

EXT_NEEDS_RELOGIN=0
if command -v gnome-extensions >/dev/null 2>&1; then
    gnome-extensions disable "$EXT_UUID" >/dev/null 2>&1 || true
    if ! gnome-extensions enable "$EXT_UUID" >/dev/null 2>&1; then
        EXT_NEEDS_RELOGIN=1
        # A newly copied extension is unknown until the shell rescans its
        # extension directory. Add it to the login list so the next session
        # starts with the top-bar icon enabled.
        ENABLED="$(gsettings get org.gnome.shell enabled-extensions 2>/dev/null || true)"
        case "$ENABLED" in
            *"$EXT_UUID"*) ;;
            "@as []"|"[]") ENABLED="['$EXT_UUID']" ;;
            *) ENABLED="$(printf '%s' "$ENABLED" | sed "s/]$/, '$EXT_UUID']/")" ;;
        esac
        if [ -n "$ENABLED" ] && gsettings set org.gnome.shell enabled-extensions "$ENABLED" 2>/dev/null; then
            echo "Top-bar icon enabled for the next GNOME Shell login." >&2
        else
            echo "Top-bar icon installed but not enabled yet." >&2
            echo "Sign out and back in, then run: gnome-extensions enable $EXT_UUID" >&2
        fi
    fi
else
    EXT_NEEDS_RELOGIN=1
    echo "Install gnome-extensions, then enable $EXT_UUID." >&2
fi
if [ "$EXT_WAS_PRESENT" -eq 1 ] && [ "$EXT_NEEDS_RELOGIN" -eq 0 ]; then
    echo "Top-bar icon updated; sign out and back in if it does not refresh." >&2
fi

cat <<EOF
Installed QA Dashboard to $PREFIX
  launcher   : $BIN
  top bar    : $EXT_DIR (GNOME extension $EXT_UUID)
  modules    : QA Sentinels, Malware Scan, QA SIEM launchers
EOF
