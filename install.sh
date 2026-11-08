#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-desktop"
BIN="$PREFIX/bin/qa-desktop"
BIN_TRAY="$PREFIX/bin/qa-desktop-tray"
APPS="$PREFIX/share/applications"
DOC="$PREFIX/share/doc/qa-desktop"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"

if ! python3 - <<'PY' >/dev/null 2>&1
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: F401
PY
then
    echo "QA Desktop requires Python 3 and PyGObject with GTK 4." >&2
    exit 1
fi

install -d -m 0755 "$LIB" "$PREFIX/bin" "$APPS" "$DOC" "$AUTOSTART"
# Remove icons from the previous custom-branding build.
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/qa-desktop.svg" \
      "$PREFIX/share/icons/hicolor/scalable/apps/qa-malware-scan.svg"
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
fi
rm -rf "$LIB/qadesk"
cp -a "$ROOT/qadesk" "$LIB/"
find "$LIB" -type d -name __pycache__ -prune -exec rm -rf {} +
python3 -m compileall -q "$LIB/qadesk"
install -m 0755 "$ROOT/bin/qa-desktop" "$BIN"
install -m 0755 "$ROOT/bin/qa-desktop-tray" "$BIN_TRAY"
install -m 0644 "$ROOT/README.md" "$ROOT/docs/ARCHITECTURE.md" "$DOC/"

# Per-app standalone launchers; no suite entry.
rm -f "$APPS/qa-desktop.desktop" "$APPS/qa-sentinels.desktop" \
      "$APPS/qa-malware-scan.desktop" "$APPS/qa-siem.desktop"

write_desktop() {
    local file=$1 title=$2 comment=$3 module=$4 icon=$5
    cat > "$APPS/$file.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$title
Comment=$comment
Exec="$BIN" --module $module
Icon=$icon
Terminal=false
Categories=System;Security;Monitor;
StartupNotify=true
StartupWMClass=org.scriptingdrafts.QADesktop
EOF
    chmod 0644 "$APPS/$file.desktop"
}

write_desktop qa-sentinels "QA Sentinels" \
    "Evidence collection and failure correlation" "sentinels" \
    "utilities-system-monitor"
write_desktop qa-malware-scan "Malware Scan" \
    "Scan files and folders for malware indicators" "malware" \
    "security-high"
write_desktop qa-siem "QA SIEM" \
    "Local QA SIEM dashboard and alerts" "siem" "network-server"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi

cat > "$AUTOSTART/qa-desktop-tray.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=QA Desktop tray
Comment=Top-bar access to QA Desktop modules
Exec="$BIN_TRAY"
Icon=security-high
Terminal=false
NoDisplay=true
Hidden=false
X-GNOME-Autostart-enabled=true
OnlyShowIn=GNOME;
EOF
chmod 0644 "$AUTOSTART/qa-desktop-tray.desktop"

if command -v gnome-extensions >/dev/null 2>&1; then
    gnome-extensions enable ubuntu-appindicators@ubuntu.com >/dev/null 2>&1 || true
fi

# Restart any running tray so the new icon and menu are loaded.
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk.tray" {print $1}' \
    | xargs -r kill 2>/dev/null || true
sleep 1
if command -v setsid >/dev/null 2>&1; then
    setsid "$BIN_TRAY" >/dev/null 2>&1 &
else
    nohup "$BIN_TRAY" >/dev/null 2>&1 &
fi

cat <<EOF
Installed QA Desktop tray access to $PREFIX
  app launcher : $BIN
  tray launcher: $BIN_TRAY
  autostart    : $AUTOSTART/qa-desktop-tray.desktop
  access       : top-bar tray icon (menu opens the three apps)
EOF
