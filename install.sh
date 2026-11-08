#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-dashboard"
BIN="$PREFIX/bin/qa-dashboard"
APPS="$PREFIX/share/applications"
DOC="$PREFIX/share/doc/qa-dashboard"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"

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

install -d -m 0755 "$LIB" "$PREFIX/bin" "$APPS" "$DOC" "$AUTOSTART"
rm -rf "$LIB/electron" "$LIB/renderer" "$LIB/assets" "$LIB/node_modules"
cp -a "$ROOT/electron" "$ROOT/renderer" "$ROOT/assets" "$LIB/"
install -m 0644 "$ROOT/package.json" "$ROOT/package-lock.json" "$LIB/"
if [ -d "$ROOT/node_modules/electron" ]; then
    cp -a "$ROOT/node_modules" "$LIB/"
else
    (cd "$LIB" && npm ci --no-audit --no-fund >/dev/null)
fi
install -m 0755 "$ROOT/bin/qa-dashboard" "$BIN"
install -m 0644 "$ROOT/README.md" "$ROOT/docs/ARCHITECTURE.md" "$DOC/"

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
    "Evidence collection and failure correlation" "sentinels" \
    "utilities-system-monitor"
write_desktop qa-malware-scan "Malware Scan" \
    "Scan files and folders for malware indicators" "malware" \
    "security-high"
write_desktop qa-siem "QA SIEM" \
    "Local QA SIEM dashboard and alerts" "siem" "network-server"

rm -f "$AUTOSTART/qa-desktop-tray.desktop"
cat > "$AUTOSTART/qa-dashboard-tray.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=QA Dashboard tray
Comment=Monochrome QA Dashboard access
Exec="$BIN" --tray
Icon=utilities-system-monitor
Terminal=false
NoDisplay=true
Hidden=false
X-GNOME-Autostart-enabled=true
OnlyShowIn=GNOME;
EOF
chmod 0644 "$AUTOSTART/qa-dashboard-tray.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi

if command -v setsid >/dev/null 2>&1; then
    setsid "$BIN" --tray >/dev/null 2>&1 &
else
    nohup "$BIN" --tray >/dev/null 2>&1 &
fi

cat <<EOF
Installed QA Dashboard to $PREFIX
  launcher : $BIN
  autostart: $AUTOSTART/qa-dashboard-tray.desktop
  access   : monochrome top-bar tray icon (dashboard and three apps)
EOF
