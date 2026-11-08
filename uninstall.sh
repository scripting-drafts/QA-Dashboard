#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-dashboard"
BIN="$PREFIX/bin/qa-dashboard"
APPS="$PREFIX/share/applications"
DOC="$PREFIX/share/doc/qa-dashboard"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"

# Stop Electron and any legacy Python tray/app.
ps -eo pid=,args= | awk -v app="$LIB" 'index($0, app) && $0 ~ /electron/ && $0 !~ /awk/ {print $1}' \
    | xargs -r kill 2>/dev/null || true
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk.tray" {print $1}' \
    | xargs -r kill 2>/dev/null || true
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk" {print $1}' \
    | xargs -r kill 2>/dev/null || true
sleep 1

rm -f "$BIN"
rm -rf "$LIB" "$DOC"
rm -f "$PREFIX/bin/qa-desktop" "$PREFIX/bin/qa-desktop-tray"
rm -rf "$PREFIX/lib/qa-desktop" "$PREFIX/share/doc/qa-desktop"
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/qa-desktop.svg" \
      "$PREFIX/share/icons/hicolor/scalable/apps/qa-malware-scan.svg"
rm -f "$AUTOSTART/qa-dashboard-tray.desktop" \
      "$AUTOSTART/qa-desktop-tray.desktop"
for file in qa-desktop qa-sentinels qa-malware-scan qa-siem; do
    rm -f "$APPS/$file.desktop"
done
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "--purge-config" ]; then
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/qa-desktop/config.json"
fi
echo "QA Dashboard removed. Configuration is kept unless --purge-config was used."
