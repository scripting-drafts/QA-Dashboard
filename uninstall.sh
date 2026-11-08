#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-desktop"
BIN="$PREFIX/bin/qa-desktop"
BIN_TRAY="$PREFIX/bin/qa-desktop-tray"
APPS="$PREFIX/share/applications"
DOC="$PREFIX/share/doc/qa-desktop"
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"

# Stop the tray process. The tray intentionally exposes no Quit menu item.
ps -eo pid=,args= | awk '$2=="python3" && $3=="-m" && $4=="qadesk.tray" {print $1}' \
    | xargs -r kill 2>/dev/null || true

rm -f "$BIN" "$BIN_TRAY"
rm -rf "$LIB" "$DOC"
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/qa-desktop.svg" \
      "$PREFIX/share/icons/hicolor/scalable/apps/qa-malware-scan.svg"
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
fi
rm -f "$AUTOSTART/qa-desktop-tray.desktop"
for file in qa-desktop qa-sentinels qa-malware-scan qa-siem; do
    rm -f "$APPS/$file.desktop"
done
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "--purge-config" ]; then
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/qa-desktop/config.json"
fi
echo "QA Desktop tray and launchers removed. Configuration is kept unless --purge-config was used."
