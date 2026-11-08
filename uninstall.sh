#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-desktop"
BIN="$PREFIX/bin/qa-desktop"
APPS="$PREFIX/share/applications"
DOC="$PREFIX/share/doc/qa-desktop"

rm -f "$BIN"
rm -rf "$LIB" "$DOC"
rm -f "$PREFIX/share/icons/hicolor/scalable/apps/qa-desktop.svg" \
      "$PREFIX/share/icons/hicolor/scalable/apps/qa-malware-scan.svg"
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
fi
for file in qa-desktop qa-sentinels qa-malware-scan qa-siem; do
    rm -f "$APPS/$file.desktop"
done
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi
if [ "${1:-}" = "--purge-config" ]; then
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/qa-desktop/config.json"
fi
echo "QA Desktop removed. Configuration is kept unless --purge-config was used."
