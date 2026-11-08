#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/qa-desktop"
BIN="$PREFIX/bin/qa-desktop"
APPS="$PREFIX/share/applications"
DOC="$PREFIX/share/doc/qa-desktop"

if ! python3 - <<'PY' >/dev/null 2>&1
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: F401
PY
then
    echo "QA Desktop requires Python 3 and PyGObject with GTK 4." >&2
    exit 1
fi

install -d -m 0755 "$LIB" "$PREFIX/bin" "$APPS" "$DOC"
rm -rf "$LIB/qadesk"
cp -a "$ROOT/qadesk" "$LIB/"
find "$LIB" -type d -name __pycache__ -prune -exec rm -rf {} +
python3 -m compileall -q "$LIB/qadesk"
install -m 0755 "$ROOT/bin/qa-desktop" "$BIN"
install -m 0644 "$ROOT/README.md" "$ROOT/docs/ARCHITECTURE.md" "$DOC/"

write_desktop() {
    local file=$1 title=$2 comment=$3 module=$4 icon=$5
    local exec_line
    if [ -n "$module" ]; then
        exec_line="Exec=\"$BIN\" --module $module"
    else
        exec_line="Exec=\"$BIN\""
    fi
    cat > "$APPS/$file.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$title
Comment=$comment
$exec_line
Icon=$icon
Terminal=false
Categories=System;Security;Monitor;
StartupNotify=true
StartupWMClass=org.scriptingdrafts.QADesktop
EOF
    chmod 0644 "$APPS/$file.desktop"
}

write_desktop qa-desktop "QA Desktop" \
    "Modular QA suite" "" "applications-system"
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

cat <<EOF
Installed QA Desktop to $PREFIX
  launcher: $BIN
  modules : Sentinels, Malware Scan, SIEM
  menu    : $APPS
EOF
