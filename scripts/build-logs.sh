#!/usr/bin/env bash
# Build a verbose diagnostics package for the current OS.
# Usage: ./scripts/build-logs.sh [linux|win|mac]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export CSC_IDENTITY_AUTO_DISCOVERY=false

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    case "$(uname -s)" in
        Linux*) TARGET=linux ;;
        Darwin*) TARGET=mac ;;
        MINGW*|MSYS*|CYGWIN*) TARGET=win ;;
        *) echo "Unsupported host: $(uname -s)" >&2; exit 1 ;;
    esac
fi

if [ ! -d node_modules ]; then
    npm ci --no-audit --no-fund
fi

OUT=dist-logs
npm test
npx electron-builder --config electron-builder-logs.yml \
    "--$TARGET" --publish never -c.directories.output="$OUT"

node scripts/checksums.js "$OUT"

echo
echo "Diagnostics artifacts in $ROOT/$OUT"
