#!/usr/bin/env bash
# Build an unsigned pre-release for the current OS.
# Usage: ./scripts/build-prerelease.sh [linux|win|mac]
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

npm test
npx electron-builder "--$TARGET" --publish never

node scripts/checksums.js dist

echo
echo "Pre-release artifacts in $ROOT/dist"
