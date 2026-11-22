#!/usr/bin/env bash
# Install the tracked release-tag guard for this clone.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chmod +x "$root/.githooks/pre-push" "$root/tools/check_release_tag.py"
git -C "$root" config --local core.hooksPath .githooks
printf 'installed Git hooks from .githooks\n'
