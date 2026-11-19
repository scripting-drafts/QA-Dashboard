#!/usr/bin/env python3
"""Check that the vendored QA Sentinels tree matches its source revision."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "sentinels"
MARKER = ROOT / "sentinels-vendor.json"


def version() -> str:
    text = (VENDOR / "sentinels" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else ""


def source_checkout() -> Path | None:
    configured = os.environ.get("QA_SENTINELS_SOURCE")
    candidates = [Path(configured)] if configured else []
    candidates.append(ROOT.parent / "QA-Sentinels")
    for candidate in candidates:
        if (candidate / ".git").is_dir() and (candidate / "sentinels").is_dir():
            return candidate
    return None


def git(source: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *args],
        check=True, capture_output=True, text=True,
    )
    return result.stdout


def main() -> int:
    marker = json.loads(MARKER.read_text(encoding="utf-8"))
    errors: list[str] = []
    actual_version = version()
    if actual_version != marker["version"]:
        errors.append(
            f"vendored version {actual_version or 'unknown'} "
            f"!= marker {marker['version']}")

    source = source_checkout()
    if source is None:
        print("vendor-check: source checkout not found; checked version marker only")
    else:
        head = git(source, "rev-parse", "HEAD").strip()
        if head != marker["commit"]:
            errors.append(f"source HEAD {head} != marker {marker['commit']}")
        tracked = git(source, "ls-files", "-z").split("\0")
        for relative in tracked:
            if not relative:
                continue
            src = source / relative
            dst = VENDOR / relative
            if not dst.is_file():
                errors.append(f"missing vendored file: {relative}")
            elif src.read_bytes() != dst.read_bytes():
                errors.append(f"content differs: {relative}")

    if errors:
        for error in errors:
            print(f"vendor-check: {error}", file=sys.stderr)
        return 1
    print(f"vendor-check: QA Sentinels {marker['version']} at {marker['commit']} is aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
