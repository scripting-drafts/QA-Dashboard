#!/usr/bin/env python3
"""Export platform finding and capability contracts from the Python source."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENTINELS = ROOT / "sentinels"
CONTRACTS = ROOT / "contracts"
sys.path.insert(0, str(SENTINELS))

from sentinels.platform import coverage, matrix  # noqa: E402
from sentinels.platform.linux import LinuxBackend  # noqa: E402
from sentinels.platform.macos import MacOSBackend  # noqa: E402
from sentinels.platform.windows import WindowsBackend  # noqa: E402


def capabilities() -> dict:
    data = {}
    for backend in (LinuxBackend(), WindowsBackend(), MacOSBackend()):
        data[backend.name] = {
            "display": backend.display,
            "family": backend.family,
            "minimum_release": list(backend.minimum_release),
            "permissions": list(backend.permissions),
            "capabilities": {
                area: value.as_dict()
                for area, value in backend.capabilities().items()
            },
        }
    return data


def payloads() -> dict[str, str]:
    return {
        "findings.json": json.dumps({
            "families": matrix(),
            "coverage": coverage(),
        }, indent=2, sort_keys=True) + "\n",
        "capabilities.json": json.dumps(
            capabilities(), indent=2, sort_keys=True) + "\n",
    }


def main() -> int:
    check = "--check" in sys.argv
    failed = False
    for name, text in payloads().items():
        target = CONTRACTS / name
        if check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != text:
                print(f"out of date: contracts/{name}", file=sys.stderr)
                failed = True
        else:
            target.write_text(text, encoding="utf-8")
            print(f"wrote contracts/{name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
