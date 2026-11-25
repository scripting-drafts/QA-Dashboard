#!/usr/bin/env python3
"""Compatibility wrapper for the vendor synchronization tool."""
from __future__ import annotations

import sys

from sync_vendor import main


if __name__ == "__main__":
    raise SystemExit(main(["--check", *sys.argv[1:]]))
