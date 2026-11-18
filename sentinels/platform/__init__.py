"""Platform selection and shared contract."""
from __future__ import annotations

import sys

from .base import Backend, Capability, Snapshot
from .findings import equivalent, family_for, matrix, coverage


def detect() -> Backend:
    if sys.platform.startswith("win"):
        from .windows import WindowsBackend
        return WindowsBackend()
    if sys.platform == "darwin":
        from .macos import MacOSBackend
        return MacOSBackend()
    from .linux import LinuxBackend
    return LinuxBackend()


__all__ = [
    "Backend", "Capability", "Snapshot", "detect",
    "equivalent", "family_for", "matrix", "coverage",
]
