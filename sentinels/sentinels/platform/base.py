"""Shared platform contract for QA Sentinels.

Every backend answers the same questions: what host is this, which areas are
available, and what read-only snapshot can be collected. Linux keeps its
existing collectors; Windows and macOS provide native equivalents.
"""
from __future__ import annotations

import json
import platform as _platform
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Capability:
    area: str
    status: str  # supported, degraded, needs_permission, planned
    source: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "area": self.area,
            "status": self.status,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass
class Snapshot:
    platform: str
    host: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Capability] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "host": self.host,
            "capabilities": {
                key: value.as_dict() for key, value in self.capabilities.items()
            },
            "data": self.data,
            "errors": self.errors,
        }


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"
    except OSError as exc:
        return 126, "", str(exc)


def run_json(cmd: list[str], timeout: int = 20) -> tuple[Any | None, str]:
    rc, out, err = run(cmd, timeout=timeout)
    if rc != 0:
        return None, (err or out or f"rc={rc}").strip()[:500]
    text = out.strip()
    if not text:
        return None, "empty output"
    try:
        return json.loads(text), ""
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"


def python_version() -> str:
    return _platform.python_version()


def sqlite_version() -> str:
    return sqlite3.sqlite_version


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


class Backend:
    name = "base"
    family = "base"
    display = "Unknown"
    minimum_release = (0, 0)
    permissions: tuple[str, ...] = ()

    def host_info(self) -> dict[str, Any]:
        return {
            "system": _platform.system(),
            "release": _platform.release(),
            "version": _platform.version(),
            "machine": _platform.machine(),
            "python": python_version(),
            "sqlite": sqlite_version(),
        }

    def capabilities(self) -> dict[str, Capability]:
        return {
            "host": Capability("host", "supported", "python"),
            "python": Capability("python", "supported", "runtime"),
            "sqlite": Capability("sqlite", "supported", "runtime"),
        }

    def collect(self) -> Snapshot:
        return Snapshot(self.name, host=self.host_info(),
                        capabilities=self.capabilities())

    def compat_report(self) -> dict[str, Any]:
        host = self.host_info()
        checks = [
            {
                "name": f"{self.display} release",
                "ok": _release_at_least(host.get("release", ""),
                                        self.minimum_release),
                "detail": f"{host.get('release') or 'unknown'}",
            },
            {
                "name": "Python >= 3.10",
                "ok": _version_at_least(host.get("python", ""), (3, 10)),
                "detail": host.get("python", "unknown"),
            },
            {
                "name": "SQLite >= 3.37",
                "ok": _version_at_least(host.get("sqlite", ""), (3, 37)),
                "detail": host.get("sqlite", "unknown"),
            },
        ]
        supported = all(item["ok"] for item in checks)
        return {
            "supported": supported,
            "checks": checks,
            "summary": (
                f"supported {self.display} baseline"
                if supported else
                f"outside the documented {self.display} baseline"
            ),
            "os": host,
            "versions": {
                "python": host.get("python", ""),
                "sqlite": host.get("sqlite", ""),
            },
            "documentation": "docs/CROSS-PLATFORM.md",
        }


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for part in str(value or "").replace("-", ".").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts)


def _version_at_least(value: str, minimum: tuple[int, int]) -> bool:
    current = _version_tuple(value)
    return bool(current) and current[:len(minimum)] >= minimum


def _release_at_least(value: str, minimum: tuple[int, int]) -> bool:
    current = _version_tuple(value)
    return bool(current) and current[:len(minimum)] >= minimum
