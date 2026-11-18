"""Linux backend.

Linux already has the full collector set in the existing modules. This
backend only exposes the shared host/capability contract and delegates
collection to the established modules when requested.
"""
from __future__ import annotations

import os
import platform as _platform
import socket
from pathlib import Path

from .base import Backend, Capability, Snapshot, python_version, sqlite_version


class LinuxBackend(Backend):
    name = "linux"
    family = "linux"
    display = "Linux"
    minimum_release = (5, 15)
    permissions = ("root for deep tracing", "journal access")

    def host_info(self) -> dict:
        release = {}
        for line in _read("/etc/os-release").splitlines():
            key, _, value = line.partition("=")
            if key and value:
                release[key.strip()] = value.strip().strip('"')
        uname = os.uname()
        return {
            "system": "Linux",
            "distribution": release.get("ID", ""),
            "version": release.get("VERSION_ID", ""),
            "pretty": release.get("PRETTY_NAME", ""),
            "release": uname.release,
            "version_id": uname.version,
            "machine": uname.machine,
            "hostname": socket.gethostname(),
            "python": python_version(),
            "sqlite": sqlite_version(),
        }

    def capabilities(self) -> dict[str, Capability]:
        caps = super().capabilities()
        for area in (
            "processes", "services", "network", "security", "crashes",
            "updates", "hardware", "boot", "kernel", "lsm", "storage",
            "faultcore", "deep", "trace", "scheduler", "logs",
        ):
            caps[area] = Capability(area, "supported", "linux")
        caps["deep"] = Capability("deep", "supported", "tracefs/perf", "requires root")
        caps["trace"] = Capability("trace", "supported", "ebpf/tracefs", "requires root")
        caps["faultcore"] = Capability(
            "faultcore", "supported", "procfs/cgroup", "requires faultlab topology",
        )
        return caps

    def collect(self) -> Snapshot:
        snapshot = Snapshot(self.name, host=self.host_info(),
                            capabilities=self.capabilities())
        snapshot.data["note"] = (
            "Linux collectors remain in their existing modules; "
            "use qa cycle, qa inventory, qa network, qa hardware and qa logs."
        )
        return snapshot


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
