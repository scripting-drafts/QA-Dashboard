"""macOS backend.

Read-only collectors use the stable command-line interfaces shipped with
macOS. Security-sensitive areas that require Endpoint Security or Full Disk
Access report `needs_permission` rather than pretending to be complete.
"""
from __future__ import annotations

import os
import platform as _platform
import socket
from pathlib import Path
from typing import Any

from .base import (
    Backend, Capability, Snapshot, python_version, run, run_json, sqlite_version,
)


def _text(cmd: list[str], timeout: int = 20) -> tuple[str, str]:
    rc, out, err = run(cmd, timeout=timeout)
    if rc != 0:
        return "", (err or out or f"rc={rc}").strip()[:500]
    return out.strip(), ""


class MacOSBackend(Backend):
    name = "macos"
    family = "darwin"
    display = "macOS"
    minimum_release = (13, 0)
    permissions = ("Full Disk Access for protected logs", "root for PF/firewall detail")

    def host_info(self) -> dict:
        product, _ = _text(["sw_vers", "-productVersion"])
        build, _ = _text(["sw_vers", "-buildVersion"])
        machine, _ = _text(["uname", "-m"])
        ncpu, _ = _text(["sysctl", "-n", "hw.ncpu"])
        memsize, _ = _text(["sysctl", "-n", "hw.memsize"])
        kernel, _ = _text(["uname", "-r"])
        return {
            "system": "macOS",
            "release": product or _platform.mac_ver()[0],
            "build": build,
            "version": kernel,
            "machine": machine or _platform.machine(),
            "hostname": socket.gethostname(),
            "cpus": int(ncpu) if ncpu.isdigit() else os.cpu_count(),
            "memory_bytes": int(memsize) if memsize.isdigit() else 0,
            "python": python_version(),
            "sqlite": sqlite_version(),
        }

    def capabilities(self) -> dict[str, Capability]:
        caps = super().capabilities()
        caps.update({
            "processes": Capability("processes", "supported", "ps/libproc"),
            "services": Capability("services", "supported", "launchctl"),
            "network": Capability("network", "supported", "ifconfig/netstat/scutil"),
            "security": Capability("security", "supported", "spctl/csrutil/fdesetup"),
            "crashes": Capability("crashes", "supported", "DiagnosticReports"),
            "updates": Capability("updates", "supported", "softwareupdate"),
            "startup": Capability("startup", "supported", "launchctl"),
            "hardware": Capability("hardware", "supported", "system_profiler"),
            "boot": Capability("boot", "degraded", "log show"),
            "kernel": Capability("kernel", "degraded", "panic reports"),
            "lsm": Capability("lsm", "degraded", "SIP/TCC/Gatekeeper"),
            "storage": Capability("storage", "supported", "system_profiler"),
            "scheduler": Capability("scheduler", "supported", "launchd"),
            "logs": Capability("logs", "supported", "Unified Logging"),
            "faultcore": Capability("faultcore", "planned", "CPU topology/affinity"),
            "deep": Capability("deep", "planned", "DTrace", "restricted by SIP"),
            "trace": Capability("trace", "planned", "DTrace", "restricted by SIP"),
        })
        return caps

    def collect(self) -> Snapshot:
        snapshot = Snapshot(self.name, host=self.host_info(),
                            capabilities=self.capabilities())
        collectors = {
            "processes": self.processes,
            "services": self.services,
            "network": self.network,
            "security": self.security,
            "crashes": self.crashes,
            "updates": self.updates,
            "startup": self.startup,
            "hardware": self.hardware,
        }
        for name, collector in collectors.items():
            try:
                value, error = collector()
                snapshot.data[name] = value
                if error:
                    snapshot.errors.append(f"{name}: {error}")
            except Exception as exc:  # noqa: BLE001 - collector isolation
                snapshot.data[name] = None
                snapshot.errors.append(f"{name}: {exc}")
        return snapshot

    def processes(self) -> tuple[Any, str]:
        out, error = _text([
            "ps", "-axo", "pid=,ppid=,comm=,%cpu=,rss=,state=",
        ], timeout=30)
        rows = []
        for line in out.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            pid, ppid, comm, cpu, rss, state = parts
            rows.append({
                "pid": int(pid) if pid.isdigit() else pid,
                "ppid": int(ppid) if ppid.isdigit() else ppid,
                "comm": comm,
                "cpu_pct": float(cpu) if _is_float(cpu) else cpu,
                "rss_kb": int(rss) if rss.isdigit() else rss,
                "state": state,
                "source": "ps",
            })
        return rows, error

    def services(self) -> tuple[Any, str]:
        out, error = _text(["launchctl", "list"], timeout=20)
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pid, status, label = parts[0], parts[1], parts[2]
            rows.append({
                "pid": pid,
                "status": status,
                "label": label,
                "source": "launchctl",
            })
        return rows, error

    def network(self) -> tuple[Any, str]:
        ifconfig, error = _text(["ifconfig", "-a"], timeout=20)
        routes, route_error = _text(["netstat", "-rn"], timeout=20)
        dns, dns_error = _text(["scutil", "--dns"], timeout=20)
        return {
            "interfaces": _parse_ifconfig(ifconfig),
            "routes": routes[:20000],
            "dns": dns[:20000],
            "source": "ifconfig/netstat/scutil",
        }, error or route_error or dns_error

    def security(self) -> tuple[Any, str]:
        checks = {
            "gatekeeper": ["spctl", "--status"],
            "sip": ["csrutil", "status"],
            "filevault": ["fdesetup", "status"],
            "firewall": [
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--getglobalstate",
            ],
        }
        result = {}
        errors = []
        for name, cmd in checks.items():
            out, error = _text(cmd, timeout=20)
            result[name] = out
            if error:
                errors.append(f"{name}: {error}")
        result["source"] = "spctl/csrutil/fdesetup/socketfilterfw"
        return result, "; ".join(errors)

    def crashes(self) -> tuple[Any, str]:
        directories = [
            Path.home() / "Library" / "Logs" / "DiagnosticReports",
            Path("/Library/Logs/DiagnosticReports"),
        ]
        rows = []
        for directory in directories:
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*"), key=lambda p: p.stat().st_mtime,
                               reverse=True)[:50]:
                if not path.is_file():
                    continue
                rows.append({
                    "path": str(path),
                    "name": path.name,
                    "mtime": int(path.stat().st_mtime),
                    "size": path.stat().st_size,
                    "source": "DiagnosticReports",
                })
        return rows, ""

    def updates(self) -> tuple[Any, str]:
        out, error = _text(["softwareupdate", "--history"], timeout=45)
        return {"history": out[:20000], "source": "softwareupdate"}, error

    def startup(self) -> tuple[Any, str]:
        out, error = _text(["launchctl", "list"], timeout=20)
        labels = []
        for line in out.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 3:
                labels.append(parts[2])
        return {
            "launchd": labels,
            "agents": _listing(Path.home() / "Library" / "LaunchAgents"),
            "daemons": _listing(Path("/Library/LaunchDaemons")),
            "source": "launchctl",
        }, error

    def hardware(self) -> tuple[Any, str]:
        data, error = run_json(
            ["system_profiler", "SPHardwareDataType", "-json"], timeout=60,
        )
        storage, storage_error = run_json(
            ["system_profiler", "SPStorageDataType", "-json"], timeout=60,
        )
        return {
            "hardware": data,
            "storage": storage,
            "source": "system_profiler",
        }, error or storage_error

    def compat_report(self) -> dict:
        host = self.host_info()
        version = host.get("release", "")
        checks = [
            {
                "name": "macOS 13 or later",
                "ok": _version_at_least(version, (13, 0)),
                "detail": version or "unknown",
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
        supported = all(check["ok"] for check in checks)
        return {
            "supported": supported,
            "checks": checks,
            "summary": (
                "supported macOS 13+ baseline"
                if supported else
                "outside the documented macOS 13+ baseline"
            ),
            "os": host,
            "versions": {
                "python": host.get("python", ""),
                "sqlite": host.get("sqlite", ""),
            },
            "documentation": "docs/CROSS-PLATFORM.md",
        }


def _parse_ifconfig(text: str) -> list[dict]:
    interfaces = []
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            name = line.split(":", 1)[0]
            current = {"name": name, "addresses": [], "flags": line}
            interfaces.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("inet "):
            current["addresses"].append(stripped)
        elif stripped.startswith("inet6 "):
            current["addresses"].append(stripped)
        elif stripped.startswith("ether "):
            current["mac"] = stripped.split(None, 1)[-1]
        elif stripped.startswith("status:"):
            current["status"] = stripped.split(":", 1)[-1].strip()
        elif stripped.startswith("mtu "):
            current["mtu"] = stripped.split(None, 1)[-1]
    return interfaces


def _listing(path: Path) -> list[str]:
    try:
        return sorted(item.name for item in path.iterdir() if item.is_file())
    except OSError:
        return []


def _is_float(value: str) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _version_at_least(value: str, minimum: tuple[int, int]) -> bool:
    parts = []
    for part in str(value or "").replace("-", ".").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return bool(parts) and tuple(parts[:len(minimum)]) >= minimum
