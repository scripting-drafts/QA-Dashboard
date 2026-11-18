"""Windows backend.

Read-only collectors use native Windows management interfaces through static
PowerShell/CIM queries and the registry. No user input is interpolated into a
command, and every collector is independently timed out.
"""
from __future__ import annotations

import platform as _platform
import socket
from typing import Any

from .base import (
    Backend, Capability, Snapshot, python_version, run_json, sqlite_version,
)

_PS = [
    "powershell.exe", "-NoProfile", "-NonInteractive",
    "-ExecutionPolicy", "Bypass", "-Command",
]


def _ps_json(script: str, timeout: int = 30) -> tuple[Any | None, str]:
    return run_json([*_PS, script], timeout=timeout)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class WindowsBackend(Backend):
    name = "windows"
    family = "windows"
    display = "Windows"
    minimum_release = (10, 0)
    permissions = ("Administrator for services, security and event logs",)

    def host_info(self) -> dict:
        build = ""
        edition = ""
        product = ""
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            ) as key:
                def get(name: str) -> str:
                    try:
                        return str(winreg.QueryValueEx(key, name)[0])
                    except OSError:
                        return ""
                build = get("CurrentBuildNumber")
                edition = get("EditionID")
                product = get("ProductName")
        except (ImportError, OSError):
            pass
        version = _platform.version()
        if not build and version:
            build = version.rsplit(".", 1)[-1]
        return {
            "system": "Windows",
            "release": _platform.release(),
            "version": version,
            "build": build,
            "edition": edition,
            "product": product,
            "machine": _platform.machine(),
            "hostname": socket.gethostname(),
            "python": python_version(),
            "sqlite": sqlite_version(),
        }

    def capabilities(self) -> dict[str, Capability]:
        caps = super().capabilities()
        caps.update({
            "processes": Capability("processes", "supported", "CIM Win32_Process"),
            "services": Capability("services", "supported", "SCM/Get-Service"),
            "network": Capability("network", "supported", "NetTCPIP/CIM"),
            "security": Capability("security", "supported", "Defender/Firewall/BitLocker/TPM"),
            "crashes": Capability("crashes", "degraded", "Windows Event Log/WER"),
            "updates": Capability("updates", "supported", "Get-HotFix"),
            "startup": Capability("startup", "supported", "Win32_StartupCommand"),
            "hardware": Capability("hardware", "degraded", "CIM/PDH"),
            "boot": Capability("boot", "degraded", "System event log"),
            "kernel": Capability("kernel", "degraded", "WER bugcheck events"),
            "lsm": Capability("lsm", "degraded", "Defender/AppLocker/ASR"),
            "storage": Capability("storage", "supported", "CIM/MSFT_Disk"),
            "scheduler": Capability("scheduler", "supported", "Task Scheduler"),
            "logs": Capability("logs", "supported", "Windows Event Log"),
            "faultcore": Capability("faultcore", "planned", "CPU topology/core parking"),
            "deep": Capability("deep", "planned", "ETW"),
            "trace": Capability("trace", "planned", "ETW"),
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
        script = (
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,"
            "WorkingSetSize,ThreadCount | ConvertTo-Json -Compress -Depth 4"
        )
        data, error = _ps_json(script)
        return [self._process(item) for item in _as_list(data)], error

    @staticmethod
    def _process(item: dict) -> dict:
        return {
            "pid": item.get("ProcessId"),
            "ppid": item.get("ParentProcessId"),
            "name": item.get("Name") or "",
            "exe": item.get("ExecutablePath") or "",
            "rss_kb": int(item.get("WorkingSetSize") or 0) // 1024,
            "threads": item.get("ThreadCount"),
            "source": "CIM Win32_Process",
        }

    def services(self) -> tuple[Any, str]:
        script = (
            "Get-Service | Select-Object Name,DisplayName,Status,StartType | "
            "ConvertTo-Json -Compress -Depth 3"
        )
        data, error = _ps_json(script)
        rows = [{
            "name": item.get("Name"),
            "display": item.get("DisplayName"),
            "status": str(item.get("Status")),
            "start_type": str(item.get("StartType")),
            "source": "Get-Service",
        } for item in _as_list(data)]
        return rows, error

    def network(self) -> tuple[Any, str]:
        script = (
            "$ips = Get-NetIPConfiguration | Select-Object InterfaceAlias,"
            "InterfaceDescription,IPv4Address,IPv6Address,IPv4DefaultGateway,"
            "DNSServer; "
            "$listen = Get-NetTCPConnection -State Listen | Select-Object "
            "LocalAddress,LocalPort,OwningProcess; "
            "$routes = Get-NetRoute | Select-Object DestinationPrefix,"
            "NextHop,InterfaceAlias,RouteMetric; "
            "$dns = Get-DnsClientServerAddress | Select-Object InterfaceAlias,"
            "AddressFamily,ServerAddresses; "
            "[pscustomobject]@{interfaces=$ips; listeners=$listen; "
            "routes=$routes; dns=$dns} | ConvertTo-Json -Compress -Depth 5"
        )
        return _ps_json(script, timeout=45)

    def security(self) -> tuple[Any, str]:
        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            "$mp = Get-MpComputerStatus | Select-Object AMServiceEnabled,"
            "AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,"
            "BehaviorMonitorEnabled,IsTamperProtected,"
            "AntivirusSignatureVersion,AntivirusSignatureLastUpdated; "
            "$fw = Get-NetFirewallProfile | Select-Object Name,Enabled,"
            "DefaultInboundAction,DefaultOutboundAction; "
            "$bl = Get-BitLockerVolume | Select-Object MountPoint,"
            "VolumeStatus,ProtectionStatus,EncryptionPercentage; "
            "$tpm = Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,"
            "TpmActivated,ManagedAuthLevel; "
            "[pscustomobject]@{defender=$mp; firewall=$fw; bitlocker=$bl; "
            "tpm=$tpm} | ConvertTo-Json -Compress -Depth 5"
        )
        return _ps_json(script, timeout=45)

    def crashes(self) -> tuple[Any, str]:
        script = (
            "Get-WinEvent -FilterHashtable @{LogName='Application'; "
            "Id=1000,1001; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 | "
            "Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message | "
            "ConvertTo-Json -Compress -Depth 4"
        )
        data, error = _ps_json(script, timeout=45)
        rows = [{
            "ts": str(item.get("TimeCreated")),
            "id": item.get("Id"),
            "provider": item.get("ProviderName"),
            "level": item.get("LevelDisplayName"),
            "message": (item.get("Message") or "")[:4000],
            "source": "Windows Event Log",
        } for item in _as_list(data)]
        return rows, error

    def updates(self) -> tuple[Any, str]:
        script = (
            "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | "
            "ConvertTo-Json -Compress -Depth 3"
        )
        return _ps_json(script, timeout=45)

    def startup(self) -> tuple[Any, str]:
        script = (
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,"
            "Location,User | ConvertTo-Json -Compress -Depth 3"
        )
        return _ps_json(script, timeout=30)

    def hardware(self) -> tuple[Any, str]:
        script = (
            "$cpu = Get-CimInstance Win32_Processor | Select-Object Name,"
            "NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,LoadPercentage; "
            "$mem = Get-CimInstance Win32_PhysicalMemory | Select-Object "
            "Capacity,Speed,Manufacturer,PartNumber; "
            "$disk = Get-CimInstance Win32_DiskDrive | Select-Object Model,"
            "SerialNumber,Size,MediaType,Status; "
            "$gpu = Get-CimInstance Win32_VideoController | Select-Object Name,"
            "DriverVersion,AdapterRAM,Status; "
            "[pscustomobject]@{cpu=$cpu; memory=$mem; disks=$disk; gpu=$gpu} | "
            "ConvertTo-Json -Compress -Depth 5"
        )
        return _ps_json(script, timeout=45)

    def compat_report(self) -> dict:
        host = self.host_info()
        try:
            build = int(host.get("build") or 0)
        except ValueError:
            build = 0
        checks = [
            {
                "name": "Windows 11 build >= 22000",
                "ok": build >= 22000,
                "detail": f"build {build or 'unknown'}",
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
                "supported Windows 11 baseline"
                if supported else
                "outside the documented Windows 11 baseline"
            ),
            "os": host,
            "versions": {
                "python": host.get("python", ""),
                "sqlite": host.get("sqlite", ""),
            },
            "documentation": "docs/CROSS-PLATFORM.md",
        }


def _version_at_least(value: str, minimum: tuple[int, int]) -> bool:
    parts = []
    for part in str(value or "").replace("-", ".").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return bool(parts) and tuple(parts[:len(minimum)]) >= minimum
