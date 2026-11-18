"""Finding-family equivalence across Linux, Windows and macOS.

Every Linux rule family maps to a concrete Windows and macOS family. A family
may be `ported`, `degraded` (weaker source) or `planned`; it is never silently
dropped. Unknown rules map to `unassigned`, which is backed by the platform
process/event inventory on every OS.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FindingFamily:
    prefix: str
    linux: str
    windows: str
    macos: str
    status: str
    note: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "prefix": self.prefix,
            "linux": self.linux,
            "windows": self.windows,
            "macos": self.macos,
            "status": self.status,
            "note": self.note,
        }


FAMILIES = (
    FindingFamily("boot", "boot.*", "boot.* (System log)", "boot.* (log show)", "ported"),
    FindingFamily("crash", "crash.*", "crash.* (WER/bugcheck)", "crash.* (panic/ips)", "ported"),
    FindingFamily("deep", "deep.*", "trace.deep (ETW)", "trace.deep (DTrace)", "planned"),
    FindingFamily("faultcore", "faultcore.*", "cpu.affinity.*", "cpu.affinity.*", "planned"),
    FindingFamily("gpu", "gpu.*", "gpu.* (WHEA/TDR)", "gpu.* (panic/IOKit)", "degraded"),
    FindingFamily("hardware", "hardware.*", "hardware.* (WMI/PDH)", "hardware.* (IOKit/SMC)", "degraded"),
    FindingFamily("io", "io.*", "io.* (PDH queue)", "io.* (vm/disk)", "degraded"),
    FindingFamily("journal", "journal.*", "eventlog.*", "unifiedlog.*", "ported"),
    FindingFamily("kernel", "kernel.*", "kernel.* (WER/bugcheck)", "kernel.* (panic)", "degraded"),
    FindingFamily("lsm", "lsm.*", "security.* (Defender/ASR)", "security.* (SIP/TCC)", "ported"),
    FindingFamily("memory", "memory.*", "memory.*", "memory.*", "ported"),
    FindingFamily("net", "net.*", "network.* (TCP/IP stack)", "network.* (sysctl)", "ported"),
    FindingFamily("network", "network.*", "network.* (IP Helper/WFP)", "network.* (ifconfig/PF)", "ported"),
    FindingFamily("security", "security.*", "security.* (Defender/ACL)", "security.* (SIP/ACL)", "ported"),
    FindingFamily("service", "service.*", "service.* (SCM)", "service.* (launchd)", "ported"),
    FindingFamily("storage", "storage.*", "storage.* (SMART/WMI)", "storage.* (SMART/IOKit)", "ported"),
    FindingFamily("system", "system.*", "system.* (Event Log)", "system.* (Unified Log)", "ported"),
    FindingFamily("trace", "trace.*", "trace.* (ETW)", "trace.* (DTrace)", "planned"),
    FindingFamily("update", "update.*", "update.* (Windows Update)", "update.* (softwareupdate)", "ported"),
    FindingFamily("usb", "usb.*", "usb.* (WMI/Event Log)", "usb.* (IOKit)", "degraded"),
)

_BY_PREFIX = {family.prefix: family for family in FAMILIES}


def family_for(rule: str) -> FindingFamily:
    prefix = str(rule or "").split(".", 1)[0].lower()
    return _BY_PREFIX.get(prefix, FindingFamily(
        prefix or "unassigned",
        "unassigned",
        "unassigned (process/event inventory)",
        "unassigned (process/event inventory)",
        "planned",
        "No family mapping; retain the raw rule and collect platform evidence.",
    ))


def equivalent(rule: str) -> dict[str, str]:
    family = family_for(rule)
    data = family.as_dict()
    data["rule"] = rule
    return data


def matrix() -> list[dict[str, str]]:
    return [family.as_dict() for family in FAMILIES]


def coverage() -> dict[str, int]:
    counts = {"ported": 0, "degraded": 0, "planned": 0}
    for family in FAMILIES:
        counts[family.status] = counts.get(family.status, 0) + 1
    return counts
