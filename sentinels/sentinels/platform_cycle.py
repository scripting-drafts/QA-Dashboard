"""Portable cycle for Windows and macOS.

The Linux cycle remains in cli.cmd_cycle. This module stores one read-only
platform snapshot, the process table and a cycle run record so status, query,
evidence and tickets keep working while individual collectors are ported.
"""
from __future__ import annotations

import json

from . import db
from .platform import detect as detect_platform
from .util import iso


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "on", "enabled")


def _finding(platform: str, rule: str, severity: str, subject: str,
             detail: str) -> dict:
    stamp = iso()
    return {
        "fingerprint": f"platform|{platform}|{rule}|{subject}",
        "ts": stamp,
        "last_ts": stamp,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": detail,
    }


def _platform_findings(platform: str, data: dict) -> list[dict]:
    out: list[dict] = []
    security = data.get("security") or {}
    if platform == "windows":
        defender = security.get("defender") or {}
        if defender and not _truthy(defender.get("AntivirusEnabled")):
            out.append(_finding(
                platform, "security.defender_disabled", "critical",
                "Microsoft Defender",
                "AntivirusEnabled is false",
            ))
        if defender and not _truthy(defender.get("RealTimeProtectionEnabled")):
            out.append(_finding(
                platform, "security.defender_realtime_off", "error",
                "Microsoft Defender",
                "RealTimeProtectionEnabled is false",
            ))
        firewall = security.get("firewall")
        for profile in _as_list(firewall):
            if not _truthy(profile.get("Enabled")):
                out.append(_finding(
                    platform, "security.firewall_disabled", "error",
                    f"Firewall profile {profile.get('Name') or 'unknown'}",
                    "firewall profile is disabled",
                ))
        for volume in _as_list(security.get("bitlocker")):
            if str(volume.get("ProtectionStatus") or "").lower() not in ("1", "on", "protected"):
                out.append(_finding(
                    platform, "security.bitlocker_off", "warning",
                    f"BitLocker {volume.get('MountPoint') or 'volume'}",
                    "BitLocker protection is off",
                ))
        tpm = security.get("tpm") or {}
        if tpm and not _truthy(tpm.get("TpmReady")):
            out.append(_finding(
                platform, "security.tpm_not_ready", "error",
                "TPM",
                "TpmReady is false",
            ))
        for crash in _as_list(data.get("crashes")):
            event_id = crash.get("id")
            severity = "critical" if event_id == 1001 else "warning"
            rule = "crash.bugcheck" if event_id == 1001 else "crash.application"
            subject = crash.get("provider") or f"event {event_id}"
            out.append(_finding(
                platform, rule, severity, subject,
                str(crash.get("message") or "")[:300],
            ))
    elif platform == "macos":
        gatekeeper = str(security.get("gatekeeper") or "").lower()
        if "disabled" in gatekeeper:
            out.append(_finding(
                platform, "security.gatekeeper_disabled", "critical",
                "Gatekeeper", gatekeeper[:200],
            ))
        sip = str(security.get("sip") or "").lower()
        if "disabled" in sip:
            out.append(_finding(
                platform, "security.sip_disabled", "critical",
                "System Integrity Protection", sip[:200],
            ))
        filevault = str(security.get("filevault") or "").lower()
        if filevault and "on" not in filevault:
            out.append(_finding(
                platform, "security.filevault_off", "warning",
                "FileVault", filevault[:200],
            ))
        firewall = str(security.get("firewall") or "").lower()
        if firewall and "enabled" not in firewall:
            out.append(_finding(
                platform, "security.firewall_disabled", "error",
                "Application Firewall", firewall[:200],
            ))
        for crash in _as_list(data.get("crashes")):
            out.append(_finding(
                platform, "crash.report", "warning",
                crash.get("name") or "DiagnosticReport",
                str(crash.get("path") or "")[:300],
            ))
    return out


def run(conn, backend=None) -> dict:
    backend = backend or detect_platform()
    snapshot = backend.collect()
    data = snapshot.as_dict()
    ts = iso()
    host = data.get("host") or {}
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True)

    conn.execute(
        "INSERT OR REPLACE INTO platform_snapshots(ts, platform, host, payload) "
        "VALUES(?,?,?,?)",
        (ts, backend.name, json.dumps(host, separators=(",", ":"), sort_keys=True),
         payload),
    )

    processes = (data.get("data") or {}).get("processes") or []
    rows = []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        rows.append((
            ts,
            proc.get("pid"),
            proc.get("ppid"),
            proc.get("name") or proc.get("comm") or "",
            proc.get("state") or "",
            proc.get("threads"),
            proc.get("rss_kb"),
            proc.get("cpu_ticks"),
            proc.get("last_cpu"),
            proc.get("cpus_allowed"),
            proc.get("exe") or "",
        ))
    if rows:
        conn.executemany(
            "INSERT OR REPLACE INTO proc_snap"
            "(ts,pid,ppid,comm,state,threads,rss_kb,cpu_ticks,last_cpu,"
            "cpus_allowed,exe) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    meta = {
        "last_platform_ts": ts,
        "last_platform": backend.name,
        "last_platform_host": host.get("hostname") or "",
    }
    for key, value in meta.items():
        db.meta_set(conn, key, str(value))

    findings = _platform_findings(backend.name, data.get("data") or {})
    new_findings = 0
    if findings:
        from . import detect as detect_mod
        for finding in findings:
            try:
                if detect_mod.upsert(conn, finding):
                    new_findings += 1
            except Exception as exc:  # noqa: BLE001 - one rule must not stop a cycle
                snapshot.errors.append(f"finding {finding['rule']}: {exc}")

    db.record_run(
        conn, "cycle", True,
        json.dumps({
            "platform": backend.name,
            "capabilities": len(data.get("capabilities") or {}),
            "collectors": len(data.get("data") or {}),
            "processes": len(processes),
            "findings": len(findings),
            "new_findings": new_findings,
            "errors": len(data.get("errors") or []),
        }, sort_keys=True),
    )
    return {
        "ts": ts,
        "platform": backend.name,
        "host": host,
        "capabilities": data.get("capabilities") or {},
        "collectors": {
            key: (len(value) if isinstance(value, list) else "object")
            for key, value in (data.get("data") or {}).items()
        },
        "processes": len(processes),
        "findings": len(findings),
        "new_findings": new_findings,
        "errors": data.get("errors") or [],
    }
