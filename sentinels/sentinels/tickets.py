"""Generate per-vendor ticket drafts. Never submits anything.

Submission is deliberately manual: a human reviews each draft, attaches the
hash-verified evidence bundle and posts it through the vendor's tracker.
"""
from __future__ import annotations

import os
import re
from datetime import timedelta

from . import classify, config, crash, faultcore, correlate, db, holds, occurrence, packages
from .util import (
    human_bytes, identity_for_ticket, iso, read_text, redact, run, sha256_text, utcnow,
)


def _software_versions(issue: dict | None = None) -> list[dict]:
    """Installed packages relevant to a ticket, newest source of truth first."""
    issue = issue or {}
    found: dict[str, str] = {}
    if issue.get("vendor") != "hardware":
        seen: set[str] = set()
        for row in issue.get("rows") or []:
            exe = str(row.get("exe") or "")
            if not exe.startswith("/") or exe in seen:
                continue
            seen.add(exe)
            try:
                owner = packages.owner(exe)
            except Exception:  # noqa: BLE001 - package state is advisory
                owner = {}
            name = owner.get("package")
            version = owner.get("version")
            if name and version:
                found[str(name)] = str(version)
            if len(found) >= 5:
                break
    if not found:
        installed = dict(packages.installed())
        candidates: list[str] = []
        vendor = issue.get("vendor")
        if vendor == "mozilla":
            candidates = ["firefox-esr", "firefox"]
        elif vendor == "gnome":
            candidates = ["gnome-shell", "mutter", "gjs"]
        elif vendor == "canonical-kernel":
            release = read_text("/proc/sys/kernel/osrelease")
            candidates = [f"linux-image-{release}", "linux-image-generic"]
        elif vendor == "systemd":
            candidates = ["systemd"]
        elif vendor == "nvidia":
            candidates = ["nvidia-settings"]
        for name in candidates:
            if name in installed:
                found[name] = installed[name]
                break
    return [
        {"package": name, "version": version}
        for name, version in sorted(found.items())
    ]


_VERSION_LINE_RE = re.compile(r"(?im)^\s*Version:\s*(.+?)\s*$")


def _context_versions(issue: dict) -> list[str]:
    if issue.get("kind") != "crash":
        return []
    versions: list[str] = []
    for row in issue.get("rows") or []:
        for match in _VERSION_LINE_RE.finditer(row.get("context") or ""):
            value = match.group(1).strip()
            if value and value not in versions:
                versions.append(value)
    return versions


def _version_tag(issue: dict, software: list[dict]) -> str:
    if issue.get("kind") != "crash" or not software:
        return ""
    shown = ", ".join(
        f"{item['package']} {item['version']}" for item in software[:2]
    )
    return f"[{shown}]" if shown else ""


def _version_note(issue: dict, software: list[dict]) -> str:
    contexts = _context_versions(issue)
    if not contexts or not software:
        return ""
    if any(item["version"] in context for item in software for context in contexts):
        return ""
    installed = ", ".join(f"`{item['package']}` {item['version']}" for item in software)
    shown = "; ".join(f"`{value}`" for value in contexts[:3])
    return (
        f"> **Version note:** the crash-time context reports {shown}; "
        f"currently installed: {installed}. Use the installed version for "
        "reproduction and bug matching."
    )


def _environment(topology: dict | None = None, issue: dict | None = None,
                 software: list[dict] | None = None) -> list[str]:
    os_release = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os_release[k] = v.strip('"')
    topo = topology or faultcore.topology()
    software = software if software is not None else _software_versions(issue)
    cpu = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    mem_kb = 0
    for line in read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            mem_kb = int(re.sub(r"[^0-9]", "", line))
            break
    gpu = ""
    rc, out, _ = run(["lspci", "-nn"], timeout=15)
    if rc == 0:
        for line in out.splitlines():
            if re.search(r"VGA|3D|Display", line):
                gpu = re.sub(r"\s+", " ", line.strip())
                break
    lines = [
        f"- OS: {os_release.get('PRETTY_NAME', 'Linux')}",
        f"- Kernel: {read_text('/proc/sys/kernel/osrelease')}",
        f"- CPU: {cpu or 'unknown'} ({topo.get('logical_cpus') or os.cpu_count()} logical CPUs)",
    ]
    if topo.get("state") not in ("retired", "offline"):
        lines.append(
            f"- {faultcore.display_label(topo)}: {faultcore.presence(topo)}")
    lines.append(f"- Memory: {human_bytes(mem_kb)}")
    for item in software:
        lines.append(f"- Software: `{item['package']}` {item['version']}")
    if gpu:
        lines.append(f"- GPU: {gpu}")
    platform = " ".join(
        filter(None, [
            read_text("/sys/class/dmi/id/sys_vendor"),
            read_text("/sys/class/dmi/id/product_name"),
        ])
    )
    if platform:
        lines.append(f"- Platform: {platform}")
    bios_version = read_text("/sys/class/dmi/id/bios_version")
    if bios_version:
        bios_vendor = read_text("/sys/class/dmi/id/bios_vendor")
        bios_date = read_text("/sys/class/dmi/id/bios_date")
        suffix = f" ({bios_date})" if bios_date else ""
        lines.append(f"- BIOS: {bios_vendor + ' ' if bios_vendor else ''}{bios_version}{suffix}")
    return lines


def _issue_context(issue: dict | None) -> str:
    if not issue:
        return ""
    for row in issue.get("rows") or []:
        context = str(row.get("context") or "")
        if context:
            return context
    return ""


def _browser_crash(issue: dict | None) -> bool:
    """True only for a Firefox-family process crash.

    Vendor alone is not enough to select browser reproduction steps. GNOME
    Shell embeds SpiderMonkey, so a shell crash contains ``libmozjs`` frames;
    the browser's own marker is the executable, a Firefox child process name,
    or ``libxul`` in the stack.
    """
    if not issue:
        return True
    # Browser repro steps reproduce a crash; an event or finding has no stack
    # to drive them and would turn into a page-load guess.
    if issue.get("kind") != "crash":
        return False
    for row in issue.get("rows") or []:
        exe = str(row.get("exe") or "").lower()
        comm = str(row.get("comm") or "").lower()
        if "firefox" in exe or comm.startswith("firefox"):
            return True
        if comm in ("isolated web co", "web content", "webextensions",
                    "gpu process", "socket thread", "geckomain",
                    "rdd process", "utility process"):
            return True
        if "libxul" in str(row.get("context") or "").lower():
            return True
    return False


def _repro_block(vendor: str, topology: dict | None = None,
                 issue: dict | None = None) -> list[str]:
    topo = topology or faultcore.topology()
    present = topo.get("present") is True
    core = faultcore.label(topo)
    siblings = ",".join(map(str, topo.get("logical") or []))
    if not siblings:
        siblings = ",".join(str(cpu) for cpu in config.FAULT_CORE_CPUS) or "unavailable"
    control = ",".join(str(cpu) for cpu in config.CONTROL_CPUS) or "0"
    if vendor == "gnome":
        frame = crash.faulting_frame(_issue_context(issue))
        module = str((frame or {}).get("module") or "").lower()
        if "mutter" in module:
            owner = "mutter"
        elif "gjs" in module or "mozjs" in module:
            owner = "gjs"
        else:
            owner = "gnome-shell"
        return [
            "1. Reproduce on a GNOME session matching the report: record "
            "`echo $XDG_SESSION_TYPE` and `gnome-shell --version`.",
            "2. List the enabled extensions (`gsettings get org.gnome.shell "
            "enabled-extensions`); repeat once with non-stock extensions disabled.",
            f"3. Repeat the window action named in the stack until {owner} exits, "
            "then record whether the faulting frame is unchanged.",
            "4. Capture `coredumpctl info <pid>` and install the debug symbols "
            "matching the recorded build-id before interpreting the frame.",
            f"5. Report the faulting frame against {owner} together with the "
            "session type, extension list and how many frames the signal handler covers.",
        ]
    if vendor == "mozilla":
        if not _browser_crash(issue):
            return [
                "1. Reproduce the action logged above on the same build; keep the "
                "component version and its configuration unchanged.",
                "2. Capture the same log line with the surrounding timestamp window.",
                "3. Attach the evidence bundle and the exact component version.",
            ]
        if present:
            pin = (
                f"2. Pin the browser to the SMT siblings of {core}: "
                f"`taskset -c {siblings} firefox-esr --no-remote --new-instance`."
            )
            control_step = (
                f"4. Control run: same steps pinned to another physical core "
                f"(e.g. `taskset -c {control}`)."
            )
            return [
                "1. Use a fresh Firefox profile (never a logged-in profile).",
                pin,
                "3. Load the page that triggered WebRender/compositor work until the tab or GPU process crashes.",
                control_step,
                "5. Compare `about:crashes` minidumps and the sentinel crash table.",
            ]
        return [
            "1. Use a fresh Firefox profile (never a logged-in profile).",
            "2. Load the page that triggered WebRender/compositor work until the tab or GPU process crashes.",
            "3. Compare `about:crashes` minidumps and the sentinel crash table.",
        ]
    if vendor == "canonical-kernel":
        if present:
            return [
                "1. Reproduce the workload on the installed system; keep the sentinel running.",
                f"2. Run the fault-core live test from a disposable live USB: "
                f"`~/faultcore/verify-faultcore-live.sh` (logical CPUs {siblings}).",
                "3. Compare suspect against a control core for equal duration.",
                "4. Capture `journalctl -k -b -1`, `coredumpctl info`, and the latest evidence bundle.",
            ]
        return [
            "1. Reproduce the workload on the installed system; keep the sentinel running.",
            "2. Capture `journalctl -k -b -1`, `coredumpctl info`, and the latest evidence bundle.",
        ]
    if vendor == "nvidia":
        return [
            "1. Reproduce with the vendor driver loaded; watch `nvidia-smi -q` and kernel `Xid` lines.",
            "2. Capture `nvidia-bug-report.sh` output and the sentinel evidence bundle.",
            "3. Compare with the open-source driver if available.",
        ]
    if vendor == "hardware":
        if present:
            return [
                "1. The sentinel records per-core affinity and crash correlation continuously.",
                f"2. From a disposable live USB, stress {core} "
                f"(`{siblings}`) and a control core (`{control}`).",
                "3. Capture MCE/EDAC/thermal data and the evidence bundle.",
                "4. Replace or re-seat the CPU only after the vendor confirms the diagnosis.",
            ]
        return [
            "1. The sentinel records per-core affinity and crash correlation continuously.",
            "2. Capture MCE/EDAC/thermal data and the evidence bundle.",
            "3. Replace or re-seat the CPU only after the vendor confirms the diagnosis.",
        ]
    return [
        "1. Reproduce with the sentinel running (`~/QA-Sentinels/bin/qa status`).",
        "2. Attach the latest evidence bundle.",
    ]


def _reproduction_viability(topo: dict, vendor: str) -> str:
    """Rough, explicitly orientative odds that the repro steps can be followed."""
    state = topo.get("state")
    if vendor == "gnome":
        return (
            "**~70%** — reproducible on a matching GNOME session, but the "
            "extension set, session type and debug symbols must match the report.")
    if vendor in ("mozilla", "canonical-kernel", "hardware"):
        if state in ("retired", "offline"):
            return (
                "**~20%** — reproduction is limited to available-core runs on "
                "this host; the control path remains reproducible.")
        if topo.get("present") is True:
            return (
                "**~70%** — the fault core is online; the affinity comparison "
                "and control run are both reproducible.")
        if topo.get("present") is False:
            return (
                "**~35%** — the configured fault core is absent; only an "
                "approximate control-core comparison is possible.")
        if state == "unconfigured":
            return (
                "**~50%** — no fault core is configured; reproduction depends "
                "on the available hardware.")
        return (
            "**~50%** — the fault-core topology is undetermined; reproduction "
            "depends on the host.")
    if vendor == "nvidia":
        return (
            "**~60%** — the driver path is reproducible, but it requires a "
            "matching GPU and driver state.")
    return (
        "**~90%** — the steps use the local sentinel and do not depend on "
        "the fault core.")


def held_context(issue: dict) -> dict:
    """Held/outdated package context for a crash issue, when resolvable.

    Only an absolute executable path can be attributed to an installed package,
    and a lookup failure must never stop a draft from being generated. The
    result is attached to the issue so the gate and the draft text agree.
    """
    if issue.get("kind") != "crash":
        return {}
    exe = next((r.get("exe") for r in issue.get("rows") or [] if r.get("exe")), None)
    if not exe or not os.path.isabs(str(exe)):
        return {}
    try:
        return holds.relevant(str(exe))
    except Exception:  # noqa: BLE001 - package state is advisory, never fatal
        return {}


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _display_text(row: dict, fallback: str) -> str:
    """Human-readable text. Signatures stay masked only for grouping keys."""
    if row.get("sig"):
        name = row.get("comm") or (row.get("exe") or "").rsplit("/", 1)[-1]
        # coredump truncates comm to 15 characters and leaves a trailing dash.
        name = re.sub(r"-+$", "", str(name)) or str(name)
        text = f"{name} {row['sig']}".strip()
    else:
        text = (row.get("message") or "").strip().splitlines()
        text = text[0] if text else ""
    text = _ANSI.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return redact(text)[:200] or fallback


def _draft_rank(issue: dict) -> tuple:
    """Order drafts by what the raise gate is likely to accept.

    A capped run must not spend its slots on one-off critical warnings while a
    high-volume, substantive error waits outside the cap.
    """
    kind = issue.get("kind")
    count = int(issue.get("count") or 0)
    substantive = kind in ("correlation", "crash") or count >= config.RAISE_MIN_COUNT
    return (
        kind != "correlation",
        kind != "crash",
        not substantive,
        issue.get("severity") != "critical",
        -count,
        issue.get("key") or "",
    )


def select_issues(issues: list[dict], max_tickets: int | None = None) -> list[dict]:
    """Apply the draft cap after substantive issues have been prioritised."""
    cap = config.MAX_TICKETS if max_tickets is None else max_tickets
    ordered = sorted(issues, key=_draft_rank)
    findings = [issue for issue in ordered if issue.get("kind") == "finding"]
    others = [issue for issue in ordered if issue.get("kind") != "finding"]
    return findings + (others if cap <= 0 else others[:cap])


def collect_issues(conn, days: int = 7, include_local: bool = False) -> list[dict]:
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    crashes = [dict(r) for r in conn.execute(
        "SELECT * FROM crashes WHERE ts>=? ORDER BY ts DESC", (since,)
    )]
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM events WHERE ts>=? AND severity IN ('critical','error') ORDER BY ts DESC",
        (since,),
    )]
    findings = [dict(r) for r in conn.execute(
        "SELECT * FROM findings WHERE status IN ('open','investigating') ORDER BY ts DESC"
    )]

    issues: dict[str, dict] = {}

    def add(vendor: str, signature: str, kind: str, row: dict) -> None:
        key = sha256_text(f"{vendor}|{kind}|{signature}")[:20]
        # Finding ``count`` is the number of collection runs that re-observed
        # the same condition, not the number of independent events. One finding
        # row is one observation; recurring evidence is represented by distinct
        # rows (for example one pstore archive per panic).
        n = 1 if kind == "finding" else int(row.get("count") or 1)
        first = row.get("ts")
        last = row.get("last_ts") or row.get("ts")
        issue = issues.setdefault(
            key,
            {
                "key": key,
                "vendor": vendor,
                "signature": signature,
                "display": _display_text(row, signature),
                "kind": kind,
                "rows": [],
                "count": 0,
                "severity": row.get("severity") or ("critical" if kind == "crash" else "error"),
                "first": first,
                "last": last,
            },
        )
        if not issue.get("display"):
            issue["display"] = _display_text(row, signature)
        issue["rows"].append(row)
        issue["count"] += n
        if first:
            issue["first"] = min(issue["first"], first) if issue["first"] else first
        if last:
            issue["last"] = max(issue["last"], last) if issue["last"] else last
        if row.get("severity") == "critical":
            issue["severity"] = "critical"

    for c in crashes:
        vendor = classify.vendor_for_crash(
            c.get("comm") or "", c.get("exe") or "",
            c.get("sig") or "", c.get("context") or "",
        )
        if c.get("faultcore_involved") == 1 and vendor == "local":
            vendor = "hardware"
        sig = f"{c.get('comm') or c.get('exe')} {c.get('sig')}"
        add(vendor, sig, "crash", c)

    for e in events:
        vendor = classify.vendor_for(e.get("unit") or "", e.get("message") or "")
        sig = classify.signature(e.get("message") or "")
        add(vendor, sig, "event", e)

    for finding in findings:
        vendor = classify.vendor_for_finding(
            finding.get("rule") or "",
            finding.get("subject") or "",
            finding.get("detail") or "",
        )
        sig = f"{finding.get('rule')}: {finding.get('subject')}"
        row = dict(finding)
        row["kind"] = "finding"
        row["message"] = (
            f"{finding.get('rule')}: {finding.get('subject')}: {finding.get('detail')}"
        )
        add(vendor, sig, "finding", row)

    # dedicated hardware ticket: fault-core correlation must reach the platform
    # vendor. A verdict without a recorded mask is unknown, not involved.
    faultcore_crashes = [
        c for c in crashes
        if c.get("faultcore_involved") == 1 and str(c.get("cpus_allowed") or "").strip()
    ]
    if faultcore_crashes:
        key = sha256_text("hardware|faultcore-correlation")[:20]
        issues[key] = {
            "key": key,
            "vendor": "hardware",
            "signature": "crashes correlated with fault-core affinity",
            "display": "crashes correlated with fault-core affinity",
            "kind": "correlation",
            "rows": faultcore_crashes,
            "count": len(faultcore_crashes),
            "severity": "critical",
            "first": min(c["ts"] for c in faultcore_crashes),
            "last": max(c["ts"] for c in faultcore_crashes),
        }

    result = [
        i
        for i in issues.values()
        if (i["kind"] == "finding" or include_local or i["vendor"] != "local")
        and classify.ticketworthy(i["signature"], i["kind"], i["severity"], i["count"])
    ]
    # silent stops correlated with a recurring component signature: the one path
    # where a ticket has no single log line to point at, only a convergence.
    result.extend(correlate.ticket_candidates(conn, days))
    # attach package state once, so the viability gate and the draft body use
    # the same answer instead of querying apt twice and disagreeing
    for issue in result:
        hold = held_context(issue)
        if hold:
            issue["held"] = hold
    result.sort(key=_draft_rank)
    return result


def _mentions_faultcore(issue: dict) -> bool:
    text = f"{issue.get('signature') or ''} {issue.get('display') or ''}".lower()
    if "fault core" in text or "fault-core" in text:
        return True
    if issue.get("kind") == "correlation":
        return True
    if issue.get("vendor") in ("canonical-kernel", "hardware"):
        return True
    # Same-process affinity is the only evidence that names the fault core.
    # A shared SpiderMonkey or GTK library is not a CPU correlation.
    return any(row.get("faultcore_involved") == 1 for row in issue.get("rows") or [])


def _faultcore_table(rows: list[dict], topology: dict | None = None) -> list[str]:
    crashed = [r for r in rows if "sig" in r]
    if not crashed:
        return ["No crash rows in this cluster."]
    lines = [
        "| time (UTC) | component | process | signal | allowed CPUs | fault core in mask |",
        "|---|---|---|---|---|---|",
    ]
    for c in crashed[:25]:
        verdict = {1: "yes", 0: "no", None: "unknown"}.get(c.get("faultcore_involved"), "unknown")
        lines.append(
            f"| {c.get('ts')} | `{c.get('component') or c.get('comm') or c.get('exe') or 'unassigned'}` | "
            f"`{c.get('comm') or c.get('exe')}` | {c.get('sig')} | "
            f"`{c.get('cpus_allowed') or 'unknown'}` | {verdict} |"
        )
    lines += [
        "",
        "Affinity comes from the last `/proc/<pid>/status` sample before the crash. "
        "Unknown affinity is labelled unknown, not discarded. This correlation is part "
        "of the QA record and is included in every ticket.",
    ]
    topo = topology or faultcore.topology()
    if topo.get("present") is False:
        lines.append(
            f"Current host topology does not expose {faultcore.label(topo)}; any `yes` "
            "rows are historical or from a different topology."
        )
    elif topo.get("present") is None:
        lines.append(
            f"Current host topology cannot verify {faultcore.label(topo)} "
            f"({topo.get('state') or 'unknown'}); verdicts are taken from the recorded "
            "affinity masks, not from a fresh CPU census."
        )
    return lines


def _crash_evidence(issue: dict) -> tuple[str, dict | None]:
    """Stack-forward digest of the crash context and its faulting frame."""
    context = _issue_context(issue)
    if not context:
        for row in issue.get("rows") or []:
            message = str(row.get("message") or "")
            if message:
                return message[:3000], None
        return "", None
    return crash.digest(context), crash.faulting_frame(context)


def _fault_bullets(issue: dict, fault: dict | None) -> list[str]:
    """Name the frame that faulted, past the process's signal handler."""
    if not fault:
        return []
    module = str(fault.get("module") or "")
    offset = str(fault.get("offset") or "")
    where = ""
    if module and module != "n/a":
        where = f" ({module}{' + ' + offset if offset else ''})"
    symbol = fault.get("symbol") or "n/a"
    lines = [f"- Faulting frame: `#{fault.get('index')} {symbol}{where}`"]
    if fault.get("handler"):
        last = max(int(fault.get("handler_frames") or 1) - 1, 0)
        lines.append(
            f"- Frames #0–#{last} are the process signal handler re-raising the "
            "signal; the fault starts at the frame above.")
    if fault.get("nearest"):
        lines.append(
            "- A `+ 0x…` offset is the nearest exported symbol, not a debug-resolved "
            "frame; install the build-id debug package before drawing conclusions.")
    if not fault.get("symbol"):
        target = module if module and module != "n/a" else "the faulting module"
        lines.append(
            f"- The faulting frame has no symbol; install the build-id debug package "
            f"for `{target}` to identify it.")
    modules = crash.crash_thread_modules(_issue_context(issue))
    if modules:
        lines.append("- Crash-thread modules: " + ", ".join(
            f"`{name}`" for name in modules))
    return lines


def _routing_bullets(issue: dict, component: str,
                     fault: dict | None) -> list[str]:
    if issue.get("kind") != "crash":
        return []
    rows = issue.get("rows") or []
    row = next((r for r in rows if r.get("context")), rows[0] if rows else {})
    notes = classify.routing_notes(
        str(row.get("comm") or ""), str(row.get("exe") or ""),
        str(row.get("sig") or ""), str(row.get("context") or ""),
        str(issue.get("vendor") or ""),
    )
    if fault and fault.get("module") not in (None, "", "n/a"):
        notes.append(
            f"Component rule: faulting module `{fault['module']}` → **{component}**.")
    return [f"- {note}" for note in notes]


def _draft(issue: dict, bundle: dict | None, identity: dict, consent: bool,
           conn=None) -> tuple[str, str]:
    meta = classify.VENDOR_META.get(issue["vendor"], classify.VENDOR_META["local"])
    component = classify.component_for_issue(issue)
    topo = faultcore.topology()
    software = _software_versions(issue)
    shown = issue.get("display") or issue["signature"]
    title = f"[QA] {component}: {shown[:120]}"
    version_tag = _version_tag(issue, software)
    if version_tag:
        title = f"{title} {version_tag}"
    fault_tag = faultcore.theme_tag(topo)
    if _mentions_faultcore(issue) and fault_tag:
        title = f"{title} [{fault_tag}]"
    rows = issue["rows"]
    if issue.get("kind") == "crash":
        # The producer owns the configured/involved distinction in its context.
        # Keep it verbatim: absence of crash affinity is not evidence that a
        # retired or offline fault core was uninvolved.
        example, fault = _crash_evidence(issue)
    else:
        example = ""
        fault = None
        if rows:
            example = redact(str(rows[0].get("message") or rows[0].get("context") or ""))[:3000]

    lines = [
        f"# {title}",
        "",
        f"- Vendor / channel: **{meta['name']}** — {meta['channel']}",
        f"- Cluster key: `{issue['key']}`",
        f"- Occurrences: **{issue['count']}** between `{issue['first']}` and `{issue['last']}`",
        "",
        "## Environment",
        "",
        *_environment(topo, issue, software),
        "",
    ]
    if issue.get("kind") == "crash":
        # a crash in a held, outdated module may already be fixed upstream
        hold = issue.get("held")
        if hold is None:
            hold = held_context(issue)
        # A global hold is only explanatory when the crashed executable has no
        # known owner. For an owned executable, show only its held family.
        if hold.get("relevant") or (
            hold.get("mass_hold") and not hold.get("owner")
        ):
            lines += ["## Held packages", ""]
            if hold.get("mass_hold"):
                lines.append(
                    f"- **Global hold**: {hold['held_total']} packages held, "
                    f"{hold['held_installed']} installed — upgrades are pinned system-wide"
                )
            for row in (hold.get("outdated") or [])[:10]:
                lines.append(
                    f"- Outdated and held: `{row['package']}` {row['installed']} "
                    f"(candidate {row['candidate']})"
                )
            if not hold.get("outdated") and hold.get("relevant"):
                lines.append("- Related packages are held but current.")
            lines.append("")
    version_note = _version_note(issue, software)
    if issue["kind"] == "crash" and issue["count"] > 1:
        summary = (
            f"A recurring crash cluster ({issue['count']} occurrences) was "
            "observed by the local QA sentinel:"
        )
    elif issue["kind"] == "crash":
        summary = "A crash was observed by the local QA sentinel:"
    else:
        summary = (
            f"A recurring {issue['kind']} cluster was observed by the local QA sentinel:"
        )
    lines += [
        "## Description",
        "",
        summary,
        "",
    ]
    if version_note:
        lines += [version_note, ""]
    lines += [
        "```",
        redact(example)[:4000] or "(no message captured)",
        "```",
        "",
    ]
    fault_lines = _fault_bullets(issue, fault)
    if fault_lines:
        lines += [*fault_lines, ""]
    routing = _routing_bullets(issue, component, fault)
    if routing:
        lines += ["## Classification", "", *routing, ""]
    if issue.get("notes"):
        lines += ["## Consistency", "", issue["notes"], ""]
    if topo.get("state") not in ("retired", "offline"):
        lines += [
            f"## {faultcore.display_label(topo)} correlation — {faultcore.presence_summary(topo)}",
            "",
            *_faultcore_table(rows, topo),
            "",
        ]
    lines += [
        "## Reproduction",
        "",
        *_repro_block(issue["vendor"], topo, issue),
        "",
        f"Reproduction viability: {_reproduction_viability(topo, issue['vendor'])}",
        "",
        "## Evidence",
        "",
    ]
    if bundle:
        import os as _os

        raw_path = str(bundle.get("path") or "")
        try:
            shown = _os.path.relpath(raw_path, config.ROOT)
            if shown.startswith(".."):
                shown = _os.path.basename(raw_path)
        except ValueError:
            shown = _os.path.basename(raw_path)
        lines += [
            f"- Bundle: `{shown}`",
            f"- Bundle SHA-256: `{bundle.get('sha256')}`",
            f"- Previous bundle SHA-256: `{bundle.get('prev_sha256')}`",
            f"- Contents: {bundle.get('contents', '')}",
            f"- Verify with: `cd ~/QA-Sentinels && bin/qa verify {shown}`",
        ]
    else:
        lines += [
            "- No bundle generated yet. Run `~/QA-Sentinels/bin/qa evidence --reason ticket` and attach it.",
        ]
    context = occurrence.ticket_context(issue, bundle, conn)
    if context:
        lines += ["", "### Occurrence context", "", *context]
    lines += [
        "",
        "## Requested action",
        "",
        "Confirm whether the fault is in this component, request additional traces, and advise",
        "on a workaround. The sentinel continues collecting 1-minute kernel/memory/CPU samples,",
        "a 3-hour layered inventory, and startup reports.",
        "",
        "## Reporter",
        "",
    ]
    if consent and identity:
        lines += [f"- Name: {identity.get('FULL_NAME', '')}"]
        if identity.get("LINKEDIN"):
            lines.append(f"- LinkedIn: {identity['LINKEDIN']}")
        if identity.get("GITHUB"):
            lines.append(f"- GitHub: {identity['GITHUB']}")
    else:
        lines.append(
            "- Identity withheld. Set `TICKET_CONSENT=1` plus FULL_NAME/LINKEDIN/GITHUB "
            "in `config/identity.env` to attach it; nothing is invented or auto-filled."
        )
    return title, "\n".join(lines) + "\n"


# Deprecated shim: kept so out-of-tree callers do not break.
_collect_issues = collect_issues


def generate(conn, days: int = 7, include_local: bool = False, max_tickets: int | None = None) -> list[dict]:
    issues = collect_issues(conn, days, include_local)
    selected = select_issues(issues, max_tickets)
    bundle_row = conn.execute(
        "SELECT * FROM bundles ORDER BY id DESC LIMIT 1"
    ).fetchone()
    bundle = dict(bundle_row) if bundle_row else None
    identity, consent = identity_for_ticket()

    made = []
    keep: set[str] = set()
    conn.execute("DELETE FROM ticket_drafts")
    for issue in selected:
        title, body = _draft(issue, bundle, identity, consent, conn)
        vendor = issue["vendor"]
        slug = re.sub(r"[^a-z0-9]+", "-", issue["signature"].lower()).strip("-")[:60]
        path = config.DRAFT_DIR / f"{vendor}-{slug}-{issue['key'][:8]}.md"
        try:
            path.write_text(body, encoding="utf-8")
        except PermissionError:
            # A root cron may have left a 0600 root-owned draft at the canonical
            # path.  Keep the evidence and write a fresh operator-owned draft.
            path = config.DRAFT_DIR / (
                f"{vendor}-{slug}-{issue['key'][:8]}-"
                f"{utcnow().strftime('%H%M%S')}.md"
            )
            path.write_text(body, encoding="utf-8")
        keep.add(str(path))
        conn.execute(
            "INSERT INTO ticket_drafts(ts, vendor, path, title, issue_key)"
            " VALUES(?,?,?,?,?) ON CONFLICT(issue_key) DO UPDATE SET"
            " ts=excluded.ts, path=excluded.path, title=excluded.title",
            (iso(), vendor, str(path), title, issue["key"]),
        )
        made.append({"vendor": vendor, "title": title, "path": str(path), "count": issue["count"]})
    retention = config.DRAFT_RETENTION_DAYS
    cutoff = utcnow().timestamp() - retention * 86400
    for old in config.DRAFT_DIR.glob("*.md"):
        if old.name == "INDEX.md":  # generated digest target, not a draft
            continue
        if str(old) in keep:
            continue
        if retention > 0:
            try:
                if old.stat().st_mtime >= cutoff:
                    continue
            except OSError:
                continue
        try:
            old.unlink(missing_ok=True)
        except PermissionError:
            # Root-owned leftovers are reported by the security tier; do
            # not let them stop the operator-owned draft set.
            continue
    db.meta_set(conn, "last_ticket_run", iso())
    _triage_new_tickets(conn, selected)
    return made


def _triage_new_tickets(conn, issues: list[dict]) -> None:
    """Run the viability gate as soon as the draft set changes.

    Drafts are generated on a schedule, but a ticket that appears should be
    triaged in the same pass that created it, not up to five minutes later.
    """
    keys = {i["key"] for i in issues}
    seen = set(filter(None, (db.meta_get(conn, "triaged_draft_keys") or "").split(",")))
    if not keys or keys == seen:
        return
    from . import raise_ticket  # lazy: raise_ticket imports this module

    try:
        result = raise_ticket.run(conn)
        db.meta_set(conn, "triaged_draft_keys", ",".join(sorted(keys)))
        db.record_run(conn, "tickets/raise", True,
                      f"viable={result['viable']} rejected={result['rejected']}")
    except Exception as exc:  # noqa: BLE001 - triage must never block drafts
        db.record_run(conn, "tickets/raise", False, str(exc)[:300])
