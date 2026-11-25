"""Severity and vendor classification, kept in one testable place.

Attribution has three explicit stages, in order:

1. **Faulting driver module** — a frame inside a proprietary driver is the
   driver vendor's defect, whatever process happened to load it.
2. **Process anchor** — the crashing executable owns its bug. Shared libraries
   do not: GNOME Shell embeds SpiderMonkey (``libmozjs``), so every gjs stack
   contains ``mozilla::`` symbols, and Firefox embeds GTK, so every Firefox
   stack contains ``g_object_unref``. Matching owners on those symbols files
   GNOME crashes against Mozilla and Firefox crashes against GNOME.
3. **Content rules** — only for processes that are not a known component.

The component label follows the faulting frame, not the embedding process:
``libmutter`` means mutter, ``libgjs`` means gjs, and a Firefox process with
WebRender frames means ``Core :: Graphics: WebRender``.
"""
from __future__ import annotations

import re

from . import crash

CRITICAL_PATTERNS = [
    r"\bpanic\b", r"\bkernel panic\b", r"\boops\b", r"\bBUG:", r"\bWARNING: CPU:",
    r"general protection fault", r"\bMCE\b", r"machine check", r"hardware error",
    r"\bEDAC\b", r"\bRAS\b", r"mce: ", r"\bXid\b",
    r"NVRM: .*(?:Xid|error|fatal|assert|GPU has fallen|video memory|out of memory)",
    r"watchdog: BUG",
    r"soft lockup", r"hard lockup", r"hung task", r"out of memory", r"oom-kill",
    r"segfault", r"segmentation fault", r"\bSIGSEGV\b", r"\bSIGABRT\b", r"\bSIGBUS\b",
    r"\bSIGILL\b", r"I/O error", r"EXT4-fs error", r"XFS .*corrupt",
    r"ata[0-9.]+: (?:hard resetting|failed command|exception)", r"nvme.*(?:reset|timeout)",
    r"GPU has fallen off the bus", r"failed to idle channel", r"page fault",
    r"unrecoverable", r"fatal", r"corrupt", r"\bABRT\b",
]

ERROR_PATTERNS = [
    r"\berror\b", r"\berr\b", r"\bfailed\b", r"\bfailure\b", r"\bfatal\b",
    r"\babort\b", r"\bcrash", r"\bdenied\b", r"\bexception\b", r"\btimeout\b",
    r"cannot allocate", r"no space left", r"broken pipe",
]

WARNING_PATTERNS = [
    r"\bwarn", r"\bdeprecat", r"\bretry", r"\bthrottl", r"\bdegraded\b",
    r"unable to", r"not responding", r"slow", r"stall",
]

NOISE_PATTERNS = [
    r"Californ(?:ia|ie) institute of Technology",  # NVIDIA EDID spam
    r"NVIDIA\(GPU-0\): .*maximum pixel clock",
    r"Failed to set mode.*EDID",
    r"dbus-daemon.*(?:Activating|Successfully activated)",
    r"^\(--\)",                                   # Xorg info level
    r"^\(II\)",
    r"NVIDIA\(GPU-0\): ?(?:DFP|.*maximum pixel clock|disconnected|connected|Internal|$)",
    r"ibus-daemon.*GChildWatchSource",
    r"Owner of volume monitor",
    r"tracker-miner-f.*volume monitor",
    r"xf86CloseConsole",
    r"systemd-logind: (?:not releasing fd|failed to release device)",
    r"UnloadModule",
    r"Deleting GPU-0",
    r"Server terminated successfully",
    r"\(EE\) event\d+ - .*client bug: event processing lagging",
    r"NVRM: loading NVIDIA",
]

# rasdaemon reports tracepoint management as "<subsys>:<event> event enabled"
# (or "Enabled event <subsys>:<event>").  The "mce:" prefix is a tracepoint
# name, not a machine-check record, so these lines are control-plane noise.
TRACEPOINT_CONTROL = re.compile(
    r"(?i)^(?:rasdaemon(?:\[\d+\])?:\s*)?(?:"
    r"(?:enabled|disabled) event [a-z0-9_]+:[a-z0-9_]+|"
    r"[a-z0-9_]+:[a-z0-9_]+ event (?:enabled|disabled)"
    r")\s*$"
)


def tracepoint_control(message: str) -> bool:
    """True for rasdaemon's tracepoint enable/disable status lines."""
    return bool(TRACEPOINT_CONTROL.match((message or "").strip()))


# Real but non-actionable for a vendor ticket: keep in the local record,
# never turn into a draft.
BENIGN_FOR_TICKET = [
    r"not generating service for xdg[ -]autostart",
    r"prime-offload",
    r"Failed to bind sideband socket",
    r"permission denied.*xdriver",
    r"NVRM: loading NVIDIA",
    r"Failed to take device /dev/dri/card0",
    r"Could not create transient scope for PID",
]

# Per-init and per-resume probe notices. They repeat on every boot and every
# controller power-up, so their presence in a death window is not evidence of
# a fault. A rate change still reaches the local record and dashboard.
BOOT_PROBE_NOISE = [
    r"ata[^:]*: supports DRM functions and may not be fully accessible",
    r"Bluetooth: hci0: (?:HCI LE Coded PHY|FW download error recovery failed|"
    r"Reading supported features failed|Failed to read MSFT supported features)",
    r"usb: port power management may be unreliable",
    r"nvidia: (?:loading out-of-tree module taints kernel|module license .* taints kernel)",
    r"Disabling lock debugging due to kernel taint",
    r"Booted with the nomodeset parameter",
    r"Driver .* not loading because of nomodeset parameter",
    r"friendly-recovery\.service",
    r"(?:systemd-journald.*)?File .*journal.*corrupted or uncleanly shut down",
    r"kauditd_printk_skb: \d+ callbacks suppressed",
]

# Probe-capability findings describe the collector, not the component. They
# belong in coverage views and must never become a vendor ticket.
COVERAGE_FOR_TICKET = [
    r"^hardware\.coverage\b",
    r"^hardware\.vendor\.missing\b",
]


def ticketworthy(signature: str, kind: str, severity: str, count: int) -> bool:
    text = signature or ""
    if any(re.search(p, text, re.IGNORECASE)
           for p in BENIGN_FOR_TICKET + BOOT_PROBE_NOISE):
        return False
    if kind == "finding":
        return not any(re.search(p, text, re.IGNORECASE)
                       for p in COVERAGE_FOR_TICKET)
    if kind in ("crash", "correlation"):
        return True
    if severity == "critical":
        return True
    return severity == "error" and count >= 5


def _match(patterns, text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def classify(message: str, priority: int | None = None) -> str:
    """Return one of critical|error|warning|info|noise."""
    text = (message or "").strip()
    if not text:
        return "info"
    if tracepoint_control(text):
        return "noise"
    if _match(NOISE_PATTERNS, text):
        return "noise"
    if _match(CRITICAL_PATTERNS, text):
        return "critical"
    if _match(ERROR_PATTERNS, text):
        return "error"
    if _match(WARNING_PATTERNS, text):
        return "warning"
    if priority is not None:
        if priority <= 2:
            return "critical"
        if priority == 3:
            return "error"
        if priority == 4:
            return "warning"
    return "info"


def priority_to_severity(priority: int | None) -> str:
    if priority is None:
        return "info"
    return {0: "critical", 1: "critical", 2: "critical", 3: "error", 4: "warning"}.get(
        priority, "info"
    )


VENDOR_RULES = [
    # Mozilla is a browser owner, not the owner of every SpiderMonkey frame.
    # ``mozilla::`` and ``libmozjs`` are deliberately absent: gjs embeds them.
    # ``compositor`` is absent too: mutter calls its own compositor that.
    ("mozilla", re.compile(
        r"firefox|webrender|\bgecko\b|libxul|tab crash|content process|"
        r"\bgfx::|\bmozilla::(?:gfx|layers|dom|wr|WebRender)",
        re.IGNORECASE)),
    ("nvidia", re.compile(r"nvidia|nvrm|\bXid\b|nouveau|gpu has fallen", re.IGNORECASE)),
    ("canonical-kernel", re.compile(
        r"kernel|oops|panic|BUG:|mce|machine check|edac|nvme|ata[0-9]|ext4|xfs|"
        r"i915|amdgpu|soft lockup|hung task|oom", re.IGNORECASE)),
    ("gnome", re.compile(
        r"gnome-shell|mutter|gdm|tracker|evolution|org\.gnome\.",
        re.IGNORECASE)),
    ("netplan", re.compile(r"netplan", re.IGNORECASE)),
    ("systemd", re.compile(r"systemd|journald|udev|logind|dbus", re.IGNORECASE)),
]

# The crashing process decides ownership. Names are matched against the
# executable basename and the (possibly 15-character-truncated) ``comm``.
PROCESS_VENDOR_RULES = [
    ("gnome", re.compile(
        r"^(?:gnome-shell|gnome-terminal|gnome-software|gnome-control-center|"
        r"gnome-session|gnome-keyring-daemon|nautilus|gjs|mutter|gdm|gdm3|"
        r"evolution|tracker|epiphany)(?:$|-)")),
    ("mozilla", re.compile(r"^(?:firefox|firefox-bin|firefox-esr|crashhelper)$")),
    ("systemd", re.compile(
        r"^(?:systemd|systemd-journald|systemd-logind|systemd-udevd|"
        r"systemd-coredump|journalctl|dbus-daemon|dbus-broker)$")),
]

# A fault inside these modules is the driver vendor's problem, even when the
# process is owned by someone else. Only the *faulting* frame counts; the
# module list of a core contains every library the process ever loaded.
DRIVER_MODULE_RULES = [
    ("nvidia", re.compile(
        r"(?:^|/)(?:libnvidia[-_a-z0-9]*|libGLX_nvidia|libEGL_nvidia|"
        r"libcuda|nvidia|nvrm)(?:\.so.*)?$", re.IGNORECASE)),
]

# Component inference is evidence-first and must never return an empty or
# "unknown" label. The steps are: faulting module project, crashing process,
# event unit, finding rule/subject, then a descriptive last resort.
MODULE_COMPONENTS = (
    (re.compile(r"(?:^|/)libmutter(?:[-.]|$)", re.IGNORECASE), "mutter"),
    (re.compile(r"(?:^|/)libgjs(?:[.-]|$)", re.IGNORECASE), "gjs"),
    # SpiderMonkey inside GJS belongs to the JS bindings, not to Firefox.
    (re.compile(r"(?:^|/)libmozjs(?:[-.]|$)", re.IGNORECASE), "gjs"),
    (re.compile(r"(?:^|/)libcairo(?:[.-]|$)", re.IGNORECASE), "cairo"),
    (re.compile(r"(?:^|/)libgtk-[34](?:[.-]|$)", re.IGNORECASE), "gtk"),
    (re.compile(r"(?:^|/)libx11(?:[.-]|$)", re.IGNORECASE), "xorg-server"),
    (re.compile(r"(?:^|/)libnvidia[-_a-z0-9]*", re.IGNORECASE), "NVIDIA driver"),
    (re.compile(r"(?:^|/)libxul(?:[.-]|$)", re.IGNORECASE), "Firefox"),
)

# Firefox child processes carry a role name, not the browser name.
FIREFOX_PROCESS_COMPONENTS = {
    "isolated web co": "firefox",
    "web content": "firefox",
    "webextensions": "firefox",
    "gpu process": "firefox",
    "rdd process": "firefox",
    "socket thread": "firefox",
    "geckomain": "firefox",
    "crashhelper": "firefox",
}

# Finding subjects that name a scope (a UID, a boot, a session) rather than a
# component; the rule prefix is the component in those cases.
_GENERIC_SUBJECTS = re.compile(
    r"^(?:user@|user$|session-|boot$|init$|io$|irq$|pstore$|lockdown$|"
    r"faultlab|unknown$|n/a$)",
    re.IGNORECASE,
)

# Component labels, most specific first. The process table is consulted after
# the faulting module and before the text table: a crash in gnome-terminal is
# not a gnome-shell crash just because both load libgjs in other paths.
GNOME_PROCESS_COMPONENTS = (
    ("gnome-terminal", "gnome-terminal"),
    ("gnome-software", "gnome-software"),
    ("gnome-control-center", "gnome-control-center"),
    ("nautilus", "nautilus"),
    ("gnome-shell", "gnome-shell"),
    ("mutter", "mutter"),
    ("gjs", "gjs"),
    ("tracker", "tracker-miners"),
    ("evolution", "evolution-data-server"),
    ("gdm", "gdm"),
)

GNOME_TEXT_COMPONENTS = (
    ("libmutter", "mutter"),
    ("mutter", "mutter"),
    ("gnome-shell", "gnome-shell"),
    ("libgjs", "gjs"),
    ("gjs", "gjs"),
    ("tracker", "tracker-miners"),
    ("evolution", "evolution-data-server"),
    ("nautilus", "nautilus"),
)

MOZILLA_COMPONENT_RULES = (
    (re.compile(r"webrender", re.IGNORECASE), "Core :: Graphics: WebRender"),
    (re.compile(r"\bgfx::|gpu process", re.IGNORECASE), "Core :: Graphics"),
    (re.compile(r"\bjs::|JS_GC|spidermonkey", re.IGNORECASE),
     "Core :: JavaScript Engine"),
)
MOZILLA_DEFAULT_COMPONENT = "Firefox :: Untriaged"

VENDOR_META = {
    "mozilla": {
        "name": "Mozilla",
        "channel": "Bugzilla (https://bugzilla.mozilla.org)",
        "component": "Firefox :: Untriaged",
    },
    "nvidia": {
        "name": "NVIDIA",
        "channel": "NVIDIA Linux driver feedback / distributor bug tracker",
        "component": "Proprietary GPU driver",
    },
    "canonical-kernel": {
        "name": "Canonical / Ubuntu kernel",
        "channel": "Launchpad (https://bugs.launchpad.net/ubuntu)",
        "component": "linux (Ubuntu)",
    },
    "gnome": {
        "name": "GNOME",
        "channel": "GNOME GitLab (https://gitlab.gnome.org)",
        "component": "gnome-shell",
    },
    "netplan": {
        "name": "netplan.io",
        "channel": "Launchpad (https://bugs.launchpad.net/ubuntu/+source/netplan.io)",
        "component": "netplan.io",
    },
    "systemd": {
        "name": "systemd",
        "channel": "systemd GitHub issues / distro tracker",
        "component": "systemd",
    },
    "local": {
        "name": "Local / unassigned",
        "channel": "local triage queue",
        "component": "unknown",
    },
    "hardware": {
        "name": "Hardware vendor",
        "channel": "vendor support portal (use the DMI product name)",
        "component": "CPU / platform",
    },
}


def vendor_for(*texts: str) -> str:
    """Pick the most specific owner for a cluster of evidence.

    Content-only fallback. Crashes should use :func:`vendor_for_crash`, which
    anchors on the process and its faulting module first.
    """
    blob = "\n".join(t for t in texts if t)
    for name, pattern in VENDOR_RULES:
        if pattern.search(blob):
            return name
    return "local"


def _process_candidates(comm: str = "", exe: str = "") -> list[str]:
    names: list[str] = []
    base = str(exe or "").strip().rstrip("/").rsplit("/", 1)[-1].lower()
    if base:
        names.append(base)
    process = str(comm or "").strip().lower()
    if process:
        names.append(process)
        # systemd-coredump truncates comm to 15 characters and leaves a
        # trailing dash ("gnome-terminal-").
        if process.endswith("-"):
            names.append(process.rstrip("-"))
    return names


def process_vendor(comm: str = "", exe: str = "") -> str | None:
    """Owner of the crashing process, or ``None`` when it is not a component."""
    for name in _process_candidates(comm, exe):
        for vendor, pattern in PROCESS_VENDOR_RULES:
            if pattern.search(name):
                return vendor
    return None


def module_vendor(module: str = "") -> str | None:
    """Owner of the faulting module when it is a proprietary driver."""
    value = str(module or "").strip()
    if not value:
        return None
    for vendor, pattern in DRIVER_MODULE_RULES:
        if pattern.search(value):
            return vendor
    return None


def vendor_for_crash(comm: str = "", exe: str = "", sig: str = "",
                     context: str = "") -> str:
    """Route a crash by faulting module, process, then the crash header.

    The module dump is never content evidence: it lists every library the
    process loaded, not the one that faulted. Reading it filed Python crashes
    against systemd (``libsystemd``), Electron against systemd (``libdbus``)
    and opencode against NVIDIA (``libnvidia``).
    """
    frame = crash.faulting_frame(context or "")
    module = str((frame or {}).get("module") or "")
    driver = module_vendor(module)
    if driver:
        return driver
    owner = process_vendor(comm, exe)
    if owner:
        return owner
    evidence: list[str] = [comm, exe, sig, crash.identity_text(context or "")]
    if frame:
        evidence += [module, str(frame.get("symbol") or "")]
    return vendor_for(*evidence)


def _clean_component(value: str) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("\\x2d", "-")
    text = text.rstrip("-")
    if text.startswith("app-"):
        text = text[4:]
    return text


def _process_name(comm: str = "", exe: str = "") -> str:
    base = _clean_component(str(exe or "").strip().rstrip("/").rsplit("/", 1)[-1])
    process = _clean_component(comm)
    # ``python3`` + ``/usr/bin/python3.10``: the executable is the precise name.
    if process and base and base.startswith(process) and len(base) > len(process):
        return base
    return process or base


def module_component(module: str = "") -> str:
    """Project named by the faulting module, or an empty string."""
    value = str(module or "")
    if not value or value == "n/a":
        return ""
    for pattern, component in MODULE_COMPONENTS:
        if pattern.search(value):
            return component
    return ""


def _unit_component(unit: str = "") -> str:
    value = _clean_component(unit)
    if not value:
        return ""
    value = value.split("@", 1)[0]
    for suffix in (".service", ".scope", ".slice", ".socket", ".target",
                   ".mount", ".automount", ".path", ".timer", ".device",
                   ".swap"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
            break
    return value.rstrip("-")


def _subject_component(rule: str = "", subject: str = "") -> str:
    value = _clean_component(subject)
    if value.startswith("ident:"):
        value = value.split(":", 1)[1].strip()
    value = re.sub(r"\[\d+\]$", "", value)
    if "@" in value or value.endswith((".service", ".scope", ".slice", ".socket")):
        unit = _unit_component(value)
        if unit and not _GENERIC_SUBJECTS.search(unit):
            return unit
    if value in FIREFOX_PROCESS_COMPONENTS:
        return FIREFOX_PROCESS_COMPONENTS[value]
    if value and not _GENERIC_SUBJECTS.search(value):
        return value
    return _clean_component(re.split(r"[.:]", str(rule or ""), maxsplit=1)[0])


def _evidence_component(module: str = "", comm: str = "", exe: str = "",
                        unit: str = "", rule: str = "", subject: str = "") -> str:
    """Evidence-only component: module, process, unit, rule, then unassigned."""
    component = module_component(module)
    if component:
        return component
    name = _process_name(comm, exe)
    if name in FIREFOX_PROCESS_COMPONENTS:
        return FIREFOX_PROCESS_COMPONENTS[name]
    if name and name not in ("n/a", "unknown"):
        return name
    component = _unit_component(unit)
    if component and not _GENERIC_SUBJECTS.search(component):
        return component
    component = _subject_component(rule, subject)
    if component:
        return component
    return "unassigned"


def component_for(vendor: str, text: str = "", fault_module: str = "",
                  comm: str = "", exe: str = "", unit: str = "",
                  rule: str = "", subject: str = "") -> str:
    """Component label for a ticket title, derived from the evidence.

    Total by construction: every branch returns a label, and ``unassigned`` is
    the last resort instead of the old ``unknown``. Evidence wins for GNOME,
    systemd and local issues. Structured trackers (Mozilla, NVIDIA, kernel,
    netplan, hardware) keep a real tracker component: a wrong route there is a
    routing bug to fix, not a component label to invent.
    """
    blob = str(text or "")
    name = _process_name(comm, exe)
    module_name = module_component(fault_module)
    if vendor == "mozilla":
        for pattern, component in MOZILLA_COMPONENT_RULES:
            if pattern.search(blob):
                return component
        if module_name in ("gtk", "xorg-server"):
            return "Core :: Widget: Gtk"
        if module_name == "cairo":
            return "Core :: Graphics"
        return MOZILLA_DEFAULT_COMPONENT
    if vendor == "gnome":
        if module_name in ("mutter", "gjs"):
            return module_name
        for token, component in GNOME_PROCESS_COMPONENTS:
            if token in name:
                return component
        if module_name in ("cairo", "gtk"):
            return module_name
        lowered = blob.lower()
        for token, component in GNOME_TEXT_COMPONENTS:
            if token in lowered:
                return component
        return "gnome-shell"
    if vendor in ("nvidia", "canonical-kernel", "netplan", "hardware"):
        return VENDOR_META[vendor]["component"]
    # local, systemd and any future free-form owner: evidence first.
    return _evidence_component(
        fault_module, comm, exe, unit, rule, subject)


def crash_component(comm: str = "", exe: str = "", sig: str = "",
                    context: str = "",
                    faultcore_involved: int | None = None) -> tuple[str, str]:
    """Return (vendor, component) for one crash row.

    The component follows the same evidence chain as a ticket: faulting
    module, process, then header content.  A fault-core affinity hit with no
    other owner becomes a hardware issue, while the component still names the
    concrete project (``CPU / platform`` for the hardware tracker).
    """
    vendor = vendor_for_crash(comm, exe, sig, context)
    if faultcore_involved == 1 and vendor == "local":
        vendor = "hardware"
    frame = crash.faulting_frame(context or "")
    module = str((frame or {}).get("module") or "")
    component = component_for(
        vendor, text=context or "", fault_module=module,
        comm=comm, exe=exe, subject=sig,
    )
    return vendor, component


def component_for_issue(issue: dict) -> str:
    """Component for an issue dict, using its first resolvable fault frame."""
    rows = issue.get("rows") or []
    texts: list[str] = []
    fault_module = ""
    comm = ""
    exe = ""
    unit = ""
    rule = ""
    subject = ""
    explicit = ""
    for row in rows:
        if not explicit:
            candidate = str(row.get("component") or "").strip()
            if candidate and candidate not in ("unassigned", "unknown"):
                explicit = candidate
        if not comm:
            comm = str(row.get("comm") or "")
            exe = str(row.get("exe") or "")
        if not unit:
            unit = str(row.get("unit") or "")
        if not rule:
            rule = str(row.get("rule") or "")
            subject = str(row.get("subject") or "")
        texts.append(" ".join(
            str(row.get(key) or "") for key in ("comm", "exe", "sig", "context", "message")
        ))
        if not fault_module:
            frame = crash.faulting_frame(str(row.get("context") or ""))
            if frame and frame.get("module") not in ("", "n/a"):
                fault_module = str(frame["module"])
    if explicit:
        return explicit
    return component_for(
        str(issue.get("vendor") or ""), "\n".join(texts), fault_module,
        comm, exe, unit, rule, subject)


def routing_notes(comm: str = "", exe: str = "", sig: str = "",
                  context: str = "", vendor: str = "") -> list[str]:
    """Why this crash went to this owner, in reviewable bullets."""
    blob = " ".join(str(part or "") for part in (comm, exe, sig, context))
    frame = crash.faulting_frame(context or "")
    evidence = " ".join(str(part or "") for part in (
        comm, exe, sig, crash.identity_text(context or ""),
        (frame or {}).get("module") or "", (frame or {}).get("symbol") or "",
    ))
    notes: list[str] = []
    owner = process_vendor(comm, exe)
    if owner:
        meta = VENDOR_META.get(owner, VENDOR_META["local"])
        notes.append(
            f"Owner rule: crashing process `{comm or exe or 'unknown'}` is a "
            f"{meta['name']} component (process anchor)."
        )
    else:
        for name, pattern in VENDOR_RULES:
            match = pattern.search(evidence)
            if match:
                notes.append(
                    f"Owner rule: no known process anchor; content matched "
                    f"`{name}` on `{match.group(0)[:60]}` (header and faulting "
                    "frame only)."
                )
                break
        else:
            notes.append(
                "Owner rule: no process anchor and no header/frame match; "
                "kept in local triage."
            )
    if vendor != "mozilla" and re.search(r"libmozjs|mozilla::", blob):
        notes.append(
            "Ignored for ownership: `libmozjs`/`mozilla::` is SpiderMonkey, "
            "the JS engine GJS embeds, not Firefox."
        )
    if vendor == "gnome" and re.search(r"webkit|chrome|electron", blob, re.IGNORECASE):
        notes.append(
            "Ignored for ownership: embedded web engines are libraries, not "
            "the crashing desktop component."
        )
    return notes


def vendor_for_finding(rule: str, subject: str = "", detail: str = "") -> str:
    """Route a sentinel finding to the owner expected to act on it."""
    text = " ".join((rule or "", subject or "", detail or ""))
    if rule.startswith("lsm."):
        if rule in ("lsm.state_unreadable", "lsm.state_changed", "lsm.lockdown.none"):
            return "local"
        return "canonical-kernel"
    if rule.startswith("hardware.gpu"):
        return "nvidia"
    if rule == "hardware.apei.pstore":
        # pstore archives kernel panics; a userspace trap in the same record
        # is local. The panic is a kernel defect, not a platform fault.
        if re.search(r"(?i)kernel panic|stack-protector|BUG: unable|Oops:",
                     detail or ""):
            return "canonical-kernel"
        return "local"
    if rule.startswith("hardware."):
        return "hardware"
    return "local"


SIGNATURE_MASKS = [
    # Xorg logs the same input-lag warning with a different latency each time.
    # Normalise the latency so it is one issue, not seven near-duplicates.
    (re.compile(r"(?i)(\blagging behind by\s+)\d+\s*ms\b"), r"\1Nms"),
    (re.compile(r"0x[0-9a-fA-F]+"), "0xADDR"),
    (re.compile(r"\b\d{2,}\b"), "N"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "HEX"),
    (re.compile(r"\b(?:pid|PID)\s*=?\s*\d+"), "PID"),
]


def signature(text: str, limit: int = 160) -> str:
    """Stable-ish signature for grouping recurring events.

    Hex values are masked here only to keep keys and paths stable. Human-facing
    titles, notifications and evidence use the raw message so error codes such
    as ``0x08`` remain searchable.
    """
    value = (text or "").strip().splitlines()[0] if text else ""
    for rx, repl in SIGNATURE_MASKS:
        value = rx.sub(repl, value)
    value = re.sub(r"\s+", " ", value)
    return value[:limit]
