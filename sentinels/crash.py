"""Crash-context parsing shared by classification and ticket drafts.

``systemd-coredump`` writes a header, then a module dump, then the stacks. A
plain prefix of that text is almost entirely module names, so a ticket built
from ``context[:3000]`` shows no frame at all. These helpers keep the facts a
maintainer needs and drop the noise:

* header fields that describe the event (signal, pid, timestamp, executable);
* the crashing thread's stack;
* the frame that actually faulted, skipping the process's own signal handler.

When a process installs a SIGSEGV handler (GNOME Shell does), the reported
frame #0 is the handler calling ``raise()`` and the real fault starts after
``__restore_rt``. Treating frame #0 as the fault is therefore wrong; the
``faulting_frame`` rule is explicit about it.
"""
from __future__ import annotations

import re

_HEADER_KEEP = (
    "size=",
    "PID:",
    "Signal:",
    "Timestamp:",
    "Command Line:",
    "Executable:",
    "Control Group:",
    "Unit:",
)

_FRAME_RE = re.compile(r"^\s*#(?P<index>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+(?P<rest>.+?)\s*$")
_TRAILING_PAREN_RE = re.compile(r"\((?P<inside>[^()]*)\)\s*$")
_THREAD_RE = re.compile(r"^\s*Stack trace of thread (?P<tid>\d+):\s*$")
_MODULE_COUNT_RE = re.compile(r"^\s*Found module ", re.MULTILINE)

_HANDLER_SYMBOLS = ("restore_rt", "sigreturn")


def parse_frame(line: str) -> dict | None:
    """Return one stack frame as a dict, or ``None`` when the line is not one."""
    match = _FRAME_RE.match(line)
    if not match:
        return None
    rest = match.group("rest").strip()
    symbol = rest
    module = ""
    offset = ""
    paren = _TRAILING_PAREN_RE.search(rest)
    if paren:
        symbol = rest[:paren.start()].strip()
        inside = paren.group("inside").strip()
        if " + " in inside:
            module, _, offset = inside.rpartition(" + ")
        else:
            module = inside
    return {
        "index": int(match.group("index")),
        "addr": match.group("addr"),
        "symbol": "" if symbol in ("n/a", "??") else symbol,
        "raw_symbol": symbol,
        "module": module.strip(),
        "offset": offset.strip(),
        # systemd-coredump prints "symbol (module + 0xoff)" whenever it matched
        # the nearest exported symbol instead of a debug-resolved frame.
        "nearest": bool(symbol and symbol not in ("n/a", "??") and offset),
        "display": _display_frame(
            int(match.group("index")),
            "" if symbol in ("n/a", "??") else symbol,
            module.strip(),
            offset.strip(),
        ),
    }


def _display_frame(index: int, symbol: str, module: str, offset: str) -> str:
    """Compact frame text: symbol plus the module that gives it meaning."""
    text = f"#{index} {symbol or 'n/a'}"
    if module and module != "n/a":
        text += f" ({module}{' + ' + offset if offset else ''})"
    elif module:
        text += " (n/a)"
    return text


def thread_frames(context: str) -> tuple[int | None, list[dict]]:
    """Frames of the crashing thread. coredump prints that thread first."""
    frames: list[dict] = []
    thread: int | None = None
    started = False
    for line in (context or "").splitlines():
        match = _THREAD_RE.match(line)
        if match:
            if started:
                break
            started = True
            thread = int(match.group("tid"))
            continue
        if not started:
            continue
        frame = parse_frame(line)
        if frame:
            frames.append(frame)
    return thread, frames


def faulting_frame(context: str) -> dict | None:
    """The frame that faulted, past the process's signal-handler trampoline.

    GNOME Shell, gjs and other runtimes catch SIGSEGV to dump a JS stack and
    then re-raise it. Frames ``#0..#3`` are then ``pthread_kill``/``raise``/
    handler/``__restore_rt``; the fault itself is the first frame after the
    trampoline. When there is no handler, frame #0 is the answer.
    """
    _thread, frames = thread_frames(context)
    for position, frame in enumerate(frames[:-1]):
        lowered = (frame.get("raw_symbol") or frame.get("symbol") or "").lower()
        if any(token in lowered for token in _HANDLER_SYMBOLS):
            fault = dict(frames[position + 1])
            fault["handler"] = True
            fault["handler_frames"] = position + 1
            return fault
    if not frames:
        return None
    fault = dict(frames[0])
    fault["handler"] = False
    fault["handler_frames"] = 0
    return fault


def crash_thread_modules(context: str, limit: int = 8) -> list[str]:
    """Modules referenced by the crashing thread, in call order."""
    seen: list[str] = []
    _thread, frames = thread_frames(context)
    for frame in frames:
        module = frame.get("module") or ""
        if not module or module == "n/a":
            continue
        name = module.rsplit("/", 1)[-1]
        if name not in seen:
            seen.append(name)
        if len(seen) >= limit:
            break
    return seen


def identity_text(context: str, limit: int = 800) -> str:
    """Header lines that identify the process, never the module or frame dump.

    Content classification for a crash must not read the module list: every
    GTK process maps ``libsystemd``, ``libdbus`` and often ``libnvidia``, so a
    Python crash would otherwise be filed against systemd or the GPU driver.
    This returns the coredump header (or the first report line for a minidump)
    and leaves the stack to ``faulting_frame``.
    """
    lines: list[str] = []
    for line in (context or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Found module "):
            continue
        if any(stripped.startswith(prefix) for prefix in _HEADER_KEEP):
            lines.append(stripped)
            continue
        if not lines:
            # Minidumps and application reports start with a description such
            # as "Firefox ESR main-process crash — WebRender scene-builder panic".
            lines.append(stripped)
        if len(lines) >= len(_HEADER_KEEP) + 1:
            break
    return "\n".join(lines)[:limit]


def digest(context: str, limit: int = 4000) -> str:
    """Header plus crashing stack, without the ``Found module`` dump."""
    text = context or ""
    if "Stack trace of thread" not in text and not text.lstrip().startswith("size="):
        # Minidumps and application reports have no coredump structure; keep
        # the text intact rather than returning an empty digest.
        return text[:limit]

    header: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(prefix) for prefix in _HEADER_KEEP):
            header.append(stripped)
        if len(header) >= len(_HEADER_KEEP):
            break

    thread, frames = thread_frames(text)
    parts = list(header)
    if frames:
        parts += ["", f"Stack trace of thread {thread} (crashing thread):"]
        parts += [f["display"] for f in frames[:16]]
        if len(frames) > 16:
            parts.append(f"... {len(frames) - 16} more frames")
    elif text.strip():
        parts += ["", *text.strip().splitlines()[:20]]

    modules = len(_MODULE_COUNT_RE.findall(text))
    if modules:
        parts += ["", f"({modules} module lines omitted; see the attached core dump)"]
    return "\n".join(parts)[:limit]
