"""Raw occurrence context for ticket drafts.

Context is not a second evidence store. It is the window of real lines or
records around the exact occurrence, embedded in the ticket that the operator
already opens. No viewer, side file, or summariser is involved.

A ticket starts with at least ``MIN_CONTEXT_LINES`` of raw source around the
anchor. The window grows in whole ``GROWTH_STEP`` blocks while the boundary
still belongs to the same correlated chain (the enclosing section, fenced
block, boot, unit, or case). There is deliberately no total ticket cap.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

from . import classify, config
from .util import parse_iso, redact, sha256_file, sha256_text

MIN_CONTEXT_LINES = 90
GROWTH_STEP = 90
CORRELATION_GAP_S = 300

# Narrow scope: these findings describe whether the hardware layer could run
# its probes at all. Other hardware findings already carry their own raw data.
HARDWARE_PROBE_RULES = {"hardware.coverage", "hardware.vendor.missing"}
_REPORTED = re.compile(r"\b([a-z][\w-]*)\s*=\s*([\w.-]+)")

_HEADING = re.compile(r"^#{2,6}\s")
_FENCE = re.compile(r"^\s*`{3,}")
_STACK = re.compile(r"^\s*#\d+\s")
_BOOT_ID = re.compile(r"Boot ID:\s*([0-9a-fA-F]+)")


def case_key(kind: str, fingerprint: str) -> str:
    """Stable case key, identical to the key used by triage.py."""
    return sha256_text(f"{kind}|{fingerprint}")[:24]


def _row_kind(row: dict) -> str:
    if row.get("sig"):
        return "crash"
    if row.get("rule") and row.get("subject"):
        return "finding"
    if row.get("message"):
        return "event"
    return ""


def _row_signature(row: dict) -> str:
    if row.get("sig"):
        name = row.get("comm") or Path(str(row.get("exe") or "")).name
        return f"{name} {row['sig']}".strip()
    if row.get("rule") and row.get("subject"):
        return f"{row['rule']}: {row['subject']}"
    message = str(row.get("message") or "").splitlines()
    return message[0][:160] if message else ""


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(config.ROOT.resolve()))
    except (OSError, ValueError):
        return str(path)


def _bundle_dir(bundle: dict | None) -> Path | None:
    """Resolve a bundle path, including manifests whose home is redacted."""
    if not bundle:
        return None
    raw = str(bundle.get("path") or "")
    if not raw:
        return None
    candidates = []
    direct = Path(raw)
    if direct.is_absolute():
        candidates.append(direct)
    candidates.append(config.EVIDENCE_DIR / direct.name)
    allowed = config.EVIDENCE_DIR.resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(allowed)
        except (OSError, ValueError):
            continue
        if resolved.is_dir():
            return resolved
    return None


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _digest(path: Path | None) -> str:
    if path is None or not path.is_file():
        return "-"
    try:
        return sha256_file(path)
    except OSError:
        return "-"


def _anchor_index(lines: list[str], tokens: list[str]) -> int | None:
    """Pick the line nearest the fault, preferring a stack frame."""
    best = None
    best_score = 0
    wanted = [token.lower() for token in tokens if token]
    for index, line in enumerate(lines):
        low = line.lower()
        score = 0
        if _STACK.match(line) or "stack trace" in low:
            score = 6
        elif "signal:" in low:
            score = 5
        elif "general protection" in low or "segmentation fault" in low:
            score = 5
        elif any(token in low for token in wanted):
            score = 4
        elif "event time" in low or "timestamp:" in low:
            score = 3
        if score > best_score:
            best_score = score
            best = index
    return best


def _section_bounds(lines: list[str], anchor: int) -> tuple[int, int]:
    start = 0
    for index in range(anchor, -1, -1):
        if _HEADING.match(lines[index]):
            start = index
            break
    end = len(lines)
    for index in range(anchor + 1, len(lines)):
        if _HEADING.match(lines[index]):
            end = index
            break
    return start, end


def _fence_bounds(lines: list[str], anchor: int) -> tuple[int | None, int | None]:
    start = None
    for index in range(anchor, -1, -1):
        if _FENCE.match(lines[index]):
            start = index
            break
    end = None
    for index in range(anchor + 1, len(lines)):
        if _FENCE.match(lines[index]):
            end = index + 1
            break
    return start, end


def _same_section(lines: list[str], index: int, anchor: int) -> bool:
    start, end = _section_bounds(lines, anchor)
    return start <= index < end


def _text_window(text: str, tokens: list[str]) -> tuple[list[str], int, int, int] | None:
    """Return raw lines around the anchor, with the correlated chain expanded."""
    lines = text.splitlines()
    if not lines:
        return None
    anchor = _anchor_index(lines, tokens)
    if anchor is None:
        return None
    start = max(0, anchor - MIN_CONTEXT_LINES)
    end = min(len(lines), anchor + MIN_CONTEXT_LINES + 1)
    section_start, section_end = _section_bounds(lines, anchor)
    start = min(start, section_start)
    end = max(end, section_end)
    fence_start, fence_end = _fence_bounds(lines, anchor)
    if fence_start is not None:
        start = min(start, fence_start)
    if fence_end is not None:
        end = max(end, fence_end)
    # Grow while the boundary is still in the same correlated section.
    while start > 0 and _same_section(lines, start - 1, anchor):
        new_start = max(0, start - GROWTH_STEP)
        if new_start == start:
            break
        start = new_start
    while end < len(lines) and _same_section(lines, end, anchor):
        new_end = min(len(lines), end + GROWTH_STEP)
        if new_end == end:
            break
        end = new_end
    return lines, start, end, anchor


def _fence(text: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _render_text_source(
    label: str,
    path: Path,
    text: str,
    tokens: list[str],
    extra: str = "",
) -> list[str]:
    window = _text_window(text, tokens)
    if window is None:
        return []
    lines, start, end, _anchor = window
    source = redact(_display_path(path))
    digest = _digest(path) if path.is_file() else sha256_text(text)
    shown = lines[start:end]
    body = "\n".join(
        f"{number:>6} | {redact(line)}" for number, line in enumerate(shown, start=start + 1)
    )
    note = f"{len(shown)} line(s)"
    if len(shown) < MIN_CONTEXT_LINES:
        note += f"; source has only {len(lines)} line(s)"
    if extra:
        note = f"{extra}; {note}"
    fence = _fence(body)
    return [
        f"#### {label}",
        f"Source: `{source}` lines {start + 1}–{end} ({note}; sha256 `{digest}`)",
        "",
        fence,
        body,
        fence,
        "",
    ]


def _case_for_row(row: dict, cases: list[dict]) -> dict | None:
    fingerprint = str(row.get("fingerprint") or "")
    kind = _row_kind(row)
    key = case_key(kind, fingerprint) if fingerprint and kind else ""
    if key:
        for case in cases:
            if case.get("case_key") == key:
                return case
    if row.get("case_id"):
        for case in cases:
            if str(case.get("id")) == str(row["case_id"]):
                return case
    stamp = str(row.get("ts") or "")
    signature = _row_signature(row)
    process = str(row.get("comm") or row.get("exe") or "")
    for case in cases:
        if str(case.get("event_ts") or "") != stamp:
            continue
        if signature and str(case.get("signature") or "") == signature:
            return case
        if process and (case.get("process") == process or str(case.get("process") or "").endswith(process)):
            return case
    try:
        anchor = parse_iso(stamp)
    except Exception:  # noqa: BLE001 - a bad timestamp must not hide a case
        return None
    for case in cases:
        try:
            event = parse_iso(str(case.get("event_ts") or ""))
        except Exception:  # noqa: BLE001
            continue
        if abs((event - anchor).total_seconds()) <= 2:
            if not signature or signature == str(case.get("signature") or ""):
                return case
    return None


def _live_cases(conn, issue: dict) -> list[dict]:
    if conn is None:
        return []
    found: list[dict] = []
    for row in issue.get("rows") or []:
        key = case_key(_row_kind(row), str(row.get("fingerprint") or ""))
        try:
            rec = conn.execute(
                "SELECT * FROM faultcore_cases WHERE case_key=? OR id=?",
                (key, row.get("case_id")),
            ).fetchone()
        except Exception:  # noqa: BLE001 - an old database may lack the table
            rec = None
        if rec:
            found.append(dict(rec))
    return found


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _live_case_path(case: dict) -> Path | None:
    try:
        case_id = int(case.get("id"))
    except (TypeError, ValueError):
        return None
    direct = config.TRIAGE_DIR / f"case-{case_id:04d}.md"
    if direct.is_file() and _within(direct, config.TRIAGE_DIR.parent):
        return direct
    name = Path(str(case.get("path") or "")).name
    if name:
        for candidate in (config.TRIAGE_DIR, config.TRIAGE_DIR.parent):
            for path in candidate.rglob(name):
                if path.is_file() and _within(path, config.TRIAGE_DIR.parent):
                    return path
    return None


def _triage_sources(issue: dict, bundle_dir: Path | None, conn) -> tuple[list[dict], list[dict]]:
    cases: list[dict] = []
    if bundle_dir:
        data = _load_json(bundle_dir / "triage-cases.json")
        if isinstance(data, list):
            cases.extend(item for item in data if isinstance(item, dict))
    matches: list[dict] = []
    seen = set()
    for row in issue.get("rows") or []:
        case = _case_for_row(row, cases)
        if not case:
            continue
        ident = case.get("case_key") or case.get("id")
        if ident in seen:
            continue
        seen.add(ident)
        matches.append(case)
    if not matches:
        for case in _live_cases(conn, issue):
            ident = case.get("case_key") or case.get("id")
            if ident in seen:
                continue
            seen.add(ident)
            matches.append(case)
    return matches, cases


def _tokens(issue: dict, row: dict | None = None) -> list[str]:
    row = row or {}
    message = str(row.get("message") or "").splitlines()
    values = [
        str(issue.get("signature") or ""),
        str(issue.get("display") or ""),
        str(row.get("fingerprint") or ""),
        str(row.get("ts") or ""),
        str(row.get("comm") or ""),
        str(row.get("sig") or ""),
        str(row.get("rule") or ""),
        str(row.get("subject") or ""),
        str(row.get("detail") or ""),
        message[0][:160] if message else "",
    ]
    return [value for value in values if value]


def _case_context(case: dict, issue: dict, bundle_dir: Path | None) -> list[str]:
    lines: list[str] = []
    try:
        case_id = int(case.get("id"))
    except (TypeError, ValueError):
        return lines
    row = next(
        (item for item in issue.get("rows") or []
         if _case_for_row(item, [case]) is not None),
        None,
    )
    tokens = _tokens(issue, row)
    snapshot = bundle_dir / f"triage-case-{case_id:04d}.md" if bundle_dir else None
    live = _live_case_path(case)
    if snapshot and snapshot.is_file():
        text = _read_text(snapshot)
        if text:
            lines += _render_text_source(
                f"Triage case {case_id} — bundle snapshot", snapshot, text, tokens,
                extra=f"case key `{case.get('case_key') or '-'}`",
            )
    if live and live.is_file():
        text = _read_text(live)
        if text:
            lines += _render_text_source(
                f"Triage case {case_id} — current", live, text, tokens,
                extra=f"case key `{case.get('case_key') or '-'}`",
            )
    return lines


def _structured_rows(bundle_dir: Path | None, name: str) -> list[dict]:
    if not bundle_dir:
        return []
    data = _load_json(bundle_dir / name)
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _crash_context(issue: dict, bundle_dir: Path | None) -> list[str]:
    bundle_rows = _structured_rows(bundle_dir, "crashes.json")
    rows: list[tuple[dict, Path | None]] = [(row, bundle_dir / "crashes.json"
                                             if bundle_dir else None)
                                            for row in bundle_rows]
    known = {row.get("fingerprint") for row in bundle_rows}
    for row in issue.get("rows") or []:
        if row.get("sig") and row.get("fingerprint") not in known:
            rows.append((row, None))
    wanted = {item.get("fingerprint") for item in issue.get("rows") or []}
    lines: list[str] = []
    seen = set()
    for row, path in rows:
        fingerprint = row.get("fingerprint")
        if fingerprint not in wanted:
            continue
        ident = fingerprint or row.get("id")
        if ident in seen:
            continue
        seen.add(ident)
        text = str(row.get("context") or "")
        if not text:
            continue
        label = f"Crash row {row.get('id', '?')} — {_row_signature(row)}"
        # crashes.json is a record set: render the context as a text source
        # but label the record so the reader can find the exact row.
        window = _text_window(text, _tokens(issue, row))
        if window is None:
            continue
        source_lines, start, end, _anchor = window
        body = "\n".join(
            f"{number:>6} | {redact(line)}"
            for number, line in enumerate(source_lines[start:end], start=start + 1)
        )
        fence = _fence(body)
        source = (_display_path(path) if path else "ticket evidence/logs.json")
        digest = _digest(path) if path else sha256_text(text)
        lines += [
            f"#### {label}",
            f"Source: `{source}` row `{row.get('id', '?')}` "
            f"context lines {start + 1}–{end} (sha256 `{digest}`)",
            "",
            fence,
            body,
            fence,
            "",
        ]
    return lines


def _finding_context(issue: dict, bundle_dir: Path | None) -> list[str]:
    bundle_rows = _structured_rows(bundle_dir, "findings.json")
    rows: list[tuple[dict, Path | None]] = [(row, bundle_dir / "findings.json"
                                             if bundle_dir else None)
                                            for row in bundle_rows]
    known = {row.get("fingerprint") for row in bundle_rows}
    for row in issue.get("rows") or []:
        if row.get("rule") and row.get("fingerprint") not in known:
            rows.append((row, None))
    wanted = {item.get("fingerprint") for item in issue.get("rows") or []}
    lines: list[str] = []
    for row, path in rows:
        if row.get("fingerprint") not in wanted:
            continue
        text = str(row.get("detail") or "")
        if not text:
            continue
        window = _text_window(text, _tokens(issue, row))
        if window is None:
            raw = text.splitlines() or [text]
            window = (raw, 0, len(raw), 0)
        source_lines, start, end, _anchor = window
        body = "\n".join(
            f"{number:>6} | {redact(line)}"
            for number, line in enumerate(source_lines[start:end], start=start + 1)
        )
        fence = _fence(body)
        source = _display_path(path) if path else "ticket evidence/logs.json"
        digest = _digest(path) if path else sha256_text(text)
        lines += [
            f"#### Finding {row.get('id', '?')} — {row.get('rule', '')}",
            f"Source: `{source}` row `{row.get('id', '?')}` "
            f"detail lines {start + 1}–{end} (sha256 `{digest}`)",
            "",
            fence,
            body,
            fence,
            "",
        ]
    return lines


def _record_lines(record: dict) -> list[str]:
    stamp = str(record.get("ts") or record.get("last_ts") or "")
    severity = str(record.get("severity") or "")
    unit = str(record.get("unit") or record.get("comm") or record.get("source") or "")
    message = str(record.get("message") or "")
    return [f"{stamp} [{severity}] {unit}".rstrip(), *message.splitlines()]


def _record_correlated(anchor: dict, other: dict) -> bool:
    if not anchor or not other:
        return False
    if anchor.get("boot_id") and other.get("boot_id") != anchor.get("boot_id"):
        return False
    if anchor.get("boot_id") and other.get("boot_id") == anchor.get("boot_id"):
        if anchor.get("fingerprint") and other.get("fingerprint") == anchor.get("fingerprint"):
            return True
        if anchor.get("unit") and other.get("unit") == anchor.get("unit"):
            return True
        if anchor.get("comm") and other.get("comm") == anchor.get("comm"):
            return True
        try:
            delta = abs((parse_iso(str(anchor.get("ts") or "")) -
                         parse_iso(str(other.get("ts") or ""))).total_seconds())
        except Exception:  # noqa: BLE001
            return False
        return delta <= CORRELATION_GAP_S
    return False


def _issue_boots(issue: dict) -> tuple[set[str], list[datetime]]:
    boots: set[str] = set()
    times: list[datetime] = []
    for row in issue.get("rows") or []:
        if row.get("boot_id"):
            boots.add(str(row["boot_id"]))
        for value in (row.get("context"), row.get("message")):
            for match in _BOOT_ID.finditer(str(value or "")):
                boots.add(match.group(1))
        for key in ("ts", "first", "last"):
            try:
                times.append(parse_iso(str(row.get(key) or "")))
            except Exception:  # noqa: BLE001
                pass
    return boots, times


def _signature_matches(issue: dict, message: str) -> bool:
    text = str(message or "").strip()
    if not text:
        return False
    signature = str(issue.get("signature") or "")
    display = str(issue.get("display") or "")
    if signature and classify.signature(text) == signature:
        return True
    if display and display.lower() in text.lower():
        return True
    # ata7.N in the cluster key is ata7.00 in the journal.
    prefix = signature.split(":")[0]
    if prefix.endswith(".N"):
        prefix = prefix[:-2] + "."
    return bool(prefix) and text.lower().startswith(prefix.lower())


def _correlation_windows(conn, issue: dict) -> list[dict]:
    if conn is None:
        return []
    signature = str(issue.get("signature") or "")
    display = str(issue.get("display") or "")
    if not signature and not display:
        return []
    try:
        rows = conn.execute(
            "SELECT boot_id, signature, display, window_start, window_end"
            " FROM correlations WHERE signature=? OR display=?"
            " OR signature LIKE ? OR display LIKE ?"
            " ORDER BY window_start",
            (signature, display, f"%{signature}%", f"%{display}%"),
        ).fetchall()
    except Exception:  # noqa: BLE001 - an old database may lack correlations
        return []
    found = []
    seen = set()
    for row in rows:
        item = dict(row)
        key = (item.get("boot_id"), item.get("window_start"), item.get("window_end"))
        if key in seen:
            continue
        seen.add(key)
        found.append(item)
    return found


def _db_event_rows(conn, issue: dict) -> list[dict]:
    if conn is None:
        return []
    windows = _correlation_windows(conn, issue)
    rows: list[dict] = []
    seen: set = set()
    for window in windows:
        try:
            selected = conn.execute(
                "SELECT * FROM events WHERE boot_id=?"
                " AND ts>=? AND ts<=? ORDER BY ts",
                (window.get("boot_id"), window.get("window_start"),
                 window.get("window_end")),
            ).fetchall()
        except Exception:  # noqa: BLE001
            selected = []
        for record in selected:
            item = dict(record)
            key = item.get("id") or (item.get("fingerprint"), item.get("ts"))
            if key in seen:
                continue
            seen.add(key)
            rows.append(item)
    if rows:
        return rows
    boots, times = _issue_boots(issue)
    if boots:
        placeholders = ",".join("?" for _ in boots)
        try:
            selected = conn.execute(
                f"SELECT * FROM events WHERE boot_id IN ({placeholders}) ORDER BY ts",
                tuple(boots),
            ).fetchall()
            return [dict(item) for item in selected]
        except Exception:  # noqa: BLE001
            return []
    for when in times:
        start = when.replace(microsecond=0)
        try:
            selected = conn.execute(
                "SELECT * FROM events WHERE ts BETWEEN ? AND ? ORDER BY ts",
                (start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 (start.replace(second=0) + timedelta(hours=1)).strftime(
                     "%Y-%m-%dT%H:%M:%SZ")),
            ).fetchall()
        except Exception:  # noqa: BLE001
            selected = []
        if selected:
            return [dict(item) for item in selected]
    return []


def _event_anchors(rows: list[dict], issue: dict) -> list[int]:
    wanted = {item.get("fingerprint") for item in issue.get("rows") or []}
    boots, times = _issue_boots(issue)
    direct: list[int] = []
    for index, row in enumerate(rows):
        if row.get("fingerprint") in wanted:
            direct.append(index)
    if direct:
        return direct
    matched: list[int] = []
    for index, row in enumerate(rows):
        if _signature_matches(issue, str(row.get("message") or "")):
            matched.append(index)
    if matched:
        return matched
    anchors: list[int] = []
    for when in times:
        best = None
        best_delta = None
        for index, row in enumerate(rows):
            if boots and row.get("boot_id") not in boots:
                continue
            try:
                event = parse_iso(str(row.get("ts") or ""))
            except Exception:  # noqa: BLE001
                continue
            delta = abs((event - when).total_seconds())
            if delta > 3600:
                continue
            if best_delta is None or delta < best_delta:
                best = index
                best_delta = delta
        if best is not None:
            anchors.append(best)
    return anchors


def _event_context(issue: dict, bundle_dir: Path | None, conn) -> list[str]:
    rows: list[dict] = []
    anchors: list[int] = []
    from_bundle = False
    # A correlation ticket names the boots and windows that made it a
    # correlation. Use those rows instead of a newer startup bundle that may
    # contain the same kernel message on a later boot.
    if issue.get("kind") == "correlation" and conn is not None:
        rows = _db_event_rows(conn, issue)
        anchors = _event_anchors(rows, issue) if rows else []
    if not anchors:
        rows = _structured_rows(bundle_dir, "events.json")
        from_bundle = bool(rows)
        anchors = _event_anchors(rows, issue) if rows else []
    if not anchors and conn is not None:
        database_rows = _db_event_rows(conn, issue)
        if database_rows:
            rows = database_rows
            from_bundle = False
            anchors = _event_anchors(rows, issue)
    if not rows or not anchors:
        return []
    rows.sort(key=lambda item: (str(item.get("ts") or ""), int(item.get("id") or 0)))
    # Recompute after sorting so the anchors point at the sorted records.
    anchors = _event_anchors(rows, issue)
    if not anchors:
        return []
    line_counts = [len(_record_lines(item)) for item in rows]
    ranges: list[tuple[int, int]] = []
    for anchor_index in anchors:
        anchor = rows[anchor_index]
        start = anchor_index
        count = line_counts[anchor_index]
        while start > 0:
            previous = start - 1
            if count >= MIN_CONTEXT_LINES and not _record_correlated(anchor, rows[previous]):
                break
            start = previous
            count += line_counts[previous]
        end = anchor_index
        count = line_counts[anchor_index]
        while end + 1 < len(rows):
            following = end + 1
            if count >= MIN_CONTEXT_LINES and not _record_correlated(anchor, rows[following]):
                break
            end = following
            count += line_counts[following]
        ranges.append((start, end))
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    path = bundle_dir / "events.json" if from_bundle and bundle_dir else None
    windows = _correlation_windows(conn, issue) if conn and not path else []
    window_text = ", ".join(
        f"`{str(item.get('boot_id') or '')[:8]}` "
        f"{item.get('window_start')}–{item.get('window_end')}"
        for item in windows
    )
    lines: list[str] = []
    for start, end in merged:
        selected = rows[start:end + 1]
        body_lines: list[str] = []
        for record in selected:
            body_lines.extend(_record_lines(record))
            body_lines.append("")
        body = "\n".join(redact(line) for line in body_lines)
        fence = _fence(body)
        note = f"{len(selected)} record(s), {len(body_lines)} line(s)"
        if path:
            source = f"`{_display_path(path)}`"
            digest = _digest(path)
        else:
            source = "`live database:events`"
            digest = "-"
            if window_text:
                note += f"; correlation windows {window_text}"
        lines += [
            "#### Journal / event chain",
            f"Source: {source} records {start + 1}–{end + 1} "
            f"({note}; sha256 `{digest}`)",
            "",
            fence,
            body,
            fence,
            "",
        ]
    return lines


def _hardware_probe_issue(issue: dict) -> bool:
    """True only for findings that report whether hardware probes could run."""
    for row in issue.get("rows") or []:
        rule = str(row.get("rule") or "")
        if rule in HARDWARE_PROBE_RULES:
            return True
    signature = str(issue.get("signature") or "").lower()
    return signature.startswith("hardware.coverage") or signature.startswith(
        "hardware.vendor.missing")


def _reported_limits(issue: dict) -> dict[str, str]:
    limits: dict[str, str] = {}
    for row in issue.get("rows") or []:
        text = " ".join(
            str(row.get(key) or "") for key in ("detail", "message")
        )
        for match in _REPORTED.finditer(text):
            limits[match.group(1)] = match.group(2)
    return limits


def _parse_sources(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    if not value:
        return {}
    try:
        data = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(item) for key, item in data.items()}


def _hardware_runs(issue: dict, bundle_dir: Path | None, conn) -> list[dict]:
    runs: list[dict] = []
    if bundle_dir:
        data = _load_json(bundle_dir / "hardware.json")
        if isinstance(data, dict) and isinstance(data.get("run"), dict):
            run = dict(data["run"])
            run["_source"] = "bundle"
            run["_path"] = bundle_dir / "hardware.json"
            runs.append(run)
    if conn is not None:
        try:
            rows = conn.execute(
                "SELECT * FROM hardware_runs ORDER BY id DESC LIMIT 48"
            ).fetchall()
        except Exception:  # noqa: BLE001 - an old database may lack hardware_runs
            rows = []
        for record in rows:
            run = dict(record)
            run["_source"] = "database"
            run["_path"] = None
            runs.append(run)
    seen: set = set()
    unique: list[dict] = []
    for run in runs:
        key = (run.get("id"), run.get("ts"))
        if key in seen:
            continue
        seen.add(key)
        run["_sources"] = _parse_sources(run.get("sources"))
        unique.append(run)
    unique.sort(
        key=lambda run: (str(run.get("ts") or ""), int(run.get("id") or 0)),
        reverse=True,
    )
    return unique


def _hardware_detail_window(text: str, tokens: list[str]):
    lines = text.splitlines()
    if not lines:
        return None
    anchor = _anchor_index(lines, tokens)
    if anchor is None:
        return None
    start = max(0, anchor - MIN_CONTEXT_LINES)
    end = min(len(lines), anchor + MIN_CONTEXT_LINES + 1)
    section_start = 0
    for index in range(anchor, -1, -1):
        if lines[index].startswith("# ") and not lines[index].startswith("## "):
            section_start = index
            break
    section_end = len(lines)
    for index in range(anchor + 1, len(lines)):
        if lines[index].startswith("# ") and not lines[index].startswith("## "):
            section_end = index
            break
    return lines, min(start, section_start), max(end, section_end)


def _hardware_context(issue: dict, bundle_dir: Path | None, conn) -> list[str]:
    reported = _reported_limits(issue)
    runs = _hardware_runs(issue, bundle_dir, conn)
    if reported:
        matched = [
            run for run in runs
            if all(run["_sources"].get(key) == value
                   for key, value in reported.items())
        ]
    else:
        matched = runs[:1]
    if not matched:
        return []
    limits_text = ", ".join(
        f"`{key}={value}`" for key, value in sorted(reported.items())
    ) or "none recorded"
    lines: list[str] = []
    for run in matched[:2]:
        run_id = run.get("id", "?")
        status = run.get("status") or "unknown"
        stamp = run.get("ts") or "unknown"
        sources = run["_sources"]
        source_text = ", ".join(
            f"`{key}={value}`" for key, value in sorted(sources.items())
        ) or "none recorded"
        if run.get("_source") == "bundle":
            path = run.get("_path")
            source = f"`{_display_path(path)}` run `{run_id}`"
            digest = _digest(path)
        else:
            source = f"`live database:hardware_runs` run `{run_id}`"
            digest = "-"
        lines += [
            f"#### Hardware probe run {run_id} — {status}",
            f"Source: {source} at `{stamp}` (sha256 `{digest}`)",
            f"Reported limitation: {limits_text}",
            f"Run sources: {source_text}",
            "",
        ]
        detail = str(run.get("detail") or "")
        window = _hardware_detail_window(
            detail, ["Permission denied", "smartctl", "needs-root", "storage"])
        if window is None:
            continue
        window_lines, start, end = window
        body = "\n".join(
            f"{number:>6} | {redact(line)}"
            for number, line in enumerate(window_lines[start:end], start=start + 1)
        )
        fence = _fence(body)
        lines += [fence, body, fence, ""]
    return lines


def embed_context(text: str, context_lines: list[str]) -> str:
    """Insert or replace the occurrence block without duplicating it."""
    if not context_lines:
        return text
    block = "### Occurrence context\n\n" + "\n".join(context_lines).rstrip() + "\n\n"
    pattern = re.compile(r"(?ms)^### Occurrence context\n.*?(?=^## |\Z)")
    if pattern.search(text):
        return pattern.sub(lambda _match: block, text, count=1)
    marker = "\n## Requested action"
    if marker in text:
        return text.replace(marker, "\n" + block + "## Requested action", 1)
    return text.rstrip() + "\n\n" + block


def ticket_context(issue: dict, bundle: dict | None, conn=None) -> list[str]:
    """Return raw occurrence context for the ticket's Evidence section.

    The result is Markdown, already redacted. It intentionally does not
    summarise trace files: the source lines are embedded as they are.
    """
    bundle_dir = _bundle_dir(bundle)
    cases, _all_cases = _triage_sources(issue, bundle_dir, conn)
    lines: list[str] = []
    for case in cases:
        lines += _case_context(case, issue, bundle_dir)
    lines += _crash_context(issue, bundle_dir)
    lines += _finding_context(issue, bundle_dir)
    if _hardware_probe_issue(issue):
        lines += _hardware_context(issue, bundle_dir, conn)
    lines += _event_context(issue, bundle_dir, conn)
    if not lines:
        return [
            "No occurrence context found in the attached bundle or triage files.",
            f"Searched bundle `{_display_path(bundle_dir) if bundle_dir else '(none)'}` "
            "for the ticket fingerprint, case key and event time.",
            "",
        ]
    return lines
