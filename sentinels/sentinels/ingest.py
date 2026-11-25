"""Ingest warnings, errors, kernel messages and crashes into SQLite."""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone

from . import classify, config, db, shutdown
from .util import iso, parse_iso, run, sha256_text, utcnow


# ---------------------------------------------------------------- journal
def _journal_args(after: str | None) -> list[str]:
    args = ["journalctl", "--no-pager", "-o", "json", "-p", config.JOURNAL_PRIORITY]
    if after:
        args.append(f"--after-cursor={after}")
    else:
        args += ["--since=-2h"]
    return args


def _message(entry: dict) -> str:
    msg = entry.get("MESSAGE", "")
    if isinstance(msg, list):
        try:
            msg = bytes(msg).decode("utf-8", "replace")
        except Exception:
            msg = str(msg)
    if not msg:
        return ""
    return str(msg).replace("\x00", "")


def ingest_journal(conn) -> int:
    """Pull journal entries at the configured priority since the stored cursor."""
    free = shutil.disk_usage(str(config.VAR)).free
    if free < config.MIN_FREE_MIB * 1024 * 1024:
        raise RuntimeError(
            f"refusing to ingest: only {free / 1024**3:.2f} GiB free "
            f"(QA_MIN_FREE_MIB={config.MIN_FREE_MIB})"
        )
    cursor = db.meta_get(conn, "journal_cursor")
    rc, out, err = run(_journal_args(cursor), timeout=60)
    if rc != 0:
        raise RuntimeError(f"journalctl rc={rc}: {err.strip()[:400]}")

    added = 0
    last_cursor = cursor
    entries = 0
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries += 1
        last_cursor = entry.get("__CURSOR") or last_cursor
        realtime = entry.get("__REALTIME_TIMESTAMP")
        try:
            ts = datetime.fromtimestamp(int(realtime) / 1_000_000, tz=timezone.utc)
            ts_s = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            ts_s = iso()

        unit = entry.get("_SYSTEMD_UNIT") or ""
        if not unit and entry.get("SYSLOG_IDENTIFIER"):
            unit = f"ident:{entry['SYSLOG_IDENTIFIER']}"
        prio = entry.get("PRIORITY")
        try:
            prio = int(prio)
        except (TypeError, ValueError):
            prio = None
        msg = _message(entry)
        sev = classify.classify(msg, prio)
        if sev == "noise":
            continue
        pid = entry.get("_PID")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = None
        source = "kernel" if not entry.get("_SYSTEMD_UNIT") and (
            entry.get("_TRANSPORT") == "kernel" or entry.get("SYSLOG_IDENTIFIER") == "kernel"
        ) else "journal"
        sig = classify.signature(msg, 200)
        bucket = ts_s[:14] + f"{int(ts_s[14:16]) - int(ts_s[14:16]) % 5:02d}"
        fp = sha256_text(f"{source}|{unit}|{sig}|{bucket}")[:40]

        cur = conn.execute(
            "INSERT INTO events"
            "(ts,boot_id,source,severity,unit,pid,comm,message,fingerprint,raw,count,last_ts)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,1,?)"
            " ON CONFLICT(fingerprint) DO UPDATE SET"
            " count=count+1, last_ts=excluded.last_ts",
            (
                ts_s,
                entry.get("_BOOT_ID"),
                source,
                sev,
                unit,
                pid,
                entry.get("_COMM"),
                msg,
                fp,
                json.dumps(entry, default=str),
                ts_s,
            ),
        )
        added += cur.rowcount

    if last_cursor:
        db.meta_set(conn, "journal_cursor", last_cursor)
    db.meta_set(conn, "last_journal_ingest", iso())
    return added


# ---------------------------------------------------------------- crashes
_LIST_RE = re.compile(
    r"^\S+\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(\S+)\s*$"
)


def parse_cpu_list(spec: str | None) -> set[int] | None:
    """Parse a kernel cpulist ('0-3,8') into ints. None = unknown."""
    if not spec:
        return None
    spec = spec.strip()
    if not spec or spec in ("-", "n/a"):
        return None
    cpus: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                cpus.update(range(int(lo), int(hi) + 1))
            except ValueError:
                return None
        else:
            try:
                cpus.add(int(part))
            except ValueError:
                return None
    return cpus or None


def faultcore_verdict(mask: set[int] | None) -> int | None:
    if mask is None or not config.FAULT_CORE_CPUS:
        return None
    if not any(c in mask for c in config.FAULT_CORE_CPUS):
        return 0
    # An unpinned process allows every CPU by construction. That default mask
    # is not evidence that the process ran on the fault core; only a narrower
    # affinity (or a kernel event that names the CPU) is.
    online = os.cpu_count() or 0
    if online and len(mask) >= online:
        return 0
    return 1


def _nearest_proc(conn, pid: int, ts: str, exe: str = "") -> dict | None:
    """Process snapshot for a crash PID, with provenance checks.

    A bare ``PID`` match is not identity: PIDs are reused, and the nearest
    sample can be days old. Returning that row attributes a stale affinity
    mask and even a different process name to the crash. Only a recent sample
    that names the same executable may supply affinity or fault-core verdict.
    """
    try:
        anchor = parse_iso(ts)
        lower = iso(anchor - timedelta(seconds=config.PROC_MATCH_WINDOW_S))
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT * FROM proc_snap WHERE pid=? AND ts<=? AND ts>=?"
        " ORDER BY ts DESC LIMIT 1",
        (pid, ts, lower),
    ).fetchone()
    if not row:
        return None
    sample = dict(row)
    if exe:
        want = os.path.basename(exe.rstrip("/"))
        got = os.path.basename(str(sample.get("exe") or "").rstrip("/"))
        if not got or got != want:
            return None
    return sample


def _journal_context(epoch: float, window: int = 45, lines: int = 120) -> str:
    since = datetime.fromtimestamp(epoch - window, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    until = datetime.fromtimestamp(epoch + window, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rc, out, _ = run(
        ["journalctl", "--no-pager", "-o", "short-iso", "--since", since,
         "--until", until, "-n", str(lines)],
        timeout=30,
    )
    return out if rc == 0 else ""


def ingest_coredumps(conn, days: int = 30) -> int:
    rc, out, err = run(
        ["coredumpctl", "list", "--no-pager", f"--since=-{days}days"], timeout=45
    )
    if rc != 0:
        # coredumpctl is absent or has no permission; minidumps still count
        return 0

    added = 0
    for line in out.splitlines()[1:]:
        m = _LIST_RE.match(line)
        if not m:
            continue
        local_ts, pid, _uid, _gid, sig, corefile, exe, size = m.groups()
        try:
            dt = datetime.strptime(local_ts, "%Y-%m-%d %H:%M:%S").astimezone()
            dt = dt.astimezone(timezone.utc)
        except ValueError:
            continue
        ts_s = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        pid = int(pid)
        fp = sha256_text(f"coredump|{ts_s}|{pid}|{sig}|{exe}")[:40]
        if conn.execute("SELECT 1 FROM crashes WHERE fingerprint=?", (fp,)).fetchone():
            continue

        proc = _nearest_proc(conn, pid, ts_s, exe=exe)
        mask = parse_cpu_list(proc.get("cpus_allowed") if proc else None)
        verdict = faultcore_verdict(mask)

        info_rc, info_out, _ = run(
            ["coredumpctl", "info", str(pid), "--no-pager"], timeout=45
        )
        info = info_out if info_rc == 0 else ""
        context = _journal_context(dt.timestamp())
        full_context = f"size={size}\n" + info + "\n--- journal context ---\n" + context
        component = classify.crash_component(
            proc.get("comm") if proc else "",
            exe,
            sig,
            full_context,
            verdict,
        )[1]

        conn.execute(
            "INSERT OR IGNORE INTO crashes"
            "(ts,pid,comm,exe,component,sig,corefile,cpus_allowed,faultcore_involved,context,fingerprint)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                ts_s,
                pid,
                proc.get("comm") if proc else None,
                exe,
                component,
                sig,
                corefile,
                (",".join(map(str, sorted(mask))) if mask else None),
                verdict,
                full_context,
                fp,
            ),
        )
        added += 1
    return added


def ingest_minidumps(conn) -> int:
    """Firefox/WebRender minidumps are evidence even without systemd-coredump."""
    patterns = [
        os.path.expanduser("~/.mozilla/firefox/*/minidumps/*.dmp"),
        os.path.expanduser("~/.mozilla/firefox/Crash Reports/pending/*.dmp"),
        os.path.expanduser("~/ff-faultcore-crashes/**/*.dmp"),
        os.path.expanduser("~/ff-core2-crashes/**/*.dmp"),
        os.path.expanduser("~/ff-control-crashes/**/*.dmp"),
    ]
    added = 0
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            try:
                st = os.stat(path)
            except OSError:
                continue
            ts_s = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            fp = sha256_text(f"minidump|{path}|{st.st_mtime_ns}")[:40]
            if conn.execute("SELECT 1 FROM crashes WHERE fingerprint=?", (fp,)).fetchone():
                continue
            tag = (
                "faultcore-run" if "faultcore" in path or "core2" in path
                else "control-run" if "control" in path
                else "profile"
            )
            configured = (
                ",".join(map(str, config.FAULT_CORE_CPUS))
                if tag == "faultcore-run" and config.FAULT_CORE_CPUS
                else None
            )
            conn.execute(
                "INSERT OR IGNORE INTO crashes"
                "(ts,pid,comm,exe,component,sig,corefile,cpus_allowed,faultcore_involved,context,fingerprint)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ts_s, None, "firefox-esr",
                    "firefox-esr",
                    classify.crash_component(
                        "firefox-esr", "firefox-esr", "minidump",
                        f"Firefox minidump ({tag})", 1 if configured else None,
                    )[1],
                    "minidump", path,
                    configured,
                    1 if configured else None,
                    f"Firefox minidump ({tag}); size={st.st_size}",
                    fp,
                ),
            )
            added += 1
    return added


# ---------------------------------------------------------------- faultlab
def _feed_lines(conn, path: str, tag: str):
    """Yield new JSONL records from one append-only feed, byte-cursor safe."""
    try:
        stat = os.stat(path)
    except OSError:
        return
    size = stat.st_size
    offset_key = f"crash_feed_offset_{tag}"
    mtime_key = f"crash_feed_mtime_{tag}"
    try:
        cursor = int(db.meta_get(conn, offset_key, "0") or "0")
    except (TypeError, ValueError):
        cursor = 0
    try:
        prior_mtime = int(db.meta_get(conn, mtime_key, "0") or "0")
    except (TypeError, ValueError):
        prior_mtime = 0
    if size < cursor or (size <= cursor and stat.st_mtime_ns != prior_mtime):
        cursor = 0
    if size == cursor:
        return
    try:
        with open(path, "rb") as fh:
            fh.seek(cursor)
            chunk = fh.read(1_048_576)
            end = fh.tell()
    except OSError:
        return
    if len(chunk) == 1_048_576:
        cut = chunk.rfind(b"\n")
        if cut >= 0:
            chunk = chunk[:cut + 1]
            end = cursor + len(chunk)
    db.meta_set(conn, offset_key, str(end))
    db.meta_set(conn, mtime_key, str(stat.st_mtime_ns))
    for raw in chunk.splitlines():
        try:
            record = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(record, dict):
            yield record


def ingest_crash_feed(conn) -> int:
    """Ingest an optional external crash feed.

    The feed is a JSONL producer contract: process, signal/kind, affinity,
    attribution and a bounded context block.  QA Sentinels re-derives the
    component with the same evidence rules used for tickets, then stores it
    alongside the row.  An explicit producer may be faultlab-crashd; QA does
    not import or execute it, and with no feed configured this returns 0.
    """
    if not config.CRASH_FEED_ENABLED:
        return 0
    paths = list(config.CRASH_FEED_PATHS)
    seen_paths: set[str] = set()
    added = 0
    for path in paths:
        text_path = str(path)
        if text_path in seen_paths:
            continue
        seen_paths.add(text_path)
        tag = sha256_text(text_path)[:12]
        for record in _feed_lines(conn, text_path, tag):
            if not str(record.get("schema", "")).startswith(
                ("faultlab.crash", "qa.crashfeed")
            ):
                continue
            incident_id = str(record.get("id") or "").strip()
            if not incident_id:
                continue
            kind = str(record.get("kind") or "crash").strip()
            comm = str(record.get("comm") or "").strip()
            exe = str(record.get("exe") or "").strip()
            if not comm and exe:
                comm = exe.rstrip("/").rsplit("/", 1)[-1]
            if not comm:
                comm = "kernel" if kind in (
                    "mce", "oops", "panic", "lockup", "warning", "thermal"
                ) else "unknown"
            sig = str(record.get("sig") or kind or "crash").strip()
            cpus_allowed = str(record.get("cpus_allowed") or "").strip()
            mask = parse_cpu_list(cpus_allowed)
            involved = record.get("faultcore_involved")
            if involved in (0, 1):
                involved = int(involved)
            elif str(involved) in ("0", "1"):
                involved = int(str(involved))
            else:
                involved = faultcore_verdict(mask)
            ctx = str(record.get("context") or "")
            occurrences = record.get("occurrences")
            if occurrences not in (None, "", 1, "1"):
                ctx += f"\noccurrences={occurrences}"
            ctx = ctx[:24000]
            feed_component = str(record.get("component") or "").strip()
            _vendor, component = classify.crash_component(
                comm, exe, sig, ctx, involved)
            if not component or component == "unassigned":
                component = feed_component or component
            pid = record.get("pid")
            try:
                pid = int(pid) if pid is not None else None
            except (TypeError, ValueError):
                pid = None
            ts = str(record.get("ts") or iso())
            fingerprint = str(
                record.get("fingerprint") or f"crash-feed|{incident_id}"
            )
            try:
                cur = conn.execute(
                    "INSERT INTO crashes"
                    "(ts,pid,comm,exe,component,sig,corefile,cpus_allowed,"
                    " faultcore_involved,context,fingerprint)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(fingerprint) DO UPDATE SET"
                    " ts=excluded.ts, pid=excluded.pid, comm=excluded.comm,"
                    " exe=excluded.exe, component=excluded.component,"
                    " sig=excluded.sig, corefile=excluded.corefile,"
                    " cpus_allowed=excluded.cpus_allowed,"
                    " faultcore_involved=COALESCE(excluded.faultcore_involved,"
                    " crashes.faultcore_involved),"
                    " context=excluded.context",
                    (
                        ts, pid, comm, exe, component, sig,
                        str(record.get("corefile") or record.get("incident_dir") or ""),
                        cpus_allowed, involved, ctx, fingerprint,
                    ),
                )
            except sqlite3.Error as exc:
                raise RuntimeError(f"crash feed insert failed: {exc}") from exc
            added += cur.rowcount
    db.meta_set(conn, "last_crash_feed_ingest", iso())
    return added


def backfill_crash_components(conn, limit: int = 500) -> int:
    """Populate the component column for crash rows captured before it existed."""
    rows = conn.execute(
        "SELECT id, comm, exe, sig, context, faultcore_involved FROM crashes"
        " WHERE component IS NULL OR component='' ORDER BY id LIMIT ?",
        (limit,),
    ).fetchall()
    updated = 0
    for row in rows:
        component = classify.crash_component(
            row["comm"] or "", row["exe"] or "", row["sig"] or "",
            row["context"] or "", row["faultcore_involved"],
        )[1]
        conn.execute(
            "UPDATE crashes SET component=? WHERE id=?",
            (component or "unassigned", row["id"]),
        )
        updated += 1
    return updated


def ingest_all(conn) -> dict:
    result = {"journal": 0, "shutdown": 0, "coredumps": 0, "minidumps": 0,
              "components_backfilled": 0}
    try:
        result["components_backfilled"] = backfill_crash_components(conn)
    except Exception as exc:  # noqa: BLE001
        result["component_backfill_error"] = str(exc)[:300]
    try:
        result["journal"] = ingest_journal(conn)
    except Exception as exc:  # noqa: BLE001 - one source must not stop the others
        result["journal_error"] = str(exc)[:300]
    try:
        result["shutdown"] = shutdown.replay(conn)
    except Exception as exc:  # noqa: BLE001
        result["shutdown_error"] = str(exc)[:300]
    try:
        result["coredumps"] = ingest_coredumps(conn)
    except Exception as exc:  # noqa: BLE001
        result["coredump_error"] = str(exc)[:300]
    try:
        result["minidumps"] = ingest_minidumps(conn)
    except Exception as exc:  # noqa: BLE001
        result["minidump_error"] = str(exc)[:300]
    if config.CRASH_FEED_ENABLED:
        try:
            result["crash_feed"] = ingest_crash_feed(conn)
        except Exception as exc:  # noqa: BLE001
            result["crash_feed_error"] = str(exc)[:300]
    return result
