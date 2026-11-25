"""Probe admission policy: when volatile probes may run.

The minute cycle always samples, ingests the journal and scans boot boundaries.
Slow or volatile probes (inventory, network, LSM, hardware) are deferred until
the machine has reached its user-space target, because their early readings
describe device enumeration, not the steady state.

The policy is adaptive by default: the deadline comes from the median time
previous boots needed to become ready. A machine that boots in 20 seconds is not
forced to wait five minutes, and a slow server is not probed while still
starting. Every knob has a preset, a policy file and an environment override so
an operator can tune one machine without changing the defaults.
"""
from __future__ import annotations

import json
import os
import statistics
from copy import deepcopy
from pathlib import Path

from . import config, db
from .util import read_text, run

POLICY_FILE = config.ROOT / "config" / "probe-policy.json"
META_HISTORY = "probe_ready_history"
META_BOOT = "probe_ready_boot"

VOLATILE_SOURCES = ("inventory", "network", "lsm", "hardware")

_CACHE: dict | None = None
READINESS_MODES = {"target", "uptime", "off"}
ADMISSION_MODES = {"defer", "allow"}
TARGETS = {
    "multi-user": "multi-user.target",
    "graphical": "graphical.target",
    "userspace": "systemd-userspace.target",
    "multi-user.target": "multi-user.target",
    "graphical.target": "graphical.target",
    "systemd-userspace.target": "systemd-userspace.target",
}


def _base() -> dict:
    return {
        "preset": "adaptive",
        "readiness_mode": "target",
        "readiness_target": "multi-user.target",
        "readiness_max_wait_s": 300,
        "readiness_settle_s": 60,
        "readiness_adaptive": True,
        "admission_mode": "defer",
        "defer": VOLATILE_SOURCES,
    }


PRESETS = {
    "strict": {
        **_base(),
        "preset": "strict",
        "readiness_settle_s": 120,
        "readiness_adaptive": False,
        "admission_mode": "defer",
    },
    "balanced": {
        **_base(),
        "preset": "balanced",
        "readiness_adaptive": False,
    },
    "permissive": {
        **_base(),
        "preset": "permissive",
        "readiness_settle_s": 0,
        "admission_mode": "allow",
    },
    "adaptive": {
        **_base(),
        "preset": "adaptive",
    },
}


def _as_int(value, default: int, low: int, high: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _as_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


def _as_choice(value, allowed: set[str], default: str) -> str:
    text = str(value).strip().lower()
    return text if text in allowed else default


def _as_sources(value, default: tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(value, str):
        if value.strip().lower() in ("", "none", "off"):
            return ()
        parts = [part.strip().lower() for part in value.split(",")]
    elif isinstance(value, (list, tuple)):
        if not value:
            return ()
        parts = [str(part).strip().lower() for part in value]
    else:
        return default
    chosen: list[str] = []
    for source in parts:
        if source in VOLATILE_SOURCES and source not in chosen:
            chosen.append(source)
    return tuple(chosen) or default


def _deep_merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _load_file(path=None) -> tuple[dict, list[str]]:
    target = Path(path or POLICY_FILE)
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {}, []
    except json.JSONDecodeError as exc:
        return {}, [f"policy file is not valid JSON: {exc.msg}"]
    if not isinstance(data, dict):
        return {}, ["policy file must contain an object"]
    if data.get("schema") != 1:
        return {}, ["policy file schema must be 1"]
    return data, []


def _flatten(data: dict) -> dict:
    out: dict = {}
    readiness = data.get("readiness") if isinstance(data.get("readiness"), dict) else {}
    admission = data.get("admission") if isinstance(data.get("admission"), dict) else {}
    if "mode" in readiness:
        out["readiness_mode"] = readiness["mode"]
    if "target" in readiness:
        out["readiness_target"] = TARGETS.get(
            str(readiness["target"]).strip().lower(), "multi-user.target")
    if "max_wait_s" in readiness:
        out["readiness_max_wait_s"] = readiness["max_wait_s"]
    if "settle_s" in readiness:
        out["readiness_settle_s"] = readiness["settle_s"]
    if "adaptive" in readiness:
        out["readiness_adaptive"] = readiness["adaptive"]
    if "mode" in admission:
        out["admission_mode"] = admission["mode"]
    if "defer" in admission:
        out["defer"] = admission["defer"]
    return out


def _env_preset() -> str:
    return _as_choice(
        os.environ.get("QA_PROBE_POLICY", ""), set(PRESETS), "")


def effective(refresh: bool = False) -> dict:
    """Resolve preset, policy file, profile and environment overrides.

    Precedence is environment > policy file/profile > preset defaults. The
    settings file is applied to the environment at import time, so a dashboard
    edit behaves like an environment override.
    """
    global _CACHE
    if _CACHE is not None and not refresh:
        return _CACHE

    data, warnings = _load_file()
    file_preset = _as_choice(data.get("preset", ""), set(PRESETS), "")
    preset = _env_preset() or file_preset or "adaptive"
    resolved = deepcopy(PRESETS[preset])

    if data:
        profile = os.environ.get("QA_PROBE_PROFILE", "").strip().lower()
        merged = deepcopy(data)
        profiles = merged.pop("profiles", {}) if isinstance(
            merged.get("profiles"), dict) else {}
        if profile:
            selected = profiles.get(profile)
            if isinstance(selected, dict):
                merged = _deep_merge(merged, selected)
            else:
                warnings.append(f"unknown policy profile: {profile}")
        for key, value in _flatten(merged).items():
            resolved[key] = value

    env = os.environ
    resolved["readiness_mode"] = _as_choice(
        env.get("QA_PROBE_READY_MODE", resolved["readiness_mode"]),
        READINESS_MODES, resolved["readiness_mode"])
    resolved["readiness_target"] = TARGETS.get(
        str(env.get("QA_PROBE_READY_TARGET",
                    resolved["readiness_target"])).strip().lower(),
        resolved["readiness_target"])
    resolved["readiness_max_wait_s"] = _as_int(
        env.get("QA_PROBE_READY_MAX_S", resolved["readiness_max_wait_s"]),
        resolved["readiness_max_wait_s"], 0, 1800)
    resolved["readiness_settle_s"] = _as_int(
        env.get("QA_PROBE_READY_SETTLE_S", resolved["readiness_settle_s"]),
        resolved["readiness_settle_s"], 0, 600)
    resolved["readiness_adaptive"] = _as_bool(
        env.get("QA_PROBE_ADAPTIVE", resolved["readiness_adaptive"]),
        resolved["readiness_adaptive"])
    resolved["admission_mode"] = _as_choice(
        env.get("QA_PROBE_ADMISSION", resolved["admission_mode"]),
        ADMISSION_MODES, resolved["admission_mode"])
    resolved["defer"] = _as_sources(
        env.get("QA_PROBE_DEFER", resolved["defer"]), resolved["defer"])
    if not _as_bool(env.get("QA_PROBE_GATE", "1"), True):
        resolved["admission_mode"] = "allow"

    resolved["preset"] = preset
    resolved["warnings"] = tuple(warnings)
    _CACHE = resolved
    return resolved


def reset() -> None:
    """Drop the per-process cache; tests and long-lived callers use this."""
    global _CACHE
    _CACHE = None


def _uptime_s() -> float | None:
    try:
        return float(read_text("/proc/uptime").split()[0])
    except (IndexError, ValueError):
        return None


def _current_boot_id() -> str:
    return read_text("/proc/sys/kernel/random/boot_id").strip()


def _history(conn) -> list[float]:
    if conn is None:
        return []
    try:
        raw = json.loads(db.meta_get(conn, META_HISTORY) or "[]")
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []
    out = []
    for value in raw:
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if 0 < number < 3600:
            out.append(number)
    return out[-16:]


def deadline(conn=None) -> tuple[int, str]:
    """Fallback readiness deadline in seconds, and where it came from."""
    resolved = effective()
    configured = int(resolved["readiness_max_wait_s"])
    if not resolved["readiness_adaptive"]:
        return configured, "configured"
    history = _history(conn)
    if not history:
        return configured, "configured"
    learned = int(statistics.median(history) * 1.5)
    return max(30, min(900, learned)), "adaptive"


def _system_ready(target: str) -> tuple[bool | None, str]:
    """None means systemd is not available, so the caller uses uptime."""
    rc, _out, _err = run(
        ["systemctl", "is-active", "--quiet", target], timeout=5)
    if rc == 0:
        return True, "target"
    if rc == 127:
        return None, "no-systemd"
    rc, out, _err = run(["systemctl", "is-system-running"], timeout=5)
    state = (out or "").strip().lower()
    if state in ("running", "degraded"):
        return True, f"system-{state}"
    if rc == 127:
        return None, "no-systemd"
    return False, f"system-{state or 'unknown'}"


def _target_ready_since(target: str) -> float | None:
    """Seconds since boot when the target became active, if systemd knows."""
    rc, out, _err = run(
        ["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic",
         "--value", target],
        timeout=5,
    )
    if rc != 0:
        return None
    try:
        micro = int((out or "").strip())
    except ValueError:
        return None
    if micro <= 0:
        return None
    return micro / 1_000_000


def _record_ready(conn, boot_id: str, uptime: float | None) -> None:
    if conn is None or uptime is None or not boot_id:
        return
    try:
        if db.meta_get(conn, META_BOOT) == boot_id:
            return
        history = _history(conn)
        history.append(round(uptime, 1))
        db.meta_set(conn, META_HISTORY, json.dumps(history[-16:]))
        db.meta_set(conn, META_BOOT, boot_id)
    except Exception:  # noqa: BLE001 - policy state must never stop a cycle
        return


def gate(conn=None) -> dict:
    """Current readiness state and the probes that should wait."""
    resolved = effective()
    uptime = _uptime_s()
    wait_s, source = deadline(conn)
    mode = resolved["readiness_mode"]
    ready_at: float | None = None

    if mode == "off":
        ready, reason = True, "disabled"
    elif mode == "uptime":
        ready = bool(wait_s and uptime is not None and uptime >= wait_s)
        reason = "uptime" if ready else "uptime-wait"
    else:
        ready, reason = _system_ready(resolved["readiness_target"])
        if ready is True and reason == "target":
            since = _target_ready_since(resolved["readiness_target"])
            ready_at = since
            settle = int(resolved["readiness_settle_s"])
            if (since is not None and uptime is not None and settle > 0
                    and uptime < since + settle):
                ready, reason = False, "settle"
        if ready is None:
            ready = bool(wait_s and uptime is not None and uptime >= wait_s)
            reason = "uptime-fallback" if ready else "uptime-wait"
        elif not ready and wait_s and uptime is not None and uptime >= wait_s:
            ready, reason = True, "deadline"

    if ready:
        _record_ready(conn, _current_boot_id(),
                      ready_at if ready_at is not None else uptime)

    deferred = ()
    if not ready and resolved["admission_mode"] == "defer":
        deferred = resolved["defer"]
    return {
        "preset": resolved["preset"],
        "ready": bool(ready),
        "reason": reason,
        "uptime_s": round(uptime, 1) if uptime is not None else None,
        "deadline_s": wait_s,
        "deadline_source": source,
        "deferred": tuple(deferred),
        "warnings": resolved.get("warnings", ()),
    }
