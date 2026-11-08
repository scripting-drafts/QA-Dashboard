from __future__ import annotations

import argparse
import getpass
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .core import (
    APP_VERSION,
    MODULE_IDS,
    Config,
    build_malware_args,
    http_json,
    parse_event,
    read_token,
    service_state,
)

SEPARATOR = "=" * 72


def _which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    path = Path(name).expanduser()
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return None


def terminal_argv(name: str, command: list[str]) -> list[str]:
    base = Path(name).name
    if base == "xdg-terminal-exec":
        return [name, *command]
    if base == "gnome-terminal":
        return [name, "--window", "--", *command]
    if base in ("kgx", "ptyxis"):
        return [name, "--", *command]
    if base in ("konsole", "alacritty"):
        return [name, "-e", *command]
    if base == "xfce4-terminal":
        return [name, "-x", *command]
    if base == "xterm":
        return [name, "-e", *command]
    if base in ("kitty", "foot"):
        return [name, *command]
    if base == "wezterm":
        return [name, "start", "--", *command]
    return [name, "-e", *command]


def build_terminal_invocation(command: list[str],
                              env: Optional[dict[str, str]] = None) -> Optional[list[str]]:
    environment = env or os.environ
    candidates = []
    preferred = environment.get("TERMINAL", "").strip()
    if preferred:
        candidates.append(preferred)
    candidates.extend((
        "xdg-terminal-exec", "gnome-terminal", "kgx", "ptyxis", "konsole",
        "xfce4-terminal", "xterm", "alacritty", "kitty", "foot", "wezterm",
    ))
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        path = _which(candidate)
        if path:
            return terminal_argv(path, command)
    return None


def inner_command(module: str) -> list[str]:
    return [sys.executable, "-m", "qadesk.terminal", "--module", module,
            "--in-terminal"]


def _input(prompt: str) -> Optional[str]:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _ask_bool(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = _input(f"{prompt} [{suffix}]: ")
    if answer is None:
        return False
    answer = answer.strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "1", "true")


def _run_qa(args: list[str], binary: str, root: str) -> int:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    if root:
        env["QA_SENTINELS_HOME"] = root
    print(f"$ {shlex.join([binary, *args])}")
    try:
        result = subprocess.run(
            [binary, *args], cwd=root or None, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False)
    except OSError as exc:
        print(f"error: {exc}")
        return 1
    if result.stdout:
        print(result.stdout.rstrip())
    return result.returncode


def sentinels_terminal() -> int:
    config = Config.load()
    binary = config.resolved_sentinels_bin()
    root = config.resolved_sentinels_root()
    if not binary:
        print("qa command not found.")
        print("Install Quality-Assurance-Sentinels or pass QA_SENTINELS_BIN.")
        return 1
    while True:
        print(f"\n{SEPARATOR}\nQuality Assurance Sentinels\n{SEPARATOR}")
        _run_qa(["status"], binary, root)
        choice = _input(
            "\n[r]efresh  [c]ycle  [f]indings  [l]ogs  [e]vidence  [q]uit > ")
        if choice is None:
            return 0
        choice = choice.strip().lower()
        if choice in ("", "q", "quit"):
            return 0
        if choice in ("r", "refresh"):
            continue
        if choice in ("c", "cycle"):
            _run_qa(["cycle"], binary, root)
        elif choice in ("f", "findings"):
            _run_qa(["findings"], binary, root)
        elif choice in ("l", "logs"):
            _run_qa(["logs", "--lines", "300"], binary, root)
        elif choice in ("e", "evidence"):
            _run_qa(["evidence", "--reason", "Terminal QA Desktop request",
                     "--hours", "24"], binary, root)
        else:
            print("Unknown choice.")


def _print_malware_event(event: dict) -> None:
    if event.get("event") == "finding":
        verdict = str(event.get("verdict", "unknown")).upper()
        reasons = "; ".join(str(item) for item in event.get("reasons") or [])
        print(f"[{verdict}] {event.get('path', '')}: {reasons}")
    elif event.get("event") == "summary":
        keys = ("scanned", "clean", "suspicious", "infected", "errors",
                "partial", "seconds")
        values = "  ".join(f"{key}={event.get(key, '-')}" for key in keys)
        print(f"summary: {values}")


def malware_terminal() -> int:
    config = Config.load()
    binary = config.resolved_malware_bin()
    if not binary:
        print("malware-scan executable not found.")
        print("Install malware-scan or set it in QA Desktop Settings.")
        return 1
    while True:
        print(f"\n{SEPARATOR}\nMalware Scan\n{SEPARATOR}")
        target = _input(f"Target [{os.getcwd()}]: ")
        if target is None:
            return 0
        target = target.strip() or os.getcwd()
        all_files = _ask_bool("Scan every regular file", True)
        deep = _ask_bool("Deep scan middle of large files", False)
        quarantine = _ask_bool("Quarantine infected files", False)
        steg = _ask_bool("Enable LSB steganalysis", False)
        clamav = yara = yara_rules = ""
        if _ask_bool("Configure external ClamAV/YARA engines", False):
            clamav = _input("ClamAV path or 'auto' (empty disables): ") or ""
            yara = _input("YARA executable (empty for default): ") or ""
            yara_rules = _input("YARA rules file (empty disables): ") or ""
        try:
            args = build_malware_args(
                binary, target, all_files=all_files, deep=deep,
                quarantine=quarantine, steg=steg, clamav=clamav,
                yara=yara, yara_rules=yara_rules)
        except ValueError as exc:
            print(f"error: {exc}")
            continue
        print(f"$ {shlex.join(args)}")
        try:
            proc = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                close_fds=True)
        except OSError as exc:
            print(f"error: {exc}")
            continue
        assert proc.stdout is not None
        for line in proc.stdout:
            event = parse_event(line)
            if event:
                _print_malware_event(event)
            elif line.strip():
                print(line.rstrip())
        rc = proc.wait()
        print(f"scan finished with exit {rc}")
        choice = _input("\n[a]gain  [l]ist quarantine  [q]uit > ")
        if choice is None:
            return 0
        choice = choice.strip().lower()
        if choice in ("q", "quit", ""):
            return 0
        if choice in ("l", "list"):
            print(f"\n{SEPARATOR}\nQuarantine\n{SEPARATOR}")
            try:
                result = subprocess.run(
                    [binary, "list"], stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, check=False)
                print(result.stdout.rstrip() or "No quarantine entries.")
            except OSError as exc:
                print(f"error: {exc}")


def _siem_fetch(config: Config, token: str) -> tuple[dict, dict, list, list, str]:
    url = config.siem_url
    health = {}
    stats = {}
    alerts: list = []
    events: list = []
    error = ""
    try:
        health = http_json(url, "/healthz", timeout=3.0)
    except Exception as exc:  # noqa: BLE001 - terminal display
        error = str(exc)
    if token:
        try:
            stats = http_json(url, "/api/v1/stats", token)
            alerts = http_json(url, "/api/v1/alerts?status=open&limit=50", token)
            events = http_json(url, "/api/v1/events?limit=20", token)
        except Exception as exc:  # noqa: BLE001 - terminal display
            error = str(exc)
    elif not error:
        error = "No bearer token available."
    return health, stats, alerts, events, error


def _siem_print(health: dict, stats: dict, alerts: list, events: list,
                error: str) -> None:
    print(f"\n{SEPARATOR}\nQA SIEM\n{SEPARATOR}")
    print(f"service: {service_state()}")
    print(f"health : {health.get('status', 'unknown')}  "
          f"version {health.get('version', '-')}  "
          f"uptime {health.get('uptime_s', '-')}s")
    if stats:
        print(f"events : {stats.get('events', '-')}  "
              f"open alerts {stats.get('alerts_open', '-')}  "
              f"hosts {stats.get('hosts', '-')}")
        print(f"last   : {stats.get('last_event_ts', '-')}")
    if error:
        print(f"error  : {error}")
    if alerts:
        print("\nOpen alerts:")
        for alert in alerts[:20]:
            print(f"  #{alert.get('id', '-')}  {alert.get('severity', '-')}  "
                  f"{alert.get('rule', '-')}  host={alert.get('host_id', '-')}  "
                  f"count={alert.get('count', '-')}  "
                  f"last={alert.get('last_seen', '-')}")
    if events:
        print("\nRecent events:")
        for event in events[:10]:
            print(f"  {event.get('ts', '-')}  {event.get('severity', '-')}  "
                  f"{event.get('event_type', '-')}  {event.get('rule', '-')}  "
                  f"{(event.get('subject') or event.get('detail') or '')}")


def siem_terminal() -> int:
    config = Config.load()
    token = read_token(config.resolved_siem_token_file())
    if not token:
        token = getpass.getpass(
            "SIEM bearer token (empty to proceed without): ").strip()
    while True:
        health, stats, alerts, events, error = _siem_fetch(config, token)
        _siem_print(health, stats, alerts, events, error)
        choice = _input(
            "\n[r]efresh  [a]ck alert  [d]ashboard  [q]uit > ")
        if choice is None:
            return 0
        choice = choice.strip().lower()
        if choice in ("", "q", "quit"):
            return 0
        if choice in ("r", "refresh"):
            continue
        if choice in ("d", "dashboard"):
            try:
                subprocess.Popen(["xdg-open", config.siem_url.rstrip("/") + "/"],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL)
            except OSError as exc:
                print(f"error: {exc}")
        elif choice in ("a", "ack"):
            ident = _input("Alert id: ")
            if ident is None:
                return 0
            if not ident.strip().isdigit():
                print("Enter a numeric alert id.")
                continue
            if not token:
                print("A bearer token is required.")
                continue
            try:
                http_json(config.siem_url, "/api/v1/alerts/ack", token,
                          method="POST", payload={"id": int(ident.strip())})
                print(f"alert {ident.strip()} acknowledged")
            except Exception as exc:  # noqa: BLE001 - terminal display
                print(f"error: {exc}")
        else:
            print("Unknown choice.")


def run_terminal(module: str) -> int:
    if module == "sentinels":
        return sentinels_terminal()
    if module == "malware":
        return malware_terminal()
    if module == "siem":
        return siem_terminal()
    print(f"unknown module: {module}")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qa-desktop-terminal")
    parser.add_argument("--module", choices=MODULE_IDS, default="sentinels")
    parser.add_argument("--in-terminal", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--print-command", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version",
                        version=f"qa-desktop-terminal {APP_VERSION}")
    args = parser.parse_args(argv)

    if args.print_command:
        invocation = build_terminal_invocation(inner_command(args.module))
        if not invocation:
            print("no terminal emulator found")
            return 1
        print(shlex.join(invocation))
        return 0

    if args.in_terminal or (sys.stdin.isatty() and sys.stdout.isatty()):
        return run_terminal(args.module)

    invocation = build_terminal_invocation(inner_command(args.module))
    if not invocation:
        print("qa-desktop-terminal: no terminal emulator found", file=sys.stderr)
        return 1
    try:
        subprocess.Popen(
            invocation, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    except OSError as exc:
        print(f"qa-desktop-terminal: cannot start terminal: {exc}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
