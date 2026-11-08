from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

APP_VERSION = "0.1.0"
MODULE_IDS = ("sentinels", "malware", "siem")
MAX_HTTP_BODY = 8 * 1024 * 1024


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _expanded(value: str) -> str:
    return str(Path(value).expanduser()) if value else ""


def _usable(path: str) -> str:
    if not path:
        return ""
    p = Path(path).expanduser()
    if p.is_file() and os.access(p, os.X_OK):
        return str(p)
    found = shutil.which(path)
    return found or ""


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "qa-desktop" / "config.json"


@dataclass
class Config:
    sentinels_bin: str = ""
    sentinels_root: str = ""
    malware_bin: str = ""
    siem_url: str = "http://127.0.0.1:8088"
    siem_token_file: str = ""
    enabled_modules: list[str] = field(default_factory=lambda: list(MODULE_IDS))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        cfg = cls()
        target = path or default_config_path()
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            for key in ("sentinels_bin", "sentinels_root", "malware_bin",
                        "siem_url", "siem_token_file"):
                value = data.get(key)
                if isinstance(value, str):
                    setattr(cfg, key, value.strip())
            modules = data.get("enabled_modules")
            if isinstance(modules, list):
                selected = [m for m in modules if isinstance(m, str) and m in MODULE_IDS]
                cfg.enabled_modules = selected or list(MODULE_IDS)
        cfg.siem_url = (cfg.siem_url or "http://127.0.0.1:8088").rstrip("/")
        return cfg

    def save(self, path: Optional[Path] = None) -> None:
        target = path or default_config_path()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {
            "sentinels_bin": self.sentinels_bin,
            "sentinels_root": self.sentinels_root,
            "malware_bin": self.malware_bin,
            "siem_url": self.siem_url,
            "siem_token_file": self.siem_token_file,
            "enabled_modules": [m for m in MODULE_IDS if m in self.enabled_modules],
        }
        tmp = target.with_name(target.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, target)
        os.chmod(target, 0o600)

    def resolved_sentinels_root(self) -> str:
        configured = _expanded(self.sentinels_root)
        if configured and (Path(configured) / "bin" / "qa").is_file():
            return configured
        env_root = _expanded(_env("QA_SENTINELS_ROOT"))
        if env_root and (Path(env_root) / "bin" / "qa").is_file():
            return env_root
        for candidate in (Path.home() / "Quality-Assurance-Sentinels",
                          Path("/opt/Quality-Assurance-Sentinels")):
            if (candidate / "bin" / "qa").is_file():
                return str(candidate)
        return ""

    def resolved_sentinels_bin(self) -> str:
        configured = _usable(_expanded(self.sentinels_bin))
        if configured:
            return configured
        env_bin = _usable(_expanded(_env("QA_SENTINELS_BIN")))
        if env_bin:
            return env_bin
        root = self.resolved_sentinels_root()
        if root:
            return _usable(str(Path(root) / "bin" / "qa"))
        return _usable("qa")

    def resolved_malware_bin(self) -> str:
        configured = _usable(_expanded(self.malware_bin))
        if configured:
            return configured
        env_bin = _usable(_expanded(_env("MALWARE_SCAN_BIN")))
        if env_bin:
            return env_bin
        found = _usable("malware-scan")
        if found:
            return found
        for candidate in (Path.home() / "malware-scan" / "build" / "malware-scan",
                          Path.home() / ".local" / "bin" / "malware-scan"):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return ""

    def resolved_siem_token_file(self) -> str:
        configured = _expanded(self.siem_token_file)
        if configured:
            return configured
        env_file = _expanded(_env("QA_SIEM_TOKEN_FILE"))
        if env_file:
            return env_file
        for candidate in (Path("/etc/qa-siem/token"),
                          Path.home() / ".config" / "qa-siem" / "token"):
            if candidate.is_file():
                return str(candidate)
        return str(Path("/etc/qa-siem/token"))

    def enabled(self, module_id: str) -> bool:
        return module_id in self.enabled_modules


def build_malware_args(binary: str, path: str, *, all_files: bool = True,
                       deep: bool = False, quarantine: bool = False,
                       steg: bool = False, clamav: str = "",
                       yara: str = "", yara_rules: str = "") -> list[str]:
    if not binary:
        raise ValueError("malware-scan executable is not configured")
    target = _expanded(path.strip())
    if not target:
        raise ValueError("choose a file or folder to scan")
    args = [binary, "scan", "--json", "--fail-on", "none"]
    if all_files:
        args.append("--all-files")
    if deep:
        args.append("--deep")
    if quarantine:
        args.append("--quarantine")
    if steg:
        args.append("--steg")
    if clamav.strip():
        args.extend(["--clamav", _expanded(clamav.strip())])
    if yara.strip():
        args.extend(["--yara", _expanded(yara.strip())])
    if yara_rules.strip():
        args.extend(["--yara-rules", _expanded(yara_rules.strip())])
    args.extend(["--", target])
    return args


def parse_event(line: str) -> Optional[dict[str, Any]]:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        value = json.loads(line)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def parse_malware_jsonl(lines: Iterable[str]) -> tuple[Optional[dict], list[dict]]:
    findings: list[dict] = []
    summary: Optional[dict] = None
    for line in lines:
        event = parse_event(line)
        if not event:
            continue
        if event.get("event") == "finding":
            findings.append(event)
        elif event.get("event") == "summary":
            summary = event
    return summary, findings


def parse_qa_status(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            values[key] = value
    return values


def read_token(path: str) -> str:
    if not path:
        return ""
    try:
        data = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    token = data.strip()
    return token if 0 < len(token) <= 4096 else ""


def http_json(base_url: str, path: str, token: str = "", *, method: str = "GET",
              payload: Any = None, timeout: float = 5.0) -> Any:
    if not base_url.lower().startswith(("http://", "https://")):
        raise ValueError("SIEM URL must start with http:// or https://")
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_HTTP_BODY + 1)
            if len(raw) > MAX_HTTP_BODY:
                raise RuntimeError("SIEM response exceeded the size limit")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = f"HTTP {exc.code}"
        try:
            body = exc.read(65536)
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict) and parsed.get("error"):
                message = str(parsed["error"])
        except Exception:
            pass
        raise RuntimeError(message) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(str(reason)) from None


def service_state(name: str = "qa-siem.service") -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = (result.stdout or result.stderr).strip()
    return text or "unknown"


def path_uri(path: str) -> str:
    return Path(path).expanduser().resolve().as_uri()
