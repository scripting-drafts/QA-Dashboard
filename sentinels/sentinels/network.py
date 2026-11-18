"""Network and connectivity tier.

Read-only snapshot of the host network state: interfaces, addresses, routes,
DNS configuration, Netplan/NetworkManager profiles, tunnels, firewall summary,
listeners, neighbour and conntrack counts, socket counters and selected
``net.*`` sysctls.

No packet is sent and no configuration is changed.  External commands are fixed
argv with timeouts.  Sensitive values (SSIDs, BSSIDs, WireGuard keys and peer
endpoints) are hashed before they reach the database; reports and evidence
bundles additionally apply the normal address/MAC/host redaction.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import time
from collections import Counter
from datetime import timedelta
from pathlib import Path

from . import config, db, detect
from .util import iso, parse_iso, read_text, redact, run, sha256_text, utcnow

PERMISSION_HINTS = (
    "permission denied", "operation not permitted", "must be root",
    "insufficient privilege", "not permitted", "access denied",
)

INTERFACE_ROOT = Path("/sys/class/net")
SYSCTL_ROOT = Path("/proc/sys/net")
NETPLAN_DIR = Path("/etc/netplan")
NETNS_DIRS = (Path("/run/netns"), Path("/var/run/netns"))
RESOLV_CONF = Path("/etc/resolv.conf")
UFW_CONF = Path("/etc/ufw/ufw.conf")

# Units that carry connectivity.  Template units are discovered separately.
CONNECTIVITY_UNITS = (
    "NetworkManager.service",
    "NetworkManager-dispatcher.service",
    "NetworkManager-wait-online.service",
    "systemd-networkd.service",
    "systemd-networkd-wait-online.service",
    "systemd-resolved.service",
    "systemd-timesyncd.service",
    "wpa_supplicant.service",
    "iwd.service",
    "connman.service",
    "ModemManager.service",
    "bluetooth.service",
    "avahi-daemon.service",
    "ssh.service",
    "sshd.service",
    "openvpn.service",
    "tailscaled.service",
    "firewalld.service",
    "ufw.service",
    "nftables.service",
    "iptables.service",
    "dnsmasq.service",
    "unbound.service",
)
TEMPLATE_PREFIXES = ("openvpn@", "openvpn-client@", "wg-quick@", "tailscale@")

# Curated sysctls: full tree is read and hashed, these values are kept for
# readable drift and security review.
SYSCTL_KEYS = (
    "net.core.somaxconn",
    "net.core.netdev_max_backlog",
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.core.default_qdisc",
    "net.core.dev_weight",
    "net.core.busy_poll",
    "net.core.busy_read",
    "net.ipv4.ip_forward",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_retries2",
    "net.ipv4.tcp_syn_retries",
    "net.ipv4.tcp_synack_retries",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.tcp_keepalive_probes",
    "net.ipv4.tcp_max_syn_backlog",
    "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_sack",
    "net.ipv4.tcp_window_scaling",
    "net.ipv4.tcp_mtu_probing",
    "net.ipv4.tcp_congestion_control",
    "net.ipv4.tcp_available_congestion_control",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.neigh.default.gc_thresh1",
    "net.ipv4.neigh.default.gc_thresh2",
    "net.ipv4.neigh.default.gc_thresh3",
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.all.use_tempaddr",
    "net.netfilter.nf_conntrack_max",
    "net.unix.max_dgram_qlen",
)

# Dynamic sysctls are excluded from the stable digest so a busy host does not
# create a diff every run.  Their current values are metrics.
DYNAMIC_SYSCTLS = {
    "net.netfilter.nf_conntrack_count",
}

# ARPHRD values seen in /sys/class/net/<if>/type.
ARPHRD = {
    1: "ether",
    512: "ppp",
    768: "tunnel",
    769: "tunnel6",
    772: "loopback",
    776: "sit",
    778: "ip6gre",
    823: "ip6tnl",
    65534: "none",
}

IF_FLAGS = {
    0x1: "UP",
    0x2: "BROADCAST",
    0x4: "DEBUG",
    0x8: "LOOPBACK",
    0x10: "POINTOPOINT",
    0x20: "NOTRAILERS",
    0x40: "RUNNING",
    0x80: "NOARP",
    0x100: "PROMISC",
    0x200: "ALLMULTI",
    0x400: "MASTER",
    0x800: "SLAVE",
    0x1000: "MULTICAST",
    0x2000: "PORTSEL",
    0x4000: "AUTOMEDIA",
    0x8000: "DYNAMIC",
    0x10000: "LOWER_UP",
    0x20000: "DORMANT",
    0x40000: "ECHO",
}

VIRTUAL_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "vnet", "lxc", "lxd", "podman",
    "cni", "flannel", "cali", "vxlan", "dummy", "bond", "tun", "tap", "wg",
    "tailscale", "zt", "proton", "ipv6leakintrf",
)


def _clip(text: str, limit: int = 4000) -> str:
    return (text or "").strip()[:limit]


def _put_item(out: dict, kind: str, item: str, value) -> None:
    text = _clip(str(value))
    if not text:
        return
    out[(kind, item)] = text


def _put_metric(out: dict, scope: str, metric: str, value) -> None:
    try:
        out[(scope, metric)] = int(value)
    except (TypeError, ValueError):
        return


def _read_int(path: Path, default: int | None = None) -> int | None:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return default


def _read_file(path: Path, limit: int = 4096) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit].strip()
    except OSError:
        return ""


def _which(name: str) -> str | None:
    return shutil.which(name)


def _perm_error(text: str) -> bool:
    return any(hint in (text or "").lower() for hint in PERMISSION_HINTS)


def _status(rc: int, err: str = "") -> str:
    if rc == 0:
        return "ok"
    if rc == 127:
        return "unavailable"
    if _perm_error(err):
        return "needs-root"
    return "error"


def _json_command(cmd: list[str]) -> tuple[object | None, int, str]:
    rc, out, err = run(cmd, timeout=config.NETWORK_TIMEOUT_S)
    if rc != 0:
        return None, rc, err
    try:
        return json.loads(out), rc, err
    except (TypeError, ValueError):
        return None, 1, f"{cmd[0]}: invalid JSON"


def _finding(rule: str, severity: str, subject: str, detail: str) -> dict:
    ts = iso()
    return {
        "fingerprint": f"network|{rule}|{subject}",
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": redact(detail),
        "case_id": None,
    }


# ---------------------------------------------------------------- parsers
def parse_interface_flags(value: str) -> tuple[str, str]:
    """Return (hex, decoded names) for a /sys/class/net/<if>/flags value."""
    text = (value or "").strip()
    try:
        number = int(text, 0)
    except ValueError:
        return text, ""
    names = [name for bit, name in IF_FLAGS.items() if number & bit]
    return text, "+".join(names)


def parse_ip_addr_json(text: str) -> dict[tuple[str, str, str, int], str]:
    """Parse ``ip -j addr show`` into stable address items.

    Lifetimes are deliberately omitted: they count down on every read and are
    not configuration drift.  Address flags such as ``temporary`` and
    ``dynamic`` are kept because they change the security meaning of an address.
    """
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    if not isinstance(data, list):
        return {}
    out: dict[tuple[str, str, str, int], str] = {}
    for link in data:
        if not isinstance(link, dict):
            continue
        ifname = str(link.get("ifname") or "")
        if not ifname:
            continue
        for addr in link.get("addr_info") or []:
            if not isinstance(addr, dict):
                continue
            family = str(addr.get("family") or "")
            local = str(addr.get("local") or "")
            if family not in ("inet", "inet6") or not local:
                continue
            try:
                prefix = int(addr.get("prefixlen") or 0)
            except (TypeError, ValueError):
                prefix = 0
            flags = [
                key for key in (
                    "secondary", "dynamic", "noprefixroute", "temporary",
                    "deprecated", "nodad", "mngtmpaddr", "optimistic", "home",
                    "permanent",
                )
                if addr.get(key)
            ]
            fields = [
                f"scope={addr.get('scope') or 'unknown'}",
                f"flags={','.join(flags) or '-'}",
            ]
            label = addr.get("label")
            if label and label != ifname:
                fields.append(f"label={label}")
            peer = addr.get("peer")
            if peer:
                fields.append(f"peer={peer}")
            out[(ifname, family, local, prefix)] = " ".join(fields)
    return out


def parse_ip_route_json(text: str) -> dict[str, str]:
    """Parse ``ip -j route show table all`` into stable route items."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    if not isinstance(data, list):
        return {}
    out: dict[str, str] = {}
    seen: Counter[str] = Counter()
    for route in data:
        if not isinstance(route, dict):
            continue
        table = str(route.get("table") or "main")
        dst = str(route.get("dst") or route.get("type") or "default")
        key = f"{table}/{dst}"
        seen[key] += 1
        if seen[key] > 1:
            key = f"{key}#{seen[key]}"
        fields = []
        for name in ("type", "via", "gateway", "dev", "metric", "protocol",
                     "scope", "prefsrc", "src", "flags", "onlink", "nexthop"):
            value = route.get(name)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                if name == "nexthop":
                    value = ";".join(
                        json.dumps(part, sort_keys=True) for part in value
                    )
                else:
                    value = "+".join(str(part) for part in value)
            label = "via" if name == "gateway" else name
            fields.append(f"{label}={value}")
        out[key] = " ".join(fields) or "present"
    return out


def parse_ip_rule_json(text: str) -> dict[str, str]:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    if not isinstance(data, list):
        return {}
    out: dict[str, str] = {}
    for rule in data:
        if not isinstance(rule, dict):
            continue
        priority = str(rule.get("priority") or "?")
        key = priority
        n = 2
        while key in out:
            key = f"{priority}#{n}"
            n += 1
        fields = []
        for name in ("from", "to", "table", "fwmark", "iif", "oif", "protocol"):
            value = rule.get(name)
            if value not in (None, ""):
                fields.append(f"{name}={value}")
        out[key] = " ".join(fields) or "present"
    return out


def parse_resolv_conf(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"nameservers": [], "search": [], "options": []}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        keyword = parts[0].lower()
        values = parts[1:]
        if keyword == "nameserver" and values:
            out["nameservers"].append(values[0])
        elif keyword in ("search", "domain"):
            out["search"].extend(values)
        elif keyword == "options":
            out["options"].extend(values)
    for key in out:
        out[key] = list(dict.fromkeys(out[key]))
    return out


def parse_resolvectl_status(text: str) -> dict:
    """Parse the human-readable ``resolvectl status`` output.

    The parser keeps only stable state.  ``Current DNS Server`` is a hint that
    can rotate between equivalent servers; it is retained because it explains
    which upstream is actually in use.
    """
    data: dict = {"global": {}, "links": {}, "resolv_conf_mode": ""}
    current = data["global"]
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        match = re.match(r"^Link\s+\d+\s+\(([^)]+)\)\s*$", stripped)
        if match:
            current = data["links"].setdefault(match.group(1), {})
            continue
        if stripped == "Global":
            current = data["global"]
            continue
        match = re.match(r"^resolv\.conf mode:\s*(.+)$", stripped, re.I)
        if match:
            data["resolv_conf_mode"] = match.group(1).strip()
            continue
        for label, key in (
            ("Current Scopes", "scopes"),
            ("Protocols", "protocols"),
            ("Current DNS Server", "current_dns"),
            ("DNS Servers", "dns"),
            ("DNS Domain", "domains"),
            ("DNSSEC", "dnssec"),
            ("DNSOverTLS", "dns_over_tls"),
        ):
            if stripped.lower().startswith(label.lower() + ":"):
                value = stripped.split(":", 1)[1].strip()
                if key in ("dns", "domains"):
                    current[key] = value.split()
                else:
                    current[key] = value
                break
    return data


def parse_proc_net_wireless(text: str) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for line in (text or "").splitlines():
        match = re.match(
            r"^\s*(\S+):\s+\d+\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)", line
        )
        if not match:
            continue
        iface, link, level, noise = match.groups()
        out[iface] = {
            "link": float(link),
            "level_dbm": float(level),
            "noise_dbm": float(noise),
        }
    return out


def parse_iw_link(text: str) -> dict:
    out: dict = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("Connected to "):
            out["bssid"] = stripped.split("Connected to ", 1)[1].split(" ", 1)[0]
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "ssid":
            out["ssid"] = value
        elif key == "freq":
            try:
                out["freq_mhz"] = float(value.split()[0])
            except (IndexError, ValueError):
                pass
        elif key == "signal":
            try:
                out["signal_dbm"] = float(value.split()[0])
            except (IndexError, ValueError):
                pass
        elif key in ("tx bitrate", "rx bitrate"):
            try:
                out[key.replace(" ", "_") + "_mbps"] = float(value.split()[0])
            except (IndexError, ValueError):
                pass
    return out


def parse_nmcli_general(text: str) -> dict[str, str]:
    line = (text or "").strip().splitlines()
    if not line:
        return {}
    parts = line[0].split(":")
    keys = ("state", "connectivity", "wifi", "wwan")
    return {key: parts[index] for index, key in enumerate(keys) if index < len(parts)}


def parse_nmcli_connections(text: str) -> list[dict[str, str]]:
    out = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) < 5:
            continue
        uuid, ctype, device, state, autoconnect = parts[:5]
        out.append({
            "uuid": uuid,
            "type": ctype,
            "device": device,
            "state": state,
            "autoconnect": autoconnect,
        })
    return out


def parse_wg_dump(text: str) -> dict:
    """Parse ``wg show <if> dump`` without retaining key material.

    The caller hashes peer public keys and endpoints.  This parser returns only
    counters, allowed-IP count and handshake timestamps.
    """
    lines = [line for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return {}
    first = lines[0].split("\t")
    if len(first) < 4:
        first = lines[0].split()
    if len(first) < 4:
        return {}
    try:
        listen_port = int(first[2])
    except ValueError:
        listen_port = 0
    peers = []
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            parts = line.split()
        if len(parts) < 8:
            continue
        try:
            latest_handshake = int(parts[4])
            rx_bytes = int(parts[5])
            tx_bytes = int(parts[6])
            keepalive = int(parts[7]) if parts[7] != "off" else 0
        except ValueError:
            continue
        peers.append({
            "public_key": parts[0],
            "endpoint": parts[2],
            "allowed_ips": [ip.strip() for ip in parts[3].split(",") if ip.strip()],
            "latest_handshake": latest_handshake,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "keepalive": keepalive,
        })
    return {"listen_port": listen_port, "peers": peers}


def parse_nft_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {}
    entries = data.get("nftables") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return {}
    counts: Counter[str] = Counter()
    tables: list[str] = []
    chains: list[str] = []
    policies: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for kind, value in entry.items():
            counts[kind] += 1
            if kind == "table" and isinstance(value, dict):
                tables.append(f"{value.get('family', '?')}/{value.get('name', '?')}")
            elif kind == "chain" and isinstance(value, dict):
                name = f"{value.get('table', '?')}/{value.get('name', '?')}"
                chains.append(name)
                policy = value.get("policy")
                if policy:
                    policies.append(f"{name}={policy}")
    return {
        "tables": counts.get("table", 0),
        "chains": counts.get("chain", 0),
        "rules": counts.get("rule", 0),
        "sets": counts.get("set", 0),
        "maps": counts.get("map", 0),
        "flows": counts.get("flowtable", 0),
        "table_names": tables,
        "chain_names": chains,
        "policies": policies,
    }


def parse_iptables_save(text: str) -> dict:
    rules = chains = 0
    policies = []
    for line in (text or "").splitlines():
        if line.startswith("-A "):
            rules += 1
        elif line.startswith(":"):
            chains += 1
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in ("-", "[0:0]"):
                policies.append(f"{parts[0].lstrip(':')}={parts[1]}")
    return {"rules": rules, "chains": chains, "policies": policies}


def stable_firewall_text(text: str) -> str:
    """Zero dynamic counters before hashing a firewall ruleset.

    ``iptables-save`` chain counters and nftables ``counter packets/bytes``
    values change continuously.  They are not configuration drift, so the
    digest must not change every run.
    """
    value = text or ""
    value = re.sub(r"\[\d+:\d+\]", "[0:0]", value)
    value = re.sub(
        r"counter packets \d+ bytes \d+", "counter packets 0 bytes 0", value
    )
    value = re.sub(r'("packets"\s*:\s*)\d+', r'\g<1>0', value)
    value = re.sub(r'("bytes"\s*:\s*)\d+', r'\g<1>0', value)
    value = re.sub(r'("used"\s*:\s*)\d+', r'\g<1>0', value)
    return value


def parse_ip_neigh_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return {"count": 0, "states": {}, "devices": {}}
    if not isinstance(data, list):
        return {"count": 0, "states": {}, "devices": {}}
    states: Counter[str] = Counter()
    devices: Counter[str] = Counter()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for state in entry.get("state") or ["UNKNOWN"]:
            states[str(state)] += 1
        device = entry.get("dev")
        if device:
            devices[str(device)] += 1
    return {"count": len(data), "states": dict(states), "devices": dict(devices)}


def parse_proc_net_dev(text: str) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for line in (text or "").splitlines():
        if ":" not in line or line.strip().startswith("Inter-"):
            continue
        iface, values = line.split(":", 1)
        fields = values.split()
        if len(fields) < 16:
            continue
        keys = (
            "rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
            "rx_fifo_errors", "rx_frame_errors", "rx_compressed", "rx_multicast",
            "tx_bytes", "tx_packets", "tx_errors", "tx_dropped",
            "tx_fifo_errors", "tx_collisions", "tx_carrier_errors", "tx_compressed",
        )
        out[iface.strip()] = {
            key: int(fields[index]) for index, key in enumerate(keys)
            if fields[index].isdigit()
        }
    return out


def parse_snmp(text: str) -> dict[str, int]:
    """Parse /proc/net/snmp into flat counters."""
    out: dict[str, int] = {}
    lines = (text or "").splitlines()
    for index in range(0, len(lines) - 1):
        header = lines[index].split()
        values = lines[index + 1].split()
        if not header or header[0] != values[0]:
            continue
        prefix = header[0].rstrip(":")
        for name, value in zip(header[1:], values[1:]):
            try:
                out[f"{prefix.lower()}/{name}"] = int(value)
            except ValueError:
                continue
    return out


def parse_netstat(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    lines = (text or "").splitlines()
    for index in range(0, len(lines) - 1):
        header = lines[index].split()
        values = lines[index + 1].split()
        if not header or not values or header[0] != values[0]:
            continue
        prefix = header[0].rstrip(":")
        for name, value in zip(header[1:], values[1:]):
            try:
                out[f"{prefix.lower()}/{name}"] = int(value)
            except ValueError:
                continue
    return out


def split_listener_endpoint(endpoint: str) -> tuple[str, int | None, str]:
    """Split an ``ss`` local endpoint into (address, port, address scope)."""
    text = (endpoint or "").strip()
    host = text
    scope_hint = ""
    port: int | None = None
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1:]
            if rest.startswith("%"):
                scope_hint, _, port_text = rest[1:].rpartition(":")
            else:
                port_text = rest.lstrip(":")
            try:
                port = int(port_text)
            except ValueError:
                port = None
    else:
        host, _, port_text = text.rpartition(":")
        if "%" in host:
            host, scope_hint = host.split("%", 1)
        try:
            port = int(port_text)
        except ValueError:
            port = None
    if host.startswith("127.") or host == "::1":
        scope = "loopback"
    elif scope_hint or host.startswith("fe80:") or host.startswith("169.254."):
        scope = "link"
    elif host in ("*", "0.0.0.0", "::", ""):
        scope = "wildcard"
    else:
        scope = "global"
    return host, port, scope


def parse_ss_listeners(text: str) -> list[dict]:
    """Parse ``ss -lntupH`` with the local address in the correct column.

    The historical inventory parser used index 3 (Send-Q), which collapsed
    listeners with the same queue size.  This parser uses index 4 and keeps the
    endpoint, process and address scope.
    """
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto.startswith("tcp"):
            proto = "tcp"
        elif proto.startswith("udp"):
            proto = "udp"
        else:
            continue
        state, recv_q, send_q = parts[1], parts[2], parts[3]
        local = parts[4]
        peer = parts[5] if len(parts) > 5 else ""
        address, port, scope = split_listener_endpoint(local)
        procs = re.findall(r'\("([^"]+)"', line)
        out.append({
            "proto": proto,
            "state": state,
            "recv_q": recv_q,
            "send_q": send_q,
            "local": local,
            "address": address,
            "port": port,
            "scope": scope,
            "peer": peer,
            "process": ",".join(dict.fromkeys(procs)) or "unknown",
        })
    return out


def _listener_is_ephemeral_udp(listener: dict) -> bool:
    port = listener.get("port")
    return listener["proto"] == "udp" and isinstance(port, int) and port >= 32768


# ---------------------------------------------------------------- collectors
def _collect_services(items: dict, metrics: dict, sources: dict) -> None:
    rc, out, err = run(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend",
         "--plain", "--no-pager"],
        timeout=config.NETWORK_TIMEOUT_S,
    )
    sources["systemd"] = _status(rc, err)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            unit = parts[0]
            if not (
                unit in CONNECTIVITY_UNITS
                or unit.startswith(TEMPLATE_PREFIXES)
            ):
                continue
            _put_item(items, "service", unit, f"active={parts[2]} sub={parts[3]}")
    # is-active also covers units that are not loaded but are enabled.
    for unit in CONNECTIVITY_UNITS:
        if any(key == ("service", unit) for key in items):
            continue
        rc, out, _err = run(
            ["systemctl", "is-active", unit],
            timeout=min(5, config.NETWORK_TIMEOUT_S),
        )
        state = (out or "").strip() or "unknown"
        if rc in (0, 3) or state:
            _put_item(items, "service", unit, f"active={state}")


def _interface_items() -> dict:
    out: dict = {}
    for path in sorted(INTERFACE_ROOT.glob("*")):
        name = path.name
        if not name:
            continue
        prefix = f"interface/{name}"
        _put_item(out, "interface", f"{name}/index", _read_int(path / "ifindex", 0))
        type_num = _read_int(path / "type", 0) or 0
        _put_item(out, "interface", f"{name}/type", ARPHRD.get(type_num, str(type_num)))
        _put_item(out, "interface", f"{name}/operstate", _read_file(path / "operstate"))
        carrier = _read_int(path / "carrier")
        if carrier is not None:
            _put_item(out, "interface", f"{name}/carrier", carrier)
        _put_item(out, "interface", f"{name}/mtu", _read_int(path / "mtu", 0))
        _put_item(out, "interface", f"{name}/mac", _read_file(path / "address"))
        _put_item(out, "interface", f"{name}/tx_queue_len", _read_int(path / "tx_queue_len", 0))
        _put_item(out, "interface", f"{name}/qdisc", _read_file(path / "qdisc"))
        speed = _read_int(path / "speed")
        if speed is not None and speed > 0:
            _put_item(out, "interface", f"{name}/speed_mbps", speed)
        duplex = _read_file(path / "duplex")
        if duplex and duplex != "unknown":
            _put_item(out, "interface", f"{name}/duplex", duplex)
        flags_hex, flags = parse_interface_flags(_read_file(path / "flags"))
        _put_item(out, "interface", f"{name}/flags", flags or flags_hex)
        device = path / "device"
        _put_item(out, "interface", f"{name}/physical", 1 if device.exists() else 0)
        _put_item(out, "interface", f"{name}/virtual", 1 if _is_virtual(name, device.exists()) else 0)
        driver = path / "device" / "driver"
        if driver.exists():
            _put_item(out, "interface", f"{name}/driver", os.path.basename(os.path.realpath(driver)))
        if (path / "wireless").exists():
            _put_item(out, "interface", f"{name}/wireless", 1)
    return out


def _is_virtual(name: str, has_device: bool) -> bool:
    if name == "lo":
        return True
    if name.startswith(VIRTUAL_PREFIXES):
        return True
    return not has_device


def _collect_addresses(items: dict, metrics: dict, sources: dict) -> None:
    data, rc, err = _json_command(["ip", "-j", "addr", "show"])
    sources["addresses"] = _status(rc, err)
    if rc != 0 or not isinstance(data, list):
        return
    addresses = parse_ip_addr_json(json.dumps(data))
    for (ifname, family, local, prefix), value in addresses.items():
        _put_item(items, "address", f"{ifname}/{family}/{local}/{prefix}", value)
    counts = Counter(family for (_if, family, _local, _prefix) in addresses)
    _put_metric(metrics, "address", "total", len(addresses))
    for family, count in counts.items():
        _put_metric(metrics, "address", family, count)
    # Fallback path: keep the interface list visible even with no addresses.
    for ifname in {key[0] for key in addresses}:
        _put_item(items, "interface", f"{ifname}/addressed", 1)


def _collect_connectivity(items: dict, metrics: dict, sources: dict) -> None:
    """Record the systemd/networkd connectivity targets and runtime state."""
    for target in ("network.target", "network-online.target"):
        rc, out, err = run(["systemctl", "is-active", target],
                           timeout=min(5, config.NETWORK_TIMEOUT_S))
        state = (out or "").strip() or "unknown"
        if rc in (0, 3) or state:
            _put_item(items, "connectivity", target, state)
    state_file = Path("/run/systemd/netif/state")
    if state_file.exists():
        values = {}
        for line in read_text(state_file).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        for key in ("OPER_STATE", "ADMIN_STATE", "DNS", "NTP"):
            if values.get(key):
                _put_item(items, "connectivity", f"networkd/{key.lower()}",
                          values[key])
        sources["networkd"] = "ok"
    else:
        sources["networkd"] = "unavailable"


def _collect_routes(items: dict, metrics: dict, sources: dict) -> None:
    data, rc, err = _json_command(["ip", "-j", "route", "show", "table", "all"])
    sources["routes"] = _status(rc, err)
    if rc != 0 or not isinstance(data, list):
        return
    routes = parse_ip_route_json(json.dumps(data))
    for key, value in routes.items():
        _put_item(items, "route", key, value)
    defaults = {}
    tables = Counter()
    for key, value in routes.items():
        table = key.split("/", 1)[0]
        tables[table] += 1
        if key.split("/", 1)[1].startswith("default"):
            defaults[table] = value
    for table, value in defaults.items():
        _put_item(items, "route", f"default/{table}", value)
    for table, count in tables.items():
        _put_metric(metrics, "route", f"table/{table}", count)
    _put_metric(metrics, "route", "total", len(routes))

    rule_data, rule_rc, rule_err = _json_command(["ip", "-j", "rule", "show"])
    sources["rules"] = _status(rule_rc, rule_err)
    if rule_rc == 0 and isinstance(rule_data, list):
        rules = parse_ip_rule_json(json.dumps(rule_data))
        for key, value in rules.items():
            _put_item(items, "rule", key, value)
        _put_metric(metrics, "rule", "total", len(rules))


def _collect_dns(items: dict, metrics: dict, sources: dict) -> None:
    text = read_text(RESOLV_CONF)
    conf = parse_resolv_conf(text)
    _put_item(items, "dns", "resolv_conf/sha256", sha256_text(text)[:32])
    _put_item(items, "dns", "resolv_conf/nameservers", len(conf["nameservers"]))
    _put_item(items, "dns", "resolv_conf/search", len(conf["search"]))
    _put_item(items, "dns", "resolv_conf/options", ",".join(conf["options"]) or "none")
    for index, server in enumerate(conf["nameservers"]):
        if _is_dns_server(server):
            _put_item(items, "dns", f"resolv_conf/server/{index}", server)
    for index, domain in enumerate(conf["search"]):
        # Search domains are local context; evidence views replace them.
        _put_item(items, "dns", f"resolv_conf/search/{index}", domain)

    rc, out, err = run(
        ["resolvectl", "status", "--no-pager"],
        timeout=config.NETWORK_TIMEOUT_S,
    )
    sources["resolved"] = _status(rc, err)
    upstreams: set[str] = {
        server for server in conf["nameservers"]
        if _is_dns_server(server) and not _is_stub_resolver(server)
    }
    if rc == 0:
        status = parse_resolvectl_status(out)
        _put_item(items, "dns", "resolv_conf/mode", status.get("resolv_conf_mode") or "unknown")
        for scope_name in ("global",):
            block = status.get(scope_name) or {}
            _collect_dns_block(items, metrics, f"dns/{scope_name}", block, upstreams)
        for link, block in sorted((status.get("links") or {}).items()):
            _collect_dns_block(items, metrics, f"dns/link/{link}", block, upstreams)
    _put_item(items, "dns", "upstream_count", len(upstreams))
    _put_metric(metrics, "dns", "upstream_count", len(upstreams))


def _is_stub_resolver(server: str) -> bool:
    # systemd-resolved's documented stub addresses.  A local dnsmasq/unbound on
    # 127.0.0.1 is a real resolver and must not be mistaken for the stub.
    return server in ("127.0.0.53", "127.0.0.54")


def _is_dns_server(value: str) -> bool:
    text = (value or "").split("%", 1)[0].strip()
    if not text or text in ("-", "none", "(none)"):
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _collect_dns_block(items: dict, metrics: dict, prefix: str,
                       block: dict, upstreams: set[str]) -> None:
    for key in ("scopes", "protocols", "current_dns", "dnssec", "dns_over_tls"):
        value = block.get(key)
        if value:
            _put_item(items, "dns", f"{prefix}/{key}", value)
    for index, server in enumerate(block.get("dns") or []):
        if not _is_dns_server(server):
            continue
        _put_item(items, "dns", f"{prefix}/server/{index}", server)
        if not _is_stub_resolver(server):
            upstreams.add(server)
    for index, domain in enumerate(block.get("domains") or []):
        _put_item(items, "dns", f"{prefix}/domain/{index}", domain)


def _collect_netplan(items: dict, metrics: dict, sources: dict,
                     findings: list[dict]) -> None:
    files = sorted(
        [path for path in NETPLAN_DIR.glob("*.yaml")] +
        [path for path in NETPLAN_DIR.glob("*.yml")]
    )
    sources["netplan"] = "ok" if NETPLAN_DIR.exists() else "unavailable"
    digests = []
    for path in files:
        try:
            data = path.read_bytes()
            st = path.stat()
        except OSError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        mode = stat.S_IMODE(st.st_mode)
        _put_item(
            items, "netplan", f"file/{path.name}",
            f"sha256={digest[:32]} size={st.st_size} "
            f"mtime={int(st.st_mtime)} mode={mode:04o}",
        )
        digests.append(f"{path.name}:{digest}")
        if mode & 0o077:
            findings.append(_finding(
                "network.netplan.permissions", "warning", "netplan",
                f"/etc/netplan/{path.name} is accessible to group/other "
                f"(mode {mode:04o}); it may contain Wi-Fi credentials",
            ))
    _put_item(items, "netplan", "file_count", len(files))
    _put_item(items, "netplan", "digest", sha256_text("\n".join(digests))[:32])
    _put_metric(metrics, "netplan", "files", len(files))


def _collect_networkmanager(items: dict, metrics: dict, sources: dict) -> None:
    rc, out, err = run(
        ["nmcli", "-t", "-f", "STATE,CONNECTIVITY,WIFI,WWAN", "general"],
        timeout=config.NETWORK_TIMEOUT_S,
    )
    sources["networkmanager"] = _status(rc, err)
    if rc == 0:
        general = parse_nmcli_general(out)
        _put_item(items, "nm", "general", " ".join(
            f"{key}={value}" for key, value in general.items()
        ))
    rc, out, err = run(
        ["nmcli", "-t", "-f", "UUID,TYPE,DEVICE,STATE,AUTOCONNECT", "connection", "show"],
        timeout=config.NETWORK_TIMEOUT_S,
    )
    if rc == 0:
        profiles = parse_nmcli_connections(out)
        for profile in profiles:
            _put_item(
                items, "nm", f"profile/{profile['uuid']}",
                f"type={profile['type']} device={profile['device']} "
                f"state={profile['state']} autoconnect={profile['autoconnect']}",
            )
        _put_metric(metrics, "nm", "profiles", len(profiles))
        _put_metric(metrics, "nm", "active",
                    sum(1 for profile in profiles if profile["state"] == "activated"))


def _collect_wifi(items: dict, metrics: dict, sources: dict) -> None:
    wireless = parse_proc_net_wireless(read_text("/proc/net/wireless"))
    for iface, values in wireless.items():
        for key, value in values.items():
            _put_metric(metrics, f"wifi/{iface}", key, round(value))
    if not wireless:
        sources["wifi"] = "unavailable"
        return
    sources["wifi"] = "ok"
    if not _which("iw"):
        sources["iw"] = "unavailable"
        return
    sources["iw"] = "ok"
    for iface in sorted(wireless):
        rc, out, err = run(
            ["iw", "dev", iface, "link"],
            timeout=min(5, config.NETWORK_TIMEOUT_S),
        )
        if rc != 0:
            if _perm_error(err):
                sources["iw"] = "needs-root"
            continue
        link = parse_iw_link(out)
        if link.get("ssid"):
            _put_item(items, "wifi", f"{iface}/ssid_sha256",
                      sha256_text(link["ssid"])[:32])
            _put_item(items, "wifi", f"{iface}/ssid_len", len(link["ssid"]))
        if link.get("bssid"):
            _put_item(items, "wifi", f"{iface}/bssid_sha256",
                      sha256_text(link["bssid"])[:32])
        if link.get("freq_mhz"):
            _put_item(items, "wifi", f"{iface}/freq_mhz", int(link["freq_mhz"]))
        for key in ("signal_dbm", "tx_bitrate_mbps", "rx_bitrate_mbps"):
            if key in link:
                _put_metric(metrics, f"wifi/{iface}", key, round(link[key]))


def _collect_tunnels(items: dict, metrics: dict, sources: dict) -> None:
    rc, out, err = run(["wg", "show", "interfaces"],
                       timeout=config.NETWORK_TIMEOUT_S)
    sources["wireguard"] = _status(rc, err)
    interfaces = [line.strip() for line in (out or "").splitlines() if line.strip()]
    tunnel_names: set[str] = set()
    for iface in interfaces:
        rc, dump, err = run(["wg", "show", iface, "dump"],
                            timeout=config.NETWORK_TIMEOUT_S)
        if rc != 0:
            if _perm_error(err):
                sources["wireguard"] = "needs-root"
            continue
        parsed = parse_wg_dump(dump)
        if not parsed:
            continue
        tunnel_names.add(iface)
        _put_item(items, "tunnel", f"wireguard/{iface}",
                  f"listen_port={parsed['listen_port']} peers={len(parsed['peers'])}")
        for peer in parsed["peers"]:
            key_hash = sha256_text(peer["public_key"])[:16]
            _put_item(
                items, "tunnel", f"wireguard/{iface}/peer/{key_hash}",
                f"endpoint_sha256={sha256_text(peer['endpoint'])[:16]} "
                f"allowed_ips={len(peer['allowed_ips'])} keepalive={peer['keepalive']}",
            )
            _put_metric(metrics, f"tunnel/{iface}/peer/{key_hash}",
                        "rx_bytes", peer["rx_bytes"])
            _put_metric(metrics, f"tunnel/{iface}/peer/{key_hash}",
                        "tx_bytes", peer["tx_bytes"])
            age = int(time.time()) - peer["latest_handshake"] if peer["latest_handshake"] else -1
            _put_metric(metrics, f"tunnel/{iface}/peer/{key_hash}",
                        "handshake_age_s", age)

    # Interface-level tunnel state is readable without root.
    for path in sorted(INTERFACE_ROOT.glob("*")):
        name = path.name
        type_num = _read_int(path / "type", 0) or 0
        type_name = ARPHRD.get(type_num, str(type_num))
        if not (
            name.startswith(("tun", "tap", "wg", "tailscale", "proton", "ppp",
                             "ipv6leakintrf", "zt")) or type_name in ("tunnel", "tunnel6", "none")
        ):
            continue
        if name == "lo":
            continue
        tunnel_names.add(name)
        _put_item(items, "tunnel", f"interface/{name}",
                  f"type={type_name} operstate={_read_file(path / 'operstate')} "
                  f"mtu={_read_int(path / 'mtu', 0)}")
    _put_metric(metrics, "tunnel", "count", len(tunnel_names))

    rc, out, err = run(
        ["systemctl", "list-units", "--all", "--no-legend", "--plain",
         "--no-pager", "openvpn*.service"],
        timeout=config.NETWORK_TIMEOUT_S,
    )
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].startswith("openvpn"):
                _put_item(items, "tunnel", f"openvpn/{parts[0]}",
                          f"active={parts[2]} sub={parts[3]}")
    if _which("tailscale"):
        data, rc, err = _json_command(["tailscale", "status", "--json"])
        if rc == 0 and isinstance(data, dict):
            peers = data.get("Peer") or {}
            _put_item(
                items, "tunnel", "tailscale",
                f"backend={data.get('BackendState', 'unknown')} "
                f"online={(data.get('Self') or {}).get('Online')} peers={len(peers)}",
            )


def _collect_firewall(items: dict, metrics: dict, sources: dict,
                      findings: list[dict]) -> None:
    active = []
    data, rc, err = _json_command(["nft", "-j", "list", "ruleset"])
    sources["nft"] = _status(rc, err)
    if rc == 0 and isinstance(data, dict):
        summary = parse_nft_json(json.dumps(data))
        raw = stable_firewall_text(json.dumps(data, sort_keys=True))
        _put_item(items, "firewall", "nft",
                  f"tables={summary.get('tables', 0)} chains={summary.get('chains', 0)} "
                  f"rules={summary.get('rules', 0)} sets={summary.get('sets', 0)}")
        _put_item(items, "firewall", "nft/digest", sha256_text(raw)[:32])
        if summary.get("table_names"):
            _put_item(items, "firewall", "nft/tables",
                      ",".join(sorted(summary["table_names"])))
        if summary.get("policies"):
            _put_item(items, "firewall", "nft/policies",
                      ",".join(sorted(summary["policies"])))
        if summary.get("rules"):
            active.append("nftables")

    for family, command, key in (
        ("iptables", ["iptables-save"], "iptables"),
        ("ip6tables", ["ip6tables-save"], "ip6tables"),
    ):
        rc, out, err = run(command, timeout=config.NETWORK_TIMEOUT_S)
        sources[family] = _status(rc, err)
        if rc == 0:
            summary = parse_iptables_save(out)
            _put_item(
                items, "firewall", key,
                f"rules={summary['rules']} chains={summary['chains']} "
                f"policies={','.join(summary['policies']) or '-'} "
                f"digest={sha256_text(stable_firewall_text(out))[:32]}",
            )
            if summary["rules"]:
                active.append(key)

    ufw_enabled = ""
    for line in read_text(UFW_CONF).splitlines():
        if line.strip().upper().startswith("ENABLED="):
            ufw_enabled = line.split("=", 1)[1].split("#", 1)[0].strip().lower()
    rc, out, _err = run(["systemctl", "is-active", "ufw.service"],
                        timeout=min(5, config.NETWORK_TIMEOUT_S))
    ufw_service = (out or "").strip() or "unknown"
    if UFW_CONF.exists():
        _put_item(items, "firewall", "ufw",
                  f"enabled={ufw_enabled or 'unknown'} service={ufw_service}")
        sources["ufw"] = "ok"
        if ufw_enabled == "yes":
            if ufw_service == "active":
                active.append("ufw")
            else:
                findings.append(_finding(
                    "network.firewall.ufw_inactive", "warning", "ufw",
                    f"UFW is enabled in {UFW_CONF} but ufw.service is {ufw_service}",
                ))
    else:
        sources["ufw"] = "unavailable"

    if _which("firewall-cmd"):
        rc, out, err = run(["firewall-cmd", "--state"],
                           timeout=min(5, config.NETWORK_TIMEOUT_S))
        if rc == 0:
            rc2, zone, _ = run(["firewall-cmd", "--get-default-zone"],
                               timeout=min(5, config.NETWORK_TIMEOUT_S))
            _put_item(items, "firewall", "firewalld",
                      f"state={(out or '').strip()} "
                      f"default_zone={(zone or '').strip() if rc2 == 0 else 'unknown'}")
            active.append("firewalld")
        sources["firewalld"] = _status(rc, err)

    _put_item(items, "firewall", "active", "+".join(dict.fromkeys(active)) or "none")
    _put_metric(metrics, "firewall", "active", len(set(active)))
    if config.NETWORK_FIREWALL_REQUIRED and not active:
        findings.append(_finding(
            "network.firewall.disabled", "warning", "firewall",
            "NETWORK_FIREWALL_REQUIRED is set but no active firewall was detected",
        ))


def _collect_conntrack(items: dict, metrics: dict, sources: dict) -> None:
    count = _read_int(Path("/proc/sys/net/netfilter/nf_conntrack_count"))
    maximum = _read_int(Path("/proc/sys/net/netfilter/nf_conntrack_max"))
    if count is None or maximum is None:
        sources["conntrack"] = "unavailable"
        return
    sources["conntrack"] = "ok"
    _put_item(items, "conntrack", "max", maximum)
    _put_metric(metrics, "conntrack", "count", count)
    if maximum > 0:
        _put_metric(metrics, "conntrack", "usage_pct",
                    round(100.0 * count / maximum))


def _collect_neighbours(items: dict, metrics: dict, sources: dict) -> None:
    data, rc, err = _json_command(["ip", "-j", "neigh", "show"])
    sources["neighbours"] = _status(rc, err)
    if rc == 0 and isinstance(data, list):
        summary = parse_ip_neigh_json(json.dumps(data))
    else:
        # /proc/net/arp fallback keeps the count available without iproute2.
        lines = [
            line for line in read_text("/proc/net/arp").splitlines()[1:]
            if line.strip()
        ]
        summary = {"count": len(lines), "states": {"ARP": len(lines)}, "devices": {}}
    _put_metric(metrics, "neigh", "count", summary["count"])
    for state, count in summary.get("states", {}).items():
        _put_metric(metrics, "neigh", f"state/{state}", count)
    for device, count in summary.get("devices", {}).items():
        _put_metric(metrics, "neigh", f"dev/{device}", count)


def _collect_sysctls(items: dict, metrics: dict, sources: dict) -> None:
    values: dict[str, str] = {}
    errors = 0
    if not SYSCTL_ROOT.exists():
        sources["sysctls"] = "unavailable"
        return
    for dirpath, _dirnames, filenames in os.walk(SYSCTL_ROOT):
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            try:
                if not path.is_file() or path.is_symlink():
                    continue
                raw = path.read_text(encoding="utf-8", errors="replace")[:4096].strip()
            except OSError:
                errors += 1
                continue
            rel = path.relative_to(SYSCTL_ROOT)
            key = "net." + ".".join(rel.parts)
            values[key] = " ".join(raw.split())
    sources["sysctls"] = "partial" if errors else "ok"
    stable = {key: value for key, value in values.items() if key not in DYNAMIC_SYSCTLS}
    _put_item(items, "sysctl", "net/count", len(values))
    _put_item(items, "sysctl", "net/digest", sha256_text(
        "\n".join(f"{key}={value}" for key, value in sorted(stable.items()))
    )[:32])
    for key in SYSCTL_KEYS:
        if key in values:
            _put_item(items, "sysctl", key, values[key])
    _put_metric(metrics, "sysctl", "count", len(values))


def _collect_namespaces(items: dict, metrics: dict, sources: dict) -> None:
    names = set()
    for directory in NETNS_DIRS:
        try:
            for entry in directory.iterdir():
                if entry.is_file() or entry.is_symlink() or entry.is_dir():
                    names.add(entry.name)
        except OSError:
            continue
    for name in sorted(names):
        _put_item(items, "netns", f"name/{name}", "present")
    inodes = set()
    try:
        pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        try:
            inodes.add(os.readlink(f"/proc/{pid}/ns/net"))
        except OSError:
            continue
    sources["namespaces"] = "ok" if pids else "unavailable"
    _put_metric(metrics, "netns", "named", len(names))
    _put_metric(metrics, "netns", "count", len(inodes))
    _put_item(items, "netns", "named_count", len(names))


def _collect_listeners(items: dict, metrics: dict, sources: dict) -> None:
    rc, out, err = run(["ss", "-lntupH"], timeout=config.NETWORK_TIMEOUT_S)
    if rc != 0:
        rc, out, err = run(["ss", "-lntup"], timeout=config.NETWORK_TIMEOUT_S)
    sources["listeners"] = _status(rc, err)
    if rc != 0:
        return
    listeners = parse_ss_listeners(out)
    tcp = udp = filtered = 0
    for listener in listeners:
        if listener["proto"] == "tcp":
            tcp += 1
        else:
            if _listener_is_ephemeral_udp(listener):
                filtered += 1
                continue
            udp += 1
        _put_item(
            items, "listener", f"{listener['proto']}/{listener['local']}",
            f"process={listener['process']} scope={listener['scope']}",
        )
    _put_metric(metrics, "listener", "tcp", tcp)
    _put_metric(metrics, "listener", "udp", udp)
    _put_metric(metrics, "listener", "udp_ephemeral_filtered", filtered)
    rc, out, err = run(["ss", "-lxH"], timeout=config.NETWORK_TIMEOUT_S)
    if rc != 0:
        rc, out, err = run(["ss", "-lx"], timeout=config.NETWORK_TIMEOUT_S)
    sources["unix_sockets"] = _status(rc, err)
    if rc == 0:
        _put_metric(metrics, "listener", "unix", len([
            line for line in out.splitlines()
            if line.strip() and not line.startswith("Netid")
        ]))


def _collect_counters(items: dict, metrics: dict, sources: dict) -> None:
    for path in sorted(INTERFACE_ROOT.glob("*")):
        name = path.name
        stats = path / "statistics"
        if not stats.is_dir():
            continue
        for metric_path in sorted(stats.iterdir()):
            value = _read_int(metric_path)
            if value is not None:
                _put_metric(metrics, f"if/{name}", metric_path.name, value)
    sources["counters"] = "ok" if INTERFACE_ROOT.exists() else "unavailable"

    for path, scope in (
        (Path("/proc/net/snmp"), "snmp"),
        (Path("/proc/net/netstat"), "netstat"),
    ):
        text = read_text(path)
        parsed = parse_snmp(text) if path.name == "snmp" else parse_netstat(text)
        if parsed:
            sources[scope] = "ok"
            for key, value in parsed.items():
                _put_metric(metrics, scope, key, value)
        else:
            sources[scope] = "unavailable"


def collect() -> dict:
    """Return one read-only network snapshot without touching the database."""
    items: dict = {}
    metrics: dict = {}
    sources: dict = {}
    errors: list[str] = []
    findings: list[dict] = []

    collectors = (
        ("interfaces", lambda: items.update(_interface_items())),
        ("services", lambda: _collect_services(items, metrics, sources)),
        ("connectivity", lambda: _collect_connectivity(items, metrics, sources)),
        ("addresses", lambda: _collect_addresses(items, metrics, sources)),
        ("routes", lambda: _collect_routes(items, metrics, sources)),
        ("dns", lambda: _collect_dns(items, metrics, sources)),
        ("netplan", lambda: _collect_netplan(items, metrics, sources, findings)),
        ("networkmanager", lambda: _collect_networkmanager(items, metrics, sources)),
        ("wifi", lambda: _collect_wifi(items, metrics, sources)),
        ("tunnels", lambda: _collect_tunnels(items, metrics, sources)),
        ("firewall", lambda: _collect_firewall(items, metrics, sources, findings)),
        ("conntrack", lambda: _collect_conntrack(items, metrics, sources)),
        ("neighbours", lambda: _collect_neighbours(items, metrics, sources)),
        ("sysctls", lambda: _collect_sysctls(items, metrics, sources)),
        ("namespaces", lambda: _collect_namespaces(items, metrics, sources)),
        ("listeners", lambda: _collect_listeners(items, metrics, sources)),
        ("counters", lambda: _collect_counters(items, metrics, sources)),
    )
    for name, collector in collectors:
        try:
            collector()
        except Exception as exc:  # noqa: BLE001 - one source must not hide others
            sources[name] = "error"
            errors.append(f"{name}: {type(exc).__name__}: {exc}"[:300])
    return {
        "items": items,
        "metrics": metrics,
        "sources": sources,
        "errors": errors,
        "findings": findings,
    }


# ---------------------------------------------------------------- state
def _previous(conn) -> tuple[dict, dict, str | None, int | None]:
    row = conn.execute(
        "SELECT id, ts FROM network_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not row:
        return {}, {}, None, None
    items = {
        (r["kind"], r["item"]): r["value"] or ""
        for r in conn.execute(
            "SELECT kind, item, value FROM network_items WHERE run_id=?",
            (row["id"],),
        )
    }
    metrics = {
        (r["scope"], r["metric"]): int(r["value"] or 0)
        for r in conn.execute(
            "SELECT scope, metric, value FROM network_metrics WHERE run_id=?",
            (row["id"],),
        )
    }
    return items, metrics, row["ts"], row["id"]


def _diff_items(ts: str, run_id: int, previous: dict, current: dict) -> list[tuple]:
    diffs = []
    for key in sorted(set(previous) | set(current)):
        before = previous.get(key)
        after = current.get(key)
        if before == after:
            continue
        change = "added" if before is None else "removed" if after is None else "changed"
        diffs.append((ts, run_id, key[0], change, key[1], before, after))
    return diffs


def _value(items: dict, kind: str, item: str) -> str:
    return items.get((kind, item), "")


def _devices_from_routes(items: dict, kind: str = "route") -> set[str]:
    devices = set()
    for (item_kind, item), value in items.items():
        if item_kind != kind or not item.startswith("default/"):
            continue
        match = re.search(r"\bdev=(\S+)", value)
        if match:
            devices.add(match.group(1))
    return devices


def _address_devices(items: dict) -> set[str]:
    return {
        item.split("/", 1)[0]
        for kind, item in items
        if kind == "address" and "/" in item
    }


def _metric_delta(previous: dict, current: dict, key: tuple[str, str]) -> int:
    before = previous.get(key)
    after = current.get(key)
    if before is None or after is None or after < before:
        return 0
    return after - before


def _findings(conn, ts: str, items: dict, metrics: dict, previous_items: dict,
              previous_metrics: dict) -> list[dict]:
    findings: list[dict] = []
    current_uplinks = _devices_from_routes(items)
    previous_uplinks = _devices_from_routes(previous_items)
    addressed = _address_devices(items) | _address_devices(previous_items)

    for kind, item in items:
        if kind != "interface" or not item.endswith("/operstate"):
            continue
        iface = item[:-len("/operstate")]
        if _value(items, "interface", f"{iface}/virtual") == "1":
            continue
        operstate = _value(items, "interface", item).lower()
        carrier = _value(items, "interface", f"{iface}/carrier")
        if operstate != "down" or carrier not in ("0", ""):
            continue
        if iface not in current_uplinks and iface not in previous_uplinks \
                and iface not in addressed:
            continue
        severity = "error" if iface in current_uplinks or iface in previous_uplinks else "warning"
        findings.append(_finding(
            "network.interface.down", severity, iface,
            f"{iface} is administratively up but carrier is down "
            f"(operstate={operstate}); default-route use="
            f"{iface in current_uplinks or iface in previous_uplinks}",
        ))

    current_defaults = {
        item: value for (kind, item), value in items.items()
        if kind == "route" and item.startswith("default/")
    }
    previous_defaults = {
        item: value for (kind, item), value in previous_items.items()
        if kind == "route" and item.startswith("default/")
    }
    if previous_defaults and not current_defaults:
        findings.append(_finding(
            "network.route.default_missing", "error", "default-route",
            "no default IPv4/IPv6 route remains; previous: " +
            "; ".join(f"{key} {value}" for key, value in sorted(previous_defaults.items())),
        ))

    current_tunnels = {
        item.split("/", 1)[1]: value for (kind, item), value in items.items()
        if kind == "tunnel" and item.startswith("interface/")
    }
    previous_tunnels = {
        item.split("/", 1)[1]: value for (kind, item), value in previous_items.items()
        if kind == "tunnel" and item.startswith("interface/")
    }
    for iface in sorted(previous_tunnels):
        now = current_tunnels.get(iface)
        if now is None:
            findings.append(_finding(
                "network.vpn.down", "warning", iface,
                f"tunnel interface {iface} disappeared; previous={previous_tunnels[iface]}",
            ))
        elif "operstate=down" in now.lower() or "operstate=unknown" in now.lower():
            findings.append(_finding(
                "network.vpn.down", "warning", iface,
                f"tunnel interface {iface} is not up: {now}",
            ))

    if _value(items, "dns", "upstream_count") == "0" and current_defaults:
        findings.append(_finding(
            "network.dns.no_upstream", "warning", "dns",
            "a default route exists but no upstream DNS server is configured "
            "(the local stub resolver is not an upstream)",
        ))

    error_total: Counter[str] = Counter()
    for (scope, metric), _ in metrics.items():
        if not scope.startswith("if/"):
            continue
        if metric not in (
            "rx_errors", "tx_errors", "rx_crc_errors", "rx_frame_errors",
            "tx_carrier_errors", "rx_fifo_errors", "tx_fifo_errors",
            "rx_missed_errors",
        ):
            continue
        error_total[scope[3:]] += _metric_delta(
            previous_metrics, metrics, (scope, metric)
        )
    for iface, delta in sorted(error_total.items()):
        if _value(items, "interface", f"{iface}/virtual") == "1":
            continue
        if delta >= config.NETWORK_ERROR_DELTA_ALERT:
            findings.append(_finding(
                "network.interface.errors", "warning", iface,
                f"{delta} receive/transmit error counter increment(s) "
                "since the previous network run",
            ))

    out_delta = _metric_delta(previous_metrics, metrics, ("snmp", "tcp/OutSegs"))
    retr_delta = _metric_delta(previous_metrics, metrics, ("snmp", "tcp/RetransSegs"))
    if out_delta >= config.NETWORK_TCP_MIN_SEGMENTS:
        ratio = 100.0 * retr_delta / out_delta if out_delta else 0.0
        if ratio >= config.NETWORK_TCP_RETRANS_ALERT_PCT:
            findings.append(_finding(
                "network.tcp.retrans", "warning", "tcp",
                f"{ratio:.1f}% TCP retransmissions ({retr_delta}/{out_delta} "
                "outbound segments) since the previous network run",
            ))

    usage = metrics.get(("conntrack", "usage_pct"), 0)
    if usage >= config.NETWORK_CONNTRACK_ALERT_PCT:
        findings.append(_finding(
            "network.conntrack.high", "warning", "conntrack",
            f"conntrack table usage {usage}%",
        ))
    return findings


def is_due(conn) -> bool:
    if not config.NETWORK_ENABLE:
        return False
    last = db.meta_get(conn, "last_network_ts")
    if not last:
        return True
    try:
        return (utcnow() - parse_iso(last)).total_seconds() >= config.NETWORK_INTERVAL_S
    except ValueError:
        return True


def scan(conn) -> dict:
    started = time.monotonic()
    ts = iso()
    snapshot = collect()
    items = snapshot["items"]
    metrics = snapshot["metrics"]
    previous_items, previous_metrics, previous_ts, previous_id = _previous(conn)
    if previous_id and previous_ts:
        try:
            elapsed = (parse_iso(ts) - parse_iso(previous_ts)).total_seconds()
        except ValueError:
            elapsed = 0
        if elapsed > 0:
            for scope, metric in list(metrics):
                if scope.startswith("if/") and metric in ("rx_bytes", "tx_bytes"):
                    delta = _metric_delta(previous_metrics, metrics, (scope, metric))
                    metrics[(scope, metric.replace("_bytes", "_kbps"))] = int(
                        delta / elapsed / 1024
                    )
    digest = sha256_text("\n".join(
        f"{kind}|{item}|{value}" for (kind, item), value in sorted(items.items())
    ))
    counts = Counter(kind for kind, _item in items)
    duration_ms = int((time.monotonic() - started) * 1000)
    cur = conn.execute(
        "INSERT INTO network_runs(ts,status,digest,counts,sources,duration_ms,detail)"
        " VALUES(?,?,?,?,?,?,?)",
        (
            ts,
            "partial" if snapshot["errors"] else "ok",
            digest,
            json.dumps(dict(counts), sort_keys=True),
            json.dumps(snapshot["sources"], sort_keys=True),
            duration_ms,
            _clip("\n".join(snapshot["errors"]), 4000),
        ),
    )
    run_id = cur.lastrowid
    conn.executemany(
        "INSERT OR REPLACE INTO network_items(run_id,kind,item,value)"
        " VALUES(?,?,?,?)",
        [(run_id, kind, item, value) for (kind, item), value in sorted(items.items())],
    )
    conn.executemany(
        "INSERT OR REPLACE INTO network_metrics(run_id,scope,metric,value)"
        " VALUES(?,?,?,?)",
        [(run_id, scope, metric, value) for (scope, metric), value in sorted(metrics.items())],
    )
    diffs = (
        _diff_items(ts, run_id, previous_items, items)
        if previous_id is not None else []
    )
    conn.executemany(
        "INSERT INTO network_diffs(ts,run_id,kind,change,item,old_value,new_value)"
        " VALUES(?,?,?,?,?,?,?)",
        diffs,
    )

    findings = snapshot["findings"] + _findings(
        conn, ts, items, metrics, previous_items, previous_metrics
    )
    active = {finding["fingerprint"] for finding in findings}
    for row in conn.execute(
        "SELECT id, fingerprint FROM findings "
        "WHERE rule LIKE 'network.%' AND status='open'"
    ):
        if row["fingerprint"] not in active:
            conn.execute(
                "UPDATE findings SET status='resolved' WHERE id=?", (row["id"],)
            )
    new = []
    for finding in findings:
        created = detect.upsert(conn, finding)
        if created:
            new.append(created)

    next_ts = (utcnow() + timedelta(
        seconds=config.NETWORK_INTERVAL_S
    )).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.meta_set(conn, "last_network_ts", ts)
    db.meta_set(conn, "last_network_id", str(run_id))
    db.meta_set(conn, "last_network_digest", digest)
    db.meta_set(conn, "next_network_ts", next_ts)

    severity_counts: dict[str, int] = {}
    for finding in new:
        severity_counts[finding["severity"]] = (
            severity_counts.get(finding["severity"], 0) + 1
        )
    return {
        "run_id": run_id,
        "ts": ts,
        "status": "partial" if snapshot["errors"] else "ok",
        "digest": digest,
        "counts": dict(counts),
        "sources": snapshot["sources"],
        "errors": snapshot["errors"],
        "duration_ms": duration_ms,
        "previous_run": previous_id,
        "next_ts": next_ts,
        "diffs": diffs,
        "new": len(new),
        "by_severity": severity_counts,
        "findings": new,
    }


def latest(conn) -> dict:
    row = conn.execute("SELECT * FROM network_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return {}
    run = dict(row)
    for key in ("counts", "sources"):
        try:
            run[key] = json.loads(run.get(key) or "{}")
        except (TypeError, ValueError):
            run[key] = {}
    return {
        "run": run,
        "items": [
            dict(r) for r in conn.execute(
                "SELECT kind, item, value FROM network_items WHERE run_id=? "
                "ORDER BY kind, item",
                (run["id"],),
            )
        ],
        "metrics": [
            dict(r) for r in conn.execute(
                "SELECT scope, metric, value FROM network_metrics WHERE run_id=? "
                "ORDER BY scope, metric",
                (run["id"],),
            )
        ],
        "diffs": [
            dict(r) for r in conn.execute(
                "SELECT kind, change, item, old_value, new_value FROM network_diffs "
                "WHERE run_id=? ORDER BY kind, item",
                (run["id"],),
            )
        ],
    }


def evidence(conn) -> dict:
    """Return the latest snapshot with identities removed for a bundle."""
    data = latest(conn)
    if not data:
        return {}
    for item in data.get("items", []):
        kind = item.get("kind") or ""
        name = item.get("item") or ""
        value = redact(item.get("value") or "")
        if kind == "dns" and (
            "/domain/" in name or name.startswith("resolv_conf/search/")
        ):
            value = "<domain>"
        item["item"] = redact(name)
        item["value"] = value
    for diff in data.get("diffs", []):
        kind = diff.get("kind") or ""
        name = diff.get("item") or ""
        old = redact(diff.get("old_value") or "")
        new = redact(diff.get("new_value") or "")
        if kind == "dns" and (
            "/domain/" in name or name.startswith("resolv_conf/search/")
        ):
            old = new = "<domain>"
        diff["item"] = redact(name)
        diff["old_value"] = old
        diff["new_value"] = new
    data["run"]["detail"] = redact(data["run"].get("detail") or "")
    return data


def availability() -> dict:
    """Report collector availability without writing to the database."""
    tools = {
        name: bool(_which(name)) for name in (
            "ip", "ss", "systemctl", "resolvectl", "nmcli", "iw", "wg",
            "nft", "iptables-save", "ip6tables-save", "firewall-cmd",
            "tailscale", "netplan",
        )
    }
    checks = {}
    for name, command in (
        ("ip", ["ip", "-j", "addr", "show"]),
        ("ss", ["ss", "-lntupH"]),
    ):
        rc, out, err = run(command, timeout=min(5, config.NETWORK_TIMEOUT_S))
        if name == "ss" and rc != 0:
            rc, out, err = run(["ss", "-lntup"],
                               timeout=min(5, config.NETWORK_TIMEOUT_S))
        checks[name] = {
            "ok": rc == 0,
            "status": _status(rc, err),
            "detail": (err or "")[:160],
            "bytes": len(out or ""),
        }
    return {
        "enabled": config.NETWORK_ENABLE,
        "interval_s": config.NETWORK_INTERVAL_S,
        "tools": tools,
        "checks": checks,
        "ready": checks["ip"]["ok"] and checks["ss"]["ok"],
    }
