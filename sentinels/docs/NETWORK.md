# Network and connectivity tier

The network tier is a read-only snapshot of host networking. It never sends a
probe packet, changes configuration, captures traffic, or stores credentials.
External commands use fixed argv and timeouts.

## Readings

| Area | What is recorded | Source |
| --- | --- | --- |
| Connectivity targets | `network.target` and `network-online.target` state; networkd oper/admin state, DNS and NTP | `systemctl is-active`, `/run/systemd/netif/state` |
| Interfaces | index, type, operstate, carrier, MTU, MAC, flags, speed/duplex, driver, physical/virtual, wireless flag | `/sys/class/net/*` |
| Addresses | IPv4/IPv6 address, prefix, scope, label, address flags and peer | `ip -j addr show` |
| Routes | every table entry, default routes per table, policy rules | `ip -j route show table all`, `ip -j rule show` |
| DNS | `/etc/resolv.conf` digest, nameservers, search and options; per-link resolved scopes, protocols, current/upstream servers and domains | `/etc/resolv.conf`, `resolvectl status` |
| Netplan | file name, hash, size, mtime, mode; config files are never copied | `/etc/netplan/*.yaml` |
| NetworkManager | general state/connectivity, profile UUID/type/device/state/autoconnect (no profile names or secrets) | `nmcli` |
| Wi-Fi | link quality, signal/noise, SSID hash and length, BSSID hash, frequency, bitrate | `/proc/net/wireless`, `iw dev <if> link` |
| Tunnels | WireGuard interfaces/peers, listen ports, hashed peer keys/endpoints, handshake age and transfer counters; OpenVPN units; tailscale backend/peer count; tun/tap/wg interface state | `wg`, `systemctl`, `ip`, `tailscale` |
| Firewall | nftables/iptables rule counts, chain policies and ruleset digest; UFW enabled/service; firewalld state/zone | `nft -j list ruleset`, `iptables-save`, UFW config, `firewall-cmd` |
| Conntrack | current/max entries and usage percentage | `/proc/sys/net/netfilter/*` |
| Neighbours | counts by state and device, never addresses or MACs | `ip -j neigh show` |
| Listeners | TCP and non-ephemeral UDP sockets with local address, port, scope and process; ephemeral UDP and Unix sockets as counts | `ss -lntupH`, `ss -lxH` |
| Counters | per-interface rx/tx bytes, packets, errors, drops, collisions and derived KiB/s; TCP/UDP and IP counters; socket statistics | `/sys/class/net/*/statistics`, `/proc/net/snmp`, `/proc/net/netstat` |
| Namespaces | named network namespaces and total namespace count | `/run/netns`, `/proc/<pid>/ns/net` |
| Sysctls | full `net.*` tree digest and count; security/reliability keys stored individually | `/proc/sys/net` |

The previous listener parser used the `ss` Send-Q column as the endpoint. That
is fixed: sockets now key on protocol and local address:port, so two listeners
with the same queue size no longer collapse into one row. Listener rows moved
from the software inventory (`L2-services`) to the network tables.

Raw `nft`/`iptables` rules require root. When the unprivileged operator cannot
read them, the source is recorded as `needs-root`; UFW/firewalld state and
counts still provide a firewall summary. Process attribution for root-owned
listening sockets is best effort for the same reason.

## Commands

```bash
./bin/qa network collect   # take a snapshot and record findings
./bin/qa network show      # latest run, counts, sources and changes
./bin/qa network show --full
./bin/qa network check     # tool/permission availability (no write)
./bin/qa query --category network-items --limit 50
./bin/qa query --category network-metrics --limit 50
```

The cycle runs the tier every `QA_NETWORK_INTERVAL_S` (default 300 s) and keeps
runs for `QA_NETWORK_RETENTION_DAYS` (default 14; `0` keeps them forever). Set
`QA_NETWORK_ENABLE=0` to disable it.

## Findings

High-signal rules only:

- `network.interface.down` — a physical uplink or addressed interface loses carrier.
- `network.route.default_missing` — the default route disappears.
- `network.vpn.down` — a tunnel interface disappears or drops out of `up`.
- `network.interface.errors` — error counters increase on a physical interface.
- `network.tcp.retrans` — retransmission ratio exceeds the configured threshold.
- `network.conntrack.high` — conntrack usage exceeds the threshold.
- `network.dns.no_upstream` — a default route exists but no upstream DNS is configured.
- `network.firewall.ufw_inactive` — UFW is enabled but its service is not active.
- `network.firewall.disabled` — `QA_NETWORK_FIREWALL_REQUIRED=1` and no active firewall.
- `network.netplan.permissions` — a Netplan file is group/world readable.

## Privacy

SSID, BSSID, WireGuard public keys and peer endpoints are hashed before storage.
Evidence bundles redact IP addresses (IPv4 and IPv6), MAC addresses, UUIDs and
DNS search/domain values. NetworkManager profile names and secrets are never
read. `nft`/`iptables` raw rules are hashed, not stored.
