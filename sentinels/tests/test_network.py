"""Tests for the read-only network and connectivity tier."""
import json
import sqlite3
import unittest
from unittest import mock

from sentinels import db, network
from sentinels.util import redact


class ListenerParserTests(unittest.TestCase):
    def test_local_address_is_not_the_send_queue(self):
        text = (
            'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
            'tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=2,fd=4))\n'
            'tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1,fd=5))\n'
        )
        listeners = network.parse_ss_listeners(text)
        self.assertEqual(
            {(item["proto"], item["local"], item["process"]) for item in listeners},
            {
                ("tcp", "0.0.0.0:22", "sshd"),
                ("tcp", "127.0.0.1:631", "cupsd"),
                ("tcp", "[::]:22", "sshd"),
            },
        )
        self.assertEqual(listeners[0]["send_q"], "128")
        self.assertEqual(listeners[0]["port"], 22)

    def test_ipv6_and_zone_endpoints(self):
        text = (
            'tcp LISTEN 0 4096 [fe80::1]%wlp4s0:546 [::]:* users:(("dhcp6",pid=9,fd=1))\n'
            'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("resolve",pid=2,fd=3))\n'
        )
        listeners = network.parse_ss_listeners(text)
        self.assertEqual(listeners[0]["address"], "fe80::1")
        self.assertEqual(listeners[0]["port"], 546)
        self.assertEqual(listeners[0]["scope"], "link")
        self.assertEqual(listeners[1]["address"], "127.0.0.53")
        self.assertEqual(listeners[1]["scope"], "loopback")

    def test_ephemeral_udp_is_filtered_but_service_udp_is_not(self):
        browser = {"proto": "udp", "port": 46112}
        dns = {"proto": "udp", "port": 53}
        self.assertTrue(network._listener_is_ephemeral_udp(browser))
        self.assertFalse(network._listener_is_ephemeral_udp(dns))


class AddressRouteParserTests(unittest.TestCase):
    def test_address_parser_omits_countdown_lifetimes(self):
        data = [{
            "ifname": "wlp4s0",
            "addr_info": [{
                "family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                "scope": "global", "dynamic": True, "valid_life_time": 100,
                "preferred_life_time": 50,
            }],
        }]
        parsed = network.parse_ip_addr_json(json.dumps(data))
        self.assertIn(("wlp4s0", "inet", "192.0.2.10", 24), parsed)
        value = parsed[("wlp4s0", "inet", "192.0.2.10", 24)]
        self.assertIn("dynamic", value)
        self.assertNotIn("life_time", value)

    def test_default_route_is_preserved(self):
        data = [{"dst": "default", "gateway": "192.0.2.1", "dev": "eth0",
                 "protocol": "dhcp", "metric": 100}]
        parsed = network.parse_ip_route_json(json.dumps(data))
        self.assertEqual(parsed["main/default"],
                         "via=192.0.2.1 dev=eth0 metric=100 protocol=dhcp")

    def test_policy_rules_keep_priority_and_table(self):
        data = [{"priority": 100, "from": "all", "table": "main"}]
        parsed = network.parse_ip_rule_json(json.dumps(data))
        self.assertEqual(parsed["100"], "from=all table=main")


class DnsParserTests(unittest.TestCase):
    def test_resolv_conf_comments_and_search(self):
        parsed = network.parse_resolv_conf(
            "# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n"
            "search example.test corp.example\noptions edns0 trust-ad\n"
        )
        self.assertEqual(parsed["nameservers"], ["192.0.2.53", "2001:db8::53"])
        self.assertEqual(parsed["search"], ["example.test", "corp.example"])
        self.assertEqual(parsed["options"], ["edns0", "trust-ad"])

    def test_resolvectl_links_and_protocols(self):
        text = (
            "Global\n"
            "       Protocols: -LLMNR +mDNS\n"
            "resolv.conf mode: stub\n"
            "\n"
            "Link 4 (wlp4s0)\n"
            "    Current Scopes: DNS\n"
            "         Protocols: +DefaultRoute -mDNS\n"
            "Current DNS Server: 192.0.2.53\n"
            "       DNS Servers: 192.0.2.53 2001:db8::53\n"
            "       DNS Domain: example.test\n"
        )
        parsed = network.parse_resolvectl_status(text)
        self.assertEqual(parsed["resolv_conf_mode"], "stub")
        link = parsed["links"]["wlp4s0"]
        self.assertEqual(link["scopes"], "DNS")
        self.assertEqual(link["current_dns"], "192.0.2.53")
        self.assertEqual(link["dns"], ["192.0.2.53", "2001:db8::53"])
        self.assertEqual(link["domains"], ["example.test"])


class CounterParserTests(unittest.TestCase):
    def test_proc_net_dev(self):
        text = (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|"
            "bytes    packets errs drop fifo colls carrier compressed\n"
            "  eth0: 100 2 1 0 0 0 0 0 200 3 0 0 0 0 0 0\n"
        )
        parsed = network.parse_proc_net_dev(text)
        self.assertEqual(parsed["eth0"]["rx_bytes"], 100)
        self.assertEqual(parsed["eth0"]["rx_errors"], 1)
        self.assertEqual(parsed["eth0"]["tx_packets"], 3)

    def test_tcp_counters(self):
        text = (
            "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens "
            "AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs\n"
            "Tcp: 1 200 120000 -1 10 20 1 2 3 100 200 4\n"
        )
        parsed = network.parse_snmp(text)
        self.assertEqual(parsed["tcp/OutSegs"], 200)
        self.assertEqual(parsed["tcp/RetransSegs"], 4)

    def test_neighbour_summary_keeps_counts_not_addresses(self):
        data = [
            {"dst": "192.0.2.1", "dev": "eth0", "lladdr": "aa:bb:cc:dd:ee:ff",
             "state": ["REACHABLE"]},
            {"dst": "192.0.2.2", "dev": "eth0", "state": ["STALE"]},
        ]
        parsed = network.parse_ip_neigh_json(json.dumps(data))
        self.assertEqual(parsed["count"], 2)
        self.assertEqual(parsed["devices"]["eth0"], 2)
        self.assertEqual(parsed["states"]["REACHABLE"], 1)
        self.assertNotIn("192.0.2.1", json.dumps(parsed))


class TunnelAndWifiParserTests(unittest.TestCase):
    def test_wireguard_dump_fields(self):
        text = (
            "private-public\tlisten\t51820\toff\n"
            "peer-public\t(none)\t192.0.2.5:51820\t10.0.0.2/32\t"
            "1700000000\t1000\t2000\toff\n"
        )
        parsed = network.parse_wg_dump(text)
        self.assertEqual(parsed["listen_port"], 51820)
        self.assertEqual(parsed["peers"][0]["allowed_ips"], ["10.0.0.2/32"])
        self.assertEqual(parsed["peers"][0]["rx_bytes"], 1000)
        self.assertEqual(parsed["peers"][0]["tx_bytes"], 2000)

    def test_wifi_parser(self):
        text = (
            "Connected to 1c:b0:44:14:b2:a8 (on wlp4s0)\n"
            "        SSID: HomeNet\n"
            "        freq: 5180.0\n"
            "        signal: -44 dBm\n"
            "        tx bitrate: 866.7 MBit/s VHT-MCS 9\n"
        )
        parsed = network.parse_iw_link(text)
        self.assertEqual(parsed["bssid"], "1c:b0:44:14:b2:a8")
        self.assertEqual(parsed["ssid"], "HomeNet")
        self.assertEqual(parsed["freq_mhz"], 5180.0)
        self.assertEqual(parsed["signal_dbm"], -44.0)
        self.assertEqual(parsed["tx_bitrate_mbps"], 866.7)

    def test_networkmanager_profiles(self):
        text = "uuid-1:802-11-wireless:wlp4s0:activated:yes\n"
        profiles = network.parse_nmcli_connections(text)
        self.assertEqual(profiles[0]["uuid"], "uuid-1")
        self.assertEqual(profiles[0]["state"], "activated")


class FirewallParserTests(unittest.TestCase):
    def test_nft_counts_and_policies(self):
        data = {"nftables": [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "inet", "name": "filter"}},
            {"chain": {"table": "filter", "name": "input", "policy": "drop"}},
            {"rule": {"table": "filter", "chain": "input"}},
        ]}
        parsed = network.parse_nft_json(json.dumps(data))
        self.assertEqual(parsed["tables"], 1)
        self.assertEqual(parsed["chains"], 1)
        self.assertEqual(parsed["rules"], 1)
        self.assertIn("filter/input=drop", parsed["policies"])

    def test_iptables_summary(self):
        text = (
            ":INPUT DROP [0:0]\n"
            ":OUTPUT ACCEPT [0:0]\n"
            "-A INPUT -i lo -j ACCEPT\n"
        )
        parsed = network.parse_iptables_save(text)
        self.assertEqual(parsed["chains"], 2)
        self.assertEqual(parsed["rules"], 1)
        self.assertIn("INPUT=DROP", parsed["policies"])

    def test_dynamic_counters_do_not_change_the_digest(self):
        a = ":INPUT DROP [1:2]\n-A INPUT -j ACCEPT\ncounter packets 5 bytes 7\n"
        b = ":INPUT DROP [9:8]\n-A INPUT -j ACCEPT\ncounter packets 0 bytes 0\n"
        self.assertEqual(network.stable_firewall_text(a),
                         network.stable_firewall_text(b))


class DiffAndFindingTests(unittest.TestCase):
    def test_baseline_diff_and_changes(self):
        current = {("interface", "eth0/operstate"): "up"}
        first = network._diff_items("t", 1, {}, current)
        self.assertEqual(first[0][3], "added")
        previous = dict(current)
        current[("interface", "eth0/operstate")] = "down"
        diffs = network._diff_items("t", 2, previous, current)
        self.assertEqual(diffs[0][3], "changed")

    def test_default_route_loss_is_a_finding(self):
        previous = {
            ("route", "default/main"): "via=192.0.2.1 dev=eth0",
            ("interface", "eth0/operstate"): "up",
            ("interface", "eth0/virtual"): "0",
        }
        current = {
            ("interface", "eth0/operstate"): "up",
            ("interface", "eth0/virtual"): "0",
        }
        findings = network._findings(
            None, "t", current, {}, previous, {}
        )
        self.assertIn("network.route.default_missing",
                      {finding["rule"] for finding in findings})

    def test_virtual_interface_errors_are_ignored(self):
        items = {
            ("interface", "vnet3/virtual"): "1",
            ("interface", "eth0/virtual"): "0",
        }
        previous = {("if/vnet3", "rx_errors"): 0, ("if/eth0", "rx_errors"): 0}
        current = {("if/vnet3", "rx_errors"): 5, ("if/eth0", "rx_errors"): 5}
        findings = network._findings(None, "t", items, current, {}, previous)
        subjects = {finding["subject"] for finding in findings
                    if finding["rule"] == "network.interface.errors"}
        self.assertEqual(subjects, {"eth0"})


class EvidenceTests(unittest.TestCase):
    def _conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        conn.execute(
            "INSERT INTO network_runs(id,ts,status,digest,counts,sources,duration_ms,detail)"
            " VALUES(1,'2026-11-17T00:00:00Z','ok','d','{}','{}',1,'')"
        )
        conn.execute(
            "INSERT INTO network_items(run_id,kind,item,value) VALUES(1,'dns',"
            "'dns/link/wlp4s0/domain/0','home.example')"
        )
        conn.execute(
            "INSERT INTO network_items(run_id,kind,item,value) VALUES(1,'address',"
            "'wlp4s0/inet/192.0.2.10/24','scope=global')"
        )
        conn.execute(
            "INSERT INTO network_items(run_id,kind,item,value) VALUES(1,'interface',"
            "'wlp4s0/mac','aa:bb:cc:dd:ee:ff')"
        )
        conn.execute(
            "INSERT INTO network_items(run_id,kind,item,value) VALUES(1,'listener',"
            "'tcp/0.0.0.0:22','process=sshd scope=wildcard')"
        )
        return conn

    def test_evidence_redacts_domains_addresses_and_macs(self):
        data = network.evidence(self._conn())
        blob = json.dumps(data)
        self.assertNotIn("192.0.2.10", blob)
        self.assertNotIn("home.example", blob)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", blob)
        self.assertIn("<domain>", blob)
        self.assertIn("<ip>", blob)
        self.assertIn("<mac>", blob)

    def test_ipv6_is_redacted_but_times_are_not(self):
        text = redact("peer 2001:db8::1 and ::1 at 12:34:56")
        self.assertNotIn("2001:db8::1", text)
        self.assertNotIn("::1", text)
        self.assertIn("12:34:56", text)


class ScanIntegrationTests(unittest.TestCase):
    def _conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_scan_baseline_then_diff_and_finding(self):
        conn = self._conn()
        base = {
            "items": {
                ("interface", "eth0/operstate"): "up",
                ("interface", "eth0/virtual"): "0",
                ("route", "default/main"): "via=192.0.2.1 dev=eth0",
            },
            "metrics": {},
            "sources": {"listeners": "ok"},
            "errors": [],
            "findings": [],
        }
        with mock.patch.object(network, "collect", return_value=base):
            first = network.scan(conn)
        self.assertEqual(first["diffs"], [])
        self.assertEqual(first["previous_run"], None)

        changed = dict(base)
        changed["items"] = {
            ("interface", "eth0/operstate"): "up",
            ("interface", "eth0/virtual"): "0",
        }
        with mock.patch.object(network, "collect", return_value=changed):
            second = network.scan(conn)
        self.assertEqual(second["previous_run"], first["run_id"])
        self.assertEqual(len(second["diffs"]), 1)
        self.assertIn("network.route.default_missing",
                      {finding["rule"] for finding in second["findings"]})
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM network_runs").fetchone()[0], 2
        )


if __name__ == "__main__":
    unittest.main()
