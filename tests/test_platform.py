"""Cross-platform contract tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import compat, config, db, platform, platform_cycle
from sentinels.platform.base import Capability, Snapshot
from sentinels.platform import findings
from sentinels.platform.macos import MacOSBackend
from sentinels.platform.windows import WindowsBackend
from sentinels.platform_cycle import _platform_findings


class PlatformContractTest(unittest.TestCase):
    def test_detect_returns_a_backend(self):
        backend = platform.detect()
        self.assertIn(backend.name, {"linux", "windows", "macos"})
        self.assertTrue(backend.family)
        self.assertTrue(backend.display)

    def test_linux_host_and_capabilities(self):
        backend = platform.detect()
        host = backend.host_info()
        self.assertIn("system", host)
        self.assertIn("python", host)
        caps = backend.capabilities()
        for area in ("host", "python", "sqlite", "processes", "network"):
            self.assertIn(area, caps)
            self.assertIn(caps[area].status,
                          {"supported", "degraded", "needs_permission", "planned"})

    def test_every_family_has_both_platform_equivalents(self):
        for family in findings.matrix():
            self.assertTrue(family["windows"], family["prefix"])
            self.assertTrue(family["macos"], family["prefix"])
            self.assertIn(family["status"], {"ported", "degraded", "planned"})

    def test_known_rules_map_to_windows_and_macos(self):
        for rule in (
            "hardware.storage.smart",
            "network.route.default_missing",
            "lsm.selinux.permissive",
            "crash.faultcore",
            "faultcore.topology.changed",
            "memory.oom",
            "security.root_user_path",
        ):
            data = findings.equivalent(rule)
            self.assertTrue(data["windows"], rule)
            self.assertTrue(data["macos"], rule)

    def test_unknown_rule_is_not_dropped(self):
        data = findings.equivalent("custom.rule")
        self.assertEqual(data["prefix"], "custom")
        self.assertIn("unassigned", data["windows"])
        self.assertIn("unassigned", data["macos"])

    def test_windows_and_macos_capability_contracts(self):
        for backend in (WindowsBackend(), MacOSBackend()):
            caps = backend.capabilities()
            for area in ("processes", "services", "network", "security",
                         "crashes", "updates", "hardware", "storage"):
                self.assertIn(area, caps)
                self.assertIn(caps[area].status,
                              {"supported", "degraded", "needs_permission", "planned"})

    def test_windows_security_snapshot_becomes_findings(self):
        findings = _platform_findings("windows", {
            "security": {
                "defender": {"AntivirusEnabled": False,
                             "RealTimeProtectionEnabled": False},
                "firewall": [{"Name": "Domain", "Enabled": False}],
                "bitlocker": [{"MountPoint": "C:", "ProtectionStatus": "Off"}],
                "tpm": {"TpmReady": False},
            },
            "crashes": [{"id": 1001, "provider": "BugCheck",
                         "message": "bugcheck"}],
        })
        rules = {item["rule"] for item in findings}
        self.assertIn("security.defender_disabled", rules)
        self.assertIn("security.firewall_disabled", rules)
        self.assertIn("security.bitlocker_off", rules)
        self.assertIn("security.tpm_not_ready", rules)
        self.assertIn("crash.bugcheck", rules)

    def test_macos_security_snapshot_becomes_findings(self):
        findings = _platform_findings("macos", {
            "security": {
                "gatekeeper": "assessments disabled",
                "sip": "System Integrity Protection status: disabled.",
                "filevault": "FileVault is Off.",
                "firewall": "Firewall is disabled. (State = 0)",
            },
            "crashes": [{"name": "foo.ips", "path": "/tmp/foo.ips"}],
        })
        rules = {item["rule"] for item in findings}
        self.assertIn("security.gatekeeper_disabled", rules)
        self.assertIn("security.sip_disabled", rules)
        self.assertIn("security.filevault_off", rules)
        self.assertIn("security.firewall_disabled", rules)
        self.assertIn("crash.report", rules)

    def test_platform_cycle_persists_snapshot_and_findings(self):
        class FakeBackend:
            name = "windows"
            def collect(self):
                return Snapshot("windows", host={"hostname": "test"},
                                capabilities={"host": Capability("host", "supported", "test")},
                                data={
                                    "processes": [{"pid": 1, "name": "init"}],
                                    "security": {
                                        "defender": {
                                            "AntivirusEnabled": False,
                                            "RealTimeProtectionEnabled": True,
                                        },
                                    },
                                })

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "sentinels.db"
            with mock.patch.object(config, "DB_PATH", db_path):
                db.init()
                with db.session() as conn:
                    result = platform_cycle.run(conn, backend=FakeBackend())
                    self.assertEqual(result["platform"], "windows")
                    self.assertGreaterEqual(result["processes"], 1)
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM platform_snapshots").fetchone()[0], 1)
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 1)

    def test_compat_report_still_has_a_platform_shape(self):
        report = compat.report()
        self.assertIn("supported", report)
        self.assertIn("checks", report)
        self.assertIn("summary", report)


if __name__ == "__main__":
    unittest.main()
