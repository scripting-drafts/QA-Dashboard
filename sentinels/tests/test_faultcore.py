"""Tests for fault-core topology and ticket presence reporting."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import config, faultcore, report, tickets


class ConfigParsingTests(unittest.TestCase):
    def test_faultlab_config_is_parsed_as_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config"
            path.write_text(
                "# generated\n"
                "FAULT_CPU=3\n"
                "FAULT_CPUS=3,9\n"
                "CONTROL_CPUS=1-2,7\n"
                "IGNORED='quoted'\n"
            )
            values = config._faultlab_values(path)
        self.assertEqual(values["FAULT_CPU"], "3")
        self.assertEqual(values["FAULT_CPUS"], "3,9")
        self.assertEqual(values["IGNORED"], "quoted")

    def test_cpu_tuple_accepts_ranges(self):
        self.assertEqual(config._cpu_tuple("0-1,3,8-9"), (0, 1, 3, 8, 9))

    def test_missing_faultlab_config_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                config._faultlab_values(Path(tmp) / "missing"),
                {},
            )


class StandaloneIntegrationTests(unittest.TestCase):
    def test_disabled_integration_is_explicit(self):
        with mock.patch.object(config, "FAULT_CORE_ENABLE", False), \
             mock.patch.object(config, "FAULT_CORE_CPUS", ()):
            state = faultcore.integration_state()
            self.assertIn("disabled", state)
            self.assertIn("optional", state)
            topo = faultcore.topology()
            self.assertEqual(topo["state"], "unconfigured")
            self.assertIn("not configured", faultcore.presence(topo))
            self.assertEqual(faultcore.findings(None), [])
            section = report._faultcore_section(None, "2026-01-01T00:00:00Z")
            self.assertIn("Fault-core integration", section)
            self.assertIn("disabled", section)

    def test_disabled_by_configuration_with_cpus(self):
        with mock.patch.object(config, "FAULT_CORE_ENABLE", False), \
             mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8)):
            self.assertEqual(
                faultcore.integration_state(),
                "disabled by configuration",
            )

    def test_enabled_without_cpus(self):
        with mock.patch.object(config, "FAULT_CORE_ENABLE", True), \
             mock.patch.object(config, "FAULT_CORE_CPUS", ()):
            self.assertIn("no fault CPUs", faultcore.integration_state())
            self.assertEqual(faultcore.findings(None), [])

    def test_auto_detection_without_faultlab_config(self):
        repo = Path(__file__).resolve().parents[1]
        base = {
            key: value for key, value in os.environ.items()
            if key not in {
                "QA_FAULT_CORE_CPUS", "QA_FAULT_CPUS", "QA_CORE2_CPUS",
                "QA_FAULT_CORE_ENABLE", "QA_FAULT_CORE_ENFORCE",
            }
        }
        base.update({
            "PYTHONPATH": str(repo),
            "PYTHONDONTWRITEBYTECODE": "1",
            "QA_SENTINELS_HOME": str(repo),
            "QA_FAULTLAB_CONFIG": "/nonexistent",
            "QA_FAULT_CORE_ENABLE": "auto",
        })
        code = (
            "from sentinels import config; "
            "print(config.FAULT_CORE_ENABLE, config.FAULT_CORE_CPUS)"
        )

        def run(extra):
            env = dict(base)
            env.update(extra)
            return subprocess.check_output(
                [sys.executable, "-c", code],
                cwd=repo, env=env, text=True,
            ).strip()

        self.assertEqual(run({}), "False ()")
        self.assertEqual(run({"QA_FAULT_CORE_CPUS": "2,8"}), "True (2, 8)")
        self.assertEqual(
            run({"QA_FAULT_CORE_CPUS": "2,8", "QA_FAULT_CORE_ENABLE": "0"}),
            "False (2, 8)",
        )


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self._cpus = mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8))
        self._cpus.start()
        self._physical = mock.patch.object(config, "FAULT_CORE_PHYSICAL_ID", None)
        self._physical.start()
        self._enforce = mock.patch.object(config, "FAULT_CORE_ENFORCE", "auto")
        self._enforce.start()

    def tearDown(self):
        self._enforce.stop()
        self._physical.stop()
        self._cpus.stop()

    def _cpu(self, root: Path, number: int, core: int, package: int = 0,
             siblings: str | None = None):
        path = root / f"cpu{number}" / "topology"
        path.mkdir(parents=True)
        (path / "core_id").write_text(str(core))
        (path / "physical_package_id").write_text(str(package))
        if siblings is not None:
            (path / "thread_siblings_list").write_text(siblings)

    def _offline(self, root: Path, number: int):
        path = root / f"cpu{number}"
        path.mkdir(parents=True)
        (path / "online").write_text("0")

    def _mode(self, root: Path, mode: str) -> Path:
        path = root / "mode"
        path.write_text(mode)
        return path

    def test_faultcore_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 2, 2, siblings="2,8")
            self._cpu(root, 8, 2, siblings="2,8")
            self._cpu(root, 3, 3)
            topo = faultcore.topology(root)
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "present")
        self.assertEqual(topo["logical"], [2, 8])
        self.assertEqual(topo["physical_id"], 2)
        self.assertEqual(topo["physical_cores"], 4)
        self.assertEqual(topo["logical_cpus"], 5)

    def test_faultcore_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 3)
            topo = faultcore.topology(root)
        self.assertFalse(topo["present"])
        self.assertEqual(topo["state"], "absent")
        self.assertEqual(topo["logical"], [])

    def test_topology_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            topo = faultcore.topology(Path(tmp))
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "unknown")

    def test_retired_core_is_undetermined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 3)
            self._offline(root, 2)
            self._offline(root, 8)
            topo = faultcore.topology(root, mode_path=self._mode(root, "retired"))
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "retired")
        self.assertIsNone(topo["physical_id"])
        self.assertEqual(topo["degraded"], [2, 8])
        self.assertEqual(topo["logical"], [])
        self.assertEqual(topo["source"], "faultlab-retired")

    def test_offline_core_outside_retired_mode_is_undetermined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._offline(root, 2)
            self._offline(root, 8)
            topo = faultcore.topology(root, mode_path=self._mode(root, "lab"))
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "offline")

    def test_partial_offline_core_uses_sibling_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 8, 2, siblings="2,8")
            self._offline(root, 2)
            topo = faultcore.topology(root, mode_path=self._mode(root, "retired"))
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "present")
        self.assertEqual(topo["logical"], [2, 8])
        self.assertEqual(topo["physical_id"], 2)
        self.assertEqual(topo["degraded"], [2])

    def test_non_two_fault_core_is_derived_from_sysfs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 4, siblings="3,9")
            self._cpu(root, 9, 4, siblings="3,9")
            with mock.patch.object(config, "FAULT_CORE_CPUS", (3, 9)):
                topo = faultcore.topology(root, mode_path=self._mode(root, "lab"))
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "present")
        self.assertEqual(topo["physical_id"], 4)
        self.assertEqual(topo["logical"], [3, 9])

    def test_split_core_mapping_is_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 2, 2)
            self._cpu(root, 8, 3)
            topo = faultcore.topology(root, mode_path=self._mode(root, "lab"))
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "changed")
        self.assertIsNone(topo["physical_id"])
        self.assertEqual(topo["logical"], [2, 8])

    def test_unconfigured_core_is_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            with mock.patch.object(config, "FAULT_CORE_CPUS", ()):
                topo = faultcore.topology(root)
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "unconfigured")
        self.assertEqual(topo["configured"], [])

    def test_labels(self):
        present = {"present": True, "state": "present", "logical": [2, 8],
                   "physical_cores": 6, "logical_cpus": 12, "physical_id": 2,
                   "configured": [2, 8]}
        absent = {"present": False, "state": "absent", "logical": [],
                  "physical_cores": 4, "logical_cpus": 8, "physical_id": None,
                  "configured": [2, 8]}
        unknown = {"present": None, "state": "unknown", "logical": [],
                   "physical_id": None, "configured": [2, 8]}
        retired = {"present": None, "state": "retired", "logical": [],
                   "physical_id": None, "configured": [2, 8]}
        self.assertIn("present", faultcore.presence(present))
        self.assertIn("absent", faultcore.presence(absent))
        self.assertIn("unknown", faultcore.presence(unknown))
        self.assertIn("retired", faultcore.presence(retired))
        self.assertIn("undetermined", faultcore.presence(retired))
        self.assertEqual(faultcore.theme_tag(present), "physical core 2 present")
        self.assertEqual(faultcore.theme_tag(absent), "fault core (CPUs 2,8) absent")
        self.assertIn("undetermined", faultcore.theme_tag(retired))
        self.assertEqual(faultcore.cpu_set(present), "2, 8")
        self.assertEqual(
            faultcore.presence_summary(present),
            "present (CPUs: 2, 8 online)")
        configured_only = dict(present, logical=[2, 8], configured=[2])
        self.assertEqual(faultcore.cpu_set(configured_only), "2")
        self.assertEqual(
            faultcore.presence_summary(configured_only),
            "present (CPUs: 2 online)")


class EventMatchingTests(unittest.TestCase):
    def test_event_matching_uses_the_configured_core(self):
        from sentinels import triage

        with mock.patch.object(config, "FAULT_CORE_CPUS", (3, 9)), \
             mock.patch.object(config, "FAULT_CORE_PHYSICAL_ID", 4):
            self.assertTrue(triage.event_is_faultcore("CPU 3: Machine Check"))
            self.assertTrue(triage.event_is_faultcore("physical core 4 failed"))
            self.assertFalse(triage.event_is_faultcore("CPU 2: Machine Check"))


class TicketThemeTests(unittest.TestCase):
    def setUp(self):
        self._cpus = mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8))
        self._cpus.start()

    def tearDown(self):
        self._cpus.stop()

    def _issue(self):
        return {
            "key": "faultcore", "vendor": "hardware",
            "signature": "crashes correlated with fault-core affinity",
            "display": "crashes correlated with fault-core affinity",
            "kind": "correlation", "count": 1, "severity": "critical",
            "first": "2026-11-07T00:00:00Z", "last": "2026-11-07T00:00:00Z",
            "rows": [{
                "ts": "2026-11-07T00:00:00Z", "comm": "firefox-esr",
                "sig": "SIGSEGV", "cpus_allowed": "2,8", "faultcore_involved": 1,
            }],
        }

    def _present(self):
        return {"present": True, "state": "present", "logical": [2, 8],
                "physical_cores": 6, "logical_cpus": 12, "physical_id": 2,
                "configured": [2, 8], "degraded": []}

    def _absent(self):
        return {"present": False, "state": "absent", "logical": [],
                "physical_cores": 4, "logical_cpus": 8, "physical_id": None,
                "configured": [2, 8], "degraded": []}

    def _retired(self):
        return {"present": None, "state": "retired", "logical": [],
                "physical_id": None, "configured": [2, 8], "degraded": [2, 8]}

    def _offline(self):
        return {"present": None, "state": "offline", "logical": [],
                "physical_id": None, "configured": [2, 8], "degraded": [2, 8]}

    def test_title_and_environment_state_presence(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._present()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[physical core 2 present]", title)
        self.assertIn("- Physical core 2: present", body)
        self.assertIn(
            "## Physical core 2 correlation — present (CPUs: 2, 8 online)", body)
        self.assertIn("`2,8`", body)
        self.assertIn("Reproduction viability: **~70%**", body)
        self.assertNotIn("DRAFT ONLY", body)
        self.assertNotIn("Remove nothing", body)

    def test_title_and_environment_state_absence(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._absent()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[fault core (CPUs 2,8) absent]", title)
        self.assertIn("- Fault core (CPUs 2,8): absent", body)
        self.assertIn("## Fault core (CPUs 2,8) correlation — absent", body)
        self.assertNotIn("fault-core comparison was absent", body)
        self.assertIn("Reproduction viability: **~35%**", body)

    def test_title_and_environment_state_retired(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._retired()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[fault core (CPUs 2,8) retired (undetermined)]", title)
        self.assertNotIn("offline", body.lower())
        self.assertNotIn("is not available", body)
        self.assertNotIn("CPUs: 2, 8", body.split("## Reproduction")[0])
        self.assertNotIn("- Fault core (CPUs 2,8): retired", body)
        self.assertNotIn("## Fault core (CPUs 2,8) correlation", body)
        self.assertNotIn("fault-core comparison was undetermined", body)
        self.assertIn("Reproduction viability: **~20%**", body)
        self.assertNotIn("Use one available core as the control", body)

    def test_title_and_environment_state_offline(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._offline()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertNotIn("offline", title.lower())
        self.assertNotIn("offline", body.lower())
        self.assertNotIn("is not available", body)
        self.assertNotIn("CPUs: 2, 8", body.split("## Reproduction")[0])
        self.assertNotIn("## Fault core (CPUs 2,8) correlation", body)
        self.assertIn("Reproduction viability: **~20%**", body)

    def test_non_default_configured_cpus_drive_the_labels(self):
        present = {"present": True, "state": "present", "logical": [4, 10],
                   "physical_cores": 6, "logical_cpus": 12, "physical_id": 4,
                   "configured": [4, 10], "degraded": []}
        with mock.patch.object(tickets.faultcore, "topology", return_value=present):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[physical core 4 present]", title)
        self.assertIn(
            "## Physical core 4 correlation — present (CPUs: 4, 10 online)", body)
        self.assertIn("`4,10`", body)
        self.assertNotIn("core 2", body.lower())

        retired = {"present": None, "state": "retired", "logical": [],
                   "physical_id": None, "configured": [4, 10],
                   "degraded": [4, 10]}
        with mock.patch.object(tickets.faultcore, "topology", return_value=retired):
            _, body = tickets._draft(self._issue(), None, {}, False)
        self.assertNotIn("offline", body.lower())
        self.assertNotIn("fault core (cpus 4,10) is not available", body.lower())
        self.assertNotIn("CPUs: 4, 10", body.split("## Reproduction")[0])
        self.assertNotIn("core 2", body.lower())


if __name__ == "__main__":
    unittest.main()
