"""Probe admission policy: presets, overrides and readiness gating."""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest
from contextlib import contextmanager
from unittest import mock

from sentinels import config, hardware, policy


ENV_KEYS = (
    "QA_PROBE_POLICY",
    "QA_PROBE_PROFILE",
    "QA_PROBE_READY_MODE",
    "QA_PROBE_READY_TARGET",
    "QA_PROBE_READY_MAX_S",
    "QA_PROBE_READY_SETTLE_S",
    "QA_PROBE_ADAPTIVE",
    "QA_PROBE_ADMISSION",
    "QA_PROBE_DEFER",
    "QA_PROBE_GATE",
)

MISSING = pathlib.Path("/nonexistent/probe-policy.json")


@contextmanager
def environment(**values):
    with mock.patch.dict(os.environ, {}, clear=False), \
         mock.patch.object(policy, "POLICY_FILE", MISSING):
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        for key, value in values.items():
            os.environ[key] = str(value)
        policy.reset()
        try:
            yield
        finally:
            policy.reset()


def runtime(uptime: str = "10.0", active_rc: int = 3,
            running: str = "starting", boot_id: str = "boot-1",
            ready_since_s: float | None = None):
    def fake_run(cmd, timeout=20):
        if cmd[:2] == ["systemctl", "is-active"]:
            return active_rc, "", ""
        if cmd[:2] == ["systemctl", "is-system-running"]:
            return (0 if running in ("running", "degraded") else 1), running + "\n", ""
        if cmd[:2] == ["systemctl", "show"]:
            if ready_since_s is None:
                return 1, "", ""
            return 0, str(int(ready_since_s * 1_000_000)), ""
        raise AssertionError(cmd)

    def fake_read(path, default=""):
        if str(path) == "/proc/uptime":
            return uptime
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return boot_id
        return default

    return mock.patch.multiple(policy, run=fake_run, read_text=fake_read)


@contextmanager
def meta_store():
    store: dict[str, str] = {}

    def get(_conn, key, default=None):
        return store.get(key, default)

    def put(_conn, key, value):
        store[key] = value

    with mock.patch.multiple(policy.db, meta_get=get, meta_set=put):
        yield store


class PolicyResolutionTests(unittest.TestCase):
    def test_adaptive_is_the_default(self):
        with environment():
            eff = policy.effective()
        self.assertEqual(eff["preset"], "adaptive")
        self.assertEqual(eff["readiness_mode"], "target")
        self.assertEqual(eff["readiness_target"], "multi-user.target")
        self.assertEqual(eff["admission_mode"], "defer")

    def test_presets_differ(self):
        with environment(QA_PROBE_POLICY="strict"):
            strict = policy.effective()
        self.assertFalse(strict["readiness_adaptive"])
        self.assertEqual(strict["admission_mode"], "defer")
        with environment(QA_PROBE_POLICY="balanced"):
            balanced = policy.effective()
        self.assertFalse(balanced["readiness_adaptive"])
        with environment(QA_PROBE_POLICY="permissive"):
            permissive = policy.effective()
        self.assertEqual(permissive["admission_mode"], "allow")

    def test_environment_overrides_the_preset(self):
        with environment(
            QA_PROBE_POLICY="strict",
            QA_PROBE_READY_MAX_S="600",
            QA_PROBE_ADMISSION="allow",
            QA_PROBE_DEFER="hardware",
        ):
            eff = policy.effective()
        self.assertEqual(eff["preset"], "strict")
        self.assertEqual(eff["readiness_max_wait_s"], 600)
        self.assertEqual(eff["admission_mode"], "allow")
        self.assertEqual(eff["defer"], ("hardware",))

    def test_bounds_and_invalid_values_fall_back(self):
        with environment(QA_PROBE_READY_MAX_S="99999",
                         QA_PROBE_READY_MODE="nonsense"):
            eff = policy.effective()
        self.assertEqual(eff["readiness_max_wait_s"], 1800)
        self.assertEqual(eff["readiness_mode"], "target")
        with environment(QA_PROBE_READY_MAX_S="-5"):
            self.assertEqual(
                policy.effective()["readiness_max_wait_s"], 0)

    def test_gate_switch_forces_permissive_admission(self):
        with environment(QA_PROBE_GATE="0", QA_PROBE_POLICY="adaptive"):
            eff = policy.effective()
        self.assertEqual(eff["admission_mode"], "allow")

    def test_settings_whitelist_accepts_the_policy_keys(self):
        self.assertIn("adaptive", config.SETTINGS_ENUM_VALUES["QA_PROBE_POLICY"])
        self.assertIn("target", config.SETTINGS_ENUM_VALUES["QA_PROBE_READY_MODE"])


class PolicyFileTests(unittest.TestCase):
    def _write(self, data) -> pathlib.Path:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        with handle:
            json.dump(data, handle)
        self.addCleanup(os.unlink, handle.name)
        return pathlib.Path(handle.name)

    def test_file_values_and_profiles_apply(self):
        path = self._write({
            "schema": 1,
            "preset": "balanced",
            "readiness": {"max_wait_s": 120},
            "admission": {"defer": ["hardware"]},
            "profiles": {
                "slow": {
                    "readiness": {"max_wait_s": 900},
                    "admission": {"defer": ["hardware", "network"]},
                }
            },
        })
        with environment():
            with mock.patch.object(policy, "POLICY_FILE", path):
                plain = policy.effective(refresh=True)
                os.environ["QA_PROBE_PROFILE"] = "slow"
                slow = policy.effective(refresh=True)
        self.assertEqual(plain["readiness_max_wait_s"], 120)
        self.assertEqual(plain["defer"], ("hardware",))
        self.assertEqual(slow["readiness_max_wait_s"], 900)
        self.assertEqual(slow["defer"], ("hardware", "network"))

    def test_unknown_profile_is_reported(self):
        path = self._write({"schema": 1, "profiles": {"fast": {}}})
        with environment(QA_PROBE_PROFILE="missing"):
            with mock.patch.object(policy, "POLICY_FILE", path):
                eff = policy.effective(refresh=True)
        self.assertTrue(any("unknown policy profile" in w for w in eff["warnings"]))

    def test_malformed_file_falls_back_to_preset(self):
        fd, name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        path = pathlib.Path(name)
        path.write_text("{", encoding="utf-8")
        self.addCleanup(path.unlink)
        with environment():
            with mock.patch.object(policy, "POLICY_FILE", path):
                eff = policy.effective(refresh=True)
        self.assertEqual(eff["preset"], "adaptive")
        self.assertTrue(eff["warnings"])

    def test_non_utf8_file_falls_back_to_preset(self):
        fd, name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        path = pathlib.Path(name)
        path.write_bytes(b"\xff\xfe")
        self.addCleanup(path.unlink)
        with environment():
            with mock.patch.object(policy, "POLICY_FILE", path):
                eff = policy.effective(refresh=True)
        self.assertEqual(eff["preset"], "adaptive")

class ReadinessGateTests(unittest.TestCase):
    def test_target_reached_opens_the_gate(self):
        with environment(), meta_store() as store, runtime(active_rc=0):
            state = policy.gate(object())
        self.assertTrue(state["ready"])
        self.assertEqual(state["reason"], "target")
        self.assertEqual(state["deferred"], ())
        self.assertEqual(len(json.loads(store[policy.META_HISTORY])), 1)

    def test_settle_period_after_the_target_defers_the_gate(self):
        with environment(QA_PROBE_READY_SETTLE_S="60",
                         QA_PROBE_READY_MAX_S="300"), \
                meta_store(), runtime(uptime="30.0", active_rc=0,
                                      ready_since_s=10):
            state = policy.gate(object())
        self.assertFalse(state["ready"])
        self.assertEqual(state["reason"], "settle")
        self.assertEqual(set(state["deferred"]), set(policy.VOLATILE_SOURCES))

    def test_settle_can_be_disabled(self):
        with environment(QA_PROBE_READY_SETTLE_S="0"), meta_store(), runtime(
                uptime="30.0", active_rc=0, ready_since_s=10):
            state = policy.gate(object())
        self.assertTrue(state["ready"])

    def test_starting_system_defers_volatile_probes(self):
        with environment(), meta_store(), runtime(
                uptime="10.0", active_rc=3, running="starting"):
            state = policy.gate(object())
        self.assertFalse(state["ready"])
        self.assertEqual(state["reason"], "system-starting")
        self.assertEqual(set(state["deferred"]), set(policy.VOLATILE_SOURCES))

    def test_deadline_opens_the_gate(self):
        with environment(QA_PROBE_READY_MAX_S="300"), meta_store(), runtime(
                uptime="400.0", active_rc=3, running="starting"):
            state = policy.gate(object())
        self.assertTrue(state["ready"])
        self.assertEqual(state["reason"], "deadline")
        self.assertEqual(state["deferred"], ())

    def test_without_systemd_uptime_is_the_fallback(self):
        with environment(QA_PROBE_READY_MAX_S="300"), meta_store(), runtime(
                uptime="400.0", active_rc=127):
            state = policy.gate(object())
        self.assertTrue(state["ready"])
        self.assertEqual(state["reason"], "uptime-fallback")

    def test_uptime_mode_ignores_systemd(self):
        with environment(QA_PROBE_READY_MODE="uptime",
                         QA_PROBE_READY_MAX_S="300"), meta_store(), \
                runtime(uptime="20.0"):
            state = policy.gate(object())
        self.assertFalse(state["ready"])
        with environment(QA_PROBE_READY_MODE="uptime",
                         QA_PROBE_READY_MAX_S="300"), meta_store(), \
                runtime(uptime="400.0"):
            state = policy.gate(object())
        self.assertTrue(state["ready"])

    def test_disabled_mode_is_always_ready(self):
        with environment(QA_PROBE_READY_MODE="off"), meta_store():
            state = policy.gate(object())
        self.assertTrue(state["ready"])
        self.assertEqual(state["reason"], "disabled")

    def test_deferral_can_be_narrowed(self):
        with environment(QA_PROBE_DEFER="hardware"), meta_store(), runtime(
                uptime="10.0", active_rc=3, running="starting"):
            state = policy.gate(object())
        self.assertEqual(state["deferred"], ("hardware",))

    def test_deferral_can_be_disabled_explicitly(self):
        with environment(QA_PROBE_DEFER="none"), meta_store(), runtime(
                uptime="10.0", active_rc=3, running="starting"):
            state = policy.gate(object())
        self.assertFalse(state["ready"])
        self.assertEqual(state["deferred"], ())

    def test_permissive_admission_never_defers(self):
        with environment(QA_PROBE_ADMISSION="allow"), meta_store(), runtime(
                uptime="10.0", active_rc=3, running="starting"):
            state = policy.gate(object())
        self.assertFalse(state["ready"])
        self.assertEqual(state["deferred"], ())

    def test_adaptive_deadline_learns_from_history(self):
        with environment(), meta_store() as store:
            store[policy.META_HISTORY] = json.dumps([20, 30, 40])
            wait, source = policy.deadline(object())
        self.assertEqual(source, "adaptive")
        self.assertEqual(wait, 45)
        with environment(QA_PROBE_ADAPTIVE="0"), meta_store() as store:
            store[policy.META_HISTORY] = json.dumps([20, 30, 40])
            wait, source = policy.deadline(object())
        self.assertEqual(source, "configured")
        self.assertEqual(wait, 300)

    def test_readiness_history_uses_the_target_timestamp(self):
        with environment(QA_PROBE_READY_SETTLE_S="60",
                         QA_PROBE_READY_MAX_S="300"), \
                meta_store() as store, runtime(uptime="100.0", active_rc=0,
                                               ready_since_s=5):
            policy.gate(object())
        self.assertEqual(json.loads(store[policy.META_HISTORY]), [5.0])

    def test_readiness_is_recorded_once_per_boot(self):
        with environment(), meta_store() as store, runtime(
                active_rc=0, boot_id="same-boot"):
            policy.gate(object())
            policy.gate(object())
        self.assertEqual(json.loads(store[policy.META_HISTORY]), [10.0])


class ProbeWindowTests(unittest.TestCase):
    def test_hardware_journal_reads_the_current_boot(self):
        self.assertEqual(
            hardware._kernel_journal_args(),
            ["journalctl", "-k", "-b", "0", "--no-pager"],
        )


if __name__ == "__main__":
    unittest.main()
