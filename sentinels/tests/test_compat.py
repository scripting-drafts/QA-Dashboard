"""Tests for Ubuntu upgrade compatibility reporting."""
import unittest
import unittest.mock

from sentinels import compat


class CompatTests(unittest.TestCase):
    def test_supported_matrix(self):
        for version in ("22.04", "24.04", "26.04", "26.10"):
            result = compat.evaluate(
                "ubuntu", version, "3.10.12", "3.37.2", "249", "6.8.0"
            )
            self.assertTrue(result["supported"], version)

    def test_systemd_259_on_noble_and_resolute(self):
        for version in ("24.04", "26.04"):
            for systemd in ("259", "259.1"):
                result = compat.evaluate(
                    "ubuntu", version, "3.12.3", "3.45.1", systemd, "6.14.0"
                )
                self.assertTrue(result["supported"], (version, systemd))

    def test_old_or_unlisted_release_is_unsupported(self):
        for version in ("20.04", "23.04", "27.04"):
            result = compat.evaluate(
                "ubuntu", version, "3.10.12", "3.37.2", "249", "6.8.0"
            )
            self.assertFalse(result["supported"], version)

    def test_component_minimums(self):
        result = compat.evaluate(
            "ubuntu", "22.04", "3.9.0", "3.36.0", "248", "5.14.0"
        )
        self.assertFalse(result["supported"])
        failed = {check["name"] for check in result["checks"] if not check["ok"]}
        self.assertEqual(
            failed,
            {"Python >= 3.10", "SQLite >= 3.37", "systemd >= 249", "kernel >= 5.15"},
        )

    def test_sysv_availability_tracks_systemd_not_the_release(self):
        with unittest.mock.patch.object(compat, "_systemd_version",
                                        return_value="249"):
            compat.sysv_available.cache_clear()
            self.assertTrue(compat.sysv_available())
            self.assertFalse(compat.ignore_sysv_failure(
                "Failed to start LSB: OpenIPMI Driver init script."))
        for version in ("250", "255", "259", "260"):
            with unittest.mock.patch.object(compat, "_systemd_version",
                                            return_value=version):
                compat.sysv_available.cache_clear()
                self.assertFalse(compat.sysv_available(), version)
                self.assertTrue(compat.ignore_sysv_failure(
                    "Failed to start LSB: OpenIPMI Driver init script."))

    def test_current_host_is_supported(self):
        self.assertTrue(compat.report()["supported"])


if __name__ == "__main__":
    unittest.main()
