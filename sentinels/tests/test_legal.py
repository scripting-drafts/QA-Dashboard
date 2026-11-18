"""Tests for the own-product license and legal register."""
import json
import unittest
from pathlib import Path

from sentinels import legal


ROOT = Path(__file__).resolve().parents[1]


class LegalRegisterTests(unittest.TestCase):
    def test_checked_in_manifest_is_valid(self):
        manifest = json.loads((ROOT / "legal" / "manifest.json").read_text())
        self.assertEqual(legal.validate_manifest(manifest), [])

    def test_register_reports_no_actions(self):
        data = legal.register(ROOT)
        self.assertTrue(data["ok"])
        self.assertEqual(data["summary"]["actions"], 0)
        self.assertEqual(data["summary"]["overall"], "ok")
        self.assertTrue(data["summary"]["version_ok"])
        self.assertEqual(data["summary"]["pending_reviews"], 0)
        self.assertTrue(all(item["available"] for item in data["documents"]))

    def test_manifest_rejects_path_traversal_and_bad_version(self):
        manifest = json.loads((ROOT / "legal" / "manifest.json").read_text())
        manifest["documents"][0]["path"] = "../LICENSE"
        manifest["components"][0]["license"] = "MIT AND"
        errors = legal.validate_manifest(manifest)
        self.assertTrue(any("path" in error for error in errors))
        self.assertTrue(any("license" in error for error in errors))

    def test_version_prefix_matching(self):
        self.assertTrue(legal._version_matches("3.10+", "3.10.12"))
        self.assertTrue(legal._version_matches("1.2.0", "1.2.0"))
        self.assertFalse(legal._version_matches("3.10+", "3.9.19"))

    def test_packaging_installs_legal_artifacts(self):
        rules = (ROOT / "debian" / "rules").read_text()
        for name in ("LICENSE", "THIRD-PARTY-NOTICES.md", "legal/manifest.json"):
            self.assertIn(name, rules)


if __name__ == "__main__":
    unittest.main()
