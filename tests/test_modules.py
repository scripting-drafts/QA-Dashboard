from __future__ import annotations

import unittest
from pathlib import Path

from qadesk.core import MODULE_IDS
from qadesk.modules import MODULE_CLASSES, MODULE_MAP


class RegistryTests(unittest.TestCase):
    def test_registry_matches_ids(self) -> None:
        self.assertEqual(set(MODULE_MAP), set(MODULE_IDS))
        self.assertEqual([cls.id for cls in MODULE_CLASSES], list(MODULE_IDS))
        for cls in MODULE_CLASSES:
            self.assertTrue(cls.title)
            self.assertTrue(cls.icon)
        icons = Path(__file__).resolve().parents[1] / "data" / "icons" / \
            "hicolor" / "scalable" / "apps"
        self.assertTrue((icons / "qa-desktop.svg").is_file())
        self.assertTrue((icons / "qa-malware-scan.svg").is_file())


if __name__ == "__main__":
    unittest.main()
