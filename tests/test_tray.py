from __future__ import annotations

import unittest

from qadesk.tray import MENU_ITEMS, QATray, tray_pixmaps


class TrayTests(unittest.TestCase):
    def test_pixmaps_are_argb(self) -> None:
        pixmaps = tray_pixmaps()
        self.assertTrue(pixmaps)
        for width, height, data in pixmaps:
            self.assertGreater(width, 0)
            self.assertGreater(height, 0)
            self.assertEqual(len(data), width * height * 4)

    def test_menu_contract(self) -> None:
        labels = [label for _ident, label, _module in MENU_ITEMS if label]
        self.assertNotIn("Open QA Desktop", labels)
        self.assertIn("Sentinels", labels)
        self.assertIn("Malware Scan", labels)
        self.assertIn("SIEM", labels)
        self.assertNotIn("Quit", labels)

    def test_item_properties(self) -> None:
        standard = QATray._item_props("Sentinels")
        separator = QATray._item_props(None)
        self.assertEqual(standard["type"].unpack(), "standard")
        self.assertEqual(separator["type"].unpack(), "separator")
        self.assertNotIn("label", separator)


if __name__ == "__main__":
    unittest.main()
