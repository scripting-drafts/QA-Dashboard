"""Tests for the ticket Reporter section."""
import unittest
from unittest import mock

from sentinels import raise_ticket, tickets, util


class ReporterTests(unittest.TestCase):
    def test_consent_line_is_not_rendered(self):
        issue = {
            "key": "reporter", "vendor": "local",
            "signature": "reporter test", "display": "reporter test",
            "kind": "event", "count": 1, "severity": "warning",
            "first": "2026-11-08T00:00:00Z", "last": "2026-11-08T00:00:00Z",
            "rows": [],
        }
        identity = {
            "FULL_NAME": "Test Reporter",
            "LINKEDIN": "https://example.invalid/reporter",
            "GITHUB": "https://example.invalid/github",
        }
        _, body = tickets._draft(issue, None, identity, True)
        self.assertIn("## Reporter", body)
        self.assertIn("- Name: Test Reporter", body)
        self.assertNotIn("Consent:", body)

    def test_staged_ticket_keeps_the_consented_linkedin(self):
        linkedin = "https://www.linkedin.com/in/gerard-sala/"
        with mock.patch.object(util, "_USER", "gerard"), \
             mock.patch.object(util, "identity_for_ticket",
                               return_value=({"LINKEDIN": linkedin}, True)):
            body = raise_ticket._redact_ticket_text(
                f"- LinkedIn: {linkedin}\npath {util.config.HOME}/x\n"
            )
        self.assertIn(f"- LinkedIn: {linkedin}", body)
        self.assertIn("/home/<user>", body)
        self.assertNotIn(f"{util.config.HOME}/x", body)


if __name__ == "__main__":
    unittest.main()
