from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from qadesk.core import (
    Config,
    build_malware_args,
    http_json,
    parse_event,
    parse_malware_jsonl,
    parse_qa_status,
    read_token,
)


class CoreTests(unittest.TestCase):
    def test_build_malware_args_quotes_nothing(self) -> None:
        target = "/tmp/a file;touch injected.js"
        args = build_malware_args(
            "/usr/bin/malware-scan", target, all_files=True, deep=True,
            quarantine=True, steg=True, clamav="auto",
            yara="/usr/bin/yara", yara_rules="/tmp/rules.yar")
        self.assertEqual(args[0], "/usr/bin/malware-scan")
        self.assertIn("--all-files", args)
        self.assertIn("--deep", args)
        self.assertIn("--quarantine", args)
        self.assertIn("--steg", args)
        self.assertEqual(args[-2:], ["--", target])
        self.assertEqual(args[args.index("--clamav") + 1], "auto")

    def test_build_malware_args_requires_target(self) -> None:
        with self.assertRaises(ValueError):
            build_malware_args("/usr/bin/malware-scan", " ")

    def test_parse_malware_jsonl(self) -> None:
        lines = [
            '{"event":"finding","verdict":"suspicious","path":"/x"}',
            "not json",
            '{"event":"summary","scanned":1,"partial":0}',
        ]
        summary, findings = parse_malware_jsonl(lines)
        self.assertIsNotNone(summary)
        self.assertEqual(summary["scanned"], 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(parse_event("not json"), None)

    def test_parse_qa_status(self) -> None:
        values = parse_qa_status(
            "Quality Assurance Sentinels status\n"
            "  last sample   : 2026-11-08T12:45:38Z\n"
            "  layer1        : open findings: critical=1\n")
        self.assertEqual(values["last sample"], "2026-11-08T12:45:38Z")
        self.assertIn("critical=1", values["layer1"])

    def test_read_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token"
            path.write_text("  abc123\n", encoding="utf-8")
            self.assertEqual(read_token(str(path)), "abc123")
            self.assertEqual(read_token(str(Path(tmp) / "missing")), "")
            path.write_text("x" * 5000, encoding="utf-8")
            self.assertEqual(read_token(str(path)), "")

    def test_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            cfg = Config(sentinels_bin="/opt/qa", malware_bin="/opt/scan",
                         siem_url="http://127.0.0.1:9000/",
                         siem_token_file="/tmp/token",
                         enabled_modules=["siem", "malware"])
            cfg.save(path)
            loaded = Config.load(path)
            self.assertEqual(loaded.sentinels_bin, "/opt/qa")
            self.assertEqual(loaded.siem_url, "http://127.0.0.1:9000")
            self.assertEqual(loaded.enabled_modules, ["malware", "siem"])
            self.assertEqual(stat_mode(path), 0o600)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/healthz":
                    self.reply({"status": "ok"})
                    return
                if self.headers.get("Authorization") != "Bearer secret":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"error":"unauthorized"}')
                    return
                self.reply({"path": self.path, "ok": True})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                self.reply({"ok": True, "body": json.loads(body)})

            def reply(self, payload: dict) -> None:
                data = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args) -> None:
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_health(self) -> None:
        self.assertEqual(http_json(self.base, "/healthz")["status"], "ok")

    def test_authorized_and_post(self) -> None:
        self.assertTrue(http_json(self.base, "/api/v1/stats", "secret")["ok"])
        result = http_json(self.base, "/api/v1/alerts/ack", "secret",
                           method="POST", payload={"id": 4})
        self.assertEqual(result["body"]["id"], 4)

    def test_unauthorized(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "unauthorized"):
            http_json(self.base, "/api/v1/stats", "wrong")


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
