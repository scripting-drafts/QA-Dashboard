"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const backend = require("../electron/backend");

test("malware arguments keep the target as one argument after --", () => {
  const target = "/tmp/a file;touch injected.js";
  const args = backend.buildMalwareArgs("/usr/bin/malware-scan", target, {
    allFiles: true,
    deep: true,
    quarantine: true,
    steg: true,
    clamav: "auto",
    yara: "/usr/bin/yara",
    yaraRules: "/tmp/rules.yar",
  });
  assert.deepEqual(args.slice(-2), ["--", target]);
  assert.ok(args.includes("--all-files"));
  assert.ok(args.includes("--deep"));
  assert.ok(args.includes("--quarantine"));
  assert.ok(args.includes("--steg"));
  assert.equal(args[args.indexOf("--clamav") + 1], "auto");
});

test("malware target is required", () => {
  assert.throws(
    () => backend.buildMalwareArgs("/usr/bin/malware-scan", " "),
    /choose a file/,
  );
});

test("sentinels actions map to fixed argv", () => {
  assert.deepEqual(backend.sentinelsArgs("status"), ["status"]);
  assert.deepEqual(backend.sentinelsArgs("logs"),
    ["logs", "--lines", "300"]);
  assert.throws(() => backend.sentinelsArgs("rm -rf /"), /unknown/);
});

test("status output parses colon-delimited values", () => {
  const values = backend.parseStatus(
    "Quality Assurance Sentinels status\n" +
    "  last sample   : 2026-11-08T12:45:38Z\n" +
    "  layer1        : open findings: critical=1\n",
  );
  assert.equal(values["last sample"], "2026-11-08T12:45:38Z");
  assert.equal(values.layer1, "open findings: critical=1");
});

test("config round-trips with private permissions", () => {
  const previous = process.env.XDG_CONFIG_HOME;
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qa-dashboard-config-"));
  process.env.XDG_CONFIG_HOME = temp;
  try {
    const cfg = backend.loadConfig();
    cfg.siemUrl = "http://127.0.0.1:9999/";
    cfg.sentinelsBin = "/opt/qa";
    backend.saveConfig(cfg);
    const loaded = backend.loadConfig();
    assert.equal(loaded.siemUrl, "http://127.0.0.1:9999");
    assert.equal(loaded.sentinelsBin, "/opt/qa");
    const mode = fs.statSync(backend.configPath()).mode & 0o777;
    assert.equal(mode, 0o600);
  } finally {
    if (previous === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previous;
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("HTTP client handles auth and errors", async () => {
  const server = http.createServer((request, response) => {
    if (request.url === "/healthz") {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ status: "ok" }));
      return;
    }
    if (request.headers.authorization !== "Bearer secret") {
      response.statusCode = 401;
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ ok: true }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;
  try {
    assert.deepEqual(await backend.httpJson(base, "/healthz"), { status: "ok" });
    assert.deepEqual(await backend.httpJson(base, "/api/v1/stats", "secret"),
      { ok: true });
    await assert.rejects(
      backend.httpJson(base, "/api/v1/stats", "wrong"),
      /unauthorized/,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
