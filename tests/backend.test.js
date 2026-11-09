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
    ["logs", "--all-layers", "--follow", "--lines", "300", "--no-color"]);
  assert.throws(() => backend.sentinelsArgs("rm -rf /"), /unknown/);
  assert.throws(() => backend.sentinelsArgs("evidence"), /unknown/);
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
  const root = path.join(temp, "sentinels");
  fs.mkdirSync(path.join(root, "bin"), { recursive: true });
  fs.writeFileSync(path.join(root, "bin", "qa"), "", { mode: 0o755 });
  process.env.XDG_CONFIG_HOME = temp;
  try {
    const cfg = backend.loadConfig();
    cfg.sentinelsRoot = root;
    assert.equal(cfg.sentinelsCycleMinutes, "10");
    cfg.siemUrl = "http://127.0.0.1:9999/";
    cfg.sentinelsBin = "/opt/qa";
    cfg.sentinelsCycleMinutes = "2";
    backend.saveConfig(cfg);
    const loaded = backend.loadConfig();
    assert.equal(loaded.siemUrl, "http://127.0.0.1:9999");
    assert.equal(loaded.sentinelsBin, "/opt/qa");
    assert.equal(loaded.sentinelsCycleMinutes, "2");
    const mode = fs.statSync(backend.configPath()).mode & 0o777;
    assert.equal(mode, 0o600);
  } finally {
    if (previous === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previous;
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("sentinels settings normalize defaults and reject bad values", () => {
  assert.deepEqual(backend.normalizeSentinelsSettings({}), {
    sentinelsCycleHours: "1",
    sentinelsDraftsRetentionDays: "30",
    sentinelsRaiseLookbackDays: "30",
    sentinelsEventRetentionDays: "0",
    sentinelsSamplesRetentionDays: "0",
    sentinelsProcRetentionDays: "0",
    sentinelsInventoryRetentionDays: "0",
  });
  const custom = backend.normalizeSentinelsSettings({
    sentinelsCycleHours: "2.5",
    sentinelsRaiseLookbackDays: "45",
    sentinelsEventRetentionDays: "30",
  });
  assert.equal(custom.sentinelsCycleHours, "2.5");
  assert.equal(custom.sentinelsRaiseLookbackDays, "45");
  assert.equal(custom.sentinelsEventRetentionDays, "30");
  assert.throws(
    () => backend.normalizeSentinelsSettings({ sentinelsEventRetentionDays: "abc" }),
    /Events retention/,
  );
  assert.throws(
    () => backend.normalizeSentinelsSettings({ sentinelsSamplesRetentionDays: "1.5" }),
    /whole number/,
  );
  assert.throws(
    () => backend.normalizeSentinelsSettings({ sentinelsCycleHours: "0" }),
    /Cycle cadence/,
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "qa-settings-empty-"));
  try {
    fs.mkdirSync(path.join(tempRoot, "bin"));
    fs.writeFileSync(path.join(tempRoot, "bin", "qa"), "", { mode: 0o755 });
    assert.deepEqual(
      backend.loadSentinelsSettings({ sentinelsRoot: tempRoot }), {});
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("sentinels settings mirror to the engine root", () => {
  const previous = process.env.XDG_CONFIG_HOME;
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qa-dashboard-settings-"));
  const root = path.join(temp, "sentinels");
  fs.mkdirSync(path.join(root, "bin"), { recursive: true });
  const qa = path.join(root, "bin", "qa");
  fs.writeFileSync(qa, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  process.env.XDG_CONFIG_HOME = path.join(temp, "config");
  try {
    const cfg = backend.loadConfig();
    cfg.sentinelsRoot = root;
    cfg.sentinelsCycleHours = "2";
    cfg.sentinelsDraftsRetentionDays = "14";
    cfg.sentinelsRaiseLookbackDays = "21";
    cfg.sentinelsEventRetentionDays = "30";
    cfg.sentinelsSamplesRetentionDays = "7";
    cfg.sentinelsProcRetentionDays = "3";
    cfg.sentinelsInventoryRetentionDays = "90";
    backend.saveConfig(cfg);

    const settingsPath = path.join(root, "config", "settings.json");
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    assert.equal(settings.QA_CYCLE_RAISE_HOURS, "2");
    assert.equal(settings.QA_DRAFTS_RETENTION_DAYS, "14");
    assert.equal(settings.QA_RAISE_LOOKBACK_DAYS, "21");
    assert.equal(settings.QA_EVENT_RETENTION_DAYS, "30");
    assert.equal(settings.QA_SAMPLE_RETENTION_DAYS, "7");
    assert.equal(settings.QA_PROC_RETENTION_DAYS, "3");
    assert.equal(settings.QA_INVENTORY_RETENTION_DAYS, "90");
    assert.equal(fs.statSync(settingsPath).mode & 0o777, 0o600);

    const loaded = backend.loadConfig();
    assert.equal(loaded.sentinelsDraftsRetentionDays, "14");
    assert.equal(loaded.sentinelsEventRetentionDays, "30");
    assert.equal(loaded.sentinelsCycleHours, "2");
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
