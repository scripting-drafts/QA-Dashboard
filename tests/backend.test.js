"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const backend = require("../electron/backend");

test("sentinels actions map to fixed argv", () => {
  assert.deepEqual(backend.sentinelsArgs("status"), ["status"]);
  assert.deepEqual(backend.sentinelsArgs("logs"),
    ["logs", "--all-layers", "--follow", "--lines", "300", "--no-color"]);
  assert.throws(() => backend.sentinelsArgs("rm -rf /"), /unknown/);
  assert.throws(() => backend.sentinelsArgs("evidence"), /unknown/);
});

test("query arguments cover categories, SQL and limits", () => {
  assert.deepEqual(backend.queryArgs({ category: "inbox", limit: 25 }),
    ["query", "--json", "--category", "inbox", "--limit", "25"]);
  assert.deepEqual(backend.queryArgs({ sql: " SELECT 1 ", limit: 10 }),
    ["query", "--json", "--sql", "SELECT 1", "--limit", "10"]);
  assert.deepEqual(backend.queryArgs({ category: "findings", limit: 5000 }),
    ["query", "--json", "--category", "findings", "--limit", "5000"]);
  assert.deepEqual(backend.queryArgs({ category: "findings", limit: 50000 }),
    ["query", "--json", "--category", "findings", "--limit", "10000"]);
  assert.deepEqual(backend.queryArgs({ latest: true }),
    ["query", "--json", "--latest-cycle"]);
  assert.deepEqual(backend.queryArgs({
    category: "findings", search: "systemd.service_start",
    severity: "error", status: "open", since: "2026-11-10T08:00:00Z",
  }), [
    "query", "--json", "--category", "findings", "--limit", "200",
    "--search", "systemd.service_start", "--severity", "error",
    "--status", "open", "--since", "2026-11-10T08:00:00Z",
  ]);
  assert.throws(
    () => backend.queryArgs({ sql: "SELECT 1", search: "x" }),
    /filters apply to categories/);
  assert.ok(backend.QUERY_CATEGORIES.includes("cycles"));
  assert.ok(backend.QUERY_CATEGORIES.includes("new-findings"));
  assert.throws(() => backend.queryArgs({ category: "sqlite_master" }),
    /unknown query category/);
  assert.throws(() => backend.queryArgs({ sql: "SELECT\u00001" }), /NUL/);
  assert.ok(backend.QUERY_CATEGORIES.includes("inbox"));
  assert.ok(backend.QUERY_CATEGORIES.includes("errors"));
  assert.ok(backend.QUERY_CATEGORIES.includes("crashes"));
  for (const category of [
    "processes", "inventory-items", "inventory-diffs", "hardware-items",
    "core2", "crosschecks", "notifications", "reports", "meta",
  ]) {
    assert.ok(backend.QUERY_CATEGORIES.includes(category), category);
  }
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

test("ticket buckets list titles and legacy folders", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qa-tickets-"));
  const root = path.join(temp, "tickets");
  try {
    for (const bucket of backend.TICKET_BUCKETS) {
      fs.mkdirSync(path.join(root, bucket), { recursive: true });
    }
    const ticketDir = path.join(root, "raise", "demo-ticket");
    fs.mkdirSync(ticketDir);
    fs.writeFileSync(path.join(ticketDir, "ticket.md"),
      "# Demo crash title\n\nBody.\n");
    fs.mkdirSync(path.join(root, "raised", "legacy"));
    fs.writeFileSync(path.join(root, "raised", "legacy", "comment.txt"), "x");
    fs.mkdirSync(path.join(root, "standby", ".hidden"));

    const data = backend.listTickets(root);
    assert.equal(data.root, root);
    assert.deepEqual(data.buckets.map((bucket) => bucket.bucket),
      backend.TICKET_BUCKETS);

    const raise = data.buckets.find((bucket) => bucket.bucket === "raise");
    assert.equal(raise.count, 1);
    assert.equal(raise.tickets[0].title, "Demo crash title");
    assert.match(raise.tickets[0].preview, /^# Demo crash title/m);
    assert.equal(raise.tickets[0].ticketMd, true);
    assert.ok(raise.tickets[0].updated);

    const raised = data.buckets.find((bucket) => bucket.bucket === "raised");
    assert.equal(raised.count, 1);
    assert.equal(raised.tickets[0].ticketMd, false);
    assert.equal(raised.tickets[0].title, "legacy");

    const standby = data.buckets.find((bucket) => bucket.bucket === "standby");
    assert.equal(standby.count, 0);

    assert.equal(
      backend.ticketPath(root, "raise", "demo-ticket").file,
      fs.realpathSync(path.join(ticketDir, "ticket.md")),
    );
    assert.equal(backend.ticketPath(root, "raised", "legacy").file, "");
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("ticket paths stay inside their bucket", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qa-tickets-safe-"));
  const root = path.join(temp, "tickets");
  try {
    fs.mkdirSync(path.join(root, "raise", "demo-ticket"), { recursive: true });
    fs.mkdirSync(path.join(temp, "outside"));
    fs.symlinkSync(path.join(temp, "outside"),
      path.join(root, "raise", "escape"), "dir");

    assert.throws(() => backend.ticketPath(root, "raise", ".."),
      /invalid ticket name/);
    assert.throws(() => backend.ticketPath(root, "raise", "../raise"),
      /invalid ticket name/);
    assert.throws(() => backend.ticketPath(root, "raise", "/etc"),
      /invalid ticket name/);
    assert.throws(() => backend.ticketPath(root, "../raise", "demo-ticket"),
      /invalid ticket bucket/);
    assert.throws(() => backend.ticketPath(root, "raise", "escape"),
      /outside its bucket/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test("sentinels scheduler detection prefers the installed timer", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qa-scheduler-"));
  const timer = path.join(temp, "qa-sentinel.timer");
  try {
    assert.equal(backend.sentinelsSchedulerPresent({ timerPath: timer }), false);
    fs.writeFileSync(timer, "");
    assert.equal(backend.sentinelsSchedulerPresent({ timerPath: timer }), true);
    assert.equal(backend.sentinelsSchedulerPresent({
      timerPath: path.join(temp, "missing"),
      cronText: "*/1 * * * * /opt/qa cycle # >>> qa-sentinels >>>",
    }), true);
    assert.equal(backend.sentinelsSchedulerPresent({
      timerPath: path.join(temp, "missing"), cronText: "",
    }), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
