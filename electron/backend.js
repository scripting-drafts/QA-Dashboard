"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const readline = require("node:readline");

const SENTINELS_SETTING_KEYS = {
  sentinelsCycleHours: {
    env: "QA_CYCLE_RAISE_HOURS", default: "1",
    label: "Cycle cadence", min: 0.1, max: 8760, decimal: true,
  },
  sentinelsDraftsRetentionDays: {
    env: "QA_DRAFTS_RETENTION_DAYS", default: "30",
    label: "Drafts retention", min: 0, max: 3650,
  },
  sentinelsRaiseLookbackDays: {
    env: "QA_RAISE_LOOKBACK_DAYS", default: "30",
    label: "Raise gate lookback", min: 1, max: 3650,
  },
  sentinelsEventRetentionDays: {
    env: "QA_EVENT_RETENTION_DAYS", default: "0",
    label: "Events retention", min: 0, max: 3650,
  },
  sentinelsSamplesRetentionDays: {
    env: "QA_SAMPLE_RETENTION_DAYS", default: "0",
    label: "Samples retention", min: 0, max: 3650,
  },
  sentinelsProcRetentionDays: {
    env: "QA_PROC_RETENTION_DAYS", default: "0",
    label: "proc_snap retention", min: 0, max: 3650,
  },
  sentinelsInventoryRetentionDays: {
    env: "QA_INVENTORY_RETENTION_DAYS", default: "0",
    label: "Inventory retention", min: 0, max: 3650,
  },
};

const DEFAULT_CONFIG = {
  sentinelsBin: "",
  sentinelsRoot: "",
  sentinelsCycleMinutes: "10",
};
for (const [key, spec] of Object.entries(SENTINELS_SETTING_KEYS)) {
  DEFAULT_CONFIG[key] = spec.default;
}

const TICKET_BUCKETS = ["raise", "raised", "rejected", "standby"];
const QUERY_CATEGORIES = [
  "inbox", "errors", "findings", "cycles", "new-findings", "events", "crashes",
  "boots", "samples", "processes", "inventory", "inventory-items",
  "inventory-diffs", "hardware", "hardware-items", "lsm", "correlations",
  "tickets", "deep", "bundles", "runs", "core2", "crosschecks", "notifications",
  "reports", "meta",
];
const QUERY_MAX_SQL = 20000;
const QUERY_MAX_ROWS = 10000;

function configPath() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(base, "qa-dashboard", "config.json");
}

function sentinelsSettingsPath(cfg) {
  const root = resolveSentinelsRoot(cfg);
  return root ? path.join(root, "config", "settings.json") : "";
}

function sentinelsSchedulerPresent(options = {}) {
  const timer = options.timerPath ||
    "/etc/systemd/system/timers.target.wants/qa-sentinel.timer";
  if (fs.existsSync(timer)) return true;
  if (typeof options.cronText === "string") {
    return options.cronText.includes(">>> qa-sentinels >>>");
  }
  try {
    const out = execFileSync("crontab", ["-l"], {
      encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"],
    });
    return out.includes(">>> qa-sentinels >>>");
  } catch (_error) {
    return false;
  }
}

function readSentinelsSettings(cfg) {
  const target = sentinelsSettingsPath(cfg);
  if (!target) return {};
  try {
    const data = JSON.parse(fs.readFileSync(target, "utf8"));
    return data && typeof data === "object" && !Array.isArray(data) ? data : {};
  } catch (_error) {
    return {};
  }
}

function normalizeSentinelsSettings(cfg) {
  const out = {};
  for (const [key, spec] of Object.entries(SENTINELS_SETTING_KEYS)) {
    const raw = String(cfg[key] ?? "").trim();
    const text = raw === "" ? spec.default : raw;
    const value = Number(text);
    if (!Number.isFinite(value) || value < spec.min || value > spec.max ||
        (!spec.decimal && !Number.isInteger(value))) {
      const kind = spec.decimal ? "a number" : "a whole number";
      throw new Error(
        `${spec.label} must be ${kind} between ${spec.min} and ${spec.max}`);
    }
    out[key] = String(value);
  }
  return out;
}

function loadSentinelsSettings(cfg) {
  const data = readSentinelsSettings(cfg);
  const out = {};
  for (const [key, spec] of Object.entries(SENTINELS_SETTING_KEYS)) {
    const raw = String(data[spec.env] ?? "").trim();
    if (!raw) continue;
    const value = Number(raw);
    if (Number.isFinite(value) && value >= spec.min && value <= spec.max &&
        (spec.decimal || Number.isInteger(value))) {
      out[key] = String(value);
    }
  }
  return out;
}

function saveSentinelsSettings(cfg, normalized) {
  const target = sentinelsSettingsPath(cfg);
  if (!target) return "";
  let data = {};
  try {
    const existing = JSON.parse(fs.readFileSync(target, "utf8"));
    if (existing && typeof existing === "object" && !Array.isArray(existing)) {
      data = existing;
    }
  } catch (_error) {
    // A missing or malformed file is replaced with a fresh one.
  }
  for (const [key, spec] of Object.entries(SENTINELS_SETTING_KEYS)) {
    data[spec.env] = normalized[key];
  }
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const tmp = `${target}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, target);
  fs.chmodSync(target, 0o600);
  return target;
}

function loadConfig() {
  const cfg = { ...DEFAULT_CONFIG };
  try {
    const data = JSON.parse(fs.readFileSync(configPath(), "utf8"));
    for (const key of Object.keys(DEFAULT_CONFIG)) {
      if (typeof data[key] === "string") cfg[key] = data[key].trim();
    }
  } catch (_error) {
    // Missing or invalid configuration falls back to defaults.
  }
  Object.assign(cfg, loadSentinelsSettings(cfg));
  return cfg;
}

function saveConfig(cfg) {
  const normalized = normalizeSentinelsSettings(cfg);
  const target = configPath();
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const payload = {};
  for (const key of Object.keys(DEFAULT_CONFIG)) {
    payload[key] = typeof cfg[key] === "string" ? cfg[key].trim() : "";
  }
  Object.assign(payload, normalized);
  const tmp = `${target}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, target);
  fs.chmodSync(target, 0o600);
  saveSentinelsSettings(payload, normalized);
}

function expand(value) {
  if (!value) return "";
  if (value === "~") return os.homedir();
  if (value.startsWith("~/")) return path.join(os.homedir(), value.slice(2));
  return value;
}

function executable(value) {
  const expanded = expand(value);
  if (!expanded) return "";
  const candidates = [];
  if (expanded.includes(path.sep)) {
    candidates.push(expanded);
  } else {
    for (const dir of (process.env.PATH || "").split(path.delimiter)) {
      if (dir) candidates.push(path.join(dir, expanded));
    }
  }
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch (_error) {
      // Keep looking.
    }
  }
  return "";
}

function resolveSentinelsRoot(cfg) {
  const configured = expand(cfg.sentinelsRoot);
  if (configured && fs.existsSync(path.join(configured, "bin", "qa"))) {
    return configured;
  }
  const envRoot = expand(process.env.QA_SENTINELS_ROOT || "");
  if (envRoot && fs.existsSync(path.join(envRoot, "bin", "qa"))) return envRoot;
  for (const candidate of [
    path.join(os.homedir(), "QA-Sentinels"),
    path.join(os.homedir(), "Quality-Assurance-Sentinels"),
    "/opt/QA-Sentinels",
    "/opt/Quality-Assurance-Sentinels",
  ]) {
    if (fs.existsSync(path.join(candidate, "bin", "qa"))) return candidate;
  }
  return "";
}

function resolveSentinelsBin(cfg) {
  const configured = executable(cfg.sentinelsBin);
  if (configured) return configured;
  const envBin = executable(process.env.QA_SENTINELS_BIN || "");
  if (envBin) return envBin;
  const root = resolveSentinelsRoot(cfg);
  if (root) {
    const fromRoot = executable(path.join(root, "bin", "qa"));
    if (fromRoot) return fromRoot;
  }
  return executable("qa");
}

function ticketsRoot() {
  for (const name of ["QA-Sentinels", "Quality-Assurance-Sentinels"]) {
    const candidate = path.join(os.homedir(), name, "tickets");
    if (fs.existsSync(candidate)) return candidate;
  }
  return "";
}

function ticketHeading(file) {
  try {
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const match = line.match(/^#\s+(.+?)\s*#*\s*$/);
      if (match) return match[1];
    }
  } catch (_error) {
    // The directory name is a usable fallback.
  }
  return "";
}

function ticketPreview(file, limit = 1600) {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) return "";
    const length = Math.min(stat.size, limit + 4);
    const buffer = Buffer.alloc(length);
    const fd = fs.openSync(file, "r");
    let read = 0;
    try {
      read = fs.readSync(fd, buffer, 0, length, 0);
    } finally {
      fs.closeSync(fd);
    }
    let text = buffer.subarray(0, read).toString("utf8");
    if (stat.size > read) text = `${text.replace(/\uFFFD$/, "").trimEnd()}\n…`;
    return text;
  } catch (_error) {
    return "";
  }
}

function listTickets(root = ticketsRoot()) {
  if (!root) throw new Error("tickets directory not found");
  const buckets = TICKET_BUCKETS.map((bucket) => {
    const dir = path.join(root, bucket);
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_error) {
      // A missing bucket is displayed as empty.
    }
    const tickets = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      const ticketDir = path.join(dir, entry.name);
      const ticketFile = path.join(ticketDir, "ticket.md");
      let updated = null;
      let hasTicket = false;
      try {
        const stat = fs.statSync(ticketFile);
        if (stat.isFile()) {
          hasTicket = true;
          updated = stat.mtime;
        }
      } catch (_error) {
        // Legacy tickets can keep their payload in sibling files.
      }
      if (!updated) {
        try {
          updated = fs.statSync(ticketDir).mtime;
        } catch (_error) {
          continue;
        }
      }
      tickets.push({
        bucket,
        name: entry.name,
        title: (hasTicket && ticketHeading(ticketFile)) || entry.name,
        preview: hasTicket ? ticketPreview(ticketFile) : "",
        ticketMd: hasTicket,
        updated: updated.toISOString(),
      });
    }
    tickets.sort((a, b) => b.updated.localeCompare(a.updated) ||
      a.title.localeCompare(b.title));
    return { bucket, count: tickets.length, tickets };
  });
  return { root, buckets };
}

function ticketPath(root, bucket, name) {
  if (!root) throw new Error("tickets directory not found");
  if (!TICKET_BUCKETS.includes(bucket)) throw new Error("invalid ticket bucket");
  if (typeof name !== "string" || !name || name === "." || name === ".." ||
      name.includes("\0") || path.basename(name) !== name) {
    throw new Error("invalid ticket name");
  }
  const bucketDir = fs.realpathSync(path.join(root, bucket));
  const ticketDir = fs.realpathSync(path.join(bucketDir, name));
  if (!ticketDir.startsWith(bucketDir + path.sep)) {
    throw new Error("ticket is outside its bucket");
  }
  const ticketFile = path.join(ticketDir, "ticket.md");
  try {
    const real = fs.realpathSync(ticketFile);
    if (!real.startsWith(bucketDir + path.sep)) {
      throw new Error("ticket is outside its bucket");
    }
    if (fs.statSync(real).isFile()) return { dir: ticketDir, file: real };
  } catch (error) {
    if (error.message === "ticket is outside its bucket") throw error;
  }
  return { dir: ticketDir, file: "" };
}

function configView(cfg) {
  return {
    ...cfg,
    resolved: {
      sentinelsBin: resolveSentinelsBin(cfg),
      sentinelsRoot: resolveSentinelsRoot(cfg),
      sentinelsSettings: sentinelsSettingsPath(cfg),
    },
  };
}

function shellEnv(extra = {}) {
  return {
    ...process.env,
    NO_COLOR: "1",
    TERM: "dumb",
    ...extra,
  };
}

function sentinelsArgs(action) {
  switch (action) {
    case "status": return ["status"];
    case "cycle": return ["cycle"];
    case "findings": return ["findings"];
    case "logs": return [
      "logs", "--all-layers", "--follow", "--lines", "300", "--no-color",
    ];
    default: throw new Error("unknown sentinels action");
  }
}

function queryArgs(options = {}) {
  if (options.schema) return ["query", "--json", "--schema"];
  const rawLimit = Number(options.limit);
  const limit = Number.isInteger(rawLimit)
    ? Math.max(1, Math.min(QUERY_MAX_ROWS, rawLimit))
    : 200;
  if (options.latest) return ["query", "--json", "--latest-cycle"];
  const sql = typeof options.sql === "string" ? options.sql.trim() : "";
  if (sql.includes("\0")) throw new Error("query contains a NUL byte");
  if (sql.length > QUERY_MAX_SQL) {
    throw new Error(`query is longer than ${QUERY_MAX_SQL} characters`);
  }
  const search = typeof options.search === "string" ? options.search.trim() : "";
  if (search.includes("\0")) throw new Error("search contains a NUL byte");
  if (search.length > 200) throw new Error("search is longer than 200 characters");
  const severity = typeof options.severity === "string"
    ? options.severity.trim() : "";
  const status = typeof options.status === "string"
    ? options.status.trim() : "";
  const since = typeof options.since === "string" ? options.since.trim() : "";
  const filtered = Boolean(search || severity || status || since);
  if (sql) {
    if (filtered) throw new Error("filters apply to categories, not custom SQL");
    return ["query", "--json", "--sql", sql, "--limit", String(limit)];
  }
  const category = String(options.category || "inbox").toLowerCase();
  if (!QUERY_CATEGORIES.includes(category)) {
    throw new Error("unknown query category");
  }
  const args = ["query", "--json", "--category", category,
    "--limit", String(limit)];
  if (search) args.push("--search", search);
  if (severity) args.push("--severity", severity);
  if (status) args.push("--status", status);
  if (since) args.push("--since", since);
  return args;
}

function runCapture(binary, args, options = {}) {
  return new Promise((resolve) => {
    let output = "";
    let child;
    try {
      child = spawn(binary, args, {
        cwd: options.cwd || undefined,
        env: options.env || shellEnv(),
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      resolve({ code: -1, output: String(error) });
      return;
    }
    const append = (chunk) => {
      if (output.length < 8 * 1024 * 1024) {
        output += chunk.toString();
      }
    };
    child.stdout.on("data", append);
    child.stderr.on("data", append);
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, "SIGKILL"); } catch (_error) { /* gone */ }
    }, options.timeout || 60000);
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ code: -1, output: String(error) });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, output });
    });
  });
}

function startStream(binary, args, options = {}) {
  let done = false;
  let child;
  try {
    child = spawn(binary, args, {
      cwd: options.cwd || undefined,
      env: options.env || shellEnv(),
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    options.onLine?.(String(error));
    options.onDone?.(-1);
    return null;
  }
  const finish = (code, signal) => {
    if (done) return;
    done = true;
    options.onDone?.(code, signal);
  };
  for (const stream of [child.stdout, child.stderr]) {
    const reader = readline.createInterface({ input: stream });
    reader.on("line", (line) => options.onLine?.(line));
  }
  child.on("error", (error) => {
    options.onLine?.(String(error));
    finish(-1, null);
  });
  child.on("close", (code, signal) => finish(code, signal));
  return child;
}

function cancelProcess(child) {
  if (!child || child.exitCode !== null) return;
  try { process.kill(-child.pid, "SIGTERM"); } catch (_error) { /* gone */ }
  const timer = setTimeout(() => {
    try { process.kill(-child.pid, "SIGKILL"); } catch (_error) { /* gone */ }
  }, 5000);
  timer.unref?.();
}

function parseStatus(text) {
  const values = {};
  for (const line of String(text || "").split(/\r?\n/)) {
    const index = line.indexOf(":");
    if (index < 0) continue;
    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim();
    if (key && value) values[key] = value;
  }
  return values;
}

module.exports = {
  DEFAULT_CONFIG,
  TICKET_BUCKETS,
  cancelProcess,
  configPath,
  configView,
  listTickets,
  loadConfig,
  parseStatus,
  resolveSentinelsBin,
  resolveSentinelsRoot,
  runCapture,
  saveConfig,
  SENTINELS_SETTING_KEYS,
  loadSentinelsSettings,
  normalizeSentinelsSettings,
  queryArgs,
  QUERY_CATEGORIES,
  QUERY_MAX_ROWS,
  QUERY_MAX_SQL,
  saveSentinelsSettings,
  sentinelsArgs,
  sentinelsSchedulerPresent,
  sentinelsSettingsPath,
  shellEnv,
  startStream,
  ticketPath,
  ticketsRoot,
};
