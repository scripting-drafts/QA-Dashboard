"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFile, spawn } = require("node:child_process");
const readline = require("node:readline");

const DEFAULT_CONFIG = {
  sentinelsBin: "",
  sentinelsRoot: "",
  malwareBin: "",
  siemUrl: "http://127.0.0.1:8088",
  siemTokenFile: "",
  sentinelsCycleMinutes: "10",
};

const MAX_HTTP_BODY = 8 * 1024 * 1024;

function configPath() {
  const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(base, "qa-desktop", "config.json");
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
  cfg.siemUrl = (cfg.siemUrl || DEFAULT_CONFIG.siemUrl).replace(/\/+$/, "");
  return cfg;
}

function saveConfig(cfg) {
  const target = configPath();
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const payload = {};
  for (const key of Object.keys(DEFAULT_CONFIG)) {
    payload[key] = typeof cfg[key] === "string" ? cfg[key].trim() : "";
  }
  if (!payload.siemUrl) payload.siemUrl = DEFAULT_CONFIG.siemUrl;
  const tmp = `${target}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, target);
  fs.chmodSync(target, 0o600);
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
    path.join(os.homedir(), "Quality-Assurance-Sentinels"),
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

function resolveMalwareBin(cfg) {
  const configured = executable(cfg.malwareBin);
  if (configured) return configured;
  const envBin = executable(process.env.MALWARE_SCAN_BIN || "");
  if (envBin) return envBin;
  const fromPath = executable("malware-scan");
  if (fromPath) return fromPath;
  for (const candidate of [
    path.join(os.homedir(), "malware-scan", "build", "malware-scan"),
    path.join(os.homedir(), ".local", "bin", "malware-scan"),
  ]) {
    if (fs.existsSync(candidate)) {
      const found = executable(candidate);
      if (found) return found;
    }
  }
  return "";
}

function resolveSandboxBin(cfg) {
  const envBin = executable(process.env.MALWARE_SCAN_SANDBOX_BIN || "");
  if (envBin) return envBin;
  const malware = resolveMalwareBin(cfg);
  if (malware) {
    const sibling = executable(path.join(path.dirname(malware), "malware-scan-sandbox"));
    if (sibling) return sibling;
  }
  const fromPath = executable("malware-scan-sandbox");
  if (fromPath) return fromPath;
  for (const candidate of [
    path.join(os.homedir(), "malware-scan", "scripts", "malware-scan-sandbox"),
    path.join(os.homedir(), ".local", "bin", "malware-scan-sandbox"),
  ]) {
    if (fs.existsSync(candidate)) {
      const found = executable(candidate);
      if (found) return found;
    }
  }
  return "";
}

function resolveSiemTokenFile(cfg) {
  const configured = expand(cfg.siemTokenFile);
  if (configured) return configured;
  const envFile = expand(process.env.QA_SIEM_TOKEN_FILE || "");
  if (envFile) return envFile;
  for (const candidate of [
    "/etc/qa-siem/token",
    path.join(os.homedir(), ".config", "qa-siem", "token"),
  ]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return "/etc/qa-siem/token";
}

function readToken(file) {
  if (!file) return "";
  try {
    const token = fs.readFileSync(file, "utf8").trim();
    return token.length > 0 && token.length <= 4096 ? token : "";
  } catch (_error) {
    return "";
  }
}

function configView(cfg) {
  return {
    ...cfg,
    resolved: {
      sentinelsBin: resolveSentinelsBin(cfg),
      sentinelsRoot: resolveSentinelsRoot(cfg),
      malwareBin: resolveMalwareBin(cfg),
      siemTokenFile: resolveSiemTokenFile(cfg),
      siemTokenAvailable: Boolean(readToken(resolveSiemTokenFile(cfg))),
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

function buildMalwareArgs(binary, target, options = {}) {
  if (!binary) throw new Error("malware-scan executable is not configured");
  const pathValue = expand(String(target || "").trim());
  if (!pathValue) throw new Error("choose a file or folder to scan");
  const args = ["scan", "--json", "--fail-on", "none"];
  if (options.allFiles) args.push("--all-files");
  if (options.deep) args.push("--deep");
  if (options.quarantine) args.push("--quarantine");
  if (options.steg) args.push("--steg");
  if (options.clamav && options.clamav.trim()) {
    args.push("--clamav", expand(options.clamav.trim()));
  }
  if (options.yara && options.yara.trim()) {
    args.push("--yara", expand(options.yara.trim()));
  }
  if (options.yaraRules && options.yaraRules.trim()) {
    args.push("--yara-rules", expand(options.yaraRules.trim()));
  }
  args.push("--", pathValue);
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

async function httpJson(baseUrl, requestPath, token = "", options = {}) {
  const base = String(baseUrl || "").replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(base)) {
    throw new Error("SIEM URL must start with http:// or https://");
  }
  const url = `${base}/${String(requestPath || "").replace(/^\/+/, "")}`;
  const headers = { Accept: "application/json" };
  let body;
  if (options.payload !== undefined) {
    body = JSON.stringify(options.payload);
    headers["Content-Type"] = "application/json";
  }
  if (token) headers.Authorization = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(), options.timeout || 5000);
  try {
    const response = await fetch(url, {
      method: options.method || "GET",
      headers,
      body,
      signal: controller.signal,
    });
    const text = await response.text();
    if (text.length > MAX_HTTP_BODY) {
      throw new Error("SIEM response exceeded the size limit");
    }
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch (_error) { /* below */ }
    if (!response.ok) {
      const message = parsed && parsed.error
        ? String(parsed.error) : `HTTP ${response.status}`;
      throw new Error(message);
    }
    return parsed;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("SIEM request timed out");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function serviceState() {
  return new Promise((resolve) => {
    execFile("systemctl", ["is-active", "qa-siem.service"],
      { timeout: 3000 }, (error, stdout, stderr) => {
        const value = String(stdout || stderr || "").trim();
        resolve(value || (error ? "unknown" : "inactive"));
      });
  });
}

async function siemSnapshot(cfg) {
  const tokenFile = resolveSiemTokenFile(cfg);
  const token = readToken(tokenFile);
  const result = {
    health: null,
    stats: null,
    alerts: [],
    events: [],
    service: await serviceState(),
    error: "",
    tokenAvailable: Boolean(token),
  };
  try {
    result.health = await httpJson(cfg.siemUrl, "/healthz", "", { timeout: 3000 });
  } catch (error) {
    result.error = String(error.message || error);
  }
  if (token) {
    try {
      result.stats = await httpJson(cfg.siemUrl, "/api/v1/stats", token);
      result.alerts = await httpJson(
        cfg.siemUrl, "/api/v1/alerts?status=open&limit=50", token);
      result.events = await httpJson(
        cfg.siemUrl, "/api/v1/events?limit=50", token);
    } catch (error) {
      result.error = String(error.message || error);
    }
  } else if (!result.error) {
    result.error = "No bearer token available.";
  }
  return result;
}

async function siemAck(cfg, id) {
  const token = readToken(resolveSiemTokenFile(cfg));
  if (!token) throw new Error("No bearer token available.");
  await httpJson(cfg.siemUrl, "/api/v1/alerts/ack", token, {
    method: "POST",
    payload: { id },
  });
}

module.exports = {
  DEFAULT_CONFIG,
  buildMalwareArgs,
  cancelProcess,
  configPath,
  configView,
  httpJson,
  loadConfig,
  parseStatus,
  resolveMalwareBin,
  resolveSandboxBin,
  resolveSentinelsBin,
  resolveSentinelsRoot,
  resolveSiemTokenFile,
  runCapture,
  saveConfig,
  sentinelsArgs,
  shellEnv,
  siemAck,
  siemSnapshot,
  startStream,
};
