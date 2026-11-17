"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const util = require("node:util");
const { app } = require("electron");

const pkg = require("../package.json");

const MAX_BYTES = 10 * 1024 * 1024;
const ENABLED = pkg.qaDiagnostics === true
  || process.env.QA_DIAGNOSTICS === "1"
  || process.argv.includes("--diagnostics");

let logPath = "";
let logBytes = 0;
let consoleHooks = null;

function logsDir() {
  try {
    return app.getPath("logs");
  } catch (_error) {
    // Fall through to userData or a temp path before app readiness.
  }
  try {
    return path.join(app.getPath("userData"), "logs");
  } catch (_error) {
    return path.join(os.tmpdir(), "qa-dashboard-logs");
  }
}

function stamp() {
  return new Date().toISOString();
}

function text(value) {
  if (value instanceof Error) return value.stack || value.message;
  if (typeof value === "string") return value;
  return util.inspect(value, {
    depth: 5,
    maxArrayLength: 100,
    maxStringLength: 20000,
    breakLength: 140,
  });
}

function rotateIfNeeded() {
  if (!logPath || logBytes < MAX_BYTES) return;
  try {
    fs.renameSync(logPath, `${logPath}.1`);
  } catch (_error) {
    // Keep appending if rotation fails.
  }
  logBytes = 0;
}

function writeRaw(line) {
  if (!ENABLED || !logPath) return;
  try {
    fs.appendFileSync(logPath, line, "utf8");
    logBytes += Buffer.byteLength(line, "utf8");
    rotateIfNeeded();
  } catch (_error) {
    // Logging must never break the app.
  }
}

function log(...args) {
  if (!ENABLED || !logPath) return;
  const rendered = args.map(text).join(" ");
  writeRaw(`${stamp()} [${process.type || "main"}] ${rendered}\n`);
}

function error(...args) {
  log("[error]", ...args);
}

function header() {
  const qaEnv = Object.entries(process.env)
    .filter(([key]) => key.startsWith("QA_"))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${/(TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)/i.test(key)
      ? "<redacted>" : value}`)
    .join("\n");
  const lines = [
    "=".repeat(88),
    "QA Dashboard diagnostics",
    `time: ${stamp()}`,
    `version: ${app.getVersion()}`,
    `diagnostics: ${ENABLED}`,
    `platform: ${process.platform} ${process.arch}`,
    `os: ${os.type()} ${os.release()} ${os.version()}`,
    `electron: ${process.versions.electron}`,
    `chrome: ${process.versions.chrome}`,
    `node: ${process.versions.node}`,
    `v8: ${process.versions.v8}`,
    `appPath: ${app.getAppPath()}`,
    `userData: ${app.getPath("userData")}`,
    `logs: ${path.dirname(logPath)}`,
    `cwd: ${process.cwd()}`,
    `argv: ${JSON.stringify(process.argv)}`,
    qaEnv ? `environment:\n${qaEnv}` : "environment: (no QA_* variables)",
    "=".repeat(88),
    "",
  ];
  writeRaw(`${lines.join("\n")}\n`);
}

function hookConsole() {
  if (consoleHooks) return;
  consoleHooks = {};
  for (const level of ["log", "info", "warn", "error", "debug"]) {
    consoleHooks[level] = console[level].bind(console);
    console[level] = (...args) => {
      consoleHooks[level](...args);
      log(`[console.${level}]`, ...args);
    };
  }
}

function hookProcess() {
  process.on("uncaughtException", (err) => {
    error("uncaughtException", err);
    if (consoleHooks) consoleHooks.error(err);
  });
  process.on("unhandledRejection", (reason) => {
    error("unhandledRejection", reason);
  });
  process.on("warning", (warning) => {
    log("[warning]", warning);
  });
}

function rendererConsole(_event, level, message, line, sourceId) {
  const details = level && typeof level === "object"
    ? level
    : { level, message, lineNumber: line, sourceId };
  log(`[renderer] [${details.level || "log"}] ${details.message || ""}`
    + ` (${details.sourceId || "?"}:${details.lineNumber || 0})`);
}

function hookWebContents(contents) {
  contents.on("console-message", rendererConsole);
  contents.on("preload-error", (_event, preloadPath, err) => {
    error("preload-error", preloadPath, err);
  });
  contents.on("did-fail-load", (_event, code, description, url, isMainFrame) => {
    error("did-fail-load", { code, description, url, isMainFrame });
  });
  contents.on("render-process-gone", (_event, details) => {
    error("render-process-gone", details);
  });
  contents.on("unresponsive", () => {
    error("webContents unresponsive", contents.getURL());
  });
}

function hookApp() {
  app.on("web-contents-created", (_event, contents) => hookWebContents(contents));
  app.on("child-process-gone", (_event, details) => {
    error("child-process-gone", details);
  });
  app.on("render-process-gone", (_event, contents, details) => {
    error("app render-process-gone", contents?.getURL?.(), details);
  });
  app.on("before-quit", () => log("app before-quit"));
  app.on("will-quit", () => log("app will-quit"));
}

function init() {
  if (!ENABLED || logPath) return ENABLED;
  try {
    const dir = logsDir();
    fs.mkdirSync(dir, { recursive: true });
    logPath = path.join(dir, "qa-dashboard.log");
    logBytes = fs.existsSync(logPath) ? fs.statSync(logPath).size : 0;
    rotateIfNeeded();
    header();
    hookConsole();
    hookProcess();
    hookApp();
    log(`diagnostics enabled: ${logPath}`);
    return true;
  } catch (err) {
    // Diagnostics must never prevent the application from starting.
    process.stderr.write(`diagnostics disabled: ${text(err)}\n`);
    logPath = "";
    return false;
  }
}

function info() {
  return {
    enabled: ENABLED && Boolean(logPath),
    path: logPath,
    directory: logPath ? path.dirname(logPath) : "",
  };
}

module.exports = {
  init,
  log,
  error,
  info,
  enabled: ENABLED,
};
