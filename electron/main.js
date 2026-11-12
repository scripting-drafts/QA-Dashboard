"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const {
  app, BrowserWindow, dialog, ipcMain, Menu, nativeTheme, screen, shell,
} = require("electron");
const backend = require("./backend");

const APP_ID = "org.scriptingdrafts.QADashboard";
const MODULES = new Set([
  "overview", "sentinels", "sen-overview", "tickets", "findings",
  "logs", "siem", "record",
]);
const APP_ICON_LIGHT = path.join(
  __dirname, "..", "assets", "qa-dashboard-light-256.png");
const APP_ICON_DARK = path.join(
  __dirname, "..", "assets", "qa-dashboard-256.png");

const WINDOW_TITLES = {
  overview: "QA Dashboard",
  sentinels: "QA Sentinels Database",
  "sen-overview": "QA Sentinels Overview",
  tickets: "QA Sentinels Tickets",
  logs: "QA Sentinels Logs",
  siem: "QA SIEM",
  record: "SIEM Record",
};

const WINDOW_SIZES = {
  overview: { width: 980, height: 640 },
  sentinels: { width: 1180, height: 820 },
  "sen-overview": { width: 1180, height: 820 },
  tickets: { width: 1180, height: 820 },
  logs: { width: 980, height: 680 },
  siem: { width: 1080, height: 820 },
  record: { width: 900, height: 720 },
};

const windows = new Map();
let activeSentinels = null;
let activeLogs = null;
let logsRestartTimer = null;
let logsRunId = 0;
let logsSeq = 0;
let logsQuitting = false;
let logsError = "";
const LOG_BUFFER_MAX = 4000;
const logBuffer = [];
let startupModule = "overview";
let screenshotPath = "";
let allMinimized = false;
let lastLaunchAt = 0;
let sentinelsTimer = null;
let siemTimer = null;
let sentinelsCycleTimer = null;
let sentinelsRefreshing = false;
let siemRefreshing = false;
let sentinelsCycleRunning = false;
let recordPayload = null;

const AUTO_REFRESH_MS = 10000;

function windowBackground() {
  return nativeTheme.shouldUseDarkColors ? "#0b1418" : "#ffffff";
}

function windowIcon() {
  return nativeTheme.shouldUseDarkColors ? APP_ICON_DARK : APP_ICON_LIGHT;
}

function syncWindowBackgrounds() {
  const color = windowBackground();
  const icon = windowIcon();
  for (const window of windows.values()) {
    if (window.isDestroyed()) continue;
    window.setBackgroundColor(color);
    window.setIcon(icon);
  }
}

function parseArgs(argv) {
  let module = "overview";
  let screenshot = "";
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value.startsWith("--module=")) {
      const candidate = value.slice("--module=".length);
      if (MODULES.has(candidate)) module = candidate;
    } else if (value === "--module" && argv[index + 1]) {
      if (MODULES.has(argv[index + 1])) module = argv[index + 1];
      index += 1;
    } else if (value.startsWith("--screenshot=")) {
      screenshot = value.slice("--screenshot=".length);
    } else if (value === "--screenshot" && argv[index + 1]) {
      screenshot = argv[index + 1];
      index += 1;
    }
  }
  return { module, screenshot };
}

function normalizeModule(module, tab = "") {
  let name = MODULES.has(module) ? module : "overview";
  if (name === "findings" || name === "tickets") {
    return { module: "tickets", tab: "tickets" };
  }
  if (name === "sen-overview") {
    return { module: "sen-overview", tab: "overview" };
  }
  return { module: name, tab: "" };
}

function createWindow(module = "overview", show = true, tab = "") {
  ({ module, tab } = normalizeModule(module, tab));
  if (!MODULES.has(module)) module = "overview";
  const existing = windows.get(module);
  if (existing && !existing.isDestroyed()) {
    if (show) {
      if (existing.isMinimized()) existing.restore();
      existing.show();
      existing.focus();
    }
    return existing;
  }
  const size = WINDOW_SIZES[module];
  const area = screen.getPrimaryDisplay().workArea;
  const offset = Math.min(windows.size, 5) * 28;
  const x = Math.min(
    Math.max(0, Math.round(area.x + (area.width - size.width) / 2) + offset),
    area.x + Math.max(0, area.width - size.width));
  const y = Math.min(
    Math.max(0, Math.round(area.y + (area.height - size.height) / 2) + offset),
    area.y + Math.max(0, area.height - size.height));
  const window = new BrowserWindow({
    ...size,
    x,
    y,
    minWidth: module === "overview" ? 820 : 900,
    minHeight: module === "overview" ? 540 : 620,
    show: false,
    title: WINDOW_TITLES[module],
    icon: windowIcon(),
    backgroundColor: windowBackground(),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  const renderModule = module === "tickets" ? "sen-overview" : module;
  const renderTab = module === "tickets" ? "tickets" : tab;
  const pane = module === "tickets"
    ? "tickets" : (module === "sen-overview" ? "overview" : "");
  const url = pathToFileURL(path.join(__dirname, "..", "renderer", "index.html"));
  url.searchParams.set("module", renderModule);
  if (renderTab) url.searchParams.set("tab", renderTab);
  if (pane) url.searchParams.set("pane", pane);
  window.loadURL(url.toString());
  window.once("ready-to-show", () => {
    if (show) window.show();
  });
  window.on("closed", () => {
    windows.delete(module);
    if (module === "sentinels") backend.cancelProcess(activeSentinels);
    if (module === "record") recordPayload = null;
  });
  window.webContents.setWindowOpenHandler(({ url: target }) => {
    if (/^https?:\/\//i.test(target)) shell.openExternal(target);
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, target) => {
    if (!target.startsWith("file://")) {
      event.preventDefault();
      if (/^https?:\/\//i.test(target)) shell.openExternal(target);
    }
  });
  window.on("minimize", () => {
    const open = Array.from(windows.values()).filter((win) => !win.isDestroyed());
    allMinimized = open.length > 0 && open.every((win) => win.isMinimized());
  });
  window.on("restore", () => {
    if (!allMinimized) return;
    allMinimized = false;
    if (Date.now() - lastLaunchAt < 1500) return;
    setTimeout(() => {
      if (Date.now() - lastLaunchAt >= 1500) showWindow("overview");
    }, 150);
  });
  windows.set(module, window);
  return window;
}

function showWindow(module = "overview", tab = "") {
  const normalized = normalizeModule(module, tab);
  if (!MODULES.has(normalized.module)) normalized.module = "overview";
  const existing = windows.get(normalized.module);
  const window = createWindow(normalized.module, true, normalized.tab);
  if (existing && !existing.isDestroyed() && normalized.tab) {
    sendEvent(window.webContents, {
      scope: "sen-tabs", type: "select", tab: normalized.tab,
    });
  }
  if (window.isMinimized()) window.restore();
  window.show();
  window.focus();
  allMinimized = false;
  return window;
}

function sendEvent(sender, payload) {
  if (sender && !sender.isDestroyed()) sender.send("event", payload);
}

function broadcastTo(modules, payload) {
  let sent = false;
  for (const module of modules) {
    const window = windows.get(module);
    if (window && !window.isDestroyed()) {
      window.webContents.send("event", payload);
      sent = true;
    }
  }
  return sent;
}

async function sentinelsStatus() {
  const cfg = backend.loadConfig();
  const binary = backend.resolveSentinelsBin(cfg);
  if (!binary) throw new Error("qa command not found");
  const root = backend.resolveSentinelsRoot(cfg);
  const result = await backend.runCapture(binary, ["status"], {
    cwd: root || undefined,
    env: backend.shellEnv(root ? { QA_SENTINELS_HOME: root } : {}),
    timeout: 30000,
  });
  return {
    code: result.code,
    output: result.output,
    values: backend.parseStatus(result.output),
  };
}

function appendLogLine(line) {
  const text = String(line ?? "");
  logsSeq += 1;
  logBuffer.push({ line: text, seq: logsSeq });
  if (logBuffer.length > LOG_BUFFER_MAX) {
    logBuffer.splice(0, logBuffer.length - LOG_BUFFER_MAX);
  }
  broadcastTo(["logs"], {
    scope: "sentinels", type: "line", line: text, seq: logsSeq,
  });
}

function scheduleLogsRestart() {
  if (logsQuitting || logsRestartTimer) return;
  logsRestartTimer = setTimeout(() => {
    logsRestartTimer = null;
    startBackgroundLogs();
  }, 5000);
  logsRestartTimer.unref?.();
}

function startBackgroundLogs() {
  if (logsQuitting || activeLogs) return;
  const cfg = backend.loadConfig();
  const binary = backend.resolveSentinelsBin(cfg);
  if (!binary) {
    logsError = "qa command not found";
    return;
  }
  const root = backend.resolveSentinelsRoot(cfg);
  const runId = ++logsRunId;
  logsError = "";
  const child = backend.startStream(binary, backend.sentinelsArgs("logs"), {
    cwd: root || undefined,
    env: backend.shellEnv(root ? { QA_SENTINELS_HOME: root } : {}),
    onLine: (line) => {
      if (runId === logsRunId) appendLogLine(line);
    },
    onDone: (code) => {
      if (runId !== logsRunId) return;
      activeLogs = null;
      if (logsQuitting) return;
      logsError = `log stream exited (${code}); restarting`;
      appendLogLine(`[dashboard] ${logsError}`);
      scheduleLogsRestart();
    },
  });
  if (runId !== logsRunId) {
    backend.cancelProcess(child);
    return;
  }
  activeLogs = child || null;
  if (!child) {
    logsError = "log stream failed to start";
    scheduleLogsRestart();
  }
}

function restartBackgroundLogs() {
  logsRunId += 1;
  if (logsRestartTimer) {
    clearTimeout(logsRestartTimer);
    logsRestartTimer = null;
  }
  backend.cancelProcess(activeLogs);
  activeLogs = null;
  logsError = "";
  startBackgroundLogs();
}

function stopBackgroundLogs() {
  logsQuitting = true;
  logsRunId += 1;
  if (logsRestartTimer) {
    clearTimeout(logsRestartTimer);
    logsRestartTimer = null;
  }
  backend.cancelProcess(activeLogs);
  activeLogs = null;
}

async function sentinelsQuery(options = {}) {
  const cfg = backend.loadConfig();
  const binary = backend.resolveSentinelsBin(cfg);
  if (!binary) throw new Error("qa command not found");
  const root = backend.resolveSentinelsRoot(cfg);
  const args = backend.queryArgs(options);
  const result = await backend.runCapture(binary, args, {
    cwd: root || undefined,
    env: backend.shellEnv(root ? { QA_SENTINELS_HOME: root } : {}),
    timeout: 20000,
  });
  let data;
  try {
    data = JSON.parse(result.output);
  } catch (_error) {
    throw new Error(result.output.trim().slice(0, 500) || "query returned no output");
  }
  if (data && data.error) throw new Error(String(data.error));
  if (result.code !== 0) {
    throw new Error(`query failed with exit ${result.code}`);
  }
  if (data && (Object.hasOwn(data, "latest") ||
               Object.hasOwn(data, "last_new") ||
               Array.isArray(data.tables))) {
    return data;
  }
  if (!data || !Array.isArray(data.columns) || !Array.isArray(data.rows)) {
    throw new Error("query returned an unexpected result");
  }
  return data;
}

async function autoRefreshSentinels() {
  if (sentinelsRefreshing) return;
  if (!windows.has("overview") && !windows.has("sen-overview")) return;
  sentinelsRefreshing = true;
  try {
    broadcastTo(["overview", "sen-overview"], {
      scope: "sentinels", type: "status", data: await sentinelsStatus(),
    });
  } catch (error) {
    broadcastTo(["overview", "sen-overview"], {
      scope: "sentinels", type: "status", error: String(error.message || error),
    });
  } finally {
    sentinelsRefreshing = false;
  }
}

async function autoRefreshSiem() {
  if (siemRefreshing) return;
  if (!windows.has("siem")) return;
  siemRefreshing = true;
  try {
    broadcastTo(["siem"], {
      scope: "siem", type: "snapshot",
      data: await backend.siemSnapshot(backend.loadConfig()),
    });
  } catch (error) {
    broadcastTo(["siem"], {
      scope: "siem", type: "snapshot", error: String(error.message || error),
    });
  } finally {
    siemRefreshing = false;
  }
}

async function runSentinelsCycle() {
  if (sentinelsCycleRunning || activeSentinels) return;
  const cfg = backend.loadConfig();
  const binary = backend.resolveSentinelsBin(cfg);
  if (!binary) return;
  sentinelsCycleRunning = true;
  try {
    const root = backend.resolveSentinelsRoot(cfg);
    await backend.runCapture(binary, ["cycle"], {
      cwd: root || undefined,
      env: backend.shellEnv(root ? { QA_SENTINELS_HOME: root } : {}),
      timeout: 30 * 60 * 1000,
    });
  } catch (_error) {
    // The next status refresh reports the current sentinel state.
  } finally {
    sentinelsCycleRunning = false;
    autoRefreshSentinels();
  }
}

function sentinelsCycleMinutes() {
  const value = Number(backend.loadConfig().sentinelsCycleMinutes);
  return Number.isFinite(value) && value > 0 ? Math.max(1, Math.round(value)) : 10;
}

function startSentinelsCycleTimer() {
  clearInterval(sentinelsCycleTimer);
  sentinelsCycleTimer = setInterval(
    runSentinelsCycle, sentinelsCycleMinutes() * 60 * 1000);
}

function stopSentinelsCycleTimer() {
  clearInterval(sentinelsCycleTimer);
  sentinelsCycleTimer = null;
}

// The installed Sentinel scheduler (systemd timer or user cron) owns the
// routine cycle. Keep the in-process timer only as a fallback for a host with
// the dashboard alone.
function refreshSentinelsCycleTimer() {
  stopSentinelsCycleTimer();
  if (backend.sentinelsSchedulerPresent()) return;
  startSentinelsCycleTimer();
}

function startAutoRefresh() {
  clearInterval(sentinelsTimer);
  clearInterval(siemTimer);
  sentinelsTimer = setInterval(autoRefreshSentinels, AUTO_REFRESH_MS);
  siemTimer = setInterval(autoRefreshSiem, AUTO_REFRESH_MS);
  refreshSentinelsCycleTimer();
}

function stopAutoRefresh() {
  clearInterval(sentinelsTimer);
  clearInterval(siemTimer);
  stopSentinelsCycleTimer();
  sentinelsTimer = null;
  siemTimer = null;
}

function registerIpc() {
  ipcMain.handle("config:get", () => backend.configView(backend.loadConfig()));
  ipcMain.handle("config:save", (_event, incoming) => {
    const current = backend.loadConfig();
    for (const key of Object.keys(backend.DEFAULT_CONFIG)) {
      if (incoming && typeof incoming[key] === "string") {
        current[key] = incoming[key].trim();
      }
    }
    backend.saveConfig(current);
    refreshSentinelsCycleTimer();
    restartBackgroundLogs();
    setTimeout(() => {
      autoRefreshSentinels();
      autoRefreshSiem();
    }, 0);
    return backend.configView(backend.loadConfig());
  });

  ipcMain.handle("app:open", (_event, module, tab) => {
    showWindow(
      String(module || "overview"),
      tab ? String(tab) : "");
    return true;
  });

  ipcMain.handle("app:open-rules", async () => {
    const target = path.join(__dirname, "..", "renderer", "rules.html");
    const error = await shell.openPath(target);
    if (error) throw new Error(error);
    return target;
  });

  ipcMain.handle("app:open-tickets", async () => {
    const found = backend.ticketsRoot();
    if (!found) throw new Error("tickets directory not found");
    const error = await shell.openPath(found);
    if (error) throw new Error(error);
    return found;
  });

  ipcMain.handle("tickets:list", () => backend.listTickets());

  ipcMain.handle("tickets:open", async (_event, bucket, name) => {
    const target = backend.ticketPath(
      backend.ticketsRoot(), String(bucket || ""), String(name || ""));
    const pathToOpen = target.file || target.dir;
    const error = await shell.openPath(pathToOpen);
    if (error) throw new Error(error);
    return { path: pathToOpen, ticketMd: Boolean(target.file) };
  });

  ipcMain.handle("record:open", (_event, record) => {
    let text = "";
    try {
      text = JSON.stringify(record);
    } catch (_error) {
      throw new Error("invalid record");
    }
    if (!text || text.length > 1024 * 1024) throw new Error("invalid record");
    recordPayload = JSON.parse(text);
    const window = showWindow("record");
    window.webContents.send("event", {
      scope: "record", type: "show", data: recordPayload,
    });
    return true;
  });

  ipcMain.handle("record:get", () => recordPayload);

  ipcMain.handle("app:version", () => app.getVersion());

  ipcMain.handle("window:fit-sentinels", (event, height) => {
    const window = windows.get("sen-overview");
    if (!window || window.isDestroyed() ||
        window.webContents !== event.sender || window.isMaximized()) {
      return false;
    }
    const numeric = Math.round(Number(height));
    if (!Number.isFinite(numeric)) return false;
    const [width] = window.getContentSize();
    const display = screen.getDisplayMatching(window.getBounds());
    const maxHeight = Math.floor(display.workArea.height * 0.92);
    const target = Math.max(620, Math.min(numeric, maxHeight));
    window.setContentSize(width, target);
    return true;
  });

  ipcMain.handle("sentinels:status", async () => sentinelsStatus());
  ipcMain.handle("sentinels:query", async (_event, options) =>
    sentinelsQuery(options));

  ipcMain.handle("sentinels:run", async (event, action) => {
    if (activeSentinels) throw new Error("a sentinel command is already running");
    const name = String(action || "");
    if (!["cycle", "findings"].includes(name)) {
      throw new Error("unsupported sentinels action");
    }
    const cfg = backend.loadConfig();
    const binary = backend.resolveSentinelsBin(cfg);
    if (!binary) throw new Error("qa command not found");
    const root = backend.resolveSentinelsRoot(cfg);
    const args = backend.sentinelsArgs(name);
    const sender = event.sender;
    activeSentinels = backend.startStream(binary, args, {
      cwd: root || undefined,
      env: backend.shellEnv(root ? { QA_SENTINELS_HOME: root } : {}),
      onLine: (line) => sendEvent(sender, { scope: "sentinels", type: "line", line }),
      onDone: (code) => {
        activeSentinels = null;
        sendEvent(sender, { scope: "sentinels", type: "done", code });
      },
    });
    return { started: Boolean(activeSentinels) };
  });

  ipcMain.handle("sentinels:cancel", () => {
    backend.cancelProcess(activeSentinels);
    activeSentinels = null;
    return true;
  });

  ipcMain.handle("sentinels:logs", async () => {
    if (!activeLogs && !logsRestartTimer) startBackgroundLogs();
    return {
      started: Boolean(activeLogs),
      lines: logBuffer.map((entry) => entry.line),
      total: logsSeq,
      error: logsError,
    };
  });

  ipcMain.handle("sentinels:stopLogs", () => true);

  ipcMain.handle("siem:refresh", async () => backend.siemSnapshot(backend.loadConfig()));
  ipcMain.handle("siem:ack", async (_event, id) => {
    const numeric = Number(id);
    if (!Number.isInteger(numeric) || numeric <= 0) {
      throw new Error("invalid alert id");
    }
    await backend.siemAck(backend.loadConfig(), numeric);
    return true;
  });
  ipcMain.handle("siem:open", async () => {
    const cfg = backend.loadConfig();
    await shell.openExternal(cfg.siemUrl.replace(/\/+$/, "") + "/");
    return true;
  });

  ipcMain.handle("dialog:pick", async (_event, kind) => {
    const parent = BrowserWindow.getFocusedWindow()
      || windows.get("overview")
      || Array.from(windows.values()).find((window) => !window.isDestroyed())
      || null;
    const result = await dialog.showOpenDialog(parent, {
      title: kind === "folder" ? "Select a folder" : "Select a file",
      properties: [kind === "folder" ? "openDirectory" : "openFile"],
    });
    return result.canceled || !result.filePaths.length
      ? null : result.filePaths[0];
  });
}

const initial = parseArgs(process.argv.slice(1));
if (!app.requestSingleInstanceLock({ module: initial.module })) {
  app.quit();
} else {
  startupModule = initial.module;
  screenshotPath = initial.screenshot;

  app.setName("QA Dashboard");
  app.setAppUserModelId(APP_ID);
  nativeTheme.themeSource = "system";
  Menu.setApplicationMenu(null);

  app.on("second-instance", (_event, argv, _workingDirectory, additionalData) => {
    lastLaunchAt = Date.now();
    const next = (additionalData && additionalData.module)
      || parseArgs(argv.slice(1)).module;
    showWindow(next || "overview");
  });

  app.whenReady().then(() => {
    registerIpc();
    nativeTheme.on("updated", syncWindowBackgrounds);
    startAutoRefresh();
    startBackgroundLogs();
    const window = createWindow(startupModule, true);
    if (screenshotPath) {
      window.webContents.once("did-finish-load", () => {
        setTimeout(async () => {
          try {
            const image = await window.webContents.capturePage();
            fs.writeFileSync(screenshotPath, image.toPNG());
          } catch (error) {
            console.error(error);
          } finally {
            app.quit();
          }
        }, 1500);
      });
    }
    app.on("activate", () => showWindow("overview"));
  });

  app.on("before-quit", () => {
    stopAutoRefresh();
    stopBackgroundLogs();
    backend.cancelProcess(activeSentinels);
  });
}
