"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const {
  app, BrowserWindow, dialog, ipcMain, Menu, nativeTheme, screen, shell,
} = require("electron");
const backend = require("./backend");

const APP_ID = "org.scriptingdrafts.QADashboard";
const MODULES = new Set(["overview", "sentinels", "logs", "malware", "siem"]);
const APP_ICON = path.join(__dirname, "..", "assets", "qa-dashboard-256.png");

const WINDOW_TITLES = {
  overview: "QA Dashboard",
  sentinels: "QA Sentinels",
  logs: "Sentinels Logs",
  malware: "Malware Scan",
  siem: "QA SIEM",
};

const WINDOW_SIZES = {
  overview: { width: 980, height: 640 },
  sentinels: { width: 1020, height: 760 },
  logs: { width: 980, height: 680 },
  malware: { width: 1080, height: 820 },
  siem: { width: 1080, height: 820 },
};

const windows = new Map();
let activeSentinels = null;
let activeLogs = null;
let activeMalware = null;
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

const AUTO_REFRESH_MS = 10000;

function windowBackground() {
  return nativeTheme.shouldUseDarkColors ? "#0b1418" : "#ffffff";
}

function syncWindowBackgrounds() {
  const color = windowBackground();
  for (const window of windows.values()) {
    if (!window.isDestroyed()) window.setBackgroundColor(color);
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

function createWindow(module = "overview", show = true) {
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
    icon: APP_ICON,
    backgroundColor: windowBackground(),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  const url = pathToFileURL(path.join(__dirname, "..", "renderer", "index.html"));
  url.searchParams.set("module", module);
  window.loadURL(url.toString());
  window.once("ready-to-show", () => {
    if (show) window.show();
  });
  window.on("closed", () => {
    windows.delete(module);
    if (module === "sentinels") backend.cancelProcess(activeSentinels);
    if (module === "logs") {
      backend.cancelProcess(activeLogs);
      activeLogs = null;
    }
    if (module === "malware") backend.cancelProcess(activeMalware);
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

function showWindow(module = "overview") {
  if (!MODULES.has(module)) module = "overview";
  const window = createWindow(module, true);
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

async function autoRefreshSentinels() {
  if (sentinelsRefreshing) return;
  if (!windows.has("overview") && !windows.has("sentinels")) return;
  sentinelsRefreshing = true;
  try {
    broadcastTo(["overview", "sentinels"], {
      scope: "sentinels", type: "status", data: await sentinelsStatus(),
    });
  } catch (error) {
    broadcastTo(["overview", "sentinels"], {
      scope: "sentinels", type: "status", error: String(error.message || error),
    });
  } finally {
    sentinelsRefreshing = false;
  }
}

async function autoRefreshSiem() {
  if (siemRefreshing) return;
  if (!windows.has("overview") && !windows.has("siem")) return;
  siemRefreshing = true;
  try {
    broadcastTo(["overview", "siem"], {
      scope: "siem", type: "snapshot",
      data: await backend.siemSnapshot(backend.loadConfig()),
    });
  } catch (error) {
    broadcastTo(["overview", "siem"], {
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

function startAutoRefresh() {
  clearInterval(sentinelsTimer);
  clearInterval(siemTimer);
  sentinelsTimer = setInterval(autoRefreshSentinels, AUTO_REFRESH_MS);
  siemTimer = setInterval(autoRefreshSiem, AUTO_REFRESH_MS);
  startSentinelsCycleTimer();
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
    startSentinelsCycleTimer();
    setTimeout(() => {
      autoRefreshSentinels();
      autoRefreshSiem();
    }, 0);
    return backend.configView(backend.loadConfig());
  });

  ipcMain.handle("app:open", (_event, module) => {
    showWindow(String(module || "overview"));
    return true;
  });

  ipcMain.handle("app:open-tickets", async () => {
    const tickets = path.join(os.homedir(),
      "Quality-Assurance-Sentinels", "tickets");
    const error = await shell.openPath(tickets);
    if (error) throw new Error(error);
    return tickets;
  });

  ipcMain.handle("app:version", () => app.getVersion());

  ipcMain.handle("window:fit-sentinels", (event, height) => {
    const window = windows.get("sentinels");
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

  ipcMain.handle("sentinels:logs", async (event) => {
    if (activeLogs) return { started: false };
    const cfg = backend.loadConfig();
    const binary = backend.resolveSentinelsBin(cfg);
    if (!binary) throw new Error("qa command not found");
    const root = backend.resolveSentinelsRoot(cfg);
    const sender = event.sender;
    activeLogs = backend.startStream(binary, backend.sentinelsArgs("logs"), {
      cwd: root || undefined,
      env: backend.shellEnv(root ? { QA_SENTINELS_HOME: root } : {}),
      onLine: (line) => sendEvent(sender, { scope: "sentinels", type: "line", line }),
      onDone: (code) => {
        activeLogs = null;
        sendEvent(sender, { scope: "sentinels", type: "done", code });
      },
    });
    return { started: Boolean(activeLogs) };
  });

  ipcMain.handle("sentinels:stopLogs", () => {
    backend.cancelProcess(activeLogs);
    activeLogs = null;
    return true;
  });

  ipcMain.handle("malware:scan", async (event, options) => {
    if (activeMalware) throw new Error("a scan is already running");
    const cfg = backend.loadConfig();
    const binary = backend.resolveMalwareBin(cfg);
    if (!binary) throw new Error("malware-scan executable not found");
    const args = backend.buildMalwareArgs(binary, options?.target, options || {});
    const sender = event.sender;
    activeMalware = backend.startStream(binary, args, {
      onLine: (line) => sendEvent(sender, { scope: "malware", type: "line", line }),
      onDone: (code) => {
        activeMalware = null;
        sendEvent(sender, { scope: "malware", type: "done", code });
      },
    });
    return { started: Boolean(activeMalware) };
  });

  ipcMain.handle("malware:cancel", () => {
    backend.cancelProcess(activeMalware);
    activeMalware = null;
    return true;
  });

  ipcMain.handle("malware:list", async () => {
    const cfg = backend.loadConfig();
    const binary = backend.resolveMalwareBin(cfg);
    if (!binary) throw new Error("malware-scan executable not found");
    return backend.runCapture(binary, ["list"], { timeout: 30000 });
  });

  ipcMain.handle("malware:sandbox", async (event, options) => {
    if (activeMalware) throw new Error("a malware task is already running");
    const target = String(options?.target || "").trim();
    const asFile = Boolean(options?.file);
    if (!target) throw new Error("choose a quarantine ID or file");
    if (!asFile && (!/^[A-Za-z0-9._-]+$/.test(target) ||
                    target.includes(".."))) {
      throw new Error("invalid quarantine ID");
    }
    const cfg = backend.loadConfig();
    const binary = backend.resolveSandboxBin(cfg);
    if (!binary) throw new Error("malware-scan-sandbox executable not found");
    const args = asFile ? ["--file", target] : ["--quarantine", target];
    const sender = event.sender;
    activeMalware = backend.startStream(binary, args, {
      onLine: (line) => sendEvent(sender, { scope: "sandbox", type: "line", line }),
      onDone: (code) => {
        activeMalware = null;
        sendEvent(sender, { scope: "sandbox", type: "done", code });
      },
    });
    return { started: Boolean(activeMalware) };
  });

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
    backend.cancelProcess(activeSentinels);
    backend.cancelProcess(activeLogs);
    backend.cancelProcess(activeMalware);
  });
}
