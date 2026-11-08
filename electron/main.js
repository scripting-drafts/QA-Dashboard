"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const {
  app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, shell, Tray,
} = require("electron");
const backend = require("./backend");

const APP_ID = "org.scriptingdrafts.QADashboard";
const MODULES = new Set(["overview", "sentinels", "malware", "siem"]);
const ICON_DIR = path.join(__dirname, "..", "assets");

let mainWindow = null;
let tray = null;
let isQuitting = false;
let activeSentinels = null;
let activeMalware = null;
let startupModule = "overview";
let startHidden = false;
let screenshotPath = "";

function parseArgs(argv) {
  let module = "overview";
  let hidden = false;
  let screenshot = "";
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--tray") hidden = true;
    else if (value.startsWith("--module=")) {
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
  return { module, hidden, screenshot };
}

function trayImage() {
  for (const name of ("tray-dashboard-22.png", "tray-dashboard-32.png",
                      "tray-dashboard-64.png")) {
    const image = nativeImage.createFromPath(path.join(ICON_DIR, name));
    if (!image.isEmpty()) return image;
  }
  return nativeImage.createEmpty();
}

function showWindow(module = "overview") {
  if (!MODULES.has(module)) module = "overview";
  if (!mainWindow || mainWindow.isDestroyed()) {
    createWindow(true, module);
    return;
  }
  mainWindow.show();
  mainWindow.focus();
  mainWindow.webContents.send("navigate", module);
}

function createWindow(show = true, module = "overview") {
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (show) {
      mainWindow.show();
      mainWindow.focus();
      mainWindow.webContents.send("navigate", module);
    }
    return mainWindow;
  }
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 900,
    minWidth: 980,
    minHeight: 680,
    show: false,
    title: "QA Dashboard",
    backgroundColor: "#1d1d20",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  const url = pathToFileURL(path.join(__dirname, "..", "renderer", "index.html"));
  url.searchParams.set("module", module);
  mainWindow.loadURL(url.toString());
  mainWindow.once("ready-to-show", () => {
    if (show) mainWindow.show();
  });
  mainWindow.on("close", (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
  mainWindow.on("closed", () => { mainWindow = null; });
  mainWindow.webContents.setWindowOpenHandler(({ url: target }) => {
    if (/^https?:\/\//i.test(target)) shell.openExternal(target);
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (event, target) => {
    if (!target.startsWith("file://")) {
      event.preventDefault();
      if (/^https?:\/\//i.test(target)) shell.openExternal(target);
    }
  });
  return mainWindow;
}

function createTray() {
  tray = new Tray(trayImage());
  tray.setToolTip("QA Dashboard");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "QA Dashboard", click: () => showWindow("overview") },
    { type: "separator" },
    { label: "Sentinels", click: () => showWindow("sentinels") },
    { label: "Malware Scan", click: () => showWindow("malware") },
    { label: "SIEM", click: () => showWindow("siem") },
  ]));
  tray.on("click", () => showWindow("overview"));
  tray.on("double-click", () => showWindow("overview"));
}

function sendEvent(sender, payload) {
  if (sender && !sender.isDestroyed()) sender.send("event", payload);
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
    return backend.configView(backend.loadConfig());
  });

  ipcMain.handle("sentinels:status", async () => {
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
  });

  ipcMain.handle("sentinels:run", async (event, action) => {
    if (activeSentinels) throw new Error("a sentinel command is already running");
    const cfg = backend.loadConfig();
    const binary = backend.resolveSentinelsBin(cfg);
    if (!binary) throw new Error("qa command not found");
    const root = backend.resolveSentinelsRoot(cfg);
    const args = backend.sentinelsArgs(String(action || ""));
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
    if (!mainWindow) return null;
    const result = await dialog.showOpenDialog(mainWindow, {
      title: kind === "folder" ? "Select a folder" : "Select a file",
      properties: [kind === "folder" ? "openDirectory" : "openFile"],
    });
    return result.canceled || !result.filePaths.length
      ? null : result.filePaths[0];
  });
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  const parsed = parseArgs(process.argv.slice(1));
  startupModule = parsed.module;
  startHidden = parsed.hidden;
  screenshotPath = parsed.screenshot;

  app.setName("QA Dashboard");
  app.setAppUserModelId(APP_ID);
  Menu.setApplicationMenu(null);

  app.on("second-instance", (_event, argv) => {
    const next = parseArgs(argv.slice(1)).module;
    showWindow(next || "overview");
  });

  app.whenReady().then(() => {
    registerIpc();
    createTray();
    createWindow(!startHidden, startupModule);
    if (screenshotPath) {
      mainWindow.webContents.once("did-finish-load", () => {
        setTimeout(async () => {
          try {
            const image = await mainWindow.webContents.capturePage();
            fs.writeFileSync(screenshotPath, image.toPNG());
          } catch (error) {
            console.error(error);
          } finally {
            isQuitting = true;
            app.quit();
          }
        }, 1500);
      });
    }
    app.on("activate", () => showWindow("overview"));
  });

  app.on("window-all-closed", () => {
    // Keep the tray process alive; the window is hidden on close.
  });

  app.on("before-quit", () => {
    isQuitting = true;
    backend.cancelProcess(activeSentinels);
    backend.cancelProcess(activeMalware);
    if (tray) {
      tray.destroy();
      tray = null;
    }
  });
}
