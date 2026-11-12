"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("qa", {
  version: () => ipcRenderer.invoke("app:version"),
  fitSentinels: (height) => ipcRenderer.invoke("window:fit-sentinels", height),
  getConfig: () => ipcRenderer.invoke("config:get"),
  saveConfig: (config) => ipcRenderer.invoke("config:save", config),
  pickPath: (kind) => ipcRenderer.invoke("dialog:pick", kind),
  openModule: (module, tab) => ipcRenderer.invoke("app:open", module, tab),
  openRules: () => ipcRenderer.invoke("app:open-rules"),
  openDocs: () => ipcRenderer.invoke("app:open-docs"),
  openTickets: () => ipcRenderer.invoke("app:open-tickets"),
  tickets: {
    list: () => ipcRenderer.invoke("tickets:list"),
    open: (bucket, name) => ipcRenderer.invoke("tickets:open", bucket, name),
  },
  sentinels: {
    status: () => ipcRenderer.invoke("sentinels:status"),
    query: (options) => ipcRenderer.invoke("sentinels:query", options),
    run: (action) => ipcRenderer.invoke("sentinels:run", action),
    cancel: () => ipcRenderer.invoke("sentinels:cancel"),
    logsStart: () => ipcRenderer.invoke("sentinels:logs"),
    logsStop: () => ipcRenderer.invoke("sentinels:stopLogs"),
  },
  onEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on("event", listener);
    return () => ipcRenderer.removeListener("event", listener);
  },
});
