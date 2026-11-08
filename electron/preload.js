"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("qa", {
  getConfig: () => ipcRenderer.invoke("config:get"),
  saveConfig: (config) => ipcRenderer.invoke("config:save", config),
  pickPath: (kind) => ipcRenderer.invoke("dialog:pick", kind),
  sentinels: {
    status: () => ipcRenderer.invoke("sentinels:status"),
    run: (action) => ipcRenderer.invoke("sentinels:run", action),
    cancel: () => ipcRenderer.invoke("sentinels:cancel"),
  },
  malware: {
    scan: (options) => ipcRenderer.invoke("malware:scan", options),
    cancel: () => ipcRenderer.invoke("malware:cancel"),
    list: () => ipcRenderer.invoke("malware:list"),
  },
  siem: {
    refresh: () => ipcRenderer.invoke("siem:refresh"),
    ack: (id) => ipcRenderer.invoke("siem:ack", id),
    open: () => ipcRenderer.invoke("siem:open"),
  },
  onEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on("event", listener);
    return () => ipcRenderer.removeListener("event", listener);
  },
  onNavigate: (callback) => {
    const listener = (_event, module) => callback(module);
    ipcRenderer.on("navigate", listener);
    return () => ipcRenderer.removeListener("navigate", listener);
  },
});
