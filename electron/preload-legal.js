"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("qaLegal", {
  get: () => ipcRenderer.invoke("legal:get"),
  document: (id) => ipcRenderer.invoke("legal:document", id),
  openDocument: (id) => ipcRenderer.invoke("legal:open-document", id),
  exportReport: (format) => ipcRenderer.invoke("legal:export", format),
});
