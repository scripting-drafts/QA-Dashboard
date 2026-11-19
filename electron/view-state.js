"use strict";

const fs = require("node:fs");
const path = require("node:path");

const STATE_FILE = "last-view.json";
const MAX_BYTES = 4096;
const MAX_FIELD = 40;
const MODULE_PATTERN = /^[a-z][a-z0-9-]{0,39}$/;

function statePath(userData) {
  return path.join(userData, STATE_FILE);
}

function validModule(module) {
  return typeof module === "string" && MODULE_PATTERN.test(module);
}

function normalize(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const module = typeof value.module === "string" ? value.module : "";
  const tab = typeof value.tab === "string" ? value.tab : "";
  if (!validModule(module) || tab.length > MAX_FIELD) return null;
  return { module, tab };
}

function load(userData) {
  if (!userData) return null;
  try {
    const target = statePath(userData);
    const info = fs.lstatSync(target);
    if (!info.isFile() || info.size > MAX_BYTES) return null;
    return normalize(JSON.parse(fs.readFileSync(target, "utf8")));
  } catch (_error) {
    return null;
  }
}

function save(userData, module, tab = "") {
  if (!userData) throw new Error("userData is required");
  if (!validModule(module)) throw new Error("invalid module");
  if (typeof tab !== "string" || tab.length > MAX_FIELD) {
    throw new Error("invalid tab");
  }
  fs.mkdirSync(userData, { recursive: true });
  const target = statePath(userData);
  const temp = `${target}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temp, JSON.stringify({ module, tab }, null, 2) + "\n",
      { mode: 0o600 });
    fs.renameSync(temp, target);
    if (process.platform !== "win32") fs.chmodSync(target, 0o600);
  } catch (error) {
    try {
      fs.unlinkSync(temp);
    } catch (_cleanup) {
      // Keep the original error.
    }
    throw error;
  }
}

module.exports = { STATE_FILE, load, save, statePath };
