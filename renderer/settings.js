"use strict";

const $ = (selector) => document.querySelector(selector);

const FIELDS = {
  sentinelsBin: "#set-sentinels-bin",
  sentinelsRoot: "#set-sentinels-root",
  sentinelsCycleMinutes: "#set-sentinels-cycle",
  sentinelsCycleHours: "#set-sen-cycle-hours",
  sentinelsDraftsRetentionDays: "#set-sen-drafts-days",
  sentinelsRaiseLookbackDays: "#set-sen-lookback-days",
  sentinelsEventRetentionDays: "#set-sen-events-days",
  sentinelsSamplesRetentionDays: "#set-sen-samples-days",
  sentinelsProcRetentionDays: "#set-sen-proc-days",
  sentinelsInventoryRetentionDays: "#set-sen-inventory-days",
};

let busy = false;

function setStatus(message, error = false) {
  const node = $("#settings-status");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.hidden = !message;
}

function setBusy(value) {
  busy = value;
  $("#settings-save").disabled = value;
  $("#settings-close").disabled = value;
}

function fill(config) {
  for (const [key, selector] of Object.entries(FIELDS)) {
    $(selector).value = config[key] ?? "";
  }
}

function collect() {
  const payload = {};
  for (const [key, selector] of Object.entries(FIELDS)) {
    payload[key] = $(selector).value;
  }
  return payload;
}

async function load() {
  try {
    fill(await window.qaSettings.getConfig());
  } catch (error) {
    setStatus(String(error.message || error), true);
  }
}

async function save(event) {
  if (event) event.preventDefault();
  if (busy) return;
  setBusy(true);
  setStatus("");
  try {
    await window.qaSettings.saveConfig(collect());
    setStatus("Saved.");
    setTimeout(() => window.qaSettings.close(), 500);
  } catch (error) {
    setStatus(String(error.message || error), true);
    setBusy(false);
  }
}

$("#settings-form").addEventListener("submit", save);
$("#settings-close").addEventListener("click", () => {
  if (!busy) window.qaSettings.close();
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || busy) return;
  event.preventDefault();
  window.qaSettings.close();
});

load();
