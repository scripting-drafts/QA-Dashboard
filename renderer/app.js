"use strict";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const TITLES = {
  overview: ["QA Dashboard", "All three QA tools in one local dashboard."],
  sentinels: ["Sentinels", "Monitoring, findings, logs and evidence bundles."],
  malware: ["Malware Scan", "Bounded scanning with live findings and coverage status."],
  siem: ["SIEM", "Health, alerts and events from the local QA SIEM API."],
};

const SENTINEL_KEYS = [
  "last sample", "last ingest", "last hardware", "last lsm", "database",
  "critical", "inventory", "evidence", "ticket drafts", "core2 triage",
  "layer1", "boots", "notify", "layer2", "posture",
];

let config = null;
let currentView = "overview";
let sentinelsBusy = false;
let sentinelsAction = "";
let malwareBusy = false;
let malwareFindings = 0;
let toastTimer = null;

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 5000);
}

function setConnection(state, text) {
  const dot = $("#connection-dot");
  dot.classList.remove("ok", "error");
  if (state) dot.classList.add(state);
  $("#sidebar-status").textContent = text;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function muted(text) {
  const p = document.createElement("p");
  p.className = "muted";
  p.textContent = text;
  return p;
}

function append(pre, line, limit = 4000) {
  pre.textContent += `${line}\n`;
  if (pre.textContent.length > 250000) {
    pre.textContent = pre.textContent.slice(-180000);
  }
  const lines = pre.textContent.split("\n");
  if (lines.length > limit) {
    pre.textContent = lines.slice(-limit).join("\n");
  }
  pre.scrollTop = pre.scrollHeight;
}

function statusGrid(node, entries) {
  clear(node);
  if (!entries.length) {
    node.append(muted("No status values were returned."));
    return;
  }
  for (const [key, value] of entries) {
    const keyNode = document.createElement("div");
    keyNode.className = "key";
    keyNode.textContent = key;
    const valueNode = document.createElement("div");
    valueNode.className = "value";
    valueNode.textContent = String(value);
    node.append(keyNode, valueNode);
  }
}

function setView(view) {
  if (!TITLES[view]) view = "overview";
  currentView = view;
  $$(".view").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${view}`);
  });
  const [title, subtitle] = TITLES[view];
  document.title = title;
  document.body.classList.toggle("overview-mode", view === "overview");
  $("#view-title").textContent = title;
  $("#view-subtitle").textContent = subtitle;
  $("#overview").hidden = view === "overview";
}

function overviewText(values) {
  if (!values) return "Not loaded yet.";
  const parts = [];
  if (values["last sample"]) parts.push(`last sample ${values["last sample"]}`);
  if (values["layer1"]) parts.push(values["layer1"]);
  if (values.boots) parts.push(values.boots);
  return parts.length ? parts.join(" · ") : "Status loaded.";
}

async function loadSentinelsStatus() {
  try {
    const result = await window.qa.sentinels.status();
    const values = result.values || {};
    const entries = [];
    for (const key of SENTINEL_KEYS) {
      if (values[key]) entries.push([key, values[key]]);
    }
    for (const [key, value] of Object.entries(values)) {
      if (!SENTINEL_KEYS.includes(key)) entries.push([key, value]);
    }
    statusGrid($("#sen-status"), entries);
    $("#overview-sentinels").textContent = overviewText(values);
    if (result.output) {
      $("#sen-output").textContent = "";
      for (const line of result.output.split(/\r?\n/)) {
        if (line) append($("#sen-output"), line);
      }
    }
    setConnection("ok", "Sentinels ready");
  } catch (error) {
    setConnection("error", "Sentinels unavailable");
    toast(String(error.message || error), true);
  }
}

function setSentinelsBusy(busy) {
  sentinelsBusy = busy;
  $$("[data-sen]").forEach((button) => { button.disabled = busy; });
  $("#sen-refresh").disabled = busy;
  $("#sen-cancel").disabled = !busy;
}

async function runSentinels(action) {
  if (sentinelsBusy) return;
  sentinelsAction = action;
  setSentinelsBusy(true);
  $("#sen-output").textContent = "";
  append($("#sen-output"), `$ qa ${action}`);
  try {
    await window.qa.sentinels.run(action);
  } catch (error) {
    setSentinelsBusy(false);
    toast(String(error.message || error), true);
  }
}

function setMalwareBusy(busy) {
  malwareBusy = busy;
  $("#mal-start").disabled = busy;
  $("#mal-stop").disabled = !busy;
  $("#mal-folder").disabled = busy;
  $("#mal-file").disabled = busy;
}

function resetMalware() {
  malwareFindings = 0;
  $("#mal-findings").replaceChildren(muted("No findings yet."));
  $("#mal-output").textContent = "";
  $$("[data-mal]").forEach((node) => { node.textContent = "-"; });
}

function addFinding(event) {
  if (malwareFindings >= 500) return;
  malwareFindings += 1;
  const box = document.createElement("div");
  box.className = "finding";
  const head = document.createElement("div");
  head.className = "finding-head";
  const verdict = String(event.verdict || "unknown").toLowerCase();
  const badge = document.createElement("span");
  badge.className = `badge badge-${verdict}`;
  badge.textContent = verdict;
  const path = document.createElement("span");
  path.className = "finding-path";
  path.textContent = event.path || "";
  path.title = event.path || "";
  head.append(badge, path);
  const reasons = document.createElement("div");
  reasons.className = "finding-reasons";
  reasons.textContent = (event.reasons || []).join("; ");
  box.append(head, reasons);
  const list = $("#mal-findings");
  if (list.firstElementChild?.classList.contains("muted")) clear(list);
  list.append(box);
}

function renderMalwareSummary(summary) {
  for (const key of ["scanned", "clean", "suspicious", "infected", "errors",
                     "partial", "seconds"]) {
    const node = document.querySelector(`[data-mal="${key}"]`);
    if (!node) continue;
    let value = summary[key];
    if (key === "seconds" && value != null) {
      value = Number(value).toFixed(2);
    }
    node.textContent = value == null ? "-" : String(value);
  }
  const parts = [];
  for (const key of ["scanned", "clean", "suspicious", "infected", "partial"]) {
    if (summary[key] != null) parts.push(`${key} ${summary[key]}`);
  }
  $("#overview-malware").textContent = parts.join(" · ") || "Scan finished.";
}

async function startMalware() {
  if (malwareBusy) return;
  const target = $("#mal-path").value.trim();
  if (!target) {
    toast("Choose a file or folder to scan.", true);
    return;
  }
  resetMalware();
  setMalwareBusy(true);
  append($("#mal-output"), "starting scan…");
  try {
    await window.qa.malware.scan({
      target,
      allFiles: $("#mal-all").checked,
      deep: $("#mal-deep").checked,
      quarantine: $("#mal-quarantine").checked,
      steg: $("#mal-steg").checked,
      clamav: $("#mal-clamav").value,
      yara: $("#mal-yara").value,
      yaraRules: $("#mal-yara-rules").value,
    });
  } catch (error) {
    setMalwareBusy(false);
    toast(String(error.message || error), true);
  }
}

async function showQuarantine() {
  try {
    const result = await window.qa.malware.list();
    $("#mal-output").textContent = "";
    for (const line of String(result.output || "").split(/\r?\n/)) {
      if (line) append($("#mal-output"), line);
    }
    $("#mal-output").scrollTop = 0;
    if (result.code !== 0) toast("Quarantine list failed.", true);
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

function severityBadge(severity) {
  const value = String(severity || "info").toLowerCase();
  const badge = document.createElement("span");
  badge.className = `badge badge-${value === "critical" || value === "error"
    ? "infected" : value === "warning" ? "suspicious" : "clean"}`;
  badge.textContent = value;
  return badge;
}

function renderSiemStatus(data) {
  const health = data.health || {};
  const stats = data.stats || {};
  const entries = [
    ["service", data.service || "unknown"],
    ["health", health.status || "unknown"],
    ["version", health.version || "-"],
    ["uptime", formatUptime(health.uptime_s)],
    ["events", stats.events ?? "-"],
    ["open alerts", stats.alerts_open ?? "-"],
    ["alerts total", stats.alerts_total ?? "-"],
    ["hosts", stats.hosts ?? "-"],
    ["last event", stats.last_event_ts || "-"],
  ];
  statusGrid($("#siem-status"), entries);
  if (data.error) {
    setConnection("error", "SIEM issue");
    $("#overview-siem").textContent = data.error;
    toast(data.error, true);
  } else {
    setConnection("ok", "SIEM connected");
    $("#overview-siem").textContent =
      `${stats.events ?? 0} events · ${stats.alerts_open ?? 0} open alerts`;
  }
}

function formatUptime(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) return "-";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

function renderAlerts(alerts) {
  const node = $("#siem-alerts");
  clear(node);
  if (!alerts.length) {
    node.append(muted("No open alerts."));
    return;
  }
  for (const alert of alerts) {
    const row = document.createElement("div");
    row.className = "row";
    const head = document.createElement("div");
    head.className = "row-head";
    head.append(severityBadge(alert.severity));
    const title = document.createElement("span");
    title.className = "row-title";
    title.textContent = alert.rule || "alert";
    head.append(title);
    const ack = document.createElement("button");
    ack.textContent = "Ack";
    ack.addEventListener("click", async () => {
      try {
        await window.qa.siem.ack(alert.id);
        toast(`Alert ${alert.id} acknowledged.`);
        loadSiem();
      } catch (error) {
        toast(String(error.message || error), true);
      }
    });
    head.append(ack);
    const detail = document.createElement("div");
    detail.className = "row-detail";
    detail.textContent = `host ${alert.host_id ?? "-"} · count ${alert.count ?? "-"} · last ${alert.last_seen ?? "-"}`;
    row.append(head, detail);
    node.append(row);
  }
}

function renderEvents(events) {
  const node = $("#siem-events");
  clear(node);
  if (!events.length) {
    node.append(muted("No recent events."));
    return;
  }
  for (const event of events) {
    const row = document.createElement("div");
    row.className = "row";
    const head = document.createElement("div");
    head.className = "row-head";
    head.append(severityBadge(event.severity));
    const title = document.createElement("span");
    title.className = "row-title";
    title.textContent = event.event_type || "event";
    head.append(title);
    const time = document.createElement("span");
    time.className = "muted mono";
    time.textContent = event.ts || "";
    head.append(time);
    const detail = document.createElement("div");
    detail.className = "row-detail";
    detail.textContent = `${event.rule ?? "-"} · host ${event.host_id ?? "-"} · ${event.subject || event.detail || ""}`;
    row.append(head, detail);
    node.append(row);
  }
}

async function loadSiem() {
  try {
    const data = await window.qa.siem.refresh();
    renderSiemStatus(data);
    renderAlerts(Array.isArray(data.alerts) ? data.alerts : []);
    renderEvents(Array.isArray(data.events) ? data.events : []);
  } catch (error) {
    setConnection("error", "SIEM unavailable");
    toast(String(error.message || error), true);
  }
}

function fillSettings(view) {
  if (!view) return;
  $("#set-sentinels-bin").value = view.sentinelsBin || "";
  $("#set-sentinels-root").value = view.sentinelsRoot || "";
  $("#set-malware-bin").value = view.malwareBin || "";
  $("#set-siem-url").value = view.siemUrl || "";
  $("#set-siem-token").value = view.siemTokenFile || "";
  const resolved = view.resolved || {};
  $("#settings-resolved").textContent =
    `Detected: qa=${resolved.sentinelsBin || "missing"} · ` +
    `malware-scan=${resolved.malwareBin || "missing"} · ` +
    `token=${resolved.siemTokenAvailable ? "readable" : "missing"}`;
}

async function openSettings() {
  try {
    config = await window.qa.getConfig();
    fillSettings(config);
    $("#settings-dialog").showModal();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function saveSettings(event) {
  event.preventDefault();
  try {
    config = await window.qa.saveConfig({
      sentinelsBin: $("#set-sentinels-bin").value,
      sentinelsRoot: $("#set-sentinels-root").value,
      malwareBin: $("#set-malware-bin").value,
      siemUrl: $("#set-siem-url").value,
      siemTokenFile: $("#set-siem-token").value,
    });
    $("#settings-dialog").close();
    toast("Settings saved.");
    refreshCurrent();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

function refreshCurrent() {
  if (currentView === "overview") {
    loadSentinelsStatus();
    loadSiem();
  } else if (currentView === "sentinels") {
    loadSentinelsStatus();
  } else if (currentView === "siem") {
    loadSiem();
  } else {
    $("#mal-path").focus();
  }
}

function bind() {
  $$("[data-open]").forEach((button) => {
    button.addEventListener("click", () => window.qa.openModule(button.dataset.open));
  });
  $("#overview").addEventListener("click", () => window.qa.openModule("overview"));
  $("#refresh").addEventListener("click", refreshCurrent);
  $("#settings").addEventListener("click", openSettings);
  $("#settings-form").addEventListener("submit", saveSettings);

  $("#sen-refresh").addEventListener("click", loadSentinelsStatus);
  $$("[data-sen]").forEach((button) => {
    button.addEventListener("click", () => runSentinels(button.dataset.sen));
  });
  $("#sen-cancel").addEventListener("click", async () => {
    await window.qa.sentinels.cancel();
    append($("#sen-output"), "stop requested");
  });

  $("#mal-start").addEventListener("click", startMalware);
  $("#mal-stop").addEventListener("click", async () => {
    await window.qa.malware.cancel();
    append($("#mal-output"), "stop requested");
  });
  $("#mal-list").addEventListener("click", showQuarantine);
  $("#mal-folder").addEventListener("click", async () => {
    const selected = await window.qa.pickPath("folder");
    if (selected) $("#mal-path").value = selected;
  });
  $("#mal-file").addEventListener("click", async () => {
    const selected = await window.qa.pickPath("file");
    if (selected) $("#mal-path").value = selected;
  });

  $("#siem-refresh").addEventListener("click", loadSiem);
  $("#siem-open").addEventListener("click", async () => {
    try { await window.qa.siem.open(); } catch (error) {
      toast(String(error.message || error), true);
    }
  });

  $$("[data-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.dataset.action;
      if (action === "sentinels-status") loadSentinelsStatus();
      else if (action === "siem-refresh") loadSiem();
      else if (action === "malware-focus") window.qa.openModule("malware");
    });
  });

  window.qa.onEvent((payload) => {
    if (payload.scope === "sentinels") {
      if (payload.type === "line") append($("#sen-output"), payload.line);
      if (payload.type === "done") {
        setSentinelsBusy(false);
        append($("#sen-output"), `exit ${payload.code}`);
        if (["cycle", "evidence", "findings"].includes(sentinelsAction)) {
          loadSentinelsStatus();
        }
      }
    }
    if (payload.scope === "malware") {
      if (payload.type === "line") {
        append($("#mal-output"), payload.line);
        let event = null;
        try { event = JSON.parse(payload.line); } catch (_error) { /* text */ }
        if (event && event.event === "finding") addFinding(event);
        if (event && event.event === "summary") renderMalwareSummary(event);
      }
      if (payload.type === "done") {
        setMalwareBusy(false);
        append($("#mal-output"), `scan exit ${payload.code}`);
        if (payload.code !== 0 && payload.code !== 1) {
          toast(`Malware Scan exited with ${payload.code}.`, true);
        }
      }
    }
  });
}

async function init() {
  bind();
  const params = new URLSearchParams(location.search);
  const initial = params.get("module") || "overview";
  setView(initial);
  try {
    config = await window.qa.getConfig();
  } catch (error) {
    toast(String(error.message || error), true);
  }
  if (initial === "overview") {
    loadSentinelsStatus();
    loadSiem();
  } else if (initial === "sentinels") {
    loadSentinelsStatus();
  } else if (initial === "siem") {
    loadSiem();
  }
}

init();
