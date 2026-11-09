"use strict";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const TITLES = {
  overview: ["QA Dashboard", "All three QA tools in one local dashboard."],
  sentinels: ["Sentinels", "Monitoring, findings and live logs."],
  logs: ["Sentinels Logs", "Live sentinel log stream."],
  malware: ["Malware Scan", "Bounded scanning with live findings and coverage status."],
  siem: ["SIEM", "Health, alerts and events from the local QA SIEM API."],
};

const SETTINGS_TITLES = {
  sentinels: "Sentinels settings",
  malware: "Malware Scan settings",
  siem: "SIEM settings",
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
let sentinelsFitted = false;
let logsRunning = false;
let settingsModule = "";
let malwareBusy = false;
let malwareFindings = 0;
let malwareView = "raw";
const expandedSiemRows = new Set();
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
  document.body.dataset.module = view;
  document.body.classList.toggle("overview-mode", view === "overview");
  $("#view-title").textContent = title;
  $("#view-subtitle").textContent = subtitle;
}

function overviewText(values) {
  if (!values) return "Not loaded yet.";
  const parts = [];
  if (values["last sample"]) parts.push(`last sample ${values["last sample"]}`);
  if (values["layer1"]) parts.push(values["layer1"]);
  if (values.boots) parts.push(values.boots);
  return parts.length ? parts.join(" · ") : "Status loaded.";
}

function renderSentinelsStatus(result) {
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
  setConnection("ok", "Sentinels ready");
  if (!sentinelsFitted && currentView === "sentinels") {
    sentinelsFitted = true;
    requestAnimationFrame(() => {
      const bottom = $("#sen-status").getBoundingClientRect().bottom;
      window.qa.fitSentinels(Math.ceil(bottom + 24));
    });
  }
}

async function loadSentinelsStatus() {
  try {
    renderSentinelsStatus(await window.qa.sentinels.status());
  } catch (error) {
    setConnection("error", "Sentinels unavailable");
    toast(String(error.message || error), true);
  }
}

function setSentinelsBusy(busy) {
  sentinelsBusy = busy;
  $$("[data-sen]").forEach((button) => { button.disabled = busy; });
}

async function runSentinels(action) {
  if (sentinelsBusy) return;
  sentinelsAction = action;
  setSentinelsBusy(true);
  try {
    await window.qa.sentinels.run(action);
  } catch (error) {
    setSentinelsBusy(false);
    toast(String(error.message || error), true);
  }
}

async function startSentinelLogs() {
  if (logsRunning) return;
  const output = $("#logs-output");
  if (!output) return;
  logsRunning = true;
  output.textContent = "";
  append(output, "$ qa logs --all-layers --follow");
  setConnection("ok", "Live logs");
  try {
    const result = await window.qa.sentinels.logsStart();
    if (!result.started) append(output, "log stream already running");
  } catch (error) {
    logsRunning = false;
    setConnection("error", "Logs unavailable");
    append(output, `error: ${error.message || error}`);
  }
}

function setMalwareBusy(busy) {
  malwareBusy = busy;
  $("#mal-start").disabled = busy;
  $("#mal-stop").disabled = !busy;
  $("#mal-folder").disabled = busy;
  $("#mal-file").disabled = busy;
  $("#mal-sandbox-run").disabled = busy;
  $("#mal-sandbox-target").disabled = busy;
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

function setMalwareView(view) {
  malwareView = ["raw", "quarantine", "sandbox"].includes(view) ? view : "raw";
  $$("[data-mal-view]").forEach((button) => {
    const active = button.dataset.malView === malwareView;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  $("#mal-raw-pane").hidden = malwareView !== "raw";
  $("#mal-quarantine-pane").hidden = malwareView !== "quarantine";
  $("#mal-sandbox-pane").hidden = malwareView !== "sandbox";
  $("#mal-view-title").textContent = {
    raw: "Raw output",
    quarantine: "Quarantine list",
    sandbox: "Sandbox",
  }[malwareView];
  if (malwareView === "quarantine") showQuarantine();
}

async function startMalware() {
  if (malwareBusy) return;
  const target = $("#mal-path").value.trim();
  if (!target) {
    toast("Choose a file or folder to scan.", true);
    return;
  }
  setMalwareView("raw");
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

function renderQuarantine(result) {
  const node = $("#mal-quarantine-list");
  clear(node);
  let rows = 0;
  for (const line of String(result.output || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const match = line.match(/^(\S+)\s+(\S+)\s+(\d+)\s+(.*)$/);
    if (!match) {
      if (!/^No quarantined files\.$/.test(line.trim())) node.append(muted(line));
      continue;
    }
    const [, id, verdict, size, original] = match;
    const row = document.createElement("div");
    row.className = "row";
    const head = document.createElement("div");
    head.className = "row-head";
    const badge = document.createElement("span");
    badge.className = `badge badge-${verdict}`;
    badge.textContent = verdict;
    const title = document.createElement("span");
    title.className = "row-title";
    title.textContent = id;
    const button = document.createElement("button");
    button.textContent = "Sandbox";
    button.addEventListener("click", () => {
      $("#mal-sandbox-target").value = id;
      runSandbox(id, false);
    });
    head.append(badge, title, button);
    const detail = document.createElement("div");
    detail.className = "row-detail";
    detail.textContent = `${Number(size).toLocaleString()} bytes · ${original}`;
    row.append(head, detail);
    node.append(row);
    rows += 1;
  }
  if (!rows) node.append(muted("No quarantined files."));
  if (result.code !== 0) toast("Quarantine list failed.", true);
}

async function showQuarantine() {
  try {
    renderQuarantine(await window.qa.malware.list());
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function runSandbox(targetOverride, fileOverride) {
  if (malwareBusy) return;
  const target = String(targetOverride ||
    $("#mal-sandbox-target").value || "").trim();
  if (!target) {
    toast("Choose a quarantine ID or file.", true);
    return;
  }
  const asFile = fileOverride !== undefined
    ? fileOverride
    : target.includes("/") || target.startsWith("~");
  setMalwareView("sandbox");
  $("#mal-sandbox-target").value = target;
  const output = $("#mal-sandbox-output");
  output.textContent = "";
  append(output, `sandbox ${asFile ? "file" : "quarantine"}: ${target}`);
  setMalwareBusy(true);
  try {
    await window.qa.malware.sandbox({ target, file: asFile });
  } catch (error) {
    setMalwareBusy(false);
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

function makeRowClickable(row, record, key) {
  row.classList.add("row-clickable");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-expanded", "false");
  const head = row.querySelector(".row-head");
  const toggle = document.createElement("span");
  toggle.className = "row-toggle";
  toggle.textContent = "\u25b8";
  toggle.setAttribute("aria-hidden", "true");
  const button = head.querySelector("button");
  if (button) head.insertBefore(toggle, button);
  else head.append(toggle);
  let body = null;
  const collapse = () => {
    if (!body) return;
    body.remove();
    body = null;
    row.classList.remove("open");
    row.setAttribute("aria-expanded", "false");
  };
  const expand = () => {
    if (body) return;
    body = document.createElement("pre");
    body.className = "row-json";
    body.textContent = JSON.stringify(record, null, 2);
    row.append(body);
    row.classList.add("open");
    row.setAttribute("aria-expanded", "true");
  };
  const activate = () => {
    if (body) {
      expandedSiemRows.delete(key);
      collapse();
      return;
    }
    expandedSiemRows.add(key);
    expand();
  };
  row.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    activate();
  });
  row.addEventListener("keydown", (event) => {
    if (event.target !== row) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      activate();
    }
  });
  if (expandedSiemRows.has(key)) expand();
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
    const time = document.createElement("span");
    time.className = "muted mono";
    time.textContent = alert.last_seen || "";
    head.append(time);
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
    detail.textContent = `host ${alert.host_id ?? "-"} · count ${alert.count ?? "-"}`;
    row.append(head, detail);
    makeRowClickable(row, alert, `alert:${alert.id}`);
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
    makeRowClickable(row, event, `event:${event.id}`);
    node.append(row);
  }
}

function renderSiemSnapshot(data) {
  renderSiemStatus(data);
  renderAlerts(Array.isArray(data.alerts) ? data.alerts : []);
  renderEvents(Array.isArray(data.events) ? data.events : []);
}

async function loadSiem() {
  try {
    renderSiemSnapshot(await window.qa.siem.refresh());
  } catch (error) {
    setConnection("error", "SIEM unavailable");
    toast(String(error.message || error), true);
  }
}

function fillSettings(view) {
  if (!view) return;
  $("#set-sentinels-bin").value = view.sentinelsBin || "";
  $("#set-sentinels-root").value = view.sentinelsRoot || "";
  $("#set-sentinels-cycle").value = view.sentinelsCycleMinutes || "10";
  $("#set-malware-bin").value = view.malwareBin || "";
  $("#set-siem-url").value = view.siemUrl || "";
  $("#set-siem-token").value = view.siemTokenFile || "";
  $$("[data-settings-module]").forEach((label) => {
    label.hidden = label.dataset.settingsModule !== settingsModule;
  });
  $("#settings-title").textContent = SETTINGS_TITLES[settingsModule] || "Settings";
  const resolved = view.resolved || {};
  if (settingsModule === "sentinels") {
    $("#settings-resolved").textContent =
      `Detected: qa=${resolved.sentinelsBin || "missing"} · ` +
      `root=${resolved.sentinelsRoot || "missing"} · ` +
      `cycle=${view.sentinelsCycleMinutes || "10"}m`;
  } else if (settingsModule === "malware") {
    $("#settings-resolved").textContent =
      `Detected: malware-scan=${resolved.malwareBin || "missing"}`;
  } else {
    $("#settings-resolved").textContent =
      `Endpoint: ${view.siemUrl || "-"} · ` +
      `token=${resolved.siemTokenAvailable ? "readable" : "missing"}`;
  }
}

async function openSettings() {
  if (!SETTINGS_TITLES[currentView]) return;
  settingsModule = currentView;
  try {
    config = await window.qa.getConfig();
    fillSettings(config);
    $("#settings-dialog").showModal();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function saveSettings(event) {
  if (event) event.preventDefault();
  const payload = {};
  if (settingsModule === "sentinels") {
    payload.sentinelsBin = $("#set-sentinels-bin").value;
    payload.sentinelsRoot = $("#set-sentinels-root").value;
    payload.sentinelsCycleMinutes = $("#set-sentinels-cycle").value;
  } else if (settingsModule === "malware") {
    payload.malwareBin = $("#set-malware-bin").value;
  } else if (settingsModule === "siem") {
    payload.siemUrl = $("#set-siem-url").value;
    payload.siemTokenFile = $("#set-siem-token").value;
  } else {
    return;
  }
  try {
    config = await window.qa.saveConfig(payload);
    $("#settings-dialog").close();
    toast(`${SETTINGS_TITLES[settingsModule]} saved.`);
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

function bind() {
  $$("[data-open]").forEach((button) => {
    button.addEventListener("click", () => window.qa.openModule(button.dataset.open));
  });
  $("#settings").addEventListener("click", openSettings);
  $("#settings-form").addEventListener("submit", (event) => event.preventDefault());
  $("#settings-save").addEventListener("click", saveSettings);
  $("#settings-cancel").addEventListener("click", () => $("#settings-dialog").close());

  $$("[data-sen]").forEach((button) => {
    button.addEventListener("click", () => runSentinels(button.dataset.sen));
  });
  $("#sen-findings").addEventListener("click", async () => {
    try {
      await window.qa.openTickets();
    } catch (error) {
      toast(String(error.message || error), true);
    }
  });
  $("#sen-logs").addEventListener("click", () => window.qa.openModule("logs"));

  $("#mal-start").addEventListener("click", startMalware);
  $("#mal-stop").addEventListener("click", async () => {
    await window.qa.malware.cancel();
    const output = malwareView === "sandbox"
      ? $("#mal-sandbox-output") : $("#mal-output");
    append(output, "stop requested");
  });
  $$("[data-mal-view]").forEach((button) => {
    button.addEventListener("click", () => setMalwareView(button.dataset.malView));
  });
  $("#mal-sandbox-run").addEventListener("click", () => runSandbox());
  $("#mal-sandbox-target").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      runSandbox();
    }
  });
  $("#mal-folder").addEventListener("click", async () => {
    const selected = await window.qa.pickPath("folder");
    if (selected) $("#mal-path").value = selected;
  });
  $("#mal-file").addEventListener("click", async () => {
    const selected = await window.qa.pickPath("file");
    if (selected) $("#mal-path").value = selected;
  });

  $("#siem-open").addEventListener("click", async () => {
    try { await window.qa.siem.open(); } catch (error) {
      toast(String(error.message || error), true);
    }
  });
  $("#siem-alerts").addEventListener("wheel", (event) => {
    const node = event.currentTarget;
    if (Math.abs(event.deltaY) > Math.abs(event.deltaX) &&
        node.scrollWidth > node.clientWidth) {
      node.scrollLeft += event.deltaY;
      event.preventDefault();
    }
  }, { passive: false });

  window.qa.onEvent((payload) => {
    if (payload.scope === "sentinels") {
      if (payload.type === "status" && currentView !== "logs") {
        if (payload.error) {
          setConnection("error", "Sentinels unavailable");
          $("#overview-sentinels").textContent = "Sentinels unavailable.";
        } else {
          renderSentinelsStatus(payload.data);
        }
      }
      if (payload.type === "line" && currentView === "logs") {
        append($("#logs-output"), payload.line);
      }
      if (payload.type === "done") {
        if (currentView === "logs") {
          logsRunning = false;
          append($("#logs-output"), `stream ended (exit ${payload.code})`);
          setConnection(payload.code === 0 ? "" : "error", "Logs ended");
        } else {
          setSentinelsBusy(false);
          toast(`Sentinel command finished (exit ${payload.code}).`, payload.code !== 0);
          if (["cycle", "findings"].includes(sentinelsAction)) {
            loadSentinelsStatus();
          }
        }
      }
    }
    if (payload.scope === "siem" && payload.type === "snapshot" &&
        currentView !== "logs") {
      if (payload.error) {
        setConnection("error", "SIEM unavailable");
        $("#overview-siem").textContent = payload.error;
      } else {
        renderSiemSnapshot(payload.data);
      }
    }
    if (payload.scope === "sandbox") {
      if (payload.type === "line") {
        append($("#mal-sandbox-output"), payload.line);
      }
      if (payload.type === "done") {
        setMalwareBusy(false);
        append($("#mal-sandbox-output"), `sandbox exit ${payload.code}`);
        if (payload.code !== 0) {
          toast(`Sandbox exited with ${payload.code}.`, true);
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
  try {
    const version = await window.qa.version();
    $("#app-version").textContent = `Version ${version}`;
  } catch (error) {
    $("#app-version").hidden = true;
  }
  if (initial === "overview") {
    loadSentinelsStatus();
    loadSiem();
  } else if (initial === "sentinels") {
    loadSentinelsStatus();
  } else if (initial === "siem") {
    loadSiem();
  } else if (initial === "logs") {
    startSentinelLogs();
  }
}

init();
