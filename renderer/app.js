"use strict";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const TITLES = {
  overview: ["QA Dashboard", "QA Sentinels and QA SIEM in one local dashboard."],
  sentinels: ["QA Sentinels Database", "Read-only sentinels.db query engine with filters and SQL."],
  "sen-overview": ["QA Sentinels Overview", "Status, scheduling and live sentinel state."],
  rules: ["Ticket Rules", "How issues move between ticket states, and why."],
  logs: ["QA Sentinels Logs", "Live QA Sentinels log stream."],
  siem: ["SIEM", "Click an alert or event for a preview; double-click for the full record."],
  record: ["SIEM Record", "Full alert or event record."],
};

const SETTINGS_TITLES = {
  sentinels: "QA Sentinels settings",
  siem: "SIEM settings",
};

const SENTINEL_KEYS = [
  "last sample", "last ingest", "last hardware", "last lsm", "database",
  "critical", "inventory", "evidence", "ticket drafts", "core2 triage",
  "layer1", "boots", "notify", "layer2", "posture",
];

const TICKET_BUCKETS = ["raise", "raised", "rejected", "standby"];
const QUERY_FILTERABLE = new Set([
  "inbox", "errors", "findings", "events", "crashes",
]);
// Derived presets stay in the CLI; the Database lists the tables themselves.
const HIDDEN_QUERY_CATEGORIES = new Set([
  "inbox", "errors", "cycles", "findings",
]);
const FALLBACK_QUERY_CATEGORIES = [
  ["new-findings", "Cycle findings", "cycle_findings"],
  ["events", "Events", "events"],
  ["crashes", "Crashes", "crashes"],
  ["boots", "Boots", "boots"],
  ["samples", "Samples", "samples"],
  ["processes", "Process snapshots", "proc_snap"],
  ["inventory", "Inventory runs", "inventory_runs"],
  ["inventory-items", "Inventory items", "inventory"],
  ["inventory-diffs", "Inventory changes", "inventory_diffs"],
  ["hardware", "Hardware runs", "hardware_runs"],
  ["hardware-items", "Hardware items", "hardware_items"],
  ["lsm", "LSM runs", "lsm_runs"],
  ["correlations", "Correlations", "correlations"],
  ["tickets", "Ticket drafts", "ticket_drafts"],
  ["deep", "Deep runs", "deep_runs"],
  ["bundles", "Bundles", "bundles"],
  ["runs", "Runs", "runs"],
  ["core2", "Core 2 cases", "core2_cases"],
  ["crosschecks", "Crosschecks", "crosschecks"],
  ["notifications", "Notifications", "notifications"],
  ["reports", "Reports", "reports"],
  ["meta", "Metadata", "meta"],
].map(([id, label, source]) => ({ id, label, source }));
const CLICK_DELAY = 220;

let config = null;
let currentView = "overview";
let sentinelsBusy = false;
let sentinelsAction = "";
let senTab = "overview";
let queryBusy = false;
let activeCategories = ["findings"];
let queryLast = { categories: ["findings"], filters: {} };
let queryResults = [];
let queryMode = "categories";
let cycleTarget = null;
let logsReady = false;
let logsLastSeq = 0;
let logsPending = [];
let settingsModule = "";
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
  const pill = $(".status-pill");
  if (pill) pill.hidden = false;
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
  const pill = $(".status-pill");
  if (pill && view === "logs" &&
      $("#sidebar-status").textContent === "Ready") {
    pill.hidden = true;
  }
  if (view === "sentinels" &&
      $("#sidebar-status").textContent === "Ready") {
    $("#sidebar-status").textContent = "sentinels.db";
  }
}

function setSenTab(tab, load = true) {
  senTab = tab === "tickets" ? "tickets" : "overview";
  $$("[data-sen-tab]").forEach((button) => {
    const active = button.dataset.senTab === senTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  $("#sen-panel-overview").hidden = senTab !== "overview";
  $("#sen-panel-tickets").hidden = senTab !== "tickets";
  const title = senTab === "tickets"
    ? "QA Sentinels Tickets" : "QA Sentinels Overview";
  $("#view-title").textContent = title;
  document.title = title;
  $("#view-subtitle").textContent = senTab === "tickets"
    ? "Ticket drafts by bucket; click to preview, double-click to open."
    : TITLES["sen-overview"][1];
  if (!load) return;
  if (senTab === "tickets") loadFindings();
  else loadSentinelsStatus();
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
  setConnection("ok", "QA Sentinels ready");
}

async function loadSentinelsStatus() {
  try {
    renderSentinelsStatus(await window.qa.sentinels.status());
  } catch (error) {
    setConnection("error", "QA Sentinels unavailable");
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

function currentCategories() {
  return activeCategories.length ? activeCategories : ["findings"];
}

function setActiveCategories(categories) {
  activeCategories = [...new Set(categories)];
  const selected = new Set(activeCategories);
  $$("[data-query-category]").forEach((button) => {
    const active = selected.has(button.dataset.queryCategory);
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

function renderQueryCategories(categories) {
  const toolbar = $("#query-categories");
  clear(toolbar);
  const visible = categories.filter((category) =>
    category && category.id && !HIDDEN_QUERY_CATEGORIES.has(category.id));
  if (!visible.length) {
    toolbar.append(muted("No categories available."));
    return;
  }
  for (const category of visible) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.queryCategory = category.id;
    button.textContent = category.label || category.id;
    button.setAttribute("aria-pressed", "false");
    if (category.source && category.source !== category.id) {
      const source = document.createElement("span");
      source.className = "query-source";
      source.textContent = category.source;
      button.append(" ", source);
    }
    const title = [category.description, category.source
      ? `SQL source: ${category.source}` : ""].filter(Boolean).join(" · ");
    if (title) button.title = title;
    toolbar.append(button);
  }
  setActiveCategories(activeCategories);
}

async function loadQueryCategories() {
  try {
    const data = await window.qa.sentinels.query({ catalog: true });
    const categories = Array.isArray(data?.categories) ? data.categories : [];
    renderQueryCategories(categories);
  } catch (_error) {
    renderQueryCategories(FALLBACK_QUERY_CATEGORIES);
  }
}

function setQueryFiltersEnabled() {
  const categories = queryMode === "sql" ? [] : currentCategories();
  const filterable = categories.some((category) => QUERY_FILTERABLE.has(category));
  const finding = categories.some((category) =>
    ["inbox", "errors", "findings"].includes(category));
  const event = categories.includes("events");
  const enabled = filterable && !queryBusy;
  $("#query-search").disabled = !enabled;
  $("#query-since").disabled = !enabled;
  $$("#query-severity-group button").forEach((button) => {
    button.disabled = !((finding || event) && !queryBusy);
  });
  $$("#query-status-group button").forEach((button) => {
    button.disabled = !(finding && !queryBusy);
  });
  $("#query-severity-group").classList.toggle(
    "disabled", !((finding || event) && !queryBusy));
  $("#query-status-group").classList.toggle(
    "disabled", !(finding && !queryBusy));
  $("#query-filter-clear").disabled = !enabled;
  $("#query-filters").classList.toggle("disabled", !filterable);
}

function setQueryBusy(busy) {
  queryBusy = busy;
  $$("[data-query-category], #query-run, #query-refresh, #query-clear, #query-limit")
    .forEach((node) => { node.disabled = busy; });
  setQueryFiltersEnabled();
}

function selectedFilterValues(groupId) {
  return $$(`#${groupId} button.active`)
    .map((button) => button.dataset.filterValue);
}

function readQueryFilters() {
  return {
    search: $("#query-search").value.trim(),
    severity: selectedFilterValues("query-severity-group").join(","),
    status: selectedFilterValues("query-status-group").join(","),
    since: $("#query-since").value.trim(),
  };
}

function filtersForCategory(category) {
  if (!QUERY_FILTERABLE.has(category)) return {};
  const filters = readQueryFilters();
  const out = {};
  if (filters.search) out.search = filters.search;
  if (filters.since) out.since = filters.since;
  if (filters.severity &&
      ["inbox", "errors", "findings", "events"].includes(category)) {
    out.severity = filters.severity;
  }
  if (filters.status &&
      ["inbox", "errors", "findings"].includes(category)) {
    out.status = filters.status;
  }
  return out;
}

function setFilterGroup(groupId, value) {
  const values = Array.isArray(value) ? value : String(value || "").split(",");
  const selected = new Set(
    values.map((item) => String(item).trim()).filter(Boolean));
  $$(`#${groupId} button`).forEach((button) => {
    const active = selected.has(button.dataset.filterValue);
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });
}

function applyQueryFilters(filters = {}) {
  $("#query-search").value = filters.search || "";
  setFilterGroup("query-severity-group", filters.severity);
  setFilterGroup("query-status-group", filters.status);
  $("#query-since").value = filters.since || "";
}

function severityClass(value) {
  const severity = String(value || "info").toLowerCase();
  return ["critical", "error", "warning", "info"].includes(severity)
    ? `sev-${severity}` : "sev-info";
}

function renderResultSummary(result, node) {
  clear(node);
  const entries = [
    ["Rows", result.count],
    ["Limit", result.limit],
    ["Elapsed", `${result.elapsed_ms} ms`],
    ["Truncated", result.truncated ? "yes" : "no"],
  ];
  for (const [label, value] of entries) {
    const metric = document.createElement("div");
    metric.className = "metric";
    const key = document.createElement("span");
    key.textContent = label;
    const strong = document.createElement("strong");
    strong.textContent = String(value);
    metric.append(key, strong);
    node.append(metric);
  }
}

function closeQueryDetail() {
  $("#query-detail").hidden = true;
  $$("#query-results tbody tr").forEach((row) => row.classList.remove("selected"));
}

function selectQueryRow(result, table, index) {
  if (!result || !Array.isArray(result.rows[index])) return;
  $$("#query-results tbody tr").forEach((row) => row.classList.remove("selected"));
  table.querySelectorAll("tbody tr").forEach((row, position) => {
    row.classList.toggle("selected", position === index);
  });
  const record = Object.create(null);
  (result.columns || []).forEach((column, position) => {
    record[column] = result.rows[index][position];
  });
  if (result.category === "cycles") {
    try { record.detail = JSON.parse(record.detail); } catch (_error) { /* raw */ }
    try { record.by_severity = JSON.parse(record.by_severity); } catch (_error) { /* raw */ }
  }
  const label = result.label || result.category || "SQL";
  $("#query-detail-title").textContent = `Row ${index + 1} · ${label}`;
  $("#query-detail-json").textContent = JSON.stringify(record, null, 2);
  $("#query-detail").hidden = false;
  $("#query-detail").scrollIntoView({ block: "nearest", behavior: "smooth" });
}

const QUERY_WRAP_COLUMNS = new Set([
  "detail", "message", "context", "last_message", "state", "pstore", "notes",
  "body", "summary", "contents", "denials", "counts", "signature", "display",
  "value", "path", "exe",
]);
const QUERY_TABLE_CELL_CHARS = 240;

function isNewCycleFinding(row, columns, cycle) {
  if (!cycle) return false;
  const index = (name) => columns.findIndex(
    (column) => String(column).toLowerCase() === name);
  const idIndex = index("id");
  const ruleIndex = index("rule");
  const tsIndex = index("ts");
  if (idIndex >= 0 && Array.isArray(cycle.ids) && cycle.ids.length) {
    return cycle.ids.map(String).includes(String(row[idIndex]));
  }
  if (ruleIndex < 0 || tsIndex < 0) return false;
  if (!cycle.rules.includes(String(row[ruleIndex]))) return false;
  const found = Date.parse(row[tsIndex]);
  const cycleTs = Date.parse(cycle.ts);
  if (!Number.isFinite(found) || !Number.isFinite(cycleTs)) return false;
  return found >= cycleTs - 15 * 60 * 1000 && found <= cycleTs + 60 * 1000;
}

function renderResultTable(result, table) {
  const head = document.createElement("thead");
  const body = document.createElement("tbody");
  table.append(head, body);
  const columns = result.columns || [];
  const rows = result.rows || [];
  const headRow = document.createElement("tr");
  for (const column of columns) {
    const th = document.createElement("th");
    th.textContent = column;
    headRow.append(th);
  }
  head.append(headRow);
  if (!columns.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.textContent = "No columns returned.";
    td.className = "muted";
    tr.append(td);
    body.append(tr);
    return;
  }
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = columns.length;
    td.className = "muted";
    td.textContent = "No rows.";
    tr.append(td);
    body.append(tr);
    return;
  }
  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    const isNew = isNewCycleFinding(row, columns, cycleTarget);
    tr.className = "query-row";
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");
    tr.title = "Click to inspect this row";
    tr.addEventListener("click", () => selectQueryRow(result, table, index));
    tr.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      selectQueryRow(result, table, index);
    });
    columns.forEach((column, position) => {
      const td = document.createElement("td");
      const value = row[position];
      const name = String(column).toLowerCase();
      if (name === "severity") {
        const badge = document.createElement("span");
        badge.className = `severity-badge ${severityClass(value)}`;
        badge.textContent = String(value || "info");
        td.append(badge);
      } else if (name === "status") {
        const badge = document.createElement("span");
        badge.className = "query-status";
        badge.textContent = String(value || "");
        td.append(badge);
      } else {
        const text = value === null ? "—" : String(value);
        const wrapped = QUERY_WRAP_COLUMNS.has(name) || text.length > 100;
        td.textContent = text.length > QUERY_TABLE_CELL_CHARS
          ? `${text.slice(0, QUERY_TABLE_CELL_CHARS - 1)}…` : text;
        if (wrapped) td.classList.add("wrap");
        if (td.textContent !== text) td.title = text;
        if (name === "id" && isNew) {
          const badge = document.createElement("span");
          badge.className = "new-badge";
          badge.textContent = "NEW";
          td.append(" ", badge);
        }
      }
      tr.append(td);
    });
    body.append(tr);
  });
}

function renderResultPanel(entry, options = {}) {
  const result = entry.result;
  const panel = document.createElement("article");
  panel.className = "query-result-panel";
  const head = document.createElement("div");
  head.className = "panel-head";
  const titleWrap = document.createElement("div");
  const heading = document.createElement("h3");
  heading.textContent = options.base
    ? "All findings"
    : (result.label || result.category || "SQL query");
  const meta = document.createElement("p");
  meta.className = "muted mono";
  meta.textContent = [
    result.category ? `category ${result.category}` : "custom SQL",
    `${result.count} rows`,
    `${result.elapsed_ms} ms`,
    result.truncated ? "truncated" : "",
  ].filter(Boolean).join(" · ");
  titleWrap.append(heading, meta);
  head.append(titleWrap);
  panel.append(head);

  const summary = document.createElement("div");
  summary.className = "summary-grid query-summary";
  renderResultSummary(result, summary);
  panel.append(summary);

  const wrap = document.createElement("div");
  wrap.className = "table-wrap query-table-wrap";
  const table = document.createElement("table");
  table.className = "rules-table query-table";
  renderResultTable(result, table);
  wrap.append(table);
  panel.append(wrap);
  return panel;
}

function renderResults(entries, options = {}) {
  queryResults = entries;
  closeQueryDetail();
  const container = $("#query-results");
  clear(container);
  if (!entries.length) {
    container.append(muted("No results."));
  } else {
    for (const entry of entries) {
      container.append(renderResultPanel(entry, options));
    }
  }

  const labels = entries.map((entry) =>
    entry.result.label || entry.result.category || "SQL query");
  const sql = Boolean(options.sql);
  const base = Boolean(options.base);
  let title = "All findings";
  if (sql) title = "SQL query";
  else if (!base && entries.length === 1) title = labels[0];
  else if (!base && entries.length > 1) title = `${entries.length} categories`;
  $("#query-title").textContent = title;

  const meta = ["Read-only", "sentinels.db"];
  if (sql) meta.push("custom SQL");
  else if (base) meta.push("base view");
  else meta.push(`categories: ${labels.join(", ")}`);
  if (!sql && entries.length > 1) meta.push(`SQL: ${labels[0]}`);
  $("#query-meta").textContent = meta.join(" · ");

  const applied = { search: "", severity: [], status: [], since: "" };
  for (const entry of entries) {
    const filters = entry.result.filters || {};
    if (filters.search) applied.search = filters.search;
    if (Array.isArray(filters.severity)) {
      for (const value of filters.severity) {
        if (!applied.severity.includes(value)) applied.severity.push(value);
      }
    }
    if (Array.isArray(filters.status)) {
      for (const value of filters.status) {
        if (!applied.status.includes(value)) applied.status.push(value);
      }
    }
    if (filters.since) applied.since = filters.since;
  }
  const severity = applied.severity.join(",");
  const status = applied.status.join(",");
  const filterBits = [];
  if (applied.search) filterBits.push(`search "${applied.search}"`);
  if (severity) filterBits.push(`severity ${severity}`);
  if (status) filterBits.push(`status ${status}`);
  if (applied.since) filterBits.push(`since ${applied.since}`);
  $("#query-filter-note").textContent = filterBits.length
    ? `Filters: ${filterBits.join(" · ")}`
    : "";

  $("#query-sql").value = entries[0]?.result.sql || "";
  $("#query-error").hidden = true;
  setQueryFiltersEnabled();
  setConnection("ok", "sentinels.db");
}

function queryErrorMessage(error) {
  const text = String(error?.message || error);
  return text.replace(
    /^Error invoking remote method '[^']+':\s*(?:Error:\s*)?/, "");
}

function showQueryError(error) {
  queryResults = [];
  closeQueryDetail();
  const message = queryErrorMessage(error);
  $("#query-error").textContent = message;
  $("#query-error").hidden = false;
  $("#query-title").textContent = "Query failed";
  $("#query-meta").textContent = "Read-only · sentinels.db";
  $("#query-filter-note").textContent = "";
  setQueryFiltersEnabled();
  const container = $("#query-results");
  clear(container);
  container.append(muted("No results."));
  setConnection("error", "sentinels.db");
}

async function runCategoryView(categories, base) {
  if (queryBusy) return;
  const list = categories.length ? [...categories] : ["findings"];
  const limit = Number($("#query-limit").value) || 200;
  const filters = readQueryFilters();
  queryMode = "categories";
  queryLast = {
    categories: [...categories],
    base: Boolean(base),
    filters,
  };
  setQueryBusy(true);
  try {
    const entries = await Promise.all(list.map(async (category) => {
      const result = await window.qa.sentinels.query({
        category, limit, ...filtersForCategory(category),
      });
      return { category, result };
    }));
    renderResults(entries, { base: Boolean(base), filters });
  } catch (error) {
    showQueryError(error);
    toast(queryErrorMessage(error), true);
  } finally {
    setQueryBusy(false);
  }
}

async function runSqlView(sql) {
  if (queryBusy) return;
  const limit = Number($("#query-limit").value) || 200;
  queryMode = "sql";
  queryLast = { sql };
  setActiveCategories([]);
  setQueryBusy(true);
  try {
    const result = await window.qa.sentinels.query({ sql, limit });
    renderResults([{ category: null, result }], { sql: true, filters: {} });
  } catch (error) {
    showQueryError(error);
    toast(queryErrorMessage(error), true);
  } finally {
    setQueryBusy(false);
  }
}

function selectCategory(category) {
  setActiveCategories([category]);
  runCategoryView([category], false);
}

function toggleQueryCategory(category) {
  if (queryBusy) return;
  if (queryMode === "sql") {
    selectCategory(category);
    return;
  }
  const next = new Set(activeCategories);
  if (next.has(category)) next.delete(category);
  else next.add(category);
  const categories = [...next];
  setActiveCategories(categories);
  runCategoryView(categories, categories.length === 0);
}

function refreshActiveQuery() {
  if (queryMode === "sql") {
    const sql = $("#query-sql").value.trim();
    if (sql) runSqlView(sql);
    return;
  }
  runCategoryView(activeCategories, activeCategories.length === 0);
}

function runQuerySql() {
  const sql = $("#query-sql").value.trim();
  if (!sql) {
    toast("Enter a read-only SQL statement first.", true);
    return;
  }
  runSqlView(sql);
}

function refreshQuery() {
  if (queryLast.sql) {
    runSqlView(queryLast.sql);
    return;
  }
  applyQueryFilters(queryLast.filters || {});
  runCategoryView(queryLast.categories || [], Boolean(queryLast.base));
}

function clearQuerySql() {
  $("#query-sql").value = "";
  $("#query-sql").focus();
}

function clearQueryFilters() {
  applyQueryFilters({});
  if (queryLast.sql) runSqlView(queryLast.sql);
  else runCategoryView(queryLast.categories || [], Boolean(queryLast.base));
}

async function loadLatestCycle() {
  try {
    const data = await window.qa.sentinels.query({ latest: true });
    const latest = data?.latest || null;
    const lastNew = data?.last_new || null;
    const target = latest && latest.new > 0 ? latest : lastNew;
    const previousTarget = cycleTarget;
    cycleTarget = target || null;
    if (queryResults.length &&
        previousTarget?.run_id !== cycleTarget?.run_id) {
      renderResults(queryResults, {
        base: Boolean(queryLast.base),
        sql: Boolean(queryLast.sql),
        filters: queryLast.filters || {},
      });
    }
  } catch (_error) {
    cycleTarget = null;
  }
}

function ticketTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
}

async function openTicket(ticket) {
  try {
    await window.qa.tickets.open(ticket.bucket, ticket.name);
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

function ticketRow(ticket) {
  const row = document.createElement("div");
  row.className = "row row-clickable";
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-expanded", "false");
  row.title = ticket.ticketMd
    ? "Click for preview; double-click to open ticket.md"
    : "Click for preview; double-click to open the ticket folder";
  const head = document.createElement("div");
  head.className = "row-head";
  const title = document.createElement("span");
  title.className = "row-title";
  title.textContent = ticket.title || ticket.name;
  title.title = ticket.name;
  head.append(title);
  const detail = document.createElement("div");
  detail.className = "row-detail";
  detail.textContent = ticket.ticketMd
    ? [ticket.name, ticketTime(ticket.updated)].filter(Boolean).join(" · ")
    : "ticket.md missing · opens folder";
  row.append(head, detail);
  let preview = null;
  let clickTimer = null;
  const collapse = () => {
    if (!preview) return;
    preview.remove();
    preview = null;
    row.classList.remove("open");
    row.setAttribute("aria-expanded", "false");
  };
  const expand = () => {
    if (preview) return;
    preview = document.createElement("pre");
    preview.className = "row-json";
    preview.textContent = ticket.preview || "Preview unavailable.";
    row.append(preview);
    row.classList.add("open");
    row.setAttribute("aria-expanded", "true");
  };
  const toggle = () => {
    if (preview) collapse();
    else expand();
  };
  row.addEventListener("click", (event) => {
    if (event.detail > 1) return;
    clearTimeout(clickTimer);
    clickTimer = setTimeout(toggle, CLICK_DELAY);
  });
  row.addEventListener("dblclick", (event) => {
    event.preventDefault();
    clearTimeout(clickTimer);
    openTicket(ticket);
  });
  row.addEventListener("keydown", (event) => {
    if (event.target !== row) return;
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      openTicket(ticket);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle();
    }
  });
  return row;
}

function renderFindings(data) {
  const buckets = new Map(
    (Array.isArray(data?.buckets) ? data.buckets : [])
      .map((bucket) => [bucket.bucket, bucket]));
  for (const bucket of TICKET_BUCKETS) {
    const node = document.querySelector(`[data-bucket-list="${bucket}"]`);
    const count = document.querySelector(`[data-bucket-count="${bucket}"]`);
    if (!node) continue;
    const tickets = buckets.get(bucket)?.tickets;
    const rows = Array.isArray(tickets) ? tickets : [];
    if (count) count.textContent = String(rows.length);
    clear(node);
    if (!rows.length) {
      node.append(muted("No tickets."));
      continue;
    }
    for (const ticket of rows) node.append(ticketRow(ticket));
  }
  if (data?.root) setConnection("ok", "Tickets loaded");
}

async function loadFindings() {
  try {
    renderFindings(await window.qa.tickets.list());
  } catch (error) {
    setConnection("error", "Tickets unavailable");
    for (const bucket of TICKET_BUCKETS) {
      const node = document.querySelector(`[data-bucket-list="${bucket}"]`);
      const count = document.querySelector(`[data-bucket-count="${bucket}"]`);
      if (!node) continue;
      clear(node);
      node.append(muted("Tickets unavailable."));
      if (count) count.textContent = "0";
    }
    toast(String(error.message || error), true);
  }
}

async function openTicketsFolder() {
  try {
    await window.qa.openTickets();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function startSentinelLogs() {
  if (logsReady) return;
  const output = $("#logs-output");
  if (!output) return;
  logsReady = false;
  logsLastSeq = 0;
  logsPending = [];
  output.textContent = "";
  const header = "$ qa logs --all-layers --follow (background)";
  append(output, header);
  setConnection("ok", "Live logs");
  try {
    const result = await window.qa.sentinels.logsStart();
    const lines = Array.isArray(result.lines) ? result.lines : [];
    output.textContent = [header, ...lines].join("\n") + (lines.length ? "\n" : "");
    logsLastSeq = Number(result.total) || 0;
    const pending = logsPending
      .slice()
      .sort((left, right) => (left.seq || 0) - (right.seq || 0));
    logsPending = [];
    for (const item of pending) {
      const seq = Number(item.seq) || 0;
      if (seq > logsLastSeq) {
        append(output, item.line);
        logsLastSeq = seq;
      }
    }
    output.scrollTop = output.scrollHeight;
    logsReady = true;
    if (result.error) append(output, `[dashboard] ${result.error}`);
    if (!result.started) {
      append(output, "[dashboard] background log stream is starting…");
    }
  } catch (error) {
    logsReady = false;
    setConnection("error", "Logs unavailable");
    append(output, `error: ${error.message || error}`);
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

function makeRowClickable(row, record, key, onOpen) {
  row.classList.add("row-clickable");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-expanded", "false");
  row.title = onOpen
    ? "Click for preview; double-click for the full record"
    : "Click for preview";
  const head = row.querySelector(".row-head");
  const toggle = document.createElement("span");
  toggle.className = "row-toggle";
  toggle.textContent = "\u25b8";
  toggle.setAttribute("aria-hidden", "true");
  const button = head.querySelector("button");
  if (button) head.insertBefore(toggle, button);
  else head.append(toggle);
  let body = null;
  let clickTimer = null;
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
    if (event.detail > 1) return;
    clearTimeout(clickTimer);
    clickTimer = setTimeout(activate, CLICK_DELAY);
  });
  row.addEventListener("dblclick", (event) => {
    if (event.target.closest("button")) return;
    event.preventDefault();
    clearTimeout(clickTimer);
    onOpen?.();
  });
  row.addEventListener("keydown", (event) => {
    if (event.target !== row) return;
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && onOpen) {
      event.preventDefault();
      onOpen();
      return;
    }
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
    makeRowClickable(row, alert, `alert:${alert.id}`, () => openRecord(alert));
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
    makeRowClickable(row, event, `event:${event.id}`, () => openRecord(event));
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

async function openRecord(record) {
  try {
    await window.qa.record.open(record);
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

function renderRecord(record) {
  const output = $("#record-json");
  if (!output) return;
  if (!record) {
    output.textContent = "No record selected.";
    $("#record-title").textContent = "SIEM record";
    $("#record-subtitle").textContent = "";
    return;
  }
  const label = record.event_type ? "Event" : "Alert";
  const heading = `${label}${record.id != null ? ` #${record.id}` : ""}`;
  output.textContent = JSON.stringify(record, null, 2);
  $("#record-title").textContent = heading;
  $("#record-subtitle").textContent = [
    record.severity, record.rule, record.last_seen || record.ts,
  ].filter(Boolean).join(" · ");
  document.title = `${heading} · ${record.rule || label}`;
}

async function loadRecord() {
  try {
    renderRecord(await window.qa.record.get());
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

function fillSettings(view) {
  if (!view) return;
  $("#set-sentinels-bin").value = view.sentinelsBin || "";
  $("#set-sentinels-root").value = view.sentinelsRoot || "";
  $("#set-sentinels-cycle").value = view.sentinelsCycleMinutes || "10";
  $("#set-sen-cycle-hours").value = view.sentinelsCycleHours || "1";
  $("#set-sen-drafts-days").value = view.sentinelsDraftsRetentionDays || "30";
  $("#set-sen-lookback-days").value = view.sentinelsRaiseLookbackDays || "30";
  $("#set-sen-events-days").value = view.sentinelsEventRetentionDays || "0";
  $("#set-sen-samples-days").value = view.sentinelsSamplesRetentionDays || "0";
  $("#set-sen-proc-days").value = view.sentinelsProcRetentionDays || "0";
  $("#set-sen-inventory-days").value = view.sentinelsInventoryRetentionDays || "0";
  $("#set-siem-url").value = view.siemUrl || "";
  $("#set-siem-token").value = view.siemTokenFile || "";
  $$("[data-settings-module]").forEach((label) => {
    label.hidden = label.dataset.settingsModule !== settingsModule;
  });
  $("#settings-title").textContent = SETTINGS_TITLES[settingsModule] || "Settings";
}

async function openSettings() {
  const module = currentView === "sen-overview" ? "sentinels" : currentView;
  if (!SETTINGS_TITLES[module]) return;
  settingsModule = module;
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
    payload.sentinelsCycleHours = $("#set-sen-cycle-hours").value;
    payload.sentinelsDraftsRetentionDays = $("#set-sen-drafts-days").value;
    payload.sentinelsRaiseLookbackDays = $("#set-sen-lookback-days").value;
    payload.sentinelsEventRetentionDays = $("#set-sen-events-days").value;
    payload.sentinelsSamplesRetentionDays = $("#set-sen-samples-days").value;
    payload.sentinelsProcRetentionDays = $("#set-sen-proc-days").value;
    payload.sentinelsInventoryRetentionDays = $("#set-sen-inventory-days").value;
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
  $("#query-categories").addEventListener("click", (event) => {
    const button = event.target.closest("[data-query-category]");
    if (!button || button.disabled) return;
    toggleQueryCategory(button.dataset.queryCategory);
  });
  $("#query-run").addEventListener("click", runQuerySql);
  $("#query-refresh").addEventListener("click", refreshQuery);
  $("#query-clear").addEventListener("click", clearQuerySql);
  $("#query-filter-clear").addEventListener("click", clearQueryFilters);
  $("#query-detail-close").addEventListener("click", closeQueryDetail);
  $("#query-limit").addEventListener("change", refreshQuery);
  $$("#query-severity-group button, #query-status-group button")
    .forEach((button) => {
      button.addEventListener("click", () => {
        if (button.disabled) return;
        const active = !button.classList.contains("active");
        button.classList.toggle("active", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");
        refreshActiveQuery();
      });
    });
  for (const selector of ["#query-search", "#query-since"]) {
    $(selector).addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      refreshActiveQuery();
    });
  }
  $("#query-sql").addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      runQuerySql();
    }
  });
  window.addEventListener("focus", () => {
    if (currentView === "sentinels") loadLatestCycle();
  });
  $$("[data-sen-tab]").forEach((button) => {
    button.addEventListener("click", () => setSenTab(button.dataset.senTab));
  });
  $("#sen-overview-rules").addEventListener(
    "click", () => window.qa.openModule("rules"));
  $("#sen-overview-logs").addEventListener(
    "click", () => window.qa.openModule("logs"));

  $("#findings-refresh").addEventListener("click", loadFindings);
  $("#findings-open-folder").addEventListener("click", openTicketsFolder);

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
    if (payload.scope === "sen-tabs" && payload.type === "select") {
      setSenTab(payload.tab);
    }
    if (payload.scope === "sentinels") {
      if (payload.type === "status" &&
          ["overview", "sen-overview"].includes(currentView)) {
        if (payload.error) {
          setConnection("error", "QA Sentinels unavailable");
          $("#overview-sentinels").textContent = "QA Sentinels unavailable.";
        } else {
          renderSentinelsStatus(payload.data);
        }
      }
      if (payload.type === "line" && currentView === "logs") {
        if (!logsReady) {
          logsPending.push(payload);
          if (logsPending.length > 4000) logsPending.shift();
          return;
        }
        const seq = Number(payload.seq) || 0;
        if (seq && seq <= logsLastSeq) return;
        append($("#logs-output"), payload.line);
        if (seq) logsLastSeq = seq;
      }
      if (payload.type === "done") {
        setSentinelsBusy(false);
        toast(`Sentinel command finished (exit ${payload.code}).`, payload.code !== 0);
        if (currentView === "sen-overview") loadSentinelsStatus();
        if (currentView === "sentinels") refreshQuery();
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
    if (payload.scope === "record" && payload.type === "show") {
      renderRecord(payload.data);
    }
  });
}

async function init() {
  bind();
  const params = new URLSearchParams(location.search);
  let initial = params.get("module") || "overview";
  let initialTab = params.get("tab") || "";
  if (initial === "findings") {
    initial = "sen-overview";
    initialTab = "tickets";
  }
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
    await loadQueryCategories();
    setActiveCategories([]);
    loadLatestCycle();
    runCategoryView([], true);
  } else if (initial === "sen-overview") {
    setSenTab(initialTab || "overview", false);
    loadSentinelsStatus();
    if (initialTab === "tickets") loadFindings();
  } else if (initial === "siem") {
    loadSiem();
  } else if (initial === "record") {
    loadRecord();
  } else if (initial === "logs") {
    startSentinelLogs();
  }
}

init();
