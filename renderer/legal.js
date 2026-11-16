"use strict";

const $ = (selector) => document.querySelector(selector);

const OVERALL = {
  ok: { text: "OK", className: "ok" },
  review: { text: "Review due", className: "" },
  action: { text: "Action needed", className: "error" },
};

const CHECK_STATUS = {
  pass: { text: "Pass", className: "ok" },
  warn: { text: "Review", className: "warn" },
  action: { text: "Action", className: "error" },
};

const REVIEW_STATUS = {
  reviewed: { text: "Reviewed", className: "ok" },
  pending: { text: "Pending", className: "warn" },
  "not-applicable": { text: "N/A", className: "" },
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text != null) element.textContent = String(text);
  return element;
}

function setOverall(status) {
  const value = OVERALL[status] || OVERALL.review;
  const dot = $("#legal-dot");
  dot.classList.remove("ok", "error");
  if (value.className) dot.classList.add(value.className);
  $("#legal-status").textContent = value.text;
}

function showError(message) {
  const error = $("#legal-error");
  error.textContent = message;
  error.hidden = false;
  $("#legal-content").hidden = true;
  setOverall("action");
}

function setText(selector, value) {
  $(selector).textContent = value == null || value === "" ? "—" : String(value);
}

function renderSource(source) {
  const link = $("#legal-source");
  if (typeof source === "string" && /^https:\/\//.test(source)) {
    link.href = source;
    link.textContent = source;
  } else {
    link.removeAttribute("href");
    link.textContent = "—";
  }
}

function renderCounts(summary) {
  const host = $("#legal-counts");
  host.replaceChildren();
  const values = [
    ["Overall", (OVERALL[summary.overall] || OVERALL.review).text],
    ["Checks", summary.checks],
    ["Passing", summary.pass],
    ["Warnings", summary.warnings],
    ["Actions", summary.actions],
    ["Reviews pending", summary.pendingReviews],
  ];
  for (const [label, value] of values) {
    const item = node("div", "legal-count");
    item.append(node("span", "muted", label), node("strong", "", value));
    host.append(item);
  }
}

function renderComponents(components) {
  const body = $("#legal-components");
  body.replaceChildren();
  for (const component of components) {
    const row = document.createElement("tr");
    row.append(
      node("td", "", component.name),
      node("td", "mono", component.version || "—"),
      node("td", "mono", component.license),
      node("td", "muted", component.scope),
    );
    body.append(row);
  }
  $("#legal-component-count").textContent =
    `${components.length} ${components.length === 1 ? "component" : "components"}`;
}

function renderChecks(checks) {
  const host = $("#legal-checks");
  host.replaceChildren();
  for (const check of checks) {
    const item = node("div", "legal-item");
    const status = CHECK_STATUS[check.status] || CHECK_STATUS.warn;
    const pill = node("span", `legal-status ${status.className}`.trim(), status.text);
    const body = node("div", "legal-item-body");
    body.append(
      node("h4", "", check.label),
      node("p", "muted", check.detail),
    );
    if (check.evidence) {
      body.append(node("code", "legal-evidence", check.evidence));
    }
    item.append(pill, body);
    host.append(item);
  }
  $("#legal-check-count").textContent =
    `${checks.length} ${checks.length === 1 ? "check" : "checks"}`;
}

function renderReviews(reviews) {
  const host = $("#legal-reviews");
  host.replaceChildren();
  for (const review of reviews) {
    const item = node("div", "legal-item");
    const status = REVIEW_STATUS[review.status] || REVIEW_STATUS.pending;
    const pill = node("span", `legal-status ${status.className}`.trim(), status.text);
    const body = node("div", "legal-item-body");
    body.append(
      node("h4", "", `${review.category} · ${review.date}`),
      node("p", "muted", review.note),
    );
    item.append(pill, body);
    host.append(item);
  }
  $("#legal-review-count").textContent =
    `${reviews.length} ${reviews.length === 1 ? "review" : "reviews"}`;
}

function renderDocuments(documents) {
  const host = $("#legal-documents");
  host.replaceChildren();
  for (const document of documents) {
    const item = node("div", "legal-document");
    const info = node("div", "legal-document-info");
    info.append(
      node("strong", "", document.label),
      node("span", "muted mono", document.path),
    );
    if (!document.available) {
      info.append(node("span", "legal-missing", "missing"));
    }
    const actions = node("div", "legal-document-actions");
    const view = node("button", "ghost", "View");
    view.type = "button";
    view.disabled = !document.available;
    view.addEventListener("click", () => viewDocument(document.id));
    const open = node("button", "ghost", "Open");
    open.type = "button";
    open.disabled = !document.available;
    open.addEventListener("click", () => openDocument(document.id));
    actions.append(view, open);
    item.append(info, actions);
    host.append(item);
  }
}

async function viewDocument(id) {
  try {
    const result = await window.qaLegal.document(id);
    if (result.tooLarge) {
      await openDocument(id);
      return;
    }
    $("#legal-document-title").textContent = result.label;
    $("#legal-document-text").textContent = result.text;
    $("#legal-document-panel").hidden = false;
    $("#legal-document-panel").scrollIntoView({ block: "nearest", behavior: "smooth" });
  } catch (error) {
    $("#legal-export-status").textContent = String(error.message || error);
  }
}

async function openDocument(id) {
  try {
    const result = await window.qaLegal.openDocument(id);
    $("#legal-export-status").textContent = `Opened ${result.label}.`;
  } catch (error) {
    $("#legal-export-status").textContent = String(error.message || error);
  }
}

async function exportReport(format) {
  const status = $("#legal-export-status");
  const buttons = [$("#legal-export-md"), $("#legal-export-json")];
  for (const button of buttons) button.disabled = true;
  try {
    const result = await window.qaLegal.exportReport(format);
    status.textContent = result.saved
      ? `Saved ${result.file}.`
      : "Export cancelled.";
  } catch (error) {
    status.textContent = String(error.message || error);
  } finally {
    for (const button of buttons) button.disabled = false;
  }
}

function render(data) {
  const manifest = data.manifest;
  const facts = data.facts;
  setOverall(data.summary.overall);
  $("#legal-subtitle").textContent =
    `${manifest.product} ${facts.appVersion} · ${manifest.spdx}`;
  setText("#legal-product", manifest.product);
  setText("#legal-version",
    `Version ${facts.appVersion} · Electron ${facts.versions.electron || "?"} · Node ${facts.versions.node || "?"}`);
  setText("#legal-license", manifest.spdx);
  setText("#legal-copyright", manifest.copyright);
  setText("#legal-reviewed", `${manifest.lastReviewed} · covers ${manifest.reviewedVersion}`);
  renderSource(manifest.source);
  renderCounts(data.summary);
  renderComponents(manifest.components);
  renderChecks(data.checks);
  renderReviews(data.reviews);
  renderDocuments(data.documents);
  $("#legal-error").hidden = true;
  $("#legal-content").hidden = false;
}

async function load() {
  try {
    const data = await window.qaLegal.get();
    if (!data.ok) {
      showError(data.error || "The legal register could not be loaded.");
      return;
    }
    render(data);
  } catch (error) {
    showError(String(error.message || error));
  }
}

$("#legal-export-md").addEventListener("click", () => exportReport("md"));
$("#legal-export-json").addEventListener("click", () => exportReport("json"));
$("#legal-document-close").addEventListener("click", () => {
  $("#legal-document-panel").hidden = true;
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") $("#legal-document-panel").hidden = true;
});

load();
