"use strict";

const fs = require("node:fs");
const path = require("node:path");

const MAX_DOCUMENT_BYTES = 256 * 1024;
const MAX_HTML_BYTES = 512 * 1024;
const REVIEW_MAX_AGE_DAYS = 366;
const SCOPES = new Set([
  "project", "shipped", "dependency", "build", "runtime", "asset", "system",
  "companion",
]);
const REVIEW_STATUSES = new Set(["reviewed", "pending", "not-applicable"]);
const REVIEW_CATEGORIES = new Set([
  "licensing", "distribution", "privacy", "export", "trademark",
  "contributions", "accessibility",
]);
const ID_RE = /^[a-z0-9][a-z0-9._-]*$/;
const LICENSE_RE = /^[A-Za-z0-9.+-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+-]+)*$/;

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readText(file) {
  return fs.readFileSync(file, "utf8");
}

function validRelativePath(value) {
  if (typeof value !== "string" || !value || value.length > 300) return false;
  if (value.includes("\0") || value.startsWith("/")) return false;
  if (!/^[A-Za-z0-9._@+/-]+$/.test(value)) return false;
  return !value.split("/").includes("..");
}

function validDate(value) {
  if (typeof value !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)) {
    return false;
  }
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) &&
    parsed.toISOString().slice(0, 10) === value;
}

function validateManifest(manifest) {
  const errors = [];
  if (!isObject(manifest)) return ["manifest: must be an object"];
  if (manifest.schemaVersion !== 1) errors.push("schemaVersion: must be 1");
  for (const key of ["product", "spdx", "copyright", "source", "lastReviewed",
    "reviewedVersion"]) {
    if (typeof manifest[key] !== "string" || !manifest[key].trim()) {
      errors.push(`${key}: must be a non-empty string`);
    }
  }
  if (typeof manifest.spdx === "string" && !LICENSE_RE.test(manifest.spdx)) {
    errors.push("spdx: must be an SPDX-style license expression");
  }
  if (typeof manifest.source === "string" && !/^https:\/\/[^\s]+$/.test(manifest.source)) {
    errors.push("source: must be an https URL");
  }
  if (typeof manifest.lastReviewed === "string" && !validDate(manifest.lastReviewed)) {
    errors.push("lastReviewed: must be a valid date");
  }
  if (!Array.isArray(manifest.components) || !manifest.components.length) {
    errors.push("components: must be a non-empty array");
  } else {
    const seen = new Set();
    manifest.components.forEach((component, index) => {
      const where = `components[${index}]`;
      if (!isObject(component)) {
        errors.push(`${where}: must be an object`);
        return;
      }
      if (typeof component.id !== "string" || !ID_RE.test(component.id)) {
        errors.push(`${where}.id: invalid id`);
      } else if (seen.has(component.id)) {
        errors.push(`${where}.id: duplicate id`);
      } else {
        seen.add(component.id);
      }
      if (typeof component.name !== "string" || !component.name) {
        errors.push(`${where}.name: must be a non-empty string`);
      }
      if (typeof component.license !== "string" || !LICENSE_RE.test(component.license)) {
        errors.push(`${where}.license: invalid license expression`);
      }
      if (!SCOPES.has(component.scope)) {
        errors.push(`${where}.scope: invalid scope`);
      }
      if (component.notice != null && !validRelativePath(component.notice)) {
        errors.push(`${where}.notice: invalid relative path`);
      }
    });
  }
  if (!Array.isArray(manifest.documents) || !manifest.documents.length) {
    errors.push("documents: must be a non-empty array");
  } else {
    const seen = new Set();
    manifest.documents.forEach((document, index) => {
      const where = `documents[${index}]`;
      if (!isObject(document)) {
        errors.push(`${where}: must be an object`);
        return;
      }
      if (typeof document.id !== "string" || !ID_RE.test(document.id)) {
        errors.push(`${where}.id: invalid id`);
      } else if (seen.has(document.id)) {
        errors.push(`${where}.id: duplicate id`);
      } else {
        seen.add(document.id);
      }
      if (typeof document.label !== "string" || !document.label) {
        errors.push(`${where}.label: must be a non-empty string`);
      }
      if (!validRelativePath(document.path)) {
        errors.push(`${where}.path: invalid relative path`);
      }
      if (!["text", "html", "external"].includes(document.kind)) {
        errors.push(`${where}.kind: invalid kind`);
      }
    });
  }
  if (!Array.isArray(manifest.reviews)) {
    errors.push("reviews: must be an array");
  } else {
    const seen = new Set();
    manifest.reviews.forEach((review, index) => {
      const where = `reviews[${index}]`;
      if (!isObject(review)) {
        errors.push(`${where}: must be an object`);
        return;
      }
      if (typeof review.id !== "string" || !ID_RE.test(review.id)) {
        errors.push(`${where}.id: invalid id`);
      } else if (seen.has(review.id)) {
        errors.push(`${where}.id: duplicate id`);
      } else {
        seen.add(review.id);
      }
      if (!REVIEW_CATEGORIES.has(review.category)) {
        errors.push(`${where}.category: invalid category`);
      }
      if (!REVIEW_STATUSES.has(review.status)) {
        errors.push(`${where}.status: invalid status`);
      }
      if (!validDate(review.date)) {
        errors.push(`${where}.date: invalid date`);
      }
      if (typeof review.note !== "string" || review.note.length > 500) {
        errors.push(`${where}.note: invalid note`);
      }
    });
  }
  return errors;
}

function appRoot(options = {}) {
  return options.root || path.join(__dirname, "..");
}

function manifestFile(root) {
  return path.join(root, "legal", "manifest.json");
}

function loadManifest(root) {
  const file = manifestFile(root);
  let manifest;
  try {
    manifest = readJson(file);
  } catch (error) {
    return {
      ok: false,
      errors: [`cannot read legal/manifest.json: ${error.message}`],
      manifest: null,
    };
  }
  const errors = validateManifest(manifest);
  return { ok: errors.length === 0, errors, manifest };
}

function realInside(root, target) {
  let realRoot;
  let realTarget;
  try {
    realRoot = fs.realpathSync(root);
    realTarget = fs.realpathSync(target);
  } catch (_error) {
    return null;
  }
  if (realTarget !== realRoot && !realTarget.startsWith(realRoot + path.sep)) {
    return null;
  }
  return realTarget;
}

function findDocument(manifest, id) {
  if (!manifest || !Array.isArray(manifest.documents)) return null;
  return manifest.documents.find((document) => document.id === id) || null;
}

function resolveDocument(root, manifest, id) {
  const document = findDocument(manifest, id);
  if (!document) throw new Error(`unknown legal document: ${id}`);
  if (document.kind === "external") {
    throw new Error(`external document cannot be opened locally: ${id}`);
  }
  const target = realInside(root, path.resolve(root, document.path));
  if (!target) throw new Error(`document is outside the application: ${id}`);
  const stat = fs.statSync(target);
  if (!stat.isFile()) throw new Error(`document is not a file: ${id}`);
  return { document, file: target, size: stat.size };
}

function runtimeFacts(root, appVersion, versions) {
  let pkg = {};
  try {
    pkg = readJson(path.join(root, "package.json"));
  } catch (_error) {
    // The checks report the missing metadata below.
  }
  return {
    appVersion: String(appVersion || pkg.version || ""),
    packageVersion: String(pkg.version || ""),
    packageLicense: String(pkg.license || ""),
    productName: String(pkg.productName || pkg.name || ""),
    versions: {
      electron: String(versions.electron || ""),
      chrome: String(versions.chrome || ""),
      node: String(versions.node || ""),
      v8: String(versions.v8 || ""),
    },
  };
}

function check(id, category, label, status, detail, evidence = "") {
  return { id, category, label, status, detail, evidence };
}

function documentStatus(root, manifest, id) {
  try {
    const resolved = resolveDocument(root, manifest, id);
    return { available: true, size: resolved.size, file: resolved.file };
  } catch (error) {
    return { available: false, size: 0, error: error.message };
  }
}

function evaluate(manifest, facts, root, options = {}) {
  const checks = [];
  const now = options.now ? new Date(options.now) : new Date();
  const packageOk = facts.packageLicense === manifest.spdx;
  checks.push(check(
    "package-license",
    "licensing",
    "Package metadata license",
    packageOk ? "pass" : "action",
    packageOk
      ? `package.json declares ${manifest.spdx}.`
      : `package.json declares "${facts.packageLicense || "nothing"}"; the manifest declares ${manifest.spdx}.`,
    "package.json",
  ));

  const licenseDoc = documentStatus(root, manifest, "license");
  let licenseText = "";
  if (licenseDoc.available) {
    try {
      licenseText = readText(licenseDoc.file);
    } catch (_error) {
      licenseText = "";
    }
  }
  const licenseTextOk = /Permission is hereby granted, free of charge/i.test(licenseText) &&
    /THE SOFTWARE IS PROVIDED "AS IS"/i.test(licenseText);
  checks.push(check(
    "license-text",
    "licensing",
    "Full MIT license text",
    licenseDoc.available && licenseTextOk ? "pass" : "action",
    licenseDoc.available && licenseTextOk
      ? "LICENSE contains the full MIT permission and warranty notice."
      : "LICENSE is missing or does not contain the expected MIT text.",
    "LICENSE",
  ));

  for (const [id, label, evidence] of [
    ["third-party", "Third-party notices", "THIRD-PARTY-NOTICES.md"],
    ["privacy", "Privacy and data handling", "docs/PRIVACY.md"],
    ["contributions", "Contribution and DCO policy", "CONTRIBUTING.md"],
  ]) {
    const status = documentStatus(root, manifest, id);
    checks.push(check(
      `document-${id}`,
      id === "privacy" ? "privacy" : "distribution",
      label,
      status.available ? "pass" : "action",
      status.available
        ? `${evidence} is present.`
        : `${evidence} is missing or outside the application.`,
      evidence,
    ));
  }

  for (const component of manifest.components) {
    if (!component.notice) continue;
    const target = realInside(root, path.resolve(root, component.notice));
    const exists = Boolean(target && fs.existsSync(target));
    checks.push(check(
      `notice-${component.id}`,
      "distribution",
      `${component.name} notice`,
      exists ? "pass" : "action",
      exists
        ? `${component.notice} is present.`
        : `${component.notice} is missing.`,
      component.notice,
    ));
  }

  const versionOk = facts.appVersion === manifest.reviewedVersion;
  checks.push(check(
    "review-version",
    "licensing",
    "Review covers this version",
    versionOk ? "pass" : "warn",
    versionOk
      ? `Reviewed for ${manifest.reviewedVersion}.`
      : `Reviewed for ${manifest.reviewedVersion}; running ${facts.appVersion}.`,
    "legal/manifest.json",
  ));

  const reviewed = manifest.lastReviewed ? new Date(`${manifest.lastReviewed}T00:00:00Z`) : null;
  const ageDays = reviewed && !Number.isNaN(reviewed.getTime())
    ? Math.floor((now.getTime() - reviewed.getTime()) / 86400000)
    : Infinity;
  const fresh = ageDays >= 0 && ageDays <= REVIEW_MAX_AGE_DAYS;
  checks.push(check(
    "review-age",
    "licensing",
    "Review is current",
    fresh ? "pass" : "warn",
    fresh
      ? `Last reviewed ${manifest.lastReviewed}.`
      : `Last review is ${Number.isFinite(ageDays) ? `${ageDays} days old` : "missing"}; review annually.`,
    "legal/manifest.json",
  ));

  for (const component of manifest.components) {
    if (!component.versionFrom) continue;
    const runtime = facts.versions[component.versionFrom] || "";
    const expected = component.version || "";
    const match = runtime && expected && runtime === expected;
    checks.push(check(
      `component-${component.id}`,
      "distribution",
      `${component.name} version`,
      match ? "pass" : "warn",
      match
        ? `${component.name} ${runtime} matches the manifest.`
        : `${component.name} runtime is "${runtime || "unknown"}"; the manifest reviews "${expected || "unknown"}".`,
      "legal/manifest.json",
    ));
  }

  const missingDocs = [];
  for (const document of manifest.documents) {
    if (document.kind === "external") continue;
    const status = documentStatus(root, manifest, document.id);
    if (!status.available) missingDocs.push(document.label);
  }
  checks.push(check(
    "documents",
    "distribution",
    "Legal document set",
    missingDocs.length ? "action" : "pass",
    missingDocs.length
      ? `Missing: ${missingDocs.join(", ")}.`
      : `${manifest.documents.length} documents are present.`,
    "legal/manifest.json",
  ));

  return checks;
}

function summarize(checks, reviews) {
  const pendingReviews = reviews.filter((review) => review.status === "pending");
  const actions = checks.filter((item) => item.status === "action").length;
  const warnings = checks.filter((item) => item.status === "warn").length +
    pendingReviews.length;
  return {
    overall: actions ? "action" : warnings ? "review" : "ok",
    actions,
    warnings,
    pendingReviews: pendingReviews.length,
    checks: checks.length,
    reviews: reviews.length,
    pass: checks.filter((item) => item.status === "pass").length,
  };
}

function register(appVersion, options = {}) {
  const root = appRoot(options);
  const loaded = loadManifest(root);
  if (!loaded.ok) {
    return {
      ok: false,
      error: loaded.errors.join("; "),
      errors: loaded.errors,
      manifest: null,
      facts: null,
      checks: [],
      reviews: [],
      documents: [],
      summary: { overall: "action", actions: 1, warnings: 0, pendingReviews: 0,
        checks: 0, reviews: 0, pass: 0 },
    };
  }
  const facts = runtimeFacts(
    root,
    appVersion,
    options.versions || process.versions,
  );
  const checks = evaluate(loaded.manifest, facts, root, options);
  const reviews = loaded.manifest.reviews.map((review) => ({ ...review }));
  const documents = loaded.manifest.documents.map((document) => {
    const status = documentStatus(root, loaded.manifest, document.id);
    return {
      id: document.id,
      label: document.label,
      path: document.path,
      kind: document.kind,
      available: status.available,
      size: status.size,
    };
  });
  return {
    ok: true,
    manifest: loaded.manifest,
    facts,
    checks,
    reviews,
    documents,
    summary: summarize(checks, reviews),
  };
}

function readDocument(id, options = {}) {
  const root = appRoot(options);
  const loaded = loadManifest(root);
  if (!loaded.ok) throw new Error(loaded.errors.join("; "));
  const resolved = resolveDocument(root, loaded.manifest, id);
  const cap = resolved.document.kind === "html"
    ? MAX_HTML_BYTES : MAX_DOCUMENT_BYTES;
  const limit = Math.min(resolved.document.maxBytes || cap, cap);
  if (resolved.size > limit) {
    return {
      id,
      label: resolved.document.label,
      kind: resolved.document.kind,
      size: resolved.size,
      tooLarge: true,
    };
  }
  return {
    id,
    label: resolved.document.label,
    kind: resolved.document.kind,
    size: resolved.size,
    tooLarge: false,
    text: readText(resolved.file),
  };
}

function documentTarget(id, options = {}) {
  const root = appRoot(options);
  const loaded = loadManifest(root);
  if (!loaded.ok) throw new Error(loaded.errors.join("; "));
  const resolved = resolveDocument(root, loaded.manifest, id);
  return {
    id,
    label: resolved.document.label,
    file: resolved.file,
    size: resolved.size,
  };
}

function markdownEscape(value) {
  return String(value ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/([`*_\[\]<>|])/g, "\\$1")
    .replace(/\r?\n/g, " ");
}

function exportReport(format = "md", appVersion, options = {}) {
  const data = register(appVersion, options);
  if (!data.ok) throw new Error(data.error);
  const generatedAt = (options.now ? new Date(options.now) : new Date())
    .toISOString();
  if (format === "json") {
    return `${JSON.stringify({
      product: data.manifest.product,
      version: data.facts.appVersion,
      spdx: data.manifest.spdx,
      copyright: data.manifest.copyright,
      source: data.manifest.source,
      lastReviewed: data.manifest.lastReviewed,
      reviewedVersion: data.manifest.reviewedVersion,
      generatedAt,
      summary: data.summary,
      components: data.manifest.components,
      checks: data.checks,
      reviews: data.reviews,
      documents: data.documents.map((document) => ({
        id: document.id,
        label: document.label,
        path: document.path,
        kind: document.kind,
        available: document.available,
      })),
    }, null, 2)}\n`;
  }
  if (format !== "md") throw new Error("unsupported legal report format");
  const lines = [];
  lines.push(`# License & Legal — ${markdownEscape(data.manifest.product)}`);
  lines.push("");
  lines.push(`- Version: ${markdownEscape(data.facts.appVersion)}`);
  lines.push(`- License: ${markdownEscape(data.manifest.spdx)}`);
  lines.push(`- Copyright: ${markdownEscape(data.manifest.copyright)}`);
  lines.push(`- Source: ${data.manifest.source}`);
  lines.push(`- Last reviewed: ${data.manifest.lastReviewed}`);
  lines.push(`- Generated: ${generatedAt}`);
  lines.push(`- Overall: ${data.summary.overall} (${data.summary.actions} actions, ${data.summary.warnings} warnings)`);
  lines.push("");
  lines.push("## Components");
  lines.push("");
  lines.push("| Component | Version | License | Scope |");
  lines.push("| --- | --- | --- | --- |");
  for (const component of data.manifest.components) {
    lines.push(`| ${markdownEscape(component.name)} | ${markdownEscape(component.version || "—")} | ${markdownEscape(component.license)} | ${markdownEscape(component.scope)} |`);
  }
  lines.push("");
  lines.push("## Checks");
  lines.push("");
  for (const item of data.checks) {
    lines.push(`- ${item.status.toUpperCase()} — ${markdownEscape(item.label)}: ${markdownEscape(item.detail)}`);
  }
  lines.push("");
  lines.push("## Reviews");
  lines.push("");
  for (const review of data.reviews) {
    lines.push(`- ${review.status.toUpperCase()} — ${markdownEscape(review.category)}: ${markdownEscape(review.note)}`);
  }
  lines.push("");
  lines.push("## Documents");
  lines.push("");
  for (const document of data.documents) {
    lines.push(`- ${markdownEscape(document.label)} (${markdownEscape(document.path)})`);
  }
  lines.push("");
  lines.push("This report is an inventory aid, not legal advice.");
  lines.push("");
  return lines.join("\n");
}

module.exports = {
  documentTarget,
  evaluate,
  exportReport,
  loadManifest,
  manifestFile,
  readDocument,
  register,
  runtimeFacts,
  summarize,
  validateManifest,
};
