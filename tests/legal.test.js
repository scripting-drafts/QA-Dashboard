"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const legal = require("../electron/legal");

const ROOT = path.join(__dirname, "..");
const VERSIONS = {
  electron: "45.2.3",
  chrome: "156.0.8078.80",
  node: "24.22.2",
  v8: "15.6.75.27-electron.0",
};

test("the checked-in manifest is valid", () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(ROOT, "legal", "manifest.json"), "utf8"));
  assert.deepEqual(legal.validateManifest(manifest), []);
});

test("the register evaluates the checked-in application", () => {
  const data = legal.register("0.4.1", { root: ROOT, versions: VERSIONS });
  assert.equal(data.ok, true);
  assert.equal(data.facts.packageLicense, "MIT");
  assert.equal(data.summary.actions, 0);
  assert.equal(data.summary.overall, "review");
  assert.ok(data.summary.pendingReviews >= 3);
  assert.ok(data.checks.some((check) =>
    check.id === "license-text" && check.status === "pass"));
  assert.ok(data.checks.some((check) =>
    check.id === "component-electron" && check.status === "pass"));
  assert.ok(data.documents.every((document) => document.available));
});

test("license documents are readable and large HTML notices are deferred", () => {
  const license = legal.readDocument("license", { root: ROOT });
  assert.match(license.text, /Permission is hereby granted/);
  const chromium = legal.readDocument("chromium-notice", { root: ROOT });
  assert.equal(chromium.tooLarge, true);
  assert.ok(chromium.size > 512 * 1024);
});

test("the exported report uses relative paths and no host data", () => {
  const text = legal.exportReport("json", "0.4.1", {
    root: ROOT, versions: VERSIONS,
  });
  const report = JSON.parse(text);
  assert.equal(report.product, "QA Dashboard");
  assert.equal(report.spdx, "MIT");
  assert.equal(report.summary.overall, "review");
  assert.ok(!text.includes(ROOT));
  assert.ok(!text.includes(os.homedir()));
  assert.ok(report.documents.every((document) => !document.path.startsWith("/")));
});

test("document resolution rejects paths outside the application", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "qa-legal-"));
  try {
    fs.mkdirSync(path.join(root, "legal"), { recursive: true });
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
      name: "fixture", version: "0.4.0", license: "MIT",
    }));
    fs.writeFileSync(path.join(root, "legal", "manifest.json"), JSON.stringify({
      schemaVersion: 1,
      product: "Fixture",
      spdx: "MIT",
      copyright: "Copyright (c) 2026 Example",
      source: "https://example.com/fixture",
      lastReviewed: "2026-11-16",
      reviewedVersion: "0.4.0",
      components: [{
        id: "fixture", name: "Fixture", license: "MIT", scope: "project",
      }],
      documents: [{
        id: "escape", label: "Escape", path: "../secret", kind: "text",
      }],
      reviews: [],
    }));
    assert.throws(
      () => legal.documentTarget("escape", { root }),
      /invalid|outside|not found|manifest/i,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("packaging installs the legal artifacts", () => {
  const rules = fs.readFileSync(path.join(ROOT, "debian", "rules"), "utf8");
  const installer = fs.readFileSync(path.join(ROOT, "install.sh"), "utf8");
  for (const name of [
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
    "legal/manifest.json",
    "electron-LICENSE",
    "chromium-LICENSES.html",
  ]) {
    assert.match(rules, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  for (const name of ["LICENSE", "THIRD-PARTY-NOTICES.md", "legal/manifest.json"]) {
    assert.match(installer, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("package metadata declares the same license", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const manifest = JSON.parse(
    fs.readFileSync(path.join(ROOT, "legal", "manifest.json"), "utf8"));
  assert.equal(pkg.version, manifest.reviewedVersion);
  assert.equal(pkg.license, "MIT");
});
