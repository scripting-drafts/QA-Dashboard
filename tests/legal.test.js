"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.join(__dirname, "..");
const manifest = JSON.parse(
  fs.readFileSync(path.join(ROOT, "legal", "manifest.json"), "utf8"));
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

test("the legal register matches the application version", () => {
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.product, pkg.productName);
  assert.equal(manifest.spdx, pkg.license);
  assert.equal(manifest.reviewedVersion, pkg.version);
});

test("the legal register has no pending reviews", () => {
  for (const review of manifest.reviews) {
    assert.ok(["reviewed", "not-applicable"].includes(review.status),
      `${review.category}: ${review.status}`);
  }
});

test("every declared legal document exists", () => {
  for (const document of manifest.documents) {
    const target = path.resolve(ROOT, document.path);
    assert.ok(target.startsWith(ROOT + path.sep), document.path);
    assert.ok(fs.existsSync(target), document.path);
  }
});

test("companion versions match the register", () => {
  const companions = new Map(
    manifest.components
      .filter((component) => component.scope === "companion")
      .map((component) => [component.id, component.version]));
  assert.equal(companions.get("qa-sentinels"), manifest.reviewedComponents["qa-sentinels"]);
  assert.equal(companions.get("qa-license-scanner"),
    manifest.reviewedComponents["qa-license-scanner"]);
});

test("legal artifacts ship with the package", () => {
  const rules = fs.readFileSync(path.join(ROOT, "debian", "rules"), "utf8");
  for (const name of ["legal/manifest.json", "docs/LEGAL.md",
    "THIRD-PARTY-NOTICES.md", "LICENSE"]) {
    assert.ok(rules.includes(name), name);
  }
});
