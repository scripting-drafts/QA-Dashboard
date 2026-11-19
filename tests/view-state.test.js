"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const viewState = require("../electron/view-state");

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qa-view-state-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("last view round-trips with a private mode", (t) => {
  const dir = tempDir(t);
  assert.equal(viewState.load(dir), null);

  viewState.save(dir, "tickets", "tickets");
  assert.deepEqual(viewState.load(dir), {
    module: "tickets", tab: "tickets",
  });
  if (process.platform !== "win32") {
    const mode = fs.statSync(viewState.statePath(dir)).mode & 0o777;
    assert.equal(mode, 0o600);
  }
  assert.deepEqual(fs.readdirSync(dir), [viewState.STATE_FILE]);

  viewState.save(dir, "sen-overview", "tickets");
  assert.deepEqual(viewState.load(dir), {
    module: "sen-overview", tab: "tickets",
  });
});

test("malformed or hostile state is ignored", (t) => {
  const dir = tempDir(t);
  const file = viewState.statePath(dir);

  fs.writeFileSync(file, "{not json");
  assert.equal(viewState.load(dir), null);
  fs.writeFileSync(file, JSON.stringify({ module: "../tickets", tab: "" }));
  assert.equal(viewState.load(dir), null);
  fs.writeFileSync(file, JSON.stringify({ module: "", tab: "tickets" }));
  assert.equal(viewState.load(dir), null);
  fs.writeFileSync(file, JSON.stringify({
    module: "x".repeat(41), tab: "tickets",
  }));
  assert.equal(viewState.load(dir), null);
  fs.writeFileSync(file, JSON.stringify({
    module: "tickets", tab: "tickets",
  }) + " ".repeat(5000));
  assert.equal(viewState.load(dir), null);
});

test("save rejects invalid fields", (t) => {
  const dir = tempDir(t);
  assert.throws(() => viewState.save(dir, "", ""), /invalid module/);
  assert.throws(() => viewState.save(dir, "tickets", null), /invalid tab/);
  assert.throws(() => viewState.save(dir, "x".repeat(41), ""),
    /invalid module/);
  assert.throws(() => viewState.save(dir, "tickets", "x".repeat(41)),
    /invalid tab/);
  assert.equal(viewState.load(dir), null);
});
