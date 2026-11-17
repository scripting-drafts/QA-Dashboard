#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const dir = path.resolve(process.argv[2] || "dist");
const artifact = /\.(exe|zip|dmg|pkg|msi|AppImage|tar\.gz|deb)$/;
const files = fs.readdirSync(dir)
  .filter((name) => name === "PRERELEASE.md" || name === "DIAGNOSTICS.md"
    || artifact.test(name))
  .filter((name) => fs.statSync(path.join(dir, name)).isFile())
  .sort();

const lines = files.map((name) => {
  const hash = crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(dir, name)))
    .digest("hex");
  return `${hash}  ${name}`;
});

fs.writeFileSync(path.join(dir, "SHA256SUMS"), `${lines.join("\n")}\n`);
console.log(lines.join("\n"));
