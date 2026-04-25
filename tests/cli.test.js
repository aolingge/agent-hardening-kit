import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanRepository, renderMarkdown, renderSarif, writePolicy } from "../src/cli.js";

const repoRoot = path.resolve(".");

test("good fixture receives a passing score", () => {
  const report = scanRepository(path.join(repoRoot, "fixtures/good-repo"));
  assert.equal(report.grade, "A");
  assert.equal(report.summary.errors, 0);
});

test("risky fixture detects cross-domain findings", () => {
  const report = scanRepository(path.join(repoRoot, "fixtures/risky-repo"));
  assert.ok(report.score < 70);
  assert.ok(report.findings.some((finding) => finding.id === "agents.missing"));
  assert.ok(report.findings.some((finding) => finding.id === "prompt.injection-phrase"));
  assert.ok(report.findings.some((finding) => finding.id === "shell.destructive-command"));
});

test("markdown and sarif render useful reports", () => {
  const report = scanRepository(path.join(repoRoot, "fixtures/risky-repo"));
  assert.match(renderMarkdown(report), /Agent Hardening Report/);
  const sarif = JSON.parse(renderSarif(report));
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.length > 0);
});

test("writePolicy creates starter files without overwriting", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ahk-"));
  const written = writePolicy(temp);
  assert.deepEqual(written.sort(), [".agent-hardening/mcp-permission-matrix.md", ".agent-hardening/policy.md", ".github/workflows/agent-hardening.yml"].sort());
  const second = writePolicy(temp);
  assert.deepEqual(second, []);
});

test("project-level scan honors ignore file for intentionally risky fixtures", () => {
  const report = scanRepository(repoRoot);
  assert.ok(report.score >= 80);
  assert.ok(!report.findings.some((finding) => finding.file.startsWith("fixtures/risky-repo/")));
});
