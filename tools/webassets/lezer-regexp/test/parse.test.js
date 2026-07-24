// node:test runner for the Python-re Lezer grammar (issue #1669 slice A).
// Cases live in test/cases.txt, in @lezer/generator's fileTests format
// ("# name\n<input>\n==>\n<expected tree>"); each case is its own subtest so
// a single mismatched tree doesn't hide the rest. fileTests() (exported from
// "@lezer/generator/test", not the package main entry -- verified against
// node_modules/@lezer/generator/package.json's "exports" map) throws on
// mismatch, which test.run(parser) surfaces as a subtest failure.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileTests } from "@lezer/generator/test";
import { parser } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const casesPath = path.join(__dirname, "cases.txt");
const casesText = readFileSync(casesPath, "utf8");

const cases = fileTests(casesText, "cases.txt");

test("cases.txt has the expected minimum coverage", () => {
  assert.ok(
    cases.length >= 30,
    `expected >= 30 cases, got ${cases.length} -- coverage matrix (issue #1669 slice A) requires >= 30 rows`,
  );
});

for (const testCase of cases) {
  test(testCase.name, () => {
    testCase.run(parser);
  });
}

// Hostile-input rows that assert "parses without throwing" rather than
// pinning an exact tree (deep nesting, large input) -- fileTests' exact-tree
// assertions don't fit an input this large/generated, so these get their own
// dedicated node:test cases instead of a cases.txt entry.
test("hostile: 200-level nested groups parse without throwing", () => {
  const input = "(".repeat(200) + "a" + ")".repeat(200);
  assert.doesNotThrow(() => parser.parse(input));
});

test("hostile: a 10 kB pattern parses in bounded time", () => {
  const input = "a|".repeat(5000) + "a";
  assert.ok(input.length >= 10_000, `fixture is ${input.length} bytes, need >= 10kB`);
  const start = performance.now();
  assert.doesNotThrow(() => parser.parse(input));
  const elapsedMs = performance.now() - start;
  // Generous bound (CI-flake-resistant) -- see handoff for the real measured
  // time on this machine, which is far below this ceiling.
  assert.ok(elapsedMs < 5000, `parse took ${elapsedMs}ms, expected < 5000ms`);
});

test("hostile: unclosed group/class and trailing backslash parse without throwing", () => {
  for (const input of ["(ab", "[ab", "ab\\"]) {
    assert.doesNotThrow(() => parser.parse(input), `input ${JSON.stringify(input)} threw`);
  }
});
