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

function errorRanges(input) {
  const errors = [];
  parser.parse(input).iterate({
    enter(node) {
      if (node.type.isError) errors.push({ from: node.from, to: node.to });
    },
  });
  return errors;
}

// issue #3059: group-open tokens (`?i`, `?:`, `?=`, …) must not match after a
// quantifier. Python's extension syntax is only valid immediately after `(`.
const INLINE_FLAG_LETTERS = ["a", "i", "L", "m", "s", "u", "x"];

test("quantifier before a Python inline-flag letter is not a FlagsMarker (issue #3059)", () => {
  for (const letter of INLINE_FLAG_LETTERS) {
    const input = `z?${letter}`;
    assert.deepEqual(errorRanges(input), [], `expected no error nodes for ${JSON.stringify(input)}`);
    assert.equal(parser.parse(input).toString(), "RegExp(Literal,Quantifier,Literal)");
  }
});

test("quantifier before group-open punctuation is not a group marker (issue #3059)", () => {
  for (const input of ["a?:", "a?=", "a?!"]) {
    assert.deepEqual(errorRanges(input), [], `expected no error nodes for ${JSON.stringify(input)}`);
    assert.equal(parser.parse(input).toString(), "RegExp(Literal,Quantifier,Literal)");
  }
});

test("maintainer DNSBL patterns that Python accepts have no error nodes (issue #3059)", () => {
  for (const input of [
    "^(.+[-_.])??m?ad[sxv]?[0-9]*[-_.]",
    "^(.+[-_.])??adse?rv(er?|ice)?s?[0-9]*[-.]",
  ]) {
    assert.deepEqual(errorRanges(input), [], `expected no error nodes for ${JSON.stringify(input)}`);
  }
});

test("trailing dash in a class is a literal, not a broken range (Python re docs)", () => {
  for (const input of ["[a-]", "[.-]", "[0-]", "[a-z-]"]) {
    assert.deepEqual(errorRanges(input), [], `expected no error nodes for ${JSON.stringify(input)}`);
  }
  assert.equal(parser.parse("[a-]").toString(), "RegExp(CharacterClass(ClassOpen,ClassLiteral,\"-\",ClassClose))");
});

test("Python re docs syntax examples parse without error nodes", () => {
  for (const input of [
    ".",
    "^a",
    "a$",
    "ab*",
    "ab+",
    "ab?",
    "a*?",
    "a+?",
    "a??",
    "a*+",
    "a++",
    "a?+",
    "a{6}",
    "a{3,5}",
    "a{4,}",
    "a{3,5}?",
    "a{3,5}+",
    "[amk]",
    "[a-z]",
    "[0-5][0-9]",
    "[0-9A-Fa-f]",
    "[a\\-z]",
    "[-a]",
    "[a-]",
    "[(+*)]",
    "[^5]",
    "[^^]",
    "[]()[{}]",
    "[()[\\]{}]",
    "A|B",
    "[|]",
    "(ab)",
    "(?:ab)",
    "(?i)",
    "(?i:x)",
    "(?-i:x)",
    "(?i-s:x)",
    "(?a:x)",
    "(?>.*)",
    "(?P<quote>['\"]).*?(?P=quote)",
    "(?#foo)",
    "Isaac (?=Asimov)",
    "Isaac (?!Asimov)",
    "(?<=abc)def",
    "(?<!abc)def",
    "(<)?(\\w+@\\w+(?:\\.\\w+)+)(?(1)>|$)",
    "(.+) \\1",
    "\\Afoo",
    "\\bat\\b",
    "at\\B",
    "\\d+",
    "\\D+",
    "\\s+",
    "\\S+",
    "\\w+",
    "\\W+",
    "foo\\Z",
    "\\x41",
    "\\u0041",
    "\\U00000041",
    "\\N{LATIN SMALL LETTER A}",
    "(?<=-)\\w+",
  ]) {
    assert.deepEqual(errorRanges(input), [], `expected no error nodes for ${JSON.stringify(input)}`);
  }
});
