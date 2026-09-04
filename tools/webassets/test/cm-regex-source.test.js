// Source-pin test for cm-regex.js (issue #1669 PR #1680 review round, FIX-2/FIX-3).
//
// issue #1875: the shared CM6 scaffold (updateListener sync, insert-before-hide order,
// aria-label, lineNumbers) moved out to cm-shell.js and is pinned once there
// (test/cm-shell-source.test.js) -- this file only pins what's specific to the regex-list
// entry: its exports, its language/lint wiring, and that it actually delegates to the
// shared shell instead of re-duplicating it.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcPath = path.join(__dirname, "..", "cm-regex.js");
const src = readFileSync(srcPath, "utf8");
const cmLintSrc = readFileSync(path.join(__dirname, "..", "cm-lint.js"), "utf8");

test("fromTextarea is exported (the --global-name=pfbCM bundle-facing entry point)", () => {
  assert.match(src, /export function fromTextarea\(/);
});

// issue #1875: the dedup itself is the contract -- cm-regex.js must delegate to the shared
// scaffold, not carry its own copy.
test("cm-regex imports mountTextarea from the shared cm-shell.js module", () => {
  assert.match(src, /import\s*\{[^}]*mountTextarea[^}]*\}\s*from\s*"\.\/cm-shell\.js"/);
});

test("fromTextareaList is exported and mounts the plain-list language with no extra extensions", () => {
  assert.match(src, /export function fromTextareaList\(/);
  assert.match(src, /import\s*\{[^}]*pfbPlainList[^}]*\}\s*from\s*"\.\/lezer-pfb-regex-list\/src\/index\.js"/);
});

test("mountLists is exported (one call per page mounts every plain-list field)", () => {
  assert.match(src, /export function mountLists\(/);
});

// ------------------------------------------------------------------
// issue #1732 step 2: advisory server lint + offline bracket lint, wired behind an
// opts.lintUrl guard so a caller that passes no opts gets byte-identical behaviour.
// ------------------------------------------------------------------

test("fromTextarea accepts an optional opts argument", () => {
  assert.match(src, /export function fromTextarea\(textarea,\s*opts\)/);
});

test("serverLint and lezerErrorLint are imported from the shared cm-lint.js module", () => {
  assert.match(src, /import\s*\{[^}]*serverLint[^}]*\}\s*from\s*"\.\/cm-lint\.js"/);
  assert.match(src, /import\s*\{[^}]*lezerErrorLint[^}]*\}\s*from\s*"\.\/cm-lint\.js"/);
});

// Extracts the brace-bounded body of `if (opts && opts.lintUrl) { ... }` so the tests
// below can assert a call happens INSIDE the guard, not merely somewhere later in the
// file (a call moved outside the guard, after its closing brace, still passes an
// indexOf-order check but never actually runs unguarded).
function lintUrlGuardBlock(source) {
  const markerIdx = source.indexOf("if (opts && opts.lintUrl) {");
  assert.notEqual(markerIdx, -1, "expected the opts.lintUrl guard to be present");
  const openIdx = source.indexOf("{", markerIdx);
  let depth = 0;
  let i = openIdx;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  assert.equal(depth, 0, "expected a balanced closing brace for the opts.lintUrl guard");
  return source.slice(openIdx, i + 1);
}

test("serverLint is wired with lang 'regex' behind an opts.lintUrl guard", () => {
  const block = lintUrlGuardBlock(src);
  assert.match(
    block,
    /serverLint\(\s*opts\.lintUrl,\s*["']regex["'],\s*opts\.lintExtraParams\s*\)/,
    "expected the serverLint(...) call INSIDE the opts.lintUrl guard block",
  );
});

test("lezerErrorLint is added alongside serverLint behind the same opts.lintUrl guard", () => {
  const block = lintUrlGuardBlock(src);
  assert.ok(
    block.includes("lezerErrorLint("),
    "expected the lezerErrorLint(...) call INSIDE the opts.lintUrl guard block",
  );
});

test("fromTextarea forwards getExceptionsView into Lezer lint options", () => {
  assert.match(src, /getExceptionsView:\s*opts\.getExceptionsView/);
});

test("cm-lint.js uses a plain XMLHttpRequest, never fetch() or FormData (csrf-magic constraint)", () => {
  // pfSense's csrf-magic.js patches XMLHttpRequest.prototype.open/send globally and
  // PREPENDS the CSRF token to any STRING POST body. fetch() is unhooked (the token is
  // never attached) and a FormData body isn't a string (the prepend would corrupt it) --
  // pinned here so a refactor to fetch() fails a test that names exactly why, instead of
  // silently breaking every save on a live pfSense box. Scans CODE lines only (strips
  // full-line "//" comments) -- the module's own header comment explains this constraint
  // in prose and legitimately names both "fetch(" and "FormData".
  const codeLines = cmLintSrc
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");
  assert.match(codeLines, /new XMLHttpRequest\(\)/);
  assert.ok(!/\bfetch\(/.test(codeLines), "expected no fetch( call in cm-lint.js code");
  assert.ok(!/\bFormData\b/.test(codeLines), "expected no FormData usage in cm-lint.js code");
});
