// Source-pin test for cm-hooks.js (issue #1669 Part B slice B2).
//
// issue #1875: the shared CM6 scaffold (updateListener sync, insert-before-hide order,
// aria-label, lineNumbers) moved out to cm-shell.js and is pinned once there
// (test/cm-shell-source.test.js) -- this file only pins what's specific to the hooks
// entry: its exports, its language-selection switch cm-regex.js does not have, its lint
// wiring, and that it actually delegates to the shared shell instead of re-duplicating it.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcPath = path.join(__dirname, "..", "cm-hooks.js");
const src = readFileSync(srcPath, "utf8");

test("fromTextarea is exported (the --global-name=pfbHooksCM bundle-facing entry point)", () => {
  assert.match(src, /export function fromTextarea\(textarea,\s*lang,\s*opts\)/);
});

// issue #1875: the dedup itself is the contract -- cm-hooks.js must delegate to the shared
// scaffold, not carry its own copy.
test("mountTextarea is imported from the shared cm-shell.js module", () => {
  assert.match(src, /import\s*\{[^}]*mountTextarea[^}]*\}\s*from\s*"\.\/cm-shell\.js"/);
});

// ------------------------------------------------------------------
// Language selection -- python + shell only, no PHP (owner-resolved language fork).
// ------------------------------------------------------------------

test("Python mode comes from @codemirror/lang-python's pythonLanguage", () => {
  assert.match(src, /import\s*\{\s*pythonLanguage\s*\}\s*from\s*"@codemirror\/lang-python"/);
});

test("shell mode comes from @codemirror/legacy-modes via StreamLanguage.define", () => {
  assert.match(src, /import\s*\{\s*shell\s*\}\s*from\s*"@codemirror\/legacy-modes\/mode\/shell"/);
  assert.match(src, /StreamLanguage\.define\(shell\)/);
});

test("no PHP language package is imported", () => {
  assert.ok(!/lang-php/i.test(src), "expected no @codemirror/lang-php (or similar) import -- python+shell only");
});

test("language selection keys off lang === 'py', defaulting everything else to shell", () => {
  assert.match(src, /lang === "py" \? pythonLanguage : shellLanguage/);
});

// ------------------------------------------------------------------
// issue #1732 step 2: advisory server lint, wired behind an opts.lintUrl guard so a
// caller that passes no opts gets byte-identical behaviour. No bracket lint here --
// shell mode is a StreamLanguage with no meaningful Lezer error nodes (scope C is the
// regex editor only).
// ------------------------------------------------------------------

test("fromTextarea accepts an optional third opts argument", () => {
  assert.match(src, /export function fromTextarea\(textarea,\s*lang,\s*opts\)/);
});

test("serverLint is imported from the shared cm-lint.js module", () => {
  assert.match(src, /import\s*\{[^}]*serverLint[^}]*\}\s*from\s*"\.\/cm-lint\.js"/);
});

// Extracts the brace-bounded body of `if (opts && opts.lintUrl) { ... }` so the test
// below can assert the serverLint call happens INSIDE the guard, not merely somewhere
// later in the file (a call moved outside the guard, after its closing brace, still
// passes an indexOf-order check but never actually runs unguarded).
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

test("serverLint is wired with the py/sh ternary behind an opts.lintUrl guard", () => {
  const block = lintUrlGuardBlock(src);
  assert.match(
    block,
    /serverLint\(\s*opts\.lintUrl,\s*lang === ["']py["']\s*\?\s*["']py["']\s*:\s*["']sh["'],\s*opts\.lintExtraParams\s*\)/,
    "expected the serverLint(...) call INSIDE the opts.lintUrl guard block",
  );
});

test("no bracket/lezer-error lint is referenced (regex editor only)", () => {
  assert.ok(!/lezerErrorLint/.test(src), "expected cm-hooks.js to never reference lezerErrorLint");
});
