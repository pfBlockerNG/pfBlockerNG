// Source-pin test for cm-hooks.js (issue #1669 Part B slice B2). Same tier and
// rationale as test/cm-regex-source.test.js's textarea<->editor sync pins -- plain
// source-text checks (grep-style, not an executed EditorView), cheap/deterministic,
// no DOM/jsdom dependency. Extends the shared contract with the language-selection
// switch cm-regex.js does not have (a single mode, so no fromTextarea() second arg).
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

test("an EditorView.updateListener is installed", () => {
  assert.match(src, /EditorView\.updateListener\.of\(/);
});

test("the updateListener checks update.docChanged before syncing", () => {
  assert.match(src, /update\.docChanged/);
});

test("the updateListener writes the doc back onto textarea.value on every change", () => {
  assert.ok(
    src.includes("textarea.value = update.state.doc.toString();"),
    "expected the literal sync statement `textarea.value = update.state.doc.toString();` -- " +
      "this is the whole data-loss-prevention contract: strip it and user edits stop reaching the POST",
  );
});

test("the textarea is hidden (display: none) only AFTER the editor DOM is inserted", () => {
  const insertIdx = src.indexOf('textarea.insertAdjacentElement("beforebegin", view.dom);');
  const hideIdx = src.indexOf('textarea.style.display = "none";');
  assert.notEqual(insertIdx, -1, "expected the view.dom insertAdjacentElement(...) call to be present");
  assert.notEqual(hideIdx, -1, 'expected the textarea.style.display = "none"; statement to be present');
  assert.ok(
    insertIdx < hideIdx,
    `expected the DOM insert (index ${insertIdx}) to occur before the textarea is hidden (index ${hideIdx})`,
  );
});

test("EditorView.contentAttributes carries an aria-label derived from the textarea", () => {
  assert.match(src, /EditorView\.contentAttributes\.of\(/);
  assert.ok(
    src.includes('textarea.getAttribute("aria-label")'),
    "expected the accessible-name derivation to read the textarea's own aria-label first",
  );
  assert.ok(
    src.includes("textarea.labels"),
    "expected a fallback to the textarea's associated <label> (textarea.labels) when it carries no aria-label",
  );
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

test("serverLint is wired with the py/sh ternary behind an opts.lintUrl guard", () => {
  assert.match(src, /opts\s*&&\s*opts\.lintUrl/);
  assert.match(
    src,
    /serverLint\(\s*opts\.lintUrl,\s*lang === ["']py["']\s*\?\s*["']py["']\s*:\s*["']sh["'],\s*opts\.lintExtraParams\s*\)/,
  );
});

test("no bracket/lezer-error lint is referenced (regex editor only)", () => {
  assert.ok(!/lezerErrorLint/.test(src), "expected cm-hooks.js to never reference lezerErrorLint");
});
