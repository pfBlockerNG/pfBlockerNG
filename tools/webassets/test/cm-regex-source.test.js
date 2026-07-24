// Source-pin test for cm-regex.js (issue #1669 PR #1680 review round, FIX-2/FIX-3).
//
// No test previously pinned cm-regex.js's textarea<->editor sync contract --
// EditorView.updateListener.of(...) writing `textarea.value` on every doc change is what
// keeps a plain HTML form submit (or a save handler that reads the textarea directly) from
// silently discarding whatever the user typed into the CodeMirror view. Deleting that
// listener is a data-loss bug that passes every other gate (grammar tests, the PHP wiring
// test, check_webassets_vendor.py) because none of them exercise runtime doc-change
// behaviour -- they pin markup/wiring shape and grammar trees, not this contract.
//
// This is a plain source-text pin (grep-style, not an executed EditorView), same tier as
// the DOM-order assertion below -- cheap, deterministic, no DOM/jsdom dependency, and it is
// exactly what closes the gap: if the sync block is stripped, this test fails.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcPath = path.join(__dirname, "..", "cm-regex.js");
const src = readFileSync(srcPath, "utf8");

test("fromTextarea is exported (the --global-name=pfbCM bundle-facing entry point)", () => {
  assert.match(src, /export function fromTextarea\(/);
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
    'expected the literal sync statement `textarea.value = update.state.doc.toString();` -- ' +
      "this is the whole data-loss-prevention contract: strip it and user edits stop reaching the POST",
  );
});

test("the textarea is hidden (display: none) only AFTER the editor DOM is inserted", () => {
  // Insert-then-hide order matters: hiding the textarea first (or hiding it without ever
  // inserting the replacement view) would leave the page with no visible editor at all.
  const insertIdx = src.indexOf('textarea.insertAdjacentElement("beforebegin", view.dom);');
  const hideIdx = src.indexOf('textarea.style.display = "none";');
  assert.notEqual(insertIdx, -1, "expected the view.dom insertAdjacentElement(...) call to be present");
  assert.notEqual(hideIdx, -1, 'expected the textarea.style.display = "none"; statement to be present');
  assert.ok(
    insertIdx < hideIdx,
    `expected the DOM insert (index ${insertIdx}) to occur before the textarea is hidden (index ${hideIdx})`,
  );
});

test("EditorView.contentAttributes carries an aria-label derived from the textarea (FIX-3, a11y)", () => {
  // Hiding the textarea (display: none, above) drops it -- and any aria-label it carried --
  // from the accessibility tree entirely. The replacement editor view needs its own
  // accessible name, transferred from the textarea it replaces.
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
