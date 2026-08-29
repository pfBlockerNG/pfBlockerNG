// Source-pin test for cm-shell.js (issue #1875 dedup of the CM6 editor scaffold cm-regex.js
// and cm-hooks.js used to duplicate). Moved here from cm-regex-source.test.js /
// cm-hooks-source.test.js -- the contract is now pinned ONCE against the shared module
// instead of twice against each entry's own copy.
//
// No test previously pinned the textarea<->editor sync contract -- EditorView.updateListener
// .of(...) writing `textarea.value` on every doc change is what keeps a plain HTML form
// submit (or a save handler that reads the textarea directly) from silently discarding
// whatever the user typed into the CodeMirror view. Deleting that listener is a data-loss
// bug that passes every other gate (grammar tests, the PHP wiring tests,
// check_webassets_vendor.py) because none of them exercise runtime doc-change behaviour --
// they pin markup/wiring shape and grammar trees, not this contract.
//
// This is a plain source-text pin (grep-style, not an executed EditorView), cheap,
// deterministic, no DOM/jsdom dependency -- exactly what closes the gap: if the sync block
// is stripped, this test fails.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcPath = path.join(__dirname, "..", "cm-shell.js");
const src = readFileSync(srcPath, "utf8");

test("mountTextarea is exported (the shared entry point cm-regex.js/cm-hooks.js delegate to)", () => {
  assert.match(src, /export function mountTextarea\(textarea,\s*language,\s*extraExtensions\s*=\s*\[\]\)/);
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

test("EditorView.contentAttributes carries an aria-label derived from the textarea (a11y)", () => {
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

// issue #1869: cheap regression guard for the line-number gutter. The rendering itself is
// proven in the browser tier (tests/smoke/ui/test_browser_line_numbers.py) -- this only
// catches the extension being dropped from the list, which no grammar or wiring test would
// notice. Pinned once here (both bundles delegate to this shared scaffold) instead of once
// per entry.
test("lineNumbers() is imported and installed in the extension list", () => {
  assert.match(src, /import \{[^}]*\blineNumbers\b[^}]*\} from "@codemirror\/view"/);
  assert.match(src, /lineNumbers\(\)/);
  assert.doesNotMatch(src, /autoGrow \? \[\] : \[lineNumbers\(\)\]/);
});

test("auto-grow fields hide the scroller until content exceeds the cap", () => {
  assert.ok(
    src.includes('overflowY = n > maxLines ? "auto" : "hidden"'),
    "expected overflow:auto only once the auto-grow field is past maxLines",
  );
  assert.match(src, /requestAnimationFrame\(\(\) => fitAutoGrow/);
});

// issue #1875: pfSense's disableInput() greys a field and keeps it out of the POST (the
// General page's internal-feed allowlist does this when the master filter is off). The
// mounted editor hides that textarea, so without tracking the attribute the editor stays
// editable over a disabled field and silently eats edits the save then ignores. The
// behaviour itself is proven in the browser tier; these pins only catch the mechanism
// being dropped from the shared shell.
test("the editor's editable state follows the textarea's disabled attribute (mount time)", () => {
  assert.match(src, /import \{[^}]*\bCompartment\b[^}]*\} from "@codemirror\/state"/);
  assert.ok(
    src.includes("EditorView.editable.of(!textarea.disabled)"),
    "expected the editable facet to be derived from !textarea.disabled at mount time",
  );
});

test("a MutationObserver tracks live disabled-attribute flips (disableInput toggles at runtime)", () => {
  assert.match(src, /new MutationObserver\(/);
  assert.ok(
    src.includes('attributeFilter: ["disabled"]'),
    "expected the observer to watch exactly the disabled attribute",
  );
  assert.match(
    src,
    /reconfigure\(EditorView\.editable\.of\(!textarea\.disabled\)\)/,
    "expected the observer to reconfigure the editable compartment from the textarea's live disabled state",
  );
});

test("a non-editable editor is greyed like a disabled pfSense input", () => {
  assert.ok(
    src.includes('".cm-content[contenteditable=false]"'),
    "expected a theme rule greying the content pane when the editable facet turns it off",
  );
  assert.match(
    src,
    /\.cm-content\[contenteditable=false\]": \{ backgroundColor: "#eee", color: "#555" \}/,
    "disabled pane must pin foreground so it cannot inherit body color",
  );
});

test("the light editor pane pins foreground wherever it pins a background", () => {
  assert.match(
    src,
    /"&": \{ border: "1px solid #b7b7b7", backgroundColor: "#fff", color: "#212121" \}/,
  );
  assert.match(src, /\.cm-cursor, \.cm-dropCursor": \{ borderLeftColor: "#212121" \}/);
  assert.match(
    src,
    /\.cm-gutters": \{ backgroundColor: "#f5f5f5", color: "#6c6c6c", borderRight: "1px solid #ddd" \}/,
  );
  assert.match(
    src,
    /&\.cm-focused \.cm-selectionBackground, \.cm-selectionBackground": \{ backgroundColor: "#d7d7d7" \}/,
  );
});

test("fixed-height mounts still use the textarea rows attribute times 1.4em", () => {
  assert.match(src, /rows \* 1\.4/);
  assert.match(src, /view\.dom\.style\.height = height/);
});

test("data-pfb-autogrow-max grows the editor with doc.lines and caps at the attribute", () => {
  assert.ok(
    src.includes('data-pfb-autogrow-max'),
    "expected mountTextarea to read data-pfb-autogrow-max from the textarea",
  );
  assert.ok(
    src.includes("view.state.doc.lines"),
    "expected auto-grow height to follow the document line count",
  );
  assert.ok(
    src.includes("view.defaultLineHeight"),
    "expected auto-grow to use the rendered line height, not a 1.4em guess",
  );
  assert.ok(
    src.includes("view.documentPadding"),
    "expected auto-grow to include content padding so a one-line editor is not cropped",
  );
});
