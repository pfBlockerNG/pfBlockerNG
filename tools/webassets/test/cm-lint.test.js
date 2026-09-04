// Tests for cm-lint.js (issue #1732 step 2: client-side lint wiring shared by both
// bundles). Real imports (not source pins) -- @codemirror/state/@codemirror/language are
// devDeps, so EditorState/syntaxTree exercise the real diagnostic-mapping and bracket-lint
// logic end to end. Run after `npm ci` in tools/webassets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EditorState } from "@codemirror/state";
import { ensureSyntaxTree } from "@codemirror/language";
import { pfbRegexList } from "../lezer-pfb-regex-list/src/index.js";
import {
  buildLintBody,
  diagnosticsToCm,
  lezerErrorDiagnostics,
  lezerErrorLint,
  moveRegexLine,
  PFB_REGEX_EDITOR_FLAG_MESSAGE,
  PFB_REGEX_MOVE_ACTION_NAME,
  serverLint,
  serverLintSource,
} from "../cm-lint.js";

test("buildLintBody encodes lang/content and merges extraParams", () => {
  const body = buildLintBody("regex", "a&b=c\ndé", { cap: "1" });
  assert.equal(
    body,
    `lang=regex&content=${encodeURIComponent("a&b=c\ndé")}&cap=${encodeURIComponent("1")}`,
  );
});

test("buildLintBody with null extraParams appends nothing extra", () => {
  const body = buildLintBody("sh", "echo hi", null);
  assert.equal(body, `lang=sh&content=${encodeURIComponent("echo hi")}`);
});

test("buildLintBody encodes every extraParams key", () => {
  const body = buildLintBody("py", "x", { cap: "1", other: "a b" });
  assert.equal(
    body,
    `lang=py&content=${encodeURIComponent("x")}&cap=${encodeURIComponent("1")}&other=${encodeURIComponent("a b")}`,
  );
});

test("diagnosticsToCm maps an in-range line to that line's from/to", () => {
  const doc = EditorState.create({ doc: "a\nb\nc" }).doc;
  const [d] = diagnosticsToCm(doc, [{ line: 2, message: "bad", severity: "error" }]);
  const line2 = doc.line(2);
  assert.equal(d.from, line2.from);
  assert.equal(d.to, line2.to);
  assert.equal(d.severity, "error");
  assert.equal(d.message, "bad");
});

test("diagnosticsToCm clamps a past-end line to the last line (never dropped)", () => {
  const doc = EditorState.create({ doc: "a\nb\nc" }).doc;
  const [d] = diagnosticsToCm(doc, [{ line: 99, message: "past", severity: "error" }]);
  const last = doc.line(doc.lines);
  assert.equal(d.from, last.from);
  assert.equal(d.to, last.to);
});

test("diagnosticsToCm clamps line 0 / missing / NaN to line 1", () => {
  const doc = EditorState.create({ doc: "a\nb\nc" }).doc;
  const line1 = doc.line(1);
  for (const bad of [0, undefined, NaN, "not-a-number"]) {
    const [d] = diagnosticsToCm(doc, [{ line: bad, message: "m", severity: "error" }]);
    assert.equal(d.from, line1.from, `line=${bad} should clamp to line 1`);
    assert.equal(d.to, line1.to, `line=${bad} should clamp to line 1`);
  }
});

test("diagnosticsToCm passes 'warning' through, maps anything else to 'error'", () => {
  const doc = EditorState.create({ doc: "a\nb\nc" }).doc;
  const [warn] = diagnosticsToCm(doc, [{ line: 1, message: "w", severity: "warning" }]);
  assert.equal(warn.severity, "warning");
  const [other] = diagnosticsToCm(doc, [{ line: 1, message: "o", severity: "info" }]);
  assert.equal(other.severity, "error");
  const [missing] = diagnosticsToCm(doc, [{ line: 1, message: "n" }]);
  assert.equal(missing.severity, "error");
});

test("diagnosticsToCm returns [] for non-array input", () => {
  const doc = EditorState.create({ doc: "a" }).doc;
  assert.deepEqual(diagnosticsToCm(doc, null), []);
  assert.deepEqual(diagnosticsToCm(doc, undefined), []);
  assert.deepEqual(diagnosticsToCm(doc, "nope"), []);
});

function parsedState(doc) {
  const state = EditorState.create({ doc, extensions: [pfbRegexList()] });
  // pfbRegexList()'s outer grammar mounts the regexp grammar as an OVERLAY on each
  // Pattern node (parseMixed) -- ensureSyntaxTree forces the mixed-language parse to
  // completion (including the mount) before lezerErrorDiagnostics walks it, no
  // EditorView/DOM needed.
  ensureSyntaxTree(state, state.doc.length, 5000);
  return state;
}

test("lezerErrorLint returns a linter extension (shape-level)", () => {
  const ext = lezerErrorLint();
  assert.ok(typeof ext === "object" && ext !== null, "expected linter() to return an extension object");
});

test("lezerErrorDiagnostics flags unbalanced '(' with a non-empty range within the doc", () => {
  const doc = "(";
  const diags = lezerErrorDiagnostics(parsedState(doc));
  assert.ok(diags.length > 0, "expected at least one diagnostic for unbalanced '('");
  for (const d of diags) {
    assert.equal(d.severity, "error");
    assert.ok(d.to > d.from || d.from < doc.length, "expected a non-empty/visible range within the doc");
    assert.ok(d.from >= 0 && d.to <= doc.length, "expected the range to stay within the doc");
  }
});

// issue #3088: save-blocking editor flags are red. Description-length stays
// warning (yellow) on the server lint path. There is no known Python-valid
// pattern that trips the current grammars after #3063; '(' is a Lezer flag
// that Python also rejects, used here to pin colour + the Move action.
test("lezerErrorDiagnostics reports a parse failure as an error, never a warning", () => {
  for (const doc of ["(", "[", "(a"]) {
    for (const d of lezerErrorDiagnostics(parsedState(doc))) {
      assert.equal(d.severity, "error", `severity for ${JSON.stringify(doc)}`);
    }
  }
});

test("lezerErrorDiagnostics uses the owner-specified editor-flag message", () => {
  const [d] = lezerErrorDiagnostics(parsedState("("));
  assert.ok(d, "expected a diagnostic");
  assert.equal(
    d.message,
    PFB_REGEX_EDITOR_FLAG_MESSAGE,
    "gutter hover and click panel share this Diagnostic.message",
  );
  assert.doesNotMatch(
    d.message,
    /unbalanced|unclosed/i,
    "the walk only knows the grammar failed; it must not claim which construct is at fault",
  );
});

test("lezerErrorDiagnostics on '(' offers Move to Regex Exceptions when a moveAction is supplied", () => {
  const apply = () => {};
  const [d] = lezerErrorDiagnostics(parsedState("("), { moveAction: apply });
  assert.ok(d, "expected a diagnostic");
  assert.equal(d.severity, "error");
  assert.ok(Array.isArray(d.actions), "expected Diagnostic.actions");
  assert.equal(d.actions.length, 1);
  assert.equal(d.actions[0].name, PFB_REGEX_MOVE_ACTION_NAME);
  assert.equal(d.actions[0].apply, apply);
});

test("lezerErrorDiagnostics has no Move action unless a moveAction is supplied", () => {
  const [d] = lezerErrorDiagnostics(parsedState("("));
  assert.ok(d, "expected a diagnostic");
  assert.equal(d.actions, undefined);
});

test("diagnosticsToCm never attaches a Move action to server (Python) diagnostics", () => {
  const doc = EditorState.create({ doc: "(" }).doc;
  const [d] = diagnosticsToCm(doc, [{ line: 1, message: "Python regex compile error", severity: "error" }]);
  assert.equal(d.severity, "error");
  assert.equal(d.actions, undefined);
});

function mutableDocView(doc) {
  let state = EditorState.create({ doc });
  return {
    get state() {
      return state;
    },
    dispatch(spec) {
      state = state.update(spec).state;
    },
  };
}

test("moveRegexLine moves only the flagged line from main onto exceptions", () => {
  const main = mutableDocView("keep-a\nbad(\nkeep-b");
  const exceptions = mutableDocView("");
  moveRegexLine(main, main.state.doc.line(2).from, exceptions);
  assert.equal(main.state.doc.toString(), "keep-a\nkeep-b");
  assert.equal(exceptions.state.doc.toString(), "bad(");
});

test("moveRegexLine appends after an existing exception line", () => {
  const main = mutableDocView("bad(");
  const exceptions = mutableDocView("held");
  moveRegexLine(main, 0, exceptions);
  assert.equal(main.state.doc.toString(), "");
  assert.equal(exceptions.state.doc.toString(), "held\nbad(");
});

test("lezerErrorDiagnostics flags unbalanced '[' with a non-empty range within the doc", () => {
  const doc = "[";
  const diags = lezerErrorDiagnostics(parsedState(doc));
  assert.ok(diags.length > 0, "expected at least one error diagnostic for unbalanced '['");
});

test("lezerErrorDiagnostics: balanced '(a)' produces zero diagnostics", () => {
  const diags = lezerErrorDiagnostics(parsedState("(a)"));
  assert.equal(diags.length, 0, "balanced input must not produce error diagnostics");
});

test("lezerErrorDiagnostics: Python-valid ? before flag letters is clean (issue #3059)", () => {
  for (const doc of [
    "m?ad",
    "^(.+[-_.])??m?ad[sxv]?[0-9]*[-_.]",
    "^(.+[-_.])??adse?rv(er?|ice)?s?[0-9]*[-.]",
  ]) {
    const diags = lezerErrorDiagnostics(parsedState(doc));
    assert.equal(diags.length, 0, `${JSON.stringify(doc)} must not produce error diagnostics`);
  }
});

test("lezerErrorDiagnostics: trailing class dash is clean (Python re docs)", () => {
  assert.equal(lezerErrorDiagnostics(parsedState("[a-]")).length, 0);
});

test("lezerErrorDiagnostics finds an error mounted deep inside a later Pattern (overlay recursion)", () => {
  // "ok" (line 1, clean) then "(a)" (line 2, clean) then "(" (line 3, unbalanced) --
  // proves the walk recurses into the mounted overlay at a non-zero host offset, not
  // just when the erroring Pattern happens to start at doc position 0.
  const doc = "ok\n(a)\n(";
  const diags = lezerErrorDiagnostics(parsedState(doc));
  assert.equal(diags.length, 1);
  assert.equal(diags[0].to, doc.length, "expected the error to be anchored at doc end");
  assert.ok(diags[0].to > diags[0].from, "expected a non-empty range even at doc end");
});

test("serverLint returns an extension array containing a lint gutter + linter", () => {
  const ext = serverLint("/pfblockerng/pfblockerng_lint.php", "regex", null);
  assert.ok(Array.isArray(ext), "expected serverLint(...) to return an array of extensions");
  assert.equal(ext.length, 2, "expected [lintGutter(), linter(...)]");
});

test("serverLint's async source returns [] for an empty doc without touching XHR", async () => {
  const realXHR = globalThis.XMLHttpRequest;
  globalThis.XMLHttpRequest = function ThrowingXHR() {
    throw new Error("XMLHttpRequest must not be instantiated for an empty doc");
  };
  try {
    const source = serverLintSource("/pfblockerng/pfblockerng_lint.php", "regex", null);
    const fakeView = { state: { doc: EditorState.create({ doc: "" }).doc } };
    const result = await source(fakeView);
    assert.deepEqual(result, []);
  } finally {
    globalThis.XMLHttpRequest = realXHR;
  }
});

// A controllable fake XHR: open()/setRequestHeader() are no-ops, send() invokes
// `driver(this)` synchronously so each test controls exactly which handler fires with
// which status/responseText -- no real network, no timers.
function installFakeXHR(driver) {
  const realXHR = globalThis.XMLHttpRequest;
  globalThis.XMLHttpRequest = function FakeXHR() {
    this.open = () => {};
    this.setRequestHeader = () => {};
    this.send = () => driver(this);
  };
  return () => {
    globalThis.XMLHttpRequest = realXHR;
  };
}

test("serverLintSource resolves [] on a non-200 status", async () => {
  const restore = installFakeXHR((xhr) => {
    xhr.status = 500;
    xhr.onload();
  });
  try {
    const source = serverLintSource("/x", "regex", null);
    const fakeView = { state: { doc: EditorState.create({ doc: "x" }).doc } };
    assert.deepEqual(await source(fakeView), []);
  } finally {
    restore();
  }
});

test("serverLintSource resolves [] on a 200 with unparseable JSON", async () => {
  const restore = installFakeXHR((xhr) => {
    xhr.status = 200;
    xhr.responseText = "not json";
    xhr.onload();
  });
  try {
    const source = serverLintSource("/x", "regex", null);
    const fakeView = { state: { doc: EditorState.create({ doc: "x" }).doc } };
    assert.deepEqual(await source(fakeView), []);
  } finally {
    restore();
  }
});

test("serverLintSource resolves [] on xhr.onerror", async () => {
  const restore = installFakeXHR((xhr) => xhr.onerror());
  try {
    const source = serverLintSource("/x", "regex", null);
    const fakeView = { state: { doc: EditorState.create({ doc: "x" }).doc } };
    assert.deepEqual(await source(fakeView), []);
  } finally {
    restore();
  }
});

test("serverLintSource resolves [] on xhr.ontimeout", async () => {
  const restore = installFakeXHR((xhr) => xhr.ontimeout());
  try {
    const source = serverLintSource("/x", "regex", null);
    const fakeView = { state: { doc: EditorState.create({ doc: "x" }).doc } };
    assert.deepEqual(await source(fakeView), []);
  } finally {
    restore();
  }
});

test("serverLintSource resolves [] (not a rejected promise) when the doc has a lone surrogate", async () => {
  // encodeURIComponent() throws a URIError on a lone surrogate (e.g. "\uD800", no valid
  // UTF-16 pairing) -- buildLintBody() calls it while constructing the POST body. A
  // Promise executor's synchronous throw auto-rejects the promise; @codemirror/lint's
  // linter() must never see that rejection.
  const restore = installFakeXHR(() => {
    throw new Error("xhr.send must not be reached -- encodeURIComponent throws first");
  });
  try {
    const source = serverLintSource("/x", "regex", null);
    const fakeView = { state: { doc: EditorState.create({ doc: "\uD800" }).doc } };
    assert.deepEqual(await source(fakeView), []);
  } finally {
    restore();
  }
});
