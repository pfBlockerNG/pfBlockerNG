// Shared client-side lint wiring for both CM6 bundles (issue #1732 step 2): the advisory
// server round-trip (POST /pfblockerng/pfblockerng_lint.php) plus the offline Lezer
// bracket-error lint. Imported by cm-regex.js and cm-hooks.js, bundled into each --
// scripts/build-webassets.sh keeps the two bundles independently buildable.
//
// XHR, not fetch(): pfSense's csrf-magic.js patches XMLHttpRequest.prototype.open/send
// globally and PREPENDS the CSRF token to any STRING POST body. fetch() is unhooked
// (the token would never be attached) and a FormData body isn't a string (the prepend
// would corrupt it) -- so every POST here goes through a plain `new XMLHttpRequest()`
// with an application/x-www-form-urlencoded string body and sends no token itself; the
// prototype patch injects it.
//
// pfb_syntax_highlight=off keeps skipping ALL of this -- the bundles themselves are
// gated at asset emission (the <script> tag only renders inside the toggle's gate).
import { linter, lintGutter } from "@codemirror/lint";
import { syntaxTree } from "@codemirror/language";
import { NodeProp } from "@lezer/common";

export function buildLintBody(lang, content, extraParams) {
  let body = `lang=${encodeURIComponent(lang)}&content=${encodeURIComponent(content)}`;
  if (extraParams) {
    for (const key of Object.keys(extraParams)) {
      body += `&${key}=${encodeURIComponent(extraParams[key])}`;
    }
  }
  return body;
}

export function diagnosticsToCm(doc, diagnostics) {
  if (!Array.isArray(diagnostics)) return [];
  return diagnostics.map((d) => {
    let line = Number(d.line);
    if (!Number.isFinite(line) || line < 1) line = 1;
    else if (line > doc.lines) line = doc.lines;
    const l = doc.line(line);
    return {
      from: l.from,
      to: l.to,
      severity: d.severity === "warning" ? "warning" : "error",
      message: String(d.message),
    };
  });
}

// Exported separately from serverLint() so tests can exercise the async source function
// directly (a fake {state: {doc}} "view", no EditorView/DOM needed).
export function serverLintSource(url, lang, extraParams) {
  return (view) =>
    new Promise((resolve) => {
      const content = view.state.doc.toString();
      if (content === "") {
        resolve([]);
        return;
      }
      try {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", url, true);
        xhr.timeout = 10000;
        xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        const fail = () => resolve([]);
        xhr.onerror = fail;
        xhr.ontimeout = fail;
        xhr.onload = () => {
          if (xhr.status !== 200) {
            resolve([]);
            return;
          }
          try {
            const parsed = JSON.parse(xhr.responseText);
            resolve(diagnosticsToCm(view.state.doc, parsed.diagnostics));
          } catch {
            resolve([]);
          }
        };
        xhr.send(buildLintBody(lang, content, typeof extraParams === "function" ? extraParams() : extraParams));
      } catch {
        // e.g. encodeURIComponent() throwing on a lone surrogate in the doc -- resolve
        // [] rather than reject the linter's promise (a Promise executor's synchronous
        // throw auto-rejects, which @codemirror/lint's linter() must never see).
        resolve([]);
      }
    });
}

export function serverLint(url, lang, extraParams) {
  return [lintGutter(), linter(serverLintSource(url, lang, extraParams))];
}

// Offline bracket lint (issue #1732 scope C): walks the Lezer error nodes the
// pfb-regex-list grammar (and, mounted inside it, the regexp grammar re-parsing each
// Pattern's contents) produces for unbalanced/unclosed "(" or "[" -- runs instantly,
// stacks with serverLint(), and still works while the endpoint is unreachable.
//
// Plain tree.cursor().iterate() (firstChild/nextSibling walking) never descends into a
// parseMixed() overlay mount -- @lezer/common's IterMode.IgnoreOverlays doc comment says
// so explicitly ("only applies in enter()-style methods"), and it's been verified against
// the installed API: pfbRegexList()'s outer grammar mounts the regexp grammar as an
// OVERLAY on each Pattern node (lezer-pfb-regex-list/src/index.js's parseMixed wrap), so
// the "(" / "[" error nodes the inner grammar produces live only in that mount -- a plain
// iterate() over the outer tree sees Pattern as a leaf and never finds them. This walk
// recurses into every NodeProp.mounted tree it meets (overlay coordinates are relative to
// the host node's own start, confirmed empirically), so it still sees error nodes at any
// mount depth.
// issue #3088: save-blocking editor flags are red. Same Diagnostic.message for
// gutter hover and the click panel. Python remains the compile gate.
export const PFB_REGEX_EDITOR_FLAG_MESSAGE =
  "Regex error: this editor could not parse this line. If you believe it is a valid Python regular expression, you can move it to the Regex Exceptions list. Python still validates it when DNSBL compiles; a pattern Python rejects will not load.";
export const PFB_REGEX_MOVE_ACTION_NAME = "Move to Regex Exceptions";

export function lezerErrorDiagnostics(state, options = {}) {
  const diagnostics = [];
  const docLength = state.doc.length;
  const severity = options.severity ?? "error";
  const message = PFB_REGEX_EDITOR_FLAG_MESSAGE;
  const moveAction = options.moveAction;

  function walk(tree, offset) {
    tree.iterate({
      enter(node) {
        if (node.type.isError) {
          let from = offset + node.from;
          let to = Math.max(offset + node.to, Math.min(from + 1, docLength));
          // An unclosed group/class hitting EOF puts the error node AT doc end
          // (from === docLength) -- there's no character past the end to extend `to`
          // into, so the forward clamp above still leaves a zero-width range. Extend
          // backward onto the last character instead: still "a visible range within the
          // doc", per the design's zero-width-at-doc-end requirement, just anchored on
          // the other side.
          if (to <= from && from > 0) from = from - 1;
          const diagnostic = { from, to, severity, message };
          if (moveAction) {
            diagnostic.actions = [{ name: PFB_REGEX_MOVE_ACTION_NAME, apply: moveAction }];
          }
          diagnostics.push(diagnostic);
        }
        const mounted = node.tree && node.tree.prop(NodeProp.mounted);
        if (mounted) walk(mounted.tree, offset + node.from);
      },
    });
  }

  walk(syntaxTree(state), 0);
  return diagnostics;
}

export function lezerErrorLint(options = {}) {
  return linter((view) => {
    const moveAction = options.getExceptionsView
      ? (v, from) => {
          const exceptionsView = options.getExceptionsView();
          if (exceptionsView) moveRegexLine(v, from, exceptionsView);
        }
      : undefined;
    return lezerErrorDiagnostics(view.state, {
      severity: options.severity ?? "error",
      moveAction,
    });
  });
}

export function moveRegexLine(mainView, from, exceptionsView) {
  const line = mainView.state.doc.lineAt(from);
  const text = line.text;
  let delFrom = line.from;
  let delTo = line.to;
  if (line.number < mainView.state.doc.lines) {
    delTo += 1;
  } else if (line.from > 0) {
    delFrom -= 1;
  }
  mainView.dispatch({ changes: { from: delFrom, to: delTo } });
  const exDoc = exceptionsView.state.doc;
  let insert = text;
  if (exDoc.length > 0 && exDoc.line(exDoc.lines).text !== "") {
    insert = "\n" + text;
  }
  exceptionsView.dispatch({ changes: { from: exDoc.length, insert } });
}

export function flaggedLineNumbers(state, diagnostics) {
  const lines = new Set();
  for (const d of diagnostics) {
    lines.add(state.doc.lineAt(d.from).number);
  }
  return [...lines].sort((a, b) => a - b).join(",");
}
