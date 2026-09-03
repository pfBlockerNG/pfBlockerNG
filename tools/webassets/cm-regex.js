// CM6 bundle entry for the pfBlockerNG regex-list editor (issue #1669 slice B). Bundled by
// scripts/build-webassets.sh (esbuild --global-name=pfbCM) into
// src/usr/local/www/pfblockerng/vendor/codemirror/cm-regex.min.js. Keep this file tiny --
// test/cm-regex-source.test.js and tests/php/DnsblRegexHighlightWiringTest.php pin the
// real call sites (textarea sync, DOM wiring, aria-label) this file exercises.
import { EditorView } from "@codemirror/view";
import { pfbRegexList, pfbPlainList } from "./lezer-pfb-regex-list/src/index.js";
import {
  serverLint,
  lezerErrorLint,
  lezerErrorDiagnostics,
  flaggedLineNumbers,
} from "./cm-lint.js";
import { mountTextarea } from "./cm-shell.js";

// Server-side validation (pfb_text_area_decode(), preg_match/re.compile) stays
// authoritative -- this is a highlighter, not a validator.

function ensureFlaggedInput(textarea) {
  const name = `${textarea.name}_editor_flags`;
  const form = textarea.form;
  let el = form ? form.elements.namedItem(name) : document.querySelector(`[name="${CSS.escape(name)}"]`);
  if (el && "length" in el && !("value" in el)) el = el[0];
  if (!el) {
    el = document.createElement("input");
    el.type = "hidden";
    el.name = name;
    textarea.insertAdjacentElement("afterend", el);
  }
  return el;
}

function syncFlaggedInput(textarea, state, lintOptions) {
  const input = ensureFlaggedInput(textarea);
  input.value = flaggedLineNumbers(state, lezerErrorDiagnostics(state, lintOptions));
}

export function fromTextarea(textarea, opts) {
  const extraExtensions = [];
  // issue #1732 step 2: advisory server lint (POST pfblockerng_lint.php) + the offline
  // Lezer bracket lint, both opt-in via opts.lintUrl -- no opts means no lintUrl means
  // byte-identical behaviour to before this slice.
  if (opts && opts.lintUrl) {
    const lintOptions = {
      severity: opts.lezerSeverity ?? "error",
      getExceptionsView: opts.getExceptionsView,
    };
    extraExtensions.push(
      ...serverLint(opts.lintUrl, "regex", opts.lintExtraParams),
      lezerErrorLint(lintOptions),
      EditorView.updateListener.of((update) => {
        if (update.docChanged) syncFlaggedInput(textarea, update.state, lintOptions);
      }),
    );
  }
  const view = mountTextarea(textarea, pfbRegexList(), extraExtensions);
  if (opts && opts.lintUrl) {
    syncFlaggedInput(textarea, view.state, {
      severity: opts.lezerSeverity ?? "error",
      getExceptionsView: opts.getExceptionsView,
    });
  }
  return view;
}

// issue #1875 -- plain "one entry per line, optional # comment" list fields (no regex
// overlay, no lint wiring).
export function fromTextareaList(textarea) {
  return mountTextarea(textarea, pfbPlainList(), []);
}

export const PFB_REGEX_EXCEPTION_LIST_ID = "pfb_regex_exception_list";

export function mountRegexListAndExceptions(lintUrl, lintExtraParams) {
  const exceptions = document.getElementById(PFB_REGEX_EXCEPTION_LIST_ID);
  let exceptionsView = null;
  if (exceptions) {
    exceptionsView = fromTextarea(exceptions, {
      lintUrl,
      lintExtraParams,
      lezerSeverity: "warning",
    });
  }
  const main = document.getElementById("pfb_regex_list");
  if (main) {
    fromTextarea(main, {
      lintUrl,
      lintExtraParams,
      getExceptionsView: () => exceptionsView,
    });
  }
  return { main, exceptionsView };
}

// issue #1875 -- one call per page mounts every plain-list field; missing ids skipped so
// pages share one helper.
export function mountLists(ids) {
  const views = [];
  for (const id of ids) {
    const textarea = document.getElementById(id);
    if (!textarea) continue;
    views.push(fromTextareaList(textarea));
  }
  return views;
}
