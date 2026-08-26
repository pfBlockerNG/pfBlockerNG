// CM6 bundle entry for the pfBlockerNG regex-list editor (issue #1669 slice B). Bundled by
// scripts/build-webassets.sh (esbuild --global-name=pfbCM) into
// src/usr/local/www/pfblockerng/vendor/codemirror/cm-regex.min.js. Keep this file tiny --
// test/cm-regex-source.test.js and tests/php/DnsblRegexHighlightWiringTest.php pin the
// real call sites (textarea sync, DOM wiring, aria-label) this file exercises.
import { pfbRegexList, pfbPlainList } from "./lezer-pfb-regex-list/src/index.js";
import { serverLint, lezerErrorLint } from "./cm-lint.js";
import { mountTextarea } from "./cm-shell.js";

// Server-side validation (pfb_text_area_decode(), preg_match/re.compile) stays
// authoritative -- this is a highlighter, not a validator.

export function fromTextarea(textarea, opts) {
  const extraExtensions = [];
  // issue #1732 step 2: advisory server lint (POST pfblockerng_lint.php) + the offline
  // Lezer bracket lint, both opt-in via opts.lintUrl -- no opts means no lintUrl means
  // byte-identical behaviour to before this slice.
  if (opts && opts.lintUrl) {
    extraExtensions.push(...serverLint(opts.lintUrl, "regex", opts.lintExtraParams), lezerErrorLint());
  }
  return mountTextarea(textarea, pfbRegexList(), extraExtensions);
}

// issue #1875 -- plain "one entry per line, optional # comment" list fields (no regex
// overlay, no lint wiring).
export function fromTextareaList(textarea) {
  return mountTextarea(textarea, pfbPlainList(), []);
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
