// CM6 bundle entry for the pfBlockerNG hook-script editor (issue #1669).
// Bundled by scripts/build-webassets.sh (esbuild --global-name=pfbHooksCM) into
// src/usr/local/www/pfblockerng/vendor/codemirror/cm-hooks.min.js. Kept a SEPARATE
// bundle from cm-regex.min.js (owner decision: keep the regex-list bundle small) --
// shares the CM6 scaffold with cm-regex.js via cm-shell.js (issue #1875) while the two
// stay independently buildable/testable bundles. test/cm-hooks-source.test.js and
// tests/php/EditHooksSyntaxHighlightWiringTest.php pin the real call sites (textarea
// sync, DOM wiring, aria-label, language selection) this file exercises.
//
// Python + shell modes ONLY (ADR-12 addendum: the owner resolved the issue #1669
// language fork against offering PHP as a hook-editor mode). Mode follows the hook
// file's extension, decided server-side by pfb_hook_editor_lang_for() and passed in
// as the $lang argument to fromTextarea() -- 'py' selects Python, anything else
// (including 'sh') falls back to the shell StreamLanguage.
import { StreamLanguage } from "@codemirror/language";
import { pythonLanguage } from "@codemirror/lang-python";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { serverLint } from "./cm-lint.js";
import { mountTextarea } from "./cm-shell.js";

// No official @codemirror/lang-shell package exists -- shell is only offered as a
// legacy CodeMirror-5-style StreamParser (@codemirror/legacy-modes), wrapped here via
// StreamLanguage.define() into a real CM6 Language (issue #1669 owner-confirmed
// mechanism).
const shellLanguage = StreamLanguage.define(shell);

// Server-side validation (pfb_hook_script_valid(), the file-write path) stays
// authoritative -- this is a highlighter, not a validator.

// Mirrors pfb_hook_editor_lang_for()'s 'py'-or-'sh' contract -- 'py' is the only value
// that selects Python; every other value (including an absent argument) is shell.
function languageFor(lang) {
  return lang === "py" ? pythonLanguage : shellLanguage;
}

export function fromTextarea(textarea, lang, opts) {
  const extraExtensions = [];
  // issue #1732 step 2: advisory server lint (POST pfblockerng_lint.php), opt-in via
  // opts.lintUrl -- no opts means no lintUrl means byte-identical behaviour to before
  // this slice. No bracket lint here: shell mode is a StreamLanguage with no meaningful
  // Lezer error nodes (scope C is the regex editor only, see cm-regex.js).
  if (opts && opts.lintUrl) {
    extraExtensions.push(...serverLint(opts.lintUrl, lang === "py" ? "py" : "sh", opts.lintExtraParams));
  }
  return mountTextarea(textarea, languageFor(lang), extraExtensions);
}
