// CM6 bundle entry for the pfBlockerNG hook-script editor (issue #1669).
// Bundled by scripts/build-webassets.sh (esbuild --global-name=pfbHooksCM) into
// src/usr/local/www/pfblockerng/vendor/codemirror/cm-hooks.min.js. Kept a SEPARATE
// bundle from cm-regex.min.js (owner decision: keep the regex-list bundle small) --
// duplicates the small CM6 scaffold (history/drawSelection/keymap/aria-label helper)
// rather than sharing a module with cm-regex.js, so the two stay independently
// buildable/testable. test/cm-hooks-source.test.js and
// tests/php/EditHooksSyntaxHighlightWiringTest.php pin the real call sites (textarea
// sync, DOM wiring, aria-label, language selection) this file exercises.
//
// Python + shell modes ONLY (ADR-12 addendum: the owner resolved the issue #1669
// language fork against offering PHP as a hook-editor mode). Mode follows the hook
// file's extension, decided server-side by pfb_hook_editor_lang_for() and passed in
// as the $lang argument to fromTextarea() -- 'py' selects Python, anything else
// (including 'sh') falls back to the shell StreamLanguage.
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { StreamLanguage, syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { pythonLanguage } from "@codemirror/lang-python";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { pfbHighlightStyle } from "./pfb-highlight-style.js";

// No official @codemirror/lang-shell package exists -- shell is only offered as a
// legacy CodeMirror-5-style StreamParser (@codemirror/legacy-modes), wrapped here via
// StreamLanguage.define() into a real CM6 Language (issue #1669 owner-confirmed
// mechanism).
const shellLanguage = StreamLanguage.define(shell);

// Server-side validation (pfb_hook_script_valid(), the file-write path) stays
// authoritative -- this is a highlighter, not a validator.

// Derives an accessible name for the replacement editor from the textarea it's replacing --
// its own aria-label, else the text of a <label> associated via `for`/wrapping (the DOM
// gives us that for free through HTMLInputElement-alike `.labels`), else a generic fallback.
// The textarea itself is display:none below, which drops it (and any aria-label it carried)
// from the accessibility tree entirely, so the replacement view needs its own name.
function accessibleNameFor(textarea) {
  const own = textarea.getAttribute("aria-label");
  if (own && own.trim()) return own.trim();
  const label = textarea.labels && textarea.labels[0];
  if (label && label.textContent && label.textContent.trim()) return label.textContent.trim();
  return "Code editor";
}

// Mirrors pfb_hook_editor_lang_for()'s 'py'-or-'sh' contract -- 'py' is the only value
// that selects Python; every other value (including an absent argument) is shell.
function languageFor(lang) {
  return lang === "py" ? pythonLanguage : shellLanguage;
}

export function fromTextarea(textarea, lang) {
  const rows = parseInt(textarea.getAttribute("rows"), 10);
  const height = Number.isFinite(rows) && rows > 0 ? `${rows * 1.4}em` : "20em";
  const ariaLabel = accessibleNameFor(textarea);

  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        history(),
        drawSelection(),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        syntaxHighlighting(defaultHighlightStyle),
        syntaxHighlighting(pfbHighlightStyle),
        languageFor(lang),
        EditorView.contentAttributes.of({ "aria-label": ariaLabel }),
        EditorView.theme({
          "&": { border: "1px solid #b7b7b7", backgroundColor: "#fff" },
          ".cm-scroller": { fontFamily: "monospace", overflow: "auto" },
          ".cm-content": { whiteSpace: "pre" },
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            textarea.value = update.state.doc.toString();
          }
        }),
      ],
    }),
  });

  view.dom.style.height = height;
  textarea.insertAdjacentElement("beforebegin", view.dom);
  // The textarea stays in the form (its name/value are the POST source) but is hidden --
  // updateListener above keeps its value synced on every doc change, so the browser's own
  // native form submit (no submit-time JS of ours needed) still posts the CURRENT editor
  // content, not just the value as of page load. (This file itself requires JS to run at
  // all -- CodeMirror has no no-JS fallback -- so "submits even with JS disabled" was never
  // an accurate framing; the point is only that no separate onsubmit handler is needed.)
  textarea.style.display = "none";

  // Clicking the <label> that used to focus the (now-hidden) textarea should focus the
  // replacement view instead, same as a native label->control association would.
  const label = textarea.labels && textarea.labels[0];
  if (label) {
    label.addEventListener("click", () => view.focus());
  }

  return view;
}
