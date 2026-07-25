// CM6 bundle entry for the pfBlockerNG regex-list editor (issue #1669 slice B). Bundled by
// scripts/build-webassets.sh (esbuild --global-name=pfbCM) into
// src/usr/local/www/pfblockerng/vendor/codemirror/cm-regex.min.js. Keep this file tiny --
// test/cm-regex-source.test.js and tests/php/DnsblRegexHighlightWiringTest.php pin the
// real call sites (textarea sync, DOM wiring, aria-label) this file exercises.
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { pfbRegexList } from "./lezer-pfb-regex-list/src/index.js";
import { pfbHighlightStyle } from "./pfb-highlight-style.js";

// Server-side validation (pfb_text_area_decode(), preg_match/re.compile) stays
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

export function fromTextarea(textarea) {
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
        pfbRegexList(),
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
  // updateListener above keeps its value synced on every doc change, so any submit path
  // (including a plain HTML form submit with JS otherwise disabled) still sees the
  // CURRENT editor content, not just the value as of page load.
  textarea.style.display = "none";

  // Clicking the <label> that used to focus the (now-hidden) textarea should focus the
  // replacement view instead, same as a native label->control association would.
  const label = textarea.labels && textarea.labels[0];
  if (label) {
    label.addEventListener("click", () => view.focus());
  }

  return view;
}
