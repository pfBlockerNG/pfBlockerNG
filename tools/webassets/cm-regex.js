// CM6 bundle entry for the pfBlockerNG regex-list editor (issue #1669 slice B). Bundled by
// scripts/build-webassets.sh (esbuild --global-name=pfbCM) into
// src/usr/local/www/pfblockerng/vendor/codemirror/cm-regex.min.js. Keep this file tiny --
// slice C pins its literal source in a wiring test.
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { pfbRegexList } from "./lezer-pfb-regex-list/src/index.js";

// Server-side validation (pfbng_text_area_decode(), preg_match/re.compile) stays
// authoritative -- this is a highlighter, not a validator.
export function fromTextarea(textarea) {
  const rows = parseInt(textarea.getAttribute("rows"), 10);
  const height = Number.isFinite(rows) && rows > 0 ? `${rows * 1.4}em` : "20em";

  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        history(),
        drawSelection(),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        syntaxHighlighting(defaultHighlightStyle),
        pfbRegexList(),
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

  return view;
}
