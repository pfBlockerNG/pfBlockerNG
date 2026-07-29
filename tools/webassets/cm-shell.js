// Shared editor shell for issue #1875 -- the piece the per-field bundles share; language
// layer supplied per entry. Extracted out of cm-regex.js/cm-hooks.js, which used to
// duplicate this whole scaffold (owner decision to keep the BUNDLES separate still holds --
// only the SOURCE dedups, so a fix like #1869's lineNumbers gutter lives once).
import { EditorState } from "@codemirror/state";
import { EditorView, keymap, drawSelection, lineNumbers } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { pfbHighlightStyle } from "./pfb-highlight-style.js";

// Derives an accessible name for the replacement editor from the textarea it's replacing --
// its own aria-label, else the text of a <label> associated via `for`/wrapping (the DOM
// gives us that for free through HTMLInputElement-alike `.labels`), else a generic fallback.
// The textarea itself is display:none below, which drops it (and any aria-label it carried)
// from the accessibility tree entirely, so the replacement view needs its own name.
export function accessibleNameFor(textarea) {
  const own = textarea.getAttribute("aria-label");
  if (own && own.trim()) return own.trim();
  const label = textarea.labels && textarea.labels[0];
  if (label && label.textContent && label.textContent.trim()) return label.textContent.trim();
  return "Code editor";
}

// Replaces `textarea` with a CM6 EditorView wired for `language` (a LanguageSupport or
// Language extension), plus any `extraExtensions` (lint wiring) appended after it.
export function mountTextarea(textarea, language, extraExtensions = []) {
  const rows = parseInt(textarea.getAttribute("rows"), 10);
  const height = Number.isFinite(rows) && rows > 0 ? `${rows * 1.4}em` : "20em";
  const ariaLabel = accessibleNameFor(textarea);

  const extensions = [
    history(),
    drawSelection(),
    // issue #1869: the lint gutter alone rendered an empty strip down the left edge, so a
    // "line N: ..." diagnostic from the save-time validator had no number to point at and
    // the admin counted rows by hand. Listed BEFORE the lint extensions so the numbers sit
    // leftmost and the lint marker keeps its own column beside them.
    lineNumbers(),
    keymap.of([...defaultKeymap, ...historyKeymap]),
    syntaxHighlighting(defaultHighlightStyle),
    syntaxHighlighting(pfbHighlightStyle),
    language,
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
    ...extraExtensions,
  ];

  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions,
    }),
  });

  view.dom.style.height = height;
  textarea.insertAdjacentElement("beforebegin", view.dom);
  // The textarea stays in the form (its name/value are the POST source) but is hidden --
  // updateListener above keeps its value synced on every doc change, so the native form
  // submit still posts the CURRENT editor content, not just the value as of page load.
  textarea.style.display = "none";

  // Clicking the <label> that used to focus the (now-hidden) textarea should focus the
  // replacement view instead, same as a native label->control association would.
  const label = textarea.labels && textarea.labels[0];
  if (label) {
    label.addEventListener("click", () => view.focus());
  }

  return view;
}
