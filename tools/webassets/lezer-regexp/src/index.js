// Public entry point for @pfblockerng/lezer-regexp (issue #1669 slice A).
// `parser` is generated (src/parser.js -- gitignored, `npm run generate`)
// and pre-configured with the highlight styleTags so consumers (the future
// CodeMirror 6 language package, slice B) get highlighting for free.
import { parser as rawParser } from "./parser.js";
import { regexpHighlighting } from "./highlight.js";

export const parser = rawParser.configure({
  props: [regexpHighlighting],
});
