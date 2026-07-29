// Public entry point for @pfblockerng/lezer-pfb-regex-list (issue #1669 slice B).
// `parser` is generated (src/parser.js -- gitignored, `npm run generate`), configured
// with this package's own styleTags (Comment) but WITHOUT the parseMixed wrap -- kept
// bare so test/cases.txt (fileTests) pins pure Pattern/Comment splitting without also
// having to pin the mounted regex grammar's tree shape in every case. `pfbRegexList()`
// is the CM6-facing export: same parser, wrapped with parseMixed so a Pattern node's
// contents get re-parsed by @pfblockerng/lezer-regexp's Python-re grammar (slice A).
//
// parseMixed lives in "@lezer/common", not "@codemirror/language" -- probed against the
// pinned package.json "exports" maps (@codemirror/language re-exports the CM6-specific
// Language/LRLanguage/LanguageSupport wrappers only, not the lower-level @lezer/common
// primitive).
import { parser as rawParser } from "./parser.js";
import { pfbRegexListHighlighting } from "./highlight.js";
import { parser as regexpParser } from "../../lezer-regexp/src/index.js";
import { parseMixed } from "@lezer/common";
import { LRLanguage, LanguageSupport } from "@codemirror/language";

export const parser = rawParser.configure({
  props: [pfbRegexListHighlighting],
});

export const mixedParser = parser.configure({
  // `overlay: [{from, to}]` (the whole Pattern span) is required to keep the Pattern node
  // itself in the tree as a wrapper around the mounted RegExp subtree -- two things
  // probed this session, both diverging from the brief's literal form:
  //  - Omitting `overlay` entirely mounts the inner parse as a NON-overlay replacement
  //    per @lezer/common's NestedParse doc comment ("the entire node is parsed with this
  //    parser, and it is mounted as a non-overlay node, REPLACING its host node in tree
  //    iteration"), which silently drops the Pattern node from every tree walk.
  //  - `overlay: () => true` (function form) is documented as being invoked once per
  //    DESCENDANT node of the target to decide which descendants' ranges to include --
  //    Pattern is a single leaf token with no descendants in the bare grammar, so the
  //    callback is never invoked and the overlay ends up empty (verified via
  //    `tree.resolveInner()` never reaching past Pattern).
  wrap: parseMixed((node) => (node.name === "Pattern" ? { parser: regexpParser, overlay: [{ from: node.from, to: node.to }] } : null)),
});

export const pfbRegexListLanguage = LRLanguage.define({ parser: mixedParser });

export function pfbRegexList() {
  return new LanguageSupport(pfbRegexListLanguage);
}

// issue #1875 -- plain "one entry per line, optional # comment" lists (domains/TLDs/IPs)
// reuse the outer grammar WITHOUT the parseMixed regex overlay.
export const pfbPlainListLanguage = LRLanguage.define({ parser });

export function pfbPlainList() {
  return new LanguageSupport(pfbPlainListLanguage);
}
