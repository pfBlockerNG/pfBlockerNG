// Supplemental HighlightStyle for the pfBlockerNG regex-list editor (issue #1669 PR #1680
// review fix). @codemirror/language's defaultHighlightStyle has NO rule for t.operator (so
// t.logicOperator, its child tag, is unstyled too), t.paren, t.squareBracket, or plain
// t.variableName (only its definition()/local() modifiers are styled) -- probed against
// node_modules/@lezer/highlight/dist/index.js's tag hierarchy and
// node_modules/@codemirror/language/dist/index.js's defaultHighlightStyle table. Those four
// tags are exactly what lezer-regexp/src/highlight.js assigns to quantifiers (`*`, `+`,
// `?`, `{m,n}`), the alternation operator (`|`), group/class delimiters (`()`, `[]` --
// the class OPENER is a named ClassOpen* node, mapped explicitly, issue #1681), and
// backreferences (`\1`, `(?P=name)`) -- so all of them render unstyled with only
// defaultHighlightStyle installed. cm-regex.js installs this ALONGSIDE (not instead of)
// defaultHighlightStyle via a second `syntaxHighlighting()` call.
import { HighlightStyle } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";

export const pfbHighlightStyle = HighlightStyle.define([
  // Quantifiers (t.operator) and `|` (t.logicOperator, a child of t.operator -- one rule
  // covers both, same inheritance defaultHighlightStyle relies on elsewhere).
  { tag: t.operator, color: "#a35a00" },
  // Group parens and character-class brackets -- one shared "delimiter" color.
  { tag: [t.paren, t.squareBracket], color: "#7a3e9d" },
  // Backreferences (Backreference / GroupRefMarker) -- same family as
  // defaultHighlightStyle's definition(variableName)/local(variableName) blues.
  { tag: t.variableName, color: "#1a56b0" },
]);
