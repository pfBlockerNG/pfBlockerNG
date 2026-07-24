// styleTags mapping for the Python-re Lezer grammar (issue #1669 slice A).
// Semantic mapping fixed by the brief; node-name deltas (Dot, ClassLiteral)
// noted alongside their entries -- see the handoff for the full rationale.
import { styleTags, tags as t } from "@lezer/highlight";

export const regexpHighlighting = styleTags({
  Escape: t.escape,
  Anchor: t.modifier,
  Quantifier: t.operator,
  "|": t.logicOperator,
  "( )": t.paren,
  "[ ]": t.squareBracket,
  GroupName: t.labelName,
  // No separate "Flags" leaf (delta -- see handoff): the flag letters are
  // fused into the FlagsMarker token together with the leading "?" to keep
  // the group-open markers a single, conflict-free tokenizer family.
  FlagsMarker: t.modifier,
  CommentGroup: t.comment,
  "Backreference GroupRefMarker": t.variableName,
  // Not in the brief's fixed table: Dot ("." -- matches any char, same
  // category as a character class) and ClassLiteral (the in-class literal
  // run -- distinct node from Literal because its excluded-char set
  // differs; see src/regexp.grammar). Literal itself carries no tag.
  Dot: t.atom,
});
