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
  // issue #3059 fused the leading "(" into these tokens; tag them so the
  // opener is not unstyled next to a styled ")".
  "NonCapMarker NamedOpenMarker LookaheadMarker NegLookaheadMarker LookbehindMarker NegLookbehindMarker AtomicMarker ConditionalMarker": t.paren,
  // Named ClassOpen* / ClassClose (issue #1681 openers; ClassClose is the "]").
  "ClassOpen ClassOpenNeg ClassOpenLit ClassOpenNegLit ClassClose": t.squareBracket,
  GroupName: t.labelName,
  FlagsMarker: t.modifier,
  CommentGroup: t.comment,
  "Backreference GroupRefMarker": t.variableName,
  // Not in the brief's fixed table: Dot ("." -- matches any char, same
  // category as a character class) and ClassLiteral (the in-class literal
  // run -- distinct node from Literal because its excluded-char set
  // differs; see src/regexp.grammar). Literal itself carries no tag.
  Dot: t.atom,
});
