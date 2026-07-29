// node:test runner for the pfb regex-list outer grammar (issue #1669 slice B). Mirrors
// lezer-regexp/test/parse.test.js's harness. Cases live in test/cases.txt (fileTests
// format) and exercise the BARE parser (`parser`, no parseMixed wrap) -- pure
// Pattern/Comment line splitting, independent of the mounted regex grammar's tree shape.
//
// fileTests' input capture trims leading/trailing whitespace on the whole case body
// (@lezer/generator/dist/test.js `m[2].trim()`), so a case whose entire content is
// whitespace (a bare trailing newline, a whitespace-only line) silently collapses to the
// empty-string case and can't be pinned that way -- those get dedicated node:test cases
// below instead, calling `parser.parse()` directly on an exact string.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileTests } from "@lezer/generator/test";
import { highlightTree } from "@lezer/highlight";
import { EditorState } from "@codemirror/state";
import { syntaxTree, defaultHighlightStyle } from "@codemirror/language";
import { parser, mixedParser, pfbRegexListLanguage, pfbRegexList } from "../src/index.js";
import { pfbHighlightStyle } from "../../pfb-highlight-style.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const casesPath = path.join(__dirname, "cases.txt");
const casesText = readFileSync(casesPath, "utf8");

const cases = fileTests(casesText, "cases.txt");

test("cases.txt has the expected minimum coverage", () => {
  assert.ok(
    cases.length >= 8,
    `expected >= 8 cases, got ${cases.length} -- issue #1669 slice B coverage list requires >= 8 rows`,
  );
});

for (const testCase of cases) {
  test(testCase.name, () => {
    testCase.run(parser);
  });
}

function names(tree) {
  const out = [];
  tree.iterate({
    enter(node) {
      out.push(node.name);
    },
  });
  return out;
}

// Dedicated cases fileTests' trim() can't express (see file header).
test("dedicated: a single trailing newline adds no spurious empty final line", () => {
  assert.deepEqual(names(parser.parse("foo\n")), ["RegexList", "Pattern"]);
});

test("dedicated: two trailing newlines add exactly one empty final line (no node)", () => {
  assert.deepEqual(names(parser.parse("foo\n\n")), ["RegexList", "Pattern"]);
});

test("dedicated: a whitespace-only line with no '#' is a Pattern, not a Comment", () => {
  assert.deepEqual(names(parser.parse("   ")), ["RegexList", "Pattern"]);
});

// issue #1867: WHERE the split lands, not just that one happened. cases.txt compares
// tree TOPOLOGY only, so "a\#b#desc" reads as Pattern,Comment under both the old
// first-hash-wins rule and the new unescaped-hash rule -- the topology is identical and
// only the boundary moves. Without a positional assertion nothing in the suite would
// notice the split regressing to the first hash on a line that has a later real one.
test("dedicated: the split lands at the first UNESCAPED '#', not the first '#'", () => {
  const input = "a\\#b#desc";
  const tree = parser.parse(input);
  let commentFrom = null;
  tree.iterate({
    enter(node) {
      if (node.name === "Comment") commentFrom = node.from;
    },
  });
  // "a\#b" is the pattern (4 chars), so the Comment starts at index 4 -- the SECOND
  // hash. Under the old rule it would start at index 1.
  assert.equal(commentFrom, 4, `expected the Comment to start at the unescaped '#' in ${JSON.stringify(input)}`);
  assert.equal(input.slice(commentFrom), "#desc");
});

test("dedicated: an escaped hash with no later marker yields no Comment at all", () => {
  // The other direction: nothing after the escape means the whole line is Pattern.
  // Pairs with the case above so neither "always split early" nor "never split"
  // could satisfy both.
  const names_ = names(parser.parse("a\\#b"));
  assert.deepEqual(names_, ["RegexList", "Pattern"]);
});

// parseMixed nesting: the wrapped parser re-parses a Pattern node's contents with
// @pfblockerng/lezer-regexp's Python-re grammar (slice A), mounted as an OVERLAY (see
// index.js's comment on `overlay: [{from, to}]` -- required, and NOT the brief's literal
// no-overlay form, to keep the Pattern node itself in the tree). Overlay mounts are
// invisible to a plain `tree.iterate()` walk (@lezer/common: cursor-style iteration only
// splices in NON-overlay mounts; overlays need position-based `resolveInner()`/`enter()`
// lookups, same as `@lezer/highlight`'s own mount-following code) -- probed this session,
// see index.js and the handoff. `chainAt()` below mirrors that lookup.
function chainAt(tree, pos) {
  const chain = [];
  let node = tree.resolveInner(pos, 1);
  while (node) {
    chain.push(node.name);
    node = node.parent;
  }
  return chain;
}

test("mixed-nesting: mixedParser nests a RegExp subtree inside Pattern (position-resolved)", () => {
  const input = "ab[c-f]#trailing comment";
  const tree = mixedParser.parse(input);
  // Position 3 sits inside "[c-f]" -- resolveInner must walk Literal/CharacterClass-class
  // descendants, through RegExp, through Pattern, up to RegexList.
  const chain = chainAt(tree, 3);
  assert.deepEqual(chain, ["ClassLiteral", "ClassRange", "CharacterClass", "RegExp", "Pattern", "RegexList"]);
  // A position inside the trailing Comment must NOT resolve through Pattern/RegExp at all.
  const commentChain = chainAt(tree, 10);
  assert.deepEqual(commentChain, ["Comment", "RegexList"]);
});

test("mixed-nesting: pfbRegexList() wires the nested grammar through a real CM6 EditorState", () => {
  const state = EditorState.create({
    doc: "^foo\\d+$#a real DNSBL regex pattern\nbareword\n",
    extensions: [pfbRegexList()],
  });
  const tree = syntaxTree(state);
  // Position 4 sits inside "\d" (the Escape) on line 1; position 40 sits inside the
  // bareword Pattern-only second line, which has no "#" and must resolve to a bare
  // RegExp/Literal with no Comment ancestor.
  assert.deepEqual(chainAt(tree, 4), ["Escape", "RegExp", "Pattern", "RegexList"]);
  const line2Pos = state.doc.line(2).from + 2;
  assert.deepEqual(chainAt(tree, line2Pos), ["Literal", "RegExp", "Pattern", "RegexList"]);
});

test("mixed-nesting: highlightTree actually emits distinct classes for anchors/escapes/comments (end-to-end proof)", () => {
  // Real proof the overlay mount feeds CM6's highlighter, not just the raw tree shape --
  // `highlightTree` is what `syntaxHighlighting()` (the extension cm-regex.js installs)
  // calls under the hood.
  const input = "^foo\\d+$#a comment";
  const tree = pfbRegexListLanguage.parser.parse(input);
  const spans = [];
  highlightTree(tree, defaultHighlightStyle, (from, to, cls) => {
    spans.push({ from, to, cls, text: input.slice(from, to) });
  });
  const anchorSpans = spans.filter((s) => s.text === "^" || s.text === "$");
  const escapeSpan = spans.find((s) => s.text === "\\d");
  const commentSpan = spans.find((s) => s.text === "#a comment");
  assert.equal(anchorSpans.length, 2, `expected 2 anchor spans, got: ${JSON.stringify(spans)}`);
  assert.ok(escapeSpan, `expected a highlighted "\\d" escape span, got: ${JSON.stringify(spans)}`);
  assert.ok(commentSpan, `expected a highlighted comment span, got: ${JSON.stringify(spans)}`);
  // The three classes must be pairwise distinct -- proof the nested regex tags and the
  // outer Comment tag are actually different highlight categories, not one catch-all.
  const classes = new Set([anchorSpans[0].cls, escapeSpan.cls, commentSpan.cls]);
  assert.equal(classes.size, 3, `expected 3 distinct highlight classes, got: ${JSON.stringify([...classes])}`);
});

test("mixed-nesting: pfbHighlightStyle covers the tags defaultHighlightStyle drops (quantifier, alternation)", () => {
  // @codemirror/language's defaultHighlightStyle has no rule for t.operator (which kills
  // t.logicOperator too, since logicOperator is a child tag of operator) -- so a bare
  // Quantifier ("*") and the alternation operator ("|") render with zero spans under
  // defaultHighlightStyle alone. pfb-highlight-style.js (installed by cm-regex.js
  // ALONGSIDE defaultHighlightStyle) is what actually covers them in the shipped editor;
  // this pins that against the real bundle-facing style object, not a private copy.
  const input = "fo*|bar";
  const tree = pfbRegexListLanguage.parser.parse(input);

  const defaultSpans = [];
  highlightTree(tree, defaultHighlightStyle, (from, to, cls) => {
    defaultSpans.push({ from, to, cls, text: input.slice(from, to) });
  });
  assert.ok(
    !defaultSpans.some((s) => s.text === "*" || s.text === "|"),
    `expected defaultHighlightStyle to leave "*"/"|" unstyled (documents the gap this fix closes), got: ${JSON.stringify(defaultSpans)}`,
  );

  const pfbSpans = [];
  highlightTree(tree, pfbHighlightStyle, (from, to, cls) => {
    pfbSpans.push({ from, to, cls, text: input.slice(from, to) });
  });
  const quantifierSpan = pfbSpans.find((s) => s.text === "*");
  const altSpan = pfbSpans.find((s) => s.text === "|");
  assert.ok(quantifierSpan, `expected a highlighted "*" quantifier span, got: ${JSON.stringify(pfbSpans)}`);
  assert.ok(altSpan, `expected a highlighted "|" alternation span, got: ${JSON.stringify(pfbSpans)}`);
});

test("character-class OPENERS get the squareBracket span, all four ClassOpen* variants (issue #1681)", () => {
  // The grammar tokenizes the class opener as one of four NAMED nodes
  // (ClassOpen "[", ClassOpenNeg "[^", ClassOpenLit "[]", ClassOpenNegLit "[^]")
  // while the closer is a literal "]" node -- so the '"[ ]": t.squareBracket'
  // shorthand styled only the closer and every opener rendered unstyled.
  // One case per variant; each asserts BOTH the opener and its closer span so
  // the pair renders symmetrically under the shipped style.
  for (const [input, opener] of [
    ["(a)[bc]", "["],
    ["a[^xy]", "[^"],
    ["a[]b]", "[]"], // leading "]" is a literal member: "[]" is the opener
    ["a[^]b]", "[^]"],
  ]) {
    const tree = pfbRegexListLanguage.parser.parse(input);
    const spans = [];
    highlightTree(tree, pfbHighlightStyle, (from, to, cls) => {
      spans.push({ from, to, cls, text: input.slice(from, to) });
    });
    const openerSpan = spans.find((s) => s.text === opener);
    const closerSpan = spans.find((s) => s.text === "]" && s.from > (openerSpan ? openerSpan.to : 0));
    assert.ok(
      openerSpan,
      `input ${JSON.stringify(input)}: expected a highlighted ${JSON.stringify(opener)} class-opener span, got: ${JSON.stringify(spans)}`,
    );
    assert.ok(
      closerSpan,
      `input ${JSON.stringify(input)}: expected a highlighted "]" class-closer span after the opener, got: ${JSON.stringify(spans)}`,
    );
    assert.equal(
      openerSpan.cls,
      closerSpan.cls,
      `input ${JSON.stringify(input)}: opener and closer must share one highlight class`,
    );
  }
});
