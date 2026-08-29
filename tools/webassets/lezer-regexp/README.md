# @pfblockerng/lezer-regexp

A [Lezer](https://lezer.codemirror.net/) grammar for Python 3.11 `re` regular expressions.

## What this is

pfBlockerNG's DNSBL rule editor highlights Python-`re` patterns (the appliance's DNSBL
engine, `pfb_unbound.py`, compiles rules with Python's `re` module). This package is the
first step of replacing the Prism-based syntax overlay with CodeMirror 6 (issue #1669): a
Lezer grammar that produces a highlightable parse tree for that dialect.

**This is a highlighter, not a validator.** It never throws on malformed input -- hostile
patterns (unclosed groups/classes, malformed quantifiers, reversed character-class ranges)
still produce a tree, using Lezer's built-in error-recovery (`⚠`) nodes where the input
genuinely doesn't parse. Server-side validation (`preg_match`/`re.compile`) stays the
authoritative check; this grammar only has to be good enough to color the pattern in an
editor.

## Dialect scope

Python 3.11 `re` syntax, non-verbose mode only (`re.X`/verbose mode -- which ignores
whitespace and supports `#` line comments inside the pattern -- is out of scope; `#` is
always literal text here). Covers: literals, `.`, anchors (`^`/`$`), greedy/lazy/possessive
quantifiers (including 3.11's possessive suffixes), counted `{m,n}` quantifiers, character
classes (including the "`]` immediately after `[`/`[^` is literal" rule and ranges), all
group forms (capturing, non-capturing, named, lookaround, atomic groups (3.11), conditional
groups, inline/scoped flags, comment groups), backreferences, and the standard escape
sequences (`\d`/`\w`/`\s`/... , `\xhh`, `\uhhhh`, `\Uhhhhhhhh`, `\N{...}`, octal, identity
escapes).

The pfBlockerNG list-format `#` comment convention (distinct from this grammar's plain
"`#` is a literal character" rule) belongs to a separate, outer grammar layered on top in a
later slice -- this package stays a pure Python-`re` grammar so it can be extracted verbatim
as a standalone community package later.

## Layout

```text
lezer-regexp/
  package.json        # scripts only -- resolves the PARENT tools/webassets/ node_modules,
                       # carries no dependencies of its own
  src/regexp.grammar   # the grammar (source of truth)
  src/parser.js         # generated -- gitignored, `npm run generate` (re)builds it
  src/parser.terms.js   # generated -- gitignored
  src/highlight.js     # styleTags mapping (@lezer/highlight)
  src/index.js         # public entry: exports `parser`, pre-configured with highlighting
  test/cases.txt       # fileTests-format parse-tree fixtures
  test/parse.test.js   # node:test runner (fileTests + dedicated hostile-input cases)
```

## Running it

From `tools/webassets/`:

```sh
npm ci
npm run test:grammar
```

`test:grammar` shells out to `npm --prefix lezer-regexp test`, whose `pretest` hook runs
`npm run generate` (`lezer-generator src/regexp.grammar -o src/parser.js`) before the test
step (`node --test test/parse.test.js`) -- so a stale or missing generated parser never
masks a grammar change. Regenerate by hand with `npm run generate` from inside
`lezer-regexp/`.

## Testing notes

`test/cases.txt` uses `@lezer/generator`'s `fileTests` format (`# name`, input, `==>`,
expected tree) -- exported from the `@lezer/generator/test` subpath (not the package's main
entry; verified against its `package.json` `exports` map). Anonymous punctuation nodes
(`( ) [ ] | -`) are omitted from expected trees by `fileTests`' default `mayIgnore`, which
skips any node name containing a non-word character.

Trees containing `⚠` run in non-strict mode (Lezer's own convention); everything else is an
exact match, so a case with no `⚠` still pins the full tree shape.

## API surface (for consumers)

```js
import { parser } from "@pfblockerng/lezer-regexp";
```

`parser` is the generated `LRParser`, pre-configured with `regexpHighlighting`
(`src/highlight.js`'s `styleTags` table) via `.configure({ props: [regexpHighlighting] })`.
Top node: `RegExp`. See `src/regexp.grammar` for the full named-node list.

## Upstream intent

Laid out to match the shape of existing `@lezer/*` language packages (e.g.
[`@lezer/css`](https://github.com/lezer-parser/css)) so it can be extracted into its own
repository and published to npm once it's exercised real-world DNSBL patterns for a while.
