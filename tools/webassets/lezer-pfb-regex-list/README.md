# @pfblockerng/lezer-pfb-regex-list

A [Lezer](https://lezer.codemirror.net/) grammar for pfBlockerNG's regex-list textarea
format -- one Python-`re` pattern plus an optional `#` description per line.

## What this is

pfBlockerNG's DNSBL rule editor stores custom entries as a plain-text list: each line is a
pattern, optionally followed by a `#` and a free-text description. This package is the
outer layer of the CodeMirror 6 editor (issue #1669 slice B): a Lezer grammar for that
line format, which mounts `@pfblockerng/lezer-regexp`'s Python-`re` grammar (slice A)
inside every `Pattern` span via [`parseMixed`](https://lezer.codemirror.net/docs/ref/#common.parseMixed),
so a pattern gets full regex highlighting and its trailing description gets styled as a
comment.

**This is a highlighter, not a validator.** The server-side decoder
(`pfb_text_area_decode()` in `src/usr/local/pkg/pfblockerng/pfblockerng.inc`) stays
authoritative for what actually gets stored.

## Line format (mirrors `pfb_text_area_decode()` exactly)

- A line whose **trimmed** start is `#` is a whole-line `Comment` -- the decoder drops
  these lines entirely, never storing them.
- Otherwise, the **first** `#` anywhere in the line splits it: everything before is
  `Pattern` (mounts the regex grammar), everything from the `#` onward is a trailing
  `Comment`. A line with no `#` at all is `Pattern`-only.
- A `#` appearing *inside* a pattern (e.g. inside a character class, `[a#b]x`) still ends
  the pattern there and starts a `Comment` -- this is intentional: it's exactly what the
  decoder does, so the editor surfaces the real split instead of hiding it.

Leading whitespace is significant only as a heuristic: it's how the grammar tells "trimmed
line starts with #" (whole-line `Comment`) apart from "pattern that happens to start with
some spaces, followed later by a #" (`Pattern` then `Comment`) -- see
`src/pfb-regex-list.grammar`'s header comment for the tokenizer mechanics (no explicit
lookahead needed: it falls out of Lezer's longest-match tokenizer, once its ambiguity
check is satisfied with an explicit `@precedence { Comment, Pattern }`).

## Layout

```text
lezer-pfb-regex-list/
  package.json              # scripts only -- resolves the PARENT tools/webassets/
                             # node_modules, carries no dependencies of its own
  src/pfb-regex-list.grammar # the grammar (source of truth)
  src/parser.js               # generated -- gitignored, `npm run generate` (re)builds it
  src/parser.terms.js         # generated -- gitignored
  src/highlight.js           # styleTags mapping (Comment -> t.lineComment)
  src/index.js               # public entry: `parser` (bare), `mixedParser`, `pfbRegexList()`
  test/cases.txt             # fileTests-format parse-tree fixtures (bare parser)
  test/parse.test.js         # node:test runner: fileTests + trim-edge-case + mixed-nesting
```

## Running it

From `tools/webassets/`:

```sh
npm ci
npm run test:listgrammar
```

`test:listgrammar` shells out to `npm --prefix lezer-pfb-regex-list test`, whose
`pretest` hook runs `npm run generate` first.

## API surface (for consumers)

```js
import { parser, mixedParser, pfbRegexListLanguage, pfbRegexList } from "@pfblockerng/lezer-pfb-regex-list";
```

- `parser` -- the bare generated `LRParser`, configured with this package's own
  `styleTags` (`Comment`) but **without** the `parseMixed` wrap. Used by
  `test/cases.txt` so those cases pin pure `Pattern`/`Comment` line-splitting without
  also having to pin the mounted regex grammar's tree shape in every case.
- `mixedParser` -- `parser`, additionally `.configure()`d with
  `wrap: parseMixed(...)` mounting `@pfblockerng/lezer-regexp`'s `parser` inside every
  `Pattern` node, as an **overlay** (`overlay: [{from, to}]` -- see `src/index.js`'s
  comment for why the overlay form is required, diverging from the simpler non-overlay
  form).
- `pfbRegexListLanguage` -- `mixedParser` wrapped in `LRLanguage.define({parser})`
  (`@codemirror/language`).
- `pfbRegexList()` -- returns a `LanguageSupport` wrapping `pfbRegexListLanguage`; this
  is what the CM6 bundle entry (`tools/webassets/cm-regex.js`) installs as an editor
  extension.

## Testing notes

Overlay-mounted trees are **not** visible to a plain `tree.iterate()` walk --
`@lezer/common`'s cursor-based iteration only splices in *non-overlay* mounts; overlays
need position-based `resolveInner()`/`enter()` lookups (the same mechanism
`@lezer/highlight`'s `highlightTree` uses internally to render nested highlighting). See
`test/parse.test.js`'s `chainAt()` helper and its "mixed-nesting" tests, including one
that calls `highlightTree()` directly and asserts three *distinct* highlight classes for
an anchor, an escape, and a comment in the same line -- proof the mount actually feeds
real syntax highlighting, not just a tree shape.

## Upstream intent

Project-specific (the line format is pfBlockerNG's own convention) -- unlike
`@pfblockerng/lezer-regexp`, this package is not intended for extraction as a standalone
community package.
