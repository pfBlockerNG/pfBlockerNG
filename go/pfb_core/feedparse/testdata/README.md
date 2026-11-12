# Feed parse parity corpus

Language-neutral record of what today's feed content stage produces, line for line (issue #3906, map #3813). Two runners
replay every case and must agree with it:

- Go: `go/pfb_core/feedparse/*_corpus_test.go` (the Core package).
- PHP/Python (the old path): `tests/php/FeedParse*CorpusTest.php`, through the production functions themselves.

The expectations were produced by the old path and then reviewed row by row; they are frozen. A case where Core differs
from the old path on purpose holds Core's result, and its `description` names the owner's sign-off. A case the old path
answers differently per platform (sed locale data) has `"appliance": true`: its expectation is the pfSense appliance's
result, and the PHP runner skips it where the host's probe differs.

## Common rules

- Every file is one JSON object `{"schema": 1, "cases": [...]}`. Unknown keys, a missing key and a duplicate `id` are
  errors in both runners, never skips.
- `id` and `description` are non-empty strings; `id` is unique in its file.
- Feed bytes are a JSON string when they are valid UTF-8, else hex: a key `x` holds text and `x_hex` lower-case hex, never
  both.

## `normalize.json`: encoding normalization (`pfb_feed_normalize_generate()`, `pfb_feed_normalize.py`)

Case: `id`, `description`, `input` or `input_hex` (the `.orig` bytes), `expect` or `expect_hex` (the `.norm` bytes after
the trailing-newline guarantee), optional `appliance`.

## `ip.json`: IP feed lines (`pfb_ip_parse_line_replay()`)

Case: `id`, `description`, `config` and `rows`.

- `config`: `vtype` (`_v4`/`_v6`), `pftype` (`auto`/`regex`), `custom` (bool), `cidr_floor_v4` and `cidr_floor_v6`
  (`"Disabled"` or a decimal string), `suppression` (bool).
- `rows`: non-empty list, run in order; each `{"line" | "line_hex", "expect"}`, the line as `fgets()` returns it (its
  `\n` included). `expect` is `{"entries": [...], "line": "...", "suppressed": bool, "parse_fail": int,
  "detailed_parse_fail": bool, "messages": [...]}`: the entries appended to the list, and the replay's other fields for
  this line alone (`parse_fail` is this line's increment).

## `dnsbl.json`: DNSBL feed lines (`pfb_dnsbl_parse_line()`)

Case: `id`, `description`, `config` and `lines`; one case is one feed file, its lines parsed in order with the parser's
per-feed state (CSV detection, reverse format, the hpHosts end marker) carried between them.

- `config`: `dnsbl_ip` (bool: IPs in a domain feed are collected), `lenient` (bool: permissive scheme handling),
  `custom` (bool: a user list), `suppression` (bool: the global Suppression setting, `$pfb['supp']`).
- `lines`: non-empty; each `{"line" | "line_hex", "expect"}`, the line as `fgets()` returns it (its `\n` included).
  `expect` is `{"rows", "ip4", "ip6", "fail", "scheme_skipped", "stop"}` for this line alone:
  - `rows`: the NDJSON rows written, each `["d" | "a", text]` (domain or verbatim ABP rule); `text` is what the row
    carries after the writer's invalid-UTF-8 substitution (U+FFFD), so it is always valid UTF-8.
  - `ip4`, `ip6`: the entries appended to the feed's IPv4 / IPv6 lists, before the feed's de-duplication.
  - `fail`: the `line` field of each parse-failure record (`pfb_parse_fail_log()`) written for this line; `"null"` is
    the placeholder for an empty line. An item is a JSON string, or `{"hex": "..."}` when its bytes are not UTF-8.
  - `scheme_skipped`: this line's increment of the feed's strict-scheme skip counter (0 or 1).
  - `stop`: the line ended the feed (hpHosts end marker). It is only ever the last line of its case.
- Rows are produced with `LC_CTYPE=C` (as the appliance runs) and the default `mbstring`/`intl` settings. A line that
  makes the old path throw (an interior NUL reaching `ip2long()`) has no row.
