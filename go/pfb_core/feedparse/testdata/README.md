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

- `config`: `dnsbl_ip` (bool: IPs in a domain feed are collected), `lenient` (bool), `custom` (bool).
- `lines`: each `{"line" | "line_hex", "expect"}`; `expect` is `{"rows": [NDJSON rows written], "ip4": [...], "ip6":
  [...], "fail": [logged failure line fields], "stop": bool}`. After a `stop`, no further line is read.
