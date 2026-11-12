# Feed parse parity corpus

Language-neutral record of what today's feed content stage produces, line for line (issue #3906, map #3813). Two runners
replay every case and must agree with it:

- Go: `go/pfb_core/feedparse/*_corpus_test.go` (the Core package).
- PHP/Python (the old path): `tests/php/FeedParse*CorpusTest.php`, through the production functions themselves.

The expectations were produced by the old path and then reviewed row by row; they are frozen. A case (`normalize.json`) or
line (`dnsbl.json`) where Core differs from the old path on purpose holds Core's result in `expect` and the old path's in
`old_expect`, and its `description` names the owner's sign-off. A case the old path answers differently per platform (sed
locale data, ICU version) has `"appliance": true`: the old path's expectation is the pfSense appliance's result, and the
PHP runner skips it where the host's probe differs.

## Common rules

- Every file is one JSON object `{"schema": 1, "cases": [...]}`. Unknown keys, a missing key and a duplicate `id` are
  errors in both runners, never skips.
- `id` and `description` are non-empty strings; `id` is unique in its file.
- Feed bytes are a JSON string when they are valid UTF-8, else hex: a key `x` holds text and `x_hex` lower-case hex, never
  both.

## `normalize.json`: encoding normalization (`pfb_feed_normalize_generate()`, `pfb_feed_normalize.py`)

Case: `id`, `description`, `converter`, `input` or `input_hex` (the `.orig` bytes), `expect` or `expect_hex` (the `.norm` bytes
after the trailing-newline guarantee), optional `old_expect` or `old_expect_hex`, optional `appliance`. A hex form is used only
for bytes that are not valid UTF-8.

- `converter` (bool): the PHP runner's interpreter. `true` is a python3 with charset_normalizer (the case is skipped where the
  host has none), `false` is `''`, today's conversion-unavailable path. The Go runner ignores it.
- `old_expect`: present only where Core differs from the old path on purpose. The Go runner asserts `expect`, the PHP
  runner asserts `old_expect`.
- Owner sign-off (2026-11-12, #3906): Core does no charset guessing. Valid UTF-8 is kept, BOM-marked UTF-16 is decoded,
  and any other input takes today's conversion-unavailable path (raw bytes, controls stripped). charset_normalizer's
  verdicts on short feeds are noise (probed on 3.4.2: a Latin-1 comment header read as `big5hkscs`, `a.com\n\x80\n` as
  `utf_16_be`, KOI8-R as `big5`), so Core diverges from them on purpose.
- `appliance`: the PHP assertion depends on the appliance's C.UTF-8 class data (replayed on a real pfSense box by
  `tests/smoke/test_smoke_feedparse_corpus.py`): BOM/ZWJ non-printable; NBSP, U+2028/2029
  and private use printable; NBSP and U+2028 in `[:space:]`, U+0085 not. Separately, a PHP assertion that is not valid
  UTF-8 needs a host sed that passes invalid sequences through; the PHP runner probes both and skips where the host differs.

## `ip.json`: IP feed lines (`pfb_ip_parse_line_replay()`) and parser types

Top level: `{"schema": 1, "cases": [...], "types": [...]}`. Ids are unique within `cases` and within `types`.

Case: `id`, `description`, `config` and `rows`.

- `config`: `vtype` (`_v4`/`_v6`), `pftype` (`auto`/`regex`), `custom` (bool), `cidr_floor_v4` and `cidr_floor_v6`
  (`"Disabled"` or a decimal string), `suppression` (bool).
- `rows`: non-empty list, run in order; each `{"line" | "line_hex", "expect"}` plus an optional `"appliance": true`, the
  line as `fgets()` returns it (its `\n` included, none inside). `appliance` marks a row whose old-path result is the
  pfSense appliance's: there `is_ipaddrv6()` ends in PEAR Net_IPv6 (1.3.0b4 with pfSense's patch) where the off-appliance
  double uses `filter_var`. The PHP runner skips such a row unless the host's `is_ipaddrv6()` accepts a trailing blank after
  `1:2:3:4:5:6:7:8` (as Net_IPv6 does); the Go runner and the appliance smoke test always run it. `expect` is `{"entries": [...],
  "line" | "line_hex", "suppressed": bool, "parse_fail": int, "detailed_parse_fail": bool, "messages" | "messages_hex":
  [...]}`: the entries appended to the list, the line as the parse-error log shows it, and the replay's other fields for
  this line alone (`parse_fail` is this line's increment).
  `messages_hex` (hex of each message) replaces `messages` when one is not valid UTF-8.

Type (`IPParseType()`, the parser the apply script picks for a feed): `id`, `description`, `format` (the list's
`format`), `url`, `expect` (`auto`/`regex`). The PHP runner cuts the dispatch block out of the apply script and
evaluates it, since it is inline code there.

## `dnsbl.json`: DNSBL feed lines (`pfb_dnsbl_parse_line()`)

Case: `id`, `description`, `config` and `lines`; one case is one feed file, its lines parsed in order with the parser's
per-feed state (CSV detection, reverse format, the hpHosts end marker) carried between them.

- `config`: `dnsbl_ip` (bool: IPs in a domain feed are collected), `lenient` (bool: permissive scheme handling),
  `custom` (bool: a user list), `suppression` (bool: the global Suppression setting, `$pfb['supp']`).
- `lines`: non-empty; each `{"line" | "line_hex", "expect", optional "old_expect", optional "appliance"}`, the line as
  `fgets()` returns it (its `\n` included). `old_expect` has the shape of `expect` and is present only where Core differs from
  the old path on purpose (never equal to `expect`): the Go runner asserts `expect`, the PHP runner `old_expect`, the smoke
  replay `old_expect` too. `"appliance": true` (only ever `true`): the old path's expectation (`old_expect` when present) is the
  pfSense appliance's result, which the PHP runner's host may not reproduce (the appliance's `is_ipaddrv6` is Net_IPv6, its
  ICU does transitional UTS46, its PCRE2/ICU classify U+180E differently); the PHP runner replays the line in its own test and
  skips it where the host differs, the Go runner always asserts `expect`.
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
- Owner sign-off (2026-11-12, #3906): Core converts IDNs with `golang.org/x/net/idna` in the pfb-dns profile (`pslIdna` in
  `go/pfb_dns_gateway/decider/pfb_unbound_psl.go`: `MapForLookup`, `BidiRule`, `StrictDomainName(false)`,
  `CheckHyphens(false)`, `VerifyDNSLength(true)`; UTS #46 non-transitional), not a port of ICU's default
  `idn_to_ascii()`. The Unicode tables come from the pinned x/net and the Go toolchain (go1.27 selects Unicode 17). The `old_expect`
  lines are where the two differ:
  - ZWNJ/ZWJ: the appliance's transitional ICU drops them (`ab.com`), the profile rejects the label.
  - Hyphens: ICU rejects a leading or trailing hyphen and `--` at positions 3 and 4 of a label, the profile converts it.
  - Bidi: the profile applies the RFC 5893 rule (`אa.com` fails), ICU's default does not.
  - U+180E: ignorable since Unicode 16 (the profile drops it), disallowed in the appliance's older ICU.
  - Newer code points: converting each code point from U+0080 alone as `X.com` (host PHP 8.4.27 with ICU 76.1 against x/net v0.56.0
    on go1.27.0) never gives two different answers. Core accepts 4,763 the host rejects (4,761 are unassigned in Unicode 16;
    U+FE63 and U+FF0D map to a hyphen) and rejects 81 the host accepts (63 Arabic-number and 16 Arabic-letter code points that
    fail the bidi rule alone, ZWNJ and ZWJ).
  A trailing root dot is not a divergence: ICU accepts it and Core strips one before converting and puts it back. Sharp s and
  final sigma (`idn_uts46`) are the non-transitional answers; the appliance's transitional ICU probably answers `ss` and `σ`,
  which no replay has confirmed (the smoke replay decides; add an `old_expect` with `"appliance": true` if it differs).
- Known limits of the ABP regex-IP gate (RE2 stands in for PCRE): a possessive quantifier (`*+`, `++`) in an octet pattern
  is refused by Core and accepted by PCRE; `{,n}` is read as `{0,n}`, which is PCRE2 >= 10.43 (probed on 10.46); an older
  PCRE2 may read it differently.
