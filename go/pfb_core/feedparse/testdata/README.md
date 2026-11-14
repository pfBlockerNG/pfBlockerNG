# Feed parse parity corpus

Language-neutral record of the feed content stage, line for line (issue #3906, map #3813).
`go/pfb_core/feedparse/*_corpus_test.go` replays every case against Core's parser.
`tests/smoke/test_smoke_feedparse_corpus.py` cross-compiles these runners and replays them on the appliance.
The PHP/Python runners and production parsers were removed in #3977; `old_expect` remains historical evidence,
not the smoke oracle. Both local and appliance runs assert Core's `expect` bytes.

`normalize.json`, `ip.json` and `dnsbl.json` pin the per-line stage (#3906); `feed.json`, `normcache.json` and `prescript.json` pin the
per-feed stage around it (#3976): whole feeds through the loops, the `.norm` cache, the pre-script.

The expectations were produced by the old path and then reviewed row by row; they are frozen. A case (`normalize.json`) or
line (`dnsbl.json`) where Core differs from the old path on purpose holds Core's result in `expect` and the old path's in
`old_expect`, and its `description` names the owner's sign-off. `"appliance": true` records that an old-path
expectation depended on pfSense's sed locale data, ICU or IP validation. Core runs these rows on every platform.

## Common rules

- Every file is one JSON object `{"schema": 1, "cases": [...]}`. Unknown keys, a missing key and a duplicate `id` are
  errors in the Core runners, never skips.
- `id` and `description` are non-empty strings; `id` is unique in its file.
- Feed bytes are a JSON string when they are valid UTF-8, else hex: a key `x` holds text and `x_hex` lower-case hex, never
  both.

## `normalize.json`: encoding normalization (`NormalizeFile`)

Case: `id`, `description`, `converter`, `input` or `input_hex` (the `.orig` bytes), `expect` or `expect_hex` (the `.norm` bytes
after the trailing-newline guarantee), optional `old_expect` or `old_expect_hex`, optional `appliance`. A hex form is used only
for bytes that are not valid UTF-8.

- `converter` (bool): historical old-path interpreter availability (`true`: charset_normalizer, `false`: unavailable).
  Core ignores it.
- `old_expect`: present only where Core differs from the old path on purpose; retained for comparison, not asserted.
- Owner sign-off (2026-11-12, #3906): Core does no charset guessing. Valid UTF-8 is kept, BOM-marked UTF-16 is decoded,
  and any other input takes today's conversion-unavailable path (raw bytes, controls stripped). charset_normalizer's
  verdicts on short feeds are noise (probed on 3.4.2: a Latin-1 comment header read as `big5hkscs`, `a.com\n\x80\n` as
  `utf_16_be`, KOI8-R as `big5`), so Core diverges from them on purpose.
- `appliance`: historical dependence on the appliance's C.UTF-8 class data: BOM/ZWJ non-printable; NBSP, U+2028/2029
  and private use printable; NBSP and U+2028 in `[:space:]`, U+0085 not. Core's expectations run without host probes.

## `ip.json`: IP feed lines (`ParseIPLine`) and parser types

Top level: `{"schema": 1, "cases": [...], "types": [...]}`. Ids are unique within `cases` and within `types`.

Case: `id`, `description`, `config` and `rows`.

- `config`: `vtype` (`_v4`/`_v6`), `pftype` (`auto`/`regex`), `custom` (bool), `cidr_floor_v4` and `cidr_floor_v6`
  (`"Disabled"` or a decimal string), `suppression` (bool).
- `rows`: non-empty list, run in order; each `{"line" | "line_hex", "expect"}` plus an optional `"appliance": true`, the
  line as `fgets()` returns it (its `\n` included, none inside). `appliance` marks a row whose old-path result is the
  pfSense appliance's: there `is_ipaddrv6()` ends in PEAR Net_IPv6 (1.3.0b4 with pfSense's patch) where the off-appliance
  double used `filter_var`. Core's local and appliance runners always run these rows. `expect` is `{"entries": [...],
  "line" | "line_hex", "suppressed": bool, "parse_fail": int, "detailed_parse_fail": bool, "messages" | "messages_hex":
  [...]}`: the entries appended to the list, the line as the parse-error log shows it, and the replay's other fields for
  this line alone (`parse_fail` is this line's increment).
  `messages_hex` (hex of each message) replaces `messages` when one is not valid UTF-8.

Type (`IPParseType()`, the parser Core picks for a feed): `id`, `description`, `format` (the list's
`format`), `url`, `expect` (`auto`/`regex`).

## `dnsbl.json`: DNSBL feed lines (`NewDNSBLParser`)

Case: `id`, `description`, `config` and `lines`; one case is one feed file, its lines parsed in order with the parser's
per-feed state (CSV detection, reverse format, the hpHosts end marker) carried between them.

- `config`: `dnsbl_ip` (bool: IPs in a domain feed are collected), `lenient` (bool: permissive scheme handling),
  `custom` (bool: a user list), `suppression` (bool: the global Suppression setting, `$pfb['supp']`).
- `lines`: non-empty; each `{"line" | "line_hex", "expect", optional "old_expect", optional "appliance"}`, the line as
  `fgets()` returns it (its `\n` included). `old_expect` has the shape of `expect` and is present only where Core differs from
  the old path on purpose (never equal to `expect`): local and appliance Core runners assert `expect`.
  `"appliance": true` (only ever `true`) records an old-path expectation specific to pfSense
  (Net_IPv6 validation, transitional UTS46 or PCRE2/ICU classification of U+180E).
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
  final sigma (`idn_uts46`) are Core's non-transitional answers. Historical appliance answers not recorded in `old_expect`
  remain unconfirmed; the Core smoke replay does not run the retired PHP parser.
- Known limits of the ABP regex-IP gate (RE2 stands in for PCRE): a possessive quantifier (`*+`, `++`) in an octet pattern
  is refused by Core and accepted by PCRE; `{,n}` is read as `{0,n}`, which is PCRE2 >= 10.43 (probed on 10.46); an older
  PCRE2 may read it differently.

## `feed.json`: whole feeds (`ParseIPFeed`, `ParseDNSBLFeed`)

Top level: `{"schema": 1, "ip": [...], "dnsbl": [...]}`; ids are unique across both lists. A case is one feed file as the parse stage
reads it (after normalization and the pre-script), its config, and everything the loop leaves for the next stage.

Case: `id`, `description`, `config`, the feed bytes and `expect`. The feed bytes are `input`, `input_hex`, or `input_parts`: a list
of strings and `{"repeat": text, "count": n}` (a line over 64 KiB without 64 KiB of JSON). Exactly one of the three. An IP case may
also have `"normalize": true` (only ever `true`): the feed bytes are then the raw download, the `.orig`.
The runner calls `NormalizeFile(dir, "feed")`, parses the `.norm` and probes the `.orig` for content.
A case without it feeds the same bytes to the parse and to the probe.

A byte item of `details` and `messages` is a JSON string, or `{"hex": "..."}` when its bytes are not valid UTF-8.

IP case (`ip`):

- `config`: `vtype`, `pftype`, `custom`, `cidr_floor_v4`, `cidr_floor_v6`, `suppression` (as in `ip.json`) and `placeholder`, the
  Placeholder IP Address setting.
- `expect`: `out`/`out_hex`, the `.txt` the Outpost's next stage reads (the entries, one per line, or the placeholder; empty when
  nothing is written and the list keeps its last known-good content); `parse_fail`, the count of failed lines; `suppressed`, whether
  Suppression dropped valid IPv6 entries; `details`, the parse-error records `{"line_no", "line", "raw"}`, in line order (`line` as
  the record shows it, `"null"` for an empty one; `raw` the input line without its trailing CR and LF); `messages`, every notice
  the parser logged, in order; `placeholder`, the empty-feed block's outcome: `""` (none), `"empty"` (no content line and no entry:
  `<ip>` or `::<ip>`) or `"suppressed"` (an IPv6 feed all of whose entries were suppressed: `::<ip>`).
- The empty-feed rule is the caller's probe: the old path counts the content lines of the raw `.orig` (the staged copy after a
  pre-script) with `grep -cv`, and writes the placeholder when that count is 0 and the loop found no entry. A line is content unless it
  is blank (ASCII whitespace, vertical tab and form feed included) or starts, after leading whitespace, with `#`, `;`, `!` or `//`. A file
  that is missing or has size 0 is not probed, which is no placeholder. `CountContent(path)` is that probe (`NoProbe` for no file or an
  empty one) and `ParseIPFeed` takes its answer as an argument: what the loop parses (the `.norm`, with its BOM and control
  characters stripped) says nothing about whether the download had content. The `normalize` cases pin the difference: a comment-only
  `.orig` behind a BOM or a control character has a content line in the raw file and none in the `.norm`, so the old path writes no
  placeholder there.

DNSBL case (`dnsbl`):

- `config`: `dnsbl_ip`, `lenient`, `custom`, `suppression` (as in `dnsbl.json`).
- `expect`: `out`/`out_hex`, the NDJSON rows written to the `.bk` (`["d","name"]` or `["a","rule"]` and a newline, `json_encode` with
  `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE`); `ip4`, `ip6`, the lists written to `_v4.ip` and
  `_v6.ip` (`array_unique`, first-seen order, the IPs the feed carried); `updateip`; `scheme_skipped`, the strict-scheme count behind
  the warning; `stop`, whether the feed ended at the hpHosts marker; `details`, as above; `messages`, every notice the parser logged, in
  order, as in an IP case (`IP literal decoded`, `IDN converted` and, from the IP sanitizer the line parser collects through, `Feed /0 CIDR
  clamped to single host`; these are all the per-line parser logs, over the 696 runs of every `dnsbl.json` case under both Suppression and custom settings).
- The parse-error records and the notices are not kept in the result: Core hands each to the sink (`Sink.Fail`, `Sink.Message`) as the
  feed is read, as the old path writes them to its log files.
- `pfb_dnsbl_abp_regex_ip4_cidrs()` also logs `ABP IPv4 regex rule expansion failed`, from a `catch (\Throwable)` around its own
  expansion. Nothing but its test seam (`pfb_test_abp_regex_fault`) reaches that catch: 400,000 generated rules of the shapes the function
  accepts or refuses (PHP 8.4.27, 2026-11-13) never threw, and a PCRE failure there is a warning the function turns into an empty
  expansion without a log line. Core's expansion cannot throw and returns nothing in those cases, so it has no such notice and the
  corpus has no row for it.
- A feed whose line makes the old path throw has no case (an interior NUL reaching `ip2long()`, as in `dnsbl.json`): a UTF-16 file
  read undecoded is one. Core decodes UTF-16 before it parses.

## `normcache.json`: the `.norm` cache (`NormalizeFile`)

`{"schema": 1, "cases": [...]}`. Core calls `NormalizeFile(dir, "feed")` without charset guessing
(owner decision, #3906). The inputs are ASCII.

Case: `id`, `description`, `setup` and `expect`. `setup` and `expect.files` hold a directory: any of `orig`/`orig_hex` (`feed.orig`),
`norm`/`norm_hex` (`feed.norm`), `xxhash128` (`feed.norm.src.xxhash128`) and `md5` (`feed.norm.src.md5`), a key absent where the file
is. `expect.files` is the whole directory after the call: a file not listed must not exist, a temporary file included. `expect.path`
is `"norm"` or `"orig"` (the file to parse), `expect.changed` and `expect.normalized` are the call's other answers.

## `prescript.json`: the pre-script on a staged copy (`RunPreScript`)

`{"schema": 1, "cases": [...]}`. The runner stages `feed.norm` as `feed.pre`, runs the script on it, checks what the call returned
and what the directory holds, then runs Core's `Cleanup` after the parse: the staged copy must be gone.

Case: `id`, `description`, `setup`, `script`, `list_type`, `blocks` and `expect`.

- `setup`: `norm`/`norm_hex` and `staged`/`staged_hex` (a stale staged copy), a key absent where the file is.
- `script`: `name` (any bytes but `/` and NUL: spaces, quotes and `$( )` run the test's canary if a shell ever reads them), `body`
  (after `#!/bin/sh`), `mode`: `exec`, `noexec` (no execute bit) or `absent`, and optionally `shebang` (only ever `false`: the script has
  no `#!` line at all, which `execvp` runs as a `/bin/sh` script and so does Core). The script gets the staged path and `list_type`.
  The runner sets `PFB_TEST_CANARY` (a path the script name must never create).
- `blocks`: the script blocks until killed. It reads the fifo `PFB_TEST_BLOCK`, nobody writes it, and first writes the fifo
  `PFB_TEST_READY` when that is set. The Go runner cancels the context when the script has reported.
- `expect`: `ok`; `reason`, `""`, `"stage"` (no staged copy could be made), `"exit"` (non-zero: `status` is it, 126 for a script that
  cannot be run, 127 for one that is missing), `"timeout"` (killed) or `"deleted"` (the script removed its input); `status`; `files`, the
  directory after the call and before the cleanup (`norm`, `staged`): a failed script leaves no staged copy.
