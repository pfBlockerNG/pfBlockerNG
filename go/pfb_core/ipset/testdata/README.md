# IP set algebra parity corpus

Language-neutral record of what today's shell and PHP produce for the IP set algebra, member for member (issue #4033,
map #3813, slice 4 of `docs/specs/go-updater-pipeline.md`). Two runners replay every case and must agree with it:

- The appliance replay: `tests/smoke/test_smoke_ipset_corpus.py`, through the installed package's own `pfblockerng.sh` and
  PHP functions on a real pfSense box. This is the oracle: every `expect` is its output.
- Go: the `ipset` package's corpus test (`corpus_test.go`, `corpus_groups_test.go`) replays the same file against Core.

`ipset.json` holds every case. The expectations were produced by the appliance and then reviewed row by row; they are
frozen. A one-member difference is a failure, never a tolerance.

## Common rules

- One JSON object `{"schema": 1, "cases": [...]}`. Unknown keys, a missing key and a duplicate `id` are errors in every
  runner, never skips.
- A case is `{"id", "description", "op", "family": "v4" | "v6", "input", "expect"}` plus an optional `"digest": true`.
  `id` and `description` are non-empty strings and `id` is unique. `op` is one of the twelve groups below.
- A member list is stored as the file's raw text. A text object has exactly one of `"text"` (a JSON string), `"text_hex"`
  (lower-case hex, for bytes that are not UTF-8) or `"parts"` (a list of strings and `{"generate": recipe}`, concatenated).
  Text keeps its CRLF, a missing final newline, blank lines and order, so those inputs are representable.
- An output member list is a JSON list of the file's lines: the text is split at `\n`, a final unterminated line counts,
  a `\r` stays part of its line. A file the run did not leave behind is `null`.
- Comparison rule: an output list is compared as a **multiset** (order-insensitive, duplicates significant), except the lists
  named `set` (canonical sets), `kept` (member names of a union), `counts` (the recompute counts file), `content` (DNSBLIP) and
  `sources` (DNSBLIP source names), which are compared **in order**: byte order or sequence is their contract. The order
  inside any other member list is the tool's (`iprange` writes numeric order, `sort -u` byte order) and no requirement on Core:
  the canonical body re-sorts every set bytewise, so that order is not observable downstream.
- `"digest": true` marks a case whose input is large. Every output member list of that case is then recorded as
  `{"count": n, "sha256": "<hex>"}`: `n` lines, and the SHA-256 of the lines sorted bytewise (`LC_ALL=C sort`) and joined with
  `\n`, no trailing newline (the empty list is `count` 0 and the hash of the empty string). Digests are order-insensitive
  on purpose.
- The harness's timing key `_seconds`, at the root of a result, is never part of an `expect`.
- Time stamps the script writes into its error log (`[ <date time> ]`) are recorded as `[ TS ]`.

### Generator recipes

A `{"generate": recipe}` part expands to lines, each ended by `\n`; `i` runs from 0 to `count - 1`. Go reproduces them byte for
byte.

- `{"kind": "v4_seq", "start": S, "count": N, "step": P, "suffix": X}`: line `i` is the dotted quad of the integer `S + i * P`,
  then `X`.
- `{"kind": "v6_seq", "base": B, "count": N, "step": P, "suffix": X}`: line `i` is `B` with its low 64 bits increased by
  `i * P`, written the way `inet_ntop()` writes it (lower case, the longest zero run compressed, an embedded IPv4 tail only
  for the IPv4-mapped and IPv4-compatible ranges), then `X`.

## Groups

Every group's `expect` is the object its harness function returns, minus `_` keys. "Verb" is a call of the installed
script's verb dispatch with the argv PHP passes today; "function" is the production PHP function, called as is.

| `op` | What runs | `input` | `expect` |
| --- | --- | --- | --- |
| `cidr_aggregate` | verb `cidr_aggregate <alias> <folder>` | `members` | `rc`, `members`, `unchanged` (file bytes equal the input), `stats` (the `Original`/`Final` row or `null`), `log` |
| `preprocess` | `pfb_ip_preprocess_args()`, then the per-feed verb it names | `members`, `dup`, `agg`, `rep`, `max`, `drep`, `cc`, `ccwhite`, `ccblack`, `geo` | `args`, `ran`, `rc`, `members`, `match_rep` (the `pfB_Match_Rep_<alias>.txt` lines or `null`), `log` |
| `recompute` | verb `recompute <family> <memberlist> <counts> <dedup> <repmode> <max> <cc> <ccwhite> <ccblack>` | ordered `members` `[{name, text...}]`, `dedup`, `repmode`, `max`, `cc`, `ccwhite`, `ccblack`, `geo`, optional `master`, `deny_pre`, `match_pre`, `ph` | `rc`, `deny`, `master`, `mastercat`, `counts`, `match`, `processed`, `log` |
| `pmax` | verb `pmax x <max>` | `deny`, `max`, `geo`, optional `master` | `rc`, `deny`, `master`, `mastercat`, `log` |
| `suppress` | v4: verb `suppress <alias> <folder> on\|off`; v6: `pfb_suppress_file_v6()` | `members`, `suppression`, v4 only `dedup`, `master` | v4: `rc`, `members`, `master`, `stats`, `log`; v6: `ok`, `members`, `log`, `leftover_tmp` |
| `remove` | verb `remove x x x <headers,>` | `headers`, files per class dir, `master` | `rc`, `files` (names per dir), `master`, `mastercat`, `messages` |
| `closing` | verb `closing on\|off` | `deny`, `dedup`, `master`, `orig`, `ph` | `rc`, `deny`, `master`, `sanity`, `log` |
| `canonical` | `pfb_canonical_alias_set()` | `members` (the concatenated content) | `set` |
| `union` | `pfb_aggregate_member_list()` then verb `aggregate <family> <memberlist> <aggout> <consumer> on\|off` | `type`, `members` (files of the class dir), `collapsed`, `ph` | `kept`, `rc`, `aggregate`, `consumer`, `stats`, `log` |
| `dnsblip` | `pfb_dnsbl_concat_files()` or the empty-case placeholder write | `ip_files`, `ip_ph` | `built`, `content`, `final_newline`, `sources` |
| `matrix` | `pfb_ip_recompute_matrix()` and `pfb_ip_closing_pass_active()` | `fn` plus the function's arguments | the function's return value |
| `pipeline` | the apply script's stages in order, see below | `switches`, `feeds`, `suppression`, `passes`, `agg_types` | per pass: `matrix`, `ran`, `canonical`, `aggregate`, `closing`, `deny_final` |

Field notes:

- `geo` is the GeoIP stub's table, `{"203.0.113": "CN"}` (the first three octets map to an ISO country code); `{}` is a
  GeoIP that knows no address; `null` is no `mmdblookup` at all.
- `recompute`: a member with `"missing": true` has no snapshot file, which exercises the live-deny-file fallback.
  `master`, `deny_pre` and `match_pre` pre-seed the masterfile, live deny files and `match/generated` files. `deny` and
  `match` are `{file name: lines}` of every file in `deny/` and `match/generated/` after the run.
- `closing.sanity`: `original` and `final` are the strings the script prints in brackets, `verdict` is `PASSED`, `FAILED` or
  `null` (dedup off prints no sanity block), `masterfile_count` and `deny_count` are printed only on a failure,
  `uniq_master` and `uniq_deny` are the two duplicate lists, `empty_lists` the names under the "Empty Lists" heading.
  `pfctl` output lines are not part of the corpus.
- `suppress` v4: the suppression list is the script's `pfbsuppression.txt`; absent means no file. v6: it is the file
  `pfb_suppress_file_v6()` is given; absent is the function's fail-safe `FALSE`. The v6 `log` is the `pfb_logger()` text with
  the time stamp removed (the production messages carry no newline, so they weld into one line).
- `union`: `members` are `{file name: text}` written into the class dir (`deny`, `permit`, `match`, `native`); `kept` is
  the basenames `pfb_aggregate_member_list()` returns (placeholder-only files dropped). The memberlist file is
  `implode("\n", kept) . "\n"` as `pfb_build_aggregate_aliases()` writes it (`pfblockerng.inc:14708-14710`).
- `dnsblip`: `ip_files` are `{file name: text}` written into the DNSBL folder. The two branches of
  `pfblockerng_apply.inc:3209-3266` (concatenate when sources exist, else write the placeholder, `::`-prefixed for v6)
  are inline there, so the harness repeats that `if`; the concatenation is the production function.

### `pipeline`

The SEQUENCE is authored from `pfblockerng_apply.inc`; every stage's result is the appliance's own. Per pass:

1. Per changed feed (`:4505-4535`): write the parsed text to the deny folder, run the per-feed verb
   `pfb_ip_preprocess_args()` names (v4 only), then `pfb_ip_recompute_write_snapshot()`; any change sets `repcheck`.
2. Recompute (`:4603-4668`): `pfb_ip_recompute_matrix()`, then per family the seeded snapshot paths in config order and the
   `recompute` verb; then the legacy `pmax x <pmax>` verb when the matrix says so (`:4675`).
3. Per alias, per family, in config order (`:4812-4905`): suppression when `pfb_ip_suppress_body_for_vtype()` allows it (the v4
   verb, or `pfb_suppress_file_v6()`), then the canonical set of the concatenated deny files of the alias's feeds.
4. The Uber unions of `agg_types` (`pfblockerng.inc:14666`, called at `pfblockerng_apply.inc:4977`).
5. `closing` when `repcheck` is set and `pfb_ip_closing_pass_active()` allows it (`:5530-5538`).

The lab has no pf tables, so `pfb_pfctl_table_count()` is empty for every alias and every alias is eligible for the member read
(`:4806-4810`). Inputs: `switches` (`dup`, `agg`, `rep`, `drep`, `prep`, `supp`, `dmax`, `pmax`, `cc`, `ccwhite`, `ccblack`,
`geo`), `feeds` `[{name, alias, text...}]` in config order (`name` ends `_v4` or `_v6`; `alias` is the logical set), `suppression`
`{"v4": text, "v6": text}`, `agg_types` (class names), and `passes` `[{"changed": [names], "set": {name: text}}]`. A feed changes in
a pass only when listed; `set` gives its new text (the first pass uses the feed's own text).

## How the appliance replay runs today's code

- The shell script hard-codes its data paths. The harness makes a scratch tree on the VM, copies the INSTALLED
  `/usr/local/pkg/pfblockerng/pfblockerng.sh` into it, and rewrites with `sed` only the path constants of the init block
  (26 lines, listed in the harness). It then asserts that each constant was found exactly once before and rewritten exactly
  once after, and that no line of the init block still names `/var/db`, `/var/log`, `/usr/local/etc` or the GeoIP paths. A
  failed assertion fails the case loudly; nothing is guessed. `pathgrepcidr` and `pathaggregate` stay the appliance's real
  `grepcidr` and `iprange`.
- The copy runs through its real verb dispatch (`sh <copy> <verb> <args>`) with the argv of the `exec()` call sites of
  `pfblockerng_apply.inc` and `pfblockerng.inc`. `PFB_IP_PLACEHOLDER` and `PFB_REENTRY_TIMEOUT` are exported, so the script
  does not read config. No fixed sleep appears anywhere: each command runs to its own exit; the only timer is a hang cap
  (`timeout`, 1200 s per verb; 3 h for the whole harness).
- The PHP functions are the production ones, called after `require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc')`
  inside `pfSsh.php`, with `$pfb` directories pointing into the scratch tree. None is re-implemented in the harness.
- **The one stubbed input is GeoIP data.** The licensed MaxMind database is absent on lab VMs. `pathgeoip` points at a small
  `/bin/sh` script that answers from the case's `geo` table in `mmdblookup`'s output shape and prints nothing for an unknown
  address; `pathgeoipdat` points at an empty dummy file. That is data, not behaviour: every parse, count and decision on the
  answer is the production script's. `pathpfbphp`, the nested re-entry target, points at a file that does not exist, so a
  GeoIP download can never start.
- Large inputs are produced on the VM from the recipes above and read back as digests.

## Frozen run

The expectations were frozen from the lab run named below, on a pfSense VM of the smoke suite (QEMU guest, `FreeBSD:15:amd64`
package ABI), with the versions the replay itself records on the guest at the start of every run (`versions` block of
`ipset_corpus_actual.json`):

| Item | Value |
| --- | --- |
| pfSense (`/etc/version`) | `2.8.1-RELEASE` |
| FreeBSD (`uname -r`) | `15.0-CURRENT` |
| PHP (`php -v`) | `PHP 8.3.19 (cli) (built: Sep  9 2025 15:55:19) (NTS)` |
| `pkg info iprange grepcidr` | `iprange-1.0.4_2`, `grepcidr-2.0_1` |
| `iprange --version` | `iprange 1.0.4` |
| `grepcidr -V` | `grepcidr 2.0` |

The same replay on a Debian 13 development host (`iprange 1.0.4`, `grepcidr 2.0`, PHP 8.4 with the PHPUnit doubles of the
pfSense functions) gave byte-identical results for all 416 cases frozen first, which is evidence that the answers do not
depend on the FreeBSD base system, on DNS (hostnames are `.invalid`) or on timing. Core must still reproduce the appliance's
answer, not Debian's. `iprange` and `grepcidr` versions are the oracle: a case that changes with another version is an
escalation, not a tolerance.

Sixteen cases were added after review and frozen from lab run `local-100032-1794929801-69289bb42e6475fb` on the same versions;
in that run the 417 earlier results were byte-identical to their frozen expectations.

Replay cost on the VM: the whole harness takes under three minutes; the heaviest cases (2,000,000 members) take 5 to 18 s each.
`supp6_large_2m_members` (2,000,000 IPv6 members) took 72 s on the VM; `pfb_suppress_file_v6()` peaks near 1.1 GB of PHP memory
there (measured on a development host), so that case runs last and a memory failure would leave every earlier result.

The corpus covers every cell of the coverage matrix of issue #4033 except the n/a ones below. Two sizes differ from the issue's
wording: the legacy `pmax` verb is not run on 2,000,000 members (it greps every offender /24 against every deny file, quadratic
in the member count), and the 10,000-hole suppression cases use `/32` holes spaced 1597 apart and 10,000 adjacent holes.

## Behaviours Core must reproduce on purpose

Each is today's result, pinned by the named case; none is a recommendation.

- `iprange` writes a host as a bare address, never `/32` (`agg_host_spellings`, `agg_exact_union_hosts`); it merges contiguous
  rows and swallows contained ones (`agg_contained`); output is sorted numerically.
- `iprange` on bad tokens: a hostname is dropped (no DNS answer for `.invalid`, `agg_h_name`), `1.2.3.4/33` is dropped
  (`agg_h_pfx33`), a leading-zero octet is read as octal (`010.1.1.1` becomes `8.1.1.1`, `agg_h_leading0`), host bits are cleared
  (`1.2.3.4/24` becomes `1.2.3.0/24`, `agg_h_hostbits`), `a-b` ranges and dotted netmasks are accepted (`agg_h_range`,
  `agg_h_netmask`), CRLF, blanks and `#` comments are accepted (`agg_crlf`, `agg_blank_and_comment`), IPv6 text is mangled
  (`agg_v6_text`). The exit status was 0 in every case, so the "iprange failed, file untouched" path was never reached.
- The v4 `suppress` verb filters strictly before `iprange`: a bare host in the suppression list is dropped and logged
  (`supp4_bare_host_in_list`), CRLF makes every list token and every member row malformed (`supp4_crlf_list`,
  `supp4_crlf_members`), a trailing comment makes a token malformed (`supp4_malformed_list_tokens`), and member rows outside
  digits, dots and one `/mask` are dropped and counted, never resolved (`supp4_malformed_members`).
- `pfb_suppress_file_v6()` is laxer and normalises: it trims CR and blanks (`supp6_crlf_both`), rewrites every surviving member
  through `ip_range_to_subnet_array()` so a bare host becomes `/128` and duplicates stay (`supp6_no_overlap_normalises`,
  `supp6_unsorted_dups_no_nl`), and its log messages carry no newline, so they weld into one line (`supp6_malformed_tokens`). A
  missing suppression file is `FALSE` with the member file untouched (`supp6_missing_suppression_file`).
- A fully suppressed set is an empty file in both families, not the placeholder (`supp4_hole_equal`, `supp6_hole_equal`,
  `pipe_all_suppressed_v4`, `pipe_all_suppressed_v6`); the placeholder only appears when `closing` refills the deny file.
- `grepcidr -vf` (recompute dedup) compares numerically, not textually: an IPv6 host spelled differently in a later feed is pruned
  (`rec_v6_spellings_across_feeds`), a pattern with host bits covers its whole network (`rec_h_hostbits_dedup_on`), and a
  later feed's `/24` survives an earlier `/25` or host (`rec_own_host_then_cidr`, `rec_own_partial_cover_kept`). `0.0.0.0/0` and
  `::/0` are kept in their own file but kept out of the cumulative pattern stream (`rec_total_range_first`, `rec_v6_total_range`).
- In a later feed the dedup hands rows to `grepcidr -vf`, which prints a row only when it reads an address on it and no earlier
  row holds that address. So a row with no readable address goes (a name, a comment, a blank, a leading-zero octet, text glued
  to the address: `rec_later_h_rows_v4`, `rec_v6_later_h_rows`); an address is read anywhere on the row, and each end of an
  `a-b` row counts (`rec_later_range_rows_v4`); a family is read only when an earlier row of that family exists, so an IPv6
  pass led by the IPv4-spelled placeholder loses every pure IPv6 row (`rec_v6_v4_placeholder_first`,
  `rec_later_other_family_only_v4`). As patterns, earlier rows are read differently: a leading-zero octet is decimal, a prefix
  over the family's length and a name are no pattern, an `a-b` row covers its hosts (`rec_later_pattern_spellings_v4`). A CIDR
  row is tested only against earlier rows of its family at least as wide; with none it is kept unread, name and all
  (`rec_later_cidr_keep_mode_v4`).
- Three removals run through `awk 'FNR==NR{a[$0];next}!($0 in a)'`, which prints nothing when its first file is empty. So `_255`
  empties the feed when the only over-full keys are not octet prefixes (`pre_255_non_octet_key`); the `suppress` masterfile
  rewrite empties the masterfile when the alias has no row of its own but its name sits inside a sibling's
  (`supp4_master_alias_inside_sibling`); and the legacy `pmax` verb empties it when it holds no row of an offender /24
  (`pmax_master_no_matching_row`). Core reproduces all three; the defect is tracked in issue #4050.
- A verb that does not rewrite the masterfile leaves its category file alone: `recompute` with dedup off
  (`rec_dedup_off_master_untouched_v4`, `rec_dedup_off_master_untouched_v6`) and `pmax` with no /24 over the threshold
  (`pmax_v6_file_with_v4_rows`).
- The offender scan splits each row at the first three `.`-separated fields, so a CIDR row counts as a member of its first three
  octets (`rec_pmax_cidr_rows_count`, `pmax_cidr_rows_count`); the placeholder's `/24` never counts
  (`rec_pmax_placeholder_prefix`); `pfB_`-prefixed aliases never count and are never diverted (`rec_pmax_pfB_excluded`,
  `rec_dmax_pfB_excluded`); the legacy `pmax` verb skips `pfB*.txt` and `*_v6.txt` (`pmax_v6_files_untouched`).
- The collapsed `/24` of a shared offender belongs to the highest-priority alias (`rec_pmax_window_owner`); a reputation
  collapse widens to addresses no feed listed (`rec_pmax_widen_not_exact`), unlike `cidr_aggregate` (`agg_exact_union_hosts`).
- dMax country handling: the cc list is matched as a substring (`rec_dmax_cc_substring`); the consolidated exempt file is gated on
  `ccwhite=match` alone (`rec_dmax_exempt_match_ccblack_only`, `rec_dmax_exempt_match_both`); a missing GeoIP keeps the previous
  match artifacts (`rec_dmax_geoip_unavailable`) while a working GeoIP reconciles them away (`rec_dmax_stale_match_removed`).
  The per-feed `_rep` verb never writes `pfB_Match_Rep_<alias>.txt` for `ccblack=match` (its temp file is moved before it is
  filled, `pre_rep_ccblack_match`), and writes the `ccwhite=match` file only when the dedup token is empty
  (`pre_rep_exempt_match_dedup_off` against `pre_rep_exempt_match_dedup_on`); recompute writes both
  (`rec_dmax_matchdup`).
- `closing` writes the v4 placeholder spelling (`127.1.7.7`) into an empty `_v6` deny file
  (`clos_empty_v6_file_placeholder_spelling`); sanity counts exclude the placeholder (`clos_placeholder_rows_excluded`).
- `remove` deletes by `header*` glob, so a sibling whose name starts with the header goes too (`rm_prefix_glob_overmatch`), while
  its masterfile match is anchored (`rm_suffix_alias_not_overmatched`); a path-like header is refused (`rm_traversal_header`).
- The canonical set drops `#` lines and empty lines only: a CR stays part of the row, whitespace-only rows stay members, and a feed
  without a final newline welds onto the next feed's first row (`canon_crlf`, `canon_comments_blank`,
  `canon_weld_without_newline`); the order is byte order (`canon_byte_order_not_numeric`).
- DNSBLIP concatenation adds no record terminator (`dnsblip_unterminated_weld`), reads sources in byte order of the file name
  (`dnsblip_order_bytes`), and builds an empty file, not the placeholder, from an empty source (`dnsblip_empty_source`); only "no
  source at all" writes the placeholder, `::`-prefixed for v6 (`dnsblip_v6_empty_placeholder`).
- Uber union: a member holding only the placeholder or only comments is dropped, an empty member is kept
  (`union_placeholder_only_dropped_v4`, `union_placeholder_only_dropped_v6`, `union_comment_only_dropped`); with CIDR Aggregation
  on the union is `sort -u` of the raw rows, tokens included (`union_collapsed_on_v4`, `union_h_leading0_on`); with it off the v4
  union goes through `iprange` and hostile tokens are cleaned (`union_h_leading0_off`); v6 is `sort -u` either way
  (`union_collapsed_off_v6`); an empty union is an empty aggregate and a `#` consumer line (`union_all_dropped_is_empty`).

## Cells that are not groups today

- **`cidr_aggregate` for IPv6.** Every call site is gated to `_v4`: `pfblockerng_apply.inc:3908` (`$vtype == '_v4'`, GeoIP
  continents), `:4523` (`!$pfbadv && $list['vtype'] == '_v4'`, `:4526` the exec). The verb is never reached with v6 text.
  `agg_v6_text` records what the verb does to v6 text anyway (it mangles it), so Core has no reason to guess.
- **Per-feed preprocess (`_255`, `_agg`, `_rep`) for IPv6.** The chain is `if ($pfbadv && $list['vtype'] == '_v4')`
  (`pfblockerng_apply.inc:4509`); a v6 feed's parsed `.txt` is the snapshot itself (`:4530-4535`). `pre_*` cases are v4 only.
- **Reputation (`max`, dMax, pMax) for IPv6.** The recompute stage's `rec_do_rep` is set only when the family is `v4`
  (`pfblockerng.sh:1257-1262`), the PHP caller passes `off` to a v6 pass (`pfblockerng_apply.inc:4657`) and the legacy `pmax`
  verb skips `*_v6.txt`. `rec_v6_repmode_ignored_*` invoke the v6 pass with reputation on anyway and record that it is ignored;
  `pmax_v6_files_untouched` and `pmax_v6_only` record the legacy verb.

## Regenerating

To refreeze after an intended change of the oracle (never to make a failing case pass):

1. Run the replay on a lab box: `scripts/local-smoke.sh --ref "$(git rev-parse HEAD)" --filter ipset_corpus --no-two-vm` (add
   `--ports-ref <branch>` while a paired FreeBSD-ports change is unmerged). It
   writes `ipset_corpus_actual.json` into the run's diagnostics directory on the box.
2. Fetch it with `scp`, then, with a copy of this directory's `ipset.json` and the actual file:

   ```python
   import json


   doc = json.load(open("ipset.json"))
   act = json.load(open("ipset_corpus_actual.json"))["results"]
   for c in doc["cases"]:
       c["expect"] = {k: v for k, v in act[c["id"]].items() if k != "_seconds"}
   with open("ipset.json", "w") as f:
       json.dump(doc, f, indent=1, ensure_ascii=False)
       f.write("\n")
   ```

3. Review every changed `expect` by eye, then update the versions in the "Frozen run" section, and rerun the replay: it must be
   green without any edit.

## What the Go runner asserts

The Go runner (`corpus_test.go`, `corpus_groups_test.go`) reads every `expect` key as one of two kinds. **Asserted** keys are
compared with what the package returns; for a value the package does not return itself (a count, a flag, a file name) the
runner derives it from what is returned, and the row says so. **Presentation** keys are text or file lifecycle that the Core
Updater owns (slice 9, #4038), not asserted. A key in neither kind, or a key of the table missing from a case, fails the load,
so a new `expect` key can never be ignored silently. `TestExpectTableMatchesReadme` holds this table equal to the runner's.

The runner stands in for the Updater's file work with plain data: a file is its alias plus an extension (`.txt`, `.ip`), a
folder is a name-to-rows map, a missing snapshot falls back to the live deny file (or is skipped) before `Recompute`, the
match folder and the deny folder are the pre-seeded files overlaid with the returned lists, and the original folder is split
into the v4 count files and the v4 original feeds before `Closing`. The comparison rule above applies; a digest case compares
every member list it records as a digest. Every `rc` must be 0 or null: no Go function has an error path.

| Group | Key | Status | Reason |
| --- | --- | --- | --- |
| `cidr_aggregate` | `members` | asserted | the exact CIDR union; `CIDRAggregate` returns its rows |
| `cidr_aggregate` | `unchanged` | asserted | derived: the returned rows written one per line equal the input text |
| `cidr_aggregate` | `stats` | asserted | derived: input line count and output line count, recorded only when they differ |
| `cidr_aggregate` | `rc` | presentation | exit status; no Go function returns an error, so the runner requires 0 or null |
| `cidr_aggregate` | `log` | presentation | error-log text of IO failures; empty in every case |
| `preprocess` | `args` | asserted | derived from `Prepped.Ran`: `_255`, `_agg`, `_rep` in that order |
| `preprocess` | `ran` | asserted | derived: any stage ran |
| `preprocess` | `members` | asserted | the feed's rows after the stages |
| `preprocess` | `match_rep` | asserted | `Prepped.Match`; null is no rows, and an empty recorded list is refused |
| `preprocess` | `rc` | presentation | exit status; the runner requires 0 or null |
| `preprocess` | `log` | presentation | the GeoIP-missing line is a script message; its effect is in `members` |
| `recompute` | `deny` | asserted | every feed's rows; files not in the member list keep their pre-seeded rows |
| `recompute` | `master` | asserted | `RecomputeOut.Master`, both families |
| `recompute` | `mastercat` | asserted | `MasterCat` of the returned masterfile with dedup on; with dedup off the verb rewrites neither file, and the corpus never seeds this one, so it is empty |
| `recompute` | `counts` | asserted | derived: `<feed> <rows>` per feed, in member order |
| `recompute` | `match` | asserted | the match folder: pre-seeded files, minus `DropRep` and `DropExempt`, plus the lists written |
| `recompute` | `processed` | asserted | derived: the number of feeds the pass returned |
| `recompute` | `rc` | presentation | exit status; the runner requires 0 or null |
| `recompute` | `log` | asserted | containment only: the missing-snapshot lines must name the runner's own fallback decision; the rest is script text |
| `pmax` | `deny` | asserted | every deny feed's rows, untouched ones included |
| `pmax` | `master` | asserted | `PMaxOut.Master` |
| `pmax` | `mastercat` | asserted | `MasterCat` of the returned masterfile when `Applied`; else the verb rewrites neither file and the unseeded one is empty |
| `pmax` | `rc` | presentation | exit status; the runner requires 0 or null |
| `pmax` | `log` | presentation | error-log text of IO failures; empty in every case |
| `suppress/v4` | `members` | asserted | the remainder rows |
| `suppress/v4` | `master` | asserted | the masterfile after the alias rows are replaced |
| `suppress/v4` | `stats` | asserted | derived: input rows, remainder rows and masterfile rows, recorded only when the hole list names an entry (`Applied`) |
| `suppress/v4` | `log` | asserted | only the dropped-token lines, against `BadHoles` and the count of `BadMembers`; their wording is not asserted |
| `suppress/v4` | `rc` | presentation | exit status; the runner requires 0 or null |
| `suppress/v6` | `ok` | asserted | `Applied`; a missing suppression list never reaches the function and records `ok` false with the member rows untouched |
| `suppress/v6` | `members` | asserted | the normalised remainder rows |
| `suppress/v6` | `log` | asserted | the welded text is the only witness of the dropped tokens: compared with `BadMembers` and `BadHoles` |
| `suppress/v6` | `leftover_tmp` | presentation | temporary-file lifecycle of the atomic write |
| `remove` | `files` | asserted | the names left in each directory; `matchgen` is not handed to `Remove` and keeps every name |
| `remove` | `master` | asserted | the masterfile left; null when no row is left (the file is deleted) |
| `remove` | `mastercat` | asserted | `MasterCat` of the masterfile left; null when no row is left |
| `remove` | `messages` | asserted | derived from `Removed` and `Invalid` |
| `remove` | `rc` | presentation | exit status; the runner requires 0 or null |
| `closing` | `deny` | asserted | the deny folder after the placeholder refill |
| `closing` | `master` | asserted | the masterfile in byte order |
| `closing` | `sanity` | asserted | the verdict `Sanity`; the nested keys below |
| `closing` | `sanity.original` | asserted | `Sanity.Original` |
| `closing` | `sanity.final` | asserted | `Sanity.Final`; null with dedup off |
| `closing` | `sanity.verdict` | asserted | `Sanity.Passed`; null with dedup off |
| `closing` | `sanity.masterfile_count` | asserted | `Sanity.MasterCat`; recorded only on a failure |
| `closing` | `sanity.deny_count` | asserted | `Sanity.Deny`; recorded only on a failure |
| `closing` | `sanity.uniq_master` | asserted | `Sanity.DupMaster` |
| `closing` | `sanity.uniq_deny` | asserted | `Sanity.DupDeny` |
| `closing` | `sanity.empty_lists` | asserted | `Sanity.Empty`, as file names |
| `closing` | `rc` | presentation | exit status; the runner requires 0 or null |
| `closing` | `log` | presentation | error-log text of IO failures; empty in every case |
| `canonical` | `set` | asserted | the canonical set, in byte order |
| `union` | `kept` | asserted | `UnionOut.Kept` as file names, in order |
| `union` | `aggregate` | asserted | `UnionOut.Aggregate` |
| `union` | `consumer` | asserted | `UnionOut.Consumer` |
| `union` | `stats` | asserted | derived: `UnionOut.Before` and the aggregate's row count |
| `union` | `rc` | presentation | exit status; the runner requires 0 or null |
| `union` | `log` | presentation | error-log text of IO failures; empty in every case |
| `dnsblip` | `content` | asserted | the file text as lines, in order, the weld included |
| `dnsblip` | `final_newline` | asserted | derived: the content ends with a newline |
| `dnsblip` | `sources` | asserted | the names concatenated, as file names, in order |
| `dnsblip` | `built` | presentation | file-write success flag; no Go function returns an error |
| `matrix/recompute_matrix` | `invoke_v4` | asserted | `Matrix.InvokeV4` |
| `matrix/recompute_matrix` | `invoke_v6` | asserted | `Matrix.InvokeV6` |
| `matrix/recompute_matrix` | `dedup` | asserted | `Matrix.Dedup` |
| `matrix/recompute_matrix` | `repmode` | asserted | `Matrix.Mode` |
| `matrix/recompute_matrix` | `legacy_pmax_followup` | asserted | `Matrix.LegacyPMax` |
| `matrix/closing_pass_active` | `invoke` | asserted | the first result of `ClosingPass` |
| `matrix/closing_pass_active` | `alias_arg` | asserted | the second result of `ClosingPass` |
| `pipeline` | `passes` | asserted | one entry per pass; the nested keys below |
| `pipeline` | `passes[].matrix` | asserted | `PassOut.Matrix`, the five keys of `matrix/recompute_matrix` |
| `pipeline` | `passes[].ran` | asserted | `PassOut.RanV4` and `RanV6` |
| `pipeline` | `passes[].canonical` | asserted | `PassOut.Canonical`, each set in byte order |
| `pipeline` | `passes[].aggregate` | asserted | `PassOut.Union`: `kept`, `aggregate`, `consumer` per family; empty without an Uber union |
| `pipeline` | `passes[].closing` | asserted | `PassOut.Closing` as `closing` `sanity`; null when the closing pass did not run |
| `pipeline` | `passes[].deny_final` | asserted | `PassOut.Deny`, the deny folder after the pass |
