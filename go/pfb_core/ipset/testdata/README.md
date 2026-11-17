# IP set algebra parity corpus

Language-neutral record of what today's shell and PHP produce for the IP set algebra, member for member (issue #4033,
map #3813, slice 4 of `docs/specs/go-updater-pipeline.md`). Two runners replay every case and must agree with it:

- The appliance replay: `tests/smoke/test_smoke_ipset_corpus.py`, through the installed package's own `pfblockerng.sh` and
  PHP functions on a real pfSense box. This is the oracle: every `expect` is its output.
- Go: the `ipset` package's corpus test (a later step of #4033) replays the same file against Core.

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
  `sources` (DNSBLIP source names), which are compared **in order**: byte order or sequence is their contract.
- `"digest": true` marks a case whose input is large. Every output member list of that case is then recorded as
  `{"count": n, "sha256": "<hex>"}`: `n` lines, and the SHA-256 of the lines sorted bytewise (`LC_ALL=C sort`) and joined with
  `\n`, no trailing newline (the empty list is `count` 0 and the hash of the empty string). Digests are order-insensitive
  on purpose.
- Bookkeeping keys that begin with `_` are never part of an `expect`.
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

Not frozen yet: the cases carry no `expect`, so the replay reports every case as unfrozen and writes `ipset_corpus_actual.json`.

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

1. Run the replay on a lab box: `scripts/local-smoke.sh --ref "$(git rev-parse HEAD)" --filter ipset_corpus --no-two-vm`. It
   writes `ipset_corpus_actual.json` into the run's diagnostics directory on the box.
2. Fetch it with `scp`, then, with a copy of this directory's `ipset.json` and the actual file:

   ```python
   import json


   def strip(v):
       if isinstance(v, dict):
           return {k: strip(x) for k, x in v.items() if not k.startswith("_")}
       if isinstance(v, list):
           return [strip(x) for x in v]
       return v


   doc = json.load(open("ipset.json"))
   act = json.load(open("ipset_corpus_actual.json"))["results"]
   for c in doc["cases"]:
       c["expect"] = strip(act[c["id"]])
   with open("ipset.json", "w") as f:
       json.dump(doc, f, indent=1, ensure_ascii=False)
       f.write("\n")
   ```

3. Review every changed `expect` by eye, then update the versions in the "Frozen run" section, and rerun the replay: it must be
   green without any edit.
