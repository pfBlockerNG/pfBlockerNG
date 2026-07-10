# Architecture notes (dev-only)

Implementation detail extracted from `CLAUDE.md` to keep the always-loaded instructions
lean. This is the mid-level summary; the authoritative design for each item is its
`.ADRs/ADR_NN_*/` directory. Read the relevant section here before touching the code it
describes.

---

## DNSBL/ABP pipeline (ADR-06, ADR-07, ADR-10, ADR-12)

### ADR-06 — DNSBL list preprocessing moved to Python

DNSBL list preprocessing (parse → normalise → classify data/zone → build dicts + feed/group
index + `whiteDB`, then emit `pfb_py_count`) lives in `pfb_unbound.py`'s pure
`dnsbl_build_from_manifest()` / `build()`, fed by the PHP/shell-written manifest
(`/var/unbound/pfb_py_sources.json` + per-feed raw). PHP/shell only download + tag + run the
DNSBL-IP firewall pass. Decision-equivalence is pinned by `tests/test_adr06_*` (golden oracle,
build module, init-from-raw, PHP boundary); the init/peak-RAM kill-gate is
`benchmarks/spike_adr06_build.py` — it exits non-zero on NO-GO (`--report-only` forces exit 0).
Its synthetic `build()` on a generic runner is NOT the production number, so the CI
`benchmarks` job is **manual-only** (dispatch Tests with `run_benchmarks`, default off); the
real build-time/RAM regression gate is moving to the live smoke VM (timing `updatednsbl`
start→finish + unbound RSS) — see issue #76 and `.ADRs/ADR_06_DNSBL_Preprocessing_To_Python/`.

### ADR-07 — ABP / EasyList support

ABP/EasyList rule shapes are parsed **entirely in Python** — `parse_abp()` is the one DNS-only
ABP parser: it adds `@@` allow exceptions, regex (block `regexDB` / allow `allowRegexDB`, with
anchored patterns folded to dicts), and `$important`/`$badfilter` precedence resolved by a
6-band numeric scale, with a build-emitted `important_rules` flag preserving a byte-identical
fast path when no ABP precedence feature is loaded. (ADR-62 retired PHP's feed-level detection
that used to route a whole feed here — see below; which lines reach `parse_abp()` is now a
per-line decision, not a feed-level one.) Untrusted feed + user regex is guarded by an opt-in
"Limit long/complex regex" static cap (drops over-long/nested-quantifier patterns at load) plus
an always-on runtime warn/evict timer (warn 10 ms / evict 100 ms thread-CPU; snapshot-iterate,
evict-after-loop). Pinned by `tests/test_adr07_*` (decision spec/oracle, parser, reconcile,
matcher strata, emit/wire, regex safety, PHP boundary); the regex/ReDoS kill-gate is
`benchmarks/spike_adr07_regex.py` — it exits non-zero on NO-GO (`--report-only` forces exit 0),
runnable via the manual-only CI `benchmarks` job. See `.ADRs/ADR_07_ABP_DNSBL_Support/`.

### ADR-62 — per-line parse authority (retires PHP's feed-level ABP classification)

The DNSBL download loop used to maintain **feed-level** ABP state: a one-shot header sniff
(`$easylist`/`pfb_dnsbl_is_abp_header()`, prefix-matching `[Adblock`/`[uBlock`/`! Title:`) set a
flag that routed the WHOLE feed either through raw-verbatim capture (ABP) or PHP's extraction
pipeline (plain) — two parallel per-line paths, one classifier, one `.abp` on-disk marker
recording the decision for a reused (not re-downloaded) feed. ADR-62 deletes all of it:
`$easylist`, `pfb_dnsbl_is_abp_header()`, `$validate_header`, and the `.abp` marker are gone
entirely (issue #1083 later retired the stale-marker sweeps and `format_hint` end-to-end —
the NDJSON `kind` field carries the per-line discrimination; see the interchange section
below).

**The line itself, not the feed it came from, now decides its parser.** One pure PHP predicate,
`pfb_dnsbl_is_abp_rule_line()`, is the single capture guard — used at the download loop's
verbatim-capture site, the manifest writer (`pfb_unbound_python_sources()`), and mirrored by
Python's per-line routing in `build()` (the ADR-21 `||`/`@@||` short-circuit, broadened to the
full shape set: `||…`, `@@…`, `/regex/…$options`, and the element-hiding family
`##`/`#@#`/`#?#`/`#%#`/`#$#`). A matching line is captured verbatim and reaches `parse_abp()`
regardless of which feed it sits in; PHP never interprets the shapes — it is a capture guard,
not a parser, so `parse_abp()` stays the sole ABP authority. `pfb_dnsbl_is_skippable_control_line()`
gives the plain path the same `''`/`!`/`[…]` comment/control skip the old ABP branch had, with a
bracketed-IPv6 carve-out: `pfb_dnsbl_unbracket_ip6()` runs FIRST, so `[2604:2dc0::]` unwraps and
collects to the DNSBL-IP firewall pass (never treated as an ABP `[section]` comment); only a
non-IPv6 `[…]` is dropped as a control line.

The TLD-analysis pass (`tld_analysis()`) reads the aggregated `pfb_dnsbl.raw` (schema-v1 NDJSON,
issue #1083 — see below) and must skip a verbatim-captured line; this used to gate on the `.abp`
marker glob (`!empty($abp_feeds)`) — a latent bug (issue #1060) meant a *plain* feed's verbatim
`||…^` line was CSV-mangled whenever no feed was ABP-classified. The skip is now unconditional on
the row's `"kind"` field (`pfb_dnsbl_ndjson_parse_row()` returns `NULL`/non-`'domain'` for an ABP
row), independent of any marker or column count.

The deliberate behaviour changes are enumerated in the ADR's delta table (D1–D6, ADR.md §2) —
the headline rows: a bare hosts/plain domain line inside a feed that used to be
header-classified ABP now takes the plain `classify()` path (registrable parent → wildcard
ZONE, same as before; a deeper sub-domain → exact DATA — delta D1); `/re/`, `@@…` and
element-hiding lines in plain feeds are now honoured via `parse_abp()` (D2); and a plain
feed's `||<IP>^` anchor now collects to the DNSBLIP firewall alias where it previously
vanished (D6). The element-hiding capture requires an ABP cosmetic domain-list prefix
(`[A-Za-z0-9._,~*-]`) before the first marker — a hosts line's mid-line `` ## `` inline
comment, a `#`-led comment, or a CSV row's `#`-fragment URL is never captured — a
comma-first line is never captured either (issue #1067: a leading comma is not valid ABP
syntax; extracting it as a plain domain historically collided with the interchange file's
positional-CSV dialect, and now instead lands JSON-quoted in an NDJSON `"domain"` field —
immune to comma-collision by construction; see "DNSBL interchange format" below — but the
capture guard's own skip predates and is independent of that format change); the manifest
writer's plain fallback likewise skips non-captured `#`-bearing residue lines instead of
extracting a blockable column-1 "domain") — and `//`-led lines are comments,
never `/re/` regex rules. Every line class outside the delta table is
byte-identical to `origin/devel`, pinned by a corpus oracle (`tests/test_adr62_*`,
`tests/php/Adr62*Test.php`) whose golden fixtures were captured by running the real
functions at the pre-change base and are regenerated only through those same functions.
See `.ADRs/ADR_62_DNSBL_Unified_Line_Parsing/`.

### DNSBL interchange format — NDJSON schema v1 (issue #1083)

Every DNSBL interchange file the sync pass writes or reads between PHP stages — the per-feed
staging `.txt` (`{dnsdir}/{header}.txt`), the concatenated all-feeds `pfb_dnsbl.raw`, and the
TLD-analysis outputs `pfb_py_data.txt`/`pfb_py_zone.txt` — is **NDJSON schema v1**: one JSON
object per physical line, two kinds only:

```text
{"kind":"domain","domain":D,"log":L,"feed":F,"group":G}
{"kind":"abp","raw":R}
```

Every field is a **required, non-empty string**; a numeric/bool/null value or a missing key is a
shape violation the reader rejects (returns `NULL`), never a partial read. This supersedes the
pre-#1083 positional 6-column CSV dialect (`,domain,,log,feed,group`) and rides alongside ADR-62's
retirement of the file-level `.abp` marker (above). The per-feed `pfb_py_raw/*.raw` files the
ADR-06 manifest (`pfb_py_sources.json`) references, and `dnsbl_build_from_manifest()`/`build()`
that consume them, are **unaffected** — they stay the old bare-domain/verbatim-ABP-line format;
`pfb_unbound_python_sources()` is the sole translator, reading NDJSON `.txt` and writing plain
`.raw` per feed.

**Emit/parse primitives** (`pfblockerng.inc`): `pfb_dnsbl_ndjson_emit_domain_row()` /
`pfb_dnsbl_ndjson_emit_abp_row()` are the only writers — `json_encode()` with a **fixed key
order** (`kind` first), `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`, no pretty-printing,
exactly one trailing `"\n"`. This makes an emitted line **grep-stable**:
`pfb_dnsbl_ndjson_domain_needle()` builds `"domain":<json-encoded-value>`, and a hit is trusted
only once `pfb_dnsbl_ndjson_domain_row_verified()` re-parses the line AND confirms the `domain`
field matches exactly (a corrupt/foreign line could still substring-match; JSON's own quoting
means an `abp` row's `raw` payload can never literally embed the needle).
`pfb_dnsbl_ndjson_parse_row()` is the strict reader every PHP consumer shares;
`_dnsbl_parse_ndjson_row()` mirrors it in Python (`pfb_unbound.py`).

**Staging-generation guard + lazy rebuild.** The sync loop's verbatim-reuse fork
(`pfb_dnsbl_verbatim_reuse_active()`) additionally requires the staged `.txt` to be
**current-generation**: `pfb_dnsbl_staging_first_line()` reads the first NON-BLANK physical line
(a blank leading line must not mask stale content after it), and
`pfb_dnsbl_staging_is_current_generation()` accepts it only when that line actually PARSES via
`pfb_dnsbl_ndjson_parse_row()` (or the file is absent/wholly blank) — a leading `'{'` byte alone is
not proof (a truncated/corrupt line rejects too). A feed whose `.txt` predates the #1083 flip (a
pkg-upgrade leftover, never redownloaded since) fails that check and is **never verbatim-reused**
— the sync loop instead reparses from the existing `.orig` download cache via the same machinery a
Reload uses (logged `Rebuild`), refetching over the network **only** when `.orig` itself is absent
too. A rebuild that reparses `.orig` and finds ZERO domains (e.g. a corrupted/HTML-error-page
download) converges staging to empty (`pfb_dnsbl_stale_rebuild_converge_txt()`) rather than
leaving the stale `.txt` in place — otherwise the guard would re-detect stale-generation and
re-log `Rebuild` on every subsequent pass, forever, with the stale lines silently double-counted.
This runs regardless of the row's `state` (`Hold`/`Flex`/`Enabled`) — a `Hold` row only skips
`pfblockerng.php`'s own change-detector pre-check (`pfblockerng_sync_cron()`, which bypasses a
Held row with an existing `.txt` outright), never the DNSBL loop's rebuild fork inside
`sync_package_pfblockerng()`, which has no `Hold` special case. Pinned live-VM
(`tests/smoke/test_smoke_adr62.py`): `test_adr62_stale_generation_rebuild_hold_row_orig_present`
(`.orig` present → byte-identical reuse, no refetch) and its
`test_adr62_stale_generation_rebuild_orig_absent_triggers_download` sibling (`.orig` absent →
genuine refetch); off-appliance reproduction: `tests/php/DnsblStagingGenerationGuardTest.php`
(`sync_package_pfblockerng()` itself has no PHPUnit harness, issue #993 — the zero-domain
convergence is proven by driving the real guard functions through the loop's exact decision
sequence, not the loop itself).

**No version marker — every future interchange change must be backwards-compatible.** A
deliberate design choice (issue #1083): the schema carries no version field and the codebase has
no migration/back-compat mechanism for a schema bump. Any future change to this interchange
format must therefore be additive/backwards-compatible with schema v1 as shipped — a breaking
change would need the staging-generation-guard's rebuild-from-`.orig` pattern again, not a new
mechanism.

**Accepted transitional window.** A pkg upgrade does **not** trigger an immediate DNSBL rebuild:
`custom_php_resync_config_command` (`pfblockerng.xml`) calls `sync_package_pfblockerng()`, but
`pfblockerng_install.inc` sets `$g['pfblockerng_install'] = TRUE` for the whole install/upgrade
process, and `sync_package_pfblockerng()` early-returns on that flag before reaching the DNSBL
loop (`pfblockerng.inc:15197`, "Sync terminated during boot process").

The window does **not** reliably close at the first `cron` tick, either. `pfblockerng_sync_cron()`
(`pfblockerng.php`) only calls `sync_package_pfblockerng('cron')` when at least one in-scope feed's
own Update Frequency check actually ran `pfb_update_check()` this tick (`$pfb['update_cron']`); a
tick where every feed is still within its own frequency window — or simply has nothing new to
fetch — instead calls `sync_package_pfblockerng('noupdates')`, which sets `$pfb['save'] = TRUE` and
skips the entire DNSBL loop (`pfblockerng.inc:15902`'s `!$pfb['save']` gate) as a save-only pass.
The window actually closes at the **first pass that enters the DNSBL loop**: a tick where some
feed's frequency is due, an explicit Force (Run Now), or any config-edit-driven sync. On a box
where every DNSBL row is `Hold`/`Never` (or simply never redue), the window can persist
indefinitely — it is not a bounded 15-minute-to-hourly window in that case. Impact stays bounded to
attribution, not blocking: the in-memory `dataDB`/`zoneDB` loaded at the last successful build keep
blocking unaffected; the Alerts page's per-domain feed/group lookup (`pfblockerng_alerts.php`),
unable to grep-match the legacy positional-CSV `pfb_py_data`/`pfb_py_zone` against the NDJSON-shaped
needle, reports the domain's feed/group as literal `Unknown` until the window closes. Accepted as a
self-healing (if potentially long) window, not a defect.

**Downgrade is unsupported by design (no back-compat rule).** Reverting the package to a
pre-#1083 build while NDJSON-shaped interchange files remain on disk is not supported — the
mirror image of "No version marker" above: schema v1 has no forward-compat mechanism, and
equally no backward one. The old build's `dnsbl_build_from_manifest()`/`build()` read the retired
`format_hint` manifest key via a bare `feed_row["format_hint"]` index (`KeyError` on a NEW-shaped
manifest, which never emits it); `dnsbl_build_from_manifest()`'s own `except Exception` catches
that and returns `None` (fail-closed — no matcher swap), so `init()` falls back to the legacy CSV
loaders over `pfb_py_data`/`pfb_py_zone` — which, under NEW code, are NDJSON, not CSV. Those
loaders (`csv.reader` with a strict six-field row gate) split each NDJSON object on commas into
the wrong field count and skip every line, so `dataDB`/`zoneDB` load EMPTY — nothing crashes and
nothing bogus loads. Net effect: DNSBL blocking on a downgraded box
goes silently ineffective (fail-open — the resolver itself stays up, queries simply stop
matching) until every feed redownloads and reparses through the old build's own dialect again.
There is no supported downgrade path; the fix is to stay on, or return to, a #1083-or-later build.

**Benchmark evidence** (issue #1083, `scripts/bench_dnsbl_line_parsing.py`, 1,000,000 lines,
5 iterations × 2 trials, base = the pre-#1083 merge-base `e9dda731`):

| Surface | base wall | branch wall | Δ wall | base peak RSS | branch peak RSS | Δ RSS |
| --- | --- | --- | --- | --- | --- | --- |
| PHP `pfb_unbound_python_sources()` (per-line `json_decode`) | 1.8409s | 2.4440s | **+32.76%** | 31.7 MiB | 31.9 MiB | +0.44% |
| Python `dnsbl_build_from_manifest()` (unchanged `.raw` reader) | 3.8041s | 3.7889s | −0.40% | 660.2 MiB | 649.0 MiB | −1.69% |

The PHP surface's per-line `json_decode` **does** regress the staging-parse pass — +32.76%
wall-clock, above ADR-62's own SS7 criterion-2 kill-threshold (25%). That threshold governed
ADR-62's build-path change; for this format migration the breach was reviewed and **accepted
as an explicit owner exception at landing** (issue #1083 / PR #1178) — a real, measured cost
of the self-describing per-line format, traded off against its grep-stability/attribution
guarantees, with the follow-up optimization tracked in issue #1177 (batched decode, a leaner
encoding). The Python surface — an unrelated code path, since it reads the untouched
per-feed `.raw` — shows no regression, as expected. On-disk size (1,000,000 domain rows, a realistic domain-length mix per
`benchmarks/_corpus_raw.py`'s distribution): the old 6-column CSV dialect is 45,719,338 bytes
(45.72 B/row) vs the new NDJSON's 99,719,338 bytes (99.72 B/row) — **2.18× the size**
(≈ +118%).
`benchmarks/spike_adr06_build.py` (the ADR-06 Phase-1 spike) is unaffected: it drives a
self-contained synthetic corpus (`benchmarks/_corpus_raw.py:59`) and never imports
`pfb_unbound.py` or touches the interchange format (`benchmarks/spike_adr06_build.py:53`).

### ADR-10 — zero-downtime DNSBL data swap

A DNSBL **DATA** update is a **zero-downtime background swap — no Unbound restart**. The module
holds the matcher strata as one frozen `Snapshot` behind a single module ref; a reload-watcher
daemon thread (`kqueue` `EVFILT_VNODE`, mtime-poll fallback) wakes on a generation **sentinel**
(`/var/unbound/pfb_py_reload`), rebuilds off the live snapshot, and **atomically swaps** the
single ref (GIL-atomic → visible to every query thread, no torn read, no dropped queries).
PHP/shell **atomically publish** the manifest (stage → `fsync` → `rename`) then **flip the
sentinel** (next integer) — the all-or-nothing commit. After flipping, PHP **waits (bounded)
for the watcher's applied-generation marker** to catch up, so the reload call returns only once
the new lists are LIVE (queries keep flowing on the old snapshot during the wait — still
zero-downtime; this restores the "lists live on return" invariant the restart had, so the
ADR-12 `post` hook sees the new state).

- **Data = swap; config = restart:** feed/cron updates AND the user custom-list edits (alerts
  Lock/Unlock + "add to whitelist" + customlist add/delete, #51) take the no-restart fast path;
  an `unbound.conf`/mode/Resolver change still restarts.
- **Fallback to restart (fail-safe)** when the swap can't run: a RAM-constrained box (PHP RAM
  gate primary, Python free-page probe secondary — the ~2× transient build/swap footprint is
  `benchmarks/spike_adr10_swap.py`'s kill-gate), the feature/python mode off, Unbound down, a
  staged config change, or a prior swap/sentinel error.
- **Cache on swap:** Reports reset; `decisionDB` cleared (no stale decision); **block→allow
  immediate** (blocks not C-cached since #43); **allow→block** flushes the prior resolved answer
  — a targeted delta flush for the #51 single-domain case, TTL-bounded for feed/cron (not a
  regression — the restart is TTL-stale there too).
- **Fail-closed:** a bad/partial build keeps the last-good snapshot serving.

Pinned by `tests/test_adr10_*` (snapshot equivalence, fail-closed swap, watcher); idle
decision-identity stays guarded by `tests/test_adr06_*`/`tests/test_adr07_*`. See
`.ADRs/ADR_10_Zero_Downtime_DNSBL/`.

### ADR-12 — update hooks (PHP/shell, no Python)

Admin-VETTED `pre`/`post` **scripts** run once per update pass from
`sync_package_pfblockerng` in `pfblockerng.inc` — `pfb_run_hooks($when, $ctx)` reads enabled
hooks from `installedpackages/pfblockerng/config/0/hooks` (`{script, when, enabled,
description, timeout}`), runs each **as root** via `/usr/bin/timeout … <script>` in list order,
captures output to the pfBlockerNG log, and **non-zero/timeout → log + continue** (a hook can
never abort/stall an update; no enabled hooks ⇒ byte-identical pass). Security model: `script` is
NOT a GUI-typed command — it is a `hook_<when>_*.{sh,py}` file a shell-access admin places in
the dedicated `hooks/` dir (`PFB_HOOK_SCRIPT_DIR`, created at install, separate from the per-feed
`list_scripts/`); the picker/save/runner all gate on the same allow-list
(`pfb_hook_script_valid()`), so a GUI user can only *select* a vetted file, never inject shell.
Admin-only **Update Hooks** settings tab (`www/pfblockerng/pfblockerng_hooks.php`, same WebCfg
priv as the other settings).

Exported env (only these are promised):

- `PFB_WHEN` (`pre`|`post`)
- `PFB_TRIGGER` (`cron`|`update`|`force-reload` — the ADR's `force-update` collapses to `cron`)
- `PFB_POST_INSTALL` (`1` when the run is the install/upgrade resync — the reconfigure right after
  the package is installed/upgraded, else `0`) and `PFB_PRE_UNINSTALL` (`1` when the run is the
  pre-deinstall teardown as the package is uninstalled, else `0`). **Always emitted as `1`/`0`**
  (#695, like `PFB_IP_CHANGED`), on both `pre` and `post`. Published by `pfb_hook_lifecycle_ctx()`
  from `$pfb['hook_lifecycle']` (set by `install.inc` / the pre-deinstall); a normal cron/manual/force
  update sets both to `0`. The pre-deinstall tears pfBlockerNG down (and fires `PFB_PRE_UNINSTALL=1`)
  ONLY on a genuine removal: `pfb_pkg_op_tears_down()` gates on the detected pkg op (#697) — a real
  uninstall and a MAJOR OS upgrade's mass-removal are `pkg delete` → teardown; a package
  upgrade/reinstall / minor in-place update is `pkg install -f` / `pkg upgrade` → SKIP (pfBlockerNG
  stays live, its resync re-applies). A major OS upgrade is reinstalled after reboot, settings kept
  by `keep=on` (the default; `keep=off` wipes config only when the teardown runs — an uninstall or a
  major OS upgrade, not a normal package update). `''` (undetectable op) fails safe to teardown.
- `PFB_PKG_OP` (`install`|`upgrade`|`reinstall`|`delete`, else `''`) — the actual package-manager
  operation, read by `pfb_pkg_operation()` from the pkg/pkg-static ancestor's argv (#697). It both
  gates the pre-deinstall teardown (above) and rides to hooks so a hook can tell a fresh install
  from an upgrade. The parser skips pkg's arg-taking GLOBAL options (`-o -j -c -r -C -R` + long
  forms) that precede the subcommand — pfSense passes `-c`/`-r` during an OS upgrade. `''` on a
  normal cron/manual pass (not run under pkg).
- post-only `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED` (`0`|`1`, accurate — guard on these)
- `PFB_CHANGED_IP_ALIASES` (post-only, space-separated `pfB_*` IP firewall aliases updated this
  pass) and `PFB_CHANGED_DNSBL_GROUPS` (post-only, space-separated `DNSBL_*` groups updated this
  pass — split from the IP aliases because DNSBL groups are not firewall aliases); both sourced
  from the signal the pass already computes, Reputation-mode-independent, empty on a no-op pass
- `PFB_STATUS` (the sole remaining stable reserved placeholder: always `ok` — do not branch on
  its value)

The `post` hook sees the new DNSBL state live (ADR-10's bounded wait-for-apply runs before the
pass returns). Hooks live in config ⇒ replicate to a CARP/HA secondary and run on whichever node
updates. The shipped **HAProxy recipe** (README) is a `post` hook guarded on
`[ "$PFB_IP_CHANGED" = "1" ]` whose command pipes `haproxy_check_run(1)` (graceful reload)
through `/usr/local/sbin/pfSsh.php`; validation = `php -l`/PHPStan/ShellCheck + a maintainer
manual smoke (no pytest oracle). See `.ADRs/ADR_12_Update_Hooks/`.

### ADR-11 — aggregate ("Uber") aliases live smoke — `tests/smoke/test_smoke_aggregate.py`

`test_smoke_aggregate.py` (marker `smoke`, same ADR-04 harness/`deployed_vm` shape as the hooks
file) drives the opt-in `pfb_agg_types` multi-select end-to-end on a real pf table: none-selected
no-op, Deny builds the table with **no firewall rule** (Native), cross-type non-leakage
(Permit ∉ Deny aggregate), additive `{Deny}`→`{Deny,Permit}`, never-empty `.lst` on an empty
union, teardown on deselect, the DNSBLIP→Deny fold, and the **post-hook freshness** leg (the
`post` hook reads `pfctl -t pfB_Deny_Aggregated_v4 -T show` + its env after a forced feed change
and sees the **new** IP + the alias in `PFB_CHANGED_IP_ALIASES`). Setter `helpers.set_aggregate_types`
(read-back-guarded CSV scalar) + `aggregate_table`/`aggregate_consumer_path`. The membership
decision is unit-pinned off-box in `tests/php/AggregateMemberListTest.php`; HAProxy
referenceability + the GeoIP/suppress content spot-check stay ADR §7 maintainer-manual. The
General-page `pfb_agg_types` render is covered by the ADR-14 Tier-A gate (next section).

### ADR-40 — content-addressed alias-table reload gating + forward-delta apply

**Reload gate (ADR-40 Phase 3).** Alias tables are reloaded iff their **final membership set**
changed — not iff a member feed was re-fetched. On each pass `pfb_alias_set_different()` compares
the freshly computed canonical set (post-suppression, post-dedup, `LC_ALL=C sort -u`) against the
last-applied mirror `/var/db/aliastables/pfB_<Alias>_v{4,6}.txt`. Only aliases whose set
actually changed enter `$pfb_alias_lists` and trigger a reload. `PFB_CHANGED_IP_ALIASES` is
driven by this content-diff set — signal-only, no forced `filter_configure()` (same precedent
as #517/#519's ip_unlock path, which applies a real `-T replace` and signals the change without
triggering a rule reload). The empty-mirror case (first load / alias reset) treats the set as
changed (missing mirror → always reload). `filter_configure()` still fires only for actual
firewall *rule* changes.

**Forward-delta apply (ADR-40 Phase 4).** For a changed alias table, pfBlockerNG applies the
diff as `pfctl -t <t> -T add -f <adds>` then `-T delete -f <dels>` (lock-hold O(churn) rather
than O(table)), falling back to atomic `pfctl -T replace` when the churn ratio ≥
`PFB_DELTA_CHURN_THRESHOLD` (0.05), when `pfb_alias_delta_mode='replace'` is forced, or on the
boot/enable-disable path. In all cases the **end-state invariant** holds: `pfctl -t <t> -T show`
membership is the canonical desired set — identical to what a full replace would load.

**Config fields** (both registered in `PfbConfig` / `pfb_cfg_registry()`; IP Settings page):

| Key | Type | Default | Notes |
| --- | ---- | ------- | ----- |
| `pfb_alias_delta_mode` | `alias_delta_mode` | `'auto'` † | `PfbAliasDeltaMode` enum: `auto`/`delta`/`replace` |
| `pfb_alias_delta_batch` | `plain` | `'512'` | Chunk size for `-T add`/`-T delete`; clamped to \[64, 4096\] |

† New-install default. An already-configured install is **grandfather-seeded to `'replace'`** (the
pre-ADR-40 full `-T replace`) at install/upgrade by `pfb_alias_delta_mode_install_default()` +
`pfblockerng_install.inc`, so an upgrade preserves the operator's prior apply path instead of
silently switching to delta; only a brand-new install takes the `'auto'` absent-default. Run-once
via the `!isset` guard, so an explicit operator choice (incl. an explicit `'auto'`) is never overridden.

**Cross-list correctness.** When dedup (`enable_dup`) or reputation is active, a feed-A change
that shifts sibling table B's effective membership (through the shared `masterfile` dedup path)
causes B's desired set to be recomputed and diffed this pass, so B reloads when its membership
actually changed. This closes the §1.2(1) eventual-consistency gap from the old feed-fetch model
(where B would defer until a Force Reload). The hybrid-scope guard (`pfb_cross_list_scope()`)
enables the all-aliases recompute only when a cross-list feature is active; with both off, a
single-feed change remains surgical (only that feed's table).

**Smoke coverage** (`tests/smoke/test_smoke_adr40.py`, marker `smoke`, dispatch-only):

- Idempotence (P3): second update over unchanged feed → `PFB_CHANGED_IP_ALIASES=''`; pf table
  unchanged.
- Surgical reload on content change (P3): feed updated → alias in `PFB_CHANGED_IP_ALIASES`; pf
  table reflects new set; old IP absent.
- Delta apply, small churn (P4, mode=delta): one-IP swap → end-state contains only new IP;
  `PFB_CHANGED_IP_ALIASES` fires.
- Replace-mode override (P4, mode=replace): same one-IP swap → end-state also correct; proves
  delta and replace are equivalent (same `pfctl -T show` membership).

Cross-list dedup/reputation and multi-million-entry data-plane latency are deferred to the
maintainer manual-smoke checklist (ADR-40 §7) — the `enable_dup`/`enable_drep` toggles need
additional harness helpers not yet in the fixture set, and real lock-hold measurement requires
live traffic on production hardware.

---

## IP dedup + reputation: batch recompute (issue #1084)

The incremental per-feed `duplicate()`/`reputation_dmax()` masterfile-surgery pass is retired.
`pfblockerng.sh recompute` (`pfb_recompute()`) does one deterministic pass **per family**
(`v4`/`v6`) over pristine per-feed snapshots, owning cross-feed dedup and v4 dMax/pMax
reputation for every caller `pfb_ip_recompute_matrix()` (`pfblockerng.inc`) routes through it.
`reputation_pmax()`/`remove()`/`process255()`/`closingprocess()` are untouched and still run
their own paths where the matrix doesn't route through recompute.

**Snapshot store + memberlist contract.** Each v4-Deny feed's post-`_255`/`_agg`/`_rep`
preprocessed output is persisted to `$pfb['snapdir']` as `<header>.snap`
(`pfb_ip_recompute_write_snapshot()`), alongside the `.aggcount` original-count sidecar
`closingprocess()` sums. `recompute`'s memberlist argument lists these snapshot paths, one per
line, in **priority order** — the alias is derived by stripping the directory then everything
from the first `.` onward, and an alias absent from the list is treated as removed (its
masterfile rows and deny file are not carried forward).

**Invocation matrix** (`pfb_ip_recompute_matrix()`), gated on the feed-changed trigger
(`$pfb['repcheck'] && !$pfb['save'] && $pfb['enable'] == 'on'` — a quiet pass, e.g. a
DNSBL-only tick, invokes no recompute at all):

| `enable_dup` | reputation (`drep`/`prep`) | invocation |
| --- | --- | --- |
| on | any | full: v4 + v6, cumulative dedup, masterfile/mastercat rebuilt |
| off | on | v4-only passthrough (overlaps retained, no masterfile — parity with today's dedup-off double-counting) |
| off | off | not invoked — parse output stands |

Both `drep` and `prep` on is a tie-break: recompute applies dMax, then the caller execs the
legacy `reputation_pmax()` over the emitted deny files unmodified (`legacy_pmax_followup`).

**Direct vs offender-subset paths.** Offender detection is a hashmap count straight over the
owned files (no sort). An empty actionmap (no offenders, repmode off, or GeoIP unavailable)
takes the **direct path** — each owned file is blank-filtered and per-alias sorted straight
into its `.txt.new` sibling. A non-empty actionmap takes the **offender-subset path** — only
offender-/24 rows are diverted into one small tagged set, windowed by a priority-attribution
awk after one small sort, and reinjected into their owners' keep sets before the same per-alias
emit runs. Reputation cost scales with offender rows, not class size.

**Masterfile is a regenerated per-family artifact.** `masterfile.new` is pre-seeded with the
live masterfile minus this pass's family-suffixed rows (a sibling family's rows survive
untouched), then every owned alias's surviving rows are appended — never patched in place.

**Ownership = config priority order.** A row's owning alias is decided by memberlist order
(`pfb_ip_recompute_family_headers()`, following `$pfb['existing']['deny']`'s config order) —
a deliberate delta from the old `duplicate()` accretion, where ownership fell out of whichever
feed's per-run dispatch call happened to run (and therefore land in the masterfile) first.

**v6 joins dedup**, unlike the old incremental path (which only `duplicate()`'d v4):
`recompute` is invoked for v6 iff `enable_dup` is on (the "full" row above) — never on
`enable_dup` off, since v6 has no reputation to trigger it standalone. v6 never runs
reputation (v4-only): when invoked it always takes the direct dedup-only path.

**Upgrade seeding fallback.** A header with no snapshot yet (a pre-#1084 install, or a header
never recomputed on this box) seeds one from the live deny `.txt`
(`pfb_ip_recompute_seed_snapshot()`) so an existing alias survives its first post-upgrade pass
instead of vanishing from the memberlist. A failed seed copy is logged, never silent.

**GeoIP-outage keep-previous.** If `mmdblookup`/the GeoIP database is unavailable mid-pass,
dMax's offender classification bails (rides the direct path, no reputation applied) and the
swap's finish arm **keeps every previous match artifact untouched** rather than reconciling a
missing `.new` sibling away as "no match this pass" — that reconcile is only safe when GeoIP
actually ran. A dropped GeoIP feed cannot silently erase yesterday's match files.

**Match-mode multi-alias emission (a deliberate delta).** `ccblack=match` writes
`match<alias>.txt` for **every** member alias sharing an offender `/24` window, not just one.
The old `reputation_dmax()` wrote only the first alias in glob order (whichever the filesystem
happened to enumerate first); the recompute window pass iterates every alias present in that
window's `winaliases` set, so a shared offender is now visible to every alias whose rows are in
it — more complete match coverage, not a bug.

**Suppression re-applies whenever recompute ran.** Recompute rewrites every family alias's deny
file whenever it runs at all — including one resurrected only because a sibling alias's feed
changed. The suppression pass and the closing report both key off "recompute ran this family
this pass" (`$pfb_recompute_ran_v4`/`$pfb_recompute_ran_v6`), not "this alias's own feed
changed", so a quiet alias whose content was rewritten by a sibling's trigger still gets
suppression/reporting applied to it.

**Both dRep and pRep on: the execution order flipped.** The old incremental path ran pMax's
`exec` first, then dMax's — the reverse of recompute's order: recompute applies dMax to every
family alias first (inside its own `pfb_recompute()` pass), and the legacy pMax `exec` runs
**afterward**, over recompute's already-collapsed deny files. Observable consequence: an offender
window dMax already collapsed to one `/24` is not something pMax discovers again the old way (it
now inherits recompute's collapse instead of independently re-detecting the same offender).

**Swap is a checked sequence, not an atomic batch.** Every recompute artifact's `.new` sibling is
moved into place with its own rc-checked `mv`, in sequence — never one atomic-looking group. A
stage failure *before* the swap starts cleans up every `.new` sibling this pass wrote and aborts
cleanly; a `mv` failure *within* the swap itself cannot be rolled back (earlier moves in that same
sequence may already be live), so it only logs the failing artifact and aborts further swapping —
the family can be left mixed until the next successful pass.

---

## Web UI test tiers (ADR-14) — `tests/smoke/ui/`

The Web-UI suite **reuses** the smoke `smoke_vm` fixture + `helpers.py` (no separate harness)
to drive the live webConfigurator. It is off the default `pytest` like the rest of
`tests/smoke/`. Three tiers, each its own pytest marker:

- **Tier A — `ui_render`** (cheap/hermetic, the **PR gate**): authenticated-HTTP GET of every
  pfBlockerNG page → 200, body free of `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`,
  a page-specific marker present, **and** no new on-box `php_error.log` line. **Never HTTP 200
  alone** — body + marker + `php_error.log` is the oracle.
- **Tier B — `ui_e2e`** (daily/on-demand): CSRF-POST flows asserting the **effective**
  `config.xml`/`pfctl`/unbound state via `helpers.config_get`, not the HTTP response.
- **Tier B — `ui_browser`** (daily/on-demand): headless Playwright/Chromium reusing the auth
  session (injected `PHPSESSID` cookie — **no second login**), exercising the JS-only UX and
  capturing per-page screenshots. Needs the separately-downloaded Chromium binary
  (`python -m playwright install chromium`); module-level `importorskip` SKIPs cleanly without it.

Run a tier against a smoke VM exactly like the smoke suite — re-enable the package and select
the marker (`SMOKE_ADMIN_PASSWORD` must be set; if unset the UI fixtures FAIL everywhere — CI and
local alike — so a missing secret can't pass the tier by skipping it):

```sh
python -m pytest tests/smoke/ui -m ui_render --override-ini="addopts="
```

The reusable `ui-tests.yml` (`workflow_call` + `workflow_dispatch` + daily `schedule`) is
matrix-parametric on image-ref/version and tier-selectable, **one GH job per (tier × version)**
(`fail-fast: false` → "Re-run failed jobs" re-runs only a flaky leg). Tier A gates PHP/JS PRs
(folded into "All tests passed"); Tier B is schedule/dispatch only (non-PR-blocking);
`release.yml` `needs:` the full suite (`tier: all`, the `ui-suite` job) before publishing, each
leg re-runnable in isolation. The version axis is parametric but runs the **single CE image**
today (B1) — adding one is a one-line `DEFAULT_VERSIONS` append + image-ref wire (IMAGE_RUNBOOK).
Diagnostics (screenshots + VM logs + smoke snapshot) upload `if: always()` as
`ui-diagnostics-<tier>-<variant>-<version>` (variant = ce/plus, e.g. `ui-diagnostics-browser-ce-2.8`).
The §7 browser reliability numbers are **CI-pending**; the
browser leg has a one-line demote/drop switch (drop `browser` from `DEFAULT_SCHEDULE_TIERS` +
run release `ui-suite` as `tier: functional`). Full design: `.ADRs/ADR_14_UI_UX_Testing/`.

**Selective dispatch (ADR-14 + smoke).** A bare `gh workflow run ui-tests.yml` (and
`smoke.yml`) defaults to **`scope=impacted`**: the **min CE leg only** plus, with no `-f
pytest_filter`, the test modules **changed vs `origin/devel`** (auto-derived by
`scripts/impacted-tests.sh` from the `prepare`/`gen` step). `-f pytest_filter="..."` **overrides** the
auto-derivation — pass it for the tests covering changed *non-test* code, which a live-VM suite
can't map automatically. `-f scope=full` restores the every-ci:true-leg whole-tier run.
`schedule`, `workflow_call` (`test.yml` Tier-A gate, `release.yml` `tier: all`), and
`version-tracker.yml`'s post-bump dispatch (which now passes `scope=full`) all stay **full** —
only a bare `workflow_dispatch` is lean. Local runs are pytest-native: pass `--filter`/`-m`
through (`scripts/local-smoke.sh` forwards them — `--filter` becomes pytest `-k` — and treats `-m smoke` as a default).

**Module sharding (#797).** Orthogonal to selective dispatch (which narrows *which* tests run),
sharding splits an already-selected, full-marker run across N parallel workers. CI's `smoke.yml`
takes a `shards` input (default 3): a CE leg with the default `smoke` marker and no `-k` filter
expands into `shards` matrix entries (`resolve-legs.sh legs`), each running one shard's slice —
module-level, or test-level for an oversized module (issue #855's hybrid split, below); Plus legs
shard exactly like CE — same `shards` count and defaults (issue #856 validated same-identity
parallel Plus boots under the single `SMOKE_PLUS_*` identity — run 28749104142: both shards green,
no license errors); the count is
clamped to the leg's `test_*.py` module count; and a filtered (`pytest_filter` set) or
non-`smoke`-marker leg collapses to 1 shard — the same empty-slice hazard `local-smoke.sh --shards`
guards against (an N-way split can leave a shard with zero matching tests). The residual case — a
plain `smoke`-marker slice made up entirely of repo/reboot-only modules, first reachable around
`shards=20` with today's marker density — is absorbed at the mechanism layer: under
`--shard-total` > 1, `run-smoke.sh` maps pytest exit 5 ("no tests ran") to success as a partition
artifact (the shard union is still the whole run); every other non-zero rc stays fatal, and
unsharded runs keep exit 5 fatal. Locally, `scripts/local-smoke.sh --shards N` leases N boxes
concurrently, one shard each. Both paths are the same mechanism by construction, not a parity
re-implementation: `scripts/run-smoke.sh --shard I --shard-total N` hands its `--paths` dir to
`scripts/shard-modules.sh` over the dir's direct-child `test_*.py` modules (see "Duration-balanced
module sharding (#816)" and "Hybrid test-level split (#855)" below) and splices the resulting
slice in as the leftmost pytest args; `smoke-on-box.sh` forwards `--shard`/`--shard-total`
unchanged and independently refuses N>1 for any non-`smoke` marker, including the UI tier (a
small, non-module-fungible suite that always runs as one unit). Diagnostics stay per-shard: CI
names each leg's artifacts `smoke-diagnostics-<image_name>-<pfsense_version>-s<I>` and
`pfBlockerNG-pkg-<image_name>-s<I>` (two shards of one leg each build their own `.pkg` — a shared
cross-shard build is a deferred optimisation); local runs get one log file per shard under the
`--shards` run's kept log dir.

**Duration-balanced module sharding (#816).** `shard-modules.sh` splits by measured LOAD, not
blind position, when it can: if `<test-dir>/module-durations.txt` exists it assigns modules by
greedy LPT (longest processing time first) — order the dir's modules by table weight DESC then
path/nodeid ASC under `LC_ALL=C`, and place each in turn into the currently least-loaded shard
(ties break to the lowest shard index) — else it falls back to the original deterministic
round-robin (the fallback `tests/smoke/ui/` and any table-less dir still rides). A module missing
from the table, or carrying a row `<= 0`, is clamped to a 0.01s epsilon weight rather than 0 — the
minimum every module needs so it always adds load, which is what keeps the first
`min(module-count, shard-total)` LPT assignments landing on that many *distinct* shards (same
empty-shard condition as round-robin: only reachable when module-count < shard-total). A stale
table row for a module no longer in the dir is simply never looked up — harmless. The table has
TWO row granularities (issue #855): a module-BASENAME sum row (`<module> <seconds>`) and one
per-test row (`<module>::<test> <seconds>`); `scripts/shard-modules.sh` reads the per-test rows to
decide the hybrid split below. Generated by `scripts/module-durations.sh` from pytest
`--durations=0` CI logs (sum setup+call+teardown at both granularities); regenerate via
`scripts/module-durations.sh <shard-log>... > tests/smoke/module-durations.txt`, feeding the
DISJOINT CE shard logs of exactly ONE leg-version's full run — never a Plus leg (it re-runs the
whole suite, so it is not disjoint and double-counts every test) or a repeated/mixed log.

**Hybrid test-level split for oversized modules (#855).** A module whose table weight exceeds the
per-shard target (`total-weight / shard-total`) AND carries per-test rows is split at TEST
granularity instead of riding whole on one shard (a module lacking per-test rows, or a table-less
dir, still rides whole). The shard with that module's largest summed test weight becomes its
CARRIER: it gets the module's path plus a `--deselect <nodeid>` pair per test assigned elsewhere;
every other shard holding some of its tests gets plain node-ID lines. Because pytest's
`--deselect` matches by nodeid PREFIX (not exact equality), a naive deselect can also strip an
unrelated LONGER sibling id (e.g. `test_cron_detects_changed_local_feed` is a literal prefix of
`..._same_second`) — a prefix-safety fixpoint promotes any such sibling onto the shorter test's
shard before printing. Two residual gaps this can't close, both requiring a stale/incomplete
**committed** table: a test added after the last regen whose id string-extends an off-carrier
known id still runs on no shard (the carrier's deselect strips it too), and a renamed/removed
test's stale row becomes a bare nonexistent node-id arg (pytest exit 4). `tests/test_shard_union.py`
carries a committed-table drift gate for both cases — run it after any table regen or before
adding a test to an oversized module. Both assignment modes are deterministic (same inputs ->
byte-identical output) and end by printing the requested shard's assigned lines — module paths,
bare node IDs, and `--deselect`/node-ID pairs — sorted `LC_ALL=C`, a `--deselect` line always
immediately followed by its node-ID value.

**CI as parallel dispatch (ADR-47 P5).** Workflows are thin dispatch wrappers; all step logic
lives in shared scripts that run identically locally and in CI:

- `scripts/resolve-legs.sh` — six subcommands covering the inline blocks previously
  repeated across `smoke.yml`, `smoke-single.yml`, and `ui-tests.yml`:
  `legs` (scope ladder + THREE-WAY jq + filter derivation), `image-ref`, `digest`,
  `exact-image-name`, `vm-identity`, `scrub`. `legs` prints the resolved JSON to
  stdout for same-step capture and also writes `scope=`, `ci_matrix=`, `pytest_filter=`
  to `$GITHUB_OUTPUT` for cross-step consumption.
- `scripts/lib/git-env-scrub.sh` — sourceable POSIX-sh lib exporting `pfb_scrub_git_env()`,
  which unsets the six GIT_\* vars that the pre-commit hook exports and that corrupt
  git operations in child processes. Sourced at entry by every production script and
  aliased as `scrub_git_env()` in `tests/shell/spec_helper.sh` for the spec suite.
- `scripts/git-env-scrub-guard.sh` — meta-assertion guard enforcing the discipline:
  (1) no raw `unset GIT_DIR` outside the lib; (2) every spec that calls `git` must
  call `scrub_git_env`. Run as part of `scripts/parity-guard.sh`'s sibling checks.
- `scripts/parity-guard.sh` — extended with Rule 4 (direct `python[3] -m pytest
  tests/smoke` bypass) and Rule 5 (inline-derived arg to `run-smoke.sh`). Runs clean
  on the actual `.github/workflows/` directory (`sh scripts/parity-guard.sh .github/workflows`).

---

## Alerts/Reports render pipeline — `pfblockerng_alerts.php`

Reported events are attributed **twice**: once at event time by the log writers
(`pfb_unbound.py` for `dnsbl.log`/`dns_reply.log`; the filterlog daemon for the `ip_*` +
`unified` logs, incl. feed match, GeoIP, rDNS, ASN), and again at render time by the
Alerts page, which re-validates each displayed row against the *current* feed/DNSBL state
to show drift (the "Previous Feed:" strikethrough) and pick action icons. The render-time
pass is per-row shell pipelines + per-row SQLite cycles and dominates page load time; the
`dnsblcache` report cache is wiped on every DNSBL swap (ADR-10 P3), and the IP render path
has no cache at all. Full model, cost table, ordering constraints (the DNSBL filter gate
matches *corrected* fields and cannot be hoisted), and the day-to-day variability
mechanics: [`alerts-reports-pipeline.md`](alerts-reports-pipeline.md). Perf work:
issue #809.

---

## HTTP mock-feed load smoke (ADR-16 Part C) — `tests/smoke/test_smoke_feeds.py`

`test_smoke_feeds.py` (marker `smoke`) is the **only suite file that drives the real HTTP fetch
path**: each case points an `IpCase`/`DnsblCase` at a URL served by `_MockFeedServer` (the
in-runner stdlib HTTP server reachable by the guest at `http://10.0.2.2:<port>/<name>` over
SLIRP — survives the egress block), runs a real Force Update, and asserts the feed loaded on the
box. Every other smoke case supplies a local file via `write_local_feed`.

**Sample fixtures** live under `tests/smoke/fixtures/` (committed to the repo):

| File | Format | Type |
| --- | --- | --- |
| `ip_plain_cidr.txt` | plain IPv4 + CIDR | IP v4 |
| `ip_range.txt` | IPv4 range `a-b` | IP v4 |
| `ip_ipv6.txt` | IPv6 single + CIDR | IP v6 |
| `dnsbl_plain.txt` | plain domain | DNSBL |
| `dnsbl_hosts.txt` | hosts `0.0.0.0 domain` | DNSBL |
| `dnsbl_abp.txt` | ABP / EasyList (\|\|d^ block, @@ allow) | DNSBL |

All data is inert (RFC 5737 / RFC 3849 IPs; `uuid-<hex>.com` domains). The `mock_feeds` fixture
auto-registers every file in `tests/smoke/fixtures/` when it starts; individual cases call
`mock_feeds.feed_url("<name>")` to get the guest URL.

**How `_MockFeedServer.register()` works.** `register(name, body)` stores the body in an
in-memory dict; the HTTP handler serves it verbatim (plain body, no `Content-Encoding`, no
`Content-Disposition`) at `GET /<name>`. The fixture directory variant
(`mock_feeds.feed_url("<filename>")`) reads the file on first access and registers it under its
basename. `curl` does not send `Accept-Encoding: gzip` nor `If-Modified-Since`, so the mock
needs no compression or ETag/304 logic — plain body is fine.

**Adding a new format fixture.**

1. Drop the fixture file into `tests/smoke/fixtures/` (inert data — TEST-NET IPs / `uuid-*.com`
   domains; never RFC 6761 TLDs or HSTS-preload names).
2. Update `tests/smoke/fixtures/README.md` with the member/non-member set.
3. Add a case in `test_smoke_feeds.py` using `mock_feeds.feed_url("<filename>")`.

**Kill-gate / gate status (ADR-16 §7).** The Part-C premise is falsifiable: "a Force Update
reliably fetches an HTTP feed from the mock over SLIRP and loads it, in CI". The reliability bar
is **≥ 4/5 clean runs**. This test is `OPTIMISTIC-GO, PENDING-CI` — all 6 representative formats
are authored; the live CI run (the `ui-tests`-labeled PR suite) decides GO vs DEMOTE. If < 4/5
clean, `test_smoke_feeds.py` is demoted to dispatch-only (Part A still ships; the local-file load
coverage in `test_smoke_matrix.py` / `test_smoke_abp.py` remains). The final decision is recorded
in `.ADRs/ADR_16_Feeds_Tabs_And_Feed_Smoke/RESULTS/05_Results.txt`.

## Locale policy (ADR-26)

`pfblockerng.sh` (and any shell added here) sets locale **explicitly, per-command, never
exported process-wide**. Three rules:

1. **Byte-exact machine-data set ops → inline `LC_ALL=C`.** Every `sort -u` / `uniq` / `comm` /
   `join` (and any plain `sort` whose order feeds a downstream compare/diff) over machine data
   (IPs, punycode domains) carries an inline `LC_ALL=C` on that command — e.g.
   `LC_ALL=C sort -u "$f"`. Under a UTF-8/language `LC_COLLATE`, distinct strings can share a
   collation weight, so `sort -u`/`uniq` silently drop one as a "duplicate" — for a blocklist that
   is a silent hole in the block set, with no error. `C` makes uniqueness byte-exact and identical
   on FreeBSD and Linux. The data reaching the shell is already ASCII (IPv4/IPv6 + punycode; the
   ADR-08 IDN work is done in Python), so byte semantics are exactly right here.
2. **Never `export LC_ALL=C` / `LANG=C` script-wide.** A global export poisons every child the
   script spawns (`php`, `host`/`drill`, `mmdblookup`, list pre/post scripts) — ASCII-crippling
   tools that are legitimately UTF-8-aware and changing error-message language, date, and number
   formatting. It also creates a partial-adoption hazard: `comm`/`join`/`diff`/`uniq` need **all**
   inputs in the **same** collation, so a global default silently mismatches any pipeline mixing a
   `C`-sorted file with a locale-sorted one. Keep locale surgical and inline.
3. **Future raw-Unicode text → split the knobs, resolve `LC_CTYPE` at runtime.** No shell path
   today classifies or case-folds raw (un-punycode'd) Unicode — that work lives in Python. **If**
   one ever appears it does **not** use bare `C` (which silently misses non-ASCII); it splits the
   two concerns: `LC_COLLATE=C` on any sort/set op (deterministic order + byte-exact uniqueness)
   and `LC_CTYPE=<UTF-8 locale>` for the classify/case-fold step, where the UTF-8 locale is
   **resolved at runtime** — never hardcoded (`C.UTF-8` is not universal; see the table).

**`C.UTF-8` availability** (why the `LC_CTYPE` value must be resolved, not assumed):

| Platform | `C.UTF-8`? | Note |
| -------- | ---------- | ---- |
| FreeBSD 15 / pfSense CE 2.8 | yes | present |
| glibc Linux | yes (>= 2.35, 2022) | older/minimal images may lack it |
| musl / Alpine | n/a | the `C` locale is already UTF-8 |
| macOS (BSD libc) | **no** | only `en_US.UTF-8` & friends — the main off-appliance dev/CI hole |

**Deferred — resolver is a copy-ready snippet, not shipped code (ADR-26 Phase 2).** There is **no
caller today** (no raw-Unicode shell path), so the runtime resolver is kept here as a snippet
rather than an unused function in `pfblockerng.sh` — that would ship to users (release archives
carry `src/`) as dead code and trip "unused" lints. Drop it in (naming per the `pfb_*` convention)
the day the first `LC_CTYPE` caller lands (space-indented here for Markdown — reindent to tabs
when pasting into `pfblockerng.sh`):

```sh
# Resolve the best available UTF-8 ctype locale ONCE, with a fallback chain. Prefer C.UTF-8;
# else the first *.UTF-8 from `locale -a`; else C (degraded ASCII ctype, never wrong-silently).
# Read by future LC_CTYPE call sites; NEVER exported.
pfb_resolve_utf8_ctype() {
    _avail=$(locale -a 2>/dev/null)
    if printf '%s\n' "${_avail}" | grep -qiE '^C\.(UTF-8|utf8)$'; then
        printf 'C.UTF-8\n'
    elif _u=$(printf '%s\n' "${_avail}" | grep -iE '\.(UTF-8|utf8)$' | head -n 1) && [ -n "${_u}" ]; then
        printf '%s\n' "${_u}"
    else
        printf 'C\n'
    fi
}
# Usage at a (future) raw-Unicode site — split the knobs, never export:
#   _ctype=$(pfb_resolve_utf8_ctype)
#   LC_COLLATE=C LC_CTYPE="${_ctype}" awk '...Unicode-aware...'
```

## Self-hosted pkg distribution — ABI is NOT 1:1 with a pfSense version (varver keying is mandatory)

**Load-bearing invariant. Do not "simplify" it away** (it keeps getting wrongly re-derived). The
self-hosted catalog (ADR-17/20) is keyed by a **varver** — the pfSense edition+version slug
`ce-2.8` / `plus-26.03` (`catalog_name_from_version()` in `scripts/build-repo-portable.py`) —
**never** by the pkg `${ABI}` (`FreeBSD:<major>:<arch>`).

**Why (the trap).** pkg's `${ABI}` carries only the FreeBSD major + arch. A pfSense `${ABI}` is
**NOT in 1:1 correspondence** with a pfSense version or its package-build inputs (the `php<XY>` /
`py3<XY>` flavors). Multiple pfSense versions/editions can share one FreeBSD major — hence one
`${ABI}` — while shipping **different** PHP/Python. So `FreeBSD:16:amd64` does not tell you whether
the box needs the php8.5 build or some later/other php build; an `${ABI}`-keyed conf would serve the
wrong package. The varver encodes exactly the `(edition, version) → (php, py)` mapping that `${ABI}`
cannot.

**Proof (live, 2026-06, Plus 26.03.1).** `pkg config abi` → `FreeBSD:16:amd64`, but **Netgate's own
repo URL** is
`pkg+https://pfsense-plus-pkg.netgate.com/pfSense_plus-v26_03_1_amd64-pfSense_plus_v26_03_1` — it
bakes the **full product version** (`v26_03_1`), not the ABI. Netgate does not key by `${ABI}`
**because `${ABI}` is not unique to a version**; their proprietary `pfSense-repoc` rewrites the whole
version-pinned conf on each upgrade (server-side) instead.

**Do NOT conclude "the current matrix is 1:1, so `${ABI}` suffices."** That 1:1 (CE→FreeBSD15,
Plus→FreeBSD16) is **incidental and not guaranteed** — CE and Plus have shared FreeBSD bases before,
and the supported window can hold two versions on one major with different deps at any time. A
fail-closed CI guard may reject a matrix that introduces such a collision, but the design **stays
varver-keyed regardless**.

**Upgrade consequence (verified — libpkg + `pfSense-upgrade`).** Because the conf is version-pinned it
cannot auto-follow a version-crossing upgrade the way an `${ABI}` template would, and there is **no
third-party pre-solve hook** to rewrite it in time: `pfSense-repo-setup`/`repoc` manage only Netgate's
own `${PRODUCT}.conf` — they enumerate only `${PLUS_CERT_BASE}/pfSense-repo-*.name` (Netgate's own
staging dir) and never rewrite foreign conf content; a `+PRE_INSTALL` runs inside the locked libpkg
transaction where nested `pkg` is impossible; libpkg pins every version at solve time. Foreign confs
(ours) **persist** across upgrades (pfSense leaves them untouched), but a varver conf goes **stale**
on a version change and can only be corrected by a **separate, later** pkg run — a structural
one-pkg-run lag. The boot-time generator hook below closes that lag.

**`rc.d` generator hook (`scripts/rc.d/pfblockerng_repo_generate.sh`).** Installed on-box by
`add-repo.sh` into `/usr/local/etc/rc.d/`; runs at every boot. It is a pure conf **regenerator**:
for each of our conf files that exists, it detects the box's `<varver>/<arch>` and
**unconditionally overwrites** the conf with the canonical body (channel-correct URL + a marker
comment). **No `pkg` call, no network, no snapshot, no reconcile, no parse-and-compare** —
re-deriving the conf from scratch is strictly simpler than diffing and patching one in place, and
never wrong. Key properties:

- **Self-guarding:** a conf is regenerated only if it already exists; if neither the release nor
  the nightly conf is present the hook is a complete no-op (an orphaned hook left after the user
  removes our repo is inert, and a channel the user never bootstrapped is never created).
- **Ordering:** `REQUIRE: FILESYSTEMS` (so `/usr/local` is mounted) and `BEFORE: NETWORKING` — it
  runs *before* anything that could invoke `pkg` over the network, so the conf is already correct
  by the time the box first reaches for a catalog. Running this early is safe precisely because it
  is local-file-only (no network, no daemon).
- **Folded detection (KISS):** edition = "`/etc/product_label` contains `Plus`" → `plus`, else
  `ce`; version = major.minor of `/etc/version`; arch = the leaf of `pkg config abi`. This mirrors
  `catalog_name_from_version()` in `scripts/build-repo-portable.py`; there is **no** separate
  `/lib` detection helper (it is folded into the one self-contained hook file).
- **Byte-identical output:** the conf body the hook writes is byte-for-byte identical to
  `add-repo.sh --print-conf`, `build-repo.sh --print-conf`, and `build-repo-portable.py
  --print-conf` (drift-pinned by `tests/test_add_repo_conf.py` across all four producers).
- **Detection-failure safety:** if version or arch cannot be resolved the hook leaves the existing
  conf **unchanged** (warns) rather than writing a malformed URL.
- **Always `exit 0`:** every code path ends in `exit 0`. A non-zero exit would wedge the rc.d
  chain; this hook must never do that.
- **Verified findings (ADR-39 §1.3):**
  - *Every varver-changing upgrade reboots.* pfSense cannot swap the running ABI / PHP /
    Python interpreters live; any upgrade that changes build inputs rides the staged
    boot-upgrade (kernel `next_stage` annotation → reboot). So the hook is guaranteed a
    turn after every upgrade that could invalidate the conf.
  - *No third-party pre-solve hook exists.* Confirmed on CE 2.8.1 + Plus 26.03.1:
    `pfSense-repo-setup` only symlinks Netgate's own `${PRODUCT}.conf`; the proprietary
    `repoc` rewrites Netgate's conf content (server-side); neither touches foreign confs.
  - *`/usr/local/etc/rc.d/*.sh` survive reboots and BE-clone upgrades.* `/usr/local` rides
    the boot-environment clone, so a non-package hook placed there persists across the very
    upgrade it heals (maintainer-confirmed from long operational use).

**Published one-file bootstrap (`site/add-repo.sh`).** The repository copy of
`scripts/add-repo.sh` installs the `rc.d` hook by copying the sibling file
`scripts/rc.d/pfblockerng_repo_generate.sh` via `dirname "$0"`. That path resolution
fails when the script is **piped** into `sh` (e.g. `fetch … | sh`) because `$0` is then
`sh`, not the script path. `gen_landing.py`'s `write_site()` generates a self-contained
`site/add-repo.sh` by splicing the hook body between the `PFB_EMBED_HOOK_BEGIN` /
`PFB_EMBED_HOOK_END` marker comments inside `pfb_emit_embedded_hook()` — using a
**single-quoted heredoc** (`cat <<'PFB_HOOK_HEREDOC'`) so none of the hook's dollar-signs
or backticks are expanded. The installed file is identical to the repository sibling.
The published file lives at `pfblockerng.github.io/pkg/add-repo.sh` and is what the
landing page's copy-paste one-liners point to.

Full design: ADR-39.

### Publish pipeline, generators, and repo smoke (ADR-17/20)

- **Publish pipeline:** the catalog is hosted + deployed by the **separate `pfBlockerNG/pkg`
  repo** (its `.github/workflows/publish.yml`), NOT this repo. Each run it builds the current
  **devel** `.pkg` by running this repo's own `scripts/build-pkg-portable.py` against a checkout
  of the source (a reusable workflow can't be reused cross-repo — it runs in the caller's context
  — so it runs the *script*), folds in **every** Release `.pkg`, regenerates the per-ABI catalog
  with `scripts/build-repo-portable.py`, and deploys to its **own** GitHub Pages via same-repo
  OIDC `actions/deploy-pages` → `pfblockerng.github.io/pkg`. **No deploy key, no cross-repo
  secret** — everything it reads from here is public. Triggers: daily `schedule` +
  `workflow_dispatch`. This repo's `release.yml` `repo-publish` job just fires `gh workflow run
  publish.yml -R pfBlockerNG/pkg` (auth: a GitHub App token via
  `actions/create-github-app-token@v3`, secrets **`PKG_GITHUB_APP_ID`** +
  **`PKG_GITHUB_APP_PRIVATE_KEY`** — `Actions:write` on `pfBlockerNG/pkg` only) so a release
  publishes within seconds; additive + isolated (`needs: [release]`), so its failure never breaks
  `release`/`sync-ports-fork`/`attach-pkgs`. The FreeBSD `pkg repo` fidelity path
  (`scripts/build-repo.sh`) is retained as a script only.
- **Generators + bootstrap:** `scripts/build-repo-portable.py` (primary catalog gen),
  `scripts/build-repo.sh` (fallback + the single `--print-conf` conf template),
  `scripts/add-repo.sh` (client bootstrap — channel is a FLAG: no-arg = release repo, `--nightly`
  = nightly repo; `priority: 100`, `pkg update` + verify). The default writes the shared release
  conf `/usr/local/etc/pkg/repos/pfblockerng.conf` (repo `pfblockerng` carries BOTH stable and
  devel packages, Netgate-style — pick at install time); only `--nightly` writes its own
  `pfblockerng-nightly.conf`. The emitted conf is byte-identical across all three (drift-pinned in
  `tests/test_add_repo_conf.py` + `tests/test_build_repo_portable.py`).
- **Repo smoke flow:** `tests/smoke/test_repo_install.py` carries its **own marker `repo`** (a
  distribution flow, **deselected from `-m smoke`**) — install-from-our-repo (no `-f`), cross-repo
  precedence (both directions vs a `netgate-decoy`), `pkg upgrade` `_1`→`_9`, and the catalog
  accepted from both generators. The ADR-20 **variant topology** (each leg's ABI / PHP / Python /
  catalog, and the opposite-edition guard) is **derived entirely from the version matrix** — never
  hardcoded CE/Plus: `tests/smoke/_matrix.py` (unit-tested off-box by `tests/test_smoke_matrix.py`)
  reads `SMOKE_MATRIX_JSON` (smoke-single.yml injects `read-version-matrix.sh --print-build` at job start,
  egress open), falls back to running that script, and SKIPs the topology cases when neither is
  available. Per-leg `SMOKE_ABI`/`SMOKE_PHP_VERSION`/`SMOKE_PY_FLAVOR` select within it; adding a
  pfSense version needs no edit here. (`scripts/install-from-repo.sh` likewise derives its
  `py3xx-*` deps from the matrix via the box's ABI.) Dispatch: `gh workflow run smoke-single.yml -f
  pytest_marker=repo` (or `repo-install.yml` once it lands on `devel`). The gated
  `test_install_from_live_pages_url` (`SMOKE_REPO_LIVE_URL`) hits the real `pfblockerng.github.io`
  URL — post-merge (a new `workflow_dispatch` workflow is only dispatchable from the default
  branch).

## IP autorule reconciliation — immutable user rules (ADR-41)

The IP-side autorule pass in `sync_package_pfblockerng()` reconciles pfBlockerNG's own
`filter/rule` entries each update via the pure helper `pfb_build_autorule_list($existing_rules,
$pfb_generated, $order, $float, $in_ifaces, $out_ifaces)` (pfblockerng.inc). It is a **stable
bucket reorder**: every surviving rule is sorted into one of four buckets — pfB pass/match, pfB
block/reject, user pass/match, user block/reject — and the buckets are concatenated in the
sequence the `pass_order` setting dictates. The pfB-owned rules (descr starts `pfB_`, **excluding**
the DNS-redirect/DoT-block bypass rules, which are kept like user rules) are regenerated unchanged;
user rules pass through verbatim. Whole buckets move — nothing **inside** a bucket is reordered,
and **no user rule is duplicated (#532), dropped, or content-mutated** (bar the legacy `_v4`
alias-suffix upgrade). Cross-bucket movement is exactly what `pass_order` means and is allowed.

The reorder is applied **independently to the two pf rule groups**, because pf evaluates them
separately: the **floating** group (always carries the DNSBL/match pass rules; also the pfB
permit/deny when float mode is on, since the call site then builds them from `base_rule_float`) and
the **interface** group (the per-interface pfB permit/deny when float mode is off). Each group
orders its own four buckets by the same ORDER table (GUI `pfblockerng_ip.php`):

```text
order_0 | pfB p/m | pfB b/r | user (not split)
order_1 | user p/m | pfB p/m | pfB b/r | user b/r
order_2 | pfB p/m | user p/m | pfB b/r | user b/r
order_3 | pfB p/m | pfB b/r | user p/m | user b/r
order_4 | pfB p/m | pfB b/r | user b/r | user p/m
absent / unknown → order_0
```

A single before/after anchor for the whole pfB block **cannot** express this: `order_1`/`order_2`
split the user rules (user pass/match in front, user block/reject behind the pfB block), so a pfB
**Permit** list (pass) must precede a user **Block** — putting the whole user block of rules ahead
of the pfB block lets a user Block shadow a pfB Permit. `order_4` likewise places the user's own
**Block** before its **Pass** (intended `pass_order` semantics, not a removable reorder).

The contract (per-order placement incl. the pfB-Permit-vs-user-Block trap, user-rule fidelity,
pfB-rule-set identical, idempotence, and behavioural equivalence to the years-proven `8c4c482`
emission on every dup-free config) is pinned off-appliance in
`tests/php/AutoruleListOracleTest.php`; the live data-plane precedence sweep is
`tests/smoke/test_smoke_autorule_immutable.py` (ADR-04). Design + the corrected pf-precedence
analysis: `.ADRs/ADR_41_Immutable_User_Firewall_Rules/` (`RESULTS/05`).

## Managed firewall object ownership and teardown (ADR-35)

A small shared ownership-and-teardown layer for pfBlockerNG-managed objects in pfSense-core sections
(`virtualip/vip`, `nat/rule`, `filter/rule`) lives inlined in `pfblockerng.inc` (it originated as
ADR-35's `pfblockerng_fwobj.inc`, since folded into the main include — there is no separate file).
A pfBlockerNG object is **owned** if and only if its `descr` carries a recognised marker. Marker
recognition is the union of the `pfB_` prefix (new convention, already in use on the filter side) plus
the exact legacy strings (`pfB_AUTO_VIP_v4`, `pfB_AUTO_VIP_v6`, `pfB DNSBL`, `pfB DNSBL - DO NOT EDIT`)
— never rewritten, because stored values are frozen (ADR-28). Three pure helpers express the layer:
`pfb_is_managed_obj()` is the single recognition predicate; `pfb_find_managed_obj($section, $marker,
$guard?)` returns the first owned row matching a marker, with an optional secondary guard (e.g. the
VIP's `subnet == stored IP`); `pfb_remove_managed_obj($section, $marker, $guard?)` filters OUT every
owned row matching a marker and writes the section back — the teardown/sweep primitive. A row that
fails the ownership check is NEVER removed (user-safety invariant).

The remove-by-marker pass runs in two places: (1) **on disable**, as a defensive teardown after
`pfb_manage_dnsbl_vip` and `pfb_create_dnsbl` have already run their own removal — catching any
half-written state those paths may have left; (2) **on deinstall**, before
`pfb_remove_config_settings()` wipes the `installedpackages/pfblockerng*` reference data. This ordering
is load-bearing: the VIP teardown reads the pfBlockerNG config sections to resolve the VIP double-guard
reference; if the config were wiped first, the reference would be gone and the guard would skip orphans.

There is no per-feature registration seam. ADR-36 (DNS-redirect) and ADR-37 (DoT/DoQ block) reuse this
layer directly: each builds its rules inline and calls `pfb_find_managed_obj` / `pfb_remove_managed_obj`
with its own `pfB_DNS_Redirect_<iface>_{v4,v6}` or `pfB_DoT_Block_<iface>` marker for reconcile and
teardown. User objects (no pfB marker) are **never** touched by any remove pass — asserted by smoke
tests that seed sibling user rows and prove they survive.

Live-VM smoke: `tests/smoke/test_smoke_managed_objects.py` (marker `smoke`).

## Optional NAT DNS-redirection (ADR-36)

When enabled, pfBlockerNG creates and maintains a pair of NAT port-forward (rdr) rules per
selected interface — one for IPv4 (`inet`, target `127.0.0.1:53`) and one for IPv6 (`inet6`,
target `::1:53`) — that redirect all outbound port-53 DNS traffic to the firewall's own
resolver. The firewall itself is structurally exempt: every generated rule carries a negated
`(self)` destination so the firewall's own outbound DNS queries are never intercepted, making
upstream resolution immune to the redirect. All four config.xml entries per interface (2 NAT
rdr + 2 associated filter PASS rules) carry a `pfB_DNS_Redirect_<iface>_{v4,v6}` marker and
are reconciled / torn down via the ADR-35 managed-object helpers (`pfb_find_managed_obj` /
`pfb_remove_managed_obj`), so their full lifecycle is handled without bespoke teardown code. The feature is
complementary to DoH/DoT domain-level NXDOMAIN blocking (DNSBL feeds) and to ADR-37's
port-853 blocking: this ADR closes only the plaintext port-53 bypass path.

Live-VM smoke: `tests/smoke/test_dns_redirect.py` (marker `smoke`).

## Optional DoT/DoQ BLOCK on port 853 (ADR-37)

When enabled, pfBlockerNG creates and maintains one `filter/rule` BLOCK entry per selected
interface that drops all TCP and UDP traffic destined for port 853 — the IANA-assigned port for
DNS-over-TLS (DoT, RFC 7858) and DNS-over-QUIC (DoQ, RFC 9250). A single `inet46` rule covers
both IPv4 and IPv6 clients without a per-family split: unlike NAT redirect (ADR-36), a BLOCK rule
carries no family-specific redirect target, so one rule is both simpler and correct. The firewall
itself is always exempt: every generated rule carries a negated `(self)` destination
(`<network>(self)</network><not/>`) so the firewall's own outbound port-853 connections are never
blocked, regardless of any future pfSense DoT/DoQ server role. Each rule carries the
`pfB_DoT_Block_<iface>` marker and is reconciled / torn down via the ADR-35 managed-object helpers
(`pfb_find_managed_obj` / `pfb_remove_managed_obj`) — no bespoke teardown code.

ADR-36 (DNS-redirect) closes the plaintext port-53 bypass; ADR-37 (this feature) closes the
standard-port encrypted-DNS bypass (DoT/DoQ on port 853). For DNS-over-HTTPS (DoH, port 443),
the complementary approach is the DNSBL domain-block layer (known DoH hostnames) together with
IP-alias feeds such as the Dibdot DoH-IP feed that block known DoH resolver IPs — blocking port
443 directly would break all HTTPS traffic and is explicitly out of scope. Non-standard-port
DoT/DoQ also remains uncovered by this rule; that limitation is documented in the UI help text.

Live-VM smoke: `tests/smoke/test_dot_doq_block.py` (marker `smoke`).

## Syslog export of security events (ADR-38)

pfBlockerNG can export IP Block/Permit/Match and DNSBL block events to syslog in `key=value`
form, tagged `pfblockerng`. The feature is **opt-in** (default off) via the **Log Settings →
Send Security Events to System Log** toggle (`log_syslog`), with companion selects for facility
(`log_syslog_facility`, default `local6`) and severity (`log_syslog_priority`, default `notice`).

**Dedicated log** — pfSense's `<logging>` block in `pfblockerng.xml` routes `!pfblockerng`
tagged messages to `/var/log/pfblockerng_syslog.log` exclusively, keeping them out of
`/var/log/system.log`. The logsocket entry (`/var/unbound/var/run/log`) gives the Unbound
Python module a chroot-local socket path to deliver DNSBL records.

**Two emit paths:**

- **IP events** — `pfblockerng.inc` calls `pfb_syslog_event(pfb_syslog_format_ip($fields))` at
  the CSV write site when `log_syslog = PfbToggle::On`. PHP `openlog()` / `syslog()` with the
  resolved facility + severity constants. Fields: `act`, `dir`, `if`, `proto`, `src`, `dst`,
  `sport`, `dport`, `ipver`, `geoip`, `alias`, `feed`.
- **DNSBL events** — `pfb_unbound.py` calls `_emit_dnsbl_syslog(msg)` at the DNSBL match site
  when `syslog_enable = on` (written to `py_unbound.ini` by `pfblockerng.inc` at reload time).
  Uses stdlib `logging.handlers.SysLogHandler` with `address="/var/run/log"` (resolves in the
  Unbound chroot to `/var/unbound/var/run/log`). The handler degrades silently on socket failure
  — it never raises into the Unbound request path. Fields: `act=dnsbl`, `qname`, `qip`, `qtype`,
  `group`, `feed`, `btype` (VIP or NULL), `eval`.

**Remote delivery** — no in-package remote syslog target. Use pfSense
*Status → System Logs → Settings → Remote Logging → "Everything"* to forward the facility.

**Config keys** (all registered in `PfbConfig` / `pfb_cfg_registry()`):

| Key | Type | Default | Notes |
| --- | ---- | ------- | ----- |
| `log_syslog` | `toggle` | `''` (off) | PfbToggle; `'on'` enables both paths |
| `log_syslog_facility` | `plain` | `'log_local6'` | Maps to PHP `LOG_LOCAL6` constant |
| `log_syslog_priority` | `plain` | `'log_notice'` | Maps to PHP `LOG_NOTICE` constant |

Live-VM smoke: `tests/smoke/test_syslog_export.py` (marker `smoke`).

## Change detection / content hashing (ADR-42)

Feed change detection is **content-addressed**, not mtime-based. The convention below is policy
of record for every site in the codebase that decides "did this file/feed change". It is a
sibling of ADR-40 (which gates IP **pf-table** reloads on radix-tree set membership, deliberately
*not* file hashing) — different data, different mechanism; cross-reference only, no overlap. The
deferred DNSBL structure-reuse ADR will build on this convention (persist each loaded file's hash
to reuse an unchanged file's in-memory structure on a swap) but is out of scope here.

**Per-side hash algorithm** — each side uses a hash native to it and compares only its own
digests; **no cross-language digest is ever produced or compared**:

| Side | Algorithm | API |
| --- | --- | --- |
| PHP (detector + download) | `xxh128` | `hash('xxh128', …)` / `hash_file('xxh128', …)` |
| POSIX shell | `xxh128` | `xxh128sum` (writes the `.xxhash128` extension) |
| Python (`pfb_unbound.py`) | `md5` | `hashlib.md5` — **policy only here; no Python code lands in ADR-42** (it ships with its first consumer, the deferred DNSBL structure-reuse ADR). `pfb_unbound.py` is stdlib-only + chrooted, and `hashlib` has no xxhash; `xxh128sum` would have to be copied into the jail. md5 is used only for Python's own self-comparisons. |

PHP `hash('xxh128', X)` is byte-identical to the base-CLI `xxh128sum` (XXH128 frozen since
xxHash 0.8.0). Pinned known-answer vector: `"pfBlockerNG"` → `4a2690170244f2e853151c59fbcb2105`
(asserted in `tests/php/FeedChangeHashHelpersTest.php`; a future divergence is caught there).

**The four comparison scenarios** — pick the lightest primitive that fits:

1. **file-vs-file → `cmp -s`** (shell `cmp -s`; PHP a streamed compare or `cmp -s` shell-out;
   Python `filecmp.cmp(a, b, shallow=False)`). Early-exits on the first differing byte, hashes
   nothing. In-tree: the `pfblockerng.sh` aggregate member-list gate (the `cmp -s` site) — the
   shell side already satisfies the convention this way; no `xxh128sum` call is introduced where
   nothing needs a persisted digest.
2. **memory-vs-file → streamed byte compare**, early-return where the language supports it; else
   hash both.
3. **hash-vs-file → hash the file** (`pfb_content_hash($path)`).
4. **memory-vs-hash → hash the memory** (`pfb_content_hash($data, FALSE)`).

**Persisted digests are self-describing by filename extension** — `{base}.xxhash128` (new) /
`{base}.md5` (legacy). A bare/untagged digest reads as **md5**. The tag is mandatory: md5 and
xxh128 are both 128-bit → both 32 hex chars, so the algorithm **cannot** be inferred from the
digest length.

**Migration — read legacy md5, write xxh128** (mirrors the ADR-28 read-boundary adapter): on read
an `.md5`/untagged digest compares with md5; any new write computes xxh128, writes `.xxhash128`,
and **deletes the superseded `.md5`**. No `config.xml` schema or migration — the digest is a
sidecar file next to `.orig`. **Downgrade-safe / fail-safe:** an unreadable/unknown tag (e.g. an
older release meeting a `.xxhash128` it cannot parse) is treated as **changed → re-ingest**, never
a crash and never a false "unchanged".

**Pre-download rule — conditional GET first.** A remote feed fetch sends a conditional request:
`If-None-Match` (persisted `ETag`, primary) and, when no ETag is stored, `If-Modified-Since`
(persisted `Last-Modified`). A **`304`** skips the body entirely and means "unchanged → no
re-ingest". A **`200`** is hashed (xxh128 of the fetched bytes) against the persisted source hash
and re-ingested **iff** the hash differs — so a spurious `200` (server ignored the validator) does
**not** force a needless rebuild. Validators are persisted as `{base}.etag` / `{base}.lastmod`
sidecars; the conditional request is sent only on the detector probe, so the sync ingest always
receives the full body. **No path ever concludes "unchanged" on changed content; any ambiguity
re-ingests.**

**`xxh128sum` provenance (shell side):** confirmed present on the box, but on FreeBSD it is
port-provided (`misc/xxhash`), not base. ADR-42 introduces **no** new shell `xxh128sum` call (the
only shell change-detection site is `cmp -s`, which needs no binary), so no RUN_DEPENDS is declared
yet. A future shell site that genuinely wants a persisted/portable digest must add a `pathxxh128`
absolute-path var (per the shell standard for add-on binaries) **and** declare `xxhash` in the
FreeBSD-ports RUN_DEPENDS so its presence is contractual, not incidental. PHP needs no binary —
`hash('xxh128')` is native.

**Where it lives:** the detector + download (`pfblockerng.inc` `pfb_content_hash` / `pfb_hash_read`
/ `pfb_hash_write` / `pfb_local_feed_changed` / `pfb_validator_read` / `pfb_validator_write` /
`pfb_conditional_get_decision`; `pfb_download`) and `pfblockerng.php` (`pfb_update_check`).
Off-appliance pinned by `tests/php/FeedChangeHashHelpersTest.php` +
`tests/php/ConditionalGetHelpersTest.php`; the live `304`/ETag + same-second detection legs are
ADR-04 smoke (`tests/smoke/test_smoke_feeds.py`).

## Scheduling, trigger API & the Update page (ADR-43)

ADR-43 sits **above** change detection (ADR-42) and apply (ADR-40 IP / ADR-10 DNSBL): it owns
*when the system looks* and *how an operator/cron asks it to*. It does not re-decide detection or
apply — it consumes them. Three reworks: a named trigger request, one cron tick driven by a
due-ledger, and apply-on-change.

### The explicit trigger request (replaces the overloaded `$cron` string)

The reload entrypoint `sync_package_pfblockerng()` now takes a `{scope, force, trigger}` request:

- **`scope`** ∈ `ip` | `dnsbl` | `both` — which side reloads.
- **`force`** ∈ bool — `TRUE` = always reparse (bypass the reuse gate); `FALSE` = respect ADR-42's
  detector (an unchanged feed is reuse-cached, not reparsed — the #517-style "no change" pass).
- **`trigger`** ∈ `cron` | `manual` | `force` — identity only, mapped to the ADR-12 hook env
  `PFB_TRIGGER` by `pfb_req_to_hook_trigger()`: `cron`→`cron`, `manual`→`update`, `force`→`force-reload`.

`sync_package_pfblockerng()` accepts the request array **or** a legacy verb string (back-compat).
`pfb_trigger_request($verb)` maps each legacy verb to its request; the string path additionally
emits one deprecation log line via `pfb_verb_deprecation_warning()`. The CLI exposes the new API as
`pfblockerng.php pfb_trigger scope=<…> force=<true|false> trigger=<…>`. HA-sync (`pfblockerng.xml`)
and the smoke harness (`tests/smoke/helpers.py` `reload()`) call the new API directly.

**Deprecated-verb migration map** (each old verb still works through an adapter; the deprecation
line is logged for the three operator-facing verbs):

| Legacy verb | New request | `PFB_TRIGGER` | Deprecation logged |
| --- | --- | --- | --- |
| `cron` | `{both, force=FALSE, cron}` | `cron` | no (internal scheduled pass) |
| `update` (GUI Update) | `{both, force=FALSE, manual}` | `update` | yes |
| `updateip` | `{ip, force=TRUE, force}` | `force-reload` | yes |
| `updatednsbl` | `{dnsbl, force=TRUE, force}` | `force-reload` | yes |
| `noupdates` / `''` (HA) | `{both, force=FALSE, cron/manual}` | `cron` / `update` | no (internal) |

Deprecation line: `DEPRECATED: pfblockerng verb '<verb>' — use explicit request (<hint>); removal
scheduled`. **Removal timeline:** the verb strings keep working through the current major series;
removal is targeted for a future **major** release (announced in its release notes), at which point
callers must use `pfb_trigger` / the request array. External scripts should migrate during this
window. `PFB_TRIGGER` values are unchanged across the migration, so the ADR-12 hook contract holds.

### One trigger-tick + the due-ledger

The four legacy cron families (`cron`/`dcc`/`bl`/`ss_refresh`) collapse to **one** crontab entry —
`*/<pfb_tick_interval> … pfblockerng.php tick` (default every **15 min**). The tick carries **no**
scheduling logic: it reads the due-ledger, dispatches each **due** job through the new API
(`pfb_trigger scope=both force=false trigger=cron` for the feed pass), runs `ss_refresh` every tick
(cheap DNS re-resolution), then `mark_ran`s each dispatched job. `clearip`/`cleardnsbl` (ADR-30) and
non-pfB cron jobs are left untouched; install/teardown stays idempotent via `pfblockerng_cron_exists`,
and a pre-ADR-43 install's old fleet jobs are removed on the next `sync_package_pfblockerng()`.

**The due-ledger** is a single JSON sidecar `pfb_due_ledger.json` under `$pfb['dbdir']`, one entry
per job/feed: `{last_run, next_due, jitter}`. Pure, clock+seed-injectable helpers in
`pfblockerng_extra.inc` (`pfb_due_ledger_*`); the tick wrapper `pfb_tick_due_jobs()` decides due-ness:

- **Absent entry ⇒ due-now-but-jittered.** A wiped ledger (the issue-#468 MFS-RAM-disk reboot path)
  makes every job due, but each picks up a **stable seeded jitter** (`crc32(seed ':' job_key) % max + 1`,
  seed = `php_uname('n')`) so `dcc`/`bl` spread across the day instead of stampeding upstreams. The
  jitter is deterministic for a fixed `(seed, job_key)` — not re-`rand()`'d each pass (the old model).
- **`next_due` in the past ⇒ due** — free offline catch-up: a window missed during downtime runs
  **once** on the next tick (`mark_ran` advances `next_due` past now, so no double-run).
- **Corrupt/partial ledger ⇒ treated as absent** (fail-safe due).

The ledger rides issue #468's persist/restore set (added to `pfb_aliastables('update')`'s backup),
so a **clean** reboot keeps the schedule; only a true RAM-disk wipe falls back to due-now-jittered.
Legacy cadence knobs (`pfb_interval`, per-feed `freq`/`updatefreq`; `dcc` daily; `bl` daily/weekly)
are read at the ADR-28/29 boundary and reinterpreted as ledger next-due intervals — **no `config.xml`
migration**.

### Apply-on-change + quiet-hours window

Because ADR-40/ADR-10 make apply cheap, a due job applies a detected change **immediately** — the
tick dispatches the reload (`force=false`), the ADR-42 detector gates reparse, and ADR-40
(`pfb_alias_set_different` / `pfb_apply_alias_delta`) / ADR-10 (`pfb_reload_unbound` zero-downtime
swap) gate apply. No change ⇒ no apply. The separate "when to apply" schedule is gone; the only
batching control is an **optional quiet-hours window** (`pfb_quiet_hours`, default empty = apply
immediately). When set and the current time is **outside** the window, a detected change is recorded
**pending** in the ledger and **deferred**; the first tick **inside** the window applies it. The
window boundary check (`pfb_quiet_hours_in_window()`) is clock-injectable and handles
midnight-wrapping ranges.

### Operator surface — the Update page & the knobs

The **Update page** (`www/pfblockerng/pfblockerng_update.php`) is rebuilt on the API: an explicit
**Run Scope** selector (`pfb_scope`: ip/dnsbl/both) + a **Force** radio group (`pfb_force_mode`:
none/parse/download/both) feeding one **Run now**. **None** — plain detector-respecting pass via
`pfb_trigger`. **Parse** — reparse cached lists without re-downloading (`force=true`). **Download**
— clear `.etag`/`.lastmod` sidecars for in-scope feeds, then run the per-feed detector
on-demand (bypassing the hour-gate) via the `forcecheck` verb so every feed is re-fetched; feeds
whose body is unchanged are still skipped. **Both** — also clears `.xxhash128`/`.md5` hash sidecars
so every re-fetched feed re-ingests regardless of content. A read-only **Schedule** view is sourced
from the ledger (last-run / next-due per job); a tidied update-log pane. No raw verb strings in
the UI.

Two registered `PfbConfig` knobs (ADR-29), both with safe defaults and **no GUI control** — set via
config/CLI for advanced tuning:

- **`pfb_tick_interval`** (default `15`) — tick cadence in minutes; `*/N` in crontab.
- **`pfb_quiet_hours`** (default `''` = apply immediately) — maintenance window that defers apply.

### Tests & DoD

Off-appliance (PHPUnit): `TriggerRequestTest` (verb→request oracle), `TriggerAdaptersTest`
(deprecation + force-vs-detector), `DueLedgerTest` (due/jitter/catch-up/round-trip/corrupt),
`TickCronTest` (single-tick generator + due computation), `QuietHoursApplyTest` (apply-now / defer /
boundary), `CfgGatewayTest` (knob round-trips). Live-VM (ADR-04 / ADR-14, dispatch-only):
`tests/smoke/test_smoke_tick.py` (tick fires a due feed, wiped-ledger jitter, `-m reboot`
persistence), `test_smoke_apply_on_change.py` (apply without Force; quiet-hours defer),
`test_trigger_api.py` (new API + deprecation log + HA), and the Update-page Tier A/B in
`tests/smoke/ui/`. Per CLAUDE.md "ADR acceptance", ADR-43 moves to Accepted on the green CE+Plus
live-VM fan-out of those cases.

## Sync-status ledger (ADR-61)

Before ADR-61, the dashboard widget's health signal was four unrelated ad-hoc checks: an
IP-row yellow gated entirely behind the optional, default-off `enable_dup` dedup feature (so a
box with dedup off could never show IP yellow, no matter what actually failed); a dead
`OUT OF SYNC` log-grep on the DNSBL row (no writer of that substring exists anywhere in the
tree); a **monotonic** `py_error.log` filesize check (one exception ever written keeps the row
yellow forever, until an operator manually clears the log); and a separate `error.log` FAIL-grep
powering the reporting list, decoupled from the icons entirely. ADR-61 replaces all four with
**one PHP-owned, general-purpose open-issues ledger** every failure/success site writes to
directly, plus a **Python-owned** companion for the DNSBL parse stage (a cross-process/chroot
boundary the PHP file cannot safely share), merged read-only by the widget.

### Ledger shape and the two-file boundary

The PHP-owned ledger is `{$pfb['dbdir']}/pfb_sync_status.json`, a nested
`{facility: {item: {stage: {message, first_seen, last_seen}}}}` object (`facility` ∈
`ip`/`dnsbl`; `stage` ∈ `download`/`apply`/`dedup`/`parse`). Pure, clock-injectable, atomic
(temp-write → `rename`, no `fsync` — same as `pfb_due_ledger_*`) read/write/open/close/
list-open helpers live in `pfblockerng_extra.inc` (`pfb_sync_status_*`), mirroring
`pfb_due_ledger_*`'s exact persistence idiom (ADR-43) — same sidecar-file convention, same
downgrade-safe-on-corrupt/absent-file contract, same "no config.xml involvement" shape.

`pfb_unbound.py` runs chrooted inside Unbound's Python loader, a separate process from PHP —
it cannot safely co-write the PHP file (write contention, and PHP is not chrooted so the paths
don't resolve the same way). It instead owns a **second**, structurally-identical file,
chroot-relative `pfb_py_status.json` (mirroring the existing `pfb_py_reload`/`.applied` marker
convention: PHP never writes it, Python never writes the PHP one), via its own pure
`pfb_py_status_open()`/`close()` functions using the identical atomic tmp-then-`os.replace()`
idiom `_reload_write_applied()` already established. A read-only PHP helper,
`pfb_py_sync_status_list_open()` in `pfblockerng_extra.inc`, reads it and returns entries in the
same shape as `pfb_sync_status_list_open()`'s, for the widget's merge — every hostile input
(absent/empty/corrupt/wrong-shape JSON) degrades to "no open entries," never a crash.

**Symmetric ownership (mandatory).** Every code path that can open an entry for a given
`(facility, item, stage)` is paired with the code path that clears that *same* key on its own
next success. Open is idempotent-by-key: opening an already-open key refreshes
`message`/`last_seen` in place, never duplicates.

### Writer sites (what's covered today, and what deliberately isn't)

| Facility | Stage | Writer/clearer site | Notes |
| --- | --- | --- | --- |
| `ip` | `download` | `pfb_ip_download_ledger_update()` at the IP feed-download call site (`pfblockerng.inc`) | paired with the download success path |
| `ip` | `dedup` | `pfb_sync_status_dedup_check()` (`pfblockerng_extra.inc`), reads the shell's `Sanity check [ PASSED / FAILED ]` line the same way the old widget grep did | replaces that grep entirely |
| `ip` | `apply` | wired **inside** `pfb_pfctl_table_op()` itself (`pfblockerng.inc`) — a deliberate choice covering every one of that function's callers (delta apply, force-replace, aggregate build/teardown) at one choke point | issue #980's logging-level fix (level 2) is untouched; this ADR only adds the ledger write alongside it |
| `dnsbl` | `download` | `pfb_dnsbl_download_ledger_update()` at the DNSBL feed-download call site (`pfblockerng.inc`) | paired with the download success path; issue #998 follow-up, mirrors the IP download writer |
| `dnsbl` | `apply` | `pfb_dnsbl_apply_ledger_update()` + the pure `pfb_dnsbl_converged(): bool` helper (sentinel/applied generation match, Unbound running, `unbound.conf` still wires `pfb_unbound.py`), wired at `pfb_reload_unbound()`'s zero-downtime-success return and its shared-restart tail (mode-gated) | the swap-not-confirmed → restart-fallback branch never opens an entry by itself (fail-safe by design, not an error) |
| `dnsbl` | `parse` | Python-owned, 8 sites in `pfb_unbound.py`: the zone/data/whitelist/hsts/SafeSearch loaders and the `pfb_unbound.ini` config read (each extracted into its own testable `_load_*` function) plus the DNSBL manifest load (`dnsbl_build_from_manifest()`, both its callers) | 7 further `sys.stderr.write` sites (module-capability imports, per-pattern REGEX-ini rows, background-thread bring-up) are deliberately left freetext-only — no stable per-run item identity / no natural clear site; still visible in `py_error.log` as before |

### Tick-driven reconciliation — apply stage only

`pfblockerng_tick()` gains one **unconditional** step (runs every tick regardless of due-ness,
placed after `pfblockerng_ss_refresh()` and before the log-maintenance tail — it never sets
`$dispatched`, so it doesn't interact with the log-trim race guard) that, for every open
`stage=apply` entry:

- **IP:** re-applies the already-persisted mirror directly — `pfb_pfctl_table_op($item,
  'replace', '-f '.escapeshellarg("{$pfb['aliasdir']}/{$item}.txt"))` when the mirror exists
  (or `kill` when it doesn't) — no re-download, no re-parse, no re-dedup. Reuses
  `pfb_pfctl_table_op()`'s own ledger wiring; the tick step makes zero direct ledger calls on
  the IP side.
- **DNSBL:** re-flips the reload sentinel (only when a live Python-mode watcher could actually
  consume it — the same eligibility gate `pfb_reload_unbound()`'s zero-downtime path uses), then
  re-runs `pfb_dnsbl_apply_ledger_update()` to re-settle the entry either way.

**Deliberate narrowing (permanent, not a stopgap):** the DNSBL retry is a sentinel-re-flip only,
**not** a full stop/restart. Re-invoking `pfb_reload_unbound()`'s restart fallback from every
15-minute tick would restart a live DNS resolver indefinitely for a condition that stays
genuinely stuck — heavier than this mechanism's own "no network I/O, no feed re-parse" premise.
Consequence: a **genuinely** stuck DNSBL apply condition (Unbound fully down, a real conf/build
failure) does **not** self-heal via the tick alone — it stays open/yellow until an operator's own
Force Reload/Update pass (which does run the full restart path) or Unbound's own recovery
resolves it. A stuck IP `pfctl` condition, by contrast, self-heals within one tick interval —
the two facilities are not symmetric on this specific point, by design.

Retry is unbounded and uncounted — no attempt-count field, no backoff timer, per direct
instruction (a genuinely un-fixable condition retries forever at tick cadence; cheap
per-attempt, accepted as fine). Download/parse-stage entries are never touched by this step —
those failures stay ledger-visible but retry only at their normal fetch/parse cadence.

### The widget — a pure reader

Both dashboard rows read the merged ledger exclusively for their **yellow** trigger; the
existing **red/green "is it live"** gates are completely untouched by this ADR. IP row: yellow
on any open `facility=ip` entry of any stage. DNSBL row: yellow on any open `facility=dnsbl`
entry, PHP ledger merged with the Python file. The reporting list
(`pfBlockerNG_get_failed()`) is rebuilt from the same merged read — each entry's `item` field
already *is* the clean alias name (no more log-line text-parsing), so a recognized
`pfB_*`/`DNSBL_*` item still deep-links to its editor page exactly as before; a Python-side
entry (whose `item` is a raw file path, e.g. `pfb_py_zone.txt`) renders as plain text, never
attempts a link. `error.log`/`py_error.log` are no longer read anywhere in the widget — they
stay pure, freetext operator logs, governed only by their existing rotation, never required to
be "cleared" for the icon to go green.

**Known UX loose end:** the pre-existing "Clear Failed Downloads" trash-can icon still POSTs a
handler that mutates `error.log` — now functionally inert against the ledger-driven list (there
is no longer a `error.log`-driven state for it to clear). Deciding what "clear" should mean
against a ledger (manually ack an entry? force the underlying retry?) is a real product
decision, left open rather than silently invented.

### Tests & DoD

Off-appliance (PHPUnit): `PfbSyncStatusLedgerTest` (ledger library — open/refresh/close/list/
corrupt-file), `PfbSyncStatusIpWritersTest`, `PfbDnsblConvergedTest` + `PfbSyncStatusDnsblWritersTest`,
`PfbPySyncStatusReaderTest` (PHP-side Python-file reader + hostile inputs), `TickApplyReconciliationTest`
(retry dispatch, Semantics-#5 non-interference, the `$dispatched`-flag guard), `PfbWidgetOracleTest`
(icon/report logic, both rows, both ledger sources). Off-appliance (pytest):
`tests/test_adr61_py_status.py` (Python-side writer/clearer pairs + hostile-input reads).
Live-VM (ADR-04/ADR-14, authored this ADR run but not yet executed against a live box — no VM
was reachable in the implementing session): `tests/smoke/ui/test_render_widget_ledger.py`
(Tier A `ui_render`, both rows' empty/populated states, the reporting list's link/plain-text
cases). Per CLAUDE.md "ADR acceptance", ADR-61 moves to Accepted on the green CE+Plus live-VM
fan-out of those cases, plus the manual smoke checklist below for the scenarios PHPUnit/pytest
structurally cannot reach (a real `pfctl` failure, a real Unbound restart, a real reboot).

## IP suppression set-subtraction (ADR-53)

Replaces the IP-side **Suppression** feature's host-explosion mechanism with genuine CIDR set
subtraction, in both families. Suppression stays **content-level** (it edits the deny member
files feeding every consumer — pf tables, ADR-11 aggregates, HAProxy `.lst`, killstates, the
Alerts/Reports view) rather than a pf rule/table-negation trick (rejected: it would bypass the
user's own block rules and still kill the exempted host's states — see ADR-53 §1.4).

**The covering-CIDR math.** Subtracting a `/b` hole from a containing `/a` block costs exactly
`b − a` covering-CIDR entries — one per prefix-length step from the hole up to the container —
**independent of the hole's exact position** (a standard property of binary CIDR decomposition).
Measured/pinned: `/24 − /32 = 8`, `/16 − /32 = 16`, `/16 − /24 = 8`, `/64 − /128 = 64` (v6). For
`k` holes in one block the bound is `k × (b − a)`. This is the entire fix: the old mechanism
enumerated hosts (`/24 − /32` = 254 lines; a v6 `/64 − /128` would be 2⁶⁴ — impossible), when the
minimal remainder was always a few dozen lines.

**v4 engine — `iprange --except`** (`pfblockerng.sh suppress()`). `iprange` is already a hard
dependency (ADR-11's `pathaggregate`). One call per feed-changed Deny member file:
`${pathaggregate} <member> --except <suppfile>` replaces the old `grep -F` + `seq 255` + awk
explode. `rc=0` publishes (including a legitimately-empty result — a fully-suppressed member is
valid, unlike `grepcidr`'s `rc=1`-means-empty quirk); any other `rc` keeps the previous list and
logs (the same #713 fail-safe shape). **DNS-resolution hazard**: `iprange` is IPv4-only, mangles
v6 input (parses it as a hostname), and — worse — treats any non-IP token as a **hostname and
DNS-resolves it** (`rc=0` regardless, no opt-out flag). Both the member file and the suppression
list are pre-filtered to strict IPv4/CIDR token shape (`pfb_is_cidr_token` / `pfb_is_ip_or_cidr_token`)
before either reaches `iprange`, so a malformed token is dropped and logged, never DNS-resolved.

**v6 engine — pure PHP** (`pfb_cidr_subtract_v6()` + `pfb_suppress_file_v6()`). `iprange` cannot
take v6 input at all, so v6 is a from-scratch fixed-width 128-bit binary-string set-diff, emitting
the minimal covering-CIDR remainder via pfSense's own `ip_range_to_subnet_array()` (verified at
the min-CE dated ref, faithful PHPUnit double). Every binary-string comparison uses `strcmp()`,
never `<`/`>`/`min()`/`max()` — a 128-char `'0'`/`'1'` string is a PHP "numeric string", and the
normal comparison operators risk silent float-precision coercion on a string that long. Streaming,
atomic tmp+rename publish, same fail-safe-keep-previous contract as v4. Measured perf bound (P5):
1.24 s / 100k lines on the CI runner — comfortably inside the §7 reject threshold (5 s).

**Wiring gotcha (flagged for the maintainer, not fixed in Phase 9):** `$pfb['supp_update']` — the
flag that unlocks BOTH the v4 and v6 suppression sub-passes for a given reload pass — is set
`TRUE` only by a **v4** Deny alias's own genuine reparse (`pfblockerng.inc` ~16550-16558, inside
`if ($pfbadv && $list['vtype'] == '_v4')`). An install with **only** v6 Deny lists configured
would never flip it, so v6 suppression would never fire in isolation even with `v6suppression`
non-empty and a v6 alias genuinely changing. `tests/smoke/test_smoke_suppression.py`'s v6 scenario
works around this (a trivial companion v4 Deny alias rides the same reload pass) rather than
hiding it — a production box with both families configured behaves the same way. Candidate fix:
also set `supp_update` on a v6 Deny alias's change; out of ADR-53 Phase 9's scope (test/docs only).

**Consumer inheritance.** Every downstream reader — pf tables (via the ADR-40 mirror/reload
model), ADR-11 aggregate aliases, HAProxy `.lst` (ADR-12), the Alerts/Reports "is this IP blocked"
view, the widget, and killstates — reads the post-suppression member files, so the content-level
fix reaches all of them with zero consumer-side changes. Killstates' suppression exclusion is
prefix-aware via `pfb_ip_suppressed()` (both families), replacing the old exact-IP hashmap +
`subnetv4_expand` host-materialisation.

**Alerts "+" live punch — a SEPARATE mechanism, not this engine.** `pfb_live_punch_plan()`
(`pfblockerng_extra.inc`) mutates the LIVE pf table directly from a single web click (locate the
containing table entr(y/ies) via the ADR-40 mirror/`pfctl -T show` fallback, `pfctl -T delete` +
`-T add` the covering-CIDR difference), independent of any reload — the update-time engines above
never run for it. Covered by `tests/smoke/ui/test_alerts.py`'s
`test_addsuppress_{v4,v6}_carves_containing_range_and_spares_sibling`; the update-time proof lives
in `tests/smoke/test_smoke_suppression.py` and is a genuinely different code path, not duplicate
coverage.

**Alerts un-suppress + row icons (issue #422 follow-up).** The trash-can revert (`delete_ip`)
matches the covering suppression entry prefix-aware via `pfb_ip_suppressed_match()`
(`pfblockerng_extra.inc` — longest prefix wins; also drives the suppressed-row icon detection),
removes exactly that entry (either family, any mask) and `pfctl -T add`s it back — the union of
the re-added entry with any covering CIDRs a live punch left behind equals the original coverage,
and the next reload rebuilds the canonical set. The legacy 255-sibling-host revert loop is gone
(nothing produces exploded state any more; pre-ADR-53 leftovers self-heal on the next reload).
The `entry_delete` gate validates `PFB_FILTER_IP` (both families), and the Alerts suppression
icons render for any Block/non-GeoIP row — v6 and broader-than-`/24` v4 rows included; the
unlock-icon eligibility is deliberately unchanged.

**Tests.** Off-appliance: `tests/shell/pfblockerng_suppress_spec.sh` (real-`iprange` shellspec —
the exact `/16 − /32 = 16` / `/24 − /32 = 8` vectors the smoke module's assertions are grounded
in), `tests/php/V6CidrSubtractTest.php` (the pure-PHP engine, incl. the `/64 − /128 = 64` vector),
`tests/php/SuppressionValidatorTest.php` (mask floors: v4 `/8`–`/32`, v6 `/32`–`/128`),
`tests/php/CreateSuppressionFileTest.php`, `tests/php/KillstatesSuppressionTest.php`,
`tests/php/LivePunchPlanTest.php`. Live-VM (ADR-04, dispatch-only):
`tests/smoke/test_smoke_suppression.py` (this section's headline acceptance proof — both families,
before-state asserted first, plus the whole-token/mask-agnostic upgrade-parity scenarios) and the
Alerts "+" Tier B e2e above. Per CLAUDE.md "ADR acceptance", ADR-53 moves to Accepted on the green
CE+Plus live-VM fan-out of those cases.

## Firewall-alias resolution — config reads, not pfSense alias helpers

Everywhere pfBlockerNG needs a firewall alias's existence, type, members, or config index, it
reads `config_get_path('aliases/alias', [])` (or the package resolver `pfb_alias_type()` in
`pfblockerng.inc`) instead of pfSense's alias helpers. This is a **deliberate, audited
decision** — do not "clean it up" back to the helpers. Evidence base: the 2026-07-07 contract
audit, which extracted every helper body at 7 dated refs of the public mirror (CE 2.8.0
`ed6c2eb8` 2025-05-28, Plus 25.07/25.07.1, CE 2.8.1, Plus 25.11/25.11.1, and
master≙26.03/26.03.1 `9363ac5b` 2026-03-31) and found them **byte-identical at every ref** —
the blockers below are structural, not version drift.

**Why `get_alias_list()` cannot serve (all refs, `util.inc`):**

- Returns **names only** (a `string[]`) — most of our sites need the full entry (`type`,
  `address`, `detail`), the config array **index** (the widget's `alias_info_popup($id)`), or
  **write access** (the alias-reconcile region) — none of which a name list provides.
- `$type` must be a **comma-separated string**; an array argument silently returns `[]`
  (the dead-feature bug found in pfSense-pkg-haproxy — already true at CE 2.8.0, so no
  "old ref" is safe either).
- Merges in the **reserved system table names** and returns `null` (undefined `$result`)
  instead of `[]` when nothing matches — `foreach` warnings on an alias-less config.

**Why `alias_get_type()` / `is_alias()` cannot serve as existence checks:**

- `is_alias()` consults the in-memory `$aliastable` cache that only `alias_make_table()`
  (filter generation) populates — empty on settings pages and in cron syncs, reporting every
  real alias missing (#636, #664).
- `alias_get_type()` gives **reserved system table names precedence** over the configuration
  (`get_reserved_table_names()`, matched case-insensitively). The 8 static reserved entries —
  `bogons`/`bogonsv6` (`urltable`), `sshguard`/`snort2c`/`virusprot` (`host`),
  `vpn_networks`/`negate_networks`/`tonatsubnets` (`network`), identical CE 2.8.0..master,
  extensible at runtime via `add_reserved_table()` — are ALL address-bearing types, so they
  pass any address-field validation while having **no `aliases/alias` entry**: the Advanced
  In/Outbound rule builder (`pfblockerng.inc`, non-empty `address` required) silently drops
  them, and `pfb_redirect_exclude_source()` would risk emitting a negated source for a pf
  table that may not exist (`bogons` without block-bogons ⇒ whole-ruleset load failure, the
  #664 class). Save-time validators therefore resolve via `pfb_alias_type()` (returns `NULL`
  for anything not in the configuration — reserved names included) so a reserved name is
  rejected at save, consistent with the autocomplete (`pfb_alias_autocomplete_lists()`, which
  never offers reserved or `pfB_*` names).

**Test-double fidelity.** The off-appliance `alias_get_type()` double
(`tests/php/pfsense_doubles.php`) mirrors the reserved-table precedence — keep it faithful to
upstream `util.inc`, not to what would be convenient: the config-only version it replaced is
exactly what hid the reserved-name defect from the suite. Behaviour pinned by the reserved-name
cases in `tests/php/AdvAliasFieldErrorsTest.php`.

**Audit scope note.** The same audit hash-compared all 104 pfSense functions called from
`src/` across those 7 refs: no call-site contract break anywhere (the 20 upstream body changes
are internal — logging refactors, debug gates, `config_read_file`'s Plus-25.11 cache rework,
which is inert for us because every call passes explicit `(FALSE, TRUE)`).
