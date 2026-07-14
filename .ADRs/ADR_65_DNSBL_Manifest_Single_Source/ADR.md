# ADR-65: Make the manifest the single source of truth for DNSBL — retire the `py_data`/`py_zone` interchange files and add a read-only decision query channel

- **Status:** **Proposed** (2026-07-13; **REWORKED 2026-07-14, phase 0** — every §1 fact and
  anchor re-derived from `devel`@862a306f after ADR-66 and the #1255 fix landed; the original
  "manifest wildcards regardless of `pfb_tld`" divergence claim is retired — the fallback's
  verified defects are lossiness, staleness, and failure-masking, §1.1)
- **Date:** 2026-07-13
- **Branch:** `adr/65-dnsbl-manifest-single-source` (off `devel`; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming")
- **Folds in:** issue **#1244** (TLD-mode finalize renames `py_data`/`py_zone` unchecked and logs
  "completed" regardless) and **#1245** (a failed python publish can leave a stale TLD-origin
  `pfb_py_zone`) — both dissolve when the files stop existing; this session's investigation thread
  is the design record that produced §2.
- **Amends:** **ADR-06** (DNSBL preprocessing → Python). ADR-06 §"the legacy data/zone CSV load …
  FALLBACK … used only when no manifest is present" is retired here; ADR-06 gets a §8 post-merge
  amendment in Phase 7 (CLAUDE.md "ADR amendments after merge").
- **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (the query channel, the
  fallback-loader removal, fail-loud), `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
  (`tld_analysis`, `pfb_dnsbl_py_swap`, `pfb_log_event`, the health check, `pfb_dnsbl_parse`),
  `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` (a NEW PHP query-channel client),
  `src/usr/local/www/pfblockerng/pfblockerng_alerts.php` (gate off the DNSBL re-check),
  `docs/misc/alerts-reports-pipeline.md` + `docs/misc/architecture-notes.md`.
- **Target runtime:** Python 3.11 in Unbound's pythonmod (stdlib only — CLAUDE.md hard constraint);
  PHP 8.3 (pfSense CE 2.8) for the consumers and the query client.
- **Test suite:** `tests/` (pytest — the query channel, side-effect-free decision, fallback
  removal, fail-loud), `tests/php/` (PHPUnit — the query client, `pfb_log_event`, the health
  check), `tests/smoke/` + `tests/smoke/ui/` (live-VM — the only place the running module answers a
  query; no live Unbound in CI).

## 1. Context — today

### 1.1 The manifest is the primary source; the interchange files are a failure-only fallback

ADR-06 moved parse/normalise/classify into Python. `init_standard()` builds from the per-feed
**manifest** (`pfb_py_sources.json` plus the per-feed IP-stripped raw files under
`/var/unbound/pfb_py_raw`, which the manifest references by path — `pfblockerng.inc:8184`):
`dnsbl_build_from_manifest()` (`pfb_unbound.py:5351`, called at `:1658`) builds
`dataDB`/`zoneDB`/`whiteDB`/`regexDB`/`allowRegexDB` via the pure `build()` layer, and only
when it returns `None` — manifest **absent** (`:5365`), **unparseable** (`:5374`), or
`build()` **threw** (`:5392`) — do the legacy loaders run: `_load_zone_and_data_dbs()`
(`:1045`) and the whitelist arm of `_load_whitelist_and_hsts_dbs()` (`:1058`), each internally
gated on `not dnsbl_built` (call sites `:1698`/`:1704`).

**The manifest build is decision-complete — its zone/data split is derived, not stored.** The
wildcard(zone) vs exact(data) distinction comes from two mechanisms: (a) **ABP** rows carry it
**intrinsically** — the per-feed raw file holds the verbatim ABP line (`pfblockerng.inc:8165`)
and `parse_abp()` maps `||domain^` → zone, exact → data; (b) **plain** rows are bare domains,
and `build()` calls `tld_wildcard_classify()` (`pfb_unbound.py:4316`, call site `:5189`)
against the public-suffix oracle. Post-#1255 the oracle is **not** a manifest key: it rides
the **shipped** `pfb_py_tld.txt` chroot file (`pfblockerng.inc:134`), loaded reader-side into
the internal `tld_wildcard_master` build key (`pfb_unbound.py:5324-5329`) **only when the
`python_tld_wildcard` ini flag is on** — derived 1:1 from `pfb_tld` ("Enable TLD Function",
`$pfb['dnsbl_tld_wildcard']`, `pfblockerng.inc:8412-8416`, emitted `:8510`). An **empty oracle
forces exact/DATA for every domain** (`pfb_unbound.py:4328`, the #1255 guard); with the oracle
loaded, a 2-label domain is ZONE (`:4344`). So the toggle genuinely gates manifest-era
wildcard classification: `pfb_tld` ON wildcards `evil.com`, OFF matches it exact-only. The
manifest itself embeds only `tld_wildcard_blacklist`/`tld_wildcard_exclusion`, emptied when
the toggle is off (`pfblockerng.inc:8223-8232`).

**What the fallback actually is (each fact verified on `devel`@862a306f):**

- **Lossy.** The legacy loaders parse the NDJSON interchange files and **silently skip every
  `abp` row** (`_load_ndjson_row_into_db`, `pfb_unbound.py:925`), and `regexDB`/`allowRegexDB`
  are populated only by the manifest build (`:1672`) plus user REGEX-ini entries (`:1591`). In
  fallback mode every ABP feed's rules — block, exception, `$important`, regex — are simply
  absent. (Both `.txt` producers skip `abp` rows too — `tld_analysis` at
  `pfblockerng.inc:8845`.)
- **Stale-able.** The loaders read whatever `pfb_py_data.txt`/`pfb_py_zone.txt` exist on disk,
  with no freshness or generation check — the #1245 stale-serve vector.
- **Failure-masking.** It runs immediately after `dnsbl_build_from_manifest` recorded the
  failure in the ADR-61 ledger (§1.7), silently serving old data under a flagged outage.
- **Nominally decision-aligned for FRESH plain-domain rows only:** `tld_analysis()` mirrors
  `tld_wildcard_classify()` (both sides' docstrings pin the mirror), and the `pfb_tld`-OFF
  swap (whole raw → data) matches the empty-oracle all-DATA classification — so a fresh
  fallback file no longer diverges from the manifest build on plain domains in either toggle
  state. The removal argument (§2.3, D3) rests on the three defects above, **not** on
  classification divergence.

History note: this ADR originally claimed the manifest wildcards registrable domains
regardless of `pfb_tld` (toggle vestigial, fallback divergent). The #1255 fix (`ada05bb1`)
introduced the toggle gating and ADR-66 renamed the TLD symbols; phase 0 (2026-07-14)
re-derived this whole section from source.

### 1.2 What writes the interchange files, and the two-producer split

`pfb_py_data.txt` (exact; `$pfb['unbound_py_data']`, `pfblockerng.inc:130`) and
`pfb_py_zone.txt` (wildcard-incl-self; `:131`) are **NDJSON schema-v1** files (`domain`/`abp`
rows; emit/read helpers `:2073-2123`). Assembly first concatenates every enabled list's dnsdir
NDJSON into `{$pfb['dnsbl_file']}.raw` (`pfb_dnsbl_concat_files`, `:18135`; #1097 — no
destructive pre-unlink), then the finals are produced mode-exclusively on `pfb_tld`:

- `pfb_tld` **ON** → `tld_analysis()` (`:8703`, gated call `:9361`) classifies the assembled
  raw into `{unbound_py_data}.raw` + `{unbound_py_zone}.raw` (`:8746`), promoted by the
  finalize `@rename()` loop (`:8935-8939`, the **#1244** site — return value discarded, logs
  "completed" unconditionally at `:8941`). `pfb_dnsbl_py_swap()` early-returns when the toggle
  is on (`:2007`).
- `pfb_tld` **OFF** → `pfb_dnsbl_py_swap()` (`:2006`, called unconditionally at `:18138`)
  renames the whole assembled raw → `pfb_py_data.txt` and unlinks `pfb_py_zone.txt` only on a
  **checked** rename success (`:2013`, the **#1241** crash-safety fix); a failed rename keeps
  the old files — including a stale TLD-origin `pfb_py_zone.txt` from an earlier ON run (the
  **#1245** window).

### 1.3 Three consumers of the interchange files (all replaceable)

1. **Python init fallback** — `_load_zone_and_data_dbs()` reads `pfb_py_zone.txt`/
   `pfb_py_data.txt` into `zoneDB`/`dataDB` when the manifest did not build (`:1045`, via
   `_load_ndjson_row_into_db` `:913`). This is the #1245 read path: it can serve a **stale**
   file silently, and it is **lossy** (§1.1 — `abp` rows skipped, no regex/allow rules).
2. **Reports/Alerts "what blocks it right now?" re-check** — `pfblockerng_alerts.php`'s
   `convert_dnsbl_log()` (`:2262`) calls `pfb_dnsbl_parse('alerts', …)` (`:2331`; memo wrapper
   `pfblockerng.inc:14597` → `pfb_dnsbl_parse_compute` `:14622`) which greps the interchange
   files (`:14676` data, `:14710` zone, `grep -F` + NDJSON needle verification `:2130-2145`)
   to compare the logged group/feed/mode against "current" and flag `$isMatch = FALSE`
   (compare block `pfblockerng_alerts.php:2330-2372`; failed-match re-derive `:2375-2378`).
   The greps ride a two-pass batched prefetch (#809): `pfb_dnsbl_prefetch`
   (`pfblockerng.inc:14480`), fed by the alerts buffer/replay scheme
   (`pfblockerng_alerts.php:4509`/`:4543`; filter mode stays single-pass, `:4451-4468`).
   **A grep of the classified interchange files cannot reproduce the full matcher**
   (regex/ABP, allow-regex, whitelist precedence, TOP1M, `$important`, HSTS, homoglyph,
   upstream) — it is an approximation. `docs/misc/alerts-reports-pipeline.md:23`: *"The logs
   are self-sufficient for rendering a complete table; the render-time pass is a
   [refinement]."*
3. **Webserver-hit attribution** — a client hitting the DNSBL block-page (VIP) is logged by
   `pfb_daemon_dnsbl` → `pfb_log_event()` (`pfblockerng.inc:15171`), which has only
   `domain`+`src_ip` and greps via `pfb_dnsbl_parse('daemon', …)` (`:15190`) to attribute the
   event, then `UPDATE dnsbl SET counter = counter + 1 WHERE groupname = :pfb_group`
   (`:15210`) — feeding the dashboard widget's per-group count.

### 1.4 The logs and DB already carry authoritative attribution

At block time Python writes the full verdict to `dnsbl.log` — `csv_line`
(`pfb_unbound.py:2829-2844`) carries `l_type, datetime, q_name, q_ip, p_type, b_type, group,
b_eval, feed, dup, q_type` (0-based: group at index 6, feed at index 8), computed by the
**real** matcher (`evaluate_domain` `:6038` → `_scan_block_band` `:5834` →
`get_details_dnsbl` `:2762`). The filterlog daemon mirrors that line verbatim into
`unified.log` via `pfb_unified_format_dnsbl()` (`pfblockerng_extra.inc:2041`; write site
`pfblockerng.inc:13867`, group/feed preserved). The alerts/reports **event table is
log-driven** (`pfblockerng_alerts.php` sources `$pfb['dnslog']`/`$pfb['unilog']`,
`:4253-4259`); `dnsblcache` (`type,domain,groupname,final,feed`) is only the re-check's cache
— Python writes it per block (enqueue `pfb_unbound.py:6750`, INSERT `:2581`) and **wipes it on
every swap** (`_db_reset_cache`, `:2586`) — and the widget reads durable per-group
**counters** (`dnsbl`/`resolver` tables, `pfblockerng.widget.php:382`), never the interchange
files.

### 1.5 Side effects a real query has (the ones a check must NOT have)

A served DNS query enqueues, on the block path: `("resolver",)` — totalqueries count
(`:2780`); `("dnsbl", group)` — per-group counter (`:2794`); the `dnsbl.log` line (`:2845`);
the `dnsblcache` row (`:6750`); and it writes the LRU memo `decisionDB[name] = dec` (`:5730`,
in `_decision_for` `:5718`). All of these except the LRU write live in the **log/emit path**
(`get_details_dnsbl` and its callers), not in the pure decision
(`evaluate_domain`/`_scan_block_band`).

### 1.6 The control channel we already have (PFBL-03)

`pfb_py_control` is a local JSON command channel: PHP writes `{seq, cmd, …}`;
`pfb_control_watcher()` (`pfb_unbound.py:799`) reads it off the query threads and routes fresh
records (seq advance) through the apply path. The command vocabulary is **mutating actions**
(`disable|enable|addbypass|removebypass`, `_control_record_to_command` `:765`, vocabulary
check `:775`), and the only reply is `_control_write_applied(seq)` (`:742`) — a seq **ack**,
no data. The watcher thread starts in init gated on `mod_threading and python_control`
(`:1827-1834`); shutdown rides the `pfb_control_stop` `threading.Event` (declared `:155`, set
in `deinit()` `:3502`). It is privileged (root writes, unbound reads, mode 0640) and the
legacy DNS-TXT transport is deprecation-warned (`warn_if_legacy_control_enabled` `:901`).
**There is no request/reply data path today.**

### 1.7 Fail-loud plumbing already exists (ADR-61)

`dnsbl_build_from_manifest` already opens the ADR-61 status ledger on the unparseable/threw
failures — `pfb_py_status_open("dnsbl", manifest_path, "parse", …)` at `:5374`/`:5392` (the
absent case only closes, `:5368`). The widget surfaces that ledger
(`pfblockerng.widget.php:468`, `pfb_py_sync_status_list_open`). The `file_notice()`
dashboard-bell mechanism is used elsewhere for the DNSBL VIP and MaxMind/ASN notices
(`pfblockerng.inc:2698`, `:18584`, `:18884`). The manifest's own atomic publish is unchecked
today: `pfb_unbound_py_atomic_write` (`:7725`) is called bare at the sources write (`:8258`),
while the sibling in-place patcher checks it (`:8293`). The bug is that init records the
failure and **then silently falls back to the stale interchange files**, masking what it just
flagged.

## 2. Decision

**The manifest is the single source of truth for the DNSBL matcher.** When it is present it is the
only input; when it cannot build, DNSBL loads **nothing** and **fails loud** — it never serves the
legacy `.txt` fallback. The `.txt` interchange files are **retired**. Every capability they served
moves to an authoritative source: the matcher's live decision (a new **read-only query channel**),
the block-time logs (self-sufficient attribution), and the manifest (health/generation).

### 2.1 The read-only decision query channel

A new **always-on, read-only** file channel parallel to PFBL-03 (§1.6) — call it `pfb_py_query`
(request) + `pfb_py_query.reply` (reply) — lets any local consumer ask the **live matcher** a
single question and receive the answer it would have logged:

| Aspect | Decision |
| --- | --- |
| **Request** | `{"id": <str>, "domain": <str>, "qtype": <str>}` — `id` is a caller-chosen correlation token (not seq-gated: a query is stateless, has no replay concern, unlike the mutating channel). |
| **Reply** | `{"id": <str>, "blocked": <bool>, "b_type","group","b_eval","feed","p_type"}` — the **exact fields `dnsbl.log` carries** (§1.4), so a consumer gets byte-identical attribution to a real block. `blocked=false` → the other fields are empty. |
| **Engine** | Runs the **pure decision** `evaluate_domain`/`_scan_block_band` against the live `dataDB`/`zoneDB`/`regexDB`/`whiteDB`/`hstsDB` — the SAME code `operate()` uses, so the answer reflects the full matcher (regex/ABP, allow, whitelist precedence, TOP1M, `$important`, HSTS, homoglyph), never a grep approximation. |
| **Side effects** | **NONE that a real query has, except the LRU.** No `("resolver")`/`("dnsbl")` counter enqueue, no `dnsbl.log` line, no `dnsblcache` row. Writing the LRU `decisionDB` memo is **allowed** (it warms the cache and is decision-neutral). Pinned by a test that asserts every counter/log/cache is untouched across a query while `decisionDB` may change. |
| **Always-on** | The query watcher runs unconditionally (read-only ⇒ safe), independent of the legacy-control toggle. Started alongside the existing watchers in init. |
| **Transport** | File request + reply file keyed by `id`, reusing the control channel's kqueue-watch + atomic-write pattern (lazy: mirrors existing code). A Unix-domain socket is the documented upgrade path if per-event latency/concurrency ever demands it; the sole caller today is one-event-at-a-time (webserver hit), so a file channel suffices. |
| **Privilege** | Owner root, group `unbound`, mode **0660** on the request file (the attributing daemon must write it; it is read-only in effect — it mutates no state), reply file 0640. Read-only ⇒ no authorization beyond "local" is required; a hostile local writer can at worst warm the LRU. Stated as a security decision, not an accident. |

### 2.2 Retire the `.txt`; rewire every consumer

| Consumer (§1.3) | Today | After |
| --- | --- | --- |
| Python init fallback | `_load_zone_and_data_dbs()` reads stale-able, lossy interchange files | **Removed.** Manifest is the only source. Absent/unbuildable ⇒ empty DBs + **fail loud** (§2.3). HSTS load stays (it is not in the manifest — `_load_hsts_db` `:1023`, gated on `python_hsts`). |
| Reports/Alerts re-check | grep `.txt`, rewrite group/feed/mode, flag `isMatch` | **Gated off, code kept.** `pfb_dnsbl_parse` stays defined (still used by daemon mode until Phase 4, and reachable in non-python/`main` contexts) but the alerts render path stops calling it for DNSBL rows. Each row renders from its **own log line** (group@6, feed@8) — self-sufficient for both the DNSBL tab and the unified tab (one `convert_dnsbl_log()` covers both). |
| Webserver-hit attribution | `pfb_dnsbl_parse('daemon')` greps `.txt` | **Query channel.** `pfb_log_event` asks `pfb_py_query` for the domain's verdict; uses the returned `group`/`feed` for the `dnsbl.log` line and the widget counter. Miss/blocked=false ⇒ `Unknown` (never a wrong grep). |
| Health check | interchange-file presence drives `$dnsbl_missing` (`:16903-16972`) | **Manifest presence/generation.** `$dnsbl_missing` keys on the manifest + its ADR-10 generation (`pfb_unbound_py_marker_generation` `:9074` / `pfb_dnsbl_converged` `:9098` are the existing generation readers), not `pfb_py_zone`/`pfb_py_data` on disk; the rebuild-trigger semantics (`:16968-16972`) stay. |
| Interchange-file writers | `tld_analysis` finalize (`:8935`) + `pfb_dnsbl_py_swap` (`:2006`, call `:18138`) + the no-feeds/disable-path writes (`:18177-18191`) | **Removed.** No file is written; the manifest + per-feed raw files already carry the inputs and the build derives the classification. `tld_analysis`'s alias/stat bookkeeping (`tld_update` `:8800-8806`, the `DNSBL_TLD` alias `dnsbl_alias_update` loop `:8945-8952`) that is NOT interchange-file I/O is retained. The assembled `{dnsbl_file}.raw` concat (`:18127-18135`) is removed too IFF phase-time grep shows no remaining consumer. |
| IP alerts re-check | `convert_ip_log` greps the IP feed files | **Unchanged** — a grep faithfully answers "is this IP in this feed now"; IPs are not the complex DNSBL matcher. Out of scope. |

### 2.3 Fail loud, never stale

When `dnsbl_build_from_manifest` cannot produce the DBs, init leaves the DNSBL structures **empty**
(nothing blocked) and raises the failure through the existing ADR-61 ledger (already written,
§1.7) **and** a `file_notice` so the dashboard bell fires — a manifest failure is a loud, visible
outage, not a silent stale-serve. The manifest write path itself is hardened: the atomic publish
result, unchecked today at the sources write (`:8258`), is checked and a write failure notices too
(the sibling patcher at `:8293` already checks — follow it). Rationale: a blocklist that silently
serves stale data is false security; a loud "DNSBL not loaded" is correct for a security tool, and
the ADR-10 generation + the `:16968-16972` rebuild trigger already self-heal on the next
successful tick.

### Accepted user-visible deltas (the ONLY permitted output changes)

| # | Delta | Why it is acceptable |
| - | ----- | -------------------- |
| **D1** | `pfb_py_data.txt`/`pfb_py_zone.txt` are no longer written or read; `tld_analysis`'s classification pass and `pfb_dnsbl_py_swap` are removed | The manifest build already produces the production `dataDB`/`zoneDB` (§1.1); this is dead-weight removal. **Net DNS block/resolve decisions are unchanged** — pinned by the Phase-1 decision oracle. Dissolves #1244 + #1245. |
| **D2** | Reports/Alerts DNSBL rows no longer show the "not currently listed / feed-changed / TLD-carve-out" refinement badges; feed-name **filtering** now matches the **logged** feed, not the current one | The refinement rode a grep that could not reproduce the real matcher — it was an approximation shown as truth. Rendering the logged verdict is honest; filtering on what actually blocked the domain is arguably more correct. Release-note it. |
| **D3** | A manifest that is absent/unparseable/unbuildable now yields an **empty DNSBL + a loud notice** instead of a silent fallback to the last on-disk interchange files | The fallback masked failures, was the #1245 stale-serve vector, AND is **lossy** (§1.1 — every ABP feed's block/exception/regex rules are absent from it) — so it serves materially weaker blocking than production while looking healthy. Loud-fail + the ADR-10 self-heal is safer for a blocklist. |
| **D4** | Webserver-hit (VIP block-page) attribution + its widget counter group now come from the **live matcher** (query channel) instead of a `.txt` grep | Strictly more accurate (full matcher vs classified-subset grep); identical group for a domain the matcher blocks. |

Anything else changing — a net block/resolve decision, a per-group **DNS-block** counter, a stored
config key, an alias name, the IP re-check, the log line schema — is a **defect**, not a delta.

### Semantics that MUST be preserved (pin with tests BEFORE any swap)

1. **Net PRODUCTION (manifest-built) DNS decisions are unchanged.** Every domain the manifest build
   blocks/allows today it blocks/allows after — this is the production path (the fallback ran
   only on a manifest-build FAILURE, §1.1). Removing the fallback does **not** claim manifest ==
   fallback (the fallback is lossy and stale-able, §1.1); it replaces a degraded,
   failure-only path with fail-loud (D3). Pinned by the Phase-1 decision oracle over a corpus,
   which pins the manifest-built decisions and characterizes — does not equate — the fallback.
2. **The query channel is decision-equal to a real query.** For any `(domain, qtype)`, the reply's
   `blocked` + `{b_type,group,b_eval,feed,p_type}` equal what `operate()` would log for the same
   name against the same DBs.
3. **The query channel has no query side effects except the LRU.** No `resolver`/`dnsbl` counter
   bump, no `dnsbl.log` line, no `dnsblcache` row across a query; `decisionDB` may change.
4. **HSTS still loads** regardless of the manifest (it is not in the manifest build —
   `_load_hsts_db` `:1023`, unconditional of `dnsbl_built` inside
   `_load_whitelist_and_hsts_dbs` `:1058`).
5. **Widget per-group DNS-block counters** (Python `_db_flush_dnsbl`) and resolver totals are
   unchanged; only the **webserver-hit** counter's group source moves (grep → query), same value.
6. **The alerts/unified table renders every row from its own log line** — no attribution is lost by
   dropping the re-check (group@6, feed@8 are in the line).
7. **No stored config key, alias name, page filename, or log-line schema changes.**
8. **The IP alerts re-check is untouched.**

### Explicitly kept / out of scope

- The **IP** side (`convert_ip_log` grep) — a grep is accurate for IP membership; unchanged.
- `pfb_dnsbl_parse` / the DNSBL grep helpers stay **defined** (gated off for alerts, reused by the
  daemon path until Phase 4, and reachable on `main`/non-python) — removal is a later cleanup.
- `dnsblcache`'s per-block Python write (`:6750`) — its grep-cache role ends, but removing the
  table is a follow-up (a tracking issue), not this ADR; the query channel makes it vestigial.
- `main`-branch (native-mode) behaviour — this ADR targets `devel` (python-mode). Any `main`
  backport is separate.

## 3. Consequences

- **#1244 and #1245 dissolve** — the code they describe stops existing.
- **A whole class of silent failure disappears** — a build failure can no longer quietly serve
  stale `.txt`; it fails loud.
- **Attribution gets more accurate** — webserver-hit + any on-demand "is X blocked?" now ask the
  real matcher, not a grep that never saw regex/whitelist/precedence.
- **The DNSBL surface shrinks** — one classification producer (the manifest), no `.txt` lifecycle,
  no grep, no swap file-mgmt.
- **New local IPC surface** — the query channel. Read-only, side-effect-bounded, but it is a new
  attack/`DoS` surface to reason about (§2.1 privilege row; hostile-input rows in Phase 2/3).
- **User-visible:** the reports "changed since" refinement badges go away and feed-filtering
  semantics shift (D2). Release-noted.
- **Latency:** the webserver-hit path gains a round-trip to the module per hit. It is off the DNS
  fast path (daemon context, one event at a time); bounded-wait with an `Unknown` fallback.

## 4. Requirements (acceptance)

1. The Phase-1 decision oracle re-runs GREEN after the `.txt` fallback is removed — **zero** net
   decision changes (Semantic 1).
2. The query channel is decision-equal to `operate()` on a corpus incl. regex/ABP, whitelist
   override, TLD-zone, HSTS, and not-blocked (Semantic 2), and provably side-effect-free except the
   LRU (Semantic 3) — both pinned by pytest.
3. `pfb_log_event` attributes a webserver hit via the query channel; a PHPUnit test drives it
   against a faked channel and asserts the widget counter + `dnsbl.log` line carry the query's
   group/feed (D4), and `Unknown` on a miss.
4. The alerts/unified DNSBL rows render from the log line with the re-check gated off; Tier-A
   `ui_render` proves the Alerts + Reports + Unified pages 200 with a marker and no new
   `php_error.log` line, and a row shows the logged feed/group (D2).
5. A manifest made absent/unparseable on the live VM yields an **empty DNSBL + a `file_notice` +
   the ADR-61 widget out-of-sync state** and **no stale block** (D3), and the next good tick
   self-heals.
6. `config.xml` is byte-identical across an upgrade; no stored key moves.
7. ADR-06 carries a §8 amendment recording the retirement; `docs/misc/alerts-reports-pipeline.md`
   and architecture-notes reflect the one-phase (log-driven) attribution model.

## 5. Constraints (from CLAUDE.md)

- **Stdlib only inside Unbound's loader** — the query channel uses `os`/`json`/`select`/`threading`,
  no external deps; mirrors the existing watchers.
- **No Python on the appliance beyond `pfb_unbound.py`** — the PHP query client drives the channel;
  no `python3` invocation.
- **PHP 8.3**, tabs, `TRUE`/`FALSE`, `PfbConfig` for any registered key, no `die()`/`exit()` in
  library code, PFBL-01 `RequirePfbFilter` on new input handlers.
- **POSIX-sh** for any shell; **`LC_ALL=C`** on machine-data sorts (none expected here).
- **No live Unbound in CI** — the running module answers queries only on the live VM; the pytest
  suite drives the pure decision + a channel harness with the module's globals, and the end-to-end
  query is a smoke row.
- **Test coverage mandate** — behaviour-preserving phases pin an oracle that stays green;
  behaviour-changing phases are red→green against it with the deltas D1–D4 enumerated.

## 6. Action plan (phases)

### Phase 1 — Oracle: pin today's decision + characterize the fallback (behaviour-preserving)

- Golden decision oracle (Oracle A): a corpus of `(domain, qtype)` through the production
  `evaluate_domain` path (block/allow verdict + the `{b_type,group,b_eval,feed,p_type}` it would
  log), covering exact/zone/regex/ABP/allow/whitelist/TOP1M/`$important`/HSTS/homoglyph/
  not-blocked — and BOTH TLD-toggle states (oracle loaded vs empty, §1.1). This is the
  falsification harness Phases 2/5/6 are gated on (Semantics 1, 2).
- Oracle B — **characterization of the fallback** (`dnsbl_build_from_manifest` vs the legacy
  loaders on the same feeds); it does NOT assert equality. Four pinned facts (§1.1):
  (a) **trigger** — the legacy loaders populate the DBs only when the manifest build returned
  `None`; (b) **lossiness** — with an ABP feed among the inputs, the fallback DBs carry NO
  ABP-derived entries and empty `regexDB`/`allowRegexDB` while the manifest build carries them;
  (c) **staleness** — interchange files seeded with content that no longer matches the manifest
  inputs ARE served verbatim on a build failure (this is Phase 5's red baseline); (d) **fresh
  plain-domain parity** — fresh interchange files agree with the manifest build's zone/data
  classes in both toggle states (2-label, 3-label, sub-domain rows). If (d) does not hold, or a
  fallback load runs while the manifest built, STOP and ESCALATE — a §1.1 fact is falsified.
  Test surface: `tests/test_adr65_decision_oracle.py` driving the real functions; pin the entry
  symbols from source.
- Blast radius: NONE (tests only).

### Phase 2 — The read-only query channel in `pfb_unbound.py` (new; PRODUCTION-DORMANT)

- `pfb_py_query`/`pfb_py_query.reply` watcher (mirror `pfb_control_watcher` `:799`), a
  `dnsbl_query_answer(domain, qtype)` that calls the pure decision and returns the reply dict, and
  the always-on start in init.
- **Side-effect-free**: no counter enqueue, no `dnsbl.log`, no `dnsblcache`; `decisionDB` may write.
  Pinned by a test asserting each side-effect sink is untouched across a query.
- Hostile-input rows (the request JSON parser): empty/missing `domain`, punycode/IDN + non-ASCII,
  oversized domain, malformed JSON, non-string fields, missing `id`, `qtype` unknown, a `domain`
  with embedded newline/comma/`;`. Decision-equal to `operate()` (Phase-1 oracle).
- Blast radius: PRODUCTION-DORMANT (no consumer yet); the watcher thread starts but nothing writes
  the request file.

### Phase 3 — The PHP query-channel client in `pfblockerng_extra.inc` (new; PRODUCTION-DORMANT)

- `pfb_dnsbl_query($domain, $qtype)` — atomic-write the request, bounded-wait the reply by `id`,
  parse it, return the verdict array or `NULL` on timeout. Reuse the atomic-write + bounded-wait
  helpers the reload/applied path uses.
- Hostile-input rows (the reply parser): absent reply (timeout), truncated/malformed JSON, `id`
  mismatch, `blocked=false`, oversized reply. PHPUnit against a faked on-disk channel.
- Blast radius: PRODUCTION-DORMANT (no caller yet).

### Phase 4 — Rewire consumers: webserver-hit → query; gate off the alerts re-check (behaviour-CHANGING: D2 + D4)

- `pfb_log_event` (`:15171`, grep at `:15190`): replace `pfb_dnsbl_parse('daemon', …)` with
  `pfb_dnsbl_query()`; use its group/feed for the `dnsbl.log` line + the widget counter
  (`:15210`); `Unknown` on NULL/blocked=false.
- `pfblockerng_alerts.php` `convert_dnsbl_log()` (`:2262`): stop calling
  `pfb_dnsbl_parse('alerts', …)` for DNSBL rows (both non-unified and unified paths; the
  compare block `:2330-2372` AND the failed-match re-derive `:2375-2378` both go); render the
  logged fields. Keep `pfb_dnsbl_parse` defined; keep the FIRST `dnsbl_whitelist_type` call
  (`:2320`). Remove the now-dead DNSBL prefetch wiring — the #809 two-pass buffer/replay
  scheme (`pfb_dnsbl_prefetch` `:4509`, `pfb_dnsbl_prefetch_store(NULL)` `:4543`, the
  buffer/replay helpers), enumerated from source at phase time.
- Red→green against the Phase-1 oracle + a PHPUnit `pfb_log_event` test; Tier-A `ui_render` for
  Alerts/Reports/Unified. Delta budget: **D2 + D4 only**.

### Phase 5 — Remove the Python init fallback + fail loud (behaviour-CHANGING: D3; dissolves #1245)

- Delete `_load_zone_and_data_dbs` (`:1045`) + `_load_zone_db`/`_load_data_db`/
  `_load_whitelist_db` (`:942`/`:968`/`:991`) + `_load_ndjson_row_into_db` (`:913`) if no other
  caller remains (grep first); keep the status-close bookkeeping and the HSTS load
  (`_load_hsts_db` `:1023` — restructure `_load_whitelist_and_hsts_dbs` `:1058` so only its
  whitelist arm dies; Semantic 4). On `build_result is None`, leave DBs empty and raise
  `file_notice` + the ADR-61 ledger (§2.3); harden the unchecked manifest-write result
  (`:8258`; the sibling `:8293` is the checked exemplar).
- Red proof: a test that makes the manifest unbuildable and asserts DBs stay empty + the ledger/notice
  fires + no stale data is served (was: silently loaded — Oracle B fact (c)). Delta budget: **D3 only**.

### Phase 6 — Stop writing the interchange files + move the health check onto the manifest (behaviour-CHANGING: D1; dissolves #1244)

- Remove `tld_analysis`'s classification outputs + finalize `rename()` loop (`:8746`,
  `:8935-8941`) and `pfb_dnsbl_py_swap` (`:2006`, call `:18138`), the no-feeds-path
  empty-data write + zone unlink (`:18177-18178`) and the disable-path data/zone unlinks
  (within `:18184-18189`; the `.conf`/manifest/rawdir cleanup stays); retain `tld_analysis`'s
  non-interchange alias/stat bookkeeping (`:8800-8806`, `:8945-8952`). Remove the assembled
  `{dnsbl_file}.raw` concat (`:18127-18135`) IFF a phase-time grep shows no remaining
  consumer. Health check (`:16903-16972`) keys on manifest presence/generation, not
  `pfb_py_zone`/`pfb_py_data`; rebuild-trigger semantics (`:16968-16972`) stay.
- Red→green against the Phase-1 oracle (decisions unchanged, D1). Delta budget: **D1 only**.

### Phase 7 — Smoke, docs, ADR-06 amendment, DoD

- Live-VM smoke: a query-channel round-trip returns the correct verdict with **no** counter/log
  side effect; a manifest-absent run shows empty DNSBL + notice + widget out-of-sync + no stale
  block, then self-heals (D3); reports render from logs (D2); webserver-hit attribution via query
  (D4). CE + Plus fan-out.
- Docs: rewrite `docs/misc/alerts-reports-pipeline.md` to the one-phase log-driven model; update
  architecture-notes; **amend ADR-06 §8** (manifest = single source, interchange files retired,
  fail-loud); release-note D2; close #1244/#1245; file the follow-up issue for retiring
  `dnsblcache`/the `pfb_dnsbl_parse` grep helpers — out of scope here. (The originally planned
  "vestigial `pfb_tld`" issue is moot: #1255 made the toggle gate the manifest path.)

## 7. Definition of done

- All seven phases landed; canonical gates green (`scripts/agent/run-gates.sh --diff origin/devel`).
- The Phase-1 decision oracle re-runs GREEN — zero net decision changes; the query channel is
  decision-equal and side-effect-free (except LRU).
- The four accepted deltas D1–D4 are the ONLY observable output changes.
- **Live-VM CE + Plus fan-out** (the org-default matrix) green on the query-channel, fail-loud,
  reports-from-logs, and webserver-hit-attribution smoke rows.
- `config.xml` byte-identical across an upgrade.
- ADR-06 §8 amended; #1244/#1245 closed; the `dnsblcache`/grep-helper cleanup issue filed.
- **Manual smoke checklist (owner: maintainer)** — CI cannot run the module: (a) `drill` a
  uuid-domain feed match on-box, confirm the block AND that `dnsbl.log` gets exactly one line while
  a `pfb_dnsbl_query` of the same name adds **none**; (b) remove the manifest, confirm empty DNSBL +
  dashboard bell + widget out-of-sync + no stale block, then a Force reload self-heals; (c) load a
  block-page (VIP) hit and confirm the widget group counter increments with the query-derived group.
- **Reject criteria:** the query channel is measurably NOT decision-equal to `operate()` on the
  corpus; or a query mutates any counter/log/`dnsblcache`; or removing the fallback changes any net
  decision on the oracle; or the webserver-hit latency of the query round-trip is unacceptable on a
  smallest-box profile with no viable `Unknown`-fallback mitigation.

## 8. Rejected alternatives

- **Keep the interchange-file fallback as a safety net.** Rejected: it is the #1245 stale-serve
  vector, it is lossy (§1.1 — no ABP/regex/allow rules), and it is a second, drifting source of
  truth; the ADR-10 generation + the `:16968-16972` rebuild trigger already provide the real
  safety net (self-heal), and loud-fail is correct for a blocklist.
- **Answer "what blocks it right now?" by grepping the interchange files (status quo) or the manifest raw.**
  Rejected: neither reproduces the full matcher (regex/ABP, whitelist precedence, TOP1M,
  `$important`, HSTS, homoglyph); the manifest raw is unclassified per-feed. Only the live matcher
  is authoritative — hence the query channel.
- **Build a durable per-domain attribution DB for reports.** Rejected as unnecessary: the block-time
  `dnsbl.log`/`unified.log` line already carries feed/group; the alerts table is log-driven and
  self-sufficient once the re-check is dropped (retention is the user's to configure).
- **Overload the existing PFBL-03 mutating channel with a `check` command.** Rejected: it is
  privileged, seq-gated, and fire-and-forget (no data reply); a read-only query wants a separate,
  always-on, unprivileged, request/reply channel — @andrebrait's "always-on read-only parallel."
- **A Unix-domain socket for the query channel.** Deferred, not rejected: the file channel matches
  existing code and suffices for one-event-at-a-time; the socket is the documented upgrade path if
  latency/concurrency ever demands it.
