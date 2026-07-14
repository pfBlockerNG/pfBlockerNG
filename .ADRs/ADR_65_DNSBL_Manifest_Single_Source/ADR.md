# ADR-65: Make the manifest the single source of truth for DNSBL — retire the `py_data`/`py_zone` interchange files and add a read-only decision query channel

- **Status:** **Proposed** (2026-07-13)
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

### 1.1 The manifest is already the primary source; the `.txt` files are a fallback and a mirror

ADR-06 moved parse/normalise/classify into Python. `init_standard()` prefers the per-feed
**manifest** (`pfb_py_sources.json`): `dnsbl_build_from_manifest()` (`pfb_unbound.py:5327`) builds
`dataDB`/`zoneDB`/`whiteDB`/`regexDB` from the raw feeds via the pure `build()` layer, and only when
it returns `None` — manifest **absent** (`:5341`), **unparseable** (`:5350`), or `build()`
**threw** (`:5368`) — does init fall back to the legacy on-disk CSV/NDJSON loaders
`_load_zone_and_data_dbs()` (`:1037`, gated `if not dnsbl_built`) and `_load_whitelist_db()`
(`:1057`).

**The manifest build IS decision-complete — and its zone/data split is derived, not stored.** The
wildcard(zone) vs exact(data) distinction comes from two mechanisms: (a) **ABP** feed lines carry it
**intrinsically** — the manifest raw is the verbatim ABP line (`pfblockerng.inc:7820`), and
`parse_abp()` maps `||domain^` → zone, exact → data; (b) **plain** feed lines are bare domains (no
per-entry flag), and `build()`'s `tld_wildcard_classify()` (`pfb_unbound.py:4297`,
`DNSBL_CLASS_ZONE`/`_DATA`) computes the split from the `tld_wildcard_master` public-suffix
oracle (post-#1255 the shipped `pfb_py_tld` file, not a manifest key — see the update note
below). The manifest embeds `tld_wildcard_blacklist`/`tld_wildcard_exclusion` gated only on
`file_exists($pfb['dnsbl_tld_data'])` (`pfblockerng.inc:7879`) — a **shipped static file** —
so it was present **unconditionally**, and `tld_wildcard_classify()` is called **without any
`pfb_tld` gate** (`:5162`). For a 2-label domain `tld_wildcard_classify()` returns **ZONE
without even consulting `tld_wildcard_master`** (`:4315`), so `evil.com` → `zoneDB` (wildcard)
in every manifest build.

**Two consequences that correct an earlier assumption:**

- The manifest build is **NOT decision-equal to the `.txt` fallback when `pfb_tld` is OFF.** With
  `pfb_tld` OFF the `.txt` swap (`pfb_dnsbl_py_swap`, §1.2) puts the whole raw into `py_data` (exact,
  `py_zone` absent), so `evil.com` → exact-only there — while the manifest build wildcards it. The
  fallback is therefore not merely *redundant*, it is *divergent* — a second reason to remove it.
  (This is why the Phase-1 oracle pins the **manifest-built production decisions** and *characterizes*
  the fallback's divergence, rather than asserting equality.)
- **`pfb_tld` ("Enable TLD Function") does not gate wildcarding in the manifest era** — the manifest
  wildcards registrable domains regardless of the toggle; `pfb_tld` OFF now only reshaped the
  now-fallback `.txt`. `pfb_tld` is effectively **vestigial** in production. This is *orthogonal* to
  this ADR (it changes no decision here — production already wildcards), but the Phase-1 oracle work
  will expose it; Phase 7 files a tracking issue rather than resolving it in scope.

> **Post-#1255 / ADR-66 update (2026-07-14):** the facts above changed after this
> ADR was written. The public-suffix oracle is no longer embedded in the manifest —
> it rides the shipped `pfb_py_tld` chroot file, loaded reader-side into the
> internal `tld_wildcard_master` build key and gated by the `python_tld_wildcard`
> ini flag (HSTS parity), so the "Enable TLD Function" toggle (`pfb_tld` /
> `$pfb['dnsbl_tld_wildcard']`) now gates manifest-era wildcard classification too —
> the "vestigial toggle" consequence above is superseded. The manifest embeds only
> `tld_wildcard_blacklist`/`tld_wildcard_exclusion` (emptied when the toggle is
> off), and ADR-66 renamed the classifier/loader to `tld_wildcard_classify()` /
> `_dnsbl_load_tld_wildcard_master()`. This ADR's decisions are unaffected; its
> phase prompts' reality-override lines govern remaining detail drift.

### 1.2 What writes the `.txt` files, and the two-producer split

`pfb_py_data.txt` (exact) and `pfb_py_zone.txt` (wildcard-incl-self suffix) are produced two ways,
mode-exclusive on the `pfb_tld` ("Enable TLD Function") setting `$pfb['dnsbl_tld_wildcard']`
(`pfblockerng.inc:15955`):

- `pfb_tld` **ON** → `tld_analysis()` (`:8352`) classifies the assembled `.raw` into
  `py_data.txt` + `py_zone.txt`, promoted by the finalize `rename()` loop (`:8585`, the **#1244**
  site — return value discarded, logs "completed" unconditionally). `pfb_dnsbl_py_swap()` (`:1955`)
  early-returns.
- `pfb_tld` **OFF** → `pfb_dnsbl_py_swap()` renames the whole `.raw` → `py_data.txt` and
  `unlink_if_exists($py_zone)` on a **checked** success (`:1962`, the **#1241** crash-safety fix);
  a failed rename leaves a stale `py_zone.txt` (the **#1245** window).

The `dnsbl_build_from_manifest` path does **not** carry `pfb_tld` — it wildcard-classifies
via `tld_wildcard_master` (post-#1255 gated by the `python_tld_wildcard` ini flag — see the
§1.1 update note). So `pfb_tld` OFF only reshapes the on-disk `.txt` files; it does not change
the manifest-built decision.

### 1.3 Three consumers of the `.txt` files (all replaceable)

1. **Python init fallback** — `_load_zone_and_data_dbs()` reads `py_zone.txt`/`py_data.txt` into
   `zoneDB`/`dataDB` when the manifest did not build (`:1041-1043`). This is the #1245 read path,
   and it can serve a **stale** file silently.
2. **Reports/Alerts "what blocks it right now?" re-check** — `pfblockerng_alerts.php`'s
   `convert_dnsbl_log()` (`:2260`) calls `pfb_dnsbl_parse('alerts', …)` (`:2329`) which greps the
   `.txt` (`pfblockerng.inc:14342` zone, `:14308` data) to compare the logged group/feed/mode
   against "current" and flag `$isMatch = FALSE` (`:2336-2367`). **A grep of the classified `.txt`
   cannot reproduce the full matcher** (regex/ABP, allow-regex, whitelist precedence, TOP1M,
   `$important`, HSTS, homoglyph, upstream) — it is an approximation. `docs/misc/alerts-reports-
   pipeline.md:23`: *"The logs are self-sufficient for rendering a complete table; the render-time
   pass is a [refinement]."*
3. **Webserver-hit attribution** — a client hitting the DNSBL block-page (VIP) is logged by
   `pfb_daemon_dnsbl` → `pfb_log_event()` (`pfblockerng.inc:14803`), which has only `domain`+`src_ip`
   and greps the `.txt` via `pfb_dnsbl_parse('daemon', …)` (`:14819`) to attribute the event, then
   `UPDATE dnsbl SET counter = counter + 1 WHERE groupname = :pfb_group` (`:14838`) — feeding the
   dashboard widget's per-group count.

### 1.4 The logs and DB already carry authoritative attribution

At block time Python writes the full verdict to `dnsbl.log` — `csv_line` (`pfb_unbound.py:2812`)
carries `l_type, datetime, q_name, q_ip, p_type, b_type, group, b_eval, feed, dup, q_type`
(group at field 6, feed at field 8), computed by the **real** matcher (`evaluate_domain` `:6014` →
`highest_block_band` `:5817` → `get_details_dnsbl` `:2745`). The filterlog daemon mirrors that line
verbatim into `unified.log` via `pfb_unified_format_dnsbl()` (`pfblockerng_extra.inc:2031`,
group/feed preserved). The alerts/reports **event table is log-driven** (`pfblockerng_alerts.php`
sources `$pfb['dnslog']`, `:4252-4253`); `dnsblcache` (`type,domain,groupname,final,feed`) is only
the re-check's cache — Python writes it per block (`pfb_unbound.py:6726`) and **wipes it on every
swap** (`_db_reset_cache`, `:2569`) — and the widget reads durable per-group **counters**
(`dnsbl`/`resolver` tables), never the `.txt`.

### 1.5 Side effects a real query has (the ones a check must NOT have)

A served DNS query enqueues, on the block path: `("resolver",)` — totalqueries count (`:2763`);
`("dnsbl", group)` — per-group counter (`:2777`); the `dnsbl.log` line (`:2828`); the
`dnsblcache` row (`:6726`); and it writes the LRU memo `decisionDB[name] = dec` (`:5706`). All of
these except the LRU write live in the **log/emit path** (`get_details_dnsbl` and its callers),
not in the pure decision (`evaluate_domain`/`highest_block_band`).

### 1.6 The control channel we already have (PFBL-03)

`pfb_py_control` is a local JSON command channel: PHP writes `{seq, cmd, …}`; `pfb_control_watcher()`
(`pfb_unbound.py:795`) reads it off the query threads and routes fresh records (seq advance) through
`pfb_apply_control_command()` (`:3238`). The command vocabulary is **mutating actions**
(`disable|enable|addbypass|removebypass`, `_control_record_to_command` `:761`), and the only reply
is `_control_write_applied(seq)` (`:738`) — a seq **ack**, no data. It is privileged (root writes,
unbound reads, mode 0640) and gated behind the legacy-control toggle
(`warn_if_legacy_control_enabled` `:897`). **There is no request/reply data path today.**

### 1.7 Fail-loud plumbing already exists (ADR-61)

`dnsbl_build_from_manifest` already opens the ADR-61 status ledger on every failure —
`pfb_py_status_open("dnsbl", manifest_path, "parse", …)` at `:5352`/`:5370` (and closes it on the
absent case at `:5344`). The widget surfaces that ledger (`pfblockerng.widget.php:468`,
`pfb_py_sync_status_list_open`). The `file_notice()` dashboard-bell mechanism is used elsewhere for
DNSBL/MaxMind (`pfblockerng.inc:2644`, `:18216`). The bug is that init records the failure and
**then silently falls back to stale `.txt`**, masking what it just flagged.

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
| **Engine** | Runs the **pure decision** `evaluate_domain`/`highest_block_band` against the live `dataDB`/`zoneDB`/`regexDB`/`whiteDB`/`hstsDB` — the SAME code `operate()` uses, so the answer reflects the full matcher (regex/ABP, allow, whitelist precedence, TOP1M, `$important`, HSTS, homoglyph), never a grep approximation. |
| **Side effects** | **NONE that a real query has, except the LRU.** No `("resolver")`/`("dnsbl")` counter enqueue, no `dnsbl.log` line, no `dnsblcache` row. Writing the LRU `decisionDB` memo is **allowed** (it warms the cache and is decision-neutral). Pinned by a test that asserts every counter/log/cache is untouched across a query while `decisionDB` may change. |
| **Always-on** | The query watcher runs unconditionally (read-only ⇒ safe), independent of the legacy-control toggle. Started alongside the existing watchers in init. |
| **Transport** | File request + reply file keyed by `id`, reusing the control channel's kqueue-watch + atomic-write pattern (lazy: mirrors existing code). A Unix-domain socket is the documented upgrade path if per-event latency/concurrency ever demands it; the sole caller today is one-event-at-a-time (webserver hit), so a file channel suffices. |
| **Privilege** | Owner root, group `unbound`, mode **0660** on the request file (the attributing daemon must write it; it is read-only in effect — it mutates no state), reply file 0640. Read-only ⇒ no authorization beyond "local" is required; a hostile local writer can at worst warm the LRU. Stated as a security decision, not an accident. |

### 2.2 Retire the `.txt`; rewire every consumer

| Consumer (§1.3) | Today | After |
| --- | --- | --- |
| Python init fallback | `_load_zone_and_data_dbs()` reads stale-able `.txt` | **Removed.** Manifest is the only source. Absent/unbuildable ⇒ empty DBs + **fail loud** (§2.3). HSTS load stays (it is not in the manifest — `:1060`). |
| Reports/Alerts re-check | grep `.txt`, rewrite group/feed/mode, flag `isMatch` | **Gated off, code kept.** `pfb_dnsbl_parse` stays defined (still used by daemon mode until Phase 4, and reachable in non-python/`main` contexts) but the alerts render path stops calling it for DNSBL rows. Each row renders from its **own log line** (group@6, feed@8) — self-sufficient for both the DNSBL tab and the unified tab (one `convert_dnsbl_log()` covers both). |
| Webserver-hit attribution | `pfb_dnsbl_parse('daemon')` greps `.txt` | **Query channel.** `pfb_log_event` asks `pfb_py_query` for the domain's verdict; uses the returned `group`/`feed` for the `dnsbl.log` line and the widget counter. Miss/blocked=false ⇒ `Unknown` (never a wrong grep). |
| Health check | `.txt` presence drives `$dnsbl_missing` (`:16582`) | **Manifest presence/generation.** `$dnsbl_missing` keys on the manifest + its ADR-10 generation, not `py_zone`/`py_data` on disk. |
| `.txt` writers | `tld_analysis` finalize (`:8585`) + `pfb_dnsbl_py_swap` (`:1955`) | **Removed.** No file is written; the manifest already carries the classification. `tld_analysis`'s alias/stat bookkeeping (`tld_update`, `DNSBL_TLD` blacklist alias) that is NOT `.txt` I/O is retained. |
| IP alerts re-check | `convert_ip_log` greps the IP feed files | **Unchanged** — a grep faithfully answers "is this IP in this feed now"; IPs are not the complex DNSBL matcher. Out of scope. |

### 2.3 Fail loud, never stale

When `dnsbl_build_from_manifest` cannot produce the DBs, init leaves the DNSBL structures **empty**
(nothing blocked) and raises the failure through the existing ADR-61 ledger (already written,
§1.7) **and** a `file_notice` so the dashboard bell fires — a manifest failure is a loud, visible
outage, not a silent stale-serve. The manifest write path itself is hardened: the atomic publish
(`pfb_unbound_py_atomic_write`) result is checked and a write failure notices too. Rationale: a
blocklist that silently serves stale data is false security; a loud "DNSBL not loaded" is correct
for a security tool, and the ADR-10 generation + `:16607` rebuild trigger already self-heal on the
next successful tick.

### Accepted user-visible deltas (the ONLY permitted output changes)

| # | Delta | Why it is acceptable |
| - | ----- | -------------------- |
| **D1** | `py_data.txt`/`py_zone.txt` are no longer written or read; `tld_analysis`'s `.txt` classification pass and `pfb_dnsbl_py_swap` are removed | The manifest build already produces the identical `dataDB`/`zoneDB` (§1.1); this is dead-weight removal. **Net DNS block/resolve decisions are unchanged** — pinned by the Phase-1 decision oracle. Dissolves #1244 + #1245. |
| **D2** | Reports/Alerts DNSBL rows no longer show the "not currently listed / feed-changed / TLD-carve-out" refinement badges; feed-name **filtering** now matches the **logged** feed, not the current one | The refinement rode a grep that could not reproduce the real matcher — it was an approximation shown as truth. Rendering the logged verdict is honest; filtering on what actually blocked the domain is arguably more correct. Release-note it. |
| **D3** | A manifest that is absent/unparseable/unbuildable now yields an **empty DNSBL + a loud notice** instead of a silent fallback to the last on-disk `.txt` | The fallback masked failures, was the #1245 stale-serve vector, AND **diverged** from the manifest when `pfb_tld` was OFF (exact-only vs the manifest's wildcard, §1.1) — so it could serve *different* blocking than production. Loud-fail + the ADR-10 self-heal is safer for a blocklist. |
| **D4** | Webserver-hit (VIP block-page) attribution + its widget counter group now come from the **live matcher** (query channel) instead of a `.txt` grep | Strictly more accurate (full matcher vs classified-subset grep); identical group for a domain the matcher blocks. |

Anything else changing — a net block/resolve decision, a per-group **DNS-block** counter, a stored
config key, an alias name, the IP re-check, the log line schema — is a **defect**, not a delta.

### Semantics that MUST be preserved (pin with tests BEFORE any swap)

1. **Net PRODUCTION (manifest-built) DNS decisions are unchanged.** Every domain the manifest build
   blocks/allows today it blocks/allows after — this is the production path (the `.txt` fallback ran
   only on a manifest-build FAILURE, §1.1). Removing the fallback does **not** claim manifest ==
   fallback (they diverge when `pfb_tld` is OFF, §1.1); it replaces a divergent, rarely-hit path with
   fail-loud (D3). Pinned by the Phase-1 decision oracle over a corpus, which pins the manifest-built
   decisions and characterizes — does not equate — the fallback.
2. **The query channel is decision-equal to a real query.** For any `(domain, qtype)`, the reply's
   `blocked` + `{b_type,group,b_eval,feed,p_type}` equal what `operate()` would log for the same
   name against the same DBs.
3. **The query channel has no query side effects except the LRU.** No `resolver`/`dnsbl` counter
   bump, no `dnsbl.log` line, no `dnsblcache` row across a query; `decisionDB` may change.
4. **HSTS still loads** regardless of the manifest (it is not in the manifest build — `:1060`).
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
- `dnsblcache`'s per-block Python write (`:6726`) — its grep-cache role ends, but removing the
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

### Phase 1 — Oracle: pin today's decision + manifest==fallback equality (behaviour-preserving)

- Golden decision oracle: a corpus of `(domain, qtype)` through the production `evaluate_domain`
  path (block/allow verdict + the `{b_type,group,b_eval,feed,p_type}` it would log), covering
  exact/zone/regex/ABP/allow/whitelist/TOP1M/`$important`/HSTS/homoglyph/not-blocked. This is the
  falsification harness Phases 2/5/6 are gated on (Semantics 1, 2).
- Oracle **characterizing** `dnsbl_build_from_manifest` vs the legacy `_load_zone_and_data_dbs` load
  on the same feeds — it pins the manifest-built decisions AND documents the **divergence** the
  fallback introduces (with `pfb_tld` OFF the fallback is exact-only while the manifest wildcards a
  registrable domain, §1.1). It does NOT assert equality (they are not equal). This is the evidence
  that Phase 5 removes a *divergent*, manifest-failure-only path (replaced by fail-loud, D3), not a
  decision-equal twin. Test surface: `tests/test_adr65_decision_oracle.py` driving the real
  functions; pin the entry symbols from source. If a 2-label plain domain does NOT land in `zoneDB`
  from the manifest build, STOP and ESCALATE — the §1.1 wildcard-unconditional fact is falsified.
- Blast radius: NONE (tests only).

### Phase 2 — The read-only query channel in `pfb_unbound.py` (new; PRODUCTION-DORMANT)

- `pfb_py_query`/`pfb_py_query.reply` watcher (mirror `pfb_control_watcher` `:795`), a
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

- `pfb_log_event` (`:14819`): replace `pfb_dnsbl_parse('daemon', …)` with `pfb_dnsbl_query()`; use
  its group/feed for the `dnsbl.log` line + the widget counter; `Unknown` on NULL/blocked=false.
- `pfblockerng_alerts.php` `convert_dnsbl_log()`: stop calling `pfb_dnsbl_parse('alerts', …)` for
  DNSBL rows (both non-unified and unified paths); render the logged fields. Keep `pfb_dnsbl_parse`
  defined. Remove the now-dead batched prefetch wiring for DNSBL.
- Red→green against the Phase-1 oracle + a PHPUnit `pfb_log_event` test; Tier-A `ui_render` for
  Alerts/Reports/Unified. Delta budget: **D2 + D4 only**.

### Phase 5 — Remove the Python init fallback + fail loud (behaviour-CHANGING: D3; dissolves #1245)

- Delete `_load_zone_and_data_dbs`'s fallback arm + `_load_zone_db`/`_load_data_db`/
  `_load_whitelist_db`; keep the status-close bookkeeping and the HSTS load (Semantic 4). On
  `build_result is None`, leave DBs empty and raise `file_notice` + the ADR-61 ledger (§2.3); harden
  the atomic manifest-write result check.
- Red proof: a test that makes the manifest unbuildable and asserts DBs stay empty + the ledger/notice
  fires + no stale data is served (was: silently loaded). Delta budget: **D3 only**.

### Phase 6 — Stop writing the `.txt` + move the health check onto the manifest (behaviour-CHANGING: D1; dissolves #1244)

- Remove `tld_analysis`'s `.txt` classification + finalize `rename()` loop (`:8585`) and
  `pfb_dnsbl_py_swap` (`:1955`) and the `#546`/disable-path `.txt` unlinks; retain `tld_analysis`'s
  non-`.txt` alias/stat bookkeeping. Health check (`:16582`) keys on manifest presence/generation,
  not `py_zone`/`py_data`.
- Red→green against the Phase-1 oracle (decisions unchanged, D1). Delta budget: **D1 only**.

### Phase 7 — Smoke, docs, ADR-06 amendment, DoD

- Live-VM smoke: a query-channel round-trip returns the correct verdict with **no** counter/log
  side effect; a manifest-absent run shows empty DNSBL + notice + widget out-of-sync + no stale
  block, then self-heals (D3); reports render from logs (D2); webserver-hit attribution via query
  (D4). CE + Plus fan-out.
- Docs: rewrite `docs/misc/alerts-reports-pipeline.md` to the one-phase log-driven model; update
  architecture-notes; **amend ADR-06 §8** (manifest = single source, `.txt` retired, fail-loud);
  release-note D2; close #1244/#1245; file the follow-up issues for (a) retiring `dnsblcache`/the
  `pfb_dnsbl_parse` grep helpers and (b) the **vestigial `pfb_tld`** toggle (does not gate
  wildcarding in the manifest era, §1.1) — both out of scope here.

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

- **Keep the `.txt` fallback as a safety net.** Rejected: it is the #1245 stale-serve vector and a
  second, drifting source of truth; the ADR-10 generation + `:16607` rebuild already provide the
  real safety net (self-heal), and loud-fail is correct for a blocklist.
- **Answer "what blocks it right now?" by grepping the `.txt` (status quo) or the manifest raw.**
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
