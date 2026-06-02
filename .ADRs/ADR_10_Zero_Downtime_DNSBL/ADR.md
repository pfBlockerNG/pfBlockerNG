# ADR-10: Zero-downtime DNSBL updates (background build + atomic snapshot swap)

- **Status:** **Proposed** (2026-06-02)
- **Date:** 2026-06-02
- **Branch:** `adr/10` (off **`next`** — depends on **ADR-07 "Full ABP-style DNSBL support"** having landed: the snapshot must bundle ADR-07's final matcher strata, and the build is heavier post-ABP, which is *why* the swap goes off-thread) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (the build/swap site + the query-time matcher + a new reload-watcher thread), `pfblockerng.inc` (`pfb_reload_unbound`/`pfb_stop_start_unbound`, the manifest writer, the DNSBL-IP/queries-daemon coordination), `pfb_unbound_include.inc`/shell (atomic publish + sentinel).
- **Target runtime:** Python 3.11+ inside Unbound's `pythonmod`, **stdlib only** (no subprocess, no out-of-stdlib deps; `select.kqueue`/`os` for the watcher); PHP 8.3; POSIX `sh`.
- **Test suite:** `tests/test_pfb_unbound.py`, `tests/conftest.py`, the **retained** `tests/test_adr06_*` and `tests/test_adr07_*` decision oracles (must stay green — the swap changes *when* structures change, never *what decision* they yield); new `tests/test_adr10_*` (single-snapshot equivalence, rebuild-and-swap atomicity/fail-closed, watcher logic). The peak-RAM kill-gate reuses `benchmarks/spike_adr06_build.py`.

---

## 1. Context

### Today (verified on `next`, post-ADR-06; ADR-07 assumed landed before this ADR builds)

A DNSBL list update in **Python DNSBL mode** (the default since ADR-02 dropped Unbound mode) is applied by **restarting Unbound** — that restart *is* the downtime this ADR removes.

1. **Update path = full Unbound restart.** `pfb_reload_unbound($mode, $cache, $pfbpython)` (`pfblockerng.inc:3095`) **always** calls `pfb_stop_start_unbound($type)` (`:3118`, again `:3138`), which `sigkillbypid("{$g['varrun_path']}/unbound.pid", 'TERM')` (`:3055-3061`) — i.e. **TERMs and restarts unbound**. The resolver cache is optionally `dump_cache`'d before and `load_cache`'d after (`:3113`, `:3153`) to avoid re-resolving, **but the service is down for the stop→start window**: in-flight queries are dropped/refused and, on restart, `init_standard` re-runs the **entire** (now ABP-heavy) build before answering again.
2. **Even the "Live sync" path restarts.** The comment "'Live sync' new DNSBL updates utilizing unbound-control" (`:3258`) precedes `pfb_reload_unbound($mode, TRUE, …)` (`:3259`) — the `unbound-control` live-sync only ever applied to **legacy** mode (blocklist = unbound `local_data`). In **Python** mode the blocklist lives in the module's in-memory dicts, which `unbound-control` cannot touch → the restart is the only way to apply it today.
3. **The build is already swap-ready.** `dnsbl_build_from_manifest(manifest_path) -> BuildResult | None` (`pfb_unbound.py:2118`) calls the pure, reentrant `build()` (`:1966`; docstring "reentrant / zero-downtime-ready", `:1984`) which **mutates no global**. The init-time application is a plain reassignment of four module globals (`pfb_unbound.py:555-562`: `dataDB`, `zoneDB`, `feedGroupIndexDB`, `whiteDB`), explicitly flagged "the build call site is the future zero-downtime swap point" (`:552`) and "a future zero-downtime reload can run it on a background thread and atomically swap in" (`:1678`, `:2122`).
4. **The matcher reads several globals per query — assigned separately today.** `evaluate_domain` (`pfb_unbound.py:2251`) reads a `containers` dict assembled per query (`:2661-2671`) from `dataDB`/`zoneDB`/`whiteDB`/`regexDB` (+ ADR-07's `allowRegexDB`, `important_rules`). These are **four-plus independent module globals** (`:87-96`, init `:383-390`) — reassigned one-by-one at `:559-562`. A naive background swap that reassigns them individually lets a mid-swap query read **new `dataDB` + old `whiteDB`** (a torn, inconsistent decision).
5. **Existing background-thread infrastructure.** The module already runs daemon worker threads — `pfb_db_worker` (`:1052`, started `:728-733`) and `pfb_async_worker` (`:165`, started `:739-744`) — gated on `pfb["mod_threading"]`, with DB access serialized by `_db_lock` (`:917`). So spawning **one more** daemon thread (the reload-watcher) is established-safe.
6. **Python-side caches.** (a) `pfb_py_cache.sqlite` (`pfb["pfb_py_cache"]`, `:336`) is the **Reports-tab log** (`dnsblcache` table, `:951`), written *after* a block decision (`:2721`) and **removed at init** today (`:340-342`); it is **never read by the matcher** (not a decision cache). (b) There is **no in-process decision memoization** — `evaluate_domain` re-reads the containers every query. This is **deliberate and correct**: at ≈1 µs/lookup (ADR-05/07) a per-domain decision cache would be pointless, so the swap has **no decision cache to invalidate** — the snapshot *is* the single source of truth. → The only Python-side state to handle on a swap is the Reports sqlite (parity with the restart's `os.remove`), cleared **through `_db_lock`/the db-queue** to not race `pfb_db_worker`; whether that async per-block write path is even worth keeping is itself benchmarked (§2, Bonus 2).
7. **Unbound's C-side message cache (the asymmetric staleness).** Blocked replies set `qstate.no_cache_store = 1` (`:2456`) → **blocks are never cached**. Therefore **block→allow flips apply immediately** (next query re-evaluates, now resolves), but **allow→block flips can keep serving the previously-cached real answer until its TTL** unless that name is flushed from Unbound's cache. Today's reload preserves the cache (`dump_cache`/`load_cache`), so today carries the same allow→block staleness.
8. **The manifest is written by PHP/shell** to `/var/unbound/pfb_py_sources.json` (`inc:114`, `pfb["pfb_py_sources"]` `:333`) plus per-feed raw. Nothing today guarantees the plugin can't read a **half-written** manifest during an update — today it doesn't matter because the plugin only reads it at init (post-restart). A no-restart swap makes concurrent read/write a live hazard.

### Load-bearing premise to falsify FIRST (Phase 1)

**Unbound `pythonmod` threading/visibility model.** Unbound serves queries on `num-threads` worker threads. The whole approach — *one* background build + *one* atomic global-ref swap serving *all* query threads — holds **iff those threads share one Python interpreter and one set of module globals** (so a reassignment on the watcher thread is visible to every query thread under the GIL). If instead each worker has **isolated** globals (separate interpreters / per-thread module state), a single swap is invisible to the other workers and the design **breaks**. This must be confirmed (Unbound docs + a live-box probe — there is no live Unbound in CI) **before** any phase is built. This is the ADR-01 trap guard: do not build the machinery on an unproven concurrency premise.

---

## 2. Decision

Apply DNSBL updates **without restarting Unbound**: the running module rebuilds the matcher structures **on a background thread** off the existing live structures, then **atomically swaps in a single immutable snapshot reference** — GIL-atomic, so every query thread sees either the whole old snapshot or the whole new one, never a mix. PHP stops restarting Unbound for a **data-only** update and instead **atomically publishes** the new manifest and **flips a single sentinel**; a watcher thread inside the module wakes on it and runs the rebuild+swap. The swap also **clears the Python report cache** and **flushes the Unbound C-cache for newly-blocked names**. The premise (shared-interpreter visibility) and the cost (≈2× transient RAM) are **falsified first (Phase 1)**; a config change, a failed build, or a constrained/unsupported box **falls back to today's restart** (fail-safe).

| Area | Decision |
| --- | --- |
| **Publish protocol (the safety barrier)** | PHP/shell writes the new manifest + per-feed raw into a **staging dir**, `fsync`s, then **atomically `rename`s** into place, and finally **flips a single sentinel file** (`mtime` bump / write of the new generation id). The sentinel flip is the **all-or-nothing commit**: the plugin only ever reads a **fully-written, immutable** manifest set. This — *not* notify latency — is what guarantees "never read a file mid-write" (Context 8). |
| **Trigger / watch** | A new **reload-watcher daemon thread** (started in `init_standard` next to `pfb_db_worker`/`pfb_async_worker`, `:728-744`) waits on the sentinel: **`select.kqueue` `EVFILT_VNODE`** on the sentinel's directory where available (FreeBSD; **`inotify` is Linux-only, not present on pfSense**), with a **low-frequency `mtime` poll fallback**. Notification is **best-effort**; correctness rides on the atomic publish + the generation id, so a missed/coalesced event only delays, never corrupts. On trigger → `rebuild_and_swap()`. |
| **Atomic swap shape (single snapshot)** | Replace the four-plus separate globals (`:559-562`) with **one module-level reference** to a **frozen `Snapshot`** bundling *all* ADR-07 strata: `dataDB`, `zoneDB`, `whiteDB`, `regexDB`, `allowRegexDB`, `feedGroupIndexDB`, the `important_rules` flag, and the counts. `evaluate_domain`/`op` capture the **one** reference at query start and read every field off it — so a query is internally consistent even if a swap lands mid-query. The swap is a single `STORE_NAME` (GIL-atomic). **No lock in the per-query hot path.** |
| **Background rebuild** | `rebuild_and_swap()` runs `build()`/`dnsbl_build_from_manifest()` (already pure, `:1966`/`:2118`) **on the watcher thread**, off the live snapshot. Query threads keep serving the **old** snapshot throughout the build (seconds for a big ABP list) → **zero downtime, briefly stale by design**. Only on a **successful** build is the snapshot ref rebound. Concurrent triggers are **coalesced** (a rebuild-in-progress flag / single-flight); a trigger during a build re-checks the generation id and rebuilds once more if it advanced. |
| **Fail-closed** | If the build returns `None`/raises (bad/partial manifest, OOM), **keep the old snapshot live** — never swap to an empty or partial set, never "fail open" to no blocking. Log + leave the last-good snapshot serving. (Mirrors the existing `build_result is not None` guard at `:558`.) |
| **Cache model — snapshot is the single source of truth (Bonus 2)** | **No Python decision cache exists or is added** — at ≈1 µs/lookup a per-domain memo is pointless (verified `main`==`next`: only the Reports sqlite + `no_cache_store` exist; no decision cache in either). So a swap needs **zero decision-cache invalidation**; the snapshot is the only authority. Two non-decision caches remain and are handled below: the **Reports sqlite** (telemetry) and **Unbound's C message cache** (network-latency, not matcher cost — kept). |
| **Reports-log on swap (Bonus 1 — restructure)** | Today the restart `os.remove`s `pfb_py_cache.sqlite` (`:340-342`). On a no-restart swap, either (a) **clear** it through `_db_lock`/the db-queue (parity, simplest), or — cleaner — (b) **generation-key** the log (add a `generation` column; the Reports UI reads the current generation) so a swap is a metadata bump, not a destructive wipe, and history survives. Phase 3 picks the cleaner one that the Reports UI can read. **Bonus 2:** Phase 1 also benchmarks whether the per-block async write path (`pfb_db_enqueue("cache", …)` `:2721`) earns its keep at all vs the µs matcher — if negligible, simplify/drop it. |
| **C-cache flip (benchmark-driven)** | allow→block names can serve a stale **resolve** until TTL; block→allow is **immediate** (`no_cache_store=1`, Context 7). Decide by Phase-1/5 measurement: **targeted delta `flush`** of newly-blocked names (correct, one control round-trip each) vs **accept TTL-bounded staleness** (do nothing — **not a regression**: today's restart already preserves the cache) vs a bounded `flush_zone`. Coalesced + coordinated with the DNSBL-queries-daemon `unbound-control` marker (`:3211`) to avoid control-socket collisions. |
| **PHP reload fork (data fast-path + restart fallback)** | `pfb_reload_unbound` gains a **data-only** path: a **DNSBL-data** update in Python mode → **atomic publish + flip sentinel, NO `pfb_stop_start_unbound`**. A **config** change (unbound.conf/VIP/mode toggle) → **still the restart** (`:3118`). The restart also remains the **fallback** when zero-downtime is unavailable (premise/RAM gate failed, feature off, or a swap errored). One `$mode`/flag drives the fork. |
| **Concurrency / consistency** | Single-ref swap = no torn read (vs today's `:559-562`). The build mutates nothing global (`:1984`). The watcher is the only writer of the snapshot ref; query threads are readers; the GIL makes the rebind atomic. The report-cache clear is serialized by `_db_lock`. ADR-07's runtime regex **eviction** (which mutates `regexDB` in place) is reconciled: eviction targets the **current** snapshot's `regexDB`; a swap replaces it with a freshly-compiled set (any evicted-pattern state is rebuilt from the manifest + the static cap — acceptable, documented). |
| **Counts** | After a swap, re-emit `pfb_py_count` + the `DNSBL_Regex` alias count from the **new** snapshot in the formats the UI reads (`inc:3149`, `:8329`) so the dashboard reflects the live lists without a restart. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

- **Idle decision-identity.** When no swap is in flight, every DNS decision is **byte-for-byte** what ADR-06/ADR-07 produce — the single-snapshot refactor (Phase 2) and the extracted `rebuild_and_swap` (Phase 3) are **behaviour-preserving**, pinned by the **retained** `tests/test_adr06_*` + `tests/test_adr07_*` oracles.
- **Atomic + consistent swap.** No query ever observes a torn mix of old/new strata; a query in flight during a swap resolves entirely against one snapshot. No query ever reads a **half-written** manifest (atomic publish + sentinel commit).
- **Fail-closed.** A failed/partial/aborted build leaves the **last-good** snapshot live and serving — never an empty set, never "no blocking", never a corrupted partial.
- **Zero dropped queries.** Through a swap under live traffic, **no query is refused, dropped, or stalled** beyond the agreed budget (the headline goal; the baseline is the current restart's dropped-query window, measured Phase 1).
- **Cache coherence.** Post-swap the Reports sqlite reflects the new lists (cleared or generation-bumped, parity with restart); **block→allow** flips are immediate (`no_cache_store`); **allow→block** flips are handled per the Phase-1 decision (delta C-cache flush *or* an accepted, documented TTL bound — the latter is no worse than today). No collision with the DNSBL-queries-daemon control socket. There is **no decision cache** to keep coherent (by design).
- **User sovereignty + ABP precedence (inherited from ADR-07) are untouched** — this ADR changes *when/how* the structures are installed, never *what decision* a given snapshot yields.
- **Restart fallback is intact.** Config changes still restart; a forced/failed path still restarts; legacy/non-python flows are unchanged.

### Explicitly kept / out of scope

- **Changing what a snapshot decides** — out. ADR-07 owns DNS semantics; ADR-10 only swaps snapshots atomically.
- **Reverting to legacy `local_data`/`unbound-control` blocklists** — out (ADR-02 dropped Unbound mode; the in-memory matcher is the point).
- **Incremental/delta in-place mutation of the live dicts** — out: a full rebuild + single-ref swap is simpler and the only thing that keeps `$badfilter`/precedence/regex-reduction (ADR-07) globally consistent. (Considered and rejected as a simpler-looking but more-fragile alternative.)
- **`unbound-control reload_keep_cache`** as the mechanism — out: it re-execs config and re-runs the heavy init build inline → still a stall, not zero-downtime.
- **Zero-downtime for *config* changes** (unbound.conf, interfaces, mode) — out; those keep the restart. Only DNSBL **data** updates are zero-downtime.
- **A new on-disk format / IPC daemon** — out; reuse the existing manifest + a sentinel + the existing thread/`_db_lock` infrastructure.
- **A Python decision/resolution cache** — out: the ≈1 µs matcher makes per-domain memoization pointless and none exists (`main`==`next`); adding one would only create a second thing to invalidate on swap.

---

## 3. Consequences

**Positive**

- **No DNS outage on a DNSBL update.** The most frequent disruptive operation (scheduled feed updates, alerts "add to whitelist", cron) stops dropping queries and restarting the resolver.
- **Faster apply, less churn.** No `dump_cache`/restart/`load_cache` dance for data updates; the build runs off-thread while queries keep flowing.
- **The swap seam ADR-06/07 deliberately left is finally used** — `build()` reentrancy pays off; the single-snapshot refactor also makes the matcher's container plumbing cleaner.
- **Cache correctness improves over today** — allow→block flips stop being TTL-stale (delta C-cache flush), which the current restart path doesn't even fix.

**Negative / risks**

- **Premise risk (ADR-01-class):** if `pythonmod` worker threads do **not** share module globals (per-interpreter isolation), one swap can't serve all workers → the whole design fails. **Falsified first (Phase 1, premise gate).**
- **≈2× transient RAM during a build.** The new structures exist alongside the live ones until the swap + GC (≈274 B/entry × millions). On a small box (e.g. a 1 GB appliance) a multi-million-entry ABP DNSBL could **OOM** mid-swap. **Measured Phase 1** (reuse `benchmarks/spike_adr06_build.py`) with a kill-threshold; mitigations: feature-gate on available RAM (fall back to restart), or a lower-peak build.
- **C-cache flush cost / collision.** Flushing a large newly-blocked delta via `unbound-control` has a cost and can collide with the DNSBL-queries daemon's control use (`inc:3211`). Bounded in Phase 5 (targeted delta flush, coalesced, marker-coordinated).
- **Added concurrency surface.** A new watcher thread + a background build mutating-then-swapping shared state. Mitigated by: single-ref atomic swap (no hot-path lock), single-flight coalescing, fail-closed, and the build's existing purity.
- **ABP regex-eviction interaction.** ADR-07's runtime eviction mutates the live `regexDB`; a swap replaces it. Reconciled (eviction acts on the current snapshot; rebuild restores from manifest+cap) and documented — not a regression, but a behaviour note.
- **No live Unbound in CI.** The headline guarantee (zero dropped queries, shared-global visibility, C-cache flush) is only fully provable on a **live box** → a mandatory maintainer smoke gate (§7), like every prior ADR.

---

## 4. Requirements (acceptance)

1. **Premise confirmed (Phase 1):** `pythonmod` query threads share one interpreter + module globals so a single atomic swap is visible to all (doc + live-box probe). If not → the ADR is **rejected** (or re-scoped to a per-thread variant) before any machinery is built.
2. **RAM within budget (Phase 1):** peak RSS of *build-while-old-live + swap* fits a realistic min-spec box, or a documented mitigation (RAM-gated fallback / lower-peak build) is taken.
3. **Zero dropped queries (live smoke):** under continuous traffic, a DNSBL update applies with **no** refused/dropped/over-budget-stalled query — versus the measured restart baseline.
4. **Atomic + consistent + fail-closed:** no torn read, no half-written-manifest read; a deliberately-broken build keeps the last-good snapshot serving (no swap, no outage).
5. **Cache coherence:** Reports sqlite cleared/generation-bumped on swap (no `_db_lock` race); block→allow immediate; allow→block per the Phase-1 decision (delta flush *or* documented TTL bound); no DNSBL-queries-daemon control collision. No decision cache exists to invalidate.
6. **Data fast-path vs restart fork:** a DNSBL-data update takes the no-restart path; a config change and any failed/disabled swap fall back to the restart.
7. **Idle decision-identity + green suite:** `tests/test_adr06_*` + `tests/test_adr07_*` pass **unchanged**; new `tests/test_adr10_*` pass; `ruff`/`php -l`/ShellCheck clean; no new shipped deps (stdlib only).

---

## 5. Constraints (from `CLAUDE.md`)

- **Plugin: stdlib only, Python 3.11+** (watcher uses `select.kqueue`/`os`/`threading` only), 4-space, type hints on new fns, no bare `except`, `from __future__ import annotations`. New build/swap/watcher code referencing a new injected Unbound symbol → declare it in `stubs/python/unboundmodule.py`; keep `evaluate_domain`/`build`/`rebuild_and_swap` unit-testable without a live Unbound.
- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs; the atomic publish uses pfSense-available primitives.
- **Shell:** POSIX `sh`, quoted, absolute binary paths, ShellCheck-clean; the staging-write + `rename` + sentinel flip is atomic on the target FS.
- Run `python -m pytest` after any `pfb_unbound.py`/`tests/` change; `ruff check .`/`ruff format .` clean each commit.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/10`, one commit per phase, push directly** (PR only if rejected); promote `devel → next` (and `main → devel`) by **rebase + `--force-with-lease`**, never merge. PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md updated when the update/reload contract or test commands change (final phase).

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` (default) green, and **preserves idle decision-identity** (the retained ADR-06/07 oracles). The **premise + cost are falsified first (Phase 1)**; the **behaviour-preserving prep (Phases 2–3)** — single snapshot + extracted swap — lands **before** the background swap (Phase 4) and the PHP boundary (Phase 5), and each prep phase retains standalone value even if the swap is later rejected.

### Phase 1 — Spike & kill-gate: shared-interpreter visibility, ≈2× RAM, restart-downtime baseline — de-risk

Prompt: `01_Spike_Visibility_RAM_Baseline.txt`

- **Premise probe (live box, owner: maintainer; CI can't reach Unbound):** confirm `pythonmod` query threads share one interpreter + module globals — e.g. set a sentinel on the module from one thread/`init` and observe it from another worker under `num-threads>1`. Document the result. **NO-GO if isolated** (record the per-thread fallback or the rejection).
- **RAM:** reuse `benchmarks/spike_adr06_build.py` to measure **peak RSS of build-while-old-live + swap** at ABP feed scale; compare to a realistic min-spec box. Propose the kill-threshold + the RAM-gated-fallback / lower-peak mitigation.
- **Baseline:** measure the **current** restart path's downtime — dropped/refused queries + latency spike during a Python-mode DNSBL update — as the number the swap must beat (target: zero dropped).
- **Cache benchmarks (Bonus):** (a) measure the per-block Reports-sqlite enqueue/write overhead (`pfb_db_enqueue("cache", …)` `:2721`) vs the ≈1 µs matcher — is the async log path overkill / droppable / generation-keyable? (b) measure a targeted C-cache **delta-flush** cost vs accepting **TTL-bounded** staleness — typical newly-blocked delta sizes + real feed TTLs. Feed both into the Phase-3/5 cache decisions.
- **Gate:** GO only if the threading premise holds **and** the RAM cost has a viable bound. Land the numbers + the demo benchmark in `RESULTS/01_Results.txt`. Miss → STOP / re-scope / reject (record it, ADR-01 discipline).

### Phase 2 — PREP (behaviour-preserving): bundle the matcher strata into one immutable `Snapshot`

Prompt: `02_Single_Snapshot_Refactor.txt`

- Define a frozen `Snapshot` holding `dataDB`/`zoneDB`/`whiteDB`/`regexDB`/`allowRegexDB`/`feedGroupIndexDB`/`important_rules`/counts. Replace the four-plus separate globals (`:559-562`, `:383-390`) with **one** module-level ref; `init_standard` builds the `Snapshot` and assigns the single ref. `evaluate_domain`/`op` capture the **one** ref per query and read all fields off it (replacing the per-query `containers` assembly `:2661-2671`). **MUST be decision-identical** — pinned by the retained ADR-06 + ADR-07 oracles. Pure refactor; standalone-valuable (atomic-swap-ready even if the rest is rejected). New `tests/test_adr10_snapshot_*` proving field-for-field equivalence.

### Phase 3 — PREP (behaviour-preserving): extract `rebuild_and_swap()` + explicit cache-clear, fail-closed

Prompt: `03_Rebuild_Swap_Extract.txt`

- Factor the build→install into `rebuild_and_swap()`: run the pure `build()`/`dnsbl_build_from_manifest()`, and **only on success** (a) rebind the single snapshot ref atomically, (b) reset the Reports sqlite via `_db_lock`/the db-queue — clear (parity with `:340-342`) **or** generation-bump per the Phase-1 benchmark, whichever the Reports UI reads cleaner (Bonus 1), and drop the per-block write path entirely if Phase 1 found it overkill (Bonus 2), (c) re-emit counts. On failure → keep the old snapshot (fail-closed; mirrors `:558`). Called **synchronously by `init_standard`** for now (no behaviour change at init). Unit-test: success swaps + resets; a build returning `None`/raising leaves the old snapshot intact and the cache untouched.

### Phase 4 — Reload-watcher thread + background swap (no restart, zero-downtime active)

Prompt: `04_Watcher_Background_Swap.txt`

- Add a reload-watcher daemon thread (started next to the existing workers, gated on `pfb["mod_threading"]`): wait on the sentinel via `select.kqueue` `EVFILT_VNODE` on the sentinel dir, **mtime-poll fallback**; on a generation-id advance → run `rebuild_and_swap()` **off the query threads**, single-flight/coalesced. The Phase-2 single-ref swap + Phase-3 fail-closed make it safe; queries serve the old snapshot during the build. Unit-test the watcher logic with a stubbed build (sentinel/generation detection, coalescing, build-fail-keeps-old, clean join on `deinit`). Reconcile ADR-07 regex-eviction vs swap (documented).

### Phase 5 — PHP/shell: atomic publish + sentinel + data-only fast path + C-cache delta flush

Prompt: `05_PHP_Publish_FastPath_Flush.txt`

- Manifest writer: stage → `fsync` → atomic `rename` → flip the sentinel (generation id) — the all-or-nothing commit. `pfb_reload_unbound` gains the **data-only** fork: DNSBL-data update in Python mode → publish + flip, **no `pfb_stop_start_unbound`**; config change / failed / disabled → restart fallback. Compute the **newly-blocked delta** and flush it from Unbound's C-cache (`unbound-control flush`/`flush_zone`, coalesced, coordinated with the DNSBL-queries-daemon marker `:3211`); block→allow needs no flush. `php -l` + ShellCheck clean; default `pytest` unchanged.

### Phase 6 — Validation, benchmark, manual smoke, DoD

Prompt: `06_Validation_Smoke_DoD.txt`

- Re-run the Phase-1 RAM/latency benchmark on `adr/10` vs threshold. Full idle-equivalence (ADR-06/07 oracles) + the new ADR-10 suite. Finalise README/CLAUDE.md (the update/reload contract: data = zero-downtime swap, config = restart). **Manual smoke (live box, owner: maintainer):** zero dropped queries through a swap under traffic; add/remove a name mid-traffic flips correctly (incl. allow→block C-cache flush, block→allow immediate); fail-closed (broken manifest keeps the old lists serving, no outage); data update takes the no-restart path while a config change still restarts; Reports tab + counts reflect the new lists. Finalise the reject criteria.

---

## 7. Definition of done

- `python -m pytest` green incl. the new `tests/test_adr10_*` **and** the retained `tests/test_adr06_*`/`tests/test_adr07_*` oracles (idle decision-identity); `ruff` clean; `php -l` + ShellCheck clean; no new shipped deps (stdlib only).
- A DNSBL-data update applies with **zero dropped queries** and **no restart**; a config change still restarts; a failed swap falls back fail-closed to the last-good snapshot (and, if needed, the restart).
- The swap is atomic + consistent (no torn read, no half-written-manifest read); caches are coherent (Reports cleared, allow→block C-cache flushed, block→allow immediate).
- Status → **Accepted** only after the maintainer confirms the manual smoke below on a live pfSense CE box.

### Reject criteria (decide cheaply, Phase 1, before building)

- **Threading premise fails:** if `pythonmod` workers have **isolated** globals (a single swap is invisible to other workers) and no cheap per-thread variant works → **reject** the zero-downtime swap; keep the restart. Settled in Phase 1, before any machinery.
- **RAM premise fails:** if ≈2× transient RAM OOMs a realistic min-spec box and no lower-peak build is feasible → **do not ship the swap as default**; gate it on available RAM with the restart as the fallback (or reject). Settled in Phase 1.
- **Swap can't beat the restart on a live box:** if a swap still drops/stalls queries beyond budget (e.g. GIL contention from the in-process build starves query threads) → reject the in-process background build; keep the restart.

### Manual smoke (owner: maintainer) — required before Accept

> **Gate: Status flips to Accepted ONLY after every box passes on a live pfSense CE box.** CI cannot reach Unbound's Python loader or the C-cache. Run under continuous DNS traffic.

- [ ] **Shared-global visibility.** With `num-threads>1`, a swap triggered once is observed by **every** query thread (a name's decision flips on all workers).
- [ ] **Zero dropped queries.** A scheduled/forced DNSBL update under load applies with **no** refused/dropped/over-budget-stalled query and **no** Unbound restart (pid unchanged).
- [ ] **Flip correctness + caches.** A name **added** to a feed (allow→block) starts blocking promptly even if it was cached as resolving (per the Phase-1 cache decision — delta flush or accepted TTL bound); a name **removed** (block→allow) resolves immediately (`no_cache_store`); the Reports tab + `pfb_py_count`/`DNSBL_Regex` counts reflect the new lists.
- [ ] **Fail-closed.** A deliberately broken/partial manifest does **not** swap — the last-good lists keep serving, the resolver stays up, an error is logged.
- [ ] **Fork.** A pure DNSBL-data update takes the no-restart path; a config change (unbound.conf/mode) still restarts; with zero-downtime disabled or after a swap error, the update falls back to the restart.
- [ ] **No control collision.** The C-cache flush does not collide with the DNSBL-queries daemon's `unbound-control` use.
- [ ] **RAM.** On the smallest supported box, a full ABP-scale rebuild+swap does not OOM (or the RAM-gated fallback engages as designed).
