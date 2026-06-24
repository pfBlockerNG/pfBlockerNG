# ADR-40: Content-addressed alias-table updates — gate reloads on the final set, apply forward deltas

- **Status:** **Proposed** (2026-06-24)
- **Date:** 2026-06-24
- **Branch:** `adr/40-content-addressed-alias` (off **`devel`**; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming"). / **Component(s):** the IP-side alias-table update path —
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (the alias-build + `pfctl` reload region of
  `sync_package_pfblockerng`, ~`:14287`–`:14970`, and the ADR-12 emit at `:15319`), with the
  cross-list dedup/aggregation primitives in `src/usr/local/pkg/pfblockerng/pfblockerng.sh`. The
  DNSBL side (its own zero-downtime swap, ADR-10) is **out of scope**.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the gating/decision + delta apply; POSIX `sh`
  for any canonicalisation primitive. `pfctl(8)` table ops (`-T replace`/`-T add`/`-T delete`).
- **Test suite:** `tests/php/` (PHPUnit — the off-appliance pure/extractable helpers of
  `pfblockerng.inc`), `tests/shell/` (shellspec — canonicalisation), `tests/smoke/`
  (live-VM ADR-04, incl. the ADR-12 hook cases) — pf is only real on the live VM, so the
  reload-cost and end-to-end behaviour are pinned there.

## 1. Context

### 1.1 Today

On every Cron/Force pass `sync_package_pfblockerng()` decides which pf alias tables to reload by
**tracking which feeds were (re)fetched**, not by looking at the table contents:

- A feed that returns **304 / md5-match** (or has no `.update` marker and reuse is off) is
  skipped by the gate at `pfblockerng.inc:13786` — not reparsed, its alias never flagged.
- A feed with **new content** is reparsed; its `.txt` is rewritten and the alias is appended to
  `$pfb_alias_lists` (`:14226`).
- The reload scope is then `$final_alias`: `$pfb_alias_lists` normally, or — when **Reputation**
  (`drep`/`prep`) is on — **every** active alias via `$pfb_alias_lists_all`
  (`:14888`–`:14894` / `:14936`–`:14942`).
- The final per-alias file is built by **concatenating** its member `.txt` files
  (`$alias_ips .= file_get_contents(...)`, `:14393`) and written to
  `/var/db/aliastables/pfB_<Alias>_v{4,6}.txt` (`:14426`) — a concatenation, **not** a global
  `LC_ALL=C sort -u`; cross-member duplicates and member order survive into the file.
- Reload is `pfctl -t <alias> -T replace -f <file>` (`:14903` in the rule-change branch, `:14954`
  in the no-rule-change branch). A `replace` ingests the **full** file and diffs it against the
  live radix tree inside pf's rules write lock.

### 1.2 The problem

Two structural consequences of gating on feed-fetch instead of final content:

1. **Cross-list dedup is eventually-consistent, not per-pass correct.** With "remove duplicate
   IPs" (`enable_dup`, the `grepcidr`/`masterfile` path in `pfblockerng.sh`), an IP's membership
   in table B can depend on feed A (priority/processing order over a shared `masterfile`,
   `pfblockerng.sh:513`–`:527`). When feed A changes, only A is reparsed and reloaded; a sibling
   table B whose **effective** content shifted as a result is **not** in `$pfb_alias_lists`, so
   B's `.txt` is not rebuilt and its table not reloaded this pass. B only realigns on the next
   Force Reload. So a removal in A can leave an IP blocked nowhere — or duplicated — until a full
   rebuild.
2. **Reputation amplifies one feed change into an all-tables reload.** Because reputation is
   inherently cross-list, any deny-feed change sets `repcheck` and widens the reload scope to
   **all** active aliases (`$pfb_alias_lists_all`). One changed feed → every pf table
   `-T replace`d (and `dmax`/`pmax` re-run), each replace O(table size) under the rules write
   lock.

Plus a latent cost independent of the above: **`pfctl -T replace` is O(total list size)**, not
O(churn). A single-IP feed change re-ingests the whole file (millions of entries for a large deny
alias) and holds pf's rules write lock for the duration — a bounded but real data-plane latency
spike on large tables. The work scales with the size you hand `replace`, not with what changed.

### 1.3 Load-bearing facts (verified, not assumed)

- **A pf table is a set (radix tree), order- and duplicate-insensitive.** `pfctl -T replace -f`
  produces the same table regardless of line order or dups in the file. So the *table* is already
  canonical even though the *aliasdir file* (a concatenation, §1.1) is not. Reasoning about
  **membership sets** sidesteps the file's non-canonical byte form entirely.
- **The forward-delta primitive already ships and is exercised in production.** The Alerts page
  applies single-entry table edits with `pfctl -t <t> -T delete <ip>` / `-T add <ip>` for
  unlock/lock (`pfblockerng_alerts.php:1499`/`:1506`), suppression revert (`:1303`/`:1321`), and
  whitelist (`:1549`) — never a full `replace` for a one-entry change. `-T add`/`-T delete` apply
  only the supplied addresses; lock-hold scales with the delta, not the table.
- **The codebase already separates "a table changed" from "do a full reload."** ADR-12's
  `PFB_IP_CHANGED` hook signal is emitted **without** forcing `filter_configure()`: the
  ip_unlock-forced re-block (#519/PR #522) does a real `-T replace` and reports the change via a
  dedicated `$pfb_ip_unlock_forced` flag OR'd into the emit (`pfblockerng.inc:15319`) precisely so
  the report does **not** trigger the heavy rule reload. #517 did the DNSBL twin. The maintainers
  already think in "signal the change, don't force a reload" terms — this ADR generalises that.
- **`filter_configure()` (full rule reload) is reserved for actual firewall *rule* changes**
  (`pfblockerng.inc:14912`/`:15030`) — never for a table-content change. A content-only update is
  pure `pfctl` table work today and must stay that way.
- **The canonical inputs are deterministic given fixed settings + config order.** `LC_ALL=C
  sort -u` (ADR-26) is byte-stable; `iprange` aggregation is set-exact; suppression
  (`grepcidr -vf`) and reputation (`dmax`/`pmax`) are pure functions of their inputs; the deny
  masterfile dedup is order-fixed by config order. So the **final membership set** of a table is a
  deterministic function of (member feeds + settings + config order) — the property that makes a
  content-based gate sound. The aliasdir files are IP-only (no timestamps/comments), so there is
  no nondeterministic noise to strip — but they are not `sort -u`'d, so a **byte** compare needs
  canonicalisation whereas a **set** compare does not.
- **pf is not real in CI.** There is no `pfctl`/live pf in the unit/PHPUnit suites; table reload
  cost, lock-hold, and end-to-end blocking behaviour are only measurable on the ADR-04 live VM.
  Any performance claim here is therefore gated on a live-VM benchmark, not a CI microbench.

### 1.4 Why this is worth an ADR (and not a drive-by patch)

The change spans the decision boundary (when to reload), the apply mechanism (replace vs delta),
and a cross-cutting correctness fix (dedup/reputation), and it carries a **falsifiable performance
premise** that — per the ADR-01 lesson — must be measured against a baseline **before** the
delta machinery is built. It also has a real "always recompute the final set" cost that could
sink the cross-list correctness fix on large installs. Those forks deserve an explicit plan with
a measurement kill-gate, not an inline edit.

## 2. Decision

Replace feed-fetch tracking with **content-addressed gating** (reload a table iff its **final
membership set** changed) and replace the full `-T replace` with a **forward delta**
(`-T add` the additions, `-T delete` the removals) — the delta arm **gated on a live-VM
benchmark** (§6 Phase 2). "Force reload" collapses into "recompute the desired set and diff": no
change → empty delta → genuine no-op.

| Area | Decision |
| --- | --- |
| **Reload gate** | Reload a table iff its freshly-computed **final canonical set** differs from the **last-applied set** persisted for that table — not iff a member feed was refetched. Comparison is **set-based** (membership), so it is immune to file order/dups. This subsumes `$pfb_alias_lists`, `$pfb_alias_lists_all`, and `repcheck` into one rule. |
| **Last-applied record** | The persisted `/var/db/aliastables/pfB_<Alias>_v{4,6}.txt` **is** the last-applied mirror (already on disk; it is the live-table source). The delta is `desired_new △ desired_last`. The kernel table (`pfctl -T show`) is the authoritative fallback if the mirror is distrusted, used sparingly (a full dump is O(table)). **No new journal** — adds/deletes compose, so the model is a *forward* diff, never "undo then reapply." |
| **Cross-list correctness** | When dedup/reputation can move a sibling table, that table's **desired set is recomputed and diffed** this pass, so it reloads exactly when its membership actually changes — closing the §1.2(1) eventual-consistency gap and removing the §1.2(2) reputation over-reload (only tables whose set moved reload, not all). |
| **Apply mechanism** | For a changed table, apply `pfctl -t <t> -T add -f <adds>` then `-T delete -f <dels>` — lock-hold O(churn). **Fallback to `-T replace`** when the delta is large relative to the table (a churn-ratio threshold where replace is cheaper and atomic) or when atomicity is required. **Gated on Phase 2.** |
| **"Force"** | No longer a special path. Force = recompute desired sets and diff; identical sets ⇒ empty delta ⇒ no-op (not a full O(list) replace). |
| **ADR-12 emit** | `PFB_IP_CHANGED` / `changed_ip_aliases` are driven by the **content-diff set** (the tables whose membership actually changed), preserving #517/#519's "signal the change without forcing a reload" contract. `filter_configure()` is still reserved for rule changes only. |
| **Canonicalisation** | Add a single canonical-set helper (`LC_ALL=C sort -u` of the final member union, post-suppression/dedup/aggregation) so "desired set" has one definition shared by the gate and the delta. The aliasdir file becomes a true sorted-unique set (a behaviour-preserving change at the *table* level — pf already deduped it). |
| **Scope of always-recompute** | To detect cross-list moves the desired set of **every** alias must be recomputed each pass (today unchanged aliases are not rebuilt). **Option (hybrid, preferred if Phase 2 demands):** only force the all-aliases recompute when a **cross-list feature is on** (`enable_dup` / reputation); with both off, single-feed→single-table already holds, so keep the cheap fetch-gated path and content-gate only the touched alias. Decided by Phase 2's recompute-cost measurement. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **Table end-state == a full replace.** After a delta apply, `pfctl -t <t> -T show` equals the
   canonical desired set — bit-for-bit membership identical to what `-T replace -f` would load.
2. **Single-feed → single-table stays surgical** when no cross-list feature is active: a change
   in feed A reloads only A's table(s); untouched tables are not reloaded.
3. **Cross-list propagation is now correct:** a feed-A change that alters sibling table B's
   effective membership (via dedup) reloads B this pass — the new behaviour, pinned red→green
   against today's deferred-to-Force-Reload behaviour.
4. **Reputation no longer blanket-reloads:** one feed change reloads only the tables whose set
   moved, not all active aliases — pinned red→green against today's `$pfb_alias_lists_all`.
5. **Empty-table repopulation** still occurs: an alias whose kernel table is empty but whose
   desired set is non-empty is loaded even if its set "did not change" vs an absent mirror.
6. **ADR-12 signal fidelity:** `PFB_IP_CHANGED=1` exactly when ≥1 table's membership changed
   (incl. the ip_unlock-forced re-block, #519); `filter_configure()` still fires only for rule
   changes.
7. **No new `filter_configure()` / network / `pkg` work** on the content-update path.
8. **Determinism:** identical (members + settings + config order) ⇒ identical canonical set ⇒
   empty delta ⇒ no-op. Pinned by a same-input-twice idempotence test.

### Explicitly kept / out of scope

- **DNSBL** reload (ADR-10 zero-downtime swap) — untouched; this is the IP/pf-table side only.
- **The dedup/aggregation/reputation algorithms themselves** — unchanged; we change *when and how
  tables reload*, not how the sets are computed. (Reputation's cross-list math stays; it just no
  longer forces an all-tables reload.)
- **`filter_configure()` for rule changes** — unchanged.
- **The feed-fetch 304/md5 skip** (`:13786`) — **kept** as a network optimisation; it stops
  re-downloading unchanged feeds. The content gate sits *below* it on the local member files; the
  two compose (don't refetch; still recompute the local desired set when a cross-list feature is
  on).
- **`config.xml` schema** — no migration; the last-applied mirror is the existing aliasdir file.

## 3. Consequences

**Positive**

- **Correctness:** cross-list dedup realigns sibling tables in the same pass (closes the
  eventually-consistent gap); reputation stops amplifying one feed change into an all-tables
  reload.
- **Performance (if Phase 2 clears the gate):** lock-hold per changed table drops from O(table
  size) to O(churn); a single-IP feed change becomes a one-entry `-T add` — no perceptible
  data-plane stall. "Force" becomes cheap (empty delta when nothing changed).
- **Simpler decision surface:** `$pfb_alias_lists` / `$pfb_alias_lists_all` / `repcheck` /
  per-branch scope logic collapse into one "did the set change" rule.
- **Reuses an in-tree primitive:** `-T add`/`-T delete` is already the Alerts-page mechanism;
  no new pf interaction model, no new trust surface.
- **Aligned with #517/#519 precedent:** "signal the change, don't force a reload" generalised
  from the unlock paths to the whole feed update.

**Negative / risks**

- **Always-recompute cost.** Detecting cross-list moves requires rebuilding every alias's desired
  set each pass (today unchanged aliases are skipped). On a box with millions of IPs this is real
  I/O+CPU. **Mitigation:** the hybrid scope (only force all-aliases recompute when a cross-list
  feature is on); **measured** in Phase 2 — if it dominates the replace cost it saves, the
  cross-list arm is re-scoped or rejected.
- **Atomicity.** `-T add` + `-T delete` are two ioctls, so a sub-millisecond window exists where
  the table is `old ∪ adds` before the deletes land (briefly over/under-blocks by the delta) —
  vs `replace`'s atomic swap. **Mitigation:** acceptable for a blocklist; fall back to atomic
  `replace` above a churn threshold or when atomicity is required.
- **Determinism dependency.** A content gate false-triggers if the canonical output is not
  byte/set-stable (a stray non-`C` locale, a future format tweak). **Mitigation:** set-based
  comparison (order/dup-immune) + a determinism test + the ADR-26 `LC_ALL=C` discipline.
- **Perf premise may not hold (ADR-01 trap).** If `-T add`/`-T delete` does not materially beat
  `-T replace` at scale, the delta arm is dropped — but the correctness arm (content gating with
  `-T replace`) stands alone and is still valuable. The benchmark decides.

## 4. Requirements (acceptance)

- A single-feed change with no cross-list feature reloads **only** that feed's table(s); untouched
  tables are not reloaded (pinned).
- A feed-A change that shifts sibling table B's effective membership (dedup on) reloads B in the
  **same** pass — red→green vs today's defer-to-Force-Reload.
- With reputation on, one feed change reloads **only** the tables whose set moved, not all active
  aliases — red→green vs today's `$pfb_alias_lists_all`.
- After a delta apply, `pfctl -t <t> -T show` membership equals the canonical desired set
  (== what `-T replace` would load).
- `PFB_IP_CHANGED=1` exactly when ≥1 table's membership changed (incl. ip_unlock-forced re-block);
  `filter_configure()` fires only for rule changes; no new network/`pkg` on the content path.
- Re-running with identical inputs is a no-op (empty delta) — idempotence pinned.
- The Phase 2 benchmark exists, with methodology + numbers + an explicit kill-threshold, run on
  the live VM.

## 5. Constraints (from CLAUDE.md)

- PHP: tabs, PHP 8.3; no `die()`/`exit()` in library code; route registered config reads/writes
  through `PfbConfig` (ADR-29) if any new field is added (none expected). pfSense functions via
  `stubs/pfsense/` + `tests/php/pfsense_doubles.php` — no `require_once` of pfSense files in tests.
- Shell: POSIX `sh`; quote expansions; **`LC_ALL=C` inline per command** on every `sort -u`/set
  compare over machine data (ADR-26) — never `export`ed.
- Test coverage (the five non-negotiables): behaviour-changing phases pin a test that **fails
  before / passes after**; behaviour-preserving prep pins the current behaviour as an **oracle**
  that stays green; every condition (cross-list on/off, reputation on/off, delta vs replace
  fallback) gets its own assertion; no phase without tests; intent-named, not coverage theater.
- pf is not real in CI → reload cost and end-to-end blocking behaviour are **live-VM** (ADR-04)
  /maintainer-smoke items, not CI gates; PHPUnit pins the decision/diff logic off-appliance.
- ADR text + phase prompts land **directly on the branch** (docs carve-out, no PR); every
  `src/`/`tests/`/CI phase uses the full worktree + rebase-only-PR flow.

## 6. Action plan

Front-loaded with behaviour-preserving prep (extract + oracle-pin the decision and final-set
construction) and the **measurement kill-gate** before any risky swap. The correctness arm
(Phase 3) is independently valuable and does **not** depend on the perf benchmark; the perf arm
(Phase 4) is **gated** on Phase 2.

### Phase 1 — Extract + oracle-pin the reload-scope decision and final-set construction (prep, behaviour-preserving)

- **Prompt:** `01_Extract_And_Pin.txt`
- Extract the inline reload-scope logic (`$pfb_alias_lists`/`$pfb_alias_lists_all`/`$final_alias`,
  `:14888`–`:14894`/`:14936`–`:14942`) and the final-file construction (concatenation `:14393` +
  write `:14426`) into named, testable helpers in `pfblockerng.inc` (kept loadable off-appliance
  by `tests/php/bootstrap.php`). Add a **canonical-set** helper (`LC_ALL=C sort -u` of the member
  union) **without** wiring it into the live reload path yet.
- **Tests (oracle, stay green):** PHPUnit pins — for representative member-file + settings
  fixtures — today's reload set and today's final-file content (membership), and the canonical
  helper's determinism (same input → identical bytes; set-equality immune to input order/dups).

### Phase 2 — Baseline benchmark on the live VM (the kill-gate; ADR-01 lesson)

- **Prompt:** `02_Benchmark_Gate.txt`
- A measurement harness (under `tests/smoke/` or `scripts/bench/`, **not** production code) on the
  ADR-04 VM: across synthetic table sizes (10k/100k/1M/5M), measure (a) `-T replace -f` wall-time
  **and** the data-plane stall (probe latency through pf during the op), (b) `-T add`/`-T delete`
  delta cost for small/medium/large churn (1 / 1k / 100k), (c) the cost of recomputing +
  canonicalising **all** aliases' desired sets vs the current fetch-skip on a representative feed
  set.
- **Kill-thresholds (record in RESULTS):** if (b) does not materially beat (a) at large sizes →
  **drop Phase 4** (perf), keep Phase 3. If (c) dominates the replace cost it saves and the
  hybrid scope (§2) cannot contain it → **re-scope or reject** the cross-list arm in favour of
  extending the existing tracking. Numbers + methodology + verdict are the deliverable.

### Phase 3 — Content-addressed reload gating (core correctness; independently valuable)

- **Prompt:** `03_Content_Gating.txt`
- Swap the reload-scope from feed-fetch tracking to **set-diff of each alias's desired set vs its
  last-applied mirror**. Apply via `-T replace` still (no atomicity change yet). Recompute the
  affected sibling sets so dedup/reputation moves are caught; apply the hybrid scope decided by
  Phase 2. Preserve empty-table repopulation, the #519 ip_unlock signal, and the ADR-12 emit
  (now driven by the content-diff set).
- **Tests (red→green):** feed-A change frees an IP from table B → B reloads now (failed before);
  reputation-on single-feed change reloads only moved tables (not all); single-feed no-cross-list
  stays surgical; idempotence no-op; PHPUnit for the decision, a live ADR-12 hook smoke case for
  end-to-end.

### Phase 4 — Forward-delta apply (`-T add`/`-T delete`) — **gated on Phase 2**

- **Prompt:** `04_Forward_Delta.txt`
- For a changed table, compute `desired △ last-applied` and apply additions via `-T add -f`,
  removals via `-T delete -f`; persist the new canonical set as last-applied. Fall back to atomic
  `-T replace` above a churn-ratio threshold or when atomicity is required. "Force" becomes
  recompute+diff (empty delta = no-op). **Only built if Phase 2 cleared the threshold**; else this
  phase is dropped and Phase 3's gating (with `-T replace`) is the final state.
- **Tests (red→green + live):** post-delta `-T show` == canonical set (membership identical to a
  replace); small-churn change applies as `add`/`delete` not `replace`; large-churn falls back to
  `replace`; live smoke measures the reduced stall vs the Phase 2 baseline.

### Phase 5 — Smoke + docs + DoD

- **Prompt:** `05_Smoke_Docs_DoD.txt`
- ADR-12 hook smoke matrix: single-feed→single-table; dedup cross-list propagation; reputation
  no-longer-all-reload; delta end-state correctness + reduced stall (if Phase 4 landed). Update
  `docs/misc/architecture-notes.md` (the new gating+delta model, replacing the feed-tracking
  description), the CLAUDE.md "alias-table update" mechanics, and cross-reference #517/#519 as the
  "signal-not-reload" precedent.

## 7. Definition of done

- All §4 requirements met; the ADR-12 hook smoke matrix (single-feed surgical, dedup cross-list
  propagation, reputation non-amplification, delta end-state == replace) green on the live-VM
  fan-out (CE + Plus).
- Phase 2 benchmark recorded with methodology, numbers, and an explicit verdict on the perf arm;
  the Phase 4 decision (built / dropped) follows that verdict and is documented.
- Reload-scope decision logic reduced to the single content-diff rule; `$pfb_alias_lists_all` /
  `repcheck` removed or demoted to the hybrid-scope guard only.
- Determinism/idempotence test green; no new `filter_configure()`/network/`pkg` on the content
  path; ADR-12 signal fidelity preserved (incl. #519).
- Docs updated.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- On a real box with a **multi-million-entry** deny alias, confirm the data-plane latency spike on
  a single-IP feed change drops from the `-T replace` baseline to the delta path (true pf
  lock-hold under live traffic is not reproducible in CI).
- With **dedup on across overlapping feeds**, confirm a removal in one feed that frees an IP
  realigns the sibling table in the same pass (no stale block / no orphaned dup).
- With **reputation on**, confirm a single-feed change does not reload every table (observe the
  per-table reload set / timing).

**REJECT / re-scope criteria (what would kill or narrow this ADR):**

- **Phase 2** shows `-T add`/`-T delete` does not materially beat `-T replace` at scale →
  **drop the perf arm (Phase 4)**; keep Phase 3 (content gating with `replace`).
- **Phase 2** shows the always-recompute-all-desired-sets cost dominates the reload cost it saves
  **and** the hybrid scope cannot contain it → **reject the content-addressed cross-list arm** in
  favour of a narrower fix: extend the existing tracking to add dedup-affected siblings to
  `$pfb_alias_lists` (cheaper, less general).
- Canonical output proves not byte/set-stable in practice and set-diff via `-T show` is too costly
  at scale → the gate is unreliable → reject.
