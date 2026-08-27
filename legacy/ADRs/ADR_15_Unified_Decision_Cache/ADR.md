# ADR-15: Unified DNSBL decision cache — the Decision as the single cached structure

- **Status:** **Accepted** (2026-06-04) — all five phases shipped to `devel`
  (#64, #67, #68, #70, #72). This is a **retroactive** ADR: the work landed as five
  sequential PRs first and is consolidated here afterward, so there are no
  `/adr-phase` prompt `.txt` files — each phase's record lives in `RESULTS/`.
- **Date:** 2026-06-04
- **Supersedes:** the former `.Plans/01–05` directory ("single-step plan ADRs"),
  whose content moved verbatim into this ADR's `RESULTS/`. The `.Plans` experiment
  (one plan → one PR, split across numbered folders) didn't earn its own top-level
  convention; this is the same line of work reframed as one phased ADR.
- **Branch:** landed directly on `devel` as five PRs (no single `adr/15` branch).
- **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (the query-time
  decision path: `operate()`, `evaluate_domain`/`evaluate_noaaaa`, the cache
  structures); plus `pfblockerng.inc`, `pfblockerng_dnsbl.php`, `stubs/pfsense/` and
  `tests/` for the Phase 5 WebUI cap.
- **Related:** [ADR-06](../ADR_06_DNSBL_Preprocessing_To_Python/ADR.md) and
  [ADR-07](../ADR_07_ABP_DNSBL_Support/ADR.md) own the **build/parse** layer and the
  golden decision oracles this work kept green; [ADR-10](../ADR_10_Zero_Downtime_DNSBL/ADR.md)
  (zero-downtime reload) depends on these caches being clearable on an atomic swap.
- **Closes:** #43 (per-feed under-count on cached blocks), #26 (the `exclude*`
  lists → O(1) + bounded).

---

## 1. Context

`pfb_unbound.py` memoised its per-query DNSBL work across **several independent,
partly contradictory cache structures**, reset only at `init()` (plugin reload):

- **`dnsblDB`** — a dict of blocked names (+ a `"last-event"` dedup key): the positive
  decision cache.
- **`excludeDB`** — a **list** of not-blocked names, tested with `not in` (O(n) linear
  scan): the negative decision cache.
- **`excludeAAAADB` / `excludeSS`** — more **lists** (noAAAA / SafeSearch negatives),
  same O(n) pattern, plus a `noAAAADB[name] = True` query-time memo.

Three problems compounded:

1. **Cached blocks broke attribution and delisting (#43).** Block replies
   (`NOERROR` + `0.0.0.0`/VIP) were built at TTL 3600 **without** `no_cache_store`, so
   Unbound's C message cache served repeats *ahead of* the python module. The
   feed-attributed logger runs only on a `operate()` cache **miss**; on a hit the
   inplace callback logged an unattributed `DNS-reply` with no feed/group. A name
   blocked once then served N× logged one attributed event — a per-feed under-count.
   A removed name also kept serving its cached block until TTL.
2. **The verdict was split across contradictory structures.** A CNAME-blocked name
   landed in **both** `excludeDB` (iteration 1, not a direct match) and `dnsblDB`
   (iteration 2, blocked via the resolved chain) → an incoherent memo, dead code, and
   full CNAME re-evaluation on every repeat query.
3. **The lists were O(n) and unbounded (#26).** `excludeDB`/`excludeAAAADB`/`excludeSS`
   grew one entry per distinct queried name between reloads, and every lookup scanned
   linearly — a latency cliff and unbounded memory on long-running busy resolvers.

The unifying observation: the thing worth caching is the **per-domain Decision** — the
single coherent verdict (block / allow / no-match, across the DNSBL, noAAAA, and
SafeSearch axes) — not a scatter of per-subsystem positive/negative side tables.

## 2. Decision

**Make the `Decision` the universal cached working structure**, stored directly in one
`decisionDB[name]`, and bound it:

- **Stop caching synthetic block replies** (`qstate.no_cache_store = 1` on the block
  path) so every blocked query re-enters `operate()` → always attributed, delisting
  immediate. The block reply is synthetic, so not caching it costs only the in-process
  (memoised) matcher re-run — no upstream round-trip (mirrors the SafeSearch CNAME
  path). [Phase 1 / #64]
- **Unify the DNSBL axis:** one `decisionDB[name] = DnsblDecision` holding *every*
  outcome including **allow** ("let Unbound resolve it" / whitelisted), replacing the
  `excludeDB` list with an O(1) dict and collapsing the dual-structure CNAME
  incoherence. `evaluate_domain` is untouched → decisions stay byte-identical (ADR-06/07
  oracles green). [Phase 2 / #67]
- **Fix the two attribution bugs** that unification surfaced (mixed-case lookup miss;
  CNAME target evaluated against the original query's TLD). [Phase 3 / #68]
- **Fold in the remaining axes:** the `Decision` becomes one composed per-domain verdict
  across **dnsbl / noaaaa / safesearch**, each a lazily-filled axis with an `UNSET`
  sentinel distinguishing "not yet evaluated" from an evaluated allow/no-match. The
  `excludeAAAADB`/`excludeSS` lists and the noAAAA query-time memo **dissolve** — the
  set-vs-list question disappears by removal. [Phase 4 / #70]
- **Bound `decisionDB` with an LRU** (`_LruCache`, `OrderedDict`-backed, recency on
  get+set, per-instance lock), **WebUI-configurable**, default **10000**, `0` =
  unlimited; `@dataclass(slots=True)` on the `Decision` types for ~2–3× less RAM/entry.
  [Phase 5 / #72]

## 3. Consequences

**Positive**

- One coherent per-domain verdict instead of contradictory positive/negative side
  tables; the CNAME incoherence and its per-query re-evaluation are gone.
- All hot-path membership tests are O(1) dict lookups (was O(n) list scans), and memory
  is **bounded** (LRU cap) with the hot working set resident.
- Cached-block attribution holes (#43) and the `exclude*` O(n)/growth warts (#26) are
  both closed.
- The caches are now a single clearable structure — the seam ADR-10's zero-downtime
  swap needs (clear `decisionDB` + flush the C-cache atomically).

**Negative / risks**

- Not caching blocks means every blocked query re-runs `operate()`; mitigated because
  the matcher result is memoised in `decisionDB`, so the re-run is a dict hit, not a
  re-resolve.
- The composed `Decision` with `UNSET` axes is more subtle than three flat side tables;
  pinned by the ADR-06/07 decision oracles plus per-phase regression tests.
- A bounded cache can evict a hot entry under cap pressure; the LRU keeps frequently
  queried names resident, and the cap is user-tunable (`0` = unbounded restores the
  pre-cap behaviour).

## 4. Action plan (as shipped)

Each phase was one PR to `devel`, kept `python -m pytest` green, and preserved net DNS
decisions (the ADR-06/07 oracles). Full per-phase Context/Decision/Findings/Result in
`RESULTS/`.

| Phase | Title | PR | Result file |
| ----- | ----- | -- | ----------- |
| 1 | DNSBL block replies: stop caching them (`no_cache_store`) | #64 | `RESULTS/01_Results.txt` |
| 2 | Unified DNSBL decision cache — `decisionDB` = `dnsblDB` + `excludeDB` (Stage 1) | #67 | `RESULTS/02_Results.txt` |
| 3 | DNSBL attribution bug fixes — mixed-case lookup + CNAME TLD | #68 | `RESULTS/03_Results.txt` |
| 4 | Unify all query-time caches — fold in noAAAA + SafeSearch (Stage 2) | #70 | `RESULTS/04_Results.txt` |
| 5 | Bound `decisionDB` with a configurable LRU cap | #72 | `RESULTS/05_Results.txt` |

## 5. Definition of done (met)

- All five PRs merged to `devel`; net DNS decisions unchanged throughout (ADR-06/07
  golden oracles green).
- `decisionDB` is the single per-domain decision cache (DNSBL + noAAAA + SafeSearch),
  O(1) and LRU-bounded; `dnsblDB`/`excludeDB`/`excludeAAAADB`/`excludeSS` and the
  noAAAA query-time memo are gone.
- Synthetic blocks are no longer C-cached → attribution + delisting correct (#43).
- Bounded memory with a WebUI cap (default 10000, `0` = unlimited); `_LruCache` and
  the decision path pinned by `tests/` (1019 pytest at Phase 5), PHPStan + PHPUnit
  green, all linters clean.
- Per-phase records preserved in `RESULTS/01–05`.
