# ADR-01: Migrate `pfb_unbound.py` DNSBL matching from flat dicts to a domain trie

- **Status:** **REJECTED** (2026-05-31) — benchmarks show the trie is both slower and more memory-hungry than the flat dicts it replaced in CPython. See §8. The implementation was completed (Phases 1–8) and is correct (behavior-equivalent, oracle-tested), but the premise did not hold empirically. **Rolled back** (2026-05-31): production matching reverted to the flat dicts; the behavior-preserving Phase 1–3 refactor (pure `evaluate_domain`/`evaluate_noaaaa` + golden/property tests) and the two independent bug fixes (regex empty-name guard; duplicate `set_return_msg`) were retained. The trie is preserved, frozen, only in `benchmarks/_trie.py` for the benchmark of record.
- **Date:** 2026-05-30
- **Component:** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (Unbound embedded-Python DNSBL plugin)
- **Test suite:** `tests/test_pfb_unbound.py`, `tests/conftest.py`
- **Target runtime:** Python 3.11+ (pfSense CE 2.8 / FreeBSD 15), stdlib only, runs inside Unbound's `pythonmod` loader

---

## 1. Context

`pfb_unbound.py` performs per-DNS-query blocklist matching inside Unbound's Python module. The hot path is `operate()` (the Unbound event callback). Domain matching today uses several **flat `dict`/`defaultdict` containers** plus **ad-hoc suffix-string walks**, all interleaved with side effects (qstate mutation, sqlite writes, memo-dict writes, log emission) inside the ~450-line `operate()` body.

### Current containers (built in `init_standard()`)

| Container | Shape | Match semantics | Matcher |
| --- | --- | --- | --- |
| `dataDB` | `{domain: {log, index}}` | **exact** only | inline `dataDB.get(q_name)` |
| `zoneDB` | `{domain: {log, index}}` | **wildcard** (domain + all subdomains, incl. self) | `find_zone_match()` |
| `whiteDB` | `{domain: wildcard_bool}` | exact + `www.`-strip exact + suffix-walk gated by `tld_seg` | `whitelist_check_domain()` |
| `noAAAADB` | `{domain: wildcard_bool}` | exact OR wildcard-parent (parent only, not self) + runtime memo write | `find_noaaaa_wildcard_parent()` |
| `hstsDB` | `{domain: 0}` (set) | exact membership + inline suffix-walk with **step −2** | inline in `operate()` |
| `gpListDB` | `{ip: 0}` | exact IP | inline (NOT a domain matcher) |
| `safeSearchDB` | `{domain: {A, AAAA}}` | exact + `www.` | inline (special redirect logic) |
| `regexDB` | `{name: compiled}` | linear scan | `pfb_regex_match()` |
| `dnsblDB` | `{q_name: decision}` | runtime memo of block decisions | — |
| `excludeDB` / `excludeAAAADB` / `excludeSS` | lists | runtime memo of non-matches | — |
| `feedGroupIndexDB` | `{index: {feed, group}}` | index → feed/group dedup | — |

### Problems

1. **Redundant work per query.** Three-to-four independent suffix-walk structures (`zoneDB`, `whiteDB`, `noAAAADB`, `hstsDB`), each re-slicing the query string (`q.split('.', 1)[-1]`) and issuing N `dict.get` calls (N = label count) on every query.
2. **Memory bloat.** Every entry (and every parent domain) is stored as a full string key. Million-entry feeds duplicate shared suffixes (`example.com` stored independently for `ads.example.com` and `track.example.com`). No suffix sharing.
3. **Untestable/unswappable.** Matching is tangled with I/O and qstate mutation inside `operate()`, so the data structure cannot be replaced without surgery on a giant function, and behavior cannot be pinned by tests at the matcher boundary.

---

## 2. Decision

Replace the per-category flat dicts and ad-hoc suffix walks with a **single reverse-label domain trie**, walked once per query, after first **extracting the matching logic into pure, oracle-tested functions**.

### Target data structure

A trie keyed by DNS label, inserted **TLD-first** (`ads.example.com` → `com` → `example` → `ads`). Category membership is recorded as flags/payloads on shared nodes, so one downward walk resolves all categories. A wildcard node short-circuits any deeper query.

```python
class TrieNode:
    __slots__ = ("children", "data", "zone", "white", "white_wild", "noaaaa", "noaaaa_wild", "hsts")
    # children: dict[str, TrieNode] | None  (lazy)
    # data:  exact-match payload {log, index} or None
    # zone:  wildcard payload {log, index} or None
    # white: bool ; white_wild: bool
    # noaaaa: bool ; noaaaa_wild: bool
    # hsts:  bool
```

One trie instance (`domainTrie`); category flags live on shared nodes; `children` allocated lazily; use `__slots__` to keep per-node overhead low.

### Semantics that MUST be preserved (the contract)

These are load-bearing and easy to break. Each must be pinned by an oracle test before the swap:

- **data = exact only.** `evil.com` blocks `evil.com`, never `x.evil.com`.
- **zone = wildcard incl. self.** `example.com` blocks `example.com` and `sub.example.com`. The matcher must return the *matched parent domain string* (`matched_q`) — it becomes `b_eval` and is logged.
- **white = exact + `www.`-strip exact + suffix-walk gated by `x >= tld_seg`.** The `tld_seg` gate is non-trivial; preserve exactly.
- **noaaaa = exact OR wildcard-parent (parent only, not self for the wildcard branch).** On a wildcard hit, the runtime memo write (`noAAAADB[q_name] = True`) must be preserved.
- **hsts walk uses step −2, not −1.** Preserve the existing stride (or fix it explicitly under its own test — do not change silently).

### Things explicitly kept as-is

- `gpListDB` (IP exact), `safeSearchDB` (special redirect), `regexDB` (linear) — not domain-trie candidates.
- `dnsblDB`, `excludeDB`, `excludeAAAADB`, `excludeSS` — runtime memo, orthogonal to the static blocklist structure.
- `feedGroupIndexDB` — index/feed-group dedup; the trie payload reuses the same `{log, index}` shape so this is untouched.
- `pfb['dataDB']` / `pfb['zoneDB']` / … boolean gate flags — cheap short-circuits, retained.

---

## 3. Consequences

**Positive**

- One trie walk replaces 3–4 independent suffix walks → less CPU per query on the DNS hot path.
- Shared-suffix storage → lower memory on large feeds.
- Matching becomes a set of small pure functions with golden tests → safe to evolve.

**Negative / risks**

- No live Unbound in CI; correctness is verified only via the pytest oracle plus manual smoke on pfSense (`scripts/deploy.sh`). The oracle tests are therefore non-negotiable.
- A subtle semantic regression (tld_seg gate, hsts −2 stride, noaaaa parent-only, zone matched-parent string) would silently change blocking behavior. Mitigated by property tests comparing new vs. retained old implementation.
- Larger up-front refactor (extraction) before any performance benefit lands.

---

## 4. Action plan (recommended order)

Each phase is an independent commit, leaves `python -m pytest` green, and (Phases 1–3) is strictly behavior-preserving. Phases 1–3 are the de-riskers: they turn the trie swap from "surgery inside `operate()`" into "reimplement five pure functions that already have golden tests."

### Phase 1 — Extract pure domain-match helpers + unify signatures (behavior-preserving)

Prompt: `01_Extract_A1_A3_and_B.txt`

- **A1** `hsts_check_domain(...)` — extract the only remaining inline suffix walk (HSTS), preserving the step −2 stride.
- **A2** `resolve_feed_group(index) -> (feed, group)` — dedup the feed/group lookup duplicated in the data and zone branches.
- **A3** `iter_domain_suffixes(name)` — one generator for the `q.split('.', 1)[-1]` walk reused by every matcher; surfaces the per-matcher offset differences in one place.
- **B** Unify matcher signatures to a consistent `(container, name, *opts)` shape so trie versions are drop-in.

### Phase 2 — Split decision from side-effects (behavior-preserving)

Prompt: `02_Extract_A4_A5.txt`

- **A4** `evaluate_domain(...) -> Decision | None` — pure decision (data → zone → tld → idn → regex → whitelist). Side effects (`dnsblDB[...]=`, `excludeDB.append`, `write_sqlite`, DNSMessage build) stay in `operate()`.
- **A5** `evaluate_noaaaa(q_name) -> bool` — pull the noAAAA match+memo orchestration out of `operate()`, keeping DNSMessage build in `operate()`.

### Phase 3 — Oracle/property tests + test-fixture insulation

Prompt: `03_Oracle_Tests.txt`

- Property tests against the extracted helpers (random domains; current impl = golden).
- Convert tests that poke globals directly (`dataDB[...] =`, `zoneDB[...] =`, `noAAAADB[...] =`) to go through insert helpers, so the eventual swap changes only the helper body, not the tests.

### Phase 4 — Trie data structure + insert/lookup functions + their tests

Prompt: `04_Trie_Structure_And_Inserts.txt`

- Add `TrieNode`, `trie_insert`, `trie_lookup_exact` (data), `trie_lookup_zone`, `trie_lookup_white`, `trie_lookup_noaaaa`, `trie_lookup_hsts`. Keep the old dict helpers as the oracle.
- Property test: random domains → new trie lookups == old dict-walk results.

### Phase 5 — Build the trie at load (dual-populate)

Prompt: `05_Build_Trie_At_Load.txt`

- Populate the trie in the existing CSV/ini load loops in `init_standard()`, alongside the old dicts (transitional dual-populate). No reader changes yet.

### Phase 6 — Swap readers to the trie

Prompt: `06_Swap_Readers.txt`

- Point `evaluate_domain` / `evaluate_noaaaa` / hsts at the trie lookups. Retain the `pfb['dataDB']`/etc. gate flags.

### Phase 7 — Single-walk fusion (optional perf win)

Prompt: `07_Single_Walk_Fusion.txt`

- Compute the label list once and descend once, collecting data/zone/white hits in a single pass. Only after Phase 6 is green.

### Phase 8 — Delete dead code + finalize

Prompt: `08_Delete_Dead_Code.txt`

- Remove old dicts (`dataDB`, `zoneDB`, `whiteDB`, `noAAAADB`, `hstsDB`), old walk helpers, their module-level type declarations and `global` lists. Migrate any remaining tests/conftest to the trie. Update docs if developer workflow changed.

---

## 5. Constraints (from `CLAUDE.md`)

- **stdlib only** — runs in Unbound's Python loader; no third-party deps.
- Python 3.11+; 4-space indent; type hints on new functions; `from __future__ import annotations` already present.
- No `die()`/`exit()` in library code — return values or raise.
- Run `python -m pytest` (from repo root) after **any** change to `pfb_unbound.py` or `tests/`.
- `ruff check .` and `ruff format .` clean before each commit; keep `.flake8` in sync if Ruff config changes.
- Commit style: `pfb_unbound: <imperative summary>` (or `refactor:` / `test:` scope as appropriate). Work lands on `devel`.
- Unbound injects API symbols (`log_info`, `RR_TYPE_*`, `DNSMessage`, …) as runtime globals; new injected symbols are declared in `stubs/python/unboundmodule.py` and copied onto `builtins` by `tests/conftest.py`. The trie code must not depend on any Unbound symbol (keep it pure).

---

## 6. Pre-existing issues noted (do NOT fold into this migration)

- `operate()` calls `msg.set_return_msg(qstate)` twice in the block path (once standalone, once inside the `if`). Redundant; fix under a separate change with its own test.

---

## 7. Definition of done

- `python -m pytest` green, including new oracle/property tests.
- `ruff check .` / `ruff format .` clean.
- A single trie is populated at load; all four domain categories (data, zone, white, noaaaa) — plus hsts — read through the trie.
- Old per-category dicts and ad-hoc walk helpers removed.
- ADR status moved to **Accepted** and the manual pfSense smoke result recorded.

### Phase 8 / Manual smoke test

Code and automated tests are complete as of Phase 8 (dict matchers removed; trie
is the sole DNSBL structure; 203 pytest cases green; ruff clean). Acceptance is
**blocked on a human-run smoke test** against a live pfSense box (deploy via
`scripts/deploy.sh`; no live Unbound is available in the development/CI
environment, so these cannot be automated and were **not** run).

The following checks are **OUTSTANDING** — owner: **maintainer**:

- [ ] **Known blocked domain — exact match:** query a domain that is an exact
      DNSBL `data` entry; confirm it is blocked (DNSBL response) and logged.
- [ ] **Known blocked domain — subdomain/wildcard:** query a subdomain of a
      `zone` (wildcard-incl-self) entry; confirm the wildcard match blocks it.
- [ ] **Whitelisted domain:** query a domain present in the whitelist (and a
      `www.`-prefixed and a tld_seg-gated suffix case); confirm it resolves
      normally and is not blocked.
- [ ] **AAAA noAAAA case:** query `AAAA` for a domain in the noAAAA list (exact
      and a wildcard-parent subdomain); confirm the AAAA→A suppression behaviour
      and that the reply path logs it as `noAAAA`.

Once all four pass on a live box, update **Status** to **Accepted** and record
the result here.

> **Superseded — this section is moot.** The migration was completed through
> Phase 8 but is **rejected** (§8) on benchmark evidence before the smoke test
> was run. The Definition of Done above describes the goal as originally
> proposed; it was met mechanically, but the goal itself proved
> counterproductive. Do not mark Accepted.

---

## 8. Rejection — benchmark findings (2026-05-31)

After Phase 8, the trie matcher was benchmarked head-to-head against the flat
dicts it replaced (`benchmarks/`, kept in-tree). The migration's core premises —
*"one trie walk replaces 3–4 dict walks → less CPU"* (§3) and *"shared-suffix
storage → lower memory"* (§3) — **did not hold in CPython**.

Methodology: pytest-benchmark for latency, `pympler.asizeof` for fair retained
memory (deep object-graph size; not raw `tracemalloc`, which would skew toward
the trie — see `benchmarks/test_memory.py`), `tracemalloc` for build peak. A
feed-shaped corpus (~70% exact data / 20% wildcard zone / 5% white / 3% hsts /
2% noAAAA) with shared suffixes; dict and trie verified to return identical
decisions before timing. Figures below: CPython 3.14 / macOS, 100k-entry corpus,
seed 1234 — machine-/corpus-dependent; treat ratios as the signal. Full results
in `RESULTS/09_Benchmark_Results.txt`.

**Latency (dict = 1.0×; higher = slower):**

| scenario | dict | trie (fused, prod path) | trie (per-category) |
| --- | --- | --- | --- |
| negative (no match → bypass to Unbound) | 1.0× | ~2.0× | ~1.1× |
| positive — exact `data` hit | 1.0× | ~1.8× | ~1.6× |
| positive — `zone` subdomain | 1.0× | ~1.4× | ~1.8× |
| noAAAA positive (exact) | 1.0× | ~6× | — |
| noAAAA negative | 1.0× | ~1.2× | — |

**Memory (retained, `asizeof`):** dict ≈ 257 B/entry, trie ≈ 358 B/entry →
**trie +40%**; trie build-time peak ≈ +82%.

**Why (root cause):**

1. `dict.get()` is a single C-level call; a trie descent is several *interpreted*
   Python steps per query (label split, loop, per-node `dict.get`, attribute
   reads). The "fewer node-steps" analysis in §3 is valid for a compiled
   language but is dominated, in CPython, by per-step interpreter overhead. An
   exact `data`/noAAAA hit is `O(1)` C for the dict vs an `O(depth)` Python walk
   for the trie — hence the ~6× noAAAA gap.
2. The Phase 7 *fusion* is the **worst** option on the common negative path
   (~2.0× vs per-category's ~1.1×): it always computes every category even when
   the query matches nothing, where the dict path stops after `data`+`zone`.
3. Each `TrieNode` (object header + 8 `__slots__` + a `children` dict) outweighs
   suffix-sharing at realistic sharing ratios, so the trie's footprint is larger.

The trie's theoretical edge ("one walk for all categories") grows with domain
*depth* and *category count* — neither large at typical DNS name depths — and
cannot be recovered here because the plugin runs in Unbound's pure-Python loader
(stdlib only; no Cython/Rust extension permitted, §5). **No measured benefit on
either axis the migration was justified by; net added complexity. Rejected.**

The benchmark suite and these results are retained in-tree to justify the
rejection and to guard any future data-structure proposal against the same trap.
