# ADR-05: Reattempting the DNSBL trie (a second pure-Python try, then in C) — REJECTED

- **Status:** **Rejected** (2026-06-01) — rejected on evidence *before* any implementation. No phases were written; nothing was built.
- **Date:** 2026-06-01
- **Branch:** documentation-only (no `adr/05` implementation branch — rejected pre-implementation) / **Component(s) it *would* have touched:** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (the DNSBL matcher) and, for the C variant, the FreeBSD port `net/pfSense-pkg-pfBlockerNG-devel`.
- **Target runtime (had it shipped):** Python 3.11+ inside Unbound's `pythonmod` (stdlib only); the C variant would have added a compiled extension.
- **Evidence:** `benchmarks/` (`_baseline.py` dict matcher, `_trie.py` rejected ADR-01 trie, `_corpus.py`); ADR-01 `§8` + `RESULTS/09_Benchmark_Results.md`; a throwaway dict-baseline measurement (script reproduced in **Appendix A**).

---

## 1. Context

### Today
The DNSBL hot path in `pfb_unbound.py` matches each query against **five flat dicts** — `dataDB` (exact), `zoneDB` (wildcard-incl-self), `whiteDB`, `hstsDB`, `noAAAADB`. The match sequence is reproduced verbatim in `benchmarks/_baseline.py::decide_dict`:

- exact: `dataDB.get(q_name)` — one C-level hash lookup on the full name;
- on miss: `find_zone_match` walks suffixes (`_baseline.py:17-24`);
- white / hsts / noaaaa run **only when a block already matched** (`decide_dict:107-110`) — so the common **negative** path is just "data-miss + zone-walk" and stops.

### Precedent — ADR-01
ADR-01 replaced these dicts with a reversed-label trie (`TrieNode` + per-category lookups + a Phase-7 fused single-descent). It was **fully implemented (8 phases), correct, and oracle-tested — then REJECTED** (ADR-01 §8) when benchmarks showed its core premises ("one walk → less CPU", "shared suffixes → less memory") did not hold in CPython. The frozen trie and the dict baseline are kept in `benchmarks/` precisely to guard future proposals against the same trap.

### The proposal that prompted this ADR
"Do the trie again, but **write it in C** so it's faster and uses less memory." On scrutiny this splits into two distinct ideas, both examined below:
1. a **second pure-Python trie**, redesigned to avoid ADR-01's mistakes;
2. a **C-extension trie** called from `pfb_unbound.py`.

---

## 2. The change that was considered

| Variant | What it would do |
| --- | --- |
| **Pure-Python trie v2** | Re-implement the matcher as a reversed-label trie, but leaner than ADR-01: plain-dict nodes (no `__slots__` object + attribute loads), categories packed into one int, and no "fuse-then-compute-every-category" waste on the negative path. Premise: a better-engineered trie beats the dicts on latency and/or memory. |
| **C-extension trie** | Implement the trie as a compiled CPython extension (`.so`) and call it per query from `pfb_unbound.py`. Premise: native code makes the walk fast and a packed C structure smaller than Python dicts. |

Goal as stated: win on **both** speed and memory.

---

## 3. Findings (why it was rejected)

### 3a. The baseline ADR-01 never recorded
ADR-01 reported only **trie/dict ratios**, never the dict's absolute cost — so "the dicts are too slow / too big" was never substantiated. Measured here (dict only, via `_corpus.py` + `_baseline.py`, CPython 3.14/macOS, the same environment as ADR-01 §8; reproduction script in **Appendix A**):

| feed (deduped) | retained | **bytes/entry** | build peak | match latency (ns/query) |
| --- | --- | --- | --- | --- |
| 87k  | 21 MiB  | 257 | 16 MiB  | neg 740 · exact 1217 · zone 1437 · noAAAA 1167 |
| 219k | 57 MiB  | 274 | 44 MiB  | neg 799 · exact 1348 · zone 1610 · noAAAA 1223 |
| 437k | 114 MiB | 274 | 87 MiB  | neg 801 · exact 1494 · zone 1798 · noAAAA 1358 |
| 875k | 229 MiB | 274 | 175 MiB | neg 956 · exact 1498 · zone 1938 · noAAAA 1709 |

Steady state **~274 B/entry**; projection **1M ≈ 261 MiB, 2M ≈ 523 MiB, 3M ≈ 785 MiB** retained. Structural match is **~0.7–1.9 µs/query at every size**.

### 3b. Speed is a non-problem
A DNS query is **millisecond**-scale (Unbound processing + upstream network); the structural match is **~1 µs**, three to four orders of magnitude smaller, and the DB/log writes already run **off the response path** on the async worker. There is no measurable latency to win. ADR-01 §8 further showed the trie *adds* latency in CPython, and a C trie called per query pays a Python↔C boundary cost (`PyArg_ParseTuple`, return-object build, refcounts) on every lookup that erases any algorithmic gain at these depths.

### 3c. A second Python trie hits the same intrinsic CPython walls
These are properties of CPython + node-based structures, not artifacts of ADR-01's code, so a redesign cannot escape them:

- **Exact match is unbeatable.** `dataDB.get(full_name)` is one C-level call (`O(1)`); any trie must `split` + walk labels in **interpreted Python** (`O(depth)`). ADR-01 measured exact `data` **1.6–1.8×** slower and exact `noAAAA` **~6×** slower for exactly this reason (ADR-01 §8).
- **The negative-path floor is already tiny** (data-miss + short zone-walk, then stop). A trie must still split + descend; ADR-01's fused path was **2.0×** worse here.
- **Zone is the trie's best case and it still lost** (1.4–1.8×): per-bytecode interpreter overhead per node exceeds the `str.split` the trie saves.
- **Memory: any Python node graph loses.** ADR-01's leanest reasonable node (`__slots__` object + `children` dict) was **+40% (358 B/entry)**; plain-dict nodes are heavier still. Per-node container overhead exceeds a flat hash table's per-entry cost at realistic DNS suffix-sharing.

A redesign's realistic ceiling is "approach parity on zone, stay worse on exact + negative, stay worse on memory" — i.e. never a win on either axis the proposal targets.

### 3d. The C variant carries blockers a benchmark cannot retire
- **A — distribution model.** The port `net/pfSense-pkg-pfBlockerNG-devel/Makefile` is `NO_BUILD=yes`, `NO_MTREE=yes`, arch-independent; `pkg-plist` ships **zero `.so`** (all `INSTALL_DATA`/`INSTALL_SCRIPT` of text). A compiled extension means dropping `NO_BUILD`, building per-arch (`amd64` **and** `arm64`), and **ABI-locking** to the box's exact CPython — a Python minor bump on pfSense would stop Unbound loading the module (**DNS down**), and FreeBSD-ports/Netgate must accept a compiled port. ADR-01 §5 already forbade this ("no Cython/Rust extension permitted").
- **B — safety regression (worst failure mode).** Pure Python cannot segfault Unbound (a bug is a catchable, logged exception). A C extension running in Unbound's loader can **segfault or corrupt memory → crash the firewall's resolver process**. For a security/networking appliance that is a categorical downgrade ADR-01 never had to pay.

### 3e. Even the *only* arguably-real axis doesn't need a trie — and isn't hurting anyone
The 274 B/entry is dominated by the **per-entry payload dict** `{"log":"1","index":0}` (`_corpus.py:106-107`) attached to ~80% of entries (data + zone). A trie *keeps* those payload dicts and *adds nodes* — which is exactly why ADR-01 grew +40%. If DNSBL memory ever needed cutting, the lever is **flat compaction** (store the index as the value directly, fold `log` into a bit; `sys.intern` shared suffixes) — pure-Python, ships under `NO_BUILD`, none of blockers A/B. **However, the maintainer confirms (2026-06-01) memory is not hurting real deployments**, so even flat compaction is unjustified today.

---

## 4. Decision — REJECTED

Both variants are rejected, before any implementation:

1. **Speed motivation is void** — match latency (~1 µs) is negligible against millisecond DNS resolution; DB/log are already off-path.
2. **A second pure-Python trie cannot win** — exact-match is O(1) C `dict.get` vs O(depth) interpreted walk (unbeatable), the negative-path floor is already minimal, and any Python node graph costs more memory than the flat dicts (ADR-01: +40%). These are intrinsic CPython walls, re-confirmed against the measured baseline.
3. **The C variant is not justified** — its only plausible axis (memory) is better served by pure-Python flat compaction, while it introduces a per-arch/ABI-locked compiled port (blocker A) and the ability to crash the resolver via native UB (blocker B).
4. **There is no live problem to solve** — neither latency nor memory is hurting real deployments. The flat dicts stay as-is.

This ADR is documentation only; **no phase plan, no implementation**. Like ADR-01 §8, it is retained to keep the rejection evidence durable and to stop the next "let's make it a trie" (in any language) from re-running the same trap.

---

## 5. Constraints (from `CLAUDE.md`) that shaped the rejection
- **Shipped code is stdlib-only** — `pfb_unbound.py` runs in Unbound's Python loader; no third-party deps, and (per ADR-01 §5) no compiled extension.
- **The release archive is `src/` text only**, and the port is `NO_BUILD`/arch-independent — adding native code is a port-model change, not a code tweak.
- Any future memory work must stay pure-Python, keep `python -m pytest` green, and remain behaviour-preserving for every observable DNSBL decision (the `tests/test_pfb_unbound.py` oracle).

---

## 6. What would reopen this
Only a **measured** report that the flat dicts cost too much **on a real box** — e.g. a large-feed deployment OOM-ing or paging on a low-RAM appliance. If that ever happens, the response is a **falsify-first, pure-Python flat-compaction** ADR (pack the payload dict + `sys.intern`), benchmarked against the §3a baseline with an explicit kill-threshold **before** any code — **not** a trie, and **not** C.

---

## Appendix A — baseline measurement script

Throwaway, **not shipped and deliberately not added to `benchmarks/`** — recorded here only so §3a is reproducible. It reuses `benchmarks/_corpus.py` and `_baseline.py` verbatim and measures the **dict only** (no trie build). Save as e.g. `adr05_dict_baseline.py` at the repo root and run:

```sh
python -m pip install pympler   # dev-only; not a shipped dependency
SIZES=100000,250000,500000,1000000 python adr05_dict_baseline.py
```

```python
"""Throwaway dict-baseline measurement for ADR-05 (not shipped; not in benchmarks/).

Records the ABSOLUTE cost of the current flat-dict DNSBL matcher — the baseline
ADR-01 never recorded (it reported only trie/dict ratios). Dict only; no trie.
Reuses benchmarks/_corpus.py + _baseline.py verbatim. Run from the repo root.
"""

from __future__ import annotations

import gc
import os
import sys
import time
import tracemalloc

sys.path.insert(0, "benchmarks")  # run from the repo root

from _baseline import decide_dict
from _corpus import (
    build_dicts,
    generate_corpus,
    queries_negative,
    queries_noaaaa_positive,
    queries_positive_data,
    queries_positive_zone,
)
from pympler import asizeof

HSTS_TLDS = ("dev", "app")
TLD_SEG = 2
SIZES = [int(s) for s in os.environ.get("SIZES", "100000,250000,500000,1000000").split(",")]


def measure_mem(n_entries):
    corpus = generate_corpus(n_entries)
    total = corpus.total
    gc.collect()
    tracemalloc.start()
    tracemalloc.reset_peak()
    dbs = build_dicts(corpus)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    size = asizeof.asizeof(*dbs.values())  # deep retained graph, all five dicts together
    return corpus, dbs, total, size, peak


def bench_queries(dbs, corpus, n_iter=200_000):
    qsets = {
        "negative": queries_negative(corpus, n_iter),
        "exact data": queries_positive_data(corpus, n_iter),
        "zone subdomain": queries_positive_zone(corpus, n_iter),
        "noAAAA exact": queries_noaaaa_positive(corpus, n_iter),
    }
    out = {}
    for name, qs in qsets.items():
        for q, tld in qs[:1000]:  # warm
            decide_dict(q, tld, dbs, TLD_SEG, HSTS_TLDS)
        t0 = time.perf_counter()
        for q, tld in qs:
            decide_dict(q, tld, dbs, TLD_SEG, HSTS_TLDS)
        dt = time.perf_counter() - t0
        out[name] = dt / len(qs) * 1e9  # ns/query
    return out


def main():
    print("CURRENT DICT MATCHER — absolute baseline (CPython {}.{}, {})".format(
        sys.version_info.major, sys.version_info.minor, sys.platform))
    for n in SIZES:
        corpus, dbs, total, size, peak = measure_mem(n)
        print("\nfeed entries (deduped): {:,}".format(total))
        print("  retained:   {:.2f} MiB  ({:.1f} bytes/entry)".format(size / 2**20, size / total))
        print("  build peak: {:.2f} MiB".format(peak / 2**20))
        lat = bench_queries(dbs, corpus)
        print("  latency (ns/query):  " + "   ".join("{}={:.0f}".format(k, v) for k, v in lat.items()))
        del corpus, dbs
        gc.collect()


if __name__ == "__main__":
    main()
```

