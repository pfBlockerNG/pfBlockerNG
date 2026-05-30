# ADR-01 — Benchmark results (basis for REJECTION)

Head-to-head comparison of the **pre-ADR flat dicts** vs the **post-ADR domain
trie** for `pfb_unbound` DNSBL/noAAAA matching. Suite lives in `benchmarks/`
(kept in-tree). This document is the evidence the ADR is rejected on.

## How to reproduce

```sh
python -m pip install -r benchmarks/requirements.txt
python -m pytest benchmarks/test_bench_matching.py --benchmark-columns=min,mean,stddev,ops
python -m pytest benchmarks/test_memory.py -s
```

## Methodology

- **Latency:** `pytest-benchmark`. Three implementations per scenario — `dict`
  (frozen pre-ADR matchers, `benchmarks/_baseline.py`), `trie_fused`
  (`trie_lookup_all`, the Phase-7 production path), `trie_percat` (per-category
  trie lookups gated like the dict path). A fixed 2,000-query batch is timed per
  round; dict and trie run the identical batch.
- **Memory:** `pympler.asizeof` for retained deep object-graph size (counts each
  reachable object once — dict tables, key/label strings, payload dicts, trie
  nodes incl. `__slots__`). Raw `tracemalloc` is **not** used for the retained
  figure: the dict reuses the corpus's pre-existing key strings (uncounted in a
  build-window snapshot) while the trie allocates fresh label strings (counted),
  which would unfairly inflate the trie. `tracemalloc` peak is reported only as
  the transient build spike.
- **Correctness guard:** `test_decision_equivalence` asserts `dict`,
  `trie_fused` and `trie_percat` return identical decisions (and dict-noAAAA ==
  trie-noAAAA) over the entire query set before any timing — the comparison is
  valid because all implementations agree.
- **Corpus:** deterministic, feed-shaped (~70% exact `data`, 20% wildcard `zone`,
  5% white, 3% hsts, 2% noAAAA), shared suffixes (~8 entries per second-level
  domain). Seed 1234.
- **Environment:** CPython 3.14 / macOS (production targets 3.11). Single run.
  Machine- and corpus-dependent — **treat ratios, not absolutes, as the signal.**

## Latency — 100k-entry corpus, 2,000-query batch

Mean time per batch (lower is better); ratio vs `dict` in parentheses.

| scenario | dict | trie_fused | trie_percat |
| --- | --- | --- | --- |
| `negative` (no match → bypass to Unbound) | 1.30 ms (1.0×) | 2.57 ms (**1.98×**) | 1.48 ms (1.14×) |
| `positive_data` (exact hit) | 1.90 ms (1.0×) | 3.72 ms (**1.96×**) | 3.34 ms (1.75×) |
| `positive_zone` (wildcard subdomain) | 2.61 ms (1.0×) | 3.51 ms (1.34×) | 4.57 ms (1.75×) |
| `noaaaa_positive` (exact) | 169 µs (1.0×) | 1,136 µs (**6.73×**) | — |
| `noaaaa_negative` | 722 µs (1.0×) | 987 µs (1.37×) | — |

The dict wins every scenario. The production path (`trie_fused`) is ~2× slower
on the two most common cases (negative bypass, exact hit) and ~6.7× slower on
exact noAAAA. `trie_percat` is closer on negatives but loses the zone case and
is not the shipped path.

## Memory — retained (`asizeof`)

| corpus entries | dict retained | trie retained | dict B/entry | trie B/entry | trie/dict |
| --- | --- | --- | --- | --- | --- |
| 8,795 | 2,263,152 | 3,128,944 | 257.3 | 355.8 | **+38.3%** |
| 87,474 | 22,484,368 | 31,465,816 | 257.0 | 359.7 | **+39.9%** |

Build-time peak (`tracemalloc`): trie ≈ +82% over dict (e.g. 31.0 MB vs 16.9 MB
at 87k entries).

## Root cause

1. **`dict.get()` is C; a trie descent is interpreted Python.** Per query the
   trie does: split labels, reverse, loop, per-node `dict.get`, attribute reads
   — several bytecode-level ops vs one C call. The §3 "fewer node-steps" model is
   right for a compiled language but is dominated by interpreter overhead in
   CPython. Exact hits are the extreme: `O(1)` C dict lookup vs `O(depth)` Python
   walk → the ~6.7× noAAAA gap (most noAAAA-positive queries are exact entries).
2. **Fusion backfires on the common case.** `trie_lookup_all` always computes
   every category; on a negative query (the overwhelming majority of real DNS
   traffic) the dict path stops after `data`+`zone`, so fusion does strictly more
   work → it is the slowest option on negatives (1.98× vs per-category 1.14×).
3. **Node objects outweigh suffix sharing.** Each `TrieNode` is an object header
   + 8 `__slots__` + a `children` dict; at realistic sharing ratios that exceeds
   the savings from not repeating shared suffix strings → +40% retained.

## Conclusion

No measured benefit on either axis the migration was justified by (CPU, memory);
net added complexity (TrieNode + insert/lookup/fused-walk API). The trie's
theoretical advantage needs deep names and many categories (neither holds for
DNS) and a compiled runtime (disallowed — Unbound's pure-Python, stdlib-only
loader). **ADR-01 is rejected.**

**Roll-back completed (2026-05-31).** Production matching was reverted to the
flat dicts. The behavior-preserving Phase 1–3 refactor (pure `evaluate_domain`/
`evaluate_noaaaa` + golden/property tests) and the two independent bug fixes
(regex empty-name guard; duplicate `set_return_msg`) were kept — only the trie
(Phases 4–8) was removed. The trie now lives frozen in `benchmarks/_trie.py`, so
this suite stays runnable and self-contained (it imports neither production
matcher; both `dict` and `trie` sides are frozen references). Retained to
justify the decision and to test any future structural proposal before it ships.
