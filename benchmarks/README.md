# pfb_unbound matching benchmarks

Compares the **pre-ADR-01 flat dicts** against the **post-ADR-01 domain trie**
for DNSBL/noAAAA matching: latency on positive *and* negative (bypass-to-Unbound)
queries, plus memory footprint. Dev-only — not shipped (release archives contain
only `src/`), and not collected by the default `pytest` run (`testpaths=["tests"]`).

## Install

```sh
python -m pip install -r benchmarks/requirements.txt
```

- [`pytest-benchmark`](https://pytest-benchmark.readthedocs.io/) — latency (the `benchmark` fixture).
- [`pympler`](https://pympler.readthedocs.io/) `asizeof` — deep retained object-graph size (memory).
- `tracemalloc` (stdlib) — build-time peak allocation.

## Run

```sh
# Latency: dict vs trie_fused vs trie_percat, grouped per scenario
python -m pytest benchmarks/test_bench_matching.py --benchmark-columns=min,mean,ops

# Memory: retained footprint + build peak (use -s to see the table)
python -m pytest benchmarks/test_memory.py -s

# Larger / different memory corpus sizes
PFB_BENCH_MEM_SIZES="10000,100000,1000000" python -m pytest benchmarks/test_memory.py -s
```

`test_decision_equivalence` runs first and asserts the dict, fused-trie and
per-category-trie deciders return identical decisions over the whole query set —
the comparison is only meaningful because all three agree.

## What is measured

- **Implementations.** `dict` = the frozen pre-ADR matchers (`_baseline.py`,
  verbatim `find_zone_match` / `whitelist_check_domain` / `find_noaaaa_wildcard_parent`
  / dict `hsts` walk). `trie_fused` = the rejected, now-frozen trie (`trie_lookup_all` in `_trie.py`, one
  descent for all categories — Phase 7). `trie_percat` = per-category trie
  lookups gated like the dict path.
- **Scenarios.** `negative` (matches nothing → bypassed to Unbound — the common
  case), `positive_data` (exact hit), `positive_zone` (subdomain of a wildcard
  zone), and the `noaaaa_*` AAAA path.
- **Corpus.** `_corpus.py` generates a deterministic feed-shaped mix (~70% exact
  data, 20% wildcard zone, 5% white, 3% hsts, 2% noAAAA) with shared suffixes
  (~8 entries per second-level domain). Same corpus feeds both structures.
- **Batch timing.** Each round times a fixed batch of queries so the per-call
  signal sits above timer resolution; dict and trie run the identical batch.
- **Memory.** `asizeof` of the populated structure (retained, fair: counts each
  reachable object once, including key/label strings and payloads). `tracemalloc`
  peak captures the transient build spike separately.

## Snapshot (illustrative — rerun locally)

Numbers are machine- and corpus-dependent (captured on CPython 3.14 / macOS,
seed 1234; production targets 3.11). Treat ratios, not absolutes, as the signal.

Latency, 100k-entry corpus, 2000-query batch (mean; lower is better):

| scenario       | dict   | trie_fused | trie_percat |
| -------------- | ------ | ---------- | ----------- |
| negative       | 1.0×   | ~2.0×      | ~1.1×       |
| positive_data  | 1.0×   | ~1.8×      | ~1.6×       |
| positive_zone  | 1.0×   | ~1.4×      | ~1.8×       |
| noaaaa_pos     | 1.0×   | ~6×        | —           |
| noaaaa_neg     | 1.0×   | ~1.2×      | —           |

Memory, retained (`asizeof`):

| corpus | dict B/entry | trie B/entry | trie/dict |
| ------ | ------------ | ------------ | --------- |
| ~9k    | ~257         | ~356         | +38%      |
| ~87k   | ~257         | ~360         | +40%      |

**Takeaway:** in CPython the flat dicts are faster and smaller for this workload.
`dict.get` is a single C-level call, whereas a trie descent is several
interpreted Python steps per query; and each `TrieNode` (object header + slots +
a `children` dict) outweighs the suffix-sharing savings at realistic
sharing ratios. The trie's theoretical "one walk for all categories" advantage
only grows with domain depth and the number of categories checked — neither
large at typical DNS name depths. Re-run with your own feeds before drawing
production conclusions.
