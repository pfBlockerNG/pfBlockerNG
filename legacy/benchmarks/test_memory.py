"""Memory comparison: pre-ADR flat dicts vs post-ADR domain trie.

Run with:  python -m pytest benchmarks/test_memory.py -s
(`-s` so the report table is printed.)

Two metrics, two tools:

* Retained footprint (primary) — ``pympler.asizeof``. Deep object-graph size:
  follows every reference (dict tables, key/label strings, payload dicts, trie
  nodes incl. __slots__) and counts each reachable object once. This is the
  fair "bytes to represent the blocklist" number. tracemalloc is NOT used for
  this because it only counts allocations made inside its window, and the dict
  reuses the corpus's pre-existing key strings (so they'd go uncounted) while
  the trie allocates fresh label strings (counted) — an apples-to-oranges skew.

* Build-time peak (secondary) — stdlib ``tracemalloc``. The transient high-water
  mark while constructing the structure (split lists, rehashing, etc.).

Reporting harness, not a pass/fail gate — assertions only sanity check that both
structures were populated. Read the printed table.
"""

from __future__ import annotations

import gc
import os
import tracemalloc

import pytest
from _corpus import build_dicts, build_trie, generate_corpus
from pympler import asizeof

# Override via PFB_BENCH_MEM_SIZES="10000,100000,1000000"
_SIZES = os.environ.get("PFB_BENCH_MEM_SIZES", "10000,100000")
MEM_SIZES = [int(s) for s in _SIZES.split(",") if s.strip()]


def _build_peak(build_fn) -> tuple[int, object]:
    """Return (peak_bytes_during_build, structure). Structure kept alive."""
    gc.collect()
    tracemalloc.start()
    tracemalloc.reset_peak()
    structure = build_fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak, structure


@pytest.mark.parametrize("n_entries", MEM_SIZES)
def test_memory_footprint(n_entries):
    corpus = generate_corpus(n_entries)
    total = corpus.total

    dict_peak, dbs = _build_peak(lambda: build_dicts(corpus))
    trie_peak, trie = _build_peak(lambda: build_trie(corpus))

    # Sanity: both structures were actually populated with the corpus.
    assert sum(len(d) for d in dbs.values()) == total
    assert trie is not None and trie.children is not None

    # Retained deep size — count each structure's full reachable graph once.
    # For the dicts, size all five together so shared/interned objects (e.g. the
    # "1" log string, the index 0 int) are counted a single time.
    dict_size = asizeof.asizeof(*dbs.values())
    trie_size = asizeof.asizeof(trie)

    ratio = trie_size / dict_size if dict_size else float("nan")
    print("\n" + "=" * 78)
    print(
        "MEMORY  corpus entries={:,}  (data={:,} zone={:,} white={:,} hsts={:,} noaaaa={:,})".format(
            total, len(corpus.data), len(corpus.zone), len(corpus.white), len(corpus.hsts), len(corpus.noaaaa)
        )
    )
    print("-" * 78)
    print("{:<14}{:>18}{:>16}{:>14}".format("structure", "retained bytes", "build peak", "bytes/entry"))
    print("{:<14}{:>18,}{:>16,}{:>14.1f}".format("dict (pre)", dict_size, dict_peak, dict_size / total))
    print("{:<14}{:>18,}{:>16,}{:>14.1f}".format("trie (post)", trie_size, trie_peak, trie_size / total))
    print("-" * 78)
    print("trie/dict retained ratio: {:.3f}  ({:+.1f}%)".format(ratio, (ratio - 1) * 100))
    print("=" * 78)

    # Keep references live until after measurement/printing.
    assert dbs is not None
