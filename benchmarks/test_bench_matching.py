"""Latency benchmarks: pre-ADR flat dicts vs post-ADR domain trie.

Run with:  python -m pytest benchmarks/test_bench_matching.py
(Not collected by the default `pytest` run — testpaths is ["tests"].)

Each scenario is a pytest-benchmark group; within a group the implementations
(dict / trie_fused / trie_percat) appear side by side for direct comparison.
A fixed batch of queries is timed per round so the per-call signal sits well
above timer resolution and round-to-round noise.

Scenarios:
  - negative          : query matches nothing -> bypassed to Unbound (common case)
  - positive_data     : exact data hit
  - positive_zone     : subdomain of a wildcard zone (data-miss, suffix walk)
  - whitelisted       : a blocked domain that is also whitelisted (data + white)
  - noaaaa_positive/negative : the AAAA noAAAA path (exact OR wildcard-parent)
"""

from __future__ import annotations

import _trie
import pytest
from _baseline import MatchResult, decide_dict, evaluate_noaaaa_dict
from _corpus import (
    build_dicts,
    build_trie,
    generate_corpus,
    queries_negative,
    queries_noaaaa_positive,
    queries_positive_data,
    queries_positive_zone,
)

CORPUS_ENTRIES = 100_000
BATCH = 2_000
TLD_SEG = 2
HSTS_TLDS = ("app", "dev")  # 'app'/'dev' overlap the corpus TLDs to exercise the TLD shortcut


# --------------------------------------------------------------------------- #
# Session-scoped fixtures: build the corpus and both structures exactly once.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def corpus():
    return generate_corpus(CORPUS_ENTRIES)


@pytest.fixture(scope="session")
def dbs(corpus):
    return build_dicts(corpus)


@pytest.fixture(scope="session")
def trie(corpus):
    return build_trie(corpus)


@pytest.fixture(scope="session")
def query_sets(corpus):
    return {
        "negative": queries_negative(corpus, BATCH),
        "positive_data": queries_positive_data(corpus, BATCH),
        "positive_zone": queries_positive_zone(corpus, BATCH),
        "noaaaa_positive": queries_noaaaa_positive(corpus, BATCH),
    }


# --------------------------------------------------------------------------- #
# Trie decision functions (structural data/zone/white/hsts), mirroring decide_dict.
# --------------------------------------------------------------------------- #


def decide_trie_fused(q_name, tld, root, tld_seg, hsts_tlds) -> MatchResult:
    """Rejected trie's fused path: one descent for all categories (now in _trie.py)."""
    hit = _trie.trie_lookup_all(root, q_name, tld_seg, hsts_tlds, tld)
    if hit.data is not None:
        is_found, b_type, b_eval = True, "DNSBL", q_name
    elif hit.zone[0] is not None:
        is_found, b_type, b_eval = True, "TLD", hit.zone[0]
    else:
        return MatchResult(False, "Python", "", False, False)
    in_white = hit.white
    in_hsts = hit.hsts[0] if not in_white else False
    return MatchResult(is_found, b_type, b_eval, in_white, in_hsts)


def decide_trie_percat(q_name, tld, root, tld_seg, hsts_tlds) -> MatchResult:
    """Per-category trie lookups gated like the dict path (data->zone->white->hsts)."""
    entry = _trie.trie_lookup_exact(root, q_name)
    if entry is not None:
        is_found, b_type, b_eval = True, "DNSBL", q_name
    else:
        matched_q, _ = _trie.trie_lookup_zone(root, q_name)
        if matched_q is not None:
            is_found, b_type, b_eval = True, "TLD", matched_q
        else:
            return MatchResult(False, "Python", "", False, False)
    in_white = _trie.trie_lookup_white(root, q_name, tld_seg)
    in_hsts = _trie.trie_lookup_hsts(root, q_name, hsts_tlds, tld)[0] if not in_white else False
    return MatchResult(is_found, b_type, b_eval, in_white, in_hsts)


def _run_batch(decide, queries) -> int:
    hits = 0
    for q, tld in queries:
        if decide(q, tld).is_found:
            hits += 1
    return hits


def _make_decider(impl, dbs, trie):
    if impl == "dict":
        return lambda q, tld: decide_dict(q, tld, dbs, TLD_SEG, HSTS_TLDS)
    if impl == "trie_fused":
        return lambda q, tld: decide_trie_fused(q, tld, trie, TLD_SEG, HSTS_TLDS)
    if impl == "trie_percat":
        return lambda q, tld: decide_trie_percat(q, tld, trie, TLD_SEG, HSTS_TLDS)
    raise ValueError(impl)


IMPLS = ["dict", "trie_fused", "trie_percat"]


# --------------------------------------------------------------------------- #
# Correctness guard — the comparison is only meaningful if both agree.
# --------------------------------------------------------------------------- #


def test_decision_equivalence(corpus, dbs, trie, query_sets):
    """dict, trie_fused and trie_percat must return identical decisions."""
    d = _make_decider("dict", dbs, trie)
    tf = _make_decider("trie_fused", dbs, trie)
    tp = _make_decider("trie_percat", dbs, trie)
    checked = 0
    for qs in query_sets.values():
        for q, tld in qs:
            assert d(q, tld) == tf(q, tld) == tp(q, tld), q
            checked += 1
    assert checked > 0

    # noAAAA path equivalence (separate matcher).
    for q, _ in query_sets["noaaaa_positive"] + query_sets["negative"]:
        assert evaluate_noaaaa_dict(q, dbs["noAAAADB"]) == _trie.trie_lookup_noaaaa(trie, q), q


# --------------------------------------------------------------------------- #
# Latency benchmarks.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.benchmark(group="negative")
def test_negative(benchmark, impl, dbs, trie, query_sets):
    decide = _make_decider(impl, dbs, trie)
    queries = query_sets["negative"]
    hits = benchmark(_run_batch, decide, queries)
    assert hits == 0


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.benchmark(group="positive_data")
def test_positive_data(benchmark, impl, dbs, trie, query_sets):
    decide = _make_decider(impl, dbs, trie)
    queries = query_sets["positive_data"]
    hits = benchmark(_run_batch, decide, queries)
    assert hits == len(queries)


@pytest.mark.parametrize("impl", IMPLS)
@pytest.mark.benchmark(group="positive_zone")
def test_positive_zone(benchmark, impl, dbs, trie, query_sets):
    decide = _make_decider(impl, dbs, trie)
    queries = query_sets["positive_zone"]
    hits = benchmark(_run_batch, decide, queries)
    assert hits == len(queries)


def _noaaaa_decider(impl, dbs, trie):
    if impl == "dict":

        def decide(q):
            return evaluate_noaaaa_dict(q, dbs["noAAAADB"])
    else:

        def decide(q):
            return _trie.trie_lookup_noaaaa(trie, q)

    return decide


def _run_noaaaa_batch(decide, queries) -> int:
    return sum(1 for q, _ in queries if decide(q))


@pytest.mark.parametrize("impl", ["dict", "trie"])
@pytest.mark.benchmark(group="noaaaa_positive")
def test_noaaaa_positive(benchmark, impl, dbs, trie, query_sets):
    queries = query_sets["noaaaa_positive"]
    hits = benchmark(_run_noaaaa_batch, _noaaaa_decider(impl, dbs, trie), queries)
    assert hits == len(queries)


@pytest.mark.parametrize("impl", ["dict", "trie"])
@pytest.mark.benchmark(group="noaaaa_negative")
def test_noaaaa_negative(benchmark, impl, dbs, trie, query_sets):
    queries = query_sets["negative"]
    hits = benchmark(_run_noaaaa_batch, _noaaaa_decider(impl, dbs, trie), queries)
    assert hits == 0
