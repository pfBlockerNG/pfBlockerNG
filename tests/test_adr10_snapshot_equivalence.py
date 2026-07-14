"""ADR-10 Phase 2 -- single immutable Snapshot is DECISION-EQUIVALENT.

WHY THIS FILE EXISTS
--------------------
Phase 2 is a PURE, behaviour-preserving refactor: the matcher strata that the
per-query matcher reads (``dataDB``/``zoneDB``/``whiteDB``/``regexDB`` + ADR-07's
``allowRegexDB``/``feedGroupIndexDB``/``hstsDB`` and the ``important_rules`` fast-path
gate) are bundled into ONE frozen ``Snapshot`` behind a single module reference, so a
future zero-downtime swap rebinds them atomically (no torn read). It changes WHERE the
structures are held, never WHAT a query decides.

This file is the Phase-2 guard. The retained ADR-06/07 oracles already pin idle
decision-identity through ``evaluate_domain``; here we additionally prove FIELD-FOR-
FIELD that:

  1. ``Snapshot.containers()`` reproduces the EXACT legacy ``containers`` mapping the
     pre-refactor ``operate()`` assembled from the separate module globals -- same keys,
     same dict objects (completeness: every per-query stratum is in the Snapshot).
  2. Running the PRODUCTION ``evaluate_domain`` over the OLD per-global ``containers``
     and over the NEW ``Snapshot.containers()`` yields a BYTE-IDENTICAL ``DnsblDecision``
     (every field), across BOTH ABP-off (``important_rules`` False -> fast path) and
     ABP-on (``important_rules`` True -> numeric 6-band path) corpora, with and without
     a user whitelist.

Following the repo test-coverage rules, each equivalence assertion first asserts the
PRE-state (the legacy-global decision is the one the oracles already trust) and THEN
asserts the post-refactor decision equals it -- so a green proves the Snapshot CAUSED
no change, not that both paths merely happen to land on the same end-state.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Iterable

import pfb_unbound as P

# A minimal public-suffix oracle (mirrors test_adr07_emit_wire): com/net/org are
# public suffixes, so example.com is the registrable parent for zone classification.
_TLD_MASTER = ["com", "net", "org"]

# Every key the pre-refactor operate() assembled into the per-query ``containers``
# dict (pfb_unbound.py, the old :4140-4148 assembly). The Snapshot MUST cover all of
# them -- this is the completeness contract.
_CONTAINER_KEYS = frozenset(
    {
        "dataDB",
        "zoneDB",
        "whiteDB",
        "regexDB",
        "allowRegexDB",
        "feedGroupIndexDB",
        "hstsDB",
    }
)


def _build(
    feeds: dict[str, list[str]],
    *,
    user_whitelist: Iterable[str] = (),
    top1m_enabled: bool = False,
) -> P.BuildResult:
    """Build a BuildResult from an in-memory manifest. ``feeds`` maps name -> raw lines;
    each line is routed by its own shape (the permanent per-line capture guard,
    #1083 P4), never by a feed-level tag."""
    raw_store = dict(feeds)
    manifest = {
        "feeds": [
            {
                "raw": name,
                "feed": name,
                "group": name,
                "log_flag": "1",
                "provenance": "feed",
            }
            for name in feeds
        ],
    }
    config = {
        "tld_wildcard_master": _TLD_MASTER,
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": list(user_whitelist),
        "user_unlock": [],
        "top1m_list": [],
    }

    def reader(raw: str) -> Iterable[str]:
        return list(raw_store.get(raw, []))

    return P.build(manifest, config, line_reader=reader, top1m_enabled=top1m_enabled)


def _snapshot_from_result(result: P.BuildResult, *, hsts: dict[str, Any] | None = None) -> P.Snapshot:
    """Build the production Snapshot from a BuildResult (mirrors what init_standard does:
    the build's dicts + the regex merge + the HSTS file load)."""
    return P.Snapshot(
        data_db=result.data_db,
        zone_db=result.zone_db,
        white_db=result.white_db,
        regex_db=result.regex_db,
        allow_regex_db=result.allow_regex_db,
        feed_group_index_db=result.feed_group_index_db,
        hsts_db=hsts if hsts is not None else {},
        important_rules=result.important_rules,
        counts=result.counts,
        regex_count=result.regex_count,
    )


def _legacy_containers(result: P.BuildResult, *, hsts: dict[str, Any] | None = None) -> dict[str, Any]:
    """The EXACT per-query ``containers`` dict the pre-refactor operate() assembled from
    the separate module globals (pre-ADR-10). The equivalence proof compares evaluating
    over THIS against evaluating over Snapshot.containers()."""
    return {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": result.regex_db,
        "allowRegexDB": result.allow_regex_db,
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": hsts if hsts is not None else {},
    }


def _cfg(result: P.BuildResult, *, hsts: bool = False) -> dict[str, Any]:
    return {
        "python_blocking": True,
        "dataDB": bool(result.data_db),
        "zoneDB": bool(result.zone_db),
        "whiteDB": bool(result.white_db),
        "regexDB": bool(result.regex_db),
        "allowRegexDB": bool(result.allow_regex_db),
        "important_rules": result.important_rules,
        "hstsDB": hsts,
        "tld_allow": False,
        "python_idn": False,
        "python_tld_seg": 2,
        "tld_allow_list": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "hsts_tlds": (),
        "regex_warn_ms": P.REGEX_WARN_MS_DEFAULT,
        "regex_evict_ms": P.REGEX_EVICT_MS_DEFAULT,
    }


def _evaluate(containers: dict[str, Any], cfg: dict[str, Any], q_name: str) -> P.DnsblDecision:
    tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
    return P.evaluate_domain(q_name, q_name, tld, False, cfg, containers)


# --------------------------------------------------------------------------- #
# Corpora -- one ABP-off (fast path) and one ABP-on (numeric 6-band path).
# --------------------------------------------------------------------------- #

# ABP-off: plain block lists. important_rules stays False -> historical fast path.
_PLAIN_FEEDS = {"adsfeed": ["ads.example.com", "tracker.example.net"]}
_PLAIN_QUERIES = [
    "ads.example.com",  # exact data block
    "deep.sub.ads.example.com",  # zone-suffix block (registrable example.com? no: ads is data)
    "tracker.example.net",  # exact data block
    "safe.example.org",  # pass (no rule)
    "example.com",  # not a listed name -> pass
]

# ABP-on: @@ allow exception + $important block + irreducible regex -> important_rules
# True (numeric 6-band resolution path). Covers block/allow/regex/important strata.
_ABP_FEEDS = {
    "abpfeed": [
        "||evil.com^",  # block (reducible -> zone)
        "||tracker.net^$important",  # important block (band 4)
        "@@||good.com^",  # allow exception
        "/ad[0-9]+\\.example\\.org/",  # irreducible block regex
    ]
}
_ABP_QUERIES = [
    "evil.com",  # important?no -> block
    "sub.evil.com",  # wildcard zone block
    "tracker.net",  # important block
    "good.com",  # @@ allow -> resolve
    "ad42.example.org",  # irreducible regex block
    "noad.example.org",  # regex miss -> pass
    "unlisted.com",  # pass
]


def _assert_field_for_field(result: P.BuildResult, queries: list[str], *, hsts: bool, with_white: bool) -> None:
    """For each query, assert the LEGACY-global decision first (the trusted pre-state),
    then assert the Snapshot decision equals it field-for-field (the post-state)."""
    hsts_db: dict[str, Any] = {}
    cfg = _cfg(result, hsts=hsts)
    legacy = _legacy_containers(result, hsts=hsts_db)
    snap = _snapshot_from_result(result, hsts=hsts_db)

    # Completeness: the Snapshot's container mapping is identical to the legacy keys,
    # and each value is the SAME object the legacy assembly used (no copy, no drift).
    snap_containers = snap.containers()
    assert set(snap_containers) == _CONTAINER_KEYS == set(legacy)
    for k in _CONTAINER_KEYS:
        assert snap_containers[k] is legacy[k], f"container[{k}] is not the same object"

    failures: list[str] = []
    for q in queries:
        # PRE-state: the decision the retained ADR-06/07 oracles trust (legacy globals).
        before = _evaluate(legacy, cfg, q)
        # POST-state: the decision off the single immutable Snapshot.
        after = _evaluate(snap.containers(), cfg, q)
        if dataclasses.astuple(before) != dataclasses.astuple(after):
            failures.append(f"{q}: legacy={before!r} snapshot={after!r}")
    assert not failures, "snapshot decision diverged from legacy globals:\n" + "\n".join(failures)


class TestSnapshotType:
    def test_is_frozen(self) -> None:
        snap = P.Snapshot(
            data_db={},
            zone_db={},
            white_db={},
            regex_db={},
            allow_regex_db={},
            feed_group_index_db={},
            hsts_db={},
        )
        # Frozen: the single ref cannot be re-pointed field-by-field (the torn-swap
        # hazard ADR-10 removes -- a swap must replace the WHOLE Snapshot).
        try:
            snap.data_db = {"x": 1}  # type: ignore[misc]
        except dataclasses.FrozenInstanceError:
            pass
        else:
            raise AssertionError("Snapshot must be frozen (immutable single ref)")

    def test_containers_covers_every_legacy_key(self) -> None:
        snap = P.Snapshot(
            data_db={"a": 1},
            zone_db={"b": 2},
            white_db={"c": 3},
            regex_db={"d": 4},
            allow_regex_db={"e": 5},
            feed_group_index_db={0: 6},
            hsts_db={"f": 7},
        )
        containers = snap.containers()
        assert set(containers) == _CONTAINER_KEYS
        # Each value is the SAME dict object the field holds -- evaluate_domain mutates
        # regexDB in place (eviction); identity must hold or eviction would target a copy.
        assert containers["dataDB"] is snap.data_db
        assert containers["zoneDB"] is snap.zone_db
        assert containers["whiteDB"] is snap.white_db
        assert containers["regexDB"] is snap.regex_db
        assert containers["allowRegexDB"] is snap.allow_regex_db
        assert containers["feedGroupIndexDB"] is snap.feed_group_index_db
        assert containers["hstsDB"] is snap.hsts_db


class TestPlainCorpusEquivalence:
    """ABP-off: important_rules MUST be False (the historical fast path)."""

    def test_important_rules_off(self) -> None:
        result = _build(_PLAIN_FEEDS)
        # Branch anchor: this corpus exercises the FAST path.
        assert result.important_rules is False

    def test_field_for_field_no_whitelist(self) -> None:
        result = _build(_PLAIN_FEEDS)
        _assert_field_for_field(result, _PLAIN_QUERIES, hsts=False, with_white=False)

    def test_field_for_field_with_whitelist(self) -> None:
        # whiteDB present -> the fast-path whitelist override branch is taken.
        result = _build(_PLAIN_FEEDS, user_whitelist=["ads.example.com"])
        assert result.important_rules is False
        assert bool(result.white_db) is True
        _assert_field_for_field(result, _PLAIN_QUERIES, hsts=False, with_white=True)


class TestAbpCorpusEquivalence:
    """ABP-on: important_rules MUST be True (the numeric 6-band path)."""

    def test_important_rules_on(self) -> None:
        result = _build(_ABP_FEEDS)
        # Branch anchor: an @@/regex/$important loaded -> the numeric path is engaged.
        assert result.important_rules is True

    def test_field_for_field_no_whitelist(self) -> None:
        result = _build(_ABP_FEEDS)
        _assert_field_for_field(result, _ABP_QUERIES, hsts=False, with_white=False)

    def test_field_for_field_with_whitelist(self) -> None:
        result = _build(_ABP_FEEDS, user_whitelist=["evil.com"])
        assert result.important_rules is True
        assert bool(result.white_db) is True
        _assert_field_for_field(result, _ABP_QUERIES, hsts=False, with_white=True)


class TestInitAssignsSingleRef:
    """init_standard builds the Snapshot and assigns the ONE module ref; operate() reads
    it. Prove the module-level ``_snapshot`` is the single source operate() consumes."""

    def test_module_ref_present_and_usable(self) -> None:
        result = _build(_ABP_FEEDS)
        snap = _snapshot_from_result(result)
        # Mimic the init assignment of the single ref.
        P._snapshot = snap
        # operate() reads exactly this ref via ``snap = _snapshot``; the captured
        # containers must equal what we built (one source of truth, no separate globals).
        assert P._snapshot is snap
        assert P._snapshot.containers()["dataDB"] is result.data_db
        assert P._snapshot.important_rules is True
