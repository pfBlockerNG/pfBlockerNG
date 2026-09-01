"""Issue #3050 -- the TLD-wildcard blacklist is normalized ONCE, by the caller.

``tld_wildcard_classify()`` runs once per DNSBL feed entry, so nothing inside it
may cost O(len(blacklist)). The intent pinned here is a contract, not a duration:

* the classifier CONSUMES already dot-stripped TLD roots -- it never iterates or
  re-strips the blacklist it is handed, and
* ``build()`` derives those roots ONCE before its per-entry loop and passes the
  SAME object for every entry -- exactly the treatment ``tld_wildcard_exclusion``
  has always had (``exclusion`` at ``build()``'s prologue).

Each cost row pairs with a behaviour row: the blacklist must still decide the
classification, so ignoring it cannot satisfy the cost contract alone.

Pure pytest, stdlib only, no Unbound symbols (CI-runnable).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pfb_unbound as P

# Minimal self-contained PSL: an ICANN two-label suffix (co.uk) whose root (uk)
# is what a user blacklists, plus a single-label ICANN suffix to contrast with.
PSL = """// ===BEGIN ICANN DOMAINS===
com
co.uk
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// ===END PRIVATE DOMAINS===
"""


def _rules() -> P.PslRules:
    return P.parse_psl_rules(PSL)


class _CountingRoots(frozenset):  # type: ignore[type-arg]
    """A blacklist of TLD roots that records every iteration over itself.

    Membership tests (``in``) are free; ``__iter__`` is what a per-call
    normalization pass needs, so counting it isolates exactly the work this
    issue removes from the per-entry path.
    """

    iterations = 0

    def __iter__(self) -> Iterator[str]:
        self.iterations += 1
        return super().__iter__()


class TestClassifierConsumesPreStrippedRoots:
    """``tld_wildcard_classify()``'s ``blacklist`` is pre-stripped TLD roots."""

    def test_blacklisted_root_forces_exact_data(self) -> None:
        """Before-state for the rows below: the root DOES decide the class."""
        no_blacklist = P.tld_wildcard_classify("example.co.uk", _rules(), set())
        assert no_blacklist == (P.DNSBL_CLASS_ZONE, "example.co.uk"), (
            f"expected {(P.DNSBL_CLASS_ZONE, 'example.co.uk')!r} without a blacklist, got {no_blacklist!r}"
        )
        blacklisted = P.tld_wildcard_classify("example.co.uk", _rules(), set(), blacklist={"uk"})
        assert blacklisted == (P.DNSBL_CLASS_DATA, "example.co.uk"), (
            f"expected {(P.DNSBL_CLASS_DATA, 'example.co.uk')!r} with root 'uk' blacklisted, got {blacklisted!r}"
        )

    def test_classifier_never_iterates_the_blacklist(self) -> None:
        """Per-call cost is O(name labels), never O(len(blacklist))."""
        roots = _CountingRoots({"uk"})
        domains = ("example.co.uk", "sub.example.co.uk", "example.com", "other.co.uk", "deep.sub.example.com")
        for domain in domains:
            P.tld_wildcard_classify(domain, _rules(), set(), blacklist=roots)
        # Read the counter BEFORE asserting: rendering the set iterates it.
        observed = roots.iterations
        assert observed == 0, (
            f"expected 0 iterations over the blacklist across {len(domains)} classifications, "
            f"got {observed} -- the blacklist is being re-normalized per call"
        )

    def test_blacklist_still_decides_while_never_iterated(self) -> None:
        """The cost contract must not be satisfied by ignoring the blacklist."""
        roots = _CountingRoots({"uk"})
        verdict = P.tld_wildcard_classify("example.co.uk", _rules(), set(), blacklist=roots)
        observed = roots.iterations
        assert verdict == (P.DNSBL_CLASS_DATA, "example.co.uk"), (
            f"expected {(P.DNSBL_CLASS_DATA, 'example.co.uk')!r} with root 'uk' blacklisted, got {verdict!r}"
        )
        assert observed == 0, f"expected 0 iterations, got {observed}"


def _run_build(
    lines: list[str],
    *,
    blacklist: list[str],
) -> P.BuildResult:
    """Drive ``build()`` over a synthetic single-feed manifest (issue #2371 idiom)."""
    raw_key = "feed.raw"
    manifest = {"feeds": [{"feed": "FEED", "group": "GRP", "log_flag": "1", "provenance": "feed", "raw": raw_key}]}
    config: dict[str, Any] = {
        "psl_rules": _rules(),
        "psl_wildcard_enabled": True,
        "psl_include_private": True,
        "tld_wildcard_blacklist": blacklist,
        "tld_wildcard_exclusion": [],
        "user_whitelist": [],
    }

    def reader(raw: str) -> list[str]:
        assert raw == raw_key
        return list(lines)

    return P.build(manifest, config, line_reader=reader)


class TestBuildNormalizesTheBlacklistOnce:
    """``build()`` hoists the blacklist out of its per-entry loop."""

    def test_one_shared_blacklist_object_for_every_entry(self, monkeypatch: Any) -> None:
        """Scenario: three feed entries, one blacklist.

        Given a build over three block entries
        When each reaches ``tld_wildcard_classify()``
        Then every call receives the SAME pre-derived roots object -- not a fresh
        set built per entry.
        """
        seen: list[Any] = []
        real = P.tld_wildcard_classify

        def recording(*a: Any, **k: Any) -> tuple[str, str]:
            seen.append(k.get("blacklist"))
            return real(*a, **k)

        monkeypatch.setattr(P, "tld_wildcard_classify", recording)
        _run_build(["a.example.com", "b.example.com", "c.example.com"], blacklist=[".uk", "test"])

        assert len(seen) == 3, f"expected 3 classifications, got {len(seen)}"
        distinct = {id(entry) for entry in seen}
        assert len(distinct) == 1, (
            f"expected 1 shared blacklist object across {len(seen)} entries, got {len(distinct)} distinct objects "
            "-- the loop-invariant blacklist is being rebuilt per feed entry"
        )

    def test_dotted_user_blacklist_still_blocks_at_the_root(self) -> None:
        """End-to-end behaviour is unchanged by moving the strip to the caller."""
        without = _run_build(["example.co.uk"], blacklist=[])
        assert "example.co.uk" in without.zone_db, (
            f"expected a wildcard ZONE without a blacklist, zone_db={sorted(without.zone_db)!r} "
            f"data_db={sorted(without.data_db)!r}"
        )
        with_root = _run_build(["example.co.uk"], blacklist=[".uk"])
        assert "example.co.uk" in with_root.data_db, (
            f"expected an exact DATA block with '.uk' blacklisted, data_db={sorted(with_root.data_db)!r} "
            f"zone_db={sorted(with_root.zone_db)!r}"
        )
        assert "uk" in with_root.zone_db, (
            f"expected the synthetic whole-TLD zone for 'uk', zone_db={sorted(with_root.zone_db)!r}"
        )
