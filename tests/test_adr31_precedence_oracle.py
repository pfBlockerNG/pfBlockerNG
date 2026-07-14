"""ADR-31 Phase 1 — Pin the DNSBL feed-allow precedence contract (oracle).

WHY THIS FILE EXISTS
--------------------
ADR-31 adds subscribable DNSWL (allow-list) feeds, routing each host into
``whiteDB`` at **band 2** (feed-allow) — the same band that an inline ABP
``@@||host^`` rule already occupies.  Before writing that build branch (Phase 2),
we pin the band-2 semantics that already exist as a regression net.

The three contracts this oracle guards:

  1. **Band 2 beats band 1 (feed allow overrides feed block).**
     An ABP ``@@||host^`` allow (band 2) causes a blocked domain to resolve,
     even when a block feed lists it (band 1).  Pinned both ways: block-only
     ⇒ blocked; block + allow ⇒ resolves.

  2. **Operator sovereignty (band 6 / band 5 still win over band 2).**
     The manual suppression list (band 6) resolves a blocked domain even
     without any permit feed.  A ``$important`` user block (band 5) is NOT
     overridden by a feed allow (band 2); the block still wins.

  3. **Non-listed domains are unaffected** — neither block feeds nor allow
     entries disturb a domain that appears in neither.

These tests MUST pass on untouched ``devel`` production code.  Phase 2 must
leave them green after adding the ``permit``-mode build branch.

HARNESS SHAPE
-------------
All tests drive ``pfb_unbound.build()`` via a synthetic in-memory manifest
(the same pattern as ``tests/test_adr21_abp_per_line.py``), then call
``pfb_unbound.evaluate_domain()`` over the resulting structures — the same
end-to-end path the live matcher uses.  No Unbound symbols; CI-runnable.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pfb_unbound as P

# --------------------------------------------------------------------------- #
# Shared build / evaluate helpers
# --------------------------------------------------------------------------- #


def _run_build(
    block_lines: list[str],
    allow_lines: list[str] | None = None,
    *,
    user_whitelist: list[str] | None = None,
) -> P.BuildResult:
    """Build a BlockResult from synthetic in-memory feeds.

    * ``block_lines`` are written into a block feed; each ``||domain^`` anchor
      is routed by the permanent per-line capture guard (#1083 P4) to produce
      band-1 blocks. (The ``@@||…`` allow lines in ``allow_lines`` are parsed
      the same way — exactly as a real block feed carrying inline
      exceptions would produce.)
    * ``allow_lines`` are written into the SAME block feed after the block
      lines.  ``@@||domain^`` entries go into ``whiteDB`` at band 2 via the
      Stage-B reconcile.
    * ``user_whitelist`` populates ``config.user_whitelist`` — these become
      band-6 entries in ``whiteDB`` (sovereign manual allow).
    """
    combined: list[str] = list(block_lines)
    if allow_lines:
        combined.extend(allow_lines)

    raw_key = "block.raw"
    manifest: dict[str, Any] = {
        "feeds": [
            {
                "feed": "BlockFeed",
                "group": "TestBlock",
                "log_flag": "1",
                "raw": raw_key,
            }
        ]
    }
    config: dict[str, Any] = {
        "tld_wildcard_master": [],
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": user_whitelist or [],
        "top1m_list": [],
    }

    def reader(raw: str) -> list[str]:
        assert raw == raw_key
        return list(combined)

    return P.build(manifest, config, line_reader=reader)


def _cfg_for(result: P.BuildResult) -> dict[str, Any]:
    """Build the ``cfg`` dict ``evaluate_domain`` reads, from a BuildResult."""
    return {
        "python_blocking": True,
        "dataDB": bool(result.data_db),
        "zoneDB": bool(result.zone_db),
        "whiteDB": bool(result.white_db),
        "allowRegexDB": bool(result.allow_regex_db),
        "regexDB": bool(result.regex_db),
        "important_rules": result.important_rules,
        "tld_allow": False,
        "tld_allow_list": [],
        "python_tld_seg": 2,
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "python_idn": False,
        "hstsDB": False,
        "hsts_tlds": (),
    }


def _containers_for(result: P.BuildResult) -> dict[str, Any]:
    """Build the ``containers`` dict ``evaluate_domain`` reads, from a BuildResult."""
    return {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": result.regex_db or defaultdict(str),
        "allowRegexDB": result.allow_regex_db or defaultdict(str),
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {},
    }


def _decide(result: P.BuildResult, domain: str) -> P.DnsblDecision:
    """Run the production ``evaluate_domain`` for ``domain`` over ``result``."""
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    return P.evaluate_domain(
        domain,
        domain,
        tld,
        False,
        _cfg_for(result),
        _containers_for(result),
    )


def _is_blocked(result: P.BuildResult, domain: str) -> bool:
    """True iff ``evaluate_domain`` reports ``is_found=True`` and no allow wins."""
    dec = _decide(result, domain)
    return dec.is_found and not dec.in_whitelist


def _resolves(result: P.BuildResult, domain: str) -> bool:
    """True iff ``evaluate_domain`` reports the domain resolves (not blocked)."""
    dec = _decide(result, domain)
    return not dec.is_found or dec.in_whitelist


# --------------------------------------------------------------------------- #
# Contract 1 — Band 2 feed allow overrides band 1 feed block
# --------------------------------------------------------------------------- #


class TestFeedAllowBeatsFeedBlock:
    """Pin: a feed ``@@||host^`` allow (band 2) resolves a domain a block feed lists
    (band 1).  Asserts the before-state (block-only ⇒ blocked) before the after-state
    (block + allow ⇒ resolves) so green proves the allow CAUSED the change.
    """

    def test_block_only_domain_is_blocked(self) -> None:
        """Scenario: a domain on the block feed is blocked when no allow is present.

        Given: a block feed listing ``blocked.example.com``.
        When: ``blocked.example.com`` is queried.
        Then: the domain IS blocked (is_found True, in_whitelist False).

        Pins band 1 (feed block) semantics — the BEFORE state for the next test.
        """
        # Given
        result = _run_build(["||blocked.example.com^"])

        # When / Then — block-only feed ⇒ blocked
        dec = _decide(result, "blocked.example.com")
        assert dec.is_found is True, "expected is_found (domain on block feed)"
        assert dec.in_whitelist is False, "expected no allow override (block-only)"

    def test_abp_allow_resolves_blocked_domain(self) -> None:
        """Scenario: adding a feed ``@@||host^`` allow causes the blocked domain to resolve.

        Given: a block feed listing ``blocked.example.com`` ⇒ domain IS blocked
            (verified by test_block_only_domain_is_blocked above — the BEFORE state).
        When: the same feed also carries ``@@||blocked.example.com^`` (band-2 allow).
        Then: ``blocked.example.com`` RESOLVES (band 2 >= band 1).

        Exercises ``_resolve_numeric_allow`` (pfb_unbound.py:5405) with
        ``allow_band=2 >= block_band=1`` ⇒ True.
        """
        # Given (BEFORE): block-only — blocked.
        before = _run_build(["||blocked.example.com^"])
        assert _is_blocked(before, "blocked.example.com"), "BEFORE: must be blocked"

        # When: add the ABP allow anchor.
        after = _run_build(
            ["||blocked.example.com^"],
            ["@@||blocked.example.com^"],
        )

        # Then: the domain now resolves.
        assert _resolves(after, "blocked.example.com"), "AFTER: feed allow (band 2) must resolve a feed block (band 1)"

        # Verify the allow is in whiteDB at band 2 (the store Phase 2 will reuse).
        assert "blocked.example.com" in after.white_db, "allow entry must be in whiteDB"
        assert after.white_db["blocked.example.com"]["band"] == P.PRIO_FEED_ALLOW, (
            "allow entry must carry PRIO_FEED_ALLOW (band 2)"
        )

    def test_allow_domain_subdomain_coverage(self) -> None:
        """Scenario: a feed ``@@||host^`` allow covers subdomains of the host.

        Given: a block feed listing ``sub.example.com`` + a parent zone block
            ``example.com`` ⇒ both are blocked.
        When: ``@@||example.com^`` allow is added.
        Then: both ``example.com`` and ``sub.example.com`` resolve (wildcard=True
            in whiteDB means the suffix walk covers subdomains).

        Pins subdomain-covering semantics (ADR-31 §2.2.4).
        """
        # Given (BEFORE): block the parent zone and a subdomain.
        before = _run_build(["||example.com^", "||sub.example.com^"])
        # The parent zone block covers subdomains; sub. is also directly blocked.
        assert _is_blocked(before, "example.com"), "BEFORE: example.com must be blocked"

        # When: allow the parent zone — should cover subdomains.
        after = _run_build(
            ["||example.com^", "||sub.example.com^"],
            ["@@||example.com^"],
        )

        # Then: the parent resolves; the allow's wildcard covers the sub.
        assert _resolves(after, "example.com"), "@@||example.com^ must allow example.com"
        assert _resolves(after, "sub.example.com"), "@@||example.com^ wildcard must cover sub.example.com"

        # The whiteDB entry must be wildcard-covering.
        entry = after.white_db.get("example.com")
        assert entry is not None, "example.com must be in whiteDB"
        assert entry["wildcard"] is True, "whiteDB entry must be wildcard=True"
        assert entry["band"] == P.PRIO_FEED_ALLOW, "band must be PRIO_FEED_ALLOW (2)"


# --------------------------------------------------------------------------- #
# Contract 2 — Operator sovereignty (band 6 and band 5 win over band 2)
# --------------------------------------------------------------------------- #


class TestOperatorSovereignty:
    """Pin: the manual suppression (band 6) and user $important block (band 5)
    take precedence over a feed allow (band 2).  The operator always wins.
    """

    def test_manual_whitelist_resolves_blocked_domain(self) -> None:
        """Scenario: a manual suppression entry (band 6) resolves a blocked domain.

        Given: a block feed listing ``blocked.manual.com`` with no allow feed
            ⇒ the domain IS blocked (the BEFORE state).
        When: the operator's manual whitelist includes ``blocked.manual.com``
            (loaded into whiteDB at band 6 via ``user_whitelist``).
        Then: ``blocked.manual.com`` RESOLVES (band 6 >= band 1).

        Exercises ``whitelist_lookup_band`` (pfb_unbound.py:5380) returning 6
        via the manual suppression path, and ``_resolve_numeric_allow`` returning
        True (6 >= 1).  Band 6 = PRIO_USER_ALLOW (sovereign).
        """
        # Given (BEFORE): block-only, no whitelist — blocked.
        before = _run_build(["||blocked.manual.com^"])
        assert _is_blocked(before, "blocked.manual.com"), "BEFORE: must be blocked"

        # When: add to manual whitelist (band 6 — sovereign over all feed rules).
        after = _run_build(
            ["||blocked.manual.com^"],
            user_whitelist=["blocked.manual.com"],
        )

        # Then: manual whitelist wins.
        dec = _decide(after, "blocked.manual.com")
        assert dec.in_whitelist is True, "manual whitelist (band 6) must win"
        assert _resolves(after, "blocked.manual.com"), "manual whitelist must resolve the domain"

        # The manual whitelist entry must be at band 6 in whiteDB.
        entry = after.white_db.get("blocked.manual.com")
        assert entry is not None, "manual whitelist entry must be in whiteDB"
        assert entry["band"] == P.PRIO_USER_ALLOW, "manual whitelist entry must carry PRIO_USER_ALLOW (band 6)"

    def test_manual_whitelist_sovereign_over_feed_allow(self) -> None:
        """Scenario: a manual whitelist entry (band 6) is NOT downgraded by a
        concurrent feed allow (band 2) on the same domain.

        Given: a block feed + a feed ``@@||domain^`` allow (band 2) already resolves
            the domain (verified as the BEFORE state).
        When: a manual whitelist entry (band 6) is also present for the same domain.
        Then: the whiteDB entry stays at band 6 — the manual entry is NOT narrowed
            down to band 2 (the monotonic widen rule at pfb_unbound.py:4709-4726).

        Pins the non-downgrade invariant: whiteDB only widens, never narrows.
        """
        # Given (BEFORE): feed allow (band 2) already resolves the domain.
        before_allow = _run_build(
            ["||overlap.com^"],
            ["@@||overlap.com^"],
        )
        assert _resolves(before_allow, "overlap.com"), "BEFORE: feed allow must resolve"
        assert before_allow.white_db.get("overlap.com", {}).get("band") == P.PRIO_FEED_ALLOW

        # When: add a manual whitelist entry for the same domain.
        after = _run_build(
            ["||overlap.com^"],
            ["@@||overlap.com^"],
            user_whitelist=["overlap.com"],
        )

        # Then: the entry stays at band 6 (the manual whitelist wins the merge).
        entry = after.white_db.get("overlap.com")
        assert entry is not None
        assert entry["band"] == P.PRIO_USER_ALLOW, (
            "manual whitelist (band 6) must not be downgraded by feed allow (band 2)"
        )

    def test_user_important_block_beats_feed_allow(self) -> None:
        """Scenario: a Custom_List (user-sovereign) ``$important`` block (band 5)
        is NOT overridden by a feed ``@@||…^`` allow (band 2).

        A DNSBL Group Custom_List is loaded with provenance='user', which bands
        its ABP block entries at ``PRIO_USER_BLOCK`` (band 5) instead of the
        normal feed band 1.  A feed allow at band 2 CANNOT override band 5.

        Given: a Custom_List block at band 5 for ``user-blocked.com`` — it IS blocked.
        When: a separate block feed ALSO lists the domain and carries a feed allow
            (band 2) via ``@@||user-blocked.com^``.
        Then: the domain stays BLOCKED — band 5 > band 2.

        Exercises ``_resolve_numeric_allow`` (pfb_unbound.py:5405): 2 >= 5 is False.
        Band 5 = PRIO_USER_BLOCK.

        NOTE: to produce a band-5 block we need a second feed with provenance='user'.
        The band-2 allow comes from an abp feed block.  We drive build() twice with
        two separate manifests merged: user-block feed + allow feed.
        """
        # To exercise band-5 we need two feeds: one user-provenance block feed and
        # one normal (feed-provenance) abp feed with the @@ allow.  We combine them
        # in a single build() call with two manifest entries.
        raw_user_block = "user_block.raw"
        raw_feed_allow = "feed_allow.raw"

        manifest: dict[str, Any] = {
            "feeds": [
                {
                    "feed": "CustomList",
                    "group": "UserGroup",
                    "log_flag": "1",
                    "provenance": "user",  # ← band-5 USER block
                    "raw": raw_user_block,
                },
                {
                    "feed": "BlockAndAllow",
                    "group": "FeedGroup",
                    "log_flag": "1",
                    "raw": raw_feed_allow,
                },
            ]
        }
        config: dict[str, Any] = {
            "tld_wildcard_master": [],
            "tld_wildcard_blacklist": [],
            "tld_wildcard_exclusion": [],
            "user_whitelist": [],
            "top1m_list": [],
        }

        lines_map = {
            raw_user_block: ["||user-blocked.com^"],  # band 5
            raw_feed_allow: ["@@||user-blocked.com^"],  # band 2 allow
        }

        def reader(raw: str) -> list[str]:
            return list(lines_map[raw])

        # Given (BEFORE): user block alone — domain IS blocked at band 5.
        manifest_user_only: dict[str, Any] = {"feeds": [manifest["feeds"][0]]}

        def reader_user_only(raw: str) -> list[str]:
            assert raw == raw_user_block
            return lines_map[raw_user_block]

        before = P.build(manifest_user_only, config, line_reader=reader_user_only)
        assert _is_blocked(before, "user-blocked.com"), "BEFORE: user Custom_List block must block the domain"
        block_payload = before.data_db.get("user-blocked.com") or before.zone_db.get("user-blocked.com")
        assert block_payload is not None
        assert block_payload["band"] == P.PRIO_USER_BLOCK, "Custom_List block must be band 5 (PRIO_USER_BLOCK)"

        # When: add the feed allow (band 2).
        after = P.build(manifest, config, line_reader=reader)

        # Then: band 5 > band 2 — the domain stays BLOCKED.
        dec = _decide(after, "user-blocked.com")
        assert dec.is_found is True, "domain must still be found as blocked"
        assert dec.in_whitelist is False, "feed allow (band 2) must NOT override user block (band 5)"
        assert _is_blocked(after, "user-blocked.com"), "band 5 user block must survive a band-2 feed allow"


# --------------------------------------------------------------------------- #
# Contract 3 — Non-listed domains are unaffected
# --------------------------------------------------------------------------- #


class TestNonListedUnaffected:
    """Pin: a domain not present in any block or allow feed is unaffected — it
    resolves normally (is_found False) regardless of what other domains are listed.
    """

    def test_unlisted_domain_not_blocked(self) -> None:
        """Scenario: an unlisted domain resolves even when other domains are blocked.

        Given: a block feed listing ``blocked.com`` and a feed allow for
            ``allowed.com``.
        When: ``unlisted.org`` is queried.
        Then: ``unlisted.org`` is NOT blocked (is_found False).

        Pins that the block and allow structures have zero interference with an
        unrelated domain.
        """
        result = _run_build(
            ["||blocked.com^"],
            ["@@||allowed.com^"],
        )

        # Sanity: block and allow entries are present for the listed domains.
        assert _is_blocked(result, "blocked.com"), "sanity: blocked.com must be blocked"
        assert _resolves(result, "allowed.com"), "sanity: allowed.com must resolve"

        # The unlisted domain must be untouched.
        dec = _decide(result, "unlisted.org")
        assert dec.is_found is False, "unlisted domain must not appear in any block DB"
        assert _resolves(result, "unlisted.org"), "unlisted domain must resolve"

    def test_unlisted_domain_unaffected_by_manual_whitelist(self) -> None:
        """Scenario: an unlisted domain is unaffected by the manual whitelist.

        Given: the manual whitelist contains ``whitelisted.com`` and a block feed
            lists ``blocked.com``.
        When: ``third.net`` is queried.
        Then: ``third.net`` is NOT blocked (it is not on the block feed and the
            whitelist entry for a different domain has no bearing on it).
        """
        result = _run_build(
            ["||blocked.com^"],
            user_whitelist=["whitelisted.com"],
        )

        dec = _decide(result, "third.net")
        assert dec.is_found is False, "third.net must not be found in any block DB"

    def test_allow_feed_does_not_create_block_for_unlisted(self) -> None:
        """Scenario: adding a feed allow does not accidentally BLOCK an unlisted domain.

        Given: a block feed + a feed allow for ``allowed.com``.
        When: ``other.net`` (in neither feed) is queried.
        Then: ``other.net`` is NOT blocked — the allow entries in whiteDB are
            irrelevant to a domain that was never found in the block DBs.

        Pins that whiteDB entries only affect domains that hit a block; they cannot
        create a block where none exists.
        """
        result = _run_build(
            ["||blocked.com^"],
            ["@@||allowed.com^"],
        )

        assert _resolves(result, "other.net"), "an unlisted domain must resolve regardless of whiteDB contents"
