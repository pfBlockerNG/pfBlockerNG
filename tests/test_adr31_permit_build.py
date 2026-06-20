"""ADR-31 Phase 2 — Pin the permit-mode build branch (band-2 allow from DNSWL feeds).

WHY THIS FILE EXISTS
--------------------
Phase 2 adds a ``mode='permit'`` branch to ``build()``/``dnsbl_build_from_manifest()``.
A manifest feed entry with ``mode='permit'`` routes every host line of that raw feed
into ``whiteDB`` at **band 2** (``PRIO_FEED_ALLOW``, wildcard=True) — the same store
and shape as an inline ABP ``@@||host^`` allow.  ``mode`` absent or ``'deny'`` builds
byte-identically to today (the Phase-1 oracle guards this invariant).

CONTRACTS PINNED
----------------
  1. **Block-only feed ⇒ blocked; also on permit feed ⇒ resolves.**
     BEFORE state (block-only) is asserted first so green proves the permit feed
     CAUSED the change — not a pre-existing allow.
  2. **Manual suppression (band 6) is sovereign over a permit allow (band 2).**
     A domain blocked by a block feed AND listed on a permit feed STILL resolves;
     but a manual whitelist (band 6) is NOT downgraded to band 2 by a permit entry.
  3. **Subdomain coverage:** a permit entry ``example.com`` covers ``sub.example.com``
     (wildcard=True, matching ``@@||example.com^``).
  4. **Non-listed host unaffected** — a domain in neither feed resolves normally.
  5. **REGRESSION: the Phase-1 oracle still passes unchanged** — manifests with NO
     permit feed build byte-identically (the pytest run covers both files).

HARNESS SHAPE
-------------
Same pattern as ``tests/test_adr31_precedence_oracle.py``:
  * synthetic in-memory manifests (two feeds: a block ABP feed + a permit plain feed);
  * ``build()`` called directly (no filesystem, no Unbound globals);
  * ``evaluate_domain()`` for verdict assertions.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pfb_unbound as P

# --------------------------------------------------------------------------- #
# Shared build / evaluate helpers (mirrors test_adr31_precedence_oracle.py)
# --------------------------------------------------------------------------- #


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
        "python_tld": False,
        "python_tlds": [],
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


# Raw feed key constants used across tests.
_RAW_BLOCK = "block.raw"
_RAW_PERMIT = "permit.raw"

_BASE_CONFIG: dict[str, Any] = {
    "tld_master": [],
    "tld_blacklist": [],
    "tld_exclusion": [],
    "user_whitelist": [],
    "top1m_list": [],
}


def _build_block_only(block_lines: list[str]) -> P.BuildResult:
    """Build with a single ABP block feed and NO permit feed."""
    manifest: dict[str, Any] = {
        "feeds": [
            {
                "feed": "BlockFeed",
                "group": "TestBlock",
                "format_hint": "abp",
                "log_flag": "1",
                "raw": _RAW_BLOCK,
            }
        ]
    }

    def reader(raw: str) -> list[str]:
        assert raw == _RAW_BLOCK
        return list(block_lines)

    return P.build(manifest, _BASE_CONFIG, line_reader=reader)


def _build_block_and_permit(
    block_lines: list[str],
    permit_lines: list[str],
    *,
    user_whitelist: list[str] | None = None,
) -> P.BuildResult:
    """Build with an ABP block feed AND a permit-mode plain feed.

    ``permit_lines`` are loaded by a ``mode='permit'`` feed entry (format_hint='plain')
    so that plain ``host.example.com`` lines produce band-2 wildcard allows.
    ``block_lines`` remain in an ABP block feed (``||domain^`` anchors → band-1 blocks).
    """
    manifest: dict[str, Any] = {
        "feeds": [
            {
                "feed": "BlockFeed",
                "group": "TestBlock",
                "format_hint": "abp",
                "log_flag": "1",
                "raw": _RAW_BLOCK,
            },
            {
                "feed": "PermitFeed",
                "group": "TestPermit",
                "format_hint": "plain",
                "log_flag": "1",
                "mode": "permit",
                "raw": _RAW_PERMIT,
            },
        ]
    }
    config: dict[str, Any] = {
        **_BASE_CONFIG,
        "user_whitelist": user_whitelist or [],
    }
    lines_map = {
        _RAW_BLOCK: block_lines,
        _RAW_PERMIT: permit_lines,
    }

    def reader(raw: str) -> list[str]:
        return list(lines_map[raw])

    return P.build(manifest, config, line_reader=reader)


# --------------------------------------------------------------------------- #
# Contract 1 — A permit feed's host overrides a block feed (band 2 > band 1)
# --------------------------------------------------------------------------- #


class TestPermitFeedOverridesBlockFeed:
    """Pin: a ``mode='permit'`` feed entry routes hosts into whiteDB at band 2;
    those hosts resolve even when a block feed lists them.

    BEFORE state (block-only ⇒ blocked) is asserted before the AFTER state
    (block + permit ⇒ resolves) so green proves the permit feed CAUSED the change.
    """

    def test_block_only_domain_is_blocked_before_permit(self) -> None:
        """Scenario: a domain listed on the block feed is blocked when no permit feed exists.

        Given: a block feed listing ``blocked.permit.test.example.com``.
        When: ``blocked.permit.test.example.com`` is queried.
        Then: the domain IS blocked (is_found True, in_whitelist False).

        Pins the BEFORE state used by the next test.
        """
        # Given
        result = _build_block_only(["||blocked.permit.test.example.com^"])

        # When / Then — block-only feed ⇒ blocked
        dec = _decide(result, "blocked.permit.test.example.com")
        assert dec.is_found is True, "expected is_found (domain on block feed)"
        assert dec.in_whitelist is False, "expected no allow override (block-only, no permit feed)"

    def test_permit_feed_resolves_blocked_domain(self) -> None:
        """Scenario: adding a permit feed listing the host causes it to resolve.

        Given: a block feed listing ``blocked.permit.test.example.com``
            ⇒ domain IS blocked (verified by the BEFORE test above).
        When: a permit feed also lists ``blocked.permit.test.example.com``.
        Then: the domain RESOLVES (band 2 >= band 1).

        Exercises the new permit-mode branch in ``build()``: host enters whiteDB
        at PRIO_FEED_ALLOW (band 2), wildcard=True.
        """
        # Given (BEFORE): block-only — blocked.
        before = _build_block_only(["||blocked.permit.test.example.com^"])
        assert _is_blocked(before, "blocked.permit.test.example.com"), "BEFORE: must be blocked"

        # When: add permit feed listing the same host.
        after = _build_block_and_permit(
            ["||blocked.permit.test.example.com^"],
            ["blocked.permit.test.example.com"],
        )

        # Then: the domain resolves.
        assert _resolves(after, "blocked.permit.test.example.com"), (
            "AFTER: permit feed (band 2) must resolve a block feed domain (band 1)"
        )

        # Verify the allow is in whiteDB at band 2 (wildcard=True).
        entry = after.white_db.get("blocked.permit.test.example.com")
        assert entry is not None, "permit host must be in whiteDB"
        assert entry["band"] == P.PRIO_FEED_ALLOW, "permit entry must carry PRIO_FEED_ALLOW (band 2)"
        assert entry["wildcard"] is True, "permit entry must be wildcard=True (subdomain-covering)"

    def test_permit_feed_host_has_feed_group_index(self) -> None:
        """Scenario: a permit feed's host entry carries provenance via feed_group_index_db.

        Given: a permit feed 'PermitFeed' / group 'TestPermit' listing ``tagged.example.com``.
        When: the build completes.
        Then: the whiteDB entry for ``tagged.example.com`` has an ``index`` key
            that maps back to the feed/group in ``feed_group_index_db``.

        Pins the provenance-tagging convention: permit entries are attributed to their
        feed via the same ``index_for(feed, group)`` mechanism as block entries.
        """
        result = _build_block_and_permit([], ["tagged.example.com"])

        entry = result.white_db.get("tagged.example.com")
        assert entry is not None, "permit host must be in whiteDB"
        idx = entry.get("index")
        assert idx is not None, "permit entry must carry an 'index' for provenance"
        feed_info = result.feed_group_index_db.get(idx)
        assert feed_info is not None, "index must map to a feed_group_index_db entry"
        assert feed_info["feed"] == "PermitFeed", "provenance feed must be 'PermitFeed'"
        assert feed_info["group"] == "TestPermit", "provenance group must be 'TestPermit'"


# --------------------------------------------------------------------------- #
# Contract 2 — Manual suppression (band 6) is sovereign over permit allow (band 2)
# --------------------------------------------------------------------------- #


class TestManualSovereignOverPermit:
    """Pin: the manual whitelist (band 6) is NOT downgraded by a permit feed (band 2).
    A domain blocked by a block feed AND listed on a permit feed resolves (band 2 > 1);
    but when the manual whitelist entry exists, it stays at band 6, not band 2.
    """

    def test_permit_allow_resolves_block_before_manual(self) -> None:
        """Scenario: a permit feed resolves a blocked domain (the BEFORE state for the
        subsequent manual-sovereignty test).

        Given: a block feed listing ``overlap.sovereign.example.com`` + a permit feed
            listing the same host.
        When: the domain is queried.
        Then: it RESOLVES (band 2 > 1), whiteDB entry at band 2.

        Pins the permit-resolves BEFORE state.
        """
        result = _build_block_and_permit(
            ["||overlap.sovereign.example.com^"],
            ["overlap.sovereign.example.com"],
        )
        assert _resolves(result, "overlap.sovereign.example.com"), (
            "BEFORE: permit feed (band 2) must resolve a block feed domain"
        )
        entry = result.white_db.get("overlap.sovereign.example.com")
        assert entry is not None
        assert entry["band"] == P.PRIO_FEED_ALLOW, "entry must be band 2 when no manual whitelist"

    def test_manual_whitelist_not_downgraded_by_permit(self) -> None:
        """Scenario: a manual whitelist entry (band 6) is NOT narrowed to band 2 by a
        concurrent permit feed entry for the same domain.

        Given: block feed + permit feed ⇒ whiteDB at band 2 (verified above as BEFORE).
        When: a manual whitelist entry is also present for the same domain.
        Then: the whiteDB entry stays at band 6 — the permit feed does NOT downgrade it
            (monotonic-widen rule: whiteDB only widens, never narrows).
        """
        # Given (BEFORE): permit feed alone → band 2.
        before = _build_block_and_permit(
            ["||overlap.sovereign.example.com^"],
            ["overlap.sovereign.example.com"],
        )
        assert before.white_db.get("overlap.sovereign.example.com", {}).get("band") == P.PRIO_FEED_ALLOW

        # When: also add manual whitelist.
        after = _build_block_and_permit(
            ["||overlap.sovereign.example.com^"],
            ["overlap.sovereign.example.com"],
            user_whitelist=["overlap.sovereign.example.com"],
        )

        # Then: entry stays at band 6 (manual whitelist wins the merge).
        entry = after.white_db.get("overlap.sovereign.example.com")
        assert entry is not None
        assert entry["band"] == P.PRIO_USER_ALLOW, (
            "manual whitelist (band 6) must not be downgraded by permit allow (band 2)"
        )
        assert _resolves(after, "overlap.sovereign.example.com"), "domain must still resolve"


# --------------------------------------------------------------------------- #
# Contract 3 — Subdomain coverage: permit entry covers subdomains (wildcard=True)
# --------------------------------------------------------------------------- #


class TestPermitSubdomainCoverage:
    """Pin: a permit feed entry for ``example.com`` covers ``sub.example.com``.

    The whiteDB entry is stored with ``wildcard=True`` (same as ``@@||host^``);
    the existing suffix-walk in ``evaluate_domain`` then covers subdomains.
    """

    def test_permit_subdomain_before_state(self) -> None:
        """Scenario: a subdomain of a permit host is blocked before the permit feed exists.

        Given: a block feed listing ``sub.permitdomain.example.com``.
        When: ``sub.permitdomain.example.com`` is queried.
        Then: the subdomain IS blocked.

        Pins the BEFORE state for the subdomain-coverage test.
        """
        result = _build_block_only(["||sub.permitdomain.example.com^"])
        assert _is_blocked(result, "sub.permitdomain.example.com"), (
            "BEFORE: sub.permitdomain.example.com must be blocked"
        )

    def test_permit_entry_covers_subdomain(self) -> None:
        """Scenario: a permit entry for a parent domain covers its subdomains.

        Given: a block feed listing ``sub.permitdomain.example.com`` ⇒ blocked (BEFORE).
        When: a permit feed lists ``permitdomain.example.com`` (the parent domain).
        Then: both ``permitdomain.example.com`` AND ``sub.permitdomain.example.com``
            resolve — the wildcard=True entry covers subdomains via the suffix walk.

        Exercises the wildcard=True contract for permit entries (ADR-31 §2.2.4).
        """
        # Given (BEFORE): sub is blocked, no permit feed.
        before = _build_block_only(["||sub.permitdomain.example.com^"])
        assert _is_blocked(before, "sub.permitdomain.example.com"), (
            "BEFORE: sub.permitdomain.example.com must be blocked"
        )

        # When: permit feed lists the parent domain.
        after = _build_block_and_permit(
            ["||sub.permitdomain.example.com^", "||permitdomain.example.com^"],
            ["permitdomain.example.com"],
        )

        # Then: parent resolves and wildcard covers the sub.
        assert _resolves(after, "permitdomain.example.com"), "permit entry must allow permitdomain.example.com"
        assert _resolves(after, "sub.permitdomain.example.com"), (
            "permit wildcard must cover sub.permitdomain.example.com"
        )

        # Confirm the whiteDB entry has wildcard=True.
        entry = after.white_db.get("permitdomain.example.com")
        assert entry is not None, "permit parent must be in whiteDB"
        assert entry["wildcard"] is True, "permit entry must be wildcard=True"
        assert entry["band"] == P.PRIO_FEED_ALLOW, "permit entry must be at band 2"


# --------------------------------------------------------------------------- #
# Contract 4 — Non-listed host unaffected by permit feed
# --------------------------------------------------------------------------- #


class TestNonListedUnaffectedByPermit:
    """Pin: a domain in neither the block feed nor the permit feed is entirely unaffected.

    A permit feed must not accidentally block or alter the resolution of domains it
    doesn't mention, and must not interfere with other permit entries.
    """

    def test_non_listed_host_still_resolves(self) -> None:
        """Scenario: an unlisted domain resolves normally when permit + block feeds are present.

        Given: a block feed listing ``blocked.example.com`` and a permit feed listing
            ``permitted.example.com``.
        When: ``unlisted.net`` is queried.
        Then: ``unlisted.net`` is NOT blocked (is_found False) — the permit feed has
            no bearing on it.
        """
        result = _build_block_and_permit(
            ["||blocked.example.com^"],
            ["permitted.example.com"],
        )

        # Sanity checks: the listed domains behave as expected.
        assert _is_blocked(result, "blocked.example.com"), "sanity: blocked.example.com must be blocked"
        assert _resolves(result, "permitted.example.com"), "sanity: permitted.example.com must resolve"

        # Unlisted domain must be unaffected.
        dec = _decide(result, "unlisted.net")
        assert dec.is_found is False, "unlisted domain must not appear in any block DB"
        assert _resolves(result, "unlisted.net"), "unlisted domain must resolve"


# --------------------------------------------------------------------------- #
# Contract 5 — Absent / deny mode: byte-identical build (Phase-1 oracle regression)
# --------------------------------------------------------------------------- #


class TestDenyModeByteIdentical:
    """Pin: a manifest with no permit feed (or explicit mode='deny') builds
    byte-identically to the pre-ADR-31 Phase-1 baseline.

    This test is the local regression gate — the full Phase-1 oracle is exercised
    by running the entire test suite (both files in one ``python -m pytest`` run).
    """

    def test_no_permit_feed_builds_byte_identical(self) -> None:
        """Scenario: a manifest with no mode field builds identically to the Phase-1 oracle.

        Given: a manifest with a block ABP feed listing ``identical.example.com``
            and NO permit feed entry.
        When: ``build()`` is called.
        Then: ``identical.example.com`` is in ``data_db``/``zone_db`` at band 1 (PRIO_FEED_BLOCK),
            ``white_db`` is empty (no allow entries), and the domain is blocked.

        Pins that absent ``mode`` does NOT add any allow entries.
        """
        result = _build_block_only(["||identical.example.com^"])

        assert _is_blocked(result, "identical.example.com"), "block-only feed must block the domain"
        assert not result.white_db, "white_db must be empty with no permit feed"
        block_entry = result.data_db.get("identical.example.com") or result.zone_db.get("identical.example.com")
        assert block_entry is not None, "domain must be in data_db or zone_db"
        assert block_entry["band"] == P.PRIO_FEED_BLOCK, "block entry must be band 1 (PRIO_FEED_BLOCK)"

    def test_explicit_deny_mode_unchanged(self) -> None:
        """Scenario: an explicit ``mode='deny'`` feed entry behaves identically to absent mode.

        Given: a manifest with a block ABP feed AND a second feed entry with ``mode='deny'``
            listing the same domain.
        When: ``build()`` is called.
        Then: the domain is blocked (deny path used), NOT in white_db.

        Pins that ``mode='deny'`` is the same as absent mode — no allow side-effect.
        """
        manifest: dict[str, Any] = {
            "feeds": [
                {
                    "feed": "BlockFeed",
                    "group": "TestBlock",
                    "format_hint": "abp",
                    "log_flag": "1",
                    "raw": _RAW_BLOCK,
                },
                {
                    "feed": "DenyFeed",
                    "group": "TestDeny",
                    "format_hint": "plain",
                    "log_flag": "1",
                    "mode": "deny",  # explicit deny — must be block-only
                    "raw": _RAW_PERMIT,
                },
            ]
        }
        lines_map = {
            _RAW_BLOCK: ["||explicit.deny.example.com^"],
            _RAW_PERMIT: ["explicit.deny.example.com"],  # deny feed — must block, not allow
        }

        def reader(raw: str) -> list[str]:
            return list(lines_map[raw])

        result = P.build(manifest, _BASE_CONFIG, line_reader=reader)

        assert _is_blocked(result, "explicit.deny.example.com"), "mode='deny' feed must produce a block, not an allow"
        assert "explicit.deny.example.com" not in result.white_db, "mode='deny' entry must NOT appear in white_db"
