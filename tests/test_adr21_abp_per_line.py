"""ADR-21 Phase 1 -- per-line ABP detection in ``build()``.

WHAT THIS PINS
--------------
``build()`` routes every raw line by its OWN shape, not by any feed-level tag
(format_hint's whole-feed dispatch retired #1083 P4 -- see the ADR-62 amendment):
a line the capture guard (``_dnsbl_is_abp_rule_line()``) recognises as ``||``/
``@@||``/element-hiding/regex-shaped is routed to ``parse_abp()`` (-> ``abp_rules``
-> Stage-B reconcile); every other line stays on the lite ``parse()`` block-only
path. Before ADR-21, an ``||domain^`` / ``@@||domain^`` line was dropped outright
(``|``/``^`` are not valid domain chars, so the plain validator rejected the line).

These tests drive ``build()`` via its public call path with a synthetic in-memory
manifest -- never ``parse_abp()`` directly -- so they pin the ROUTING decision, not the
parser (which is frozen by the ADR-07 suites). Each transition test asserts the BEFORE
state (the ABP line absent) so green proves the routing CAUSED the change (ADR.md §4.11
red->green, no coverage theater).

Tests (a)-(d) FAIL against the unmodified source (the ``||``/``@@||`` line is dropped);
tests (e)-(h) are deliberate regression pins that pass on both sides.

Pure pytest, stdlib only, no Unbound symbols (CI-runnable).
"""

from __future__ import annotations

from typing import Any

import pfb_unbound as P

# --------------------------------------------------------------------------- #
# Helpers: build a synthetic single-feed manifest + in-memory line_reader, run
# build(), and answer the membership questions the scenarios ask.
# --------------------------------------------------------------------------- #


def _run_build(
    lines: list[str],
    *,
    provenance: str = "feed",
    feed: str = "FEED",
    group: str = "GRP",
    log_flag: str = "1",
) -> P.BuildResult:
    """Drive build() over one synthetic feed whose raw lines are ``lines``.

    The feed's ``raw`` reference is a sentinel key; the injected ``line_reader``
    maps that key back to ``lines`` (keeps build() pure / filesystem-free).
    """
    raw_key = "feed.raw"
    manifest = {
        "feeds": [
            {
                "feed": feed,
                "group": group,
                "log_flag": log_flag,
                "provenance": provenance,
                "raw": raw_key,
            }
        ]
    }
    config: dict[str, Any] = {
        "tld_master": [],
        "tld_blacklist": [],
        "tld_exclusion": [],
        "user_whitelist": [],
        "top1m_list": [],
    }

    def reader(raw: str) -> list[str]:
        assert raw == raw_key
        return list(lines)

    return P.build(manifest, config, line_reader=reader)


def _blocked(result: P.BuildResult, domain: str) -> bool:
    """Is ``domain`` an exact key in the block DBs (dataDB or zoneDB)?"""
    return domain in result.data_db or domain in result.zone_db


def _block_payload(result: P.BuildResult, domain: str) -> dict[str, Any]:
    """The block payload for ``domain`` (asserts it is present in a block DB)."""
    if domain in result.zone_db:
        return result.zone_db[domain]
    return result.data_db[domain]


def _allowed(result: P.BuildResult, domain: str) -> bool:
    """Is ``domain`` present in the allow / white DB?"""
    return domain in result.white_db


# --------------------------------------------------------------------------- #
# (a) ||domain^ in a non-ABP feed -> DNSBL block  (§4.1; red->green)
# --------------------------------------------------------------------------- #


def test_plain_feed_abp_anchor_block() -> None:
    """Scenario: an ``||domain^`` anchor in a plain feed produces a DNSBL block.

    Background: a feed carrying a plain domain plus an ABP block anchor.
    Given: with only the plain line present, ``block-me.com`` is NOT in any block DB
        (the BEFORE state -- the anchor has not been added yet).
    When: the feed also contains ``||block-me.com^``.
    Then: ``block-me.com`` is in dataDB/zoneDB at the feed-block band, AND the plain
        ``domain.com`` line is still blocked (no regression on the plain path).
    """
    # Given (BEFORE): plain-only feed -> the anchor target is absent.
    before = _run_build(["domain.com"])
    assert not _blocked(before, "block-me.com")
    assert _blocked(before, "domain.com")

    # When: add the ABP anchor line.
    after = _run_build(["domain.com", "||block-me.com^"])

    # Then: the anchored domain is now blocked at the feed-block band ...
    assert _blocked(after, "block-me.com")
    assert _block_payload(after, "block-me.com")["band"] == P.PRIO_FEED_BLOCK
    # ... and the plain domain is unaffected.
    assert _blocked(after, "domain.com")


# --------------------------------------------------------------------------- #
# (b) @@||domain^ allow overrides a plain block in the SAME feed (§4.2; red->green)
# --------------------------------------------------------------------------- #


def test_plain_feed_abp_anchor_allow_overrides_plain_block() -> None:
    """Scenario: an ``@@||domain^`` allow in a plain feed overrides a plain block.

    Given: with only the plain ``allow.com`` line, ``allow.com`` IS blocked and is
        NOT in the allow DB (the BEFORE state).
    When: ``@@||allow.com^`` is added to the same feed.
    Then: ``allow.com`` is in the allow DB; the feed allow has overridden the plain
        block (the plain block band 1 loses to the feed allow band 2).
    """
    # Given (BEFORE): plain block only -> blocked, not allowed.
    before = _run_build(["allow.com"])
    assert _blocked(before, "allow.com")
    assert not _allowed(before, "allow.com")

    # When: add the ABP allow anchor.
    after = _run_build(["allow.com", "@@||allow.com^"])

    # Then: the allow is recorded and wins over the plain block.
    assert _allowed(after, "allow.com")
    assert after.white_db["allow.com"]["band"] == P.PRIO_FEED_ALLOW


# --------------------------------------------------------------------------- #
# (c) ||domain^$important -> important=True / band 3  (§4.3; red->green)
# --------------------------------------------------------------------------- #


def test_plain_feed_important_modifier() -> None:
    """Scenario: ``||domain^$important`` escalates the block to band 3.

    Given: a plain-feed ``||domain.com^`` (no modifier) blocks at band 1 with
        ``important=False`` (the BEFORE state for the $important branch).
    When: ``$important`` is present on the anchor.
    Then: the reconciled block payload carries ``important=True`` at band 3.
    """
    # Given (BEFORE): no $important -> band 1, important False.
    before = _run_build(["||domain.com^"])
    assert _blocked(before, "domain.com")
    before_payload = _block_payload(before, "domain.com")
    assert before_payload["important"] is False
    assert before_payload["band"] == P.PRIO_FEED_BLOCK

    # When: add $important.
    after = _run_build(["||domain.com^$important"])

    # Then: important escalates the band to 3.
    payload = _block_payload(after, "domain.com")
    assert payload["important"] is True
    assert payload["band"] == P.PRIO_FEED_BLOCK_IMPORTANT


# --------------------------------------------------------------------------- #
# (d) ||domain^$badfilter cancels a plain block  (§4.4; red->green)
# --------------------------------------------------------------------------- #


def test_plain_feed_badfilter_cancels_block() -> None:
    """Scenario: ``||domain^$badfilter`` cancels a same-feed ABP block routed by the
    new per-line guard.

    ``$badfilter`` is a FEED-only, signature-matched prune performed INSIDE the frozen
    ``reconcile()`` over the ABP rule stream (ADR-07): it cancels a matching ``Rule``,
    not a plain-path block written straight to dataDB/zoneDB (that block is never a
    ``Rule``). Both the block anchor and the ``$badfilter`` anchor are routed to the
    stream by the ADR-21 guard, so the prune fires; a sibling plain line confirms the
    plain path is untouched by the prune.

    Given: with only ``||cancel-me.com^`` present, ``cancel-me.com`` IS blocked
        (the BEFORE state -- the guard routed the anchor to the stream).
    When: ``||cancel-me.com^$badfilter`` is added to the same feed.
    Then: ``cancel-me.com`` is NO LONGER in any block DB (badfilter pruned the rule),
        while the sibling plain ``keep.com`` line stays blocked.
    """
    # Given (BEFORE): the routed ABP block is present.
    before = _run_build(["keep.com", "||cancel-me.com^"])
    assert _blocked(before, "cancel-me.com")
    assert _blocked(before, "keep.com")

    # When: add the $badfilter cancel for the same anchor.
    after = _run_build(["keep.com", "||cancel-me.com^", "||cancel-me.com^$badfilter"])

    # Then: the ABP block is cancelled; the plain sibling is untouched.
    assert not _blocked(after, "cancel-me.com")
    assert _blocked(after, "keep.com")


# --------------------------------------------------------------------------- #
# (e) plain feed with no ABP lines -> unchanged  (§4.5; regression pin)
# --------------------------------------------------------------------------- #


def test_plain_path_unchanged_no_abp_lines() -> None:
    """Scenario (regression pin): a plain feed with no ``||`` lines is processed
    exactly as before -- both domains block, nothing reaches the allow DB or the
    ABP rule stream.
    """
    result = _run_build(["example.com", "subdomain.example.com"])
    assert _blocked(result, "example.com")
    assert _blocked(result, "subdomain.example.com")
    # No allow entry was created from a plain-only feed.
    assert not result.white_db
    # No $important rule was reconciled (the ABP stream stayed empty).
    assert result.important_rules is False


# --------------------------------------------------------------------------- #
# (f) mixed ABP + plain lines in one feed  (§4.6; regression pin)
# --------------------------------------------------------------------------- #


def test_mixed_abp_and_plain_lines_in_one_feed() -> None:
    """Scenario (regression pin): several ABP-shaped lines and a plain domain
    coexist in a single feed; each line is routed independently by its own shape
    (no feed-level tag exists -- #1083 P4).

    block.com is blocked (per-line capture -> parse_abp); allow.com is allowed
    (same); the bare plain.com is blocked via the lite parse() path.
    """
    result = _run_build(["||block.com^", "@@||allow.com^", "plain.com"])
    assert _blocked(result, "block.com")
    assert _allowed(result, "allow.com")
    assert _blocked(result, "plain.com")


# --------------------------------------------------------------------------- #
# (g) path / wildcard anchors skipped  (§4.7; regression pin)
# --------------------------------------------------------------------------- #


def test_wildcard_and_path_anchors_skipped() -> None:
    """Scenario (regression pin): ``||domain.com/path^`` and ``||*.com^`` in a plain
    feed are routed to ``parse_abp()`` but it returns ``None`` for path/wildcard
    anchors, so neither becomes a block.
    """
    result = _run_build(["||domain.com/path^", "||*.com^"])
    assert not _blocked(result, "domain.com")
    assert not _blocked(result, "*.com")
    assert not _blocked(result, ".com")


# --------------------------------------------------------------------------- #
# (h) page-context option skipped  (§4.8; regression pin)
# --------------------------------------------------------------------------- #


def test_page_context_option_skipped() -> None:
    """Scenario (regression pin): ``||domain.com^$third-party`` is a page-context
    (non-DNS) rule; ``parse_abp()`` returns ``None`` for it, so ``domain.com`` is not
    blocked.
    """
    result = _run_build(["||domain.com^$third-party"])
    assert not _blocked(result, "domain.com")


# --------------------------------------------------------------------------- #
# (i) PHP manifest-builder pass-through  (§4.7 / §4.8 PHP; exempt simulation)
# --------------------------------------------------------------------------- #


def _simulate_php_manifest_builder(txt_lines: list[str]) -> list[str]:
    """Re-implement the PHP manifest-builder 'plain' path (ADR-21 site 2).

    Mirrors ``pfblockerng.inc`` (~line 3841): for each ``.txt`` line in a non-ABP
    ('plain') feed the builder writes either the verbatim ABP-anchored line (when it
    starts ``||`` / ``@@||``) or CSV column 1 (the bare domain) to the ``.raw``. This
    is a faithful Python transcription of that small rule, NOT a PHP invocation -- it
    is an off-appliance SIMULATION (ADR §5 red->green exemption) and proves the SHAPE
    of the PHP change, not that the live PHP runs (Phase 3 smoke is the live proof).
    """
    raw: list[str] = []
    for line in txt_lines:
        rawline = line.rstrip("\r\n")
        if rawline.startswith("||") or rawline.startswith("@@||"):
            raw.append(rawline)
            continue
        cols = rawline.split(",", 2)
        if len(cols) > 1 and cols[1] != "":
            raw.append(cols[1])
    return raw


def test_manifest_builder_mixed_feed() -> None:
    """Scenario (exempt PHP simulation): a non-ABP feed's ``.txt`` mixes the 6-col CSV
    plain rows the download loop writes with the verbatim ``||``/``@@||`` lines the
    ADR-21 download-loop guard writes through. The manifest builder must emit BOTH the
    bare domains (from CSV col-1) AND the verbatim ABP anchors into the ``.raw`` --
    so the Phase-1 ``build()`` routing (proven above) actually receives them.

    Given a mixed ``.txt`` (plain CSV rows + verbatim ABP lines),
    When the manifest builder's plain path processes it,
    Then the ``.raw`` carries each CSV col-1 domain AND each ABP anchor verbatim,
    and never the leading comma / other CSV columns of a plain row.
    """
    # Given: download-loop output -- plain rows are ',domain,,log,header,alias'
    # 6-col CSV (col-1 = the bare domain); ABP anchors were written verbatim.
    txt_lines = [
        ",plain-a.com,,1,HEADER,ALIAS\n",
        "||block-abp.com^\n",
        ",plain-b.com,,1,HEADER,ALIAS\n",
        "@@||allow-abp.com^\n",
        "||important.com^$important\n",
    ]

    # When
    raw = _simulate_php_manifest_builder(txt_lines)

    # Then: both shapes survive; the ABP anchors are byte-verbatim; the CSV decoration
    # (leading comma, trailing columns) of plain rows does NOT leak into the .raw.
    assert raw == [
        "plain-a.com",
        "||block-abp.com^",
        "plain-b.com",
        "@@||allow-abp.com^",
        "||important.com^$important",
    ]
