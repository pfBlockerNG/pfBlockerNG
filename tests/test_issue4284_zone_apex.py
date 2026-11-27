"""issue #4284: AdGuard's subdomain-only mask ``.host^`` blocks the subdomains of ``host``, never ``host``.

The capture guard (``_dnsbl_is_abp_rule_line()``, the twin of PHP's
``pfb_dnsbl_is_abp_rule_line()``, pinned to the same rows by
tests/php/DnsblAbpSubdomainMaskTest.php) routes ``.host^`` to ``parse_abp()``, which reads it
as a block rule with ``apex=False``. ``build()`` emits it as a zone entry marked
``"apex": False``: the suffix walk skips that entry when the matched suffix is the query name
itself. On one zone key the merged entry keeps ``apex = a.apex or b.apex``, so a ``.host^``
never unblocks a host another rule blocks. A ``.host^`` whose key cannot be a zone (TLD
Exclusion, the PSL feed policy's ``apex`` demotion) is dropped: an exact block would cover only
the host the rule excludes.
"""

from __future__ import annotations

from typing import Any

import pytest

import pfb_unbound as P

PSL = """// ===BEGIN ICANN DOMAINS===
com
net
co.uk
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// ===END PRIVATE DOMAINS===
"""


def _build(
    feeds: list[list[str]],
    *,
    exclusion: list[str] | None = None,
    icann_policy: str = "honor",
    top1m: list[str] = [],  # noqa: B006 - read only
    top1m_feeds: frozenset[int] = frozenset(),
) -> P.BuildResult:
    raws = {f"feed{i}.raw": lines for i, lines in enumerate(feeds)}
    manifest = {
        "feeds": [
            {
                "feed": f"FEED{i}",
                "group": f"GRP{i}",
                "log_flag": "1",
                "provenance": "feed",
                "raw": raw,
                "top1m": i in top1m_feeds,
            }
            for i, raw in enumerate(raws)
        ]
    }
    config: dict[str, Any] = {
        "psl_rules": P.parse_psl_rules(PSL),
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": exclusion or [],
        "user_whitelist": [],
        "psl_feed_icann_policy": icann_policy,
    }
    return P.build(
        manifest, config, line_reader=lambda raw: list(raws[raw]), top1m_enabled=bool(top1m), top1m_lines=top1m
    )


def _blocks(result: P.BuildResult, q_name: str) -> bool:
    """Both block lookups agree: the fast path's exact + suffix walk, and the numeric path's scan."""
    fast = q_name in result.data_db or P.find_zone_match(q_name, result.zone_db)[0] is not None
    cfg = {"dataDB": bool(result.data_db), "zoneDB": bool(result.zone_db), "regexDB": False, "userRegexDB": False}
    band, _ = P._scan_block_band(q_name, cfg, result.data_db, result.zone_db, {}, {})
    assert fast == (band > 0), q_name
    return fast


@pytest.mark.parametrize("line", [".webhop.net^", ".webhop.net^$important", ".Ads.Example.com^"])
def test_a_subdomain_only_mask_is_captured(line: str) -> None:
    assert P._dnsbl_is_abp_rule_line(line)


@pytest.mark.parametrize(
    "line",
    [".imgur.com/lumbar.gif", ".webhop.net", ".top^*-960x80-*.gif", ".*.webhop.net^", ".web|hop.net^", ". webhop.net^"],
)
def test_a_path_wildcard_or_unterminated_dot_line_is_not_captured(line: str) -> None:
    assert not P._dnsbl_is_abp_rule_line(line)


def test_parse_abp_reads_a_subdomain_only_block() -> None:
    rule = P.parse_abp(".WebHop.net^$important")
    assert rule is not None
    assert (rule.kind, rule.target, rule.key_or_pattern) == (P.DNSBL_KIND_BLOCK, P.RULE_TARGET_DOMAIN, "webhop.net")
    assert rule.wildcard and not rule.apex and rule.important
    anchored = P.parse_abp("||webhop.net^$important")
    assert anchored is not None and anchored.apex
    assert rule.signature != anchored.signature


def test_parse_abp_skips_a_subdomain_only_mask_with_a_page_option() -> None:
    assert P.parse_abp(".variti.ch^$third-party,popup") is None


def test_a_subdomain_only_mask_blocks_subdomains_and_not_the_host() -> None:
    result = _build([[".webhop.net^"]])
    assert result.zone_db["webhop.net"]["apex"] is False
    assert _blocks(result, "someone.webhop.net")
    assert _blocks(result, "a.b.webhop.net")
    assert not _blocks(result, "webhop.net")
    assert not _blocks(result, "notwebhop.net")


def test_the_walk_continues_past_a_subdomain_only_key() -> None:
    result = _build([[".ads.example.com^", "||example.com^"]])
    assert _blocks(result, "ads.example.com")


@pytest.mark.parametrize(
    "feeds",
    [
        [[".webhop.net^", "||webhop.net^"]],
        [["||webhop.net^", ".webhop.net^"]],
        [["webhop.net"], [".webhop.net^"]],
        [[".webhop.net^"], ["0.0.0.0 webhop.net"]],
    ],
    ids=["mask then anchor", "anchor then mask", "plain feed then mask feed", "mask feed then hosts feed"],
)
def test_a_subdomain_only_mask_never_unblocks_a_blocked_host(feeds: list[list[str]]) -> None:
    result = _build(feeds)
    assert _blocks(result, "webhop.net")
    assert _blocks(result, "someone.webhop.net")


def test_a_badfilter_anchor_does_not_prune_a_subdomain_only_mask() -> None:
    result = _build([[".webhop.net^"], ["||webhop.net^$badfilter"]])
    assert _blocks(result, "someone.webhop.net")


def test_a_subdomain_only_mask_on_tld_exclusion_is_dropped() -> None:
    result = _build([[".webhop.net^"]], exclusion=["webhop.net"])
    assert not _blocks(result, "webhop.net")
    assert "webhop.net" not in result.zone_db


def test_a_subdomain_only_mask_the_suffix_policy_demotes_is_dropped() -> None:
    result = _build([[".co.uk^"]], icann_policy="apex")
    assert not _blocks(result, "co.uk")
    assert "co.uk" not in result.zone_db
    # Dropped, not demoted: no exact block exists for the Reject Stats to report.
    tally = result.rejects[("FEED0", "GRP0")]
    assert (tally.get("suffix_drop"), tally.get("suffix_demote", 0)) == (1, 0)


def test_two_subdomain_only_masks_on_one_host_leave_the_host_unblocked() -> None:
    result = _build([[".webhop.net^"], [".webhop.net^"]])
    assert not _blocks(result, "webhop.net")
    assert _blocks(result, "someone.webhop.net")


def _hit(result: P.BuildResult, q_name: str) -> tuple[int, str]:
    """The (band, group) the block lookups attribute ``q_name`` to; both lookups agree."""
    _, entry = P.find_zone_match(q_name, result.zone_db)
    assert entry is not None, q_name
    cfg = {"dataDB": False, "zoneDB": True, "regexDB": False, "userRegexDB": False}
    band, meta = P._scan_block_band(q_name, cfg, {}, result.zone_db, {}, {})
    assert meta is not None and meta["entry"] is entry, q_name
    return band, result.feed_group_index_db[entry["index"]]["group"]


@pytest.mark.parametrize(
    "feeds",
    [[["||webhop.net^"], [".webhop.net^$important"]], [[".webhop.net^$important"], ["||webhop.net^"]]],
    ids=["anchor then mask", "mask then anchor"],
)
def test_the_host_keeps_the_band_and_group_of_the_rule_that_blocks_it(feeds: list[list[str]]) -> None:
    result = _build(feeds)
    anchor = next(i for i, lines in enumerate(feeds) if lines[0].startswith("||"))
    assert _hit(result, "webhop.net") == (P.PRIO_FEED_BLOCK, f"GRP{anchor}")


def test_subdomains_keep_the_last_writer_when_a_mask_follows_an_anchor() -> None:
    result = _build([["||webhop.net^"], [".webhop.net^$important"]])
    band, group = _hit(result, "someone.webhop.net")
    assert group == "GRP1" and band > P.PRIO_FEED_BLOCK


@pytest.mark.parametrize("anchor_first", [True, False], ids=["anchor then mask", "mask then anchor"])
def test_a_top1m_filtered_anchor_never_blocks_a_listed_host_through_a_mask(anchor_first: bool) -> None:
    feeds = [["||webhop.net^"], [".webhop.net^"]] if anchor_first else [[".webhop.net^"], ["||webhop.net^"]]
    result = _build(feeds, top1m=["webhop.net"], top1m_feeds=frozenset({0 if anchor_first else 1}))
    assert not _blocks(result, "webhop.net")
    assert _blocks(result, "someone.webhop.net")


def test_a_listed_host_stays_unblocked_through_nested_top1m_fallbacks() -> None:
    """Codex on #4285: a wrapped apex payload's fallback can itself be TOP1M-filtered."""
    result = _build(
        [["||webhop.net^"], [".webhop.net^"], ["||webhop.net^"], [".webhop.net^"]],
        top1m=["webhop.net"],
        top1m_feeds=frozenset({0, 2}),
    )
    assert not _blocks(result, "webhop.net")
    assert _blocks(result, "someone.webhop.net")
