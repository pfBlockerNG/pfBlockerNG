"""Core FeedPhase's exact per-ID log grammar, through the real smoke oracle."""

from __future__ import annotations

import pytest

from tests.smoke.test_core_update import _assert_feed_disposition

FEED_IDS = (
    "dnsbl:cumanualdnsbl",
    "ipv4:cumanualv4_v4",
    "ipv6:cumanualv6_v6",
    "custom:dnsbl:cumanualdnsbl",
    "custom:ipv4:cumanualv4",
    "custom:ipv6:cumanualv6",
    "synthetic:ipv4:DNSBLIP_v4",
    "synthetic:ipv6:DNSBLIP_v6",
    "blacklist:cumanualcat:test.cat",
)
DISPOSITIONS = ("changed", "unchanged", "failed", "held", "reparsed")


@pytest.mark.parametrize("feed_id", FEED_IDS)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
@pytest.mark.parametrize("tail", ["\nnext log line\n", ""])
def test_exact_core_feed_line_is_consumed(feed_id: str, disposition: str, tail: str) -> None:
    # feed_phase.go emits fmt.Fprintf(log, "feed %s: %s\n", result.ID, result.Disposition).
    _assert_feed_disposition(f"previous log line\nfeed {feed_id}: {disposition}{tail}", feed_id, disposition)


@pytest.mark.parametrize("feed_id", FEED_IDS)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
@pytest.mark.parametrize(
    "line",
    [
        "feed {feed_id} {disposition}",
        "feed {feed_id}:: {disposition}",
        "feed {feed_id}:{disposition}",
        "feed {feed_id}:  {disposition}",
        "feed {feed_id} - {disposition}",
        "feed {feed_id}:\t{disposition}",
        "prefix feed {feed_id}: {disposition}",
        "{feed_id}: {disposition}",
        "feed {feed_id}: {disposition} suffix",
        "feed {feed_id}: {disposition}suffix",
        "feed {feed_id}: prefix{disposition}",
        "feed {feed_id}:\n{disposition}",
        "feed {feed_id}: other\nother line {disposition}",
        "feed {feed_id}: other",
    ],
)
def test_malformed_or_unrelated_line_is_rejected(feed_id: str, disposition: str, line: str) -> None:
    with pytest.raises(AssertionError, match="Core Update log has no"):
        _assert_feed_disposition(line.format(feed_id=feed_id, disposition=disposition) + "\n", feed_id, disposition)


@pytest.mark.parametrize(
    "other_id",
    [
        "custom:ipv4:cumanualv4_v4",
        "ipv6:cumanualv4_v4",
        "ipv4:cumanualv4_v40",
        "ipv4:prefixcumanualv4_v4",
        "prefixipv4:cumanualv4_v4",
        "ipv4:cumanualv4_v4.extra",
    ],
)
@pytest.mark.parametrize("disposition", DISPOSITIONS)
def test_regular_id_cannot_be_satisfied_by_another_feed(other_id: str, disposition: str) -> None:
    with pytest.raises(AssertionError, match="Core Update log has no"):
        _assert_feed_disposition(f"feed {other_id}: {disposition}\n", "ipv4:cumanualv4_v4", disposition)


@pytest.mark.parametrize("feed_id", FEED_IDS)
@pytest.mark.parametrize(
    "expected,actual",
    [(expected, actual) for expected in DISPOSITIONS for actual in DISPOSITIONS if expected != actual],
)
def test_other_disposition_is_rejected(feed_id: str, expected: str, actual: str) -> None:
    with pytest.raises(AssertionError, match="Core Update log has no"):
        _assert_feed_disposition(f"feed {feed_id}: {actual}\n", feed_id, expected)


def test_blacklist_dot_is_literal() -> None:
    with pytest.raises(AssertionError, match="Core Update log has no"):
        _assert_feed_disposition("feed blacklist:cumanualcat:testXcat: changed\n", FEED_IDS[-1], "changed")
