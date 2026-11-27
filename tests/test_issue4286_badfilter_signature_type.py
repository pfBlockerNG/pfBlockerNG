"""issue #4286: a feed ``$badfilter`` prunes only rules of its own type.

AdGuard's ``$badfilter`` disables the rule that is identical apart from the ``$badfilter``
modifier. ``reconcile()``'s signature was ``(key_or_pattern, DNS options)`` with no rule type,
so ``||example.com^$badfilter`` also pruned the regex ``/example.com/``, whose inner pattern is
the same string, and ``/example.com/$badfilter`` pruned ``||example.com^``.
"""

from __future__ import annotations

from typing import Any

import pfb_unbound as P


def _build(lines: list[str]) -> P.BuildResult:
    manifest = {"feeds": [{"feed": "FEED", "group": "GRP", "log_flag": "1", "provenance": "feed", "raw": "f.raw"}]}
    config: dict[str, Any] = {"tld_wildcard_blacklist": [], "tld_wildcard_exclusion": [], "user_whitelist": []}
    return P.build(manifest, config, line_reader=lambda _raw: list(lines))


def test_an_anchor_badfilter_keeps_a_regex_with_the_same_text() -> None:
    result = _build(["/example.com/", "||example.com^", "||example.com^$badfilter"])
    assert len(result.regex_db) == 1
    assert "example.com" not in result.zone_db


def test_a_regex_badfilter_keeps_an_anchor_with_the_same_text() -> None:
    result = _build(["/example.com/", "||example.com^", "/example.com/$badfilter"])
    assert result.regex_db == {}
    assert "example.com" in result.zone_db


def test_a_badfilter_still_prunes_its_own_rule_with_the_same_options() -> None:
    result = _build(["/ads[0-9]+\\./$important", "/ads[0-9]+\\./$important,badfilter", "/ads[0-9]+\\./"])
    assert [entry["important"] for entry in result.regex_db.values()] == [False]


def test_an_allow_badfilter_keeps_the_block_with_the_same_target() -> None:
    result = _build(["||example.com^", "@@||example.com^$badfilter", "/ads[0-9]+\\./", "@@/ads[0-9]+\\./$badfilter"])
    assert "example.com" in result.zone_db
    assert len(result.regex_db) == 1


def test_a_block_badfilter_keeps_the_allow_with_the_same_target() -> None:
    result = _build(["@@||example.com^", "||example.com^$badfilter", "@@/ads[0-9]+\\./", "/ads[0-9]+\\./$badfilter"])
    assert "example.com" in result.white_db
    assert len(result.allow_regex_db) == 1


def test_an_allow_regex_badfilter_keeps_an_allow_anchor_with_the_same_text() -> None:
    result = _build(["@@/example.com/", "@@||example.com^", "@@/example.com/$badfilter"])
    assert result.allow_regex_db == {}
    assert "example.com" in result.white_db
