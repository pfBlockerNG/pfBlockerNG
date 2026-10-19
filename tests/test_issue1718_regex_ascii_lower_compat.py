"""Issue #2079: preserve raw user regex syntax with case-insensitive matching."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P
from pfb_dnsbl_regex_rules import pfb_regex_admission
from tests.test_issue1718_regex_transport import _ini, _initial_load


def test_user_regex_preserves_raw_patterns_and_matches_case_insensitively(tmp_path: Path, monkeypatch: Any) -> None:
    text = (
        r"^\D+\.EXAMPLE\.COM#Non digit"
        "\n"
        r"^\W+\.EXAMPLE\.COM#Non word"
        "\n"
        r"^\S+\.EXAMPLE\.COM#Non space"
        "\n"
        r"a\Bbc\.EXAMPLE\.COM#Boundary"
        "\n"
        r"\d+\.EXAMPLE\.COM#Digit"
        "\n"
    )
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    expected = {
        "non_digit": (r"^\D+\.EXAMPLE\.COM", "abc.example.com", "123.example.com"),
        "non_word": (r"^\W+\.EXAMPLE\.COM", "---.example.com", "abc.example.com"),
        "non_space": (r"^\S+\.EXAMPLE\.COM", "abc.example.com", " .example.com"),
        "boundary": (r"a\Bbc\.EXAMPLE\.COM", "abc.example.com", "a-bc.example.com"),
        "digit": (r"\d+\.EXAMPLE\.COM", "123.example.com", "abc.example.com"),
    }

    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        for name, (pattern, matching_query, non_matching_query) in expected.items():
            compiled = P.userRegexDB[name]["re"]
            assert compiled.pattern == pattern
            assert compiled.flags & re.IGNORECASE
            assert compiled.search(matching_query), (name, matching_query)
            assert not compiled.search(non_matching_query), (name, non_matching_query)

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        for name, (pattern, matching_query, non_matching_query) in expected.items():
            compiled = swapped.user_regex_db[name]["re"]
            assert compiled.pattern == pattern
            assert compiled.flags & re.IGNORECASE
            assert compiled.search(matching_query), (name, matching_query)
            assert not compiled.search(non_matching_query), (name, non_matching_query)
    finally:
        P.deinit(0)


@pytest.mark.parametrize("escape", [r"\D", r"\W", r"\S"], ids=["non-digit", "non-word", "non-space"])
def test_the_unanchored_originals_of_the_anchored_rows_are_refused_with_the_anchor_remedy(
    escape: str, capsys: Any
) -> None:
    """Written without ``^`` the three class-negation rows above start a match at every position of the
    name, which the cost bound refuses: the reason names the remedy, and the anchored row is the admitted one."""
    unanchored = rf"{escape}+\.EXAMPLE\.COM"
    cost, reason, _text = pfb_regex_admission(unanchored)
    assert (cost, reason) == (0, "too costly to match unanchored (bound 852224 > 262144); anchor it with ^")
    assert pfb_regex_admission("^" + unanchored)[1] is None
    assert P._dnsbl_compile_user_regex([("row", unanchored)], False) == {}
    assert "anchor it with ^" in capsys.readouterr().err
