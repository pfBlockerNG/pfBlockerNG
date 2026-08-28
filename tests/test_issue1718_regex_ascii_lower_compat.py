"""Issue #2079: preserve raw user regex syntax with case-insensitive matching."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import pfb_unbound as P
from tests.test_issue1718_regex_transport import _ini, _initial_load


def test_user_regex_preserves_raw_patterns_and_matches_case_insensitively(tmp_path: Path, monkeypatch: Any) -> None:
    text = (
        r"\D+\.EXAMPLE\.COM#Non digit"
        "\n"
        r"\W+\.EXAMPLE\.COM#Non word"
        "\n"
        r"\S+\.EXAMPLE\.COM#Non space"
        "\n"
        r"a\Bbc\.EXAMPLE\.COM#Boundary"
        "\n"
        r"\d+\.EXAMPLE\.COM#Digit"
        "\n"
    )
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    expected = {
        "non_digit": (r"\D+\.EXAMPLE\.COM", "abc.example.com", "123.example.com"),
        "non_word": (r"\W+\.EXAMPLE\.COM", "---.example.com", "abc.example.com"),
        "non_space": (r"\S+\.EXAMPLE\.COM", "abc.example.com", " .example.com"),
        "boundary": (r"a\Bbc\.EXAMPLE\.COM", "abc.example.com", "a-bc.example.com"),
        "digit": (r"\d+\.EXAMPLE\.COM", "123.example.com", "abc.example.com"),
    }

    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        for name, (pattern, matching_query, non_matching_query) in expected.items():
            compiled = P.regexDB[name]["re"]
            assert compiled.pattern == pattern
            assert compiled.flags & re.IGNORECASE
            assert compiled.search(matching_query), (name, matching_query)
            assert not compiled.search(non_matching_query), (name, non_matching_query)

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        for name, (pattern, matching_query, non_matching_query) in expected.items():
            compiled = swapped.regex_db[name]["re"]
            assert compiled.pattern == pattern
            assert compiled.flags & re.IGNORECASE
            assert compiled.search(matching_query), (name, matching_query)
            assert not compiled.search(non_matching_query), (name, non_matching_query)
    finally:
        P.deinit(0)
