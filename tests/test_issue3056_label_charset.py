"""DNS-label validation preserves both alphabets without per-character Python work."""

from __future__ import annotations

import cProfile
from collections.abc import Callable

import pytest

import pfb_unbound as P


@pytest.mark.parametrize("normalize", [P._psl_normalize_name, P.normalise])
def test_ascii_validation_python_work_does_not_scale_with_label_length(normalize: Callable[[str], str | None]) -> None:
    calls = []
    for width in (1, 63):
        name = f"{'a' * width}.com"
        profile = cProfile.Profile()
        assert profile.runcall(normalize, name) == name
        calls.append(sum(row.callcount for row in profile.getstats() if not isinstance(row.code, str)))
    assert calls[1] == calls[0], f"Python calls grew with label length: short={calls[0]}, long={calls[1]}"


@pytest.mark.parametrize("name", ["", ".", "a..com"])
def test_empty_names_and_labels_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        P._psl_normalize_name(name)
    assert P.normalise(name) is None
    assert P._normalise_verdict(name) == (None, "shape")


def test_ascii_alphabets_remain_distinct() -> None:
    for codepoint in range(128):
        char = chr(codepoint)
        name = f"a{char}b.com"
        allowed = char.lower() in "abcdefghijklmnopqrstuvwxyz0123456789-" or char == "."
        if allowed:
            assert P._psl_normalize_name(name) == name.lower()
        else:
            with pytest.raises(ValueError):
                P._psl_normalize_name(name)
        assert P.normalise(name) == (name.lower() if allowed or char == "_" else None), repr(char)


@pytest.mark.parametrize(
    ("name", "expected"),
    [("BÜCHER.de", "xn--bcher-kva.de"), ("xn--bcher-kva.de", "xn--bcher-kva.de")],
)
def test_idna_normalization_is_preserved(name: str, expected: str) -> None:
    assert P._psl_normalize_name(name) == expected


@pytest.mark.parametrize("name", ["a\u200bb.com", "a\x00b.com", "a\t b.com", "xn--bad.com", "-bad.com", "bad-.com"])
def test_hostile_labels_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        P._psl_normalize_name(name)
