"""Issue #1867: a backslash-escaped '#' belongs to the pattern, not the description.

A regex-list line is split into pattern and description at a '#'. Before this
change the split took the FIRST '#' anywhere on the line, so a pattern that
legitimately contains a hash ("^track\\.example\\.com/#/ads$") was silently
truncated at it: the resolver compiled only the fragment before the hash and the
remainder became a description, with no error raised at save time.

The rule these tests pin: the description starts at the first '#' that is NOT
escaped, where "escaped" means preceded by an ODD number of backslashes. The
escaped form needs no unescaping step -- Python's ``re`` reads "\\#" as a literal
'#' already -- so the pattern half reaches ``re.compile`` verbatim.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pfb_unbound as P
from tests.test_issue1718_regex_transport import _ini, _initial_load


def _load(tmp_path: Path, monkeypatch: Any, text: str) -> None:
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    _initial_load(tmp_path, monkeypatch, _ini(encoded))


def test_escaped_hash_stays_in_the_pattern_and_the_description_follows_the_real_marker(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """``a\\#b#desc``: the escaped hash is pattern, the bare hash starts the description."""
    try:
        _load(tmp_path, monkeypatch, "^track\\.example\\.com/\\#/ads$#adshash\n")
        assert set(P.regexDB) == {"adshash"}
        assert P.regexDB["adshash"]["re"].pattern == "^track\\.example\\.com/\\#/ads$"
    finally:
        P.deinit(0)


def test_escaped_hash_pattern_actually_matches_a_literal_hash(tmp_path: Path, monkeypatch: Any) -> None:
    """The surviving pattern compiles to something that matches a real '#'.

    Guards the whole point of the escape: keeping the bytes is worthless if the
    compiled matcher does not then match the host the admin meant to block.
    """
    try:
        _load(tmp_path, monkeypatch, "^ads\\#tag\\.example\\.com$#hashtag\n")
        compiled = P.regexDB["hashtag"]["re"]
        assert compiled.search("ads#tag.example.com") is not None
        assert compiled.search("adstag.example.com") is None
    finally:
        P.deinit(0)


def test_escaped_hash_with_no_description_keeps_the_whole_line_as_the_pattern(tmp_path: Path, monkeypatch: Any) -> None:
    """No unescaped '#' anywhere means no description -- the row keeps its positional name."""
    try:
        _load(tmp_path, monkeypatch, "^ads\\#tag\\.example\\.com$\n")
        assert set(P.regexDB) == {"regex_1"}
        assert P.regexDB["regex_1"]["re"].pattern == "^ads\\#tag\\.example\\.com$"
    finally:
        P.deinit(0)


def test_an_escaped_backslash_does_not_escape_the_hash_after_it(tmp_path: Path, monkeypatch: Any) -> None:
    """``a\\\\#desc``: the backslash is itself escaped, so the '#' IS the marker.

    The parity branch: an EVEN backslash run leaves the '#' unescaped. Without
    this the rule would degrade into "any backslash before a hash protects it"
    and a pattern ending in a literal backslash could never take a description.
    """
    try:
        _load(tmp_path, monkeypatch, "^ads\\\\#evenrun\n")
        assert set(P.regexDB) == {"evenrun"}
        assert P.regexDB["evenrun"]["re"].pattern == "^ads\\\\"
    finally:
        P.deinit(0)


def test_an_unescaped_hash_still_starts_the_description(tmp_path: Path, monkeypatch: Any) -> None:
    """The pre-existing split is untouched for every line with no escape in it."""
    try:
        _load(tmp_path, monkeypatch, "^ads\\.example\\.com$#plain\n")
        assert set(P.regexDB) == {"plain"}
        assert P.regexDB["plain"]["re"].pattern == "^ads\\.example\\.com$"
    finally:
        P.deinit(0)


def test_a_whole_line_comment_is_still_dropped(tmp_path: Path, monkeypatch: Any) -> None:
    """A line whose first non-space character is '#' remains a comment, escape rule or not."""
    try:
        _load(tmp_path, monkeypatch, "  # just a comment\n^kept\\.example\\.com$#kept\n")
        assert set(P.regexDB) == {"kept"}
    finally:
        P.deinit(0)


def test_a_leading_escaped_hash_is_a_pattern_not_a_comment(tmp_path: Path, monkeypatch: Any) -> None:
    """``\\#foo`` starts with a backslash, so the whole-line-comment rule does not fire."""
    try:
        _load(tmp_path, monkeypatch, "\\#foo\n")
        assert set(P.regexDB) == {"regex_1"}
        assert P.regexDB["regex_1"]["re"].pattern == "\\#foo"
    finally:
        P.deinit(0)
