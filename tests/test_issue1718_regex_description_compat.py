"""Issue #1718: preserve legacy regex description name semantics."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pfb_unbound as P
from tests.test_issue1718_regex_transport import _ini, _initial_load


def test_extra_hash_in_description_is_not_part_of_regex_name(tmp_path: Path, monkeypatch: Any) -> None:
    encoded = base64.b64encode(b"alpha#Foo#Bar\n").decode("ascii")

    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        assert set(P.regexDB) == {"foo"}
        assert P.regexDB["foo"]["re"].pattern == "alpha"

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert set(swapped.regex_db) == {"foo"}
        assert swapped.regex_db["foo"]["re"].pattern == "alpha"
    finally:
        P.deinit(0)
