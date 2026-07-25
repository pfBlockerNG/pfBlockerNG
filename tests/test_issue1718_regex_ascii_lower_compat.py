"""Issue #1718: preserve PHP ASCII-only regex lowercasing."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pfb_unbound as P
from tests.test_issue1718_regex_transport import _ini, _initial_load


def test_user_regex_lowercase_matches_php_ascii_semantics(tmp_path: Path, monkeypatch: Any) -> None:
    encoded = base64.b64encode("ÄBC#Name\n".encode("utf-8")).decode("ascii")

    try:
        _initial_load(tmp_path, monkeypatch, _ini(encoded))
        assert P.regexDB["name"]["re"].pattern == "Äbc"

        swapped = P._build_swap_snapshot()
        assert swapped is not None
        assert swapped.regex_db["name"]["re"].pattern == "Äbc"
    finally:
        P.deinit(0)
