"""Issue #1284: DNSBL raw feeds use LF framing and reject actual CR bytes.

The file-backed manifest reader treats LF as the only record delimiter. Actual CR
bytes are invalid feed content and are removed, including CRLF terminators, while
literal ``\\r`` text and UTF-8 replacement decoding remain byte-semantically intact.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P

_FRAMING_CASES: list[tuple[bytes, list[str]]] = [
    (b"", []),
    (b"a.example\nb.example\n", ["a.example", "b.example"]),
    (b"a.example\r\nb.example\r\n", ["a.example", "b.example"]),
    (b"a.example\rb.example\n", ["a.exampleb.example"]),
    (b"a.\rexample\n", ["a.example"]),
    (b"a.example\rb.example\r", ["a.exampleb.example"]),
    (b"a.example\nb.example", ["a.example", "b.example"]),
    (b"a\\r.example\n", [r"a\r.example"]),
    (b"a\xff.example\n", ["a�.example"]),
    (b"$[]\t  \\r.example\r\n", ["$[]\t  \\r.example"]),
    (b"a" * 65_536 + b"\r\n", ["a" * 65_536]),
]


@pytest.mark.parametrize(
    ("raw_bytes", "expected"),
    _FRAMING_CASES,
    ids=[
        "empty",
        "lf",
        "crlf",
        "lone-cr",
        "internal-cr",
        "cr-only",
        "no-final-lf",
        "literal-backslash-r",
        "invalid-utf8",
        "syntax-and-whitespace",
        "oversized-line",
    ],
)
def test_reader_uses_lf_framing_and_removes_actual_cr(
    tmp_path: Path,
    raw_bytes: bytes,
    expected: list[str],
) -> None:
    feed = tmp_path / "feed.raw"
    feed.write_bytes(raw_bytes)

    lines = list(P._dnsbl_file_line_reader(str(tmp_path))("feed.raw"))

    assert lines == expected, f"reader mismatch: expected {expected!r}, got {lines!r}"


@pytest.mark.parametrize("reference_kind", ["traversal", "absolute"])
def test_reader_refuses_paths_outside_manifest_base(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reference_kind: str,
) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside.raw"
    outside.write_bytes(b"outside.example\n")
    raw = os.path.join("..", outside.name) if reference_kind == "traversal" else str(outside)

    lines = list(P._dnsbl_file_line_reader(str(base))(raw))

    assert lines == [], f"{reference_kind} reference unexpectedly yielded {lines!r}"
    assert "Refusing DNSBL feed outside base dir" in capsys.readouterr().err


@pytest.mark.parametrize("failure_kind", ["missing", "unreadable"])
def test_reader_logs_and_skips_open_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    failure_kind: str,
) -> None:
    raw = "missing.raw"
    if failure_kind == "unreadable":
        raw = "directory.raw"
        (tmp_path / raw).mkdir()

    lines = list(P._dnsbl_file_line_reader(str(tmp_path))(raw))

    assert lines == [], f"{failure_kind} reference unexpectedly yielded {lines!r}"
    assert "Failed to read DNSBL feed" in capsys.readouterr().err


def test_reader_defers_open_until_iteration(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lines = P._dnsbl_file_line_reader(str(tmp_path))("missing.raw")

    assert iter(lines) is lines
    assert capsys.readouterr().err == "", "reader performed I/O before iteration"
    assert list(lines) == []
    assert "Failed to read DNSBL feed" in capsys.readouterr().err


def _build_from_raw(
    tmp_path: Path,
    raw_bytes: bytes,
    *,
    mode: str | None = None,
    provenance: str | None = None,
    include_mode: bool = False,
    include_provenance: bool = False,
) -> P.BuildResult:
    (tmp_path / "feed.raw").write_bytes(raw_bytes)
    row: dict[str, Any] = {
        "raw": "feed.raw",
        "feed": "FramingFeed",
        "group": "FramingGroup",
        "log_flag": "1",
    }
    if include_mode:
        row["mode"] = mode
    if include_provenance:
        row["provenance"] = provenance
    manifest = {
        "version": 1,
        "config": {
            "tld_wildcard_blacklist": [],
            "tld_wildcard_exclusion": [],
            "user_whitelist": [],
            "user_unlock": [],
            "top1m_enabled": False,
        },
        "feeds": [row],
    }
    manifest_path = tmp_path / "pfb_py_sources.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest_path))

    assert result is not None, "valid manifest unexpectedly failed to build"
    return result


def _block_payload(result: P.BuildResult, domain: str) -> dict[str, Any]:
    matches = [database[domain] for database in (result.data_db, result.zone_db) if domain in database]
    assert len(matches) == 1, f"expected one block payload for {domain!r}, got {matches!r}"
    return matches[0]


def test_full_manifest_lone_cr_never_creates_two_rules(tmp_path: Path) -> None:
    result = _build_from_raw(tmp_path, b"one.example\rtwo.example\n")

    assert set(result.data_db) | set(result.zone_db) == {"one.exampletwo.example"}
    assert result.counts == 1


@pytest.mark.parametrize(
    ("case", "mode", "provenance", "include_mode", "include_provenance", "expected_band", "permit"),
    [
        ("mode-absent-feed", None, None, False, False, P.PRIO_FEED_BLOCK, False),
        ("explicit-deny-feed", "deny", "feed", True, True, P.PRIO_FEED_BLOCK, False),
        ("mode-absent-user", None, "user", False, True, P.PRIO_USER_BLOCK, False),
        ("permit", "permit", None, True, False, P.PRIO_FEED_ALLOW, True),
    ],
)
def test_full_manifest_crlf_preserves_mode_provenance_and_attribution(
    tmp_path: Path,
    case: str,
    mode: str | None,
    provenance: str | None,
    include_mode: bool,
    include_provenance: bool,
    expected_band: int,
    permit: bool,
) -> None:
    domain = f"{case}.example"
    result = _build_from_raw(
        tmp_path,
        domain.encode() + b"\r\n",
        mode=mode,
        provenance=provenance,
        include_mode=include_mode,
        include_provenance=include_provenance,
    )

    payload = result.white_db[domain] if permit else _block_payload(result, domain)
    assert payload["band"] == expected_band
    assert result.feed_group_index_db[payload["index"]] == {
        "feed": "FramingFeed",
        "group": "FramingGroup",
    }
    if permit:
        assert payload["wildcard"] is True
        assert payload["important"] is False
    else:
        assert payload["important"] is False


def test_get_details_dnsbl_declares_only_used_globals() -> None:
    parsed = ast.parse(inspect.getsource(P.get_details_dnsbl))
    function = parsed.body[0]
    assert isinstance(function, ast.FunctionDef)
    declared = {name for node in ast.walk(function) if isinstance(node, ast.Global) for name in node.names}
    referenced = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}

    assert declared == {"_dnsbl_last_event"}, f"unexpected global declaration: {sorted(declared)!r}"
    assert declared <= referenced, f"declared but unreferenced globals: {sorted(declared - referenced)!r}"
