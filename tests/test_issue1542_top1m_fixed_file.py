from __future__ import annotations

import builtins
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import pytest

import pfb_unbound as P
from tests.test_adr06_golden_oracle import _build_cfg, _decision_label


def _manifest(tmp_path: Path, *, enabled: bool = True) -> Path:
    raw = tmp_path / "feed.raw"
    raw.write_text("blocked.example\n", encoding="utf-8")
    path = tmp_path / "pfb_py_sources.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "config": {"top1m_enabled": enabled, "user_whitelist": []},
                "feeds": [{"raw": raw.name, "feed": "feed", "group": "g", "log_flag": "1"}],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_disabled_does_not_require_fixed_file(tmp_path: Path) -> None:
    result = P.dnsbl_build_from_manifest(str(_manifest(tmp_path, enabled=False)))
    assert result is not None
    assert result.white_db == {}


def test_enabled_streams_fixed_file_with_crlf_blanks_and_first_writer_duplicates(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_bytes(b"first.example\r\n\r\n SECOND.EXAMPLE \r\nfirst.example\r\n")
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert result is not None
    assert set(result.white_db) == {"first.example", "second.example"}
    assert result.white_db["first.example"]["important"] is True


@pytest.mark.parametrize("legacy", [".legacy.example,,\n", ",legacy.example,,\n", ",www.legacy.example,,\n"])
def test_enabled_rejects_retired_comma_framed_top1m_lines(tmp_path: Path, legacy: str) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_text(legacy, encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.white_db == {}, f"retired TOP1M record became a whitelist key: {result.white_db!r}"
    assert all("," not in key for key in result.white_db)


@pytest.mark.parametrize(
    "invalid",
    [
        "dotless\n",
        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".com\n",
    ],
)
def test_enabled_rejects_invalid_top1m_domain_shape_and_wire_cap(tmp_path: Path, invalid: str) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "pfb_py_top1m.txt").write_text(invalid, encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.white_db == {}


def test_enabled_top1m_is_exact_allow_with_www_fallback_not_deeper_wildcard(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "feed.raw").write_text("blocked.example\nwww.blocked.example\n", encoding="utf-8")
    (tmp_path / "pfb_py_top1m.txt").write_text("blocked.example\nblocked.example\n", encoding="utf-8")

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.white_db["blocked.example"]["wildcard"] is False
    assert P.whitelist_check_domain("blocked.example", result.white_db, 1)
    assert P.whitelist_check_domain("www.blocked.example", result.white_db, 1)
    assert not P.whitelist_check_domain("deep.blocked.example", result.white_db, 1)

    containers = {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": {},
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {},
    }
    cfg = _build_cfg({}, has_white=True)
    assert (
        _decision_label(P.evaluate_domain("blocked.example", "blocked.example", "example", False, cfg, containers))
        == "whitelist"
    )
    assert (
        _decision_label(
            P.evaluate_domain("www.blocked.example", "www.blocked.example", "example", False, cfg, containers)
        )
        == "whitelist"
    )
    deep_decision = P.evaluate_domain("deep.blocked.example", "deep.blocked.example", "example", False, cfg, containers)
    assert deep_decision.in_whitelist is False


@pytest.mark.parametrize("kind", ["missing", "directory", "unreadable"])
def test_enabled_missing_directory_or_unreadable_fixed_file_fails_closed(tmp_path: Path, kind: str) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    if kind == "directory":
        path.mkdir()
    elif kind == "unreadable":
        path.write_text("blocked.example\n", encoding="utf-8")
        path.chmod(0)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None
    if kind == "unreadable":
        path.chmod(0o600)


def test_enabled_mid_read_failure_discards_candidate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("first.example\nsecond.example\n", encoding="utf-8")
    real_open = builtins.open

    class FailingReader:
        def __enter__(self) -> FailingReader:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> Literal[False]:
            return False

        def __iter__(self) -> Iterator[str]:
            yield "first.example\n"
            raise OSError("injected mid-read")

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        if os.fspath(name) == os.fspath(path):
            return FailingReader()
        return real_open(name, *args, **kwargs)

    monkeypatch.setattr("builtins.open", injected_open)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_enabled_truncation_after_open_discards_candidate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    path = tmp_path / "pfb_py_top1m.txt"
    path.write_text("".join("domain-{}.example\n".format(index) for index in range(100_000)), encoding="utf-8")
    opened = threading.Event()
    truncated = threading.Event()
    real_open = builtins.open

    def truncate_when_opened() -> None:
        assert opened.wait(5), "TOP1M open was not reached"
        os.truncate(path, 0)
        truncated.set()

    def injected_open(name: str | os.PathLike[str], *args: Any, **kwargs: Any) -> Any:
        handle = real_open(name, *args, **kwargs)
        if os.fspath(name) == os.fspath(path):
            opened.set()
            assert truncated.wait(5), "TOP1M truncation did not complete"
        return handle

    worker = threading.Thread(target=truncate_when_opened)
    worker.start()
    monkeypatch.setattr("builtins.open", injected_open)
    try:
        assert P.dnsbl_build_from_manifest(str(manifest)) is None
    finally:
        worker.join(5)
    assert not worker.is_alive(), "TOP1M truncation worker did not finish"
