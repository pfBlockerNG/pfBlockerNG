"""Issue #1841 -- a package upgrade must never take DNSBL down just because the
manifest schema moved.

A box upgraded across the TOP1M externalisation (#1542) keeps its pre-retirement
``pfb_py_sources.json`` until the next full update rewrites it. That manifest still
carries ``config.top1m_list`` (the inline TOP1M source) and predates the
``pfb_py_top1m.txt`` sidecar. The manifest validator rejected the whole generation on
the retired key, so the resolver served no DNSBL at all until a full sync succeeded.

Intended behaviour pinned here: the retired key is TOLERATED with a one-line warning,
the generation builds, and -- because the sidecar of that vintage does not exist -- the
retired inline list supplies TOP1M filtering for opted-in feed rows. It never becomes a
global whitelist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pfb_unbound as P

RETIRED_KEY_WARNING = "config.top1m_list"


def _manifest(
    tmp_path: Path,
    *,
    top1m_enabled: bool,
    top1m_list: object | None,
) -> str:
    """A manifest/v1 with one raw feed; ``top1m_list`` present == pre-#1542 vintage."""
    (tmp_path / "feed.raw").write_text(
        "blocked.example\npopularcdn.com\nwww.popularcdn.com\nsidecar.example\nlegacy.example\nwww.legacy.example\n",
        encoding="utf-8",
    )
    config: dict[str, object] = {"user_whitelist": [], "top1m_enabled": top1m_enabled}
    if top1m_list is not None:
        config["top1m_list"] = top1m_list
    path = tmp_path / "pfb_py_sources.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "config": config,
                "feeds": [{"raw": "feed.raw", "feed": "feed", "group": "g", "log_flag": "1", "top1m": True}],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_legacy_manifest_with_top1m_disabled_still_builds_its_feeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The retired key alone no longer costs the box its feed data, and the warning
    says the list was ignored rather than claiming a TOP1M load that never happened."""
    manifest = _manifest(tmp_path, top1m_enabled=False, top1m_list=["popularcdn.com"])

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None, "retired config.top1m_list still fails the whole generation"
    assert set(result.data_db) == {
        "blocked.example",
        "popularcdn.com",
        "www.popularcdn.com",
        "sidecar.example",
        "legacy.example",
        "www.legacy.example",
    }
    assert result.zone_db == {}
    assert result.white_db == {}
    warning = capsys.readouterr().err
    assert RETIRED_KEY_WARNING in warning
    assert "ignoring it (TOP1M is disabled)" in warning


def test_legacy_manifest_with_top1m_enabled_filters_its_opted_in_feed(tmp_path: Path) -> None:
    """TOP1M on + no sidecar of that vintage: the retired inline list is the source
    that removes listed and www entries from opted-in feeds, not a global whitelist."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=["popularcdn.com"])
    assert not (tmp_path / "pfb_py_top1m.txt").exists(), "pre-#1542 manifests predate the sidecar"

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None
    assert set(result.data_db) == {"blocked.example", "sidecar.example", "legacy.example", "www.legacy.example"}
    assert result.zone_db == {}
    assert result.white_db == {}


@pytest.mark.parametrize(
    "comma_framed",
    [".legacy.example,,", ",legacy.example,,", ",www.legacy.example,,"],
    ids=["wildcard-record", "exact-record", "www-record"],
)
def test_real_legacy_vintage_records_build_without_filtering_comma_framed_names(
    tmp_path: Path, comma_framed: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Comma-framed records remain inert while a valid companion still filters:
    the retired source must be read without inventing coverage for malformed names."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=[comma_framed, "popularcdn.com"])

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None, "a real legacy manifest must still load its feeds"
    assert set(result.data_db) == {"blocked.example", "sidecar.example", "legacy.example", "www.legacy.example"}
    assert result.zone_db == {}
    assert result.white_db == {}
    assert RETIRED_KEY_WARNING in capsys.readouterr().err


def test_legacy_manifest_warns_once_about_the_retired_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The tolerated retirement is operator-visible -- one warning, not silence."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=["popularcdn.com"])

    result = P.dnsbl_build_from_manifest(manifest)
    assert result is not None
    assert set(result.data_db) == {"blocked.example", "sidecar.example", "legacy.example", "www.legacy.example"}
    assert result.zone_db == {}
    assert result.white_db == {}

    warning = capsys.readouterr().err
    assert warning.count(RETIRED_KEY_WARNING) == 1
    assert "reading TOP1M from it" in warning


def test_current_manifest_reads_the_sidecar_and_warns_about_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Guard the flip: a post-#1542 manifest keeps the sidecar contract, no warning."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=None)
    (tmp_path / "pfb_py_top1m.txt").write_text("sidecar.example\n", encoding="utf-8")

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None
    assert set(result.data_db) == {
        "blocked.example",
        "popularcdn.com",
        "www.popularcdn.com",
        "legacy.example",
        "www.legacy.example",
    }
    assert result.zone_db == {}
    assert result.white_db == {}
    assert RETIRED_KEY_WARNING not in capsys.readouterr().err


@pytest.mark.parametrize(
    "malformed",
    [["popularcdn.com", 42], "popularcdn.com", {"popularcdn.com": True}],
    ids=["non-string-entry", "bare-string", "object"],
)
def test_malformed_legacy_top1m_list_still_fails_the_generation(tmp_path: Path, malformed: object) -> None:
    """Tolerating the retired key does not tolerate a corrupt one: the ``list[str]``
    shape contract of the sibling config lists still governs it, and a violation is a
    generation failure, not a silently ignored field."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=malformed)

    assert P.dnsbl_build_from_manifest(manifest) is None


def test_legacy_manifest_prefers_its_own_inline_list_over_a_stray_sidecar(tmp_path: Path) -> None:
    """A manifest and its TOP1M snapshot are published together, so a manifest of the
    retired vintage is read with the TOP1M data of that same vintage -- its inline list."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=["popularcdn.com"])
    (tmp_path / "pfb_py_top1m.txt").write_text("sidecar.example\n", encoding="utf-8")

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None
    assert set(result.data_db) == {"blocked.example", "sidecar.example", "legacy.example", "www.legacy.example"}
    assert result.zone_db == {}
    assert result.white_db == {}
