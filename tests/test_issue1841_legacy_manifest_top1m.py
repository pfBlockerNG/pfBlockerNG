"""Issue #1841 -- a package upgrade must never take DNSBL down just because the
manifest schema moved.

A box upgraded across the TOP1M externalisation (#1542) keeps its pre-retirement
``pfb_py_sources.json`` until the next full update rewrites it. That manifest still
carries ``config.top1m_list`` (the inline TOP1M whitelist) and predates the
``pfb_py_top1m.txt`` sidecar. The manifest validator rejected the whole generation on
the retired key, so the resolver served no DNSBL at all until a full sync succeeded.

Intended behaviour pinned here: the retired key is TOLERATED with a one-line warning,
the generation builds, and -- because the sidecar of that vintage does not exist -- the
retired inline list is what feeds the TOP1M whitelist, so the box keeps exactly the
DNSBL it had before the upgrade.
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
    (tmp_path / "feed.raw").write_text("blocked.example\npopularcdn.com\n", encoding="utf-8")
    config: dict[str, object] = {"user_whitelist": [], "top1m_enabled": top1m_enabled}
    if top1m_list is not None:
        config["top1m_list"] = top1m_list
    path = tmp_path / "pfb_py_sources.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "config": config,
                "feeds": [{"raw": "feed.raw", "feed": "feed", "group": "g", "log_flag": "1"}],
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
    assert "blocked.example" in result.data_db
    assert result.white_db == {}, "TOP1M is off -- the retired list must not whitelist anything"
    warning = capsys.readouterr().err
    assert RETIRED_KEY_WARNING in warning
    assert "ignoring it (TOP1M is disabled)" in warning


def test_legacy_manifest_with_top1m_enabled_keeps_its_top1m_whitelist(tmp_path: Path) -> None:
    """TOP1M on + no sidecar of that vintage: the retired inline list is the source,
    so a popular domain listed by a feed keeps resolving exactly as before the upgrade."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=["popularcdn.com"])
    assert not (tmp_path / "pfb_py_top1m.txt").exists(), "pre-#1542 manifests predate the sidecar"

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None
    assert "blocked.example" in result.data_db
    assert P.whitelist_check_domain("popularcdn.com", result.white_db, 1)
    assert result.white_db["popularcdn.com"]["important"] is True


@pytest.mark.parametrize(
    "comma_framed",
    [".legacy.example,,", ",legacy.example,,", ",www.legacy.example,,"],
    ids=["wildcard-record", "exact-record", "www-record"],
)
def test_real_legacy_vintage_records_build_and_whitelist_nothing(
    tmp_path: Path, comma_framed: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The producer vintage that emitted ``top1m_list`` wrote comma-framed records, and
    the consumer of that vintage stored them as exact keys no query could ever match.
    Reading the inline list reproduces that inert whitelist rather than inventing
    coverage: the generation builds, the retirement is announced, nothing is allowed --
    the same outcome the sidecar path pins for these records
    (test_issue1542_top1m_fixed_file.py::test_enabled_rejects_retired_comma_framed_top1m_lines)."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=[comma_framed])

    result = P.dnsbl_build_from_manifest(manifest)

    assert result is not None, "a real legacy manifest must still load its feeds"
    assert "blocked.example" in result.data_db
    assert result.white_db == {}, f"retired TOP1M record became a whitelist key: {result.white_db!r}"
    assert RETIRED_KEY_WARNING in capsys.readouterr().err


def test_legacy_manifest_warns_once_about_the_retired_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The tolerated retirement is operator-visible -- one warning, not silence."""
    manifest = _manifest(tmp_path, top1m_enabled=True, top1m_list=["popularcdn.com"])

    assert P.dnsbl_build_from_manifest(manifest) is not None

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
    assert set(result.white_db) == {"sidecar.example"}
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
    assert set(result.white_db) == {"popularcdn.com"}
