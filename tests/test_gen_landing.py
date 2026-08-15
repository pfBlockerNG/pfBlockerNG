"""Tests for scripts/gen_landing.py — the human-navigable pkg-repo landing page.

The generator turns a built four-channel catalogue tree (stable/testing/edge/nightly,
issue #2147) into a styled index: channel install cards, a Version x ABI table read
from each .pkg manifest, and per-dir listings that show packages but hide pkg(8) catalog
plumbing. Most cases inject the manifest reader or exercise pure render helpers. The
record-epoch HTML pin (issue #2401) builds a real libpkg fixture for the listing
and landing rows.
"""

from __future__ import annotations

import importlib.util
import inspect
import io
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pfb_pkg
import pytest

# Load scripts/gen_landing.py (a script path, not an installed module).
_SPEC = importlib.util.spec_from_file_location(
    "gen_landing", Path(__file__).resolve().parent.parent / "scripts" / "gen_landing.py"
)
assert _SPEC and _SPEC.loader
gl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gl)

# Paths to the real scripts — used wherever tests exercise the live integration
# (write_site + write_add_repo) rather than fake fixtures.
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
_ADD_REPO_REAL = _SCRIPTS_DIR / "add-repo.sh"

_CANON = gl.CANONICAL_EMITTED_IDENTITY  # "pfSense-pkg-pfBlockerNG" — the ONE channel-agnostic identity


# ── Pure helpers ──────────────────────────────────────────────────────────────


def test_channel_of_path_maps_each_known_channel_and_rejects_unknown() -> None:
    """Channel comes from the catalogue PATH (first segment under the site root), never
    from the package name — the suffix-based channel_of() is retired (issue #2147)."""
    assert gl.channel_of_path("stable/ce-2.8/x.pkg") == "stable"
    assert gl.channel_of_path("testing/ce-2.8/x.pkg") == "testing"
    assert gl.channel_of_path("edge/ce-2.8/x.pkg") == "edge"
    assert gl.channel_of_path("nightly/ce-2.8/x.pkg") == "nightly"
    # An unrecognized top-level segment (a stray dir, or the retired 'release/' path) is
    # NOT a channel — the caller drops the package from every channel-scoped view.
    assert gl.channel_of_path("release/ce-2.8/x.pkg") is None
    assert gl.channel_of_path("quarantine/ce-2.8/x.pkg") is None
    assert not hasattr(gl, "channel_of"), "the suffix-based channel_of() must be retired"


def test_is_package_file_excludes_catalog_plumbing() -> None:
    """A real package is a .pkg; packagesite.pkg / data.pkg / non-.pkg are not."""
    assert gl.is_package_file(f"{_CANON}-3.2.16.pkg")
    assert not gl.is_package_file("packagesite.pkg")
    assert not gl.is_package_file("data.pkg")
    assert not gl.is_package_file("meta.conf")


def test_is_pfblockerng_package_keys_on_the_one_canonical_identity_only() -> None:
    """Every channel serves the SAME canonical package (issue #2147) — channel is
    catalogue placement, not a name suffix. The legacy suffixed identities no longer
    qualify, even though they used to be real channel packages."""
    assert gl.is_pfblockerng_package(_CANON)
    assert _CANON == "pfSense-pkg-pfBlockerNG"
    # The retired suffixed identities are no longer recognized.
    assert not gl.is_pfblockerng_package(f"{_CANON}-devel")
    assert not gl.is_pfblockerng_package(f"{_CANON}-nightly")
    # An unrelated dependency package (issue #1806) is never mistaken for it either.
    assert not gl.is_pfblockerng_package("py311-charset-normalizer")


def test_human_size_units() -> None:
    assert gl.human_size(512) == "512 B"
    assert gl.human_size(1024) == "1.0 KiB"
    assert gl.human_size(1024 * 1024 * 3) == "3.0 MiB"


def test_ver_key_orders_nightly_after_release() -> None:
    """The dated nightly version sorts above the bare PORTVERSION."""
    assert gl.ver_key("3.2.16.20260614.20") > gl.ver_key("3.2.16")
    assert gl.ver_key("3.2.16.20260614.20") > gl.ver_key("3.2.16.20260614.7")


def test_ver_key_orders_prerelease_stages_alpha_beta_rc_then_release() -> None:
    """ver_key ranks the release-tag stages the way FreeBSD pkg does (release-version.sh).

    A naive numeric-run key (re.findall(r"\\d+", v)) folds the stage keyword away
    entirely: 4.0.0.alpha.1 / .beta.1 / .rc.1 all collapsed to the SAME key [4,0,0,1],
    and the bare 4.0.0 release ([4,0,0]) sorted BELOW every prerelease. This bites
    when more than one prerelease build is retained per channel. Correct order:
    alpha < beta < rc < release.
    """
    versions = ["4.0.0.alpha.1", "4.0.0.beta.1", "4.0.0.rc.1", "4.0.0"]
    assert sorted(versions, key=gl.ver_key) == versions

    # Stage keywords must NOT compare equal — each is a distinct, ordered stage.
    assert gl.ver_key("4.0.0.alpha.1") < gl.ver_key("4.0.0.beta.1")
    assert gl.ver_key("4.0.0.beta.1") < gl.ver_key("4.0.0.rc.1")
    # The bare release ranks ABOVE every prerelease, not below.
    assert gl.ver_key("4.0.0.rc.1") < gl.ver_key("4.0.0")

    # The stage NUMBER still tie-breaks within one stage.
    assert gl.ver_key("4.0.0.alpha.1") < gl.ver_key("4.0.0.alpha.2")


def test_ver_key_preserves_numeric_prefix_ordering() -> None:
    """A shorter all-numeric version must sort BELOW its longer prefix-extension
    (build_edition_sections sorts rows by ver_key(pfsense_version), a bare
    edition version like '2.8' vs '2.8.1'). A flat [*base, stage_rank, stage_num]
    key breaks this -- see pfb_pkg.pkg_version_sort_key's docstring for why the
    nested (base, stage_rank, stage_num) tuple fixes it.
    """
    assert gl.ver_key("2.8") < gl.ver_key("2.8.1")
    assert gl.ver_key("4.0.0") < gl.ver_key("4.0.0.1")


def test_ver_key_full_multi_version_sort_matches_pkg_order() -> None:
    """A shuffled multi-version list sorts into the exact pkg-defined order."""
    shuffled = [
        "4.0.0",
        "4.0.0.rc.1",
        "4.0.0.alpha.2",
        "4.0.0.beta.1",
        "4.0.0.alpha.1",
        "4.0.1.alpha.1",
    ]
    expected = [
        "4.0.0.alpha.1",
        "4.0.0.alpha.2",
        "4.0.0.beta.1",
        "4.0.0.rc.1",
        "4.0.0",
        "4.0.1.alpha.1",
    ]
    assert sorted(shuffled, key=gl.ver_key) == expected


def test_artifact_datetime_is_utc_minute_precision() -> None:
    """A Unix epoch formats to a UTC, minute-precision datetime.

    Two artifacts created on the same day differ by time, so the column must carry
    the time-of-day — not just the date.
    """
    morning = datetime(2026, 6, 14, 3, 5, 40, tzinfo=timezone.utc).timestamp()
    evening = datetime(2026, 6, 14, 21, 47, 0, tzinfo=timezone.utc).timestamp()
    assert gl.artifact_datetime(morning) == "2026-06-14 03:05 UTC"
    assert gl.artifact_datetime(evening) == "2026-06-14 21:47 UTC"
    assert gl.artifact_datetime(morning) != gl.artifact_datetime(evening)  # same day, distinct


def test_published_datetime_prefers_created_annotation() -> None:
    """Scenario: a daily republish must NOT reset an artifact's shown creation time.

    Given a .pkg whose manifest carries a `created` build annotation (the source
    commit epoch) AND a much-later mtime (a re-download/rebuild 'today'),
    When the published datetime is computed,
    Then the annotation wins — so a rebuilt channel stops showing the republish date.
    And with no annotation, it falls back to the mtime.
    """
    commit_epoch = datetime(2026, 6, 10, 5, 52, tzinfo=timezone.utc).timestamp()
    republish_mtime = datetime(2026, 6, 14, 9, 38, tzinfo=timezone.utc).timestamp()
    manifest_with = {"annotations": {"commit": "deadbeef", "created": str(int(commit_epoch))}}
    assert gl.published_datetime(manifest_with, republish_mtime) == "2026-06-10 05:52 UTC"
    # No annotation -> mtime fallback.
    assert gl.published_datetime({"annotations": {}}, republish_mtime) == "2026-06-14 09:38 UTC"
    assert gl.published_datetime({}, republish_mtime) == "2026-06-14 09:38 UTC"
    # Malformed annotation -> mtime fallback, not a crash.
    assert gl.published_datetime({"annotations": {"created": "nope"}}, republish_mtime) == "2026-06-14 09:38 UTC"
    # Numeric-but-out-of-range epoch (inf / huge) -> mtime fallback, not a crash on the
    # whole page (datetime.fromtimestamp raises OverflowError/OSError, not ValueError).
    assert gl.published_datetime({"annotations": {"created": "1e309"}}, republish_mtime) == "2026-06-14 09:38 UTC"
    assert (
        gl.published_datetime({"annotations": {"created": "999999999999999999"}}, republish_mtime)
        == "2026-06-14 09:38 UTC"
    )


def test_published_datetime_falls_back_to_build_record_epoch() -> None:
    """Scenario: release builds embed pfb_build_record but no `created` annotation.

    Given a .pkg whose only annotation is `pfb_build_record` (the release/nightly
    builders stamp the record, and nothing stamps `created` — issue #2375),
    When the published datetime is computed,
    Then the record's `source_date_epoch` wins over the checkout mtime,
    And a bare `created` annotation still takes precedence over the record,
    And a malformed/incomplete record falls back to mtime instead of crashing.
    """
    import json

    commit_epoch = datetime(2026, 8, 14, 19, 32, tzinfo=timezone.utc).timestamp()
    republish_mtime = datetime(2026, 8, 14, 22, 5, tzinfo=timezone.utc).timestamp()
    record = json.dumps({"source_date_epoch": int(commit_epoch), "source_sha": "f" * 40})
    manifest_record_only = {"annotations": {"pfb_build_record": record}}
    assert gl.published_datetime(manifest_record_only, republish_mtime) == "2026-08-14 19:32 UTC"
    # `created` still wins when both are present.
    created_epoch = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc).timestamp()
    both = {"annotations": {"created": str(int(created_epoch)), "pfb_build_record": record}}
    assert gl.published_datetime(both, republish_mtime) == "2026-08-01 00:00 UTC"
    # Malformed record JSON, record without the key, non-numeric epoch -> mtime fallback.
    for bad in ("{not json", json.dumps({}), json.dumps({"source_date_epoch": "nope"})):
        assert (
            gl.published_datetime({"annotations": {"pfb_build_record": bad}}, republish_mtime) == "2026-08-14 22:05 UTC"
        )


def test_commit_sha_falls_back_to_build_record_source_sha() -> None:
    """Scenario: the Commit column must work for record-only packages too.

    Given a manifest with no `commit` annotation but a pfb_build_record carrying
    `source_sha`, the resolved sha is the record's; a bare `commit` annotation wins
    when present; no annotation and no/bad record resolve to the empty string.
    """
    import json

    sha = "f2c5650a1768c5df2bf05fd2cd4ae938a2f566a8"
    record = json.dumps({"source_sha": sha})
    assert gl.commit_sha({"annotations": {"pfb_build_record": record}}) == sha
    assert gl.commit_sha({"annotations": {"commit": "deadbeef", "pfb_build_record": record}}) == "deadbeef"
    assert gl.commit_sha({"annotations": {}}) == ""
    assert gl.commit_sha({}) == ""
    assert gl.commit_sha({"annotations": {"pfb_build_record": "{not json"}}) == ""


def test_dir_entries_use_record_epoch_for_pkg_files(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: the per-directory listing must not show the publish run's mtime for packages.

    Given a cell directory holding a .pkg (whose embedded build record carries
    source_date_epoch) and a catalog plumbing file,
    When the directory entries are scanned,
    Then the .pkg row carries the record epoch while the plumbing file keeps its mtime,
    And an unreadable .pkg (corrupt/foreign) falls back to its mtime instead of crashing.
    """
    record_epoch = int(datetime(2026, 8, 14, 19, 32, tzinfo=timezone.utc).timestamp())
    project = tmp_path / "pfSense-pkg-pfBlockerNG-3.3.2.pkg"
    project.write_bytes(b"not a real pkg")
    (tmp_path / "broken.pkg").write_bytes(b"also not a pkg")
    (tmp_path / "packagesite.pkg").write_bytes(b"catalog")
    (tmp_path / "meta.conf").write_text("meta")

    def fake_read(path: str) -> dict:
        if path.endswith("broken.pkg"):
            raise ValueError("corrupt")
        return {"annotations": {"pfb_build_record": json.dumps({"source_date_epoch": record_epoch})}}

    monkeypatch.setattr(gl, "read_compact_manifest", fake_read)
    _, files = gl._dir_entries(str(tmp_path), "")
    by_name = {name: mtime for name, _size, mtime in files}
    assert by_name["pfSense-pkg-pfBlockerNG-3.3.2.pkg"] == float(record_epoch)
    assert by_name["broken.pkg"] == os.stat(tmp_path / "broken.pkg").st_mtime
    assert by_name["meta.conf"] == os.stat(tmp_path / "meta.conf").st_mtime
    # Catalog plumbing stays on mtime even when the stub would hand it a record
    # (is_package_file is the gate — issue #2401 leftover of path.endswith(".pkg")).
    assert by_name["packagesite.pkg"] == os.stat(tmp_path / "packagesite.pkg").st_mtime
    # Out-of-range epoch (inf) must fall back to mtime, not crash the renderer later.
    monkeypatch.setattr(
        gl,
        "read_compact_manifest",
        lambda _p: {"annotations": {"created": "1e309"}},
    )
    _, files = gl._dir_entries(str(tmp_path), "")
    by_name = {name: mtime for name, _size, mtime in files}
    assert by_name["broken.pkg"] == os.stat(tmp_path / "broken.pkg").st_mtime
    assert by_name[project.name] == os.stat(project).st_mtime


# Record-only fixture used by the write_site HTML pin (issue #2401). Epochs are
# the ticket's own numbers so a listing/landing mismatch is visible in the assert.
_RECORD_EPOCH = 1786735920  # 2026-08-14 19:32 UTC
_FILE_MTIME = 1786750000  # 2026-08-14 23:26 UTC
_SOURCE_SHA = "f2c5650a1768c5df2bf05fd2cd4ae938a2f566a8"
_RECORD_DATE = "2026-08-14 19:32 UTC"
_MTIME_DATE = "2026-08-14 23:26 UTC"


def _write_pkg(path: Path, *, annotations: dict[str, str], name: str = _CANON, version: str = "3.3.2") -> None:
    """Write a libpkg-shaped .pkg whose +COMPACT_MANIFEST carries *annotations*."""
    manifest: dict[str, Any] = {
        "name": name,
        "origin": f"net/{name}",
        "version": version,
        "comment": "demo",
        "maintainer": "dev@example.com",
        "www": "https://example.com",
        "abi": "FreeBSD:15:*",
        "arch": "freebsd:15:x86:64",
        "prefix": "/usr/local",
        "flatsize": 1,
        "licenselogic": "single",
        "desc": "demo",
        "categories": ["net"],
        "annotations": annotations,
    }
    compact = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        info = tarfile.TarInfo(name="+COMPACT_MANIFEST")
        info.size = len(compact)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(compact))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), RuntimeError, "zstd unavailable"))


def _autoindex_row(html: str, name: str) -> str:
    needle = f">{name}</a>"
    for chunk in html.split("<tr>"):
        if needle in chunk:
            return chunk
    raise AssertionError(f"no autoindex row for {name!r}")


def _record_only_cell(root: Path) -> tuple[Path, Path]:
    """Cell dir with a record-only project .pkg plus catalog plumbing, all utime-pinned."""
    cell = root / "stable" / "ce-2.8"
    pkg = cell / f"{_CANON}-3.3.2.pkg"
    record = json.dumps({"source_date_epoch": _RECORD_EPOCH, "source_sha": _SOURCE_SHA})
    _write_pkg(pkg, annotations={pfb_pkg.PFB_BUILD_RECORD_KEY: record})
    (cell / "packagesite.pkg").write_bytes(b"catalog")
    (cell / "data.pkg").write_bytes(b"data")
    (cell / "meta.conf").write_text("version = 2;\n")
    for child in cell.iterdir():
        os.utime(child, (_FILE_MTIME, _FILE_MTIME))
    return root, cell


def test_artifact_epoch_prefers_created_then_record_then_mtime() -> None:
    """One resolver: created annotation, then pfb_build_record, then the file mtime."""
    record = json.dumps({"source_date_epoch": _RECORD_EPOCH, "source_sha": _SOURCE_SHA})
    created = {"annotations": {"created": "10", pfb_pkg.PFB_BUILD_RECORD_KEY: record}}
    assert gl.artifact_epoch(created, float(_FILE_MTIME)) == 10.0
    assert gl.artifact_epoch({"annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: record}}, float(_FILE_MTIME)) == float(
        _RECORD_EPOCH
    )
    # Out-of-range created falls through to the record, then to mtime.
    assert gl.artifact_epoch(
        {"annotations": {"created": "1e309", pfb_pkg.PFB_BUILD_RECORD_KEY: record}}, float(_FILE_MTIME)
    ) == float(_RECORD_EPOCH)
    assert gl.artifact_epoch({"annotations": {"created": "1e309"}}, float(_FILE_MTIME)) == float(_FILE_MTIME)
    assert gl.artifact_epoch({}, float(_FILE_MTIME)) == float(_FILE_MTIME)
    assert gl.artifact_epoch({"annotations": ["not", "a", "map"]}, float(_FILE_MTIME)) == float(_FILE_MTIME)
    assert gl.artifact_epoch({"annotations": "created=1"}, float(_FILE_MTIME)) == float(_FILE_MTIME)


def test_published_datetime_and_display_epoch_share_artifact_epoch(tmp_path: Path, monkeypatch: Any) -> None:
    """Both display surfaces call artifact_epoch (issue #2401)."""
    src_pub = inspect.getsource(gl.published_datetime)
    src_disp = inspect.getsource(gl._display_epoch)
    assert "artifact_epoch(" in src_pub
    assert "artifact_epoch(" in src_disp

    sentinel = 1111111111.0
    seen: list[tuple[dict, float]] = []

    def fake_epoch(manifest: dict, mtime: float) -> float:
        seen.append((manifest, mtime))
        return sentinel

    monkeypatch.setattr(gl, "artifact_epoch", fake_epoch)
    assert gl.published_datetime({"annotations": {"created": "1"}}, 9.0) == gl.artifact_datetime(sentinel)

    pkg = tmp_path / f"{_CANON}-3.3.2.pkg"
    pkg.write_bytes(b"x")
    monkeypatch.setattr(gl, "read_compact_manifest", lambda _p: {"annotations": {}})
    assert gl._display_epoch(str(pkg), 22.0) == sentinel
    assert len(seen) == 2


def test_catalog_pkg_keeps_mtime_when_manifest_reader_returns_record(tmp_path: Path, monkeypatch: Any) -> None:
    """packagesite.pkg / data.pkg must not inherit a stubbed project record.

    is_package_file is the gate: even if read_compact_manifest would return the
    project record for every path, catalog .pkg files keep their mtime.
    """
    cell = tmp_path / "cell"
    cell.mkdir()
    project = cell / f"{_CANON}-3.3.2.pkg"
    site_pkg = cell / "packagesite.pkg"
    data_pkg = cell / "data.pkg"
    project.write_bytes(b"pkg")
    site_pkg.write_bytes(b"catalog")
    data_pkg.write_bytes(b"data")
    for path in (project, site_pkg, data_pkg):
        os.utime(path, (_FILE_MTIME, _FILE_MTIME))

    record = json.dumps({"source_date_epoch": _RECORD_EPOCH, "source_sha": _SOURCE_SHA})
    monkeypatch.setattr(
        gl,
        "read_compact_manifest",
        lambda _p: {"annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: record}},
    )
    _, files = gl._dir_entries(str(cell), "")
    by_name = {name: mtime for name, _size, mtime in files}
    assert by_name[project.name] == float(_RECORD_EPOCH)
    assert by_name["packagesite.pkg"] == float(_FILE_MTIME)
    assert by_name["data.pkg"] == float(_FILE_MTIME)


def test_write_site_record_only_pkg_drives_listing_and_landing(tmp_path: Path, monkeypatch: Any) -> None:
    """A real record-only compact-manifest fixture drives write_site (issue #2401).

    The cell listing and the landing Published / Commit cells show the record
    epoch / source_sha, not the file mtime.
    """
    site, cell = _record_only_cell(tmp_path / "site")
    # Prove the archive is a real record-only compact manifest before rendering.
    compact = pfb_pkg.read_compact_manifest(cell / f"{_CANON}-3.3.2.pkg")
    annotations = compact.get("annotations") or {}
    assert "created" not in annotations
    assert "commit" not in annotations
    assert pfb_pkg.PFB_BUILD_RECORD_KEY in annotations

    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")
    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_ADD_REPO_REAL))
    assert n == 1

    listing = (cell / "index.html").read_text()
    pkg_row = _autoindex_row(listing, f"{_CANON}-3.3.2.pkg")
    assert _RECORD_DATE in pkg_row
    assert _MTIME_DATE not in pkg_row
    for plumbing in ("packagesite.pkg", "data.pkg", "meta.conf"):
        row = _autoindex_row(listing, plumbing)
        assert _RECORD_DATE not in row
        assert _MTIME_DATE in row

    landing = (site / "index.html").read_text()
    assert _RECORD_DATE in landing
    assert _MTIME_DATE not in landing
    assert f"{gl.SOURCE_REPO_URL}/commit/{_SOURCE_SHA}" in landing
    assert f">{_SOURCE_SHA[:7]}<" in landing


def test_write_site_out_of_range_created_on_project_pkg_falls_back(tmp_path: Path, monkeypatch: Any) -> None:
    """created=1e309 on the project .pkg falls back to mtime; write_site does not raise."""
    site = tmp_path / "site"
    cell = site / "stable" / "ce-2.8"
    pkg = cell / f"{_CANON}-3.3.2.pkg"
    _write_pkg(pkg, annotations={"created": "1e309"})
    os.utime(pkg, (_FILE_MTIME, _FILE_MTIME))

    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")
    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_ADD_REPO_REAL))
    assert n == 1
    listing = (cell / "index.html").read_text()
    assert _MTIME_DATE in _autoindex_row(listing, pkg.name)
    landing = (site / "index.html").read_text()
    assert _MTIME_DATE in landing


def test_commit_cell_links_valid_sha_and_dashes_missing() -> None:
    """The Commit column links a short SHA to GitHub, and degrades safely.

    Every input class is covered: a real SHA renders a 7-char link to the commit on
    the source repo; an absent annotation (older asset) and a non-hex value both
    render an em dash, never a broken or unsafe link.
    """
    full = "9d4b0b4556edca49b856c093838ccd0e2e91736b"
    cell = gl.commit_cell(full)
    assert f'href="{gl.SOURCE_REPO_URL}/commit/{full}"' in cell  # full SHA in the URL
    assert ">9d4b0b4<" in cell  # 7-char short SHA shown
    # Missing / blank annotation -> em dash, no link.
    for missing in ("", "   ", None):
        assert gl.commit_cell(missing) == '<span class="empty">&mdash;</span>'  # type: ignore[arg-type]
    # Non-hex / junk -> em dash (the hex guard keeps untrusted text out of the URL).
    assert "href" not in gl.commit_cell("not-a-sha")
    assert "href" not in gl.commit_cell("../../evil")


# Manifest reading now lives in the shared pfb_pkg module (gen_landing imports
# read_compact_manifest); its zstd-decoder-absent error is covered in
# tests/test_pfb_pkg.py.


# ── collect_packages: walk + classify + exclude plumbing ──────────────────────


def _touch(path: Path, size: int = 10) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def test_collect_packages_walks_and_excludes_metadata(tmp_path: Path) -> None:
    """Given a four-channel catalog tree with packages + pkg(8) metadata, collect only
    packages, with the channel read from each package's catalogue placement (path)."""
    # Given: a testing + nightly bucket per channel/ABI, each also holding catalog plumbing.
    site = tmp_path / "site"
    layout = {
        f"testing/FreeBSD:16:amd64/{_CANON}-3.2.16.pkg": (_CANON, "3.2.16"),
        f"nightly/FreeBSD:16:amd64/{_CANON}-3.2.16.20260614.7.pkg": (_CANON, "3.2.16.20260614.7"),
    }
    for rel in layout:
        _touch(site / rel)
    for rel in ("testing/FreeBSD:16:amd64", "nightly/FreeBSD:16:amd64"):
        _touch(site / rel / "packagesite.pkg")
        _touch(site / rel / "data.pkg")
        (site / rel / "meta.conf").write_text("version = 2;\n")

    def fake_read(path: str) -> dict[str, Any]:
        name, ver = layout[os.path.relpath(path, site)]
        return {
            "name": name,
            "version": ver,
            "abi": Path(path).parent.name,
            "annotations": {"commit": "cafe1234"},
            "deps": {"php85": {}, "php85-intl": {}, "py311": {}, "py311-sqlite3": {}, "python311": {}},
        }

    # When
    pkgs = gl.collect_packages(str(site), read_manifest=fake_read)

    # Then: only the two real packages, correctly classified by PATH; no packagesite/data.
    assert {p["name"] for p in pkgs} == {_CANON}
    assert {p["channel"] for p in pkgs} == {"testing", "nightly"}
    assert all(p["rel"].endswith(".pkg") for p in pkgs)
    assert not any("packagesite" in p["rel"] or "data.pkg" in p["rel"] for p in pkgs)
    # The source-commit annotation is carried onto each row (drives the Commit column).
    assert {p["commit"] for p in pkgs} == {"cafe1234"}
    # PHP/Python come from the manifest deps — the runtime flavor pkg, not its sub-packages.
    assert {p["php"] for p in pkgs} == {"8.5"}
    assert {p["py"] for p in pkgs} == {"3.11"}


def test_collect_packages_excludes_dependency_packages(tmp_path: Path) -> None:
    """A dependency package we publish is never treated as a pfBlockerNG build (issue #1863).

    The CE-only `py311-charset-normalizer` (issue #1806) ships in the same catalog dirs as
    our own packages. Its name is not the canonical identity, so a name-only classifier
    correctly excludes it — but this must hold in EVERY channel dir, not just one.

    Given a catalog tree holding a testing pfBlockerNG build plus the dependency package
      under BOTH the stable and the nightly channel dirs,
    When the packages are collected,
    Then only the pfBlockerNG build is returned and no channel claims the dependency version.
    """
    site = tmp_path / "site"
    layout = {
        f"testing/ce-2.8/{_CANON}-4.0.0.alpha.22.pkg": (_CANON, "4.0.0.alpha.22"),
        "stable/ce-2.8/py311-charset-normalizer-3.4.4.pkg": ("py311-charset-normalizer", "3.4.4"),
        "nightly/ce-2.8/py311-charset-normalizer-3.4.4.pkg": ("py311-charset-normalizer", "3.4.4"),
    }
    for rel in layout:
        _touch(site / rel)

    def fake_read(path: str) -> dict[str, Any]:
        name, ver = layout[os.path.relpath(path, site)]
        return {"name": name, "version": ver, "abi": "FreeBSD:15:*", "annotations": {}, "deps": {}}

    pkgs = gl.collect_packages(str(site), read_manifest=fake_read)

    assert {p["name"] for p in pkgs} == {_CANON}
    assert not any(p["version"] == "3.4.4" for p in pkgs)
    # The card-driving consequence: stable stays unpublished instead of borrowing 3.4.4.
    assert gl.latest_versions(pkgs) == {"testing": "4.0.0.alpha.22"}


def test_collect_packages_dir_with_only_catalog_meta_yields_no_channel_packages(tmp_path: Path) -> None:
    """A channel dir holding only pkg(8) catalog plumbing (no real .pkg yet) contributes
    nothing — the channel stays 'not yet published', not a crash reading a fake manifest."""
    site = tmp_path / "site"
    for ch in ("stable", "edge"):
        d = site / ch / "ce-2.8"
        _touch(d / "packagesite.pkg")
        _touch(d / "data.pkg")
        (d / "meta.conf").write_text("version = 2;\n")

    pkgs = gl.collect_packages(str(site))  # default real read_manifest — never invoked here

    assert pkgs == []


def test_collect_packages_legacy_suffixed_names_no_longer_hijack_a_channel(tmp_path: Path) -> None:
    """Model retired (issue #2147): a package still carrying the OLD suffixed identity
    (-devel/-nightly) is not the canonical package and must not become a channel row,
    even sitting inside a now-valid channel directory."""
    site = tmp_path / "site"
    _touch(site / "stable" / "ce-2.8" / f"{_CANON}-devel-4.0.0.alpha.1.pkg")
    _touch(site / "nightly" / "ce-2.8" / f"{_CANON}-nightly-20260810.pkg")

    def fake_read(path: str) -> dict[str, Any]:
        if "devel" in path:
            return {"name": f"{_CANON}-devel", "version": "4.0.0.alpha.1", "abi": "FreeBSD:15:*"}
        return {"name": f"{_CANON}-nightly", "version": "20260810", "abi": "FreeBSD:15:*"}

    pkgs = gl.collect_packages(str(site), read_manifest=fake_read)

    assert pkgs == []  # neither legacy-suffixed identity is the canonical package
    assert gl.latest_versions(pkgs) == {}


def test_collect_packages_and_write_site_skip_unknown_top_level_dir(tmp_path: Path, monkeypatch: Any) -> None:
    """A top-level dir that is not one of the four known channels is not a channel row.

    Given a catalog tree with a real 'stable/' channel package AND a stray unrecognized
    top-level dir ('quarantine/') holding what looks like a canonical package,
    When packages are collected / the site is written,
    Then only the real channel's package counts, the stray dir's file never appears in
    the packages table/cards, and write_site still succeeds (the stray dir stays
    browsable via its own autoindex — the directory walk doesn't consult channel_of_path).
    """
    site = tmp_path / "site"
    _touch(site / "stable" / "ce-2.8" / f"{_CANON}-1.0.0.pkg")
    _touch(site / "quarantine" / "ce-2.8" / f"{_CANON}-9.9.9.pkg")

    def fake_read(path: str) -> dict[str, Any]:
        version = "1.0.0" if "stable" in path else "9.9.9"
        return {"name": _CANON, "version": version, "abi": "FreeBSD:15:*"}

    pkgs = gl.collect_packages(str(site), read_manifest=fake_read)
    assert {p["channel"] for p in pkgs} == {"stable"}
    assert {p["version"] for p in pkgs} == {"1.0.0"}

    monkeypatch.setattr(gl, "read_compact_manifest", fake_read)
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")
    n = gl.write_site(str(site), "https://x/pkg", str(_ADD_REPO_REAL))

    assert n == 1
    index_html = (site / "index.html").read_text()
    assert "9.9.9" not in index_html
    # Still browsable: the stray dir gets its own autoindex, and appears in browse.html.
    assert (site / "quarantine" / "ce-2.8" / "index.html").is_file()
    browse = (site / "browse.html").read_text()
    assert '<a href="./quarantine/">quarantine/</a>' in browse


def test_write_site_resolves_latest_version_per_channel_from_path_fixtures(tmp_path: Path, monkeypatch: Any) -> None:
    """Latest-version resolution reads the channel from catalogue PATH, not package name —
    exercised across all four channels."""
    site = tmp_path / "site"
    versions = {"stable": "1.0.0", "testing": "1.1.0.b1", "edge": "2.0.0.a1", "nightly": "20260810"}
    for ch, ver in versions.items():
        _touch(site / ch / "ce-2.8" / f"{_CANON}-{ver}.pkg")

    def fake_read(path: str) -> dict[str, Any]:
        for ver in versions.values():
            if path.endswith(f"-{ver}.pkg"):
                return {"name": _CANON, "version": ver, "abi": "FreeBSD:15:*"}
        raise AssertionError(path)

    pkgs = gl.collect_packages(str(site), read_manifest=fake_read)

    assert gl.latest_versions(pkgs) == versions


# ── build_table: newest version per (channel, ABI) ────────────────────────────


def _pkg(channel: str, name: str, version: str, abi: str, rel: str, size: int = 10) -> dict[str, Any]:
    return {
        "channel": channel,
        "name": name,
        "version": version,
        "abi": abi,
        "rel": rel,
        "size": size,
        "published": "2026-06-14 09:38 UTC",
        "commit": "9d4b0b4556edca49b856c093838ccd0e2e91736b",
    }


def test_build_table_keeps_only_latest_nightly_per_abi() -> None:
    """Scenario: retention keeps several nightlies; the table shows only the newest.

    Given two nightly builds (old + new) for one ABI plus a testing build,
    When the table is built,
    Then the OLD nightly is dropped (proving newest-wins, not just 'all rows')
    and the testing + newest-nightly rows remain, channel-then-ABI sorted.
    """
    old = _pkg("nightly", _CANON, "3.2.16.20260601.1", "FreeBSD:16:amd64", "old.pkg")
    new = _pkg("nightly", _CANON, "3.2.16.20260614.9", "FreeBSD:16:amd64", "new.pkg")
    tst = _pkg("testing", _CANON, "3.2.16", "FreeBSD:16:amd64", "dev.pkg")

    rows = gl.build_table([new, old, tst])

    versions = [(r["channel"], r["version"]) for r in rows]
    assert ("nightly", "3.2.16.20260601.1") not in versions  # old build dropped
    assert versions == [("testing", "3.2.16"), ("nightly", "3.2.16.20260614.9")]  # sorted, latest only


def test_latest_versions_per_channel() -> None:
    pkgs = [
        _pkg("nightly", "n", "3.2.16.20260601.1", "a", "1"),
        _pkg("nightly", "n", "3.2.16.20260614.9", "a", "2"),
        _pkg("testing", "d", "3.2.16", "a", "3"),
    ]
    assert gl.latest_versions(pkgs) == {"nightly": "3.2.16.20260614.9", "testing": "3.2.16"}


# ── Edition split: matrix join → per-edition sections ─────────────────────────


def _mx(abi: str, ver: str, variant: str, php: str, py: str) -> dict[str, str]:
    """A supported-versions matrix entry, as read-version-matrix.sh --print-build emits."""
    return {"abi": abi, "pfsense_version": ver, "variant": variant, "php_version": php, "py_flavor": py}


def test_matrix_varver_strips_prerelease_suffix() -> None:
    """The landing page pins a row to the varver its packages are PUBLISHED under.

    A pre-release matrix entry ("26.07-BETA") carries the suffix inside the minor
    field; the publisher strips it (build-repo-portable.catalog_name_from_version),
    so this mirror must strip identically — otherwise the varver pin matches nothing
    and every row falls back to the unpinned pool (issue #1965).
    """
    assert gl._matrix_varver("26.07-BETA", "Plus") == "plus-26.07"
    assert gl._matrix_varver("2.9-RC1", "CE") == "ce-2.9"
    # Release versions are unaffected.
    assert gl._matrix_varver("26.03.1", "Plus") == "plus-26.03"
    assert gl._matrix_varver("2.8.1", "CE") == "ce-2.8"


def test_dotted_and_dep_flavor_formatting() -> None:
    """A flavor token / dep name formats to a dotted version; sub-packages don't match."""
    assert gl._dotted_ver("py311") == "3.11"
    assert gl._dotted_ver("php85") == "8.5"
    assert gl._dotted_ver("python314") == "3.14"
    assert gl._dotted_ver("nodigits") == ""
    # The runtime flavor pkg matches; its sub-packages (php85-intl, py311-sqlite3) do not.
    assert gl._dep_flavor(["php85-intl", "php85"], ("php",)) == "8.5"
    assert gl._dep_flavor(["py311-sqlite3", "python311"], ("py", "python")) == "3.11"
    assert gl._dep_flavor(["lighttpd", "jq"], ("php",)) == ""


def test_build_edition_sections_splits_and_shares_abi_across_versions() -> None:
    """Scenario: organize installables by pfSense edition, sharing a build across versions.

    Given testing builds for two ABIs, and a matrix where one ABI serves TWO pfSense
      versions (a CE and a Plus),
    When the edition sections are built,
    Then CE sorts before Plus; each row carries the matrix pfSense version + PHP/Python;
      and the shared-ABI build appears under BOTH editions (it installs on each, since
      pkg resolves on ABI alone).
    """
    p_ce = _pkg("testing", "d", "3.2.16", "FreeBSD:15:amd64", "a.pkg")
    p_shared = _pkg("testing", "d", "3.2.16", "FreeBSD:16:amd64", "b.pkg")
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:16:amd64", "2.9", "CE", "8.4", "py311"),
        _mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py312"),
    ]

    sections = dict(gl.build_edition_sections([p_ce, p_shared], matrix))

    assert [k for k, _ in gl.build_edition_sections([p_ce, p_shared], matrix)] == ["CE", "Plus"]
    # The shared ABI build appears under BOTH editions.
    assert any(r["abi"] == "FreeBSD:16:amd64" for r in sections["CE"])
    assert any(r["abi"] == "FreeBSD:16:amd64" for r in sections["Plus"])
    # Matrix php/py/version win per edition — proving the join, not a fixed value.
    plus = next(r for r in sections["Plus"] if r["abi"] == "FreeBSD:16:amd64")
    assert (plus["pfsense_version"], plus["php"], plus["py"]) == ("26.03", "8.5", "3.12")
    ce_29 = next(r for r in sections["CE"] if r["abi"] == "FreeBSD:16:amd64")
    assert (ce_29["pfsense_version"], ce_29["php"], ce_29["py"]) == ("2.9", "8.4", "3.11")


def test_build_edition_sections_wildcard_abi_joins_every_row_of_its_major() -> None:
    """A NO_ARCH package's manifest ABI is CPU-wildcarded (issue #1806, e.g.
    "FreeBSD:16:*") — it must join the matrix by OS+major, landing under EVERY
    edition/arch row of that major, never dropping to the unmatched "Other"
    section (the bug: an exact-string join misses it entirely).

    Scenario: one wildcard-ABI testing build, matrix has CE 2.9 (FreeBSD 16 amd64)
              AND Plus 26.03 (FreeBSD 16 amd64) — both major 16
      Given a testing .pkg whose manifest abi is "FreeBSD:16:*"
       When the edition sections are built
      Then it appears under BOTH CE and Plus (not "Other"), each carrying that
           edition's own matrix-joined pfSense version/php/py
    """
    p_wild = _pkg("testing", "d", "3.2.16", "FreeBSD:16:*", "w.pkg")
    matrix = [
        _mx("FreeBSD:16:amd64", "2.9", "CE", "8.4", "py311"),
        _mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py312"),
    ]

    sections = dict(gl.build_edition_sections([p_wild], matrix))

    assert "Other" not in sections, "a wildcard-ABI build must join the matrix, never fall to Other"
    assert set(sections) == {"CE", "Plus"}
    ce = sections["CE"][0]
    assert (ce["pfsense_version"], ce["php"], ce["py"]) == ("2.9", "8.4", "3.11")
    plus = sections["Plus"][0]
    assert (plus["pfsense_version"], plus["php"], plus["py"]) == ("26.03", "8.5", "3.12")


def test_build_edition_sections_wildcard_MATRIX_abi_joins_identically() -> None:
    """The MATRIX side is wildcarded too, and the join is unchanged by that.

    Every other matrix fixture here records a concrete ABI, but the publisher emits
    ``FreeBSD:<major>:*`` (pfBlockerNG/pkg: `arch` was retired from the matrix by
    issue #1806, so interpolating it produced the literal "FreeBSD:16:null"). With
    both sides wildcarded the exact-string index now HITS instead of falling back to
    the OS+major scan — a different code path in ``_join_matrix`` reaching the same
    rows. Pins that equivalence, so the production shape is covered and not merely
    assumed harmless.

    Given the same package set joined against a concrete-ABI matrix and a
      wildcard-ABI one,
    When the edition sections are built from each,
    Then both yield identical editions, versions, php and py.
    """
    pkgs = [_pkg("testing", "d", "3.2.16", "FreeBSD:16:*", "w.pkg")]
    concrete = [
        _mx("FreeBSD:16:amd64", "2.9", "CE", "8.4", "py311"),
        _mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py312"),
    ]
    wildcard = [
        _mx("FreeBSD:16:*", "2.9", "CE", "8.4", "py311"),
        _mx("FreeBSD:16:*", "26.03", "Plus", "8.5", "py312"),
    ]

    def shape(matrix: list[dict[str, str]]) -> list[tuple[str, str, str, str]]:
        return [
            (edition, r["pfsense_version"], r["php"], r["py"])
            for edition, rows in gl.build_edition_sections(pkgs, matrix)
            for r in rows
        ]

    assert shape(wildcard) == shape(concrete)
    # ...and the join really happened — nothing degraded to the unmatched section.
    assert shape(wildcard) == [("CE", "2.9", "8.4", "3.11"), ("Plus", "26.03", "8.5", "3.12")]


def test_build_edition_sections_pins_a_published_row_to_its_own_varver_dir() -> None:
    """A published file is listed under the pfSense version of the dir it was published to.

    Two pfSense Plus varvers share one FreeBSD major, so a NO_ARCH package's wildcarded ABI
    (issue #1806) matches BOTH matrix rows. The catalog is published per varver, so each
    varver dir holds its own copy — broadcasting every copy to every matching matrix row
    cross-products them (issue #1863: a 26.03 row linking the plus-26.07 file and vice
    versa). The varver dir in the row's own path decides which pfSense version it belongs to.

    Given one wildcard-ABI testing build published under BOTH plus-26.03/ and plus-26.07/,
      and a matrix whose 26.03 and 26.07 Plus rows share FreeBSD major 16,
    When the edition sections are built,
    Then each file appears exactly once, under the pfSense version of its own varver dir.
    """
    p_2603 = _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:16:*", "testing/plus-26.03/d.pkg")
    p_2607 = _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:16:*", "testing/plus-26.07/d.pkg")
    matrix = [
        _mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py311"),
        _mx("FreeBSD:16:amd64", "26.07", "Plus", "8.5", "py311"),
    ]

    sections = dict(gl.build_edition_sections([p_2603, p_2607], matrix))

    assert set(sections) == {"Plus"}
    assert {(r["pfsense_version"], r["rel"]) for r in sections["Plus"]} == {
        ("26.03", "testing/plus-26.03/d.pkg"),
        ("26.07", "testing/plus-26.07/d.pkg"),
    }


def test_build_edition_sections_one_row_per_pfsense_minor_whatever_the_flavor_set() -> None:
    """One row per pfSense minor release per table, each linking a single .pkg (issue #1863).

    A pfSense minor can appear in the matrix several times — one entry per arch, and in
    general per FreeBSD/PHP/Python combination. Those are build-matrix facts, not separate
    downloads: since issue #1806 the catalog is arch-less, so a minor serves exactly ONE
    file per channel. Joining a published file to every matching entry would list that same
    minor once per flavor combination.

    Given a testing build published under testing/ce-2.8/,
      and a matrix carrying CE 2.8 twice (amd64 and aarch64),
    When the edition sections are built,
    Then CE 2.8 is listed exactly once.
    """
    p = _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:15:*", "testing/ce-2.8/d.pkg")
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:15:aarch64", "2.8", "CE", "8.3", "py311"),
    ]

    sections = dict(gl.build_edition_sections([p], matrix))

    assert [r["pfsense_version"] for r in sections["CE"]] == ["2.8"]


def test_sort_table_rows_breaks_a_version_tie_by_channel() -> None:
    """Rows tying on both versions still land in CH_ORDER — stable, testing, edge, nightly.

    Without the tie-break the order would depend on collection order, so the same catalog
    could render two different pages.
    """
    rows = [
        _pkg("nightly", "n", "3.2.16", "FreeBSD:15:*", "nightly/ce-2.8/n.pkg"),
        _pkg("edge", "e", "3.2.16", "FreeBSD:15:*", "edge/ce-2.8/e.pkg"),
        _pkg("stable", "s", "3.2.16", "FreeBSD:15:*", "stable/ce-2.8/s.pkg"),
        _pkg("testing", "t", "3.2.16", "FreeBSD:15:*", "testing/ce-2.8/t.pkg"),
    ]
    for r in rows:
        r["pfsense_version"] = "2.8"

    gl.sort_table_rows(rows)

    assert [r["channel"] for r in rows] == ["stable", "testing", "edge", "nightly"]


def test_build_edition_sections_keeps_distinct_files_a_legacy_layout_cannot_pin() -> None:
    """The one-row-per-minor rule collapses matrix flavors, never distinct published files.

    One pfSense minor serves one file only because the catalog is arch-less (issue #1806).
    A legacy per-ABI layout publishes a separate file per arch, and no such path names a
    varver, so those rows keep the matrix broadcast — they must also keep their own rows,
    or a published package silently disappears from the page (issue #1863).

    Given two per-arch files published for one pfSense minor under legacy per-ABI dirs,
      and a matrix entry per arch for that minor,
    When the edition sections are built,
    Then both files are listed.
    """
    p_amd64 = _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:16:amd64", "testing/FreeBSD:16:amd64/d.pkg")
    p_arm64 = _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:16:aarch64", "testing/FreeBSD:16:aarch64/d.pkg")
    matrix = [
        _mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py311"),
        _mx("FreeBSD:16:aarch64", "26.03", "Plus", "8.5", "py311"),
    ]

    sections = dict(gl.build_edition_sections([p_amd64, p_arm64], matrix))

    assert {r["rel"] for r in sections["Plus"]} == {
        "testing/FreeBSD:16:amd64/d.pkg",
        "testing/FreeBSD:16:aarch64/d.pkg",
    }


def test_build_edition_sections_sorted_by_pkg_version_then_pfsense_version_desc() -> None:
    """Table order: pfBlockerNG version desc, then pfSense version desc (issue #1863).

    Editions are already separate tables (CE before Plus), so within one table the
    pfBlockerNG version leads and the pfSense version breaks its ties — both newest-first.
    A pfSense-version-first order interleaves channels instead, burying the newest build.

    Given a testing and a nightly build, each published for CE 2.8 and CE 2.9,
    When the edition sections are built,
    Then the nightly rows come first (higher pfBlockerNG version), 2.9 before 2.8 in each.
    """
    pkgs = [
        _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:15:*", "testing/ce-2.8/d.pkg"),
        _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:15:*", "testing/ce-2.9/d.pkg"),
        _pkg("nightly", "n", "4.0.0.alpha.22.20260729.1", "FreeBSD:15:*", "nightly/ce-2.8/n.pkg"),
        _pkg("nightly", "n", "4.0.0.alpha.22.20260729.1", "FreeBSD:15:*", "nightly/ce-2.9/n.pkg"),
    ]
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:15:amd64", "2.9", "CE", "8.4", "py311"),
    ]

    sections = dict(gl.build_edition_sections(pkgs, matrix))

    assert [(r["version"], r["pfsense_version"]) for r in sections["CE"]] == [
        ("4.0.0.alpha.22.20260729.1", "2.9"),
        ("4.0.0.alpha.22.20260729.1", "2.8"),
        ("4.0.0.alpha.22", "2.9"),
        ("4.0.0.alpha.22", "2.8"),
    ]


def test_older_nightlies_one_row_per_nightly_version_per_pfsense_version() -> None:
    """Retention keeps several nightlies, so the disclosure lists one row per retained
    nightly version per pfSense version it was built for — same order rule as the main
    table: pfBlockerNG version desc, then pfSense version desc (issue #1863).

    Given two retained nightly versions, each published for CE 2.8 and CE 2.9,
    When the older-nightlies rows are grouped per edition,
    Then there are four rows, the newer nightly's pair first, 2.9 before 2.8 within each.
    """
    latest = _pkg("nightly", "n", "4.0.0.alpha.22.20260729.1", "FreeBSD:15:*", "nightly/ce-2.8/n3.pkg")
    pkgs = [
        latest,
        _pkg("nightly", "n", "4.0.0.alpha.22.20260728.1", "FreeBSD:15:*", "nightly/ce-2.8/n2.pkg"),
        _pkg("nightly", "n", "4.0.0.alpha.22.20260728.1", "FreeBSD:15:*", "nightly/ce-2.9/n2.pkg"),
        _pkg("nightly", "n", "4.0.0.alpha.22.20260727.1", "FreeBSD:15:*", "nightly/ce-2.8/n1.pkg"),
        _pkg("nightly", "n", "4.0.0.alpha.22.20260727.1", "FreeBSD:15:*", "nightly/ce-2.9/n1.pkg"),
    ]
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:15:amd64", "2.9", "CE", "8.4", "py311"),
    ]

    rows = gl._older_nightlies_by_edition(pkgs, matrix)["CE"]

    assert [(r["version"], r["pfsense_version"]) for r in rows] == [
        ("4.0.0.alpha.22.20260728.1", "2.9"),
        ("4.0.0.alpha.22.20260728.1", "2.8"),
        ("4.0.0.alpha.22.20260727.1", "2.9"),
        ("4.0.0.alpha.22.20260727.1", "2.8"),
    ]


def test_older_releases_sorted_by_pkg_version_then_pfsense_version_desc() -> None:
    """The retained older releases obey the same order rule (issue #1863).

    Given two retained testing versions, each published for CE 2.8 and CE 2.9,
    When the older-releases rows are grouped per edition,
    Then the newer version's pair leads, 2.9 before 2.8 within each.
    """
    pkgs = [
        _pkg("testing", "d", "4.0.0.alpha.22", "FreeBSD:15:*", "testing/ce-2.8/d3.pkg"),
        _pkg("testing", "d", "4.0.0.alpha.21", "FreeBSD:15:*", "testing/ce-2.8/d2.pkg"),
        _pkg("testing", "d", "4.0.0.alpha.21", "FreeBSD:15:*", "testing/ce-2.9/d2.pkg"),
        _pkg("testing", "d", "4.0.0.alpha.20", "FreeBSD:15:*", "testing/ce-2.8/d1.pkg"),
        _pkg("testing", "d", "4.0.0.alpha.20", "FreeBSD:15:*", "testing/ce-2.9/d1.pkg"),
    ]
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:15:amd64", "2.9", "CE", "8.4", "py311"),
    ]

    rows = gl._older_releases_by_edition(pkgs, matrix)["CE"]

    assert [(r["version"], r["pfsense_version"]) for r in rows] == [
        ("4.0.0.alpha.21", "2.9"),
        ("4.0.0.alpha.21", "2.8"),
        ("4.0.0.alpha.20", "2.9"),
        ("4.0.0.alpha.20", "2.8"),
    ]


def test_older_nightlies_lists_retained_excludes_latest() -> None:
    """Scenario: surface the retained older nightlies, never the current one.

    Given three nightly builds for one ABI (two old + the newest) plus a testing build,
    When the older-nightlies list is built,
    Then the NEWEST nightly is excluded (it's already in the edition table) and the two
      older ones remain, newest-first; testing/stable are never included.
    """
    new = _pkg("nightly", "n", "3.2.16.20260614.9", "FreeBSD:16:amd64", "n9.pkg")
    mid = _pkg("nightly", "n", "3.2.16.20260613.4", "FreeBSD:16:amd64", "n4.pkg")
    old = _pkg("nightly", "n", "3.2.16.20260601.1", "FreeBSD:16:amd64", "n1.pkg")
    tst = _pkg("testing", "d", "3.2.16", "FreeBSD:16:amd64", "d.pkg")

    rows = gl.older_nightlies([new, mid, old, tst])

    versions = [r["version"] for r in rows]
    assert versions == ["3.2.16.20260613.4", "3.2.16.20260601.1"]  # newest excluded, rest newest-first
    assert all(r["channel"] == "nightly" for r in rows)  # testing never listed
    # The packages block folds the two retained nightlies into a disclosure UNDER the edition
    # table, never the latest (which lives in the edition table itself).
    matrix = [_mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py311")]
    html = gl._packages_html([new, mid, old, tst], matrix)
    assert "<h3>Nightly</h3>" in html
    assert "<h4>pfSense Plus</h4>" in html
    assert "<details><summary>Older nightlies (2)</summary>" in html
    # The disclosure sits AFTER the edition's main table (folded under it).
    assert html.index("<h4>pfSense Plus</h4>") < html.index("Older nightlies (2)")
    details = html[html.index("Older nightlies (2)") :]
    assert "3.2.16.20260613.4" in details and "3.2.16.20260601.1" in details
    assert "3.2.16.20260614.9" not in details  # the current nightly stays out of the 'older' disclosure
    # The disclosure's table carries the same columns as the edition table, minus Channel.
    assert "<th>Channel</th>" not in details and "<th>pfSense</th>" in details
    assert ">26.03<" in details and ">8.5<" in details and ">3.11<" in details


def test_older_nightlies_empty_when_only_latest() -> None:
    """With a single nightly version present there is nothing 'older' to disclose."""
    only = _pkg("nightly", "n", "3.2.16.20260614.9", "FreeBSD:16:amd64", "n.pkg")
    assert gl.older_nightlies([only, _pkg("testing", "d", "3.2.16", "FreeBSD:16:amd64", "d.pkg")]) == []
    # …and the packages block omits the disclosure entirely (no empty 'Older nightlies' affordance).
    html = gl._packages_html([only], None)
    assert "Older nightlies" not in html
    # The Nightly heading identifies the channel, so the table does not repeat it as a column.
    assert "<h3>Nightly</h3>" in html
    assert "<h4>Other builds</h4>" in html
    assert "<th>Channel</th>" not in html


def test_older_nightlies_fold_under_each_edition() -> None:
    """Scenario: each edition's older nightlies fold UNDER that edition's own table.

    Given retained older nightlies for BOTH a CE ABI and a Plus ABI,
    When the packages block is rendered with a matrix covering both ABIs,
    Then the CE older-nightlies disclosure sits inside the CE section (after the CE table,
      before the Plus heading) carrying only CE rows, and the Plus one sits in the Plus
      section carrying only Plus rows — CE section first.
    """
    ce_new = _pkg("nightly", "n", "3.2.16.20260614.9", "FreeBSD:15:amd64", "ce9.pkg")
    ce_old = _pkg("nightly", "n", "3.2.16.20260601.1", "FreeBSD:15:amd64", "ce1.pkg")
    plus_new = _pkg("nightly", "n", "3.2.16.20260614.9", "FreeBSD:16:aarch64", "p9.pkg")
    plus_old = _pkg("nightly", "n", "3.2.16.20260601.1", "FreeBSD:16:aarch64", "p1.pkg")
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:16:aarch64", "26.03", "Plus", "8.5", "py311"),
    ]

    html = gl._packages_html([ce_new, ce_old, plus_new, plus_old], matrix)

    # Nightly owns CE then Plus; each edition has its own folded history.
    assert "<h3>Nightly</h3>" in html
    assert html.index("<h4>pfSense CE</h4>") < html.index("<h4>pfSense Plus</h4>")
    assert html.count("<summary>Older nightlies (1)</summary>") == 2  # one per edition (each ABI: 1 older)
    # The CE section spans from its heading to the Plus heading; the Plus section follows.
    ce_section = html[html.index("<h4>pfSense CE</h4>") : html.index("<h4>pfSense Plus</h4>")]
    plus_section = html[html.index("<h4>pfSense Plus</h4>") :]
    # Each edition's disclosure folds in its OWN ABI's older nightly, never the other's.
    assert "Older nightlies (1)" in ce_section and "FreeBSD:15:amd64" in ce_section
    assert "FreeBSD:16:aarch64" not in ce_section and ">2.8<" in ce_section and ">8.3<" in ce_section
    assert "Older nightlies (1)" in plus_section and "FreeBSD:16:aarch64" in plus_section
    assert "FreeBSD:15:amd64" not in plus_section and ">26.03<" in plus_section and ">8.5<" in plus_section


def test_older_releases_lists_retained_excludes_latest() -> None:
    """Scenario: surface the retained older stable/testing/edge releases, never the newest
    per channel.

    Given three testing versions (two old + the newest) and two stable versions (one old +
      the newest) for one ABI plus a nightly build,
    When the older-releases list is built,
    Then the NEWEST testing and the NEWEST stable are excluded (they are in the edition
      table already) and the two older testing + one older stable remain; nightly is never
      included.
    """
    dev_new = _pkg("testing", _CANON, "3.2.16", "FreeBSD:16:amd64", "d3.pkg")
    dev_mid = _pkg("testing", _CANON, "3.2.15", "FreeBSD:16:amd64", "d2.pkg")
    dev_old = _pkg("testing", _CANON, "3.2.14", "FreeBSD:16:amd64", "d1.pkg")
    stb_new = _pkg("stable", _CANON, "3.1.0", "FreeBSD:16:amd64", "s2.pkg")
    stb_old = _pkg("stable", _CANON, "3.0.0", "FreeBSD:16:amd64", "s1.pkg")
    nightly = _pkg("nightly", _CANON, "3.2.16.20260614.9", "FreeBSD:16:amd64", "n.pkg")
    all_pkgs = [dev_new, dev_mid, dev_old, stb_new, stb_old, nightly]

    # Before: the newest versions are NOT in older_releases (they live in the edition table).
    rows = gl.older_releases(all_pkgs)
    versions = [(r["channel"], r["version"]) for r in rows]
    assert ("testing", "3.2.16") not in versions  # newest testing stays out
    assert ("stable", "3.1.0") not in versions  # newest stable stays out
    assert ("nightly", "3.2.16.20260614.9") not in versions  # nightly never in older_releases

    # After (what's retained): two older testing + one older stable.
    assert ("testing", "3.2.15") in versions
    assert ("testing", "3.2.14") in versions
    assert ("stable", "3.0.0") in versions

    # The packages block scopes each disclosure to its own channel.
    matrix = [_mx("FreeBSD:16:amd64", "2.8", "CE", "8.3", "py311")]
    html = gl._packages_html(all_pkgs, matrix)
    assert html.index("<h3>Stable</h3>") < html.index("<h3>Testing</h3>") < html.index("<h3>Nightly</h3>")
    stable = html[html.index("<h3>Stable</h3>") : html.index("<h3>Testing</h3>")]
    testing = html[html.index("<h3>Testing</h3>") : html.index("<h3>Nightly</h3>")]
    assert "<h4>pfSense CE</h4>" in stable and "<h4>pfSense CE</h4>" in testing
    assert "Older releases (1)" in stable and "3.0.0" in stable and "3.2.15" not in stable
    assert "Older releases (2)" in testing and "3.2.15" in testing and "3.2.14" in testing
    assert "3.0.0" not in testing
    assert "<th>Channel</th>" not in html and "<th>pfSense</th>" in html


def test_older_releases_empty_when_only_latest_per_channel() -> None:
    """With only one version of each channel retained there is nothing 'older' to disclose.

    This is today's default (N=M=1): only the newest testing and stable live in the catalog.
    The disclosure is entirely absent from the rendered page — no empty affordance.
    """
    dev = _pkg("testing", _CANON, "3.2.16", "FreeBSD:16:amd64", "d.pkg")
    stb = _pkg("stable", _CANON, "3.1.0", "FreeBSD:16:amd64", "s.pkg")
    nightly = _pkg("nightly", _CANON, "3.2.16.20260614.9", "FreeBSD:16:amd64", "n.pkg")

    assert gl.older_releases([dev, stb, nightly]) == []
    # …and the packages block omits the disclosure entirely.
    assert "Older releases" not in gl._packages_html([dev, stb, nightly], None)


def test_older_releases_spans_stable_testing_and_edge_never_nightly() -> None:
    """older_releases generalizes to every non-nightly channel (issue #2147), not just two.

    Given a retained older build in EACH of stable, testing, and edge, plus a nightly
      build at the same ABI,
    When the older-releases list is built,
    Then all three non-nightly channels' older rows are present and nightly is absent.
    """
    pkgs = [
        _pkg("stable", _CANON, "1.0.0", "FreeBSD:16:amd64", "s2.pkg"),
        _pkg("stable", _CANON, "0.9.0", "FreeBSD:16:amd64", "s1.pkg"),
        _pkg("testing", _CANON, "1.1.0.b2", "FreeBSD:16:amd64", "t2.pkg"),
        _pkg("testing", _CANON, "1.1.0.b1", "FreeBSD:16:amd64", "t1.pkg"),
        _pkg("edge", _CANON, "2.0.0.a2", "FreeBSD:16:amd64", "e2.pkg"),
        _pkg("edge", _CANON, "2.0.0.a1", "FreeBSD:16:amd64", "e1.pkg"),
        _pkg("nightly", _CANON, "20260810", "FreeBSD:16:amd64", "n2.pkg"),
        _pkg("nightly", _CANON, "20260809", "FreeBSD:16:amd64", "n1.pkg"),
    ]

    rows = gl.older_releases(pkgs)

    channels = {r["channel"] for r in rows}
    assert channels == {"stable", "testing", "edge"}
    assert "nightly" not in channels


def test_packages_html_orders_channels_then_editions() -> None:
    """Published packages group by cadence channel, then pfSense edition."""
    channel_versions = (
        ("stable", "1.0.0"),
        ("testing", "1.1.0.r1"),
        ("edge", "2.0.0.a1"),
        ("nightly", "20260810"),
    )
    pkgs = [
        *[
            _pkg(channel, _CANON, version, "FreeBSD:15:*", f"{channel}/ce-2.8/c.pkg")
            for channel, version in channel_versions
        ],
        *[
            _pkg(channel, _CANON, version, "FreeBSD:16:*", f"{channel}/plus-26.03/p.pkg")
            for channel, version in channel_versions
        ],
    ]
    matrix = [
        _mx("FreeBSD:15:*", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:16:*", "26.03", "Plus", "8.5", "py311"),
    ]

    html = gl._packages_html(pkgs, matrix)

    assert html.index("<h3>Stable</h3>") < html.index("<h3>Testing</h3>")
    assert html.index("<h3>Testing</h3>") < html.index("<h3>Edge</h3>")
    assert html.index("<h3>Edge</h3>") < html.index("<h3>Nightly</h3>")
    for channel, next_channel in (("Stable", "Testing"), ("Testing", "Edge"), ("Edge", "Nightly")):
        section = html[html.index(f"<h3>{channel}</h3>") : html.index(f"<h3>{next_channel}</h3>")]
        assert section.index("<h4>pfSense CE</h4>") < section.index("<h4>pfSense Plus</h4>")
    nightly = html[html.index("<h3>Nightly</h3>") :]
    assert nightly.index("<h4>pfSense CE</h4>") < nightly.index("<h4>pfSense Plus</h4>")
    assert html.count('<div class="tablewrap"><table>') == 8
    assert "<th>Channel</th>" not in html


def test_older_releases_fold_under_each_edition() -> None:
    """Scenario: each edition's older releases fold UNDER that edition's own table.

    Given retained older testing releases for BOTH a CE ABI and a Plus ABI,
    When the packages block is rendered with a matrix covering both ABIs,
    Then the CE older-releases disclosure sits inside the CE section (after the CE table,
      before the Plus heading) carrying only CE rows, and the Plus one sits in the Plus
      section carrying only Plus rows — CE section first, Channel column present in each.
    """
    ce_new = _pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "ce2.pkg")
    ce_old = _pkg("testing", _CANON, "3.2.15", "FreeBSD:15:amd64", "ce1.pkg")
    plus_new = _pkg("testing", _CANON, "3.2.16", "FreeBSD:16:aarch64", "p2.pkg")
    plus_old = _pkg("testing", _CANON, "3.2.15", "FreeBSD:16:aarch64", "p1.pkg")
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:16:aarch64", "26.03", "Plus", "8.5", "py311"),
    ]

    html = gl._packages_html([ce_new, ce_old, plus_new, plus_old], matrix)

    # Testing owns CE then Plus; each edition has its own folded history.
    assert "<h3>Testing</h3>" in html
    assert html.index("<h4>pfSense CE</h4>") < html.index("<h4>pfSense Plus</h4>")
    assert html.count("<summary>Older releases (1)</summary>") == 2  # one per edition (each ABI: 1 older)
    # The CE section spans from its heading to the Plus heading; the Plus section follows.
    ce_section = html[html.index("<h4>pfSense CE</h4>") : html.index("<h4>pfSense Plus</h4>")]
    plus_section = html[html.index("<h4>pfSense Plus</h4>") :]
    # Each edition's disclosure folds in its OWN ABI's older release, never the other's.
    assert "Older releases (1)" in ce_section and "FreeBSD:15:amd64" in ce_section
    assert "FreeBSD:16:aarch64" not in ce_section and ">2.8<" in ce_section and ">8.3<" in ce_section
    assert "Older releases (1)" in plus_section and "FreeBSD:16:aarch64" in plus_section
    assert "FreeBSD:15:amd64" not in plus_section and ">26.03<" in plus_section and ">8.5<" in plus_section
    # The Testing heading identifies the channel; neither table repeats it as a column.
    assert "<th>Channel</th>" not in ce_section and "<th>Channel</th>" not in plus_section


def test_build_edition_sections_unmatched_abi_falls_to_other() -> None:
    """A build whose ABI the matrix doesn't cover lands in 'Other' (manifest php/py), not hidden."""
    p = _pkg("testing", "d", "3.2.16", "FreeBSD:14:amd64", "x.pkg")
    p["php"], p["py"] = "8.2", "3.9"  # manifest-derived fallback (no matrix row)

    sections = dict(gl.build_edition_sections([p], matrix=[]))

    assert list(sections) == ["Other"]
    row = sections["Other"][0]
    assert row["pfsense_version"] == "" and (row["php"], row["py"]) == ("8.2", "3.9")


# ── Rendering ─────────────────────────────────────────────────────────────────


def _stub_conf(channel: str) -> str:
    return f"{channel}-conf-snippet"


def test_render_page_renders_all_four_channel_cards_with_correct_content() -> None:
    """Each of the four channels gets its own card — title, audience prose, badge.

    An empty site is unpublished on every channel (issue #2382): cards keep the
    "not yet published" blurb and must not ship add-repo / pkg install / conf
    snippets.
    """
    base = "https://pfblockerng.github.io/pkg"
    page = gl.render_page(base, [], _stub_conf)

    titles = {"stable": "Stable", "testing": "Testing", "edge": "Edge", "nightly": "Nightly"}
    audience_anchor = {
        "stable": "final tagged releases",
        "testing": "nonzero-patch prereleases",
        "edge": "patch-zero prereleases",
        "nightly": "untagged snapshot builds",
    }
    for ch, title in titles.items():
        assert f'<div class="card {ch}">' in page
        assert f"<h3>{title}" in page
        assert audience_anchor[ch] in page.lower()
        assert f"--channel {ch}" not in page
        assert f"{ch}-conf-snippet" not in page
        # install-<ch>.sh present iff the channel is published — none are here.
        assert f"install-{ch}.sh" not in page
    assert "add-repo.sh" not in page
    assert "pkg install" not in page
    # Nightly keeps its stability badge.
    assert '<span class="badge">not for daily use</span>' in page
    assert "<code>YYYYMMDDHHMMSS.&lt;7-character source SHA&gt;</code>" in page
    assert page.count("not yet published") == 4


def test_render_page_shows_latest_and_empty_stable() -> None:
    """The page splits packages into per-edition tables; stable (absent here) is
    empty-stated in its card."""
    pkgs = [
        _pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "testing/ce-2.8/FreeBSD:15:amd64/d.pkg"),
        _pkg("testing", _CANON, "3.2.16", "FreeBSD:16:aarch64", "testing/plus-26.03/FreeBSD:16:aarch64/d.pkg"),
        _pkg(
            "nightly",
            _CANON,
            "3.2.16.20260614.9",
            "FreeBSD:16:aarch64",
            "nightly/plus-26.03/FreeBSD:16:aarch64/n.pkg",
        ),
    ]
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx("FreeBSD:16:aarch64", "26.03", "Plus", "8.5", "py311"),
    ]
    base = "https://pfblockerng.github.io/pkg"
    page = gl.render_page(base, pkgs, _stub_conf, matrix)

    # Latest versions surfaced for the present channels.
    assert "3.2.16.20260614.9" in page
    # Each channel splits into pfSense edition tables, CE before Plus.
    assert "<h4>pfSense CE</h4>" in page
    assert "<h4>pfSense Plus</h4>" in page
    assert page.index("pfSense CE") < page.index("pfSense Plus")
    # Each table carries the informative pfSense version + PHP + Python columns (joined
    # from the matrix), plus Published and Commit.
    for header in ("<th>pfSense</th>", "<th>PHP</th>", "<th>Python</th>", "<th>Published</th>", "<th>Commit</th>"):
        assert header in page
    assert ">2.8<" in page and ">26.03<" in page  # pfSense versions, per edition
    assert ">8.3<" in page and ">8.5<" in page  # PHP, per edition
    assert ">3.11<" in page  # Python
    assert "2026-06-14 09:38 UTC" in page
    # The Commit column links the short SHA to the source commit on GitHub.
    assert f'href="{gl.SOURCE_REPO_URL}/commit/9d4b0b4556edca49b856c093838ccd0e2e91736b"' in page
    assert ">9d4b0b4<" in page
    # Each table sits in an overflow-x wrapper so a mobile viewport scrolls the table,
    # not the whole page (the .tablewrap rule is what makes that scroll possible).
    assert '<div class="tablewrap"><table>' in page
    assert ".tablewrap{overflow-x:auto" in page
    # Stable (and edge) have no package -> empty state, no install recipe.
    assert "not yet published" in page
    assert "--channel stable" not in page
    assert "--channel edge" not in page
    assert "stable-conf-snippet" not in page
    assert "edge-conf-snippet" not in page
    # Published channels (testing, nightly) get the ONE-line per-channel installer
    # recipe (issue #2416) — no add-repo.sh, no migrate-channel.sh, no bare pkg install.
    assert f"fetch -qo - {base}/install-testing.sh | sh" in page
    assert f"fetch -qo - {base}/install-nightly.sh | sh" in page
    assert "add-repo.sh" not in page
    assert "migrate-channel.sh" not in page
    assert "pkg install" not in page
    assert "testing-conf-snippet" in page
    assert "nightly-conf-snippet" in page
    # The badge/title casing fix: no CSS capitalize that would mangle `pfSense-pkg-...`.
    assert "text-transform:capitalize" not in page
    # Card order follows CH_ORDER.
    assert '<div class="card stable">' in page
    assert '<div class="card testing">' in page
    assert '<div class="card edge">' in page
    assert '<div class="card nightly">' in page
    assert (
        page.index('"card stable"')
        < page.index('"card testing"')
        < page.index('"card edge"')
        < page.index('"card nightly"')
    )
    assert ".card.stable{border-color:var(--acc)}" in page
    assert ".card.testing{border-color:var(--warn)}" in page
    assert ".card.edge{border-color:var(--edge)}" in page
    assert ".card.nightly{border-color:var(--red)}" in page
    assert ".card.nightly .badge{border-color:var(--red);color:var(--red)}" in page
    # The catalog-trees list is replaced by a SINGLE link to the folder-navigable browse page.
    assert '<a class="browse" href="./browse.html">' in page
    assert "Browse the repository" in page
    # The old flat tree list is gone (no per-leaf-dir <ul> on the landing page).
    assert "ul.trees" not in page
    assert 'href="./FreeBSD:16:aarch64/"' not in page


def test_render_page_snippets_have_copy_buttons() -> None:
    """Scenario: every install/bootstrap/conf snippet gets a one-click 'Copy' affordance.

    Given a rendered landing page,
    Then each command snippet is wrapped in a .snip block carrying a .copy button while its
      <pre> content is emitted unchanged (so the copied text is exactly the command),
    And the supporting CSS + a dependency-free clipboard script are present,
    And exactly two command snippets are wrapped on the one published card (the
      one-line channel-installer recipe + a manual conf, issue #2416) — not the
      inline <code> spans, and unpublished cards have none.
    """
    pkgs = [_pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "testing/ce-2.8/FreeBSD:15:amd64/d.pkg")]
    page = gl.render_page("https://pfblockerng.github.io/pkg", pkgs, _stub_conf)

    # The button + wrapper exist, and the <pre> payload is unchanged (button is a sibling).
    assert '<div class="snip">' in page
    btn = '<button class="copy" type="button" aria-label="Copy to clipboard">Copy</button>'
    assert btn in page
    # Only published channels (testing here) get a copyable recipe + manual conf.
    assert f"{btn}<pre>fetch -qo - https://pfblockerng.github.io/pkg/install-testing.sh | sh</pre>" in page
    assert f"{btn}<pre>testing-conf-snippet</pre>" in page
    assert "stable-conf-snippet" not in page

    # Two copyable snippets on the one published card: the install recipe + manual
    # conf. Unpublished cards have none.
    assert page.count('<button class="copy"') == 2

    # The styling + the behaviour that make the button work are shipped inline (static page).
    assert ".copy{" in page and ".snip{position:relative}" in page
    assert "navigator.clipboard" in page and "document.execCommand('copy')" in page  # API + fallback
    assert "<script>" in page  # the handler is wired


def test_autoindex_has_no_copy_affordance() -> None:
    """The copy button/script live only on the landing page, not the directory autoindex."""
    out = gl.render_autoindex("stable", ["amd64"], [("notes.txt", 12, 1_700_000_000.0)])
    assert 'class="copy"' not in out
    assert "navigator.clipboard" not in out


def test_render_page_table_empty_when_no_packages() -> None:
    page = gl.render_page("https://x/pkg", [], _stub_conf)
    assert "No packages published yet." in page
    assert '<a class="browse" href="./browse.html">' in page  # browse link present even when empty


def test_render_page_empty_channel_shows_not_yet_published_for_every_card() -> None:
    """Empty site: four unpublished cards, zero recipes, zero manual conf, zero copy buttons."""
    page = gl.render_page("https://x/pkg", [], _stub_conf)
    assert page.count("not yet published") == 4
    assert "add-repo.sh" not in page
    assert "pkg install" not in page
    assert "migrate-channel.sh" not in page
    assert "install-stable.sh" not in page
    assert "install-testing.sh" not in page
    assert "install-edge.sh" not in page
    assert "install-nightly.sh" not in page
    assert "-conf-snippet" not in page
    assert '<button class="copy"' not in page


def test_render_page_shared_version_across_stable_testing_edge() -> None:
    """Row 4: the SAME canonical pkg name+version fixture present in stable/testing/edge
    means all three cards show the same version."""
    ver = "4.0.0"
    pkgs = [
        _pkg("stable", _CANON, ver, "FreeBSD:15:*", f"stable/ce-2.8/x-{ver}.pkg"),
        _pkg("testing", _CANON, ver, "FreeBSD:15:*", f"testing/ce-2.8/x-{ver}.pkg"),
        _pkg("edge", _CANON, ver, "FreeBSD:15:*", f"edge/ce-2.8/x-{ver}.pkg"),
    ]
    page = gl.render_page("https://x/pkg", pkgs, _stub_conf)

    # Same version string surfaces on stable, testing, AND edge's card (3 occurrences).
    assert page.count(f'<p class="ver">Latest <code>{ver}</code></p>') == 3


def test_render_page_edge_ahead_of_testing_and_stable_shows_divergence() -> None:
    """Row 5: Edge opening the next release family shows a genuinely newer version than
    Testing/Stable — the three cards diverge, proving no card is hardcoded/shared blindly."""
    pkgs = [
        _pkg("stable", _CANON, "4.0.0", "FreeBSD:15:*", "stable/ce-2.8/x.pkg"),
        _pkg("testing", _CANON, "4.0.1.b1", "FreeBSD:15:*", "testing/ce-2.8/x.pkg"),
        _pkg("edge", _CANON, "4.1.0.a1", "FreeBSD:15:*", "edge/ce-2.8/x.pkg"),
    ]
    page = gl.render_page("https://x/pkg", pkgs, _stub_conf)

    assert '<p class="ver">Latest <code>4.0.0</code></p>' in page
    assert '<p class="ver">Latest <code>4.0.1.b1</code></p>' in page
    assert '<p class="ver">Latest <code>4.1.0.a1</code></p>' in page


def test_unpublished_nightly_card_has_no_install_recipe() -> None:
    """Issue #2382: unpublished Nightly keeps the badge/blurb and ships no recipe."""
    pkgs = [_pkg("stable", _CANON, "3.3.2", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]
    page = gl.render_page("https://pfblockerng.github.io/pkg", pkgs, _stub_conf)
    nightly = page[page.index('"card nightly"') :]
    # The nightly card ends at the next footer-ish boundary; search the nightly
    # slice up to the published-packages heading.
    nightly = nightly.split("<h2>Published packages</h2>", 1)[0]
    assert "not yet published" in nightly
    assert "add-repo.sh" not in nightly
    assert "install-nightly.sh" not in nightly
    assert "--channel nightly" not in nightly
    assert "pkg install" not in nightly
    assert "nightly-conf-snippet" not in nightly


def test_published_card_recipe_is_the_one_line_channel_installer() -> None:
    """Published stable: the card's ONE recipe is the piped per-channel installer —
    no add-repo.sh, no migrate-channel.sh, no bare `pkg install` — plus the manual-conf
    details (issue #2416: the four per-channel installers replace the two-script
    add-repo+migrate-channel bootstrap on the landing cards)."""
    pkgs = [_pkg("stable", _CANON, "3.3.2", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]
    base = "https://pfblockerng.github.io/pkg"
    page = gl.render_page(base, pkgs, _stub_conf)
    assert f"fetch -qo - {base}/install-stable.sh | sh" in page
    assert "add-repo.sh" not in page
    assert "migrate-channel.sh" not in page
    assert "pkg install" not in page
    assert "stable-conf-snippet" in page
    assert "Manual conf (advanced)" in page


def test_render_page_omits_internal_trust_and_channel_model() -> None:
    """Development and implementation details do not leak into the user-facing page."""
    page = gl.render_page("https://x/pkg", [], _stub_conf)

    assert "Every channel installs the same canonical package" not in page
    assert "Trust &amp; channel model" not in page
    assert "signature_type: none" not in page
    assert "Single-repository subscription" not in page
    assert "Channel switching" not in page


def test_render_autoindex_lists_dirs_files_and_parent() -> None:
    """A non-root autoindex shows a Parent Directory row, subdirs (name/), and files (name+size),
    with './'-prefixed hrefs so a colon-bearing ABI segment stays a relative path."""
    out = gl.render_autoindex(
        "stable/ce-2.8",
        ["amd64"],
        [("notes.txt", 12, 1_700_000_000.0)],
    )
    assert "Index of /stable/ce-2.8" in out
    assert '<a href="../">../</a>' in out  # Parent Directory row
    assert '<a href="./amd64/">amd64/</a>' in out  # subdir, trailing slash
    assert '<a href="./notes.txt">notes.txt</a>' in out  # file
    assert "12 B" in out  # size column rendered


def test_render_autoindex_root_has_no_parent_and_is_colon_safe() -> None:
    """The browse root omits Parent Directory; an ABI dir with ':' links via './' (RFC 3986 §4.2)."""
    out = gl.render_autoindex("", ["stable", "nightly"], [("meta.json", 99, 1_700_000_000.0)], is_root=True)
    assert "Index of /" in out
    assert "Parent Directory" not in out and 'href="../"' not in out
    assert '<a href="./stable/">stable/</a>' in out and '<a href="./nightly/">nightly/</a>' in out
    # A colon-ABI subdir would link with the scheme-safe './' prefix.
    deep = gl.render_autoindex("stable", ["FreeBSD:16:aarch64"], [])
    assert 'href="./FreeBSD:16:aarch64/"' in deep


def test_render_autoindex_escapes_special_chars_in_names() -> None:
    """Hostile input: a filename carrying HTML-special characters renders escaped, never
    raw markup — a directory listing walks whatever bytes are on disk."""
    out = gl.render_autoindex(
        "stable/ce-2.8",
        ["<script>evil"],
        [("py311-charset<script>&normalizer-3.4.4.pkg", 12, 1_700_000_000.0)],
    )
    assert "<script>evil" not in out.split("<tbody>")[1].replace("&lt;script&gt;evil", "")
    assert "&lt;script&gt;evil" in out
    assert "&lt;script&gt;&amp;normalizer" in out or "py311-charset&lt;script&gt;&amp;normalizer" in out
    assert "<script>evil</a>" not in out  # never unescaped inside a link


def test_render_page_handles_varver_dir_with_spaces_no_crash() -> None:
    """Hostile input: a malformed/unusual varver dir name (spaces) never crashes rendering
    and never breaks out of the relative-link scheme (no raw path escape)."""
    weird = _pkg("stable", _CANON, "1.0.0", "FreeBSD:15:*", "stable/ce 2.8 beta/pfSense-pkg-pfBlockerNG-1.0.0.pkg")

    page = gl.render_page("https://x/pkg", [weird], _stub_conf)

    assert "1.0.0" in page
    assert 'href="./stable/ce 2.8 beta/pfSense-pkg-pfBlockerNG-1.0.0.pkg"' in page


def test_write_site_keeps_dependency_packages_browsable(tmp_path: Path, monkeypatch: Any) -> None:
    """A dependency package stays in the directory listing while leaving the page alone.

    Filtering it out of the channel tables (issue #1863) must not make it unreachable: the
    autoindex is how a user gets at everything we publish, including the CE-only
    `py311-charset-normalizer` (issue #1806). The returned count is OUR packages.
    """
    site = tmp_path / "site"
    _touch(site / "stable" / "ce-2.8" / f"{_CANON}-4.0.0.alpha.22.pkg")
    _touch(site / "stable" / "ce-2.8" / "py311-charset-normalizer-3.4.4.pkg")
    manifests = {
        f"{_CANON}-4.0.0.alpha.22.pkg": {
            "name": _CANON,
            "version": "4.0.0.alpha.22",
            "abi": "FreeBSD:15:*",
        },
        "py311-charset-normalizer-3.4.4.pkg": {
            "name": "py311-charset-normalizer",
            "version": "3.4.4",
            "abi": "FreeBSD:15:*",
        },
    }
    monkeypatch.setattr(gl, "read_compact_manifest", lambda p: manifests[os.path.basename(p)])
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_ADD_REPO_REAL))

    assert n == 1  # the count is pfBlockerNG packages, not everything published
    listing = (site / "stable" / "ce-2.8" / "index.html").read_text()
    assert "py311-charset-normalizer-3.4.4.pkg" in listing  # still reachable by browsing
    assert "3.4.4" not in (site / "index.html").read_text()  # but never on the landing page


def test_write_site_emits_browse_and_autoindex_at_every_level(tmp_path: Path, monkeypatch: Any) -> None:
    """write_site emits the landing page, browse.html, and an autoindex index.html at EVERY
    directory level (intermediate dirs too) so the whole tree is folder-navigable."""
    site = tmp_path / "site"
    _touch(site / "stable" / "ce-2.8" / "FreeBSD:15:amd64" / f"{_CANON}-3.2.16.pkg")
    _touch(site / "stable" / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg")
    _touch(site / "meta.json")

    manifest = {"name": _CANON, "version": "3.2.16", "abi": "FreeBSD:15:amd64"}
    monkeypatch.setattr(gl, "read_compact_manifest", lambda p: manifest)
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_ADD_REPO_REAL))

    assert n == 1
    # Landing page (root) links to the browse entry; browse.html exists and lists the top dirs.
    assert (site / "index.html").is_file()
    assert '<a class="browse" href="./browse.html">' in (site / "index.html").read_text()
    browse = (site / "browse.html").read_text()
    assert '<a href="./stable/">stable/</a>' in browse
    # An autoindex index.html exists at EVERY level — intermediate dirs too, not just the leaf.
    for rel in ("stable", "stable/ce-2.8", "stable/ce-2.8/FreeBSD:15:amd64"):
        assert (site / rel / "index.html").is_file(), f"missing autoindex at {rel}"
    # Intermediate dir lists its subdir; leaf lists the package + the catalog plumbing (a real
    # directory listing, unlike the old package-only view).
    assert '<a href="./ce-2.8/">ce-2.8/</a>' in (site / "stable" / "index.html").read_text()
    leaf = (site / "stable" / "ce-2.8" / "FreeBSD:15:amd64" / "index.html").read_text()
    assert f"{_CANON}-3.2.16.pkg" in leaf
    assert "packagesite.pkg" in leaf  # the catalog files ARE shown in a directory listing
    # The generated index pages themselves are hidden from listings (not repository content).
    assert "browse.html" not in browse.split("<tbody>")[1]


def test_write_site_never_indexes_docs_staging(tmp_path: Path, monkeypatch: Any) -> None:
    """A staged (not-yet-gated) tree under docs/staging/<seg>/<channel>/<varver>/ (issue
    #2389's stage->gate->promote flow) stays SERVED as plain files, but write_site must
    never emit an autoindex under it and must never link it from the root/browse
    listing -- a concurrent `direct` publish (nightly.yml, pkg-republish.yml -- both
    outside release-published.yml's concurrency group) during a stage window would
    otherwise make the un-gated staged tree browsable."""
    site = tmp_path / "site"
    _touch(site / "edge" / "ce-2.8" / "FreeBSD:15:amd64" / f"{_CANON}-3.2.16.pkg")
    _touch(site / "edge" / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg")
    _touch(site / "staging" / "10-1" / "stable" / "ce-2.8" / "meta.conf")
    _touch(site / "staging" / "10-1" / "stable" / "ce-2.8" / "data.pkg")
    _touch(site / "staging" / "10-1" / "stable" / "ce-2.8" / "packagesite.pkg")

    manifest = {"name": _CANON, "version": "3.2.16", "abi": "FreeBSD:15:amd64"}
    monkeypatch.setattr(gl, "read_compact_manifest", lambda p: manifest)
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_ADD_REPO_REAL))

    # The staged package never counts toward a real channel (it sits under an
    # unrecognized top-level dir, exactly like any other stray future dir).
    assert n == 1
    # The staged files themselves are untouched -- still served, just not indexed.
    assert (site / "staging" / "10-1" / "stable" / "ce-2.8" / "meta.conf").is_file()
    # No autoindex anywhere under docs/staging.
    assert not list(site.glob("staging/**/index.html"))
    assert not (site / "staging" / "index.html").is_file()
    # Root/browse listing carries no link to staging at all.
    root_index = (site / "index.html").read_text()
    browse = (site / "browse.html").read_text()
    assert "staging" not in root_index
    assert 'href="./staging/"' not in browse
    # A real channel is unaffected — still gets its own autoindex + browse link.
    assert (site / "edge" / "ce-2.8" / "index.html").is_file()
    assert 'href="./edge/"' in browse


def test_write_site_empty_site_root_renders_four_empty_cards_exit_zero(tmp_path: Path, monkeypatch: Any) -> None:
    """Hostile row: an empty site root (no channel dirs at all) still renders — four empty
    cards, no crash, write_site returns 0 (the CLI's exit-0 equivalent)."""
    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://x/pkg", str(_ADD_REPO_REAL))

    assert n == 0
    index_html = (site / "index.html").read_text()
    assert index_html.count("not yet published") == 4
    assert "add-repo.sh" not in index_html
    assert "pkg install" not in index_html
    assert "migrate-channel.sh" not in index_html
    assert "-conf-snippet" not in index_html
    assert '<button class="copy"' not in index_html


def test_browse_adapts_to_any_future_tree_shape(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: the browse view is derived purely by walking the tree — no hardcoded layout.

    Given a deliberately NOVEL tree under two real channels ('stable', 'edge') — extra
    nesting beneath the channel dir, an `_archive/` subtree, an exotic ABI no current matrix
    entry covers, and a stray top-level file,
    When write_site runs,
    Then an autoindex index.html appears at EVERY level (whatever the names/depth), browse.html
    lists the new top-level entries, packages are discovered wherever they live under a KNOWN
    channel, and the deepest dir's autoindex still climbs correctly — proving a future folder
    restructure below the channel segment needs NO code change.
    """
    site = tmp_path / "site"
    # A structure we do NOT use today: +1 nesting level, an archive subtree, an ABI/varver the
    # matrix doesn't know — all still rooted at a real channel, since collect_packages now keys
    # channel off the top-level segment.
    novel = [
        f"stable/ce-2.9/FreeBSD:16:riscv64/extra/{_CANON}-9.9.9.pkg",
        f"edge/_archive/plus-99.03/FreeBSD:99:powerpc64/{_CANON}-9.9.9.pkg",
    ]
    for rel in novel:
        _touch(site / rel)
    _touch(site / "CHECKSUMS.txt")

    # The manifest is read from each .pkg wherever it sits (path-agnostic); every package
    # carries the ONE canonical name — channel comes from the path, not the name.
    def fake_manifest(path: str) -> dict:
        abi = "FreeBSD:16:riscv64" if "stable" in path else "FreeBSD:99:powerpc64"
        return {"name": _CANON, "version": "9.9.9", "abi": abi}

    monkeypatch.setattr(gl, "read_compact_manifest", fake_manifest)
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://x/pkg/", str(_ADD_REPO_REAL))

    # Packages found wherever they live (both novel locations), not by an assumed path.
    assert n == 2
    # browse.html lists the top-level entries (both real channels + the stray file).
    browse = (site / "browse.html").read_text()
    assert '<a href="./stable/">stable/</a>' in browse
    assert '<a href="./edge/">edge/</a>' in browse
    assert '<a href="./CHECKSUMS.txt">CHECKSUMS.txt</a>' in browse
    # An autoindex exists at EVERY directory of the novel tree — arbitrary names + extra depth.
    for rel in (
        "stable",
        "stable/ce-2.9",
        "stable/ce-2.9/FreeBSD:16:riscv64",
        "stable/ce-2.9/FreeBSD:16:riscv64/extra",
        "edge/_archive",
        "edge/_archive/plus-99.03",
        "edge/_archive/plus-99.03/FreeBSD:99:powerpc64",
    ):
        assert (site / rel / "index.html").is_file(), f"no autoindex generated at {rel}"
    # The deepest dir lists its package and climbs to the repository root (depth-correct home link).
    deep = (site / "stable/ce-2.9/FreeBSD:16:riscv64/extra" / "index.html").read_text()
    assert f"{_CANON}-9.9.9.pkg" in deep
    assert 'href="../../../../"' in deep  # 4 levels deep -> 4 hops to the site root


# ── EOL pfSense versions ──────────────────────────────────────────────────────


def _mx_eol(abi: str, ver: str, variant: str, php: str, py: str) -> dict[str, str]:
    """A route-only (EOL) matrix entry."""
    return {
        "abi": abi,
        "pfsense_version": ver,
        "variant": variant,
        "php_version": php,
        "py_flavor": py,
        "role": "route-only",
        "status": "EOL",
    }


def _eol_pkg(version: str, abi: str, varver: str, channel: str = "stable") -> dict[str, Any]:
    """A package row as collect_packages would produce for a route-only (EOL) catalog entry.

    rel is DIRECTLY under <channel>/<varver>/ — arch-less (issue #1806 NO_ARCH), exactly
    where build-repo-portable.py places them (four-channel model, issue #2147).
    """
    return {
        "channel": channel,
        "name": _CANON,
        "version": version,
        "abi": abi,
        "rel": f"{channel}/{varver}/{_CANON}-{version}.pkg",
        "size": 42,
        "published": "2026-01-10 08:00 UTC",
        "commit": "aabbcc1122334455667788990011223344556677",
        "php": "",
        "py": "",
    }


def test_eol_versions_empty_when_no_route_only_entries() -> None:
    """Before-state: no route-only matrix entries => eol_versions returns [] and the
    EOL section is entirely absent from the rendered page."""
    # Before: no route-only entries in matrix.
    pkg = _pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "d.pkg")
    matrix = [_mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311")]

    result = gl.eol_versions([pkg], matrix)
    assert result == []  # before-state: empty

    # The EOL section is absent — no heading, no table.
    html = gl._eol_versions_html([pkg], matrix)
    assert html == ""

    # After: adding a route-only entry makes the section appear (transition proof).
    matrix_with_eol = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
    ]
    eol_pkg = _eol_pkg("3.1.0_5", "FreeBSD:14:amd64", "ce-2.7")
    result_after = gl.eol_versions([pkg, eol_pkg], matrix_with_eol)
    assert len(result_after) == 1  # after: the EOL entry appears
    html_after = gl._eol_versions_html([pkg, eol_pkg], matrix_with_eol)
    assert "EOL pfSense versions" in html_after  # section now present


def test_eol_versions_legacy_release_prefixed_path_no_longer_recognized() -> None:
    """The retired two-repo model's `release/<varver>/` path prefix is not a channel; an
    EOL .pkg published under it (the old fixture shape) is invisible to eol_versions now
    (issue #2147 — the dead model, not silently deleted: this test pins its new, empty
    result instead of removing coverage)."""
    legacy_pkg = _eol_pkg("3.1.0_5", "FreeBSD:14:amd64", "ce-2.7")
    legacy_pkg["rel"] = f"release/ce-2.7/{_CANON}-3.1.0_5.pkg"  # the retired prefix
    matrix = [_mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311")]

    assert gl.eol_versions([legacy_pkg], matrix) == []


def test_eol_versions_pool_spans_every_channel_for_the_same_varver() -> None:
    """An EOL varver's pool spans every channel that still serves it (issue #2147) — the
    newest served build across every channel wins, not just one channel's slice."""
    served_stable = _eol_pkg("3.1.9", "FreeBSD:14:amd64", "ce-2.7", channel="stable")
    served_testing = _eol_pkg("3.2.0", "FreeBSD:14:amd64", "ce-2.7", channel="testing")
    matrix = [_mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311")]

    result = gl.eol_versions([served_stable, served_testing], matrix)

    assert [(ver, row["version"]) for _, ver, row in result] == [("2.7", "3.2.0")]  # newest across BOTH channels


def test_eol_versions_lists_newest_served_pkg_per_eol_version() -> None:
    """Scenario: two .pkg versions served for a CE 2.7 (route-only) entry; only newest shown.

    Given a matrix with a live CE 2.8 (build) entry and a route-only CE 2.7 entry,
    And two .pkg files served under stable/ce-2.7/ (v3.1.0_4 older, v3.1.0_5 newer),
    When eol_versions is called,
    Then CE 2.7 appears exactly once, showing v3.1.0_5 (the newest), not v3.1.0_4.
    And the live build version (3.2.16) is ABSENT from the EOL result.
    """
    live_pkg = _pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "d.pkg")
    eol_old = _eol_pkg("3.1.0_4", "FreeBSD:14:amd64", "ce-2.7")
    eol_new = _eol_pkg("3.1.0_5", "FreeBSD:14:amd64", "ce-2.7")
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
    ]

    result = gl.eol_versions([live_pkg, eol_old, eol_new], matrix)

    assert len(result) == 1
    ekey, ver, row = result[0]
    assert ekey == "CE"
    assert ver == "2.7"
    assert row["version"] == "3.1.0_5"  # newest — not the older 3.1.0_4
    assert row["pfsense_version"] == "2.7"
    assert row["php"] == "8.2"
    assert row["py"] == "3.11"
    # Live build version never appears in the EOL result.
    all_versions = {r["version"] for _, _, r in result}
    assert "3.2.16" not in all_versions


def test_eol_versions_wildcard_served_pkg_matches_concrete_matrix_entry() -> None:
    """A served EOL .pkg with a NO_ARCH (wildcard) manifest ABI still joins a
    route-only matrix entry recorded with a CONCRETE ABI (issue #1806) — matched
    by OS+major, never exact-string equality.

    Scenario: route-only CE 2.7 (matrix records concrete FreeBSD:14:amd64), but
              the actually-served .pkg is wildcard-ABI'd (FreeBSD:14:*)
      When eol_versions is called
      Then CE 2.7 still appears, carrying the served (wildcard-ABI) package
    """
    eol_pkg = _eol_pkg("3.1.0_5", "FreeBSD:14:*", "ce-2.7")
    matrix = [_mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311")]

    result = gl.eol_versions([eol_pkg], matrix)

    assert len(result) == 1
    ekey, ver, row = result[0]
    assert ekey == "CE"
    assert ver == "2.7"
    assert row["version"] == "3.1.0_5"


def test_eol_versions_newest_is_taken_across_every_entry_of_the_varver() -> None:
    """The last-served version is the newest in the varver's WHOLE pool (issue #1863).

    One row per EOL pfSense minor means its several matrix entries (arch/FreeBSD/PHP/Python
    flavors) share one pool: taking the newest from only the first matching entry's slice
    reports a stale "last served" version and hides the file that really is the last one.

    Given route-only CE 2.7 recorded per arch, and a frozen catalog whose amd64 file is
      3.1.9 while its aarch64 file is the newer 3.2.0,
    When eol_versions is called,
    Then the single CE 2.7 row reports 3.2.0.
    """
    served_amd64 = _eol_pkg("3.1.9", "FreeBSD:14:amd64", "ce-2.7")
    served_arm64 = _eol_pkg("3.2.0", "FreeBSD:14:aarch64", "ce-2.7")
    matrix = [
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
        _mx_eol("FreeBSD:14:aarch64", "2.7", "CE", "8.2", "py311"),
    ]

    result = gl.eol_versions([served_amd64, served_arm64], matrix)

    assert [(ver, row["version"]) for _, ver, row in result] == [("2.7", "3.2.0")]


def test_eol_versions_flavor_entry_without_a_served_pkg_does_not_claim_the_varver() -> None:
    """A matrix entry whose ABI nothing serves must not consume its varver's single row.

    The varver is emitted once, so the entry that supplies the displayed flavors has to be
    one that actually matches a served file — otherwise an unserved flavor row silently
    swallows the minor and the frozen package disappears from the EOL table (issue #1863).

    Given route-only CE 2.7 recorded for two FreeBSD majors, only the second of which has
      a served file,
    When eol_versions is called,
    Then CE 2.7 is still listed, carrying the served file and that entry's PHP/Python.
    """
    served = _eol_pkg("3.1.9", "FreeBSD:14:amd64", "ce-2.7")
    matrix = [
        _mx_eol("FreeBSD:13:amd64", "2.7", "CE", "8.1", "py310"),
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
    ]

    result = gl.eol_versions([served], matrix)

    assert len(result) == 1
    _, ver, row = result[0]
    assert (ver, row["version"], row["php"], row["py"]) == ("2.7", "3.1.9", "8.2", "3.11")


def test_eol_versions_sorted_by_pkg_version_then_pfsense_version_desc() -> None:
    """The EOL table obeys the same order rule as the live tables (issue #1863):
    pfBlockerNG version desc, then pfSense version desc — within each edition's table.

    Given route-only CE 2.6 and CE 2.7, where 2.7 was frozen at the HIGHER pfBlockerNG
      version (so pfSense-version order and package-version order disagree),
    When eol_versions is called,
    Then the higher pfBlockerNG version leads.
    """
    served_27 = _eol_pkg("3.1.9", "FreeBSD:14:*", "ce-2.7")
    served_26 = _eol_pkg("3.1.0_5", "FreeBSD:13:*", "ce-2.6")
    matrix = [
        _mx_eol("FreeBSD:13:amd64", "2.6", "CE", "8.1", "py311"),
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
    ]

    result = gl.eol_versions([served_26, served_27], matrix)

    assert [(ver, row["version"]) for _, ver, row in result] == [("2.7", "3.1.9"), ("2.6", "3.1.0_5")]


def test_eol_versions_one_row_per_pfsense_minor_whatever_the_flavor_set() -> None:
    """The EOL table obeys the same one-row-per-minor rule as the live tables (issue #1863).

    A route-only pfSense minor can hold several matrix entries (one per arch, and in general
    per FreeBSD/PHP/Python combination), but its frozen catalog serves a single .pkg.

    Given a route-only CE 2.7 recorded twice in the matrix (amd64 and aarch64),
      and one .pkg served under stable/ce-2.7/,
    When eol_versions is called,
    Then CE 2.7 is listed exactly once.
    """
    served = _eol_pkg("3.1.0_5", "FreeBSD:14:*", "ce-2.7")
    matrix = [
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
        _mx_eol("FreeBSD:14:aarch64", "2.7", "CE", "8.2", "py311"),
    ]

    result = gl.eol_versions([served], matrix)

    assert [(ekey, ver) for ekey, ver, _ in result] == [("CE", "2.7")]


def test_eol_versions_ce_and_plus_split_into_separate_tables() -> None:
    """Scenario: CE and Plus route-only entries appear in separate tables; no cross-edition leak.

    Given a matrix with one route-only CE 2.7 entry and one route-only Plus 25.03 entry,
    And .pkg files served for each EOL entry under the matching <channel>/<varver>/ path,
    When _eol_versions_html is called,
    Then the CE pfSense version (2.7) appears only in the CE table (not in Plus),
    And the Plus pfSense version (25.03) appears only in the Plus table (not in CE),
    And the CE table comes before the Plus table.
    """
    eol_ce = _eol_pkg("3.1.0_5", "FreeBSD:14:amd64", "ce-2.7")
    eol_plus = _eol_pkg("3.0.9_1", "FreeBSD:15:amd64", "plus-25.03")
    # A live build pkg that must NOT appear in either EOL table.
    live_pkg = _pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "d.pkg")
    matrix = [
        _mx("FreeBSD:15:amd64", "26.03", "Plus", "8.5", "py311"),
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
        _mx_eol("FreeBSD:15:amd64", "25.03", "Plus", "8.3", "py311"),
    ]

    # Before-state: confirm live pkg is NOT in the EOL triples list.
    triples = gl.eol_versions([eol_ce, eol_plus, live_pkg], matrix)
    all_versions = {r["version"] for _, _, r in triples}
    assert "3.2.16" not in all_versions  # live build absent from EOL list

    html = gl._eol_versions_html([eol_ce, eol_plus, live_pkg], matrix)

    # Both editions have their own h3 heading.
    assert "<h3>pfSense CE</h3>" in html
    assert "<h3>pfSense Plus</h3>" in html
    # CE comes before Plus.
    assert html.index("<h3>pfSense CE</h3>") < html.index("<h3>pfSense Plus</h3>")

    # Slice CE and Plus sections.
    ce_section = html[html.index("<h3>pfSense CE</h3>") : html.index("<h3>pfSense Plus</h3>")]
    plus_section = html[html.index("<h3>pfSense Plus</h3>") :]

    # CE section: the CE EOL version appears; Plus EOL version does not.
    assert ">2.7<" in ce_section
    assert "3.1.0_5" in ce_section
    assert "25.03" not in ce_section
    assert "3.0.9_1" not in ce_section

    # Plus section: the Plus EOL version appears; CE EOL version does not.
    assert ">25.03<" in plus_section
    assert "3.0.9_1" in plus_section
    assert ">2.7<" not in plus_section
    assert "3.1.0_5" not in plus_section

    # Live build version absent from both sections.
    assert "3.2.16" not in html[html.index("EOL pfSense versions") :]

    # EOL tables omit the Channel column (pins the EOL call site's with_channel=False).
    assert "<th>Channel</th>" not in html


def test_eol_versions_section_absent_from_rendered_page_when_no_route_only() -> None:
    """The EOL section is NOT emitted to the landing page when the matrix has no route-only entries.

    This pins the before-state: an existing deployment with no route-only matrix entries
    produces an identical page (no new empty heading, no new section).
    """
    pkgs = [_pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "d.pkg")]
    matrix = [_mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311")]

    page = gl.render_page("https://pfblockerng.github.io/pkg", pkgs, _stub_conf, matrix)

    assert "EOL pfSense versions" not in page


def test_eol_versions_section_present_in_rendered_page_with_route_only() -> None:
    """The landing page surfaces the EOL section when route-only matrix entries exist.

    Given a matrix with one live CE build and one route-only CE 2.7 + one route-only Plus 25.03,
    And corresponding .pkg files under the EOL varver paths,
    When render_page is called,
    Then the page contains an 'EOL pfSense versions' h2 section after 'Published packages',
    And the CE and Plus sub-tables are present with the correct versions,
    And the live build version is absent from the EOL section.
    """
    live_pkg = _pkg(
        "testing",
        _CANON,
        "3.2.16",
        "FreeBSD:15:amd64",
        "testing/ce-2.8/amd64/pfSense-pkg-pfBlockerNG-3.2.16.pkg",
    )
    eol_ce = _eol_pkg("3.1.0_5", "FreeBSD:14:amd64", "ce-2.7")
    eol_plus = _eol_pkg("3.0.9_1", "FreeBSD:15:aarch64", "plus-25.03")
    matrix = [
        _mx("FreeBSD:15:amd64", "2.8", "CE", "8.3", "py311"),
        _mx_eol("FreeBSD:14:amd64", "2.7", "CE", "8.2", "py311"),
        _mx_eol("FreeBSD:15:aarch64", "25.03", "Plus", "8.3", "py311"),
    ]

    page = gl.render_page("https://pfblockerng.github.io/pkg", [live_pkg, eol_ce, eol_plus], _stub_conf, matrix)

    # EOL section is present, after 'Published packages'.
    assert "EOL pfSense versions" in page
    assert page.index("Published packages") < page.index("EOL pfSense versions")
    # EOL section comes before 'Repository files'.
    assert page.index("EOL pfSense versions") < page.index("Repository files")

    # The CE and Plus sub-tables are in the EOL section.
    eol_block = page[page.index("EOL pfSense versions") : page.index("Repository files")]
    assert "<h3>pfSense CE</h3>" in eol_block
    assert "<h3>pfSense Plus</h3>" in eol_block
    assert "3.1.0_5" in eol_block
    assert "3.0.9_1" in eol_block

    # Live build version is absent from the EOL section.
    assert "3.2.16" not in eol_block


# ── Contract guard: _conf_via_addrepo ↔ add-repo.sh --print-conf ─────────────
# These tests exercise the REAL add-repo.sh (no monkeypatching) so that any
# future change to add-repo.sh's --print-conf required-arg/--channel contract
# immediately breaks the unit suite instead of reaching the live publish workflow.


def test_conf_via_addrepo_matches_real_add_repo_contract() -> None:
    """_conf_via_addrepo shells the real add-repo.sh with `--channel <ch>` and must produce
    a valid, per-channel conf.

    Guards the gen_landing<->add-repo --print-conf contract: on the old code (missing
    --catalog-path) add-repo.sh exited 2 and raised CalledProcessError, breaking the
    pfBlockerNG/pkg publish.yml in render_page. All four channels are exercised (branch
    coverage) — every one of them now has its OWN repo/conf (issue #2147), unlike the
    legacy shared release repo.
    """
    addrepo: str = str(Path(__file__).resolve().parent.parent / "scripts" / "add-repo.sh")
    base: str = "https://pfblockerng.github.io/pkg"

    for channel in gl.CH_ORDER:
        conf: str = gl._conf_via_addrepo(addrepo, base, channel)
        assert conf, f"{channel} conf must be non-empty"
        assert f"pfblockerng-{channel}: {{" in conf
        assert f"{base}/{channel}/<varver>" in conf


# ── Piped-invocation: published add-repo.sh embeds hook + installs correctly ─


def test_published_add_repo_embeds_hook_and_installs_piped(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: the published add-repo.sh installs the hook when piped into sh.

    Background:
      The repository copy of add-repo.sh resolves its sibling hook via
      ``dirname "$0"``, which fails when the script is piped (``$0`` is ``sh``).
      gen_landing.py's write_site() generates a site/add-repo.sh that embeds
      the hook via a single-quoted heredoc so it is self-contained.

    Given a fresh tmp directory with NO rc.d sibling hook present,
      And write_site produces site/add-repo.sh with the hook embedded,
      And the script text is fed to sh via stdin
      (``sh -s -- --base-url ... --channel stable``),
    When add-repo.sh runs in the piped / non-checkout context,
    Then the hook file is installed on disk (HOOK_SRC absent, embedded path used),
      And the installed hook is executable and contains the rc.d PROVIDE pragma,
      And the staged conf file contains the ``Generated at boot`` marker
          (proving the hook ran via the onestart step in add-repo.sh).

    Before-state: hook file absent before the script runs.
    """
    import subprocess

    # ── Given ────────────────────────────────────────────────────────────────

    # Build the site tree (empty — we only need write_site to emit add-repo.sh).
    site = tmp_path / "site"
    site.mkdir()

    # Stub _conf_via_addrepo so write_site doesn't need a real pkg environment.
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    base = f"file://{site}"
    gl.write_site(str(site), base, str(_ADD_REPO_REAL))

    # The published add-repo.sh must exist and pass sh -n.
    published = site / "add-repo.sh"
    assert published.exists(), "write_site must produce site/add-repo.sh"
    published_text = published.read_text()
    assert published_text.startswith("#!/bin/sh"), "add-repo.sh must start with #!/bin/sh"
    sh_n = subprocess.run(["sh", "-n"], input=published_text, text=True, capture_output=True)
    assert sh_n.returncode == 0, f"sh -n failed on published add-repo.sh:\n{sh_n.stderr}"
    # Hook content is embedded — the stub error text must be gone.
    assert "no embedded hook in this copy" not in published_text, (
        "pfb_emit_embedded_hook stub was NOT replaced by gen_landing.py"
    )
    # The rc.d PROVIDE pragma from the real hook must be present inside the function.
    assert "PROVIDE: pfblockerng_repo_generate" in published_text, (
        "embedded hook body must contain the rc.d PROVIDE pragma"
    )

    # ── Fixture: a CE 2.8.1 box rooted at tmp_path/root ─────────────────────

    root = tmp_path / "root"

    # pkg stub: answers 'pkg config abi' with a real ABI, and 'pkg rquery' with a package
    # line so the bootstrap reaches its success path — a bootstrap whose catalogue verify
    # fails removes the conf it staged (issue #2148), which is exactly what this test
    # asserts got written.
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True)
    fake_pkg = bin_dir / "pkg"
    fake_pkg.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "version" ] && [ "$2" = "-t" ]; then\n'
        '  if [ "$3" = "$4" ]; then printf "=\\n"; exit 0; fi\n'
        '  _first=$(printf "%s\\n%s\\n" "$3" "$4" | sort -V | head -n1)\n'
        '  if [ "$_first" = "$3" ]; then printf "<\\n"; else printf ">\\n"; fi\n'
        "  exit 0\n"
        "fi\n"
        'case "$1" in\n'
        "  rquery)\n"
        '    fmt=""\n'
        '    for _a in "$@"; do case "$_a" in %*) fmt="$_a" ;; esac; done\n'
        '    case "$fmt" in\n'
        '      %v) printf "4.0.0\\n" ;;\n'
        '      %n-%v) printf "pfSense-pkg-pfBlockerNG-4.0.0\\n" ;;\n'
        '      *) printf "pfSense-pkg-pfBlockerNG 4.0.0\\n" ;;\n'
        "    esac\n"
        "    exit 0 ;;\n"
        "esac\n"
        "case \"$*\" in\n  'config abi') printf 'FreeBSD:15:amd64' ;;\nesac\n"
        "exit 0\n"
    )
    fake_pkg.chmod(0o755)

    # CE 2.8.1 box fixture: /etc/version + /etc/product_label (no 'Plus' -> CE).
    etc = root / "etc"
    etc.mkdir()
    (etc / "version").write_text("2.8.1\n")
    (etc / "product_label").write_text("pfSense\n")

    # Before-state: no hook installed yet.
    hook_path = root / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"
    assert not hook_path.exists(), "hook must not exist before the script runs"

    # ── When: pipe the published add-repo.sh into sh (no sibling hook present) ─

    env = {
        **{k: v for k, v in os.environ.items()},
        "PFBLOCKERNG_ROOT": str(root),
        "PKG_BIN": str(fake_pkg),
    }
    result = subprocess.run(
        ["sh", "-s", "--", "--base-url", base, "--channel", "stable"],
        input=published_text,
        text=True,
        capture_output=True,
        env=env,
        # Run from a directory with NO rc.d/ sibling so HOOK_SRC (which resolves to
        # cwd/rc.d/... when piped, since $0 is "sh") is absent — forcing the embedded
        # path, the real production bootstrap. Without this the test would lean on the
        # runner's cwd happening to lack an rc.d/ sibling.
        cwd=str(tmp_path),
    )

    # ── Then ─────────────────────────────────────────────────────────────────

    # The hook was installed (embedded path taken — no sibling was present).
    assert hook_path.exists(), (
        f"hook not installed at {hook_path}\nadd-repo stdout:\n{result.stdout}\nadd-repo stderr:\n{result.stderr}"
    )
    assert os.access(str(hook_path), os.X_OK), "installed hook must be executable"
    hook_content = hook_path.read_text()
    assert "PROVIDE: pfblockerng_repo_generate" in hook_content, "installed hook must contain the rc.d PROVIDE pragma"

    # The staged conf contains the 'Generated at boot' marker, proving the hook
    # was executed successfully by add-repo.sh's onestart step. --channel stable
    # must write pfblockerng-stable.conf with the stable/ce-2.8 URL, never the
    # unpublished release/ tree (issues #2384, #2390).
    conf_path = root / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng-stable.conf"
    assert conf_path.exists(), (
        f"conf not written at {conf_path}\nadd-repo stdout:\n{result.stdout}\nadd-repo stderr:\n{result.stderr}"
    )
    conf_text = conf_path.read_text()
    assert "Generated at boot by pfblockerng_repo_generate" in conf_text, (
        f"conf missing the 'Generated at boot' marker:\n{conf_text}"
    )
    assert "pfblockerng-stable: {" in conf_text, conf_text
    assert "/stable/ce-2.8" in conf_text, conf_text
    assert "/release/" not in conf_text
    assert not (root / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng.conf").exists()


def test_write_site_publishes_migrate_channel_beside_the_bootstrap(tmp_path: Path, monkeypatch: Any) -> None:
    """The migration script is served from the Pages root, exactly like add-repo.sh.

    A user switching channels reaches the site, not a git checkout, so both halves of
    the operation must be fetchable from the same base URL. Unlike add-repo.sh,
    migrate-channel.sh has no sibling file to embed — it is published verbatim, and a
    byte-for-byte comparison is what stops the published copy drifting from the tested
    repository copy.
    """
    import subprocess

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    gl.write_site(str(site), f"file://{site}", str(_ADD_REPO_REAL))

    published = site / "migrate-channel.sh"
    assert published.exists(), "write_site must publish site/migrate-channel.sh"
    assert os.access(str(published), os.X_OK), "the published migration script must be executable"
    published_text = published.read_text()
    assert published_text == (_SCRIPTS_DIR / "migrate-channel.sh").read_text(), (
        "the published migrate-channel.sh must be byte-identical to the repository copy"
    )
    sh_n = subprocess.run(["sh", "-n"], input=published_text, text=True, capture_output=True)
    assert sh_n.returncode == 0, f"sh -n failed on published migrate-channel.sh:\n{sh_n.stderr}"


# ── _embed_common: splice install-common.sh into a channel installer stub ─────


def test_embed_common_replaces_whole_marked_block_including_markers() -> None:
    """Unlike ``_embed_hook`` (which keeps its BEGIN/END lines), ``_embed_common``
    replaces the WHOLE marked block — both marker lines included — with the common
    text verbatim: the markers only delimit the stub `. install-common.sh` sourcing
    line, which cannot survive into a self-contained published script."""
    channel_text = (
        "#!/bin/sh\n"
        "PFB_CHANNEL=stable\n"
        f"{gl._COMMON_EMBED_BEGIN}\n"
        '. "$(dirname "$0")/install-common.sh"\n'
        f"{gl._COMMON_EMBED_END}\n"
        'pfb_channel_install "$@"\n'
    )
    common_text = "pfb_channel_install() {\n    :\n}\n"

    out = gl._embed_common(channel_text, common_text)

    assert gl._COMMON_EMBED_BEGIN not in out
    assert gl._COMMON_EMBED_END not in out
    assert '. "$(dirname "$0")/install-common.sh"' not in out
    assert common_text in out
    assert out.startswith("#!/bin/sh\nPFB_CHANNEL=stable\n")
    assert out.endswith('pfb_channel_install "$@"\n')


def test_embed_common_missing_markers_raises_value_error() -> None:
    with pytest.raises(ValueError, match="embed markers"):
        gl._embed_common("#!/bin/sh\nno markers here\n", "common body\n")


def test_embed_common_misordered_markers_raises_value_error() -> None:
    channel_text = f"{gl._COMMON_EMBED_END}\n{gl._COMMON_EMBED_BEGIN}\n"
    with pytest.raises(ValueError, match="embed markers"):
        gl._embed_common(channel_text, "common body\n")


def test_embed_common_rejects_common_text_containing_the_heredoc_delimiter() -> None:
    channel_text = f"{gl._COMMON_EMBED_BEGIN}\nstub\n{gl._COMMON_EMBED_END}\n"
    hostile_common = f"echo {gl._HOOK_HEREDOC}\n"
    with pytest.raises(ValueError, match="heredoc delimiter"):
        gl._embed_common(channel_text, hostile_common)


def test_write_site_publishes_the_four_channel_installers(tmp_path: Path, monkeypatch: Any) -> None:
    """write_site() publishes a self-contained install-<channel>.sh for each of the four
    channels (issue #2416): install-common.sh is spliced into the thin per-channel stub
    (its PFB_EMBED_COMMON block replaces the `. install-common.sh` sourcing line so the
    published script needs no sibling file on disk), then the boot hook is embedded into
    the result exactly like add-repo.sh's own splice. add-repo.sh and migrate-channel.sh
    keep publishing alongside it for one deprecation cycle.
    """
    import subprocess

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    gl.write_site(str(site), f"file://{site}", str(_ADD_REPO_REAL))

    assert (site / "add-repo.sh").exists(), "add-repo.sh must still be published (deprecation cycle)"
    assert (site / "migrate-channel.sh").exists(), "migrate-channel.sh must still be published (deprecation cycle)"

    for channel in gl.CH_ORDER:
        published = site / f"install-{channel}.sh"
        assert published.exists(), f"write_site must produce site/install-{channel}.sh"
        assert os.access(str(published), os.X_OK), f"install-{channel}.sh must be executable"
        text = published.read_text()
        assert gl._COMMON_EMBED_BEGIN not in text, "the PFB_EMBED_COMMON marker must not survive publishing"
        assert gl._COMMON_EMBED_END not in text, "the PFB_EMBED_COMMON marker must not survive publishing"
        assert 'install-common.sh"' not in text, "the published installer must not source a sibling file"
        assert 'pfb_channel_install "$@"' in text
        assert f"cat <<'{gl._HOOK_HEREDOC}'" in text, "the boot hook must be embedded, not left as the stub body"
        assert "PROVIDE: pfblockerng_repo_generate" in text, "embedded hook body must contain the rc.d PROVIDE pragma"
        sh_n = subprocess.run(["sh", "-n"], input=text, text=True, capture_output=True)
        assert sh_n.returncode == 0, f"sh -n failed on published install-{channel}.sh:\n{sh_n.stderr}"


def test_published_channel_installer_runs_piped_with_embedded_hook_and_common(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: the published install-stable.sh converges a fresh box when piped into sh
    from a directory with NO scripts/ tree at all (issue #2416) — proving both embeds
    (install-common.sh's PFB_EMBED_COMMON splice AND the hook's PFB_EMBED_HOOK splice
    living inside the now-embedded common text) are self-contained. Mirrors
    ``test_published_add_repo_embeds_hook_and_installs_piped``'s technique; reuses
    ``tests.test_channel_install``'s fake pkg(8) stub (already proven against every branch
    of ``pfb_channel_install``) rather than re-deriving pkg's behaviour here.
    """
    import subprocess

    from tests.test_channel_install import _PKG_STUB, _seed_box

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    base = f"file://{site}"
    gl.write_site(str(site), base, str(_ADD_REPO_REAL))
    published_text = (site / "install-stable.sh").read_text()

    root = tmp_path / "root"
    root.mkdir()
    _seed_box(str(root))

    bin_dir = root / "bin"
    bin_dir.mkdir()
    fake_pkg = bin_dir / "pkg"
    fake_pkg.write_text(_PKG_STUB)
    fake_pkg.chmod(0o755)

    catalog_dir = root / "catalog"
    catalog_dir.mkdir()
    (catalog_dir / "pfblockerng-stable").write_text("4.0.0\n")

    hook_path = root / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"
    assert not hook_path.exists(), "hook must not exist before the script runs"

    env = {
        **os.environ,
        "PFBLOCKERNG_ROOT": str(root),
        "PKG_BIN": str(fake_pkg),
        "PFB_TEST_ROOT": str(root),
        "PFB_BASE_URL": base,
    }
    result = subprocess.run(
        ["sh", "-s"],
        input=published_text,
        text=True,
        capture_output=True,
        env=env,
        # Run from a directory with NO scripts/ tree — forces the embedded hook
        # fallback path (HOOK_SRC resolves relative to $0, which is "sh" when piped).
        cwd=str(tmp_path),
    )

    assert result.returncode == 0, (
        f"install-stable.sh failed (exit {result.returncode}):\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    assert hook_path.exists(), f"hook not installed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    assert os.access(str(hook_path), os.X_OK), "installed hook must be executable"
    hook_text = hook_path.read_text()
    assert hook_text.strip(), "installed hook must be non-empty"
    assert "PROVIDE: pfblockerng_repo_generate" in hook_text

    conf_path = root / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng-stable.conf"
    assert conf_path.exists(), f"conf not written\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    conf_text = conf_path.read_text()
    assert "Generated at boot by pfblockerng_repo_generate" in conf_text
    assert f'url: "{base}/stable/ce-2.8"' in conf_text


# ── write_site / CLI interface — call-compatible with publish-pkg-repo.sh ─────


def test_write_site_signature_matches_publish_pkg_repo_call_site() -> None:
    """Pins the write_site(site, base, addrepo, matrix=None) signature that
    publish-pkg-repo.sh's `python3 gen_landing.py <site> <base> <addrepo> --matrix <f>`
    invocation (via main()) depends on — a rename/reorder here breaks production silently.
    """
    sig = inspect.signature(gl.write_site)
    assert list(sig.parameters) == ["site", "base", "addrepo", "matrix"]
    assert sig.parameters["matrix"].default is None


def test_main_cli_accepts_the_production_positional_and_matrix_flag_shape(tmp_path: Path, monkeypatch: Any) -> None:
    """main(argv) accepts exactly the shape publish-pkg-repo.sh invokes:
    <site> <base_url> <add_repo> --matrix <file>."""
    site = tmp_path / "site"
    site.mkdir()
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text("[]")
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    rc = gl.main([str(site), "https://x/pkg", str(_ADD_REPO_REAL), "--matrix", str(matrix_file)])

    assert rc == 0
    assert (site / "index.html").is_file()


def test_main_client_scripts_only_writes_scripts_and_nothing_else(tmp_path: Path) -> None:
    """``--client-scripts-only`` publishes ONLY the deterministic client scripts: the two
    legacy scripts (one deprecation cycle) plus the four per-channel installers.

    publish-pkg-repo.sh's catalogue-NOOP path (issue #2408) uses this mode to ship a
    script-only fix; writing any timestamped landing/browse/autoindex page here would
    manufacture a commit on every republish run instead.
    """
    site = tmp_path / "site"
    site.mkdir()

    rc = gl.main([str(site), "https://x/pkg", str(_ADD_REPO_REAL), "--client-scripts-only"])

    assert rc == 0
    assert sorted(p.name for p in site.iterdir()) == sorted(gl.CLIENT_SCRIPTS)
    embedded = (site / "add-repo.sh").read_text()
    assert f"cat <<'{gl._HOOK_HEREDOC}'" in embedded, "the boot hook must be embedded, not left as the stub body"
    for channel in gl.CH_ORDER:
        installer = (site / f"install-{channel}.sh").read_text()
        assert f"cat <<'{gl._HOOK_HEREDOC}'" in installer, (
            f"install-{channel}.sh's boot hook must be embedded, not left as the stub body"
        )


def test_main_client_scripts_only_rejects_matrix(tmp_path: Path) -> None:
    """``--client-scripts-only`` with ``--matrix`` is a usage error, not a silent ignore.

    The matrix drives the landing page's per-edition tables, which this mode never
    writes — accepting both would let a caller believe the matrix was applied.
    """
    site = tmp_path / "site"
    site.mkdir()
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text("[]")

    with pytest.raises(SystemExit) as exc:
        gl.main(
            [str(site), "https://x/pkg", str(_ADD_REPO_REAL), "--client-scripts-only", "--matrix", str(matrix_file)]
        )

    assert exc.value.code == 2
    assert list(site.iterdir()) == [], "a usage error must write nothing"
