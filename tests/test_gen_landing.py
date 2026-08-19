"""Tests for scripts/gen_landing.py — the pkg-site renderer (issue #2450).

The generator builds the declared pkg-site/ tree (install.sh, per-channel recipes,
.nojekyll), renders the dynamic pages (landing index.html, browse.html, and a
browse/<channel>/… view of every catalogue tree), and mirrors the result into
docs/ — write every desired file, delete everything extraneous, never touching a
catalogue-owned tree. Most cases inject the manifest reader or exercise pure render
helpers. The record-epoch HTML pin (issue #2401) builds a real libpkg fixture for
the browse and landing rows; rendering never reads a file's mtime.
"""

from __future__ import annotations

import html
import importlib.util
import inspect
import io
import json
import os
import re
import stat
import subprocess
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

# Paths to the real scripts/site tree — used wherever tests exercise the live
# integration (write_site + build_site_tree) rather than fake fixtures.
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
_PKG_SITE_DIR = Path(__file__).resolve().parent.parent / "pkg-site"

_CANON = gl.CANONICAL_EMITTED_IDENTITY  # "pfSense-pkg-pfBlockerNG" — the ONE channel-agnostic identity


def _fixture_site_tree(base: str) -> dict[str, tuple[bytes, int]]:
    """A minimal built site tree for pure render_page/card tests: one recipe per
    channel, {base}-substituted — mirrors what build_site_tree(PKG-SITE, base)
    would produce for pkg-site/recipes/*.sh without touching the real files."""
    return {
        f"recipes/{ch}.sh": (f"fetch -qo - {base}/install.sh | sh -s -- --channel {ch}\n".encode(), 0o644)
        for ch in gl.CH_ORDER
    }


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


def test_timestamp_html_keeps_utc_instant_and_localizes_in_the_browser(tmp_path: Path) -> None:
    """Generated dates retain a truthful UTC fallback and ISO instant, while the
    shipped script renders the visitor's local `YYYY-MM-DD HH:mm` without a suffix."""
    epoch = datetime(2026, 8, 14, 19, 32, 17, tzinfo=timezone.utc).timestamp()
    timestamp = '<time datetime="2026-08-14T19:32:17Z">2026-08-14 19:32 UTC</time>'
    assert gl._time_html(epoch) == timestamp
    assert gl._epoch_cell(epoch) == timestamp

    base = "https://pkg.pfblockerng.com"
    package = _pkg("stable", _CANON, "3.3.2", "FreeBSD:15:*", "stable/ce-2.8/package.pkg")
    package["published_epoch"] = epoch
    page = gl.render_page(base, [package], _stub_conf, _fixture_site_tree(base))
    assert timestamp in page
    docs = tmp_path / "docs"
    docs.mkdir()
    listing = gl.render_browse_root(str(docs), {})
    for rendered in (page, listing):
        assert gl._LOCAL_TIME_JS in rendered

    runner = (
        'var t={dateTime:"2026-08-14T19:32:17Z",textContent:"UTC fallback"};'
        "global.document={querySelectorAll:function(){return [t];}};"
        f"{gl._LOCAL_TIME_JS}"
        "process.stdout.write(t.textContent);"
    )
    expected = {
        "Europe/Amsterdam": "2026-08-14 21:32",
        "America/New_York": "2026-08-14 15:32",
        "Asia/Kolkata": "2026-08-15 01:02",
        "Asia/Kathmandu": "2026-08-15 01:17",
    }
    for zone, local_time in expected.items():
        env = dict(os.environ, TZ=zone)
        result = subprocess.run(["node", "-e", runner], env=env, check=True, capture_output=True, text=True)
        assert result.stdout == local_time

    invalid_runner = runner.replace("2026-08-14T19:32:17Z", "invalid")
    invalid = subprocess.run(["node", "-e", invalid_runner], check=True, capture_output=True, text=True)
    assert invalid.stdout == "UTC fallback"


def test_published_datetime_prefers_created_annotation() -> None:
    """Scenario: the published datetime never depends on when a file was written.

    Given a .pkg whose manifest carries a `created` build annotation (the source
    commit epoch),
    When the published datetime is computed,
    Then the annotation wins,
    And with no annotation (or a malformed/out-of-range one), it resolves to ""
    — never a file mtime (issue #2450) — which the caller renders as an em dash.
    """
    commit_epoch = datetime(2026, 6, 10, 5, 52, tzinfo=timezone.utc).timestamp()
    manifest_with = {"annotations": {"commit": "deadbeef", "created": str(int(commit_epoch))}}
    assert gl.published_datetime(manifest_with) == "2026-06-10 05:52 UTC"
    # No annotation -> unknown, never a mtime.
    assert gl.published_datetime({"annotations": {}}) == ""
    assert gl.published_datetime({}) == ""
    # Malformed annotation -> unknown, not a crash.
    assert gl.published_datetime({"annotations": {"created": "nope"}}) == ""
    # Numeric-but-out-of-range epoch (inf / huge) -> unknown, not a crash on the whole
    # page (datetime.fromtimestamp raises OverflowError/OSError, not ValueError).
    assert gl.published_datetime({"annotations": {"created": "1e309"}}) == ""
    assert gl.published_datetime({"annotations": {"created": "999999999999999999"}}) == ""


def test_published_datetime_falls_back_to_build_record_epoch() -> None:
    """Scenario: release builds embed pfb_build_record but no `created` annotation.

    Given a .pkg whose only annotation is `pfb_build_record` (the release/nightly
    builders stamp the record, and nothing stamps `created` — issue #2375),
    When the published datetime is computed,
    Then the record's `source_date_epoch` wins,
    And a bare `created` annotation still takes precedence over the record,
    And a malformed/incomplete record resolves to "" instead of crashing.
    """
    import json

    commit_epoch = datetime(2026, 8, 14, 19, 32, tzinfo=timezone.utc).timestamp()
    record = json.dumps({"source_date_epoch": int(commit_epoch), "source_sha": "f" * 40})
    manifest_record_only = {"annotations": {"pfb_build_record": record}}
    assert gl.published_datetime(manifest_record_only) == "2026-08-14 19:32 UTC"
    # `created` still wins when both are present.
    created_epoch = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc).timestamp()
    both = {"annotations": {"created": str(int(created_epoch)), "pfb_build_record": record}}
    assert gl.published_datetime(both) == "2026-08-01 00:00 UTC"
    # Malformed record JSON, record without the key, non-numeric epoch -> unknown.
    for bad in ("{not json", json.dumps({}), json.dumps({"source_date_epoch": "nope"})):
        assert gl.published_datetime({"annotations": {"pfb_build_record": bad}}) == ""


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


def test_display_epoch_uses_record_epoch_for_pkg_files_never_mtime(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: a browse-view row must not show the publish run's mtime for packages.

    Given a .pkg (whose embedded build record carries source_date_epoch) and a
    catalog plumbing file, both with an arbitrary mtime,
    When each file's display epoch is resolved,
    Then the .pkg resolves to the record epoch while the plumbing file resolves to
    None (never its mtime, issue #2450),
    And an unreadable .pkg (corrupt/foreign) also resolves to None instead of crashing.
    """
    record_epoch = int(datetime(2026, 8, 14, 19, 32, tzinfo=timezone.utc).timestamp())
    project = tmp_path / "pfSense-pkg-pfBlockerNG-3.3.2.pkg"
    project.write_bytes(b"not a real pkg")
    broken = tmp_path / "broken.pkg"
    broken.write_bytes(b"also not a pkg")
    site_pkg = tmp_path / "packagesite.pkg"
    site_pkg.write_bytes(b"catalog")
    meta = tmp_path / "meta.conf"
    meta.write_text("meta")
    for path in (project, broken, site_pkg, meta):
        os.utime(path, (1_700_000_000, 1_700_000_000))

    def fake_read(path: str) -> dict:
        if path.endswith("broken.pkg"):
            raise ValueError("corrupt")
        return {"annotations": {"pfb_build_record": json.dumps({"source_date_epoch": record_epoch})}}

    monkeypatch.setattr(gl, "read_compact_manifest", fake_read)
    assert gl._display_epoch(str(project)) == float(record_epoch)
    assert gl._display_epoch(str(broken)) is None
    assert gl._display_epoch(str(meta)) is None
    # Catalog plumbing stays None even when the stub would hand it a record
    # (is_package_file is the gate — issue #2401 leftover of path.endswith(".pkg")).
    assert gl._display_epoch(str(site_pkg)) is None
    # Out-of-range epoch (inf) resolves to None, not a crash later.
    monkeypatch.setattr(gl, "read_compact_manifest", lambda _p: {"annotations": {"created": "1e309"}})
    assert gl._display_epoch(str(broken)) is None
    assert gl._display_epoch(str(project)) is None


# Record-only fixture used by the write_site HTML pin (issue #2401). Epochs are
# the ticket's own numbers so a listing/landing mismatch is visible in the assert.
_RECORD_EPOCH = 1786735920  # 2026-08-14 19:32 UTC
_FILE_MTIME = 1786750000  # 2026-08-14 23:26 UTC
_SOURCE_SHA = "f2c5650a1768c5df2bf05fd2cd4ae938a2f566a8"
_RECORD_DATE = "2026-08-14 19:32 UTC"
_MTIME_DATE = "2026-08-14 23:26 UTC"
_RECORD_TIME = '<time datetime="2026-08-14T19:32:00Z">2026-08-14 19:32 UTC</time>'


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


def test_artifact_epoch_prefers_created_then_record_then_none() -> None:
    """One resolver: created annotation, then pfb_build_record, else None — never mtime."""
    record = json.dumps({"source_date_epoch": _RECORD_EPOCH, "source_sha": _SOURCE_SHA})
    created = {"annotations": {"created": "10", pfb_pkg.PFB_BUILD_RECORD_KEY: record}}
    assert gl.artifact_epoch(created) == 10.0
    assert gl.artifact_epoch({"annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: record}}) == float(_RECORD_EPOCH)
    # Out-of-range created falls through to the record, then to None.
    assert gl.artifact_epoch({"annotations": {"created": "1e309", pfb_pkg.PFB_BUILD_RECORD_KEY: record}}) == float(
        _RECORD_EPOCH
    )
    assert gl.artifact_epoch({"annotations": {"created": "1e309"}}) is None
    assert gl.artifact_epoch({}) is None
    assert gl.artifact_epoch({"annotations": ["not", "a", "map"]}) is None
    assert gl.artifact_epoch({"annotations": "created=1"}) is None


def test_published_datetime_and_display_epoch_share_artifact_epoch(tmp_path: Path, monkeypatch: Any) -> None:
    """Both display surfaces call artifact_epoch (issue #2401)."""
    src_pub = inspect.getsource(gl.published_datetime)
    src_disp = inspect.getsource(gl._display_epoch)
    assert "artifact_epoch(" in src_pub
    assert "artifact_epoch(" in src_disp

    sentinel = 1111111111.0
    seen: list[dict] = []

    def fake_epoch(manifest: dict) -> float:
        seen.append(manifest)
        return sentinel

    monkeypatch.setattr(gl, "artifact_epoch", fake_epoch)
    assert gl.published_datetime({"annotations": {"created": "1"}}) == gl.artifact_datetime(sentinel)

    pkg = tmp_path / f"{_CANON}-3.3.2.pkg"
    pkg.write_bytes(b"x")
    monkeypatch.setattr(gl, "read_compact_manifest", lambda _p: {"annotations": {}})
    assert gl._display_epoch(str(pkg)) == sentinel
    assert len(seen) == 2


def test_catalog_pkg_never_shown_via_a_stubbed_project_record(tmp_path: Path, monkeypatch: Any) -> None:
    """packagesite.pkg / data.pkg must not inherit a stubbed project record.

    is_package_file is the gate: even if read_compact_manifest would return the
    project record for every path, catalog .pkg files resolve to None (issue #2450).
    """
    cell = tmp_path / "cell"
    cell.mkdir()
    project = cell / f"{_CANON}-3.3.2.pkg"
    site_pkg = cell / "packagesite.pkg"
    data_pkg = cell / "data.pkg"
    project.write_bytes(b"pkg")
    site_pkg.write_bytes(b"catalog")
    data_pkg.write_bytes(b"data")

    record = json.dumps({"source_date_epoch": _RECORD_EPOCH, "source_sha": _SOURCE_SHA})
    monkeypatch.setattr(
        gl,
        "read_compact_manifest",
        lambda _p: {"annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: record}},
    )
    assert gl._display_epoch(str(project)) == float(_RECORD_EPOCH)
    assert gl._display_epoch(str(site_pkg)) is None
    assert gl._display_epoch(str(data_pkg)) is None


def test_write_site_record_only_pkg_drives_browse_and_landing(tmp_path: Path, monkeypatch: Any) -> None:
    """A real record-only compact-manifest fixture drives write_site (issue #2401).

    The browse-view row and the landing Published / Commit cells show the record
    epoch / source_sha; a plumbing sibling's row shows an em dash, never a mtime
    (issue #2450: no epoch ever falls back to a file's mtime).
    """
    site, cell = _record_only_cell(tmp_path / "site")
    # Prove the archive is a real record-only compact manifest before rendering.
    compact = pfb_pkg.read_compact_manifest(cell / f"{_CANON}-3.3.2.pkg")
    annotations = compact.get("annotations") or {}
    assert "created" not in annotations
    assert "commit" not in annotations
    assert pfb_pkg.PFB_BUILD_RECORD_KEY in annotations

    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")
    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_PKG_SITE_DIR))
    assert n == 1

    listing = (site / "browse" / "stable" / "ce-2.8" / "index.html").read_text()
    pkg_row = _autoindex_row(listing, f"{_CANON}-3.3.2.pkg")
    assert _RECORD_TIME in pkg_row
    assert gl._LOCAL_TIME_JS in listing
    assert _MTIME_DATE not in pkg_row
    for plumbing in ("packagesite.pkg", "data.pkg", "meta.conf"):
        row = _autoindex_row(listing, plumbing)
        assert _RECORD_DATE not in row
        assert _MTIME_DATE not in row
        assert "&mdash;" in row

    landing = (site / "index.html").read_text()
    assert _RECORD_TIME in landing
    assert gl._LOCAL_TIME_JS in landing
    assert _MTIME_DATE not in landing
    assert f"{gl.SOURCE_REPO_URL}/commit/{_SOURCE_SHA}" in landing
    assert f">{_SOURCE_SHA[:7]}<" in landing


def test_write_site_out_of_range_created_on_project_pkg_renders_dash(tmp_path: Path, monkeypatch: Any) -> None:
    """created=1e309 on the project .pkg renders an em dash; write_site does not raise."""
    site = tmp_path / "site"
    cell = site / "stable" / "ce-2.8"
    pkg = cell / f"{_CANON}-3.3.2.pkg"
    _write_pkg(pkg, annotations={"created": "1e309"})
    os.utime(pkg, (_FILE_MTIME, _FILE_MTIME))

    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")
    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_PKG_SITE_DIR))
    assert n == 1
    listing = (site / "browse" / "stable" / "ce-2.8" / "index.html").read_text()
    row = _autoindex_row(listing, pkg.name)
    assert _MTIME_DATE not in row
    assert "&mdash;" in row
    landing = (site / "index.html").read_text()
    assert _MTIME_DATE not in landing


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
    When packages are collected,
    Then only the real channel's package counts and the stray dir's file never appears
    in the packages table/cards.
    When the site is written,
    Then write_site still succeeds — but the stray dir, sitting under neither a
    CATALOGUE_DIRS prefix nor the site tree, is swept by the mirror (issue #2450: the
    renderer owns everything outside the catalogue trees, so an unrecognized top-level
    dir is extraneous, not "browsable" — that model retired with the old per-dir
    autoindex).
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
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")
    n = gl.write_site(str(site), "https://x/pkg", str(_PKG_SITE_DIR))

    assert n == 1
    index_html = (site / "index.html").read_text()
    assert "9.9.9" not in index_html
    # Swept by the mirror: not a catalogue prefix, not part of the site tree.
    assert not (site / "quarantine").exists()
    browse = (site / "browse.html").read_text()
    assert "quarantine" not in browse


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
        "published_epoch": datetime(2026, 6, 14, 9, 38, tzinfo=timezone.utc).timestamp(),
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
    dev_mid["published_epoch"] = _RECORD_EPOCH
    stb_old["published_epoch"] = _RECORD_EPOCH

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
    assert _RECORD_TIME in stable and _RECORD_TIME in testing
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
    "not yet published" blurb and must not ship an install recipe, a bare pkg
    install, or a conf snippet.
    """
    base = "https://pfblockerng.github.io/pkg"
    page = gl.render_page(base, [], _stub_conf, _fixture_site_tree(base))

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
    # The install.sh recipe appears only on a published card — none are here.
    assert "install.sh" not in page
    assert "pkg install" not in page
    # Nightly keeps its stability badge.
    assert '<span class="badge">not for daily use</span>' in page
    assert "<code>YYYYMMDDHHMMSS.&lt;7-character source SHA&gt;</code>" in page
    assert page.count("not yet published") == 4


def test_generated_pages_share_the_main_site_chrome_and_keep_channel_accents(tmp_path: Path) -> None:
    """Landing and browse pages use the main site's chrome while package channels
    retain their existing blue, amber, purple, and red status cues."""
    page = gl.render_page(
        "https://pfblockerng.github.io/pkg",
        [],
        _stub_conf,
        _fixture_site_tree("https://pfblockerng.github.io/pkg"),
    )
    docs = tmp_path / "docs"
    docs.mkdir()
    _touch(docs / "stable" / "ce-2.8" / "package.pkg")
    listing = gl.render_browse_root(str(docs), {})
    nested_listing = gl._render_catalogue_browse_page(str(docs), "stable")

    for rendered in (page, listing, nested_listing):
        assert '<link rel="stylesheet" href="https://pfblockerng.com/assets/site.css">' in rendered
        assert '<link rel="icon" href="https://pfblockerng.com/assets/logo.svg" type="image/svg+xml">' in rendered
        assert '<a class="skip-link" href="#main-content">Skip to content</a>' in rendered
        assert '<header class="site-header">' in rendered
        assert '<a class="brand" href="https://pfblockerng.com/" aria-label="pfBlockerNG home">' in rendered
        assert '<nav class="header-nav" aria-label="Primary">' in rendered
        assert '<a href="https://pkg.pfblockerng.com/" aria-current="page">Packages</a>' in rendered
        assert '<main id="main-content" class="pkg-shell">' in rendered
        assert '<footer class="site-footer">' in rendered
        assert "@media(max-width:820px){.cards{grid-template-columns:1fr}" in rendered
        assert "@media(prefers-color-scheme:dark){.card{" in rendered

    assert '<section class="pkg-hero">' in page
    assert '<p class="eyebrow">Official package repository</p>' in page
    assert '<div class="card stable">' in page
    assert "--stable:#2f81f7" in page
    assert "--testing:#d29922" in page
    assert "--edge:#a371f7" in page
    assert "--nightly:#f85149" in page
    assert ".card.stable{--channel:var(--stable)}" in page
    assert ".card.testing{--channel:var(--testing)}" in page
    assert ".card.edge{--channel:var(--edge)}" in page
    assert ".card.nightly{--channel:var(--nightly)}" in page
    assert ".card h3{margin:0 0 .15rem;color:var(--ink)" in page
    assert "border-color:var(--channel);color:var(--ink)" in page
    assert ".warn{color:var(--ink);font-weight:700}" in page


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
    page = gl.render_page(base, pkgs, _stub_conf, _fixture_site_tree(base), matrix)

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
    # recipe (issue #2416) — the SOLE recipe, no bare pkg install.
    # Anchored to the <pre> element boundary so a trailing `sh -s --` (or any other
    # tail) fails this assertion rather than slipping past a bare substring check.
    assert f"<pre>fetch -qo - {base}/install.sh | sh -s -- --channel testing</pre>" in page
    assert f"<pre>fetch -qo - {base}/install.sh | sh -s -- --channel nightly</pre>" in page
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
    assert ".card.stable{--channel:var(--stable)}" in page
    assert ".card.testing{--channel:var(--testing)}" in page
    assert ".card.edge{--channel:var(--edge)}" in page
    assert ".card.nightly{--channel:var(--nightly)}" in page
    assert ".badge{display:inline-block" in page and "border-color:var(--channel);color:var(--ink)" in page
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
      one-line --channel installer recipe + a manual conf, issue #2416) — not the
      inline <code> spans, and unpublished cards have none.
    """
    pkgs = [_pkg("testing", _CANON, "3.2.16", "FreeBSD:15:amd64", "testing/ce-2.8/FreeBSD:15:amd64/d.pkg")]
    page = gl.render_page(
        "https://pfblockerng.github.io/pkg", pkgs, _stub_conf, _fixture_site_tree("https://pfblockerng.github.io/pkg")
    )

    # The button + wrapper exist, and the <pre> payload is unchanged (button is a sibling).
    assert '<div class="snip">' in page
    btn = '<button class="copy" type="button" aria-label="Copy to clipboard">Copy</button>'
    assert btn in page
    # Only published channels (testing here) get a copyable recipe + manual conf.
    assert (
        f"{btn}<pre>fetch -qo - https://pfblockerng.github.io/pkg/install.sh | sh -s -- --channel testing</pre>" in page
    )
    assert f"{btn}<pre>testing-conf-snippet</pre>" in page
    assert "stable-conf-snippet" not in page

    # Two copyable snippets on the one published card: the install recipe + manual
    # conf. Unpublished cards have none.
    assert page.count('<button class="copy"') == 2

    # The styling + the behaviour that make the button work are shipped inline (static page).
    assert ".copy{" in page and ".snip{position:relative}" in page
    assert "navigator.clipboard" in page and "document.execCommand('copy')" in page  # API + fallback
    assert "<script>" in page  # the handler is wired


def test_autoindex_has_no_copy_affordance(tmp_path: Path) -> None:
    """The copy button/script live only on the landing page, not a browse page."""
    docs = tmp_path / "docs"
    _touch(docs / "stable" / "amd64" / "notes.txt")

    out = gl._render_catalogue_browse_page(str(docs), "stable")

    assert 'class="copy"' not in out
    assert "navigator.clipboard" not in out


def test_render_page_table_empty_when_no_packages() -> None:
    page = gl.render_page("https://x/pkg", [], _stub_conf, _fixture_site_tree("https://x/pkg"))
    assert "No packages published yet." in page
    assert '<a class="browse" href="./browse.html">' in page  # browse link present even when empty


def test_render_page_empty_channel_shows_not_yet_published_for_every_card() -> None:
    """Empty site: four unpublished cards, zero recipes, zero manual conf, zero copy buttons."""
    page = gl.render_page("https://x/pkg", [], _stub_conf, _fixture_site_tree("https://x/pkg"))
    assert page.count("not yet published") == 4
    assert "pkg install" not in page
    assert "install.sh" not in page
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
    page = gl.render_page("https://x/pkg", pkgs, _stub_conf, _fixture_site_tree("https://x/pkg"))

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
    page = gl.render_page("https://x/pkg", pkgs, _stub_conf, _fixture_site_tree("https://x/pkg"))

    assert '<p class="ver">Latest <code>4.0.0</code></p>' in page
    assert '<p class="ver">Latest <code>4.0.1.b1</code></p>' in page
    assert '<p class="ver">Latest <code>4.1.0.a1</code></p>' in page


def test_unpublished_nightly_card_has_no_install_recipe() -> None:
    """Issue #2382: unpublished Nightly keeps the badge/blurb and ships no recipe."""
    pkgs = [_pkg("stable", _CANON, "3.3.2", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]
    page = gl.render_page(
        "https://pfblockerng.github.io/pkg", pkgs, _stub_conf, _fixture_site_tree("https://pfblockerng.github.io/pkg")
    )
    nightly = page[page.index('"card nightly"') :]
    # The nightly card ends at the next footer-ish boundary; search the nightly
    # slice up to the published-packages heading.
    nightly = nightly.split("<h2>Published packages</h2>", 1)[0]
    assert "not yet published" in nightly
    assert "install.sh" not in nightly
    assert "--channel nightly" not in nightly
    assert "pkg install" not in nightly
    assert "nightly-conf-snippet" not in nightly


def test_published_card_recipe_is_the_one_line_channel_installer() -> None:
    """Published stable: the card's ONE recipe is the piped, --channel-parameterized
    installer — no bare `pkg install` — plus the manual-conf details (issue #2416
    follow-up: the single install.sh is the SOLE client entry point on the landing
    cards)."""
    pkgs = [_pkg("stable", _CANON, "3.3.2", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]
    base = "https://pfblockerng.github.io/pkg"
    page = gl.render_page(base, pkgs, _stub_conf, _fixture_site_tree(base))
    # Anchored to the <pre> element boundary so a trailing `sh -s --` (or any other
    # tail) fails this assertion rather than slipping past a bare substring check.
    assert f"<pre>fetch -qo - {base}/install.sh | sh -s -- --channel stable</pre>" in page
    assert "pkg install" not in page
    assert "stable-conf-snippet" in page
    assert "Manual conf (advanced)" in page


def test_render_page_omits_internal_trust_and_channel_model() -> None:
    """Development and implementation details do not leak into the user-facing page."""
    page = gl.render_page("https://x/pkg", [], _stub_conf, _fixture_site_tree("https://x/pkg"))

    assert "Every channel installs the same canonical package" not in page
    assert "Trust &amp; channel model" not in page
    assert "signature_type: none" not in page
    assert "Single-repository subscription" not in page
    assert "Channel switching" not in page


def test_catalogue_browse_page_lists_dirs_files_and_parent(tmp_path: Path) -> None:
    """A non-channel-root browse page shows a Parent Directory row, subdirs (name/),
    and files (name+size), the file linking OUT of browse/ into the real tree."""
    docs = tmp_path / "docs"
    _touch(docs / "stable" / "ce-2.8" / "amd64" / "placeholder")
    (docs / "stable" / "ce-2.8" / "notes.txt").write_bytes(b"x" * 12)

    out = gl._render_catalogue_browse_page(str(docs), "stable/ce-2.8")

    assert "Index of /stable/ce-2.8" in out
    folder = '<span class="entry-icon" aria-hidden="true">&#128193;</span>'
    file = '<span class="entry-icon" aria-hidden="true">&#128196;</span>'
    assert f'<a href="../">{folder}../</a>' in out  # Parent Directory row (not the channel root)
    assert f'<a href="./amd64/">{folder}amd64/</a>' in out  # subdir stays within the browse mirror
    assert f'href="../../../stable/ce-2.8/notes.txt">{file}notes.txt</a>' in out
    assert "12 B" in out  # size column rendered


def test_browse_root_has_no_parent_and_channel_root_links_browse_html(tmp_path: Path) -> None:
    """browse.html has no Parent Directory row; a channel-root browse page's Parent
    Directory instead links back to browse.html (issue #2450)."""
    docs = tmp_path / "docs"
    _touch(docs / "stable" / "ce-2.8" / "x")
    _touch(docs / "nightly" / "ce-2.8" / "x")
    built = {"meta.json": (b"x" * 99, 0o644)}

    root = gl.render_browse_root(str(docs), built)
    assert "Index of /" in root
    assert "Parent Directory" not in root and 'href="../"' not in root
    folder = '<span class="entry-icon" aria-hidden="true">&#128193;</span>'
    file = '<span class="entry-icon" aria-hidden="true">&#128196;</span>'
    assert f'<a href="./browse/stable/">{folder}stable/</a>' in root
    assert f'<a href="./browse/nightly/">{folder}nightly/</a>' in root
    assert f'<a href="./meta.json">{file}meta.json</a>' in root

    channel_page = gl._render_catalogue_browse_page(str(docs), "stable")
    assert f'<a href="../../browse.html">{folder}../</a>' in channel_page  # channel root's Parent -> browse.html

    # A colon-ABI subdir links with the scheme-safe './' prefix, staying within the mirror.
    _touch(docs / "stable" / "FreeBSD:16:aarch64" / "x")
    deep = gl._render_catalogue_browse_page(str(docs), "stable")
    assert 'href="./FreeBSD:16:aarch64/"' in deep


def test_catalogue_browse_page_escapes_special_chars_in_names(tmp_path: Path) -> None:
    """Hostile input: a filename carrying HTML-special characters renders escaped, never
    raw markup — a directory listing walks whatever bytes are on disk."""
    docs = tmp_path / "docs"
    _touch(docs / "stable" / "ce-2.8" / "<script>evil" / "placeholder")
    (docs / "stable" / "ce-2.8" / "py311-charset<script>&normalizer-3.4.4.pkg").write_bytes(b"x" * 12)

    out = gl._render_catalogue_browse_page(str(docs), "stable/ce-2.8")

    assert "<script>evil" not in out.split("<tbody>")[1].replace("&lt;script&gt;evil", "")
    assert "&lt;script&gt;evil" in out
    assert "&lt;script&gt;&amp;normalizer" in out or "py311-charset&lt;script&gt;&amp;normalizer" in out
    assert "<script>evil</a>" not in out  # never unescaped inside a link


def test_render_page_handles_varver_dir_with_spaces_no_crash() -> None:
    """Hostile input: a malformed/unusual varver dir name (spaces) never crashes rendering
    and never breaks out of the relative-link scheme (no raw path escape)."""
    weird = _pkg("stable", _CANON, "1.0.0", "FreeBSD:15:*", "stable/ce 2.8 beta/pfSense-pkg-pfBlockerNG-1.0.0.pkg")

    page = gl.render_page("https://x/pkg", [weird], _stub_conf, _fixture_site_tree("https://x/pkg"))

    assert "1.0.0" in page
    assert 'href="./stable/ce 2.8 beta/pfSense-pkg-pfBlockerNG-1.0.0.pkg"' in page


def test_write_site_keeps_dependency_packages_browsable(tmp_path: Path, monkeypatch: Any) -> None:
    """A dependency package stays in the browse view while leaving the landing page alone.

    Filtering it out of the channel tables (issue #1863) must not make it unreachable: the
    browse view is how a user gets at everything we publish, including the CE-only
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
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_PKG_SITE_DIR))

    assert n == 1  # the count is pfBlockerNG packages, not everything published
    # No index.html is ever written INSIDE the catalogue tree any more (issue #2450).
    assert not (site / "stable" / "ce-2.8" / "index.html").is_file()
    listing = (site / "browse" / "stable" / "ce-2.8" / "index.html").read_text()
    assert "py311-charset-normalizer-3.4.4.pkg" in listing  # still reachable by browsing
    assert "3.4.4" not in (site / "index.html").read_text()  # but never on the landing page


def test_write_site_emits_browse_pages_outside_the_catalogue_tree(tmp_path: Path, monkeypatch: Any) -> None:
    """write_site emits the landing page, browse.html, and a browse/<ch>/… page at EVERY
    directory level of a present channel (intermediate dirs too) — all OUTSIDE the
    catalogue tree itself (issue #2450): nothing is ever written under stable/…"""
    site = tmp_path / "site"
    _touch(site / "stable" / "ce-2.8" / "FreeBSD:15:amd64" / f"{_CANON}-3.2.16.pkg")
    _touch(site / "stable" / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg")

    manifest = {"name": _CANON, "version": "3.2.16", "abi": "FreeBSD:15:amd64"}
    monkeypatch.setattr(gl, "read_compact_manifest", lambda p: manifest)
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_PKG_SITE_DIR))

    assert n == 1
    # Landing page (root) links to the browse entry; browse.html exists and lists the top dirs.
    assert (site / "index.html").is_file()
    assert '<a class="browse" href="./browse.html">' in (site / "index.html").read_text()
    browse = (site / "browse.html").read_text()
    assert (
        '<a href="./browse/stable/"><span class="entry-icon" aria-hidden="true">&#128193;</span>stable/</a>' in browse
    )
    # A browse page exists at EVERY level under browse/ — intermediate dirs too.
    for rel in ("stable", "stable/ce-2.8", "stable/ce-2.8/FreeBSD:15:amd64"):
        assert (site / "browse" / rel / "index.html").is_file(), f"missing browse page at {rel}"
        # ...and NOTHING is ever written inside the real catalogue tree.
        assert not (site / rel / "index.html").is_file(), f"catalogue dir {rel} must carry no autoindex"
    # Intermediate dir lists its subdir; leaf lists the package + the catalog plumbing (a real
    # directory listing, unlike the old package-only view).
    assert (
        '<a href="./ce-2.8/"><span class="entry-icon" aria-hidden="true">&#128193;</span>ce-2.8/</a>'
        in (site / "browse" / "stable" / "index.html").read_text()
    )
    leaf = (site / "browse" / "stable" / "ce-2.8" / "FreeBSD:15:amd64" / "index.html").read_text()
    assert f"{_CANON}-3.2.16.pkg" in leaf
    assert "packagesite.pkg" in leaf  # the catalog files ARE shown in a directory listing
    # The file link climbs OUT of browse/ back into the real catalogue tree: 4 hops
    # (browse, stable, ce-2.8, FreeBSD:15:amd64) up to the docs root, then back down.
    assert 'href="../../../../stable/ce-2.8/FreeBSD:15:amd64/packagesite.pkg"' in leaf
    # The generated index pages themselves are hidden from listings (not repository content).
    assert "browse.html" not in browse.split("<tbody>")[1]


def test_write_site_never_indexes_docs_staging(tmp_path: Path, monkeypatch: Any) -> None:
    """A staged (not-yet-gated) tree under docs/staging/<seg>/<channel>/<varver>/ (issue
    #2389's stage->gate->promote flow) stays SERVED as plain files, but write_site must
    never emit a browse page under it and must never link it from the root/browse
    listing -- a concurrent `direct` publish (nightly.yml, pkg-republish.yml -- both
    outside release-published.yml's concurrency group) during a stage window would
    otherwise make the un-gated staged tree browsable. It is also never touched by the
    mirror sweep (issue #2450: ``staging`` is a CATALOGUE_DIRS prefix)."""
    site = tmp_path / "site"
    _touch(site / "edge" / "ce-2.8" / "FreeBSD:15:amd64" / f"{_CANON}-3.2.16.pkg")
    _touch(site / "edge" / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg")
    _touch(site / "staging" / "10-1" / "stable" / "ce-2.8" / "meta.conf")
    _touch(site / "staging" / "10-1" / "stable" / "ce-2.8" / "data.pkg")
    _touch(site / "staging" / "10-1" / "stable" / "ce-2.8" / "packagesite.pkg")

    manifest = {"name": _CANON, "version": "3.2.16", "abi": "FreeBSD:15:amd64"}
    monkeypatch.setattr(gl, "read_compact_manifest", lambda p: manifest)
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", str(_PKG_SITE_DIR))

    # The staged package never counts toward a real channel (it sits under an
    # unrecognized top-level dir, exactly like any other stray future dir).
    assert n == 1
    # The staged files themselves are untouched -- still served, just not indexed.
    assert (site / "staging" / "10-1" / "stable" / "ce-2.8" / "meta.conf").is_file()
    assert (site / "staging" / "10-1" / "stable" / "ce-2.8" / "data.pkg").is_file()
    assert (site / "staging" / "10-1" / "stable" / "ce-2.8" / "packagesite.pkg").is_file()
    # No browse page anywhere for staging.
    assert not (site / "browse" / "staging").exists()
    assert not list(site.glob("staging/**/index.html"))
    # Root/browse listing carries no link to staging at all.
    root_index = (site / "index.html").read_text()
    browse = (site / "browse.html").read_text()
    assert "staging" not in root_index
    assert "staging" not in browse
    # A real channel is unaffected — still gets its own browse page + browse link.
    assert (site / "browse" / "edge" / "ce-2.8" / "index.html").is_file()
    assert '<a href="./browse/edge/"><span class="entry-icon" aria-hidden="true">&#128193;</span>edge/</a>' in browse


def test_write_site_empty_site_root_renders_four_empty_cards_exit_zero(tmp_path: Path, monkeypatch: Any) -> None:
    """Hostile row: an empty site root (no channel dirs at all) still renders — four empty
    cards, no crash, write_site returns 0 (the CLI's exit-0 equivalent)."""
    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://x/pkg", str(_PKG_SITE_DIR))

    assert n == 0
    index_html = (site / "index.html").read_text()
    assert index_html.count("not yet published") == 4
    assert "pkg install" not in index_html
    assert "-conf-snippet" not in index_html
    assert '<button class="copy"' not in index_html


def test_browse_adapts_to_any_future_tree_shape(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: the browse view is derived purely by walking the tree — no hardcoded layout.

    Given a deliberately NOVEL tree under two real channels ('stable', 'edge') — extra
    nesting beneath the channel dir, an `_archive/` subtree, and an exotic ABI no
    current matrix entry covers,
    When write_site runs,
    Then a browse page appears at EVERY level (whatever the names/depth), browse.html
    lists the two real channels, packages are discovered wherever they live under a
    KNOWN channel, and the deepest browse page still climbs correctly — proving a
    future folder restructure below the channel segment needs NO code change.
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

    # The manifest is read from each .pkg wherever it sits (path-agnostic); every package
    # carries the ONE canonical name — channel comes from the path, not the name.
    def fake_manifest(path: str) -> dict:
        abi = "FreeBSD:16:riscv64" if "stable" in path else "FreeBSD:99:powerpc64"
        return {"name": _CANON, "version": "9.9.9", "abi": abi}

    monkeypatch.setattr(gl, "read_compact_manifest", fake_manifest)
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://x/pkg/", str(_PKG_SITE_DIR))

    # Packages found wherever they live (both novel locations), not by an assumed path.
    assert n == 2
    # browse.html lists the two catalogue channels.
    browse = (site / "browse.html").read_text()
    assert (
        '<a href="./browse/stable/"><span class="entry-icon" aria-hidden="true">&#128193;</span>stable/</a>' in browse
    )
    assert '<a href="./browse/edge/"><span class="entry-icon" aria-hidden="true">&#128193;</span>edge/</a>' in browse
    # A browse page exists at EVERY directory of the novel tree — arbitrary names + extra
    # depth — and NOTHING is written inside the real catalogue tree itself.
    for rel in (
        "stable",
        "stable/ce-2.9",
        "stable/ce-2.9/FreeBSD:16:riscv64",
        "stable/ce-2.9/FreeBSD:16:riscv64/extra",
        "edge/_archive",
        "edge/_archive/plus-99.03",
        "edge/_archive/plus-99.03/FreeBSD:99:powerpc64",
    ):
        assert (site / "browse" / rel / "index.html").is_file(), f"no browse page generated at {rel}"
        assert not (site / rel / "index.html").is_file(), f"catalogue dir {rel} must carry no autoindex"
    # The deepest browse page lists its package and climbs to the repository root
    # (depth-correct home link: browse + 4 real segments = 5 hops to the docs root).
    deep = (site / "browse" / "stable/ce-2.9/FreeBSD:16:riscv64/extra" / "index.html").read_text()
    assert f"{_CANON}-9.9.9.pkg" in deep
    assert 'href="../../../../../"' in deep  # repository-home link: 5 hops to the docs root


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
        "published_epoch": datetime(2026, 1, 10, 8, 0, tzinfo=timezone.utc).timestamp(),
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
    assert '<time datetime="2026-01-10T08:00:00Z">2026-01-10 08:00 UTC</time>' in ce_section
    assert "25.03" not in ce_section
    assert "3.0.9_1" not in ce_section

    # Plus section: the Plus EOL version appears; CE EOL version does not.
    assert ">25.03<" in plus_section
    assert "3.0.9_1" in plus_section
    assert '<time datetime="2026-01-10T08:00:00Z">2026-01-10 08:00 UTC</time>' in plus_section
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

    page = gl.render_page(
        "https://pfblockerng.github.io/pkg",
        pkgs,
        _stub_conf,
        _fixture_site_tree("https://pfblockerng.github.io/pkg"),
        matrix,
    )

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

    page = gl.render_page(
        "https://pfblockerng.github.io/pkg",
        [live_pkg, eol_ce, eol_plus],
        _stub_conf,
        _fixture_site_tree("https://pfblockerng.github.io/pkg"),
        matrix,
    )

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


# ── Contract guard: _conf_via_portable ↔ build-repo-portable.py --print-conf ──
# This test exercises the REAL build-repo-portable.py (no monkeypatching) so that
# any future change to its --print-conf required-arg/--channel contract immediately
# breaks the unit suite instead of reaching the live publish workflow.


def test_conf_via_portable_matches_real_build_repo_portable_contract() -> None:
    """_conf_via_portable shells the real build-repo-portable.py with `--channel <ch>`
    and must produce a valid, per-channel conf.

    Guards the gen_landing<->build-repo-portable.py --print-conf contract: a future
    change to its required-arg/--channel contract must break here, not reach the
    live publish workflow. All four channels are exercised (branch coverage) — every
    one of them has its OWN repo/conf (issue #2147).
    """
    base: str = "https://pfblockerng.github.io/pkg"

    for channel in gl.CH_ORDER:
        conf: str = gl._conf_via_portable(base, channel)
        assert conf, f"{channel} conf must be non-empty"
        assert f"pfblockerng-{channel}: {{" in conf
        assert f"{base}/{channel}/<varver>" in conf


# ── _embed_hook: splice the boot hook into install.sh's stub body ─────────────


def test_embed_hook_missing_markers_raises_value_error() -> None:
    with pytest.raises(ValueError, match="embed markers"):
        gl._embed_hook("#!/bin/sh\nno markers here\n", "hook body\n")


def test_embed_hook_misordered_markers_raises_value_error() -> None:
    script_text = f"{gl._HOOK_EMBED_END}\n{gl._HOOK_EMBED_BEGIN}\n"
    with pytest.raises(ValueError, match="embed markers"):
        gl._embed_hook(script_text, "hook body\n")


def test_embed_hook_rejects_hook_text_containing_the_heredoc_delimiter() -> None:
    script_text = f"{gl._HOOK_EMBED_BEGIN}\nstub\n{gl._HOOK_EMBED_END}\n"
    hostile_hook = f"echo {gl._HOOK_HEREDOC}\n"
    with pytest.raises(ValueError, match="heredoc delimiter"):
        gl._embed_hook(script_text, hostile_hook)


def test_embed_hook_keeps_the_marker_lines_around_the_heredoc_in_the_output() -> None:
    """Unlike the retired ``_embed_common`` (which replaced its whole marked block,
    markers included), ``_embed_hook`` keeps the BEGIN/END marker lines themselves —
    only the stub body between them is replaced by the heredoc."""
    script_text = f'#!/bin/sh\n{gl._HOOK_EMBED_BEGIN}\nstub body\n{gl._HOOK_EMBED_END}\npfb_channel_install "$@"\n'
    hook_text = "pfb_hook_body() {\n    :\n}\n"

    out = gl._embed_hook(script_text, hook_text)

    assert gl._HOOK_EMBED_BEGIN in out
    assert gl._HOOK_EMBED_END in out
    assert "stub body" not in out
    assert f"cat <<'{gl._HOOK_HEREDOC}'" in out
    assert hook_text in out
    assert out.startswith("#!/bin/sh\n")
    assert out.endswith('pfb_channel_install "$@"\n')


def test_write_site_publishes_install_script(tmp_path: Path, monkeypatch: Any) -> None:
    """write_site() publishes a self-contained install.sh from the pkg-site tree
    (issue #2450) — the SOLE client entry point for all four channels: the boot
    hook is embedded via the PFB_EMBED_HOOK splice, so the published script needs
    no sibling file on disk. Sibling recipes/*.sh are also mirrored.
    """
    import subprocess

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    gl.write_site(str(site), f"file://{site}", str(_PKG_SITE_DIR))

    assert sorted(p.name for p in site.iterdir() if p.name.startswith("install")) == ["install.sh"], (
        "write_site must publish EXACTLY install.sh, no per-channel/legacy scripts"
    )
    for ch in gl.CH_ORDER:
        assert (site / "recipes" / f"{ch}.sh").is_file(), f"missing mirrored recipe for {ch}"

    published = site / "install.sh"
    assert published.exists(), "write_site must produce site/install.sh"
    assert os.access(str(published), os.X_OK), "install.sh must be executable"
    text = published.read_text()
    assert 'pfb_channel_install "$@"' in text
    assert "--channel" in text, "the published script must still parse --channel"
    assert f"cat <<'{gl._HOOK_HEREDOC}'" in text, "the boot hook must be embedded, not left as the stub body"
    assert "PROVIDE: pfblockerng_repo_generate" in text, "embedded hook body must contain the rc.d PROVIDE pragma"
    sh_n = subprocess.run(["sh", "-n"], input=text, text=True, capture_output=True)
    assert sh_n.returncode == 0, f"sh -n failed on published install.sh:\n{sh_n.stderr}"


def test_published_installer_runs_piped_with_embedded_hook(tmp_path: Path, monkeypatch: Any) -> None:
    """Scenario: the published install.sh converges a fresh box when piped into
    `sh -s -- --channel stable` from a directory with NO scripts/ tree at all (issue
    #2416 follow-up) — proving the PFB_EMBED_HOOK splice is self-contained. Mirrors
    ``test_published_add_repo_embeds_hook_and_installs_piped``'s technique; reuses
    ``tests.test_channel_install``'s fake pkg(8) stub (already proven against every branch
    of ``pfb_channel_install``) rather than re-deriving pkg's behaviour here.
    """
    import subprocess

    from tests.test_channel_install import _PKG_STUB, _seed_box

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    base = f"file://{site}"
    gl.write_site(str(site), base, str(_PKG_SITE_DIR))
    published_text = (site / "install.sh").read_text()

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
        ["sh", "-s", "--", "--channel", "stable"],
        input=published_text,
        text=True,
        capture_output=True,
        env=env,
        # Run from a directory with NO scripts/ tree — forces the embedded hook
        # fallback path (HOOK_SRC resolves relative to $0, which is "sh" when piped).
        cwd=str(tmp_path),
    )

    assert result.returncode == 0, (
        f"install.sh failed (exit {result.returncode}):\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
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


def test_published_installer_never_treats_the_on_box_hook_as_its_checkout_source(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The published installer never mistakes the on-box hook for its checkout
    sibling. From cwd ``/usr/local/etc`` (``ROOT=""``) ``SCRIPT_DIR/rc.d/...`` IS
    the installed hook path, and a leftover downloaded install.sh sitting there
    makes the directory look like a checkout; the embedded hook must still win.

    Before-state: a stale hook AND a leftover install.sh copy are pre-seeded at
    the collision path. After a piped run from that cwd, the installed hook must
    be the real embedded copy, byte-identical to the repository source.
    """
    import subprocess

    from tests.test_channel_install import _PKG_STUB, _seed_box

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    base = f"file://{site}"
    gl.write_site(str(site), base, str(_PKG_SITE_DIR))
    published_text = (site / "install.sh").read_text()

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

    # Before-state: a STALE hook already "installed" on-box.
    hook_path = root / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"
    hook_path.parent.mkdir(parents=True)
    hook_path.write_text("#!/bin/sh\n# STALE\n")
    assert hook_path.read_text() == "#!/bin/sh\n# STALE\n", "before-state: the stale hook must be in place"

    # cwd = /usr/local/etc directly — its "rc.d/..." IS the on-box hook path (the
    # real collision; NOT /usr/local/etc/pkg, one level off). A leftover install.sh
    # copy also sits here (an earlier manual download), satisfying the old guard's
    # "-f SCRIPT_DIR/install.sh" even though THIS run is piped fresh.
    cwd = root / "usr" / "local" / "etc"
    (cwd / "install.sh").write_text(published_text)

    env = {
        **os.environ,
        "PFBLOCKERNG_ROOT": str(root),
        "PKG_BIN": str(fake_pkg),
        "PFB_TEST_ROOT": str(root),
        "PFB_BASE_URL": base,
    }
    result = subprocess.run(
        ["sh", "-s", "--", "--channel", "stable"],
        input=published_text,
        text=True,
        capture_output=True,
        env=env,
        cwd=str(cwd),
    )

    assert result.returncode == 0, (
        f"install.sh failed (exit {result.returncode}):\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    real_hook = (_SCRIPTS_DIR / "rc.d" / "pfblockerng_repo_generate.sh").read_text()
    assert hook_path.read_text() == real_hook, (
        "the stale on-box hook must be replaced by the embedded copy, never mistaken for a checkout sibling\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_published_installer_saved_to_disk_still_replaces_a_stale_on_box_hook(tmp_path: Path, monkeypatch: Any) -> None:
    """The same collision, hit by running the published artifact BY PATH rather
    than piped — ``fetch -o install.sh ... && sh install.sh`` saved straight into
    ``/usr/local/etc``, so ``SCRIPT_DIR`` is that directory and ``HOOK_SRC`` is the
    stale on-box hook itself. The embedded hook must still win.

    Before-state: a stale hook is pre-seeded at the on-box path, which is also
    where the published install.sh is saved. After running it BY PATH, the
    installed hook must be the real embedded copy.
    """
    import subprocess

    from tests.test_channel_install import _PKG_STUB, _seed_box

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    base = f"file://{site}"
    gl.write_site(str(site), base, str(_PKG_SITE_DIR))
    published_text = (site / "install.sh").read_text()

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

    # Before-state: a STALE hook already "installed" on-box.
    hook_path = root / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"
    hook_path.parent.mkdir(parents=True)
    hook_path.write_text("#!/bin/sh\n# STALE\n")
    assert hook_path.read_text() == "#!/bin/sh\n# STALE\n", "before-state: the stale hook must be in place"

    # The published install.sh SAVED right beside the on-box hook's own directory.
    saved_install = root / "usr" / "local" / "etc" / "install.sh"
    saved_install.write_text(published_text)
    saved_install.chmod(0o755)

    env = {
        **os.environ,
        "PFBLOCKERNG_ROOT": str(root),
        "PKG_BIN": str(fake_pkg),
        "PFB_TEST_ROOT": str(root),
        "PFB_BASE_URL": base,
    }
    result = subprocess.run(
        ["sh", str(saved_install), "--channel", "stable"],
        text=True,
        capture_output=True,
        env=env,
        cwd=str(tmp_path),
    )

    assert result.returncode == 0, (
        f"install.sh failed (exit {result.returncode}):\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    real_hook = (_SCRIPTS_DIR / "rc.d" / "pfblockerng_repo_generate.sh").read_text()
    assert hook_path.read_text() == real_hook, (
        "the stale on-box hook must be replaced by the embedded copy, even when install.sh is saved to disk\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_write_site_bakes_the_sites_base_url_into_the_published_installer(tmp_path: Path, monkeypatch: Any) -> None:
    """A fork publishing from a non-default base (or a staged prefix) must ship an
    installer whose OWN ``PFB_BASE_URL`` default points at ITS base — not the
    hardcoded upstream default baked into the repository copy of install.sh.
    Without a ``PFB_BASE_URL`` override, a piped run must resolve the conf against
    the site's real base.
    """
    import subprocess

    from tests.test_channel_install import _PKG_STUB, _seed_box

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    fork_base = "https://fork.example.org/mypkg"
    gl.write_site(str(site), fork_base, str(_PKG_SITE_DIR))

    text = (site / "install.sh").read_text()
    assert f"PFB_DEFAULT_BASE_URL='{fork_base}'" in text, (
        "install.sh must default PFB_BASE_URL to the site's own base, not upstream's"
    )
    assert 'PFB_BASE_URL="${PFB_BASE_URL:-${PFB_DEFAULT_BASE_URL}}"' in text, (
        "the baked default must be referenced through a variable, never interpolated inline"
    )

    # Running the published installer piped, with NO PFB_BASE_URL override, must
    # resolve the conf against the FORK's base — proving the baked default (not
    # just its text) drives the run.
    published_text = text

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

    env = {
        **{k: v for k, v in os.environ.items() if k != "PFB_BASE_URL"},
        "PFBLOCKERNG_ROOT": str(root),
        "PKG_BIN": str(fake_pkg),
        "PFB_TEST_ROOT": str(root),
    }
    result = subprocess.run(
        ["sh", "-s", "--", "--channel", "stable"],
        input=published_text,
        text=True,
        capture_output=True,
        env=env,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, (
        f"install.sh failed (exit {result.returncode}):\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    conf_path = root / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng-stable.conf"
    conf_text = conf_path.read_text()
    assert f'url: "{fork_base}/stable/ce-2.8"' in conf_text, conf_text


def test_write_site_bakes_a_base_url_containing_shell_metacharacters_as_inert_data(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """``_bake_base_url`` interpolates *base* into install.sh's own source text —
    a base built from ``$(...)``, backticks, ``'``, ``"``, or ``&`` must land as
    inert shell DATA, never executable shell syntax.
    A fork's configured base URL is config, not code; the published installer
    must run it through unchanged and execute nothing from it.
    """
    import subprocess

    from tests.test_channel_install import _PKG_STUB, _seed_box

    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    probe = tmp_path / "pwned"
    evil_base = f"https://evil.example.org/$(touch {probe})`touch {probe}`'\"&"
    gl.write_site(str(site), evil_base, str(_PKG_SITE_DIR))

    published_text = (site / "install.sh").read_text()
    sh_n = subprocess.run(["sh", "-n"], input=published_text, text=True, capture_output=True)
    assert sh_n.returncode == 0, f"sh -n failed on install.sh with an injected base:\n{sh_n.stderr}"

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

    # No PFB_BASE_URL override — the piped run must resolve the BAKED default,
    # proving the value (not just its escaped text) is what the shell sees.
    env = {
        **{k: v for k, v in os.environ.items() if k != "PFB_BASE_URL"},
        "PFBLOCKERNG_ROOT": str(root),
        "PKG_BIN": str(fake_pkg),
        "PFB_TEST_ROOT": str(root),
    }
    result = subprocess.run(
        ["sh", "-s", "--", "--channel", "stable"],
        input=published_text,
        text=True,
        capture_output=True,
        env=env,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, (
        f"install.sh failed (exit {result.returncode}):\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert not probe.exists(), (
        "the base URL's embedded shell metacharacters must never execute — probe file must be absent\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    conf_path = root / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng-stable.conf"
    conf_text = conf_path.read_text()
    assert f'url: "{evil_base}/stable/ce-2.8"' in conf_text, (
        f"the conf must carry the LITERAL base string, unexpanded:\n{conf_text}"
    )


# ── build_site_tree: the pkg-site source tree, baked + {base}-substituted ─────


def _write_tree_file(root: Path, rel: str, content: bytes, *, mode: int = 0o644) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return path


def test_build_site_tree_copies_a_plain_file_verbatim_and_preserves_mode(tmp_path: Path) -> None:
    """R1: a tree file with no .sh/{base} relevance is copied byte-for-byte, mode kept —
    both an executable and a non-executable fixture file."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, "bin/tool", b"#!/bin/sh\necho hi\n", mode=0o755)
    _write_tree_file(tree, "notes.txt", b"just some bytes, no markers here\n", mode=0o644)

    built = gl.build_site_tree(str(tree), "https://x/pkg")

    data, mode = built["bin/tool"]
    assert data == b"#!/bin/sh\necho hi\n"
    assert stat.S_IMODE(mode) == 0o755
    data, mode = built["notes.txt"]
    assert data == b"just some bytes, no markers here\n"
    assert stat.S_IMODE(mode) == 0o644


def test_build_site_tree_bakes_and_embeds_install_sh(tmp_path: Path) -> None:
    """R2: a .sh carrying BOTH the default-URL line and the embed markers gets baked
    and hook-embedded — exercised against the REAL scripts/install.sh via a symlink,
    mirroring the pkg-site/install.sh convention."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "install.sh").symlink_to(_SCRIPTS_DIR / "install.sh")

    built = gl.build_site_tree(str(tree), "https://fork.example/pkg")

    data, mode = built["install.sh"]
    text = data.decode()
    assert "PFB_DEFAULT_BASE_URL='https://fork.example/pkg'" in text
    assert f"cat <<'{gl._HOOK_HEREDOC}'" in text
    assert stat.S_IMODE(mode) == 0o755  # the real install.sh is executable


def test_build_site_tree_recipe_only_substitutes_base_no_bake_no_embed(tmp_path: Path) -> None:
    """R3: a .sh file with neither the default-URL line nor the embed markers gets
    ONLY its {base} token substituted — the recipe convention."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, "recipes/stable.sh", b"fetch -qo - {base}/install.sh | sh -s -- --channel stable\n")

    built = gl.build_site_tree(str(tree), "https://x/pkg")

    data, _mode = built["recipes/stable.sh"]
    assert data == b"fetch -qo - https://x/pkg/install.sh | sh -s -- --channel stable\n"


def test_build_site_tree_substitutes_base_in_non_sh_utf8_and_copies_binary_unchanged(tmp_path: Path) -> None:
    """R4: a non-.sh UTF-8 file with {base} gets it substituted; a binary (non-UTF-8)
    file is copied unchanged, never crashing the {base} substitution pass."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, "readme.txt", "see {base}/install.sh\n".encode())
    binary = bytes(range(256))
    _write_tree_file(tree, "blob.bin", binary)

    built = gl.build_site_tree(str(tree), "https://x/pkg")

    assert built["readme.txt"][0] == b"see https://x/pkg/install.sh\n"
    assert built["blob.bin"][0] == binary


def test_build_site_tree_mirrors_a_dotfile(tmp_path: Path) -> None:
    """R5: a dotfile (.nojekyll) in the tree is mirrored like any other file."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, ".nojekyll", b"")

    built = gl.build_site_tree(str(tree), "https://x/pkg")

    assert built[".nojekyll"] == (b"", 0o644)


def test_build_site_tree_two_default_url_lines_raises(tmp_path: Path) -> None:
    """H6: a .sh carrying the default-URL line TWICE fails loud (existing _bake_base_url
    rule), never silently baking the first occurrence."""
    tree = tmp_path / "tree"
    doubled = f"{gl._BASE_URL_DEFAULT_LINE}\n{gl._BASE_URL_DEFAULT_LINE}\n"
    _write_tree_file(tree, "bad.sh", doubled.encode())

    with pytest.raises(ValueError, match="found 2"):
        gl.build_site_tree(str(tree), "https://x/pkg")


def test_build_site_tree_half_marked_sh_raises(tmp_path: Path) -> None:
    """Blocking finding, PR #2451 review: build_site_tree used to trigger
    ``_embed_hook`` ONLY when the BEGIN marker was present, so a ``.sh`` carrying
    just the END marker (a drifted/half-edited script) fell through unpatched and
    unraised. The trigger now fires on EITHER marker being present, so a half-marked
    file always reaches ``_embed_hook``'s own missing-marker ``ValueError`` instead
    of silently publishing broken content."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, "half.sh", f"#!/bin/sh\n{gl._HOOK_EMBED_END}\n".encode())

    with pytest.raises(ValueError, match="embed markers"):
        gl.build_site_tree(str(tree), "https://x/pkg")


def test_scripts_install_sh_carries_the_bake_line_and_both_embed_markers() -> None:
    """Drift pin (blocking finding, PR #2451 review): build_site_tree only bakes or
    hook-embeds a .sh file when ITS OWN trigger substring occurs in the text — a
    correct, intentional design (recipes/*.sh carry neither and must stay
    untouched by either splice). That design depends on the repository's own
    ``scripts/install.sh`` — the ONE file in the real pkg-site/ tree that carries
    both — never drifting to a partial set; install.sh changes only via a reviewed
    PR, so this pin (not runtime code) is what keeps a drifted repository copy
    from silently publishing an unbaked or unpatched installer."""
    text = (_SCRIPTS_DIR / "install.sh").read_text()
    assert text.count(gl._BASE_URL_DEFAULT_LINE) == 1
    assert text.count(gl._HOOK_EMBED_BEGIN) == 1
    assert text.count(gl._HOOK_EMBED_END) == 1


# ── sync_site: mirror the desired tree into docs/, never touching a catalogue dir ──


def test_sync_site_writes_every_desired_file_and_deletes_extraneous(tmp_path: Path) -> None:
    """R10: extraneous renderer-side files (legacy scripts, a stray browse/ leftover,
    a junk dir) are removed and their now-empty parent dirs pruned; a stray non-index
    file INSIDE a catalogue dir survives untouched."""
    docs = tmp_path / "docs"
    _touch(docs / "add-repo.sh")
    _touch(docs / "migrate-channel.sh")
    _touch(docs / "browse" / "edge" / "old-varver" / "index.html")
    _touch(docs / "junk" / "x.txt")
    _touch(docs / "testing" / "ce-2.9" / "whatever")

    desired = {"install.sh": (b"#!/bin/sh\n", 0o755)}
    written, deleted = gl.sync_site(str(docs), desired)

    assert written == ["install.sh"]
    assert (docs / "install.sh").read_bytes() == b"#!/bin/sh\n"
    assert not (docs / "add-repo.sh").exists()
    assert not (docs / "migrate-channel.sh").exists()
    assert not (docs / "browse").exists()  # emptied and pruned
    assert not (docs / "junk").exists()
    assert (docs / "testing" / "ce-2.9" / "whatever").is_file()  # catalogue-owned, untouched
    assert sorted(deleted) == sorted(
        [
            "add-repo.sh",
            "browse/edge/old-varver/index.html",
            "junk/x.txt",
            "migrate-channel.sh",
        ]
    )


def test_sync_site_leaves_a_legacy_index_html_under_a_catalogue_dir_untouched(tmp_path: Path) -> None:
    """R9: a pre-existing legacy index.html anywhere under a catalogue prefix is left
    byte-for-byte alone by the renderer — no add/modify/delete under a catalogue
    prefix, ever (owner ruling: any one-time cleanup of such a leftover is an
    operator task run once after the first publish with this script, never logic
    carried in the script itself). Every sibling file (meta.conf/.pkg bytes) is
    likewise untouched, and the render is byte-identical before/after."""
    docs = tmp_path / "docs"
    stable_index = docs / "stable" / "index.html"
    cell_index = docs / "stable" / "ce-2.8" / "index.html"
    _touch(stable_index)
    _touch(cell_index)
    meta = docs / "stable" / "ce-2.8" / "meta.conf"
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_bytes(b"version = 2;\n")
    pkg = docs / "stable" / "ce-2.8" / f"{_CANON}-1.0.0.pkg"
    pkg.write_bytes(b"pkg-bytes")
    before = _snapshot(docs)

    written, deleted = gl.sync_site(str(docs), {})

    assert written == []
    assert deleted == []
    assert stable_index.is_file()
    assert cell_index.is_file()
    assert meta.read_bytes() == b"version = 2;\n"
    assert pkg.read_bytes() == b"pkg-bytes"
    assert _snapshot(docs) == before


def test_sync_site_never_prunes_an_empty_catalogue_owned_dir(tmp_path: Path) -> None:
    """`_prune_empty_dirs` must skip catalogue-owned trees, matching the "never
    added, modified, or deleted here — no exception" contract sync_site's own
    docstring states (CodeRabbit finding id 3791471640, PR #2451 review N3): an
    empty ``docs/staging/`` (never git-visible, but reachable via a partial
    publisher run) and an empty ``docs/stable/empty/`` both survive."""
    docs = tmp_path / "docs"
    (docs / "staging").mkdir(parents=True)
    (docs / "stable" / "empty").mkdir(parents=True)

    written, deleted = gl.sync_site(str(docs), {})

    assert written == []
    assert deleted == []
    assert (docs / "staging").is_dir()
    assert (docs / "stable" / "empty").is_dir()


def test_sync_site_refuses_a_desired_path_under_a_catalogue_prefix(tmp_path: Path) -> None:
    """H3: a desired site path rooted under a catalogue prefix raises BEFORE writing
    anything — the renderer must be structurally unable to write there."""
    docs = tmp_path / "docs"
    _touch(docs / "existing.txt")
    desired = {"install.sh": (b"x", 0o644), "stable/x": (b"evil", 0o644)}

    with pytest.raises(ValueError, match="catalogue-owned"):
        gl.sync_site(str(docs), desired)

    assert not (docs / "install.sh").exists()  # nothing written — checked before any write
    assert (docs / "existing.txt").is_file()  # untouched


def test_sync_site_never_follows_a_symlink_inside_docs(tmp_path: Path) -> None:
    """A symlink living directly under docs/ (not inside a catalogue prefix) is
    skipped by the walk — never deleted, never mistaken for a desired/extraneous
    regular file."""
    docs = tmp_path / "docs"
    docs.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    (docs / "link.txt").symlink_to(target)

    written, deleted = gl.sync_site(str(docs), {})

    assert written == [] and deleted == []
    assert (docs / "link.txt").is_symlink()


def test_sync_site_refuses_to_write_through_a_symlinked_leaf(tmp_path: Path) -> None:
    """A pre-existing symlink AT a desired path (e.g. a leftover ``install.sh`` ->
    outside docs/) must never be written through — the write pass raises before
    touching it, and the symlink's target is left byte-for-byte alone (PR #2451
    review N2: the write pass used to follow it while the delete pass already
    refused to)."""
    docs = tmp_path / "docs"
    docs.mkdir()
    victim = tmp_path / "outside" / "victim.txt"
    victim.parent.mkdir(parents=True)
    victim.write_text("untouched")
    (docs / "install.sh").symlink_to(victim)

    with pytest.raises(ValueError, match="symlink"):
        gl.sync_site(str(docs), {"install.sh": (b"RENDERED\n", 0o755)})

    assert victim.read_text() == "untouched"
    assert (docs / "install.sh").is_symlink()


def test_sync_site_refuses_to_write_through_a_symlinked_directory(tmp_path: Path) -> None:
    """A symlinked DIRECTORY component between docs/ and the write target (e.g. a
    leftover ``browse`` -> ``stable``) must also be refused — the write pass walks
    every path component, not just the leaf."""
    docs = tmp_path / "docs"
    (docs / "stable").mkdir(parents=True)
    (docs / "browse").symlink_to(docs / "stable")

    with pytest.raises(ValueError, match="symlink"):
        gl.sync_site(str(docs), {"browse/edge/ce-2.8/index.html": (b"<html></html>", 0o644)})

    assert (docs / "browse").is_symlink()
    assert not (docs / "stable" / "edge").exists()


def test_sync_site_refuses_a_desired_key_containing_a_traversal_segment(tmp_path: Path) -> None:
    """A desired key carrying a `..` segment must never be written — even though
    ``write_site`` never produces one today, an internal caller passing one would
    otherwise write straight through it (PR #2451 review N2)."""
    docs = tmp_path / "docs"
    docs.mkdir()
    outside_marker = tmp_path / "x.txt"

    with pytest.raises(ValueError, match="safe relative path"):
        gl.sync_site(str(docs), {"../x.txt": (b"escaped\n", 0o644)})

    assert not outside_marker.exists()


# ── render_page / _channel_card: recipe text from the built site tree ─────────


def test_channel_card_recipe_is_verbatim_built_tree_text() -> None:
    """R6: a published channel's card shows recipes/<channel>.sh's built (already
    {base}-substituted) text verbatim, HTML-escaped."""
    base = "https://x/pkg"
    pkgs = [_pkg("stable", _CANON, "1.0.0", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]
    site_tree = {"recipes/stable.sh": (f"fetch -qo - {base}/install.sh | sh -s -- --channel stable\n".encode(), 0o644)}

    page = gl.render_page(base, pkgs, _stub_conf, site_tree)

    assert f"<pre>fetch -qo - {base}/install.sh | sh -s -- --channel stable</pre>" in page


def test_channel_card_missing_recipe_for_published_channel_raises() -> None:
    """R6: a published channel with NO recipes/<channel>.sh in the site tree fails
    loudly, naming the missing path — never a silently blank recipe."""
    pkgs = [_pkg("stable", _CANON, "1.0.0", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]

    with pytest.raises(ValueError, match="recipes/stable.sh"):
        gl.render_page("https://x/pkg", pkgs, _stub_conf, {})


def test_channel_card_hostile_recipe_text_escaped_and_base_substituted() -> None:
    """H1: a recipe carrying HTML-special characters and a literal $ is HTML-escaped
    in the card exactly once (no double-escaping), with {base} still substituted."""
    base = "https://x/pkg"
    pkgs = [_pkg("stable", _CANON, "1.0.0", "FreeBSD:15:*", "stable/ce-2.8/x.pkg")]
    hostile = 'fetch -qo - {base}/i.sh | sh -s -- --channel "<stable>" && echo $HOME\n'
    site_tree = {"recipes/stable.sh": (hostile.replace("{base}", base).encode(), 0o644)}

    page = gl.render_page(base, pkgs, _stub_conf, site_tree)

    escaped = html.escape(hostile.replace("{base}", base).strip())
    assert f"<pre>{escaped}</pre>" in page
    assert "&amp;lt;" not in page  # never double-escaped
    assert '<stable>"' not in page  # the raw (unescaped) text never appears


def test_write_site_base_with_trailing_slash_stripped_once(tmp_path: Path, monkeypatch: Any) -> None:
    """H2: write_site strips a trailing '/' from base ONCE before it drives
    build_site_tree's {base} substitution (existing rstrip("/") behaviour) — the
    published recipe carries exactly one slash between base and install.sh."""
    site = tmp_path / "site"
    _touch(site / "stable" / "ce-2.8" / f"{_CANON}-1.0.0.pkg")
    monkeypatch.setattr(gl, "read_compact_manifest", lambda p: {"name": _CANON, "version": "1.0.0", "abi": "x"})
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    gl.write_site(str(site), "https://x/pkg/", str(_PKG_SITE_DIR))

    recipe = (site / "recipes" / "stable.sh").read_text()
    assert recipe == "fetch -qo - https://x/pkg/install.sh | sh -s -- --channel stable\n"
    assert "https://x/pkg//install.sh" not in recipe


# ── write_site / main(): the pkg-site renderer CLI (issue #2450) ──────────────


def test_write_site_signature_pins_the_positional_shape() -> None:
    """Pins write_site(site, base, site_tree, matrix=None) — a rename/reorder here
    breaks step 2's (render-pkg-site.sh) call site silently."""
    sig = inspect.signature(gl.write_site)
    assert list(sig.parameters) == ["site", "base", "site_tree", "matrix"]
    assert sig.parameters["matrix"].default is None


def test_main_cli_accepts_the_production_positional_and_flag_shape(tmp_path: Path, monkeypatch: Any) -> None:
    """main(argv) accepts <site> <base_url> --site-tree <tree> --matrix <file>."""
    site = tmp_path / "site"
    site.mkdir()
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text("[]")
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    rc = gl.main([str(site), "https://x/pkg", "--site-tree", str(_PKG_SITE_DIR), "--matrix", str(matrix_file)])

    assert rc == 0
    assert (site / "index.html").is_file()


def test_main_requires_site_tree(tmp_path: Path) -> None:
    """R14: --site-tree is REQUIRED — a missing flag is a usage error, exit != 0,
    nothing written."""
    site = tmp_path / "site"
    site.mkdir()

    with pytest.raises(SystemExit) as exc:
        gl.main([str(site), "https://x/pkg"])

    assert exc.value.code != 0
    assert list(site.iterdir()) == []


def test_main_client_scripts_only_flag_is_gone(tmp_path: Path) -> None:
    """R14: --client-scripts-only no longer exists — passing it is an argparse
    usage error, not a silently-ignored flag."""
    site = tmp_path / "site"
    site.mkdir()

    with pytest.raises(SystemExit) as exc:
        gl.main([str(site), "https://x/pkg", "--site-tree", str(_PKG_SITE_DIR), "--client-scripts-only"])

    assert exc.value.code == 2
    assert list(site.iterdir()) == []


def test_main_production_shape_with_real_pkg_site_and_matrix(tmp_path: Path, monkeypatch: Any) -> None:
    """The full production CLI shape: gen_landing.py <docs> <base> --site-tree
    <pkg-site> --matrix <file>, against the REAL pkg-site/ tree."""
    site = tmp_path / "docs"
    site.mkdir()
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text("[]")
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    rc = gl.main([str(site), "https://x/pkg", "--site-tree", str(_PKG_SITE_DIR), "--matrix", str(matrix_file)])

    assert rc == 0
    assert (site / "install.sh").is_file()
    assert (site / ".nojekyll").is_file()
    assert (site / "CNAME").read_text() == "pkg.pfblockerng.com\n"
    assert (site / "index.html").is_file()
    assert (site / "browse.html").is_file()
    assert 'href="./CNAME"' not in (site / "browse.html").read_text()


# ── Determinism: two renders of the same input are byte-identical (issue #2450) ──


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file() and not p.is_symlink()}


def test_write_site_is_deterministic_across_two_renders_even_with_mtime_churn(tmp_path: Path, monkeypatch: Any) -> None:
    """R12: rendering the SAME inputs twice produces byte-identical output — even
    when a file's mtime changes between runs (no mtime ever leaks into a render).
    A .pkg with no epoch at all, and its meta.conf sibling, both render an em dash.
    """
    site = tmp_path / "site"
    cell = site / "stable" / "ce-2.8"
    pkg = cell / f"{_CANON}-1.0.0.pkg"
    _write_pkg(pkg, annotations={}, version="1.0.0")
    (cell / "meta.conf").write_text("version = 2;\n")
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    gl.write_site(str(site), "https://x/pkg", str(_PKG_SITE_DIR))
    first = _snapshot(site)

    listing = (site / "browse" / "stable" / "ce-2.8" / "index.html").read_text()
    assert "&mdash;" in _autoindex_row(listing, pkg.name)
    assert "&mdash;" in _autoindex_row(listing, "meta.conf")

    # Touch every file's mtime forward between runs — must not change a single byte.
    for p in site.rglob("*"):
        if p.is_file() and not p.is_symlink():
            os.utime(p, (2_000_000_000, 2_000_000_000))

    gl.write_site(str(site), "https://x/pkg", str(_PKG_SITE_DIR))
    second = _snapshot(site)

    assert first == second


# ── README drift guard + install.sh symlink (issue #2450) ─────────────────────

_README_FETCH_RE = re.compile(r"fetch -qo - .*install\.sh \| sh -s -- --channel (\w+)")


def test_readme_install_snippets_match_the_pkg_site_recipes() -> None:
    """R15: every README install one-liner equals its pkg-site/recipes/<ch>.sh with
    {base} substituted to the production base URL — the README never drifts from
    the recipe the renderer actually ships."""
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    channels = _README_FETCH_RE.findall(readme)
    assert channels, "README.md carries no fetch|sh --channel snippet to check"

    base = "https://pfblockerng.github.io/pkg"
    for line in readme.splitlines():
        m = _README_FETCH_RE.search(line)
        if not m:
            continue
        ch = m.group(1)
        recipe = (_PKG_SITE_DIR / "recipes" / f"{ch}.sh").read_text().replace("{base}", base).strip()
        assert line.strip() == recipe, f"README {ch} snippet drifted from pkg-site/recipes/{ch}.sh"


def test_pkg_site_install_sh_is_a_symlink_to_scripts_install_sh() -> None:
    """R16: pkg-site/install.sh is a git symlink resolving to scripts/install.sh —
    the repository copy stays the one source of truth."""
    link = _PKG_SITE_DIR / "install.sh"
    assert link.is_symlink()
    assert os.path.realpath(link) == os.path.realpath(_SCRIPTS_DIR / "install.sh")


# ── Hostile: a site-tree file shadowing a rendered page name (issue #2450) ────


def test_rendered_page_wins_over_a_same_named_site_tree_file(tmp_path: Path, monkeypatch: Any) -> None:
    """H4: a site-tree file literally named index.html/browse.html loses to the
    rendered page of the same name — the render always wins."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, "index.html", b"<p>not the real landing page</p>")
    _write_tree_file(tree, "browse.html", b"<p>not the real browse page</p>")
    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    gl.write_site(str(site), "https://x/pkg", str(tree))

    assert "not the real landing page" not in (site / "index.html").read_text()
    assert "not the real browse page" not in (site / "browse.html").read_text()


def test_write_site_empty_tree_and_docs_renders_four_cards_no_crash(tmp_path: Path, monkeypatch: Any) -> None:
    """H5: an almost-empty site tree (only .nojekyll, no recipes) over empty docs
    still renders four 'not yet published' cards without crashing — no channel is
    published, so the missing recipes are never looked up."""
    tree = tmp_path / "tree"
    _write_tree_file(tree, ".nojekyll", b"")
    site = tmp_path / "site"
    site.mkdir()
    monkeypatch.setattr(gl, "_conf_via_portable", lambda base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://x/pkg", str(tree))

    assert n == 0
    index_html = (site / "index.html").read_text()
    assert index_html.count("not yet published") == 4
