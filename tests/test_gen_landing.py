"""Tests for scripts/gen_landing.py — the human-navigable pkg-repo landing page.

The generator turns a built per-ABI catalog tree into a styled index: channel
install cards, a Version x ABI table read from each .pkg manifest, and per-dir
listings that show packages but hide pkg(8) catalog plumbing. These tests pin
that behaviour without needing real .pkg archives (the manifest reader is
injected / the render helpers are pure).
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any

# Load scripts/gen_landing.py (a script path, not an installed module).
_SPEC = importlib.util.spec_from_file_location(
    "gen_landing", Path(__file__).resolve().parent.parent / "scripts" / "gen_landing.py"
)
assert _SPEC and _SPEC.loader
gl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gl)


# ── Pure helpers ──────────────────────────────────────────────────────────────


def test_channel_of_maps_each_suffix() -> None:
    """Every package-name suffix routes to its channel (each branch covered)."""
    assert gl.channel_of("pfSense-pkg-pfBlockerNG-nightly") == "nightly"
    assert gl.channel_of("pfSense-pkg-pfBlockerNG-devel") == "devel"
    assert gl.channel_of("pfSense-pkg-pfBlockerNG") == "stable"


def test_is_package_file_excludes_catalog_plumbing() -> None:
    """A real package is a .pkg; packagesite.pkg / data.pkg / non-.pkg are not."""
    assert gl.is_package_file("pfSense-pkg-pfBlockerNG-devel-3.2.16.pkg")
    assert not gl.is_package_file("packagesite.pkg")
    assert not gl.is_package_file("data.pkg")
    assert not gl.is_package_file("meta.conf")


def test_human_size_units() -> None:
    assert gl.human_size(512) == "512 B"
    assert gl.human_size(1024) == "1.0 KiB"
    assert gl.human_size(1024 * 1024 * 3) == "3.0 MiB"


def test_ver_key_orders_nightly_after_release() -> None:
    """The dated nightly version sorts above the bare PORTVERSION."""
    assert gl.ver_key("3.2.16.20260614.20") > gl.ver_key("3.2.16")
    assert gl.ver_key("3.2.16.20260614.20") > gl.ver_key("3.2.16.20260614.7")


# ── collect_packages: walk + classify + exclude plumbing ──────────────────────


def _touch(path: Path, size: int = 10) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def test_collect_packages_walks_and_excludes_metadata(tmp_path: Path) -> None:
    """Given a catalog tree with packages + pkg(8) metadata, collect only packages."""
    # Given: a devel + nightly bucket per ABI, each also holding catalog plumbing.
    site = tmp_path / "site"
    layout = {
        "FreeBSD:16:amd64/pfSense-pkg-pfBlockerNG-devel-3.2.16.pkg": ("pfSense-pkg-pfBlockerNG-devel", "3.2.16"),
        "nightly/FreeBSD:16:amd64/pfSense-pkg-pfBlockerNG-nightly-3.2.16.20260614.7.pkg": (
            "pfSense-pkg-pfBlockerNG-nightly",
            "3.2.16.20260614.7",
        ),
    }
    for rel in layout:
        _touch(site / rel)
    for rel in ("FreeBSD:16:amd64", "nightly/FreeBSD:16:amd64"):
        _touch(site / rel / "packagesite.pkg")
        _touch(site / rel / "data.pkg")
        (site / rel / "meta.conf").write_text("version = 2;\n")

    def fake_read(path: str) -> dict[str, str]:
        name, ver = layout[os.path.relpath(path, site)]
        return {"name": name, "version": ver, "abi": Path(path).parent.name}

    # When
    pkgs = gl.collect_packages(str(site), read_manifest=fake_read)

    # Then: only the two real packages, correctly classified; no packagesite/data.
    assert {p["name"] for p in pkgs} == {"pfSense-pkg-pfBlockerNG-devel", "pfSense-pkg-pfBlockerNG-nightly"}
    assert {p["channel"] for p in pkgs} == {"devel", "nightly"}
    assert all(p["rel"].endswith(".pkg") for p in pkgs)
    assert not any("packagesite" in p["rel"] or "data.pkg" in p["rel"] for p in pkgs)


# ── build_table: newest version per (channel, ABI) ────────────────────────────


def _pkg(channel: str, name: str, version: str, abi: str, rel: str, size: int = 10) -> dict[str, Any]:
    return {"channel": channel, "name": name, "version": version, "abi": abi, "rel": rel, "size": size}


def test_build_table_keeps_only_latest_nightly_per_abi() -> None:
    """Scenario: retention keeps several nightlies; the table shows only the newest.

    Given two nightly builds (old + new) for one ABI plus a devel build,
    When the table is built,
    Then the OLD nightly is dropped (proving newest-wins, not just 'all rows')
    and the devel + newest-nightly rows remain, channel-then-ABI sorted.
    """
    old = _pkg("nightly", "pfSense-pkg-pfBlockerNG-nightly", "3.2.16.20260601.1", "FreeBSD:16:amd64", "old.pkg")
    new = _pkg("nightly", "pfSense-pkg-pfBlockerNG-nightly", "3.2.16.20260614.9", "FreeBSD:16:amd64", "new.pkg")
    dev = _pkg("devel", "pfSense-pkg-pfBlockerNG-devel", "3.2.16", "FreeBSD:16:amd64", "dev.pkg")

    rows = gl.build_table([new, old, dev])

    versions = [(r["channel"], r["version"]) for r in rows]
    assert ("nightly", "3.2.16.20260601.1") not in versions  # old build dropped
    assert versions == [("devel", "3.2.16"), ("nightly", "3.2.16.20260614.9")]  # sorted, latest only


def test_latest_versions_per_channel() -> None:
    pkgs = [
        _pkg("nightly", "n", "3.2.16.20260601.1", "a", "1"),
        _pkg("nightly", "n", "3.2.16.20260614.9", "a", "2"),
        _pkg("devel", "d", "3.2.16", "a", "3"),
    ]
    assert gl.latest_versions(pkgs) == {"nightly": "3.2.16.20260614.9", "devel": "3.2.16"}


# ── Rendering ─────────────────────────────────────────────────────────────────


def _stub_conf(channel: str) -> str:
    return f"{channel}-conf-snippet"


def test_render_page_shows_latest_and_empty_stable() -> None:
    """The page shows devel+nightly latest and the install URL; stable (absent) is empty-stated."""
    pkgs = [
        _pkg("devel", "pfSense-pkg-pfBlockerNG-devel", "3.2.16", "FreeBSD:16:aarch64", "FreeBSD:16:aarch64/d.pkg"),
        _pkg(
            "nightly",
            "pfSense-pkg-pfBlockerNG-nightly",
            "3.2.16.20260614.9",
            "FreeBSD:16:aarch64",
            "nightly/FreeBSD:16:aarch64/n.pkg",
        ),
    ]
    base = "https://pfblockerng.github.io/pkg"
    page = gl.render_page(base, pkgs, ["FreeBSD:16:aarch64", "nightly/FreeBSD:16:aarch64"], _stub_conf)

    # Latest versions surfaced for the present channels.
    assert "3.2.16.20260614.9" in page
    # Stable has no package -> empty state, NOT a bogus version.
    assert "not yet published" in page
    # Install one-liner pins this repo's base URL (the working Pages mirror).
    assert f"--base-url {base} devel" in page
    assert "pkg install pfSense-pkg-pfBlockerNG-nightly" in page
    # The manual conf came from the injected conf function.
    assert "devel-conf-snippet" in page
    # Catalog-tree link to the colon-ABI dir is './'-prefixed (browser scheme guard).
    assert 'href="./FreeBSD:16:aarch64/"' in page


def test_render_page_table_empty_when_no_packages() -> None:
    page = gl.render_page("https://x/pkg", [], [], _stub_conf)
    assert "No packages published yet." in page


def test_render_dir_index_lists_package_hides_plumbing() -> None:
    """A per-dir index links the package(s) but not meta.conf/packagesite.pkg/data.pkg."""
    files = ["pfSense-pkg-pfBlockerNG-nightly-3.2.16.20260614.9.pkg", "packagesite.pkg", "data.pkg", "meta.conf"]
    out = gl.render_dir_index("nightly/FreeBSD:16:aarch64", files)
    assert 'href="pfSense-pkg-pfBlockerNG-nightly-3.2.16.20260614.9.pkg"' in out
    assert "packagesite.pkg</a>" not in out
    assert 'href="data.pkg"' not in out
    assert 'href="meta.conf"' not in out
    # Two path segments deep -> back link climbs two levels.
    assert 'href="../../"' in out


def test_write_site_end_to_end(tmp_path: Path, monkeypatch: Any) -> None:
    """write_site emits a root index + one per catalog dir, package count returned."""
    site = tmp_path / "site"
    _touch(site / "FreeBSD:16:amd64" / "pfSense-pkg-pfBlockerNG-devel-3.2.16.pkg")
    _touch(site / "FreeBSD:16:amd64" / "packagesite.pkg")

    manifest = {"name": "pfSense-pkg-pfBlockerNG-devel", "version": "3.2.16", "abi": "FreeBSD:16:amd64"}
    monkeypatch.setattr(gl, "read_manifest_zstd", lambda p: manifest)
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", "add-repo.sh")

    assert n == 1
    assert (site / "index.html").is_file()
    assert (site / "FreeBSD:16:amd64" / "index.html").is_file()
    # The dir index links the package, not the catalog plumbing.
    dir_index = (site / "FreeBSD:16:amd64" / "index.html").read_text()
    assert "pfSense-pkg-pfBlockerNG-devel-3.2.16.pkg" in dir_index
    assert 'href="packagesite.pkg"' not in dir_index
