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
from datetime import datetime, timezone
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
    Then the annotation wins — so devel/release stop showing the republish date.
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


def test_read_manifest_requires_zstd(monkeypatch: Any) -> None:
    """A clear error (not a generic FileNotFoundError) when the zstd binary is absent."""
    monkeypatch.setattr(gl.shutil, "which", lambda _name: None)
    try:
        gl.read_manifest_zstd("whatever.pkg")
    except RuntimeError as exc:
        assert "zstd" in str(exc)
    else:  # pragma: no cover - the guard must fire
        raise AssertionError("expected RuntimeError when zstd is missing")


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

    # Then: only the two real packages, correctly classified; no packagesite/data.
    assert {p["name"] for p in pkgs} == {"pfSense-pkg-pfBlockerNG-devel", "pfSense-pkg-pfBlockerNG-nightly"}
    assert {p["channel"] for p in pkgs} == {"devel", "nightly"}
    assert all(p["rel"].endswith(".pkg") for p in pkgs)
    assert not any("packagesite" in p["rel"] or "data.pkg" in p["rel"] for p in pkgs)
    # The source-commit annotation is carried onto each row (drives the Commit column).
    assert {p["commit"] for p in pkgs} == {"cafe1234"}
    # PHP/Python come from the manifest deps — the runtime flavor pkg, not its sub-packages.
    assert {p["php"] for p in pkgs} == {"8.5"}
    assert {p["py"] for p in pkgs} == {"3.11"}


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


# ── Edition split: matrix join → per-edition sections ─────────────────────────


def _mx(abi: str, ver: str, variant: str, php: str, py: str) -> dict[str, str]:
    """A supported-versions matrix entry, as read-version-matrix.sh --print-build emits."""
    return {"abi": abi, "pfsense_version": ver, "variant": variant, "php_version": php, "py_flavor": py}


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

    Given devel builds for two ABIs, and a matrix where one ABI serves TWO pfSense
      versions (a CE and a Plus),
    When the edition sections are built,
    Then CE sorts before Plus; each row carries the matrix pfSense version + PHP/Python;
      and the shared-ABI build appears under BOTH editions (it installs on each, since
      pkg resolves on ABI alone).
    """
    p_ce = _pkg("devel", "d", "3.2.16", "FreeBSD:15:amd64", "a.pkg")
    p_shared = _pkg("devel", "d", "3.2.16", "FreeBSD:16:amd64", "b.pkg")
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


def test_older_nightlies_lists_retained_excludes_latest() -> None:
    """Scenario: surface the retained older nightlies, never the current one.

    Given three nightly builds for one ABI (two old + the newest) plus a devel build,
    When the older-nightlies list is built,
    Then the NEWEST nightly is excluded (it's already in the edition table) and the two
      older ones remain, newest-first; devel/stable are never included.
    """
    new = _pkg("nightly", "n", "3.2.16.20260614.9", "FreeBSD:16:amd64", "n9.pkg")
    mid = _pkg("nightly", "n", "3.2.16.20260613.4", "FreeBSD:16:amd64", "n4.pkg")
    old = _pkg("nightly", "n", "3.2.16.20260601.1", "FreeBSD:16:amd64", "n1.pkg")
    dev = _pkg("devel", "d", "3.2.16", "FreeBSD:16:amd64", "d.pkg")

    rows = gl.older_nightlies([new, mid, old, dev])

    versions = [r["version"] for r in rows]
    assert versions == ["3.2.16.20260613.4", "3.2.16.20260601.1"]  # newest excluded, rest newest-first
    assert all(r["channel"] == "nightly" for r in rows)  # devel never listed
    # The packages block folds the two retained nightlies into a disclosure UNDER the edition
    # table, never the latest (which lives in the edition table itself).
    matrix = [_mx("FreeBSD:16:amd64", "26.03", "Plus", "8.5", "py311")]
    html = gl._packages_html([new, mid, old, dev], matrix)
    assert "<h3>pfSense Plus</h3>" in html
    assert "<details><summary>Older nightlies (2)</summary>" in html
    # The disclosure sits AFTER the edition's main table (folded under it).
    assert html.index("<h3>pfSense Plus</h3>") < html.index("Older nightlies (2)")
    details = html[html.index("Older nightlies (2)") :]
    assert "3.2.16.20260613.4" in details and "3.2.16.20260601.1" in details
    assert "3.2.16.20260614.9" not in details  # the current nightly stays out of the 'older' disclosure
    # The disclosure's table carries the same columns as the edition table, minus Channel.
    assert "<th>Channel</th>" not in details and "<th>pfSense</th>" in details
    assert ">26.03<" in details and ">8.5<" in details and ">3.11<" in details


def test_older_nightlies_empty_when_only_latest() -> None:
    """With a single nightly version present there is nothing 'older' to disclose."""
    only = _pkg("nightly", "n", "3.2.16.20260614.9", "FreeBSD:16:amd64", "n.pkg")
    assert gl.older_nightlies([only, _pkg("devel", "d", "3.2.16", "FreeBSD:16:amd64", "d.pkg")]) == []
    # …and the packages block omits the disclosure entirely (no empty 'Older nightlies' affordance).
    assert "Older nightlies" not in gl._packages_html([only], None)


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

    # CE section before Plus section; each has its own folded older-nightlies disclosure.
    assert html.index("<h3>pfSense CE</h3>") < html.index("<h3>pfSense Plus</h3>")
    assert html.count("<summary>Older nightlies (1)</summary>") == 2  # one per edition (each ABI: 1 older)
    # The CE section spans from its heading to the Plus heading; the Plus section follows.
    ce_section = html[html.index("<h3>pfSense CE</h3>") : html.index("<h3>pfSense Plus</h3>")]
    plus_section = html[html.index("<h3>pfSense Plus</h3>") :]
    # Each edition's disclosure folds in its OWN ABI's older nightly, never the other's.
    assert "Older nightlies (1)" in ce_section and "FreeBSD:15:amd64" in ce_section
    assert "FreeBSD:16:aarch64" not in ce_section and ">2.8<" in ce_section and ">8.3<" in ce_section
    assert "Older nightlies (1)" in plus_section and "FreeBSD:16:aarch64" in plus_section
    assert "FreeBSD:15:amd64" not in plus_section and ">26.03<" in plus_section and ">8.5<" in plus_section


def test_build_edition_sections_unmatched_abi_falls_to_other() -> None:
    """A build whose ABI the matrix doesn't cover lands in 'Other' (manifest php/py), not hidden."""
    p = _pkg("devel", "d", "3.2.16", "FreeBSD:14:amd64", "x.pkg")
    p["php"], p["py"] = "8.2", "3.9"  # manifest-derived fallback (no matrix row)

    sections = dict(gl.build_edition_sections([p], matrix=[]))

    assert list(sections) == ["Other"]
    row = sections["Other"][0]
    assert row["pfsense_version"] == "" and (row["php"], row["py"]) == ("8.2", "3.9")


# ── Rendering ─────────────────────────────────────────────────────────────────


def _stub_conf(channel: str) -> str:
    return f"{channel}-conf-snippet"


def test_render_page_shows_latest_and_empty_stable() -> None:
    """The page splits packages into per-edition tables; stable (absent) is empty-stated."""
    pkgs = [
        _pkg("devel", "pfSense-pkg-pfBlockerNG-devel", "3.2.16", "FreeBSD:15:amd64", "FreeBSD:15:amd64/d.pkg"),
        _pkg("devel", "pfSense-pkg-pfBlockerNG-devel", "3.2.16", "FreeBSD:16:aarch64", "FreeBSD:16:aarch64/d.pkg"),
        _pkg(
            "nightly",
            "pfSense-pkg-pfBlockerNG-nightly",
            "3.2.16.20260614.9",
            "FreeBSD:16:aarch64",
            "nightly/FreeBSD:16:aarch64/n.pkg",
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
    # One table per pfSense edition, CE before Plus.
    assert "<h3>pfSense CE</h3>" in page
    assert "<h3>pfSense Plus</h3>" in page
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
    # Stable has no package -> empty state, NOT a bogus version (its line in the unified
    # release card).
    assert "not yet published" in page
    # The unified release card: ONE bootstrap (no channel arg), then both install targets.
    assert f"sh -s -- --base-url {base}" in page
    assert "pkg install pfSense-pkg-pfBlockerNG<" in page  # stable (exact, not -devel)
    assert "pkg install pfSense-pkg-pfBlockerNG-devel" in page  # development
    # Nightly is its own card with the --nightly flag and its own package.
    assert f"--base-url {base} --nightly" in page
    assert "pkg install pfSense-pkg-pfBlockerNG-nightly" in page
    # The manual conf came from the injected conf function — release + nightly, keyed by
    # the logical channel the cards pass.
    assert "release-conf-snippet" in page
    assert "nightly-conf-snippet" in page
    # The badge/title casing fix: no CSS capitalize that would mangle `pfSense-pkg-...`.
    assert "text-transform:capitalize" not in page
    # Accent grammar: the release card is the primary (blue --acc); nightly is cautioned
    # (amber --warn), never the other way round (blue would read as "recommended").
    assert '<div class="card release">' in page
    assert '<div class="card nightly">' in page
    assert "--warn:#d29922" in page
    assert ".card.release{border-color:var(--acc)}" in page
    assert ".card.nightly{border-color:var(--warn)}" in page
    # The catalog-trees list is replaced by a SINGLE link to the folder-navigable browse page.
    assert '<a class="browse" href="./browse.html">' in page
    assert "Browse the repository" in page
    # The old flat tree list is gone (no per-leaf-dir <ul> on the landing page).
    assert "ul.trees" not in page
    assert 'href="./FreeBSD:16:aarch64/"' not in page


def test_render_page_table_empty_when_no_packages() -> None:
    page = gl.render_page("https://x/pkg", [], _stub_conf)
    assert "No packages published yet." in page
    assert '<a class="browse" href="./browse.html">' in page  # browse link present even when empty


def test_render_autoindex_lists_dirs_files_and_parent() -> None:
    """A non-root autoindex shows a Parent Directory row, subdirs (name/), and files (name+size),
    with './'-prefixed hrefs so a colon-bearing ABI segment stays a relative path."""
    out = gl.render_autoindex(
        "release/ce-2.8",
        ["amd64"],
        [("notes.txt", 12, 1_700_000_000.0)],
    )
    assert "Index of /release/ce-2.8" in out
    assert '<a href="../">../</a>' in out  # Parent Directory row
    assert '<a href="./amd64/">amd64/</a>' in out  # subdir, trailing slash
    assert '<a href="./notes.txt">notes.txt</a>' in out  # file
    assert "12 B" in out  # size column rendered


def test_render_autoindex_root_has_no_parent_and_is_colon_safe() -> None:
    """The browse root omits Parent Directory; an ABI dir with ':' links via './' (RFC 3986 §4.2)."""
    out = gl.render_autoindex("", ["release", "nightly"], [("routing.json", 99, 1_700_000_000.0)], is_root=True)
    assert "Index of /" in out
    assert "Parent Directory" not in out and 'href="../"' not in out
    assert '<a href="./release/">release/</a>' in out and '<a href="./nightly/">nightly/</a>' in out
    # A colon-ABI subdir would link with the scheme-safe './' prefix.
    deep = gl.render_autoindex("release", ["FreeBSD:16:aarch64"], [])
    assert 'href="./FreeBSD:16:aarch64/"' in deep


def test_write_site_emits_browse_and_autoindex_at_every_level(tmp_path: Path, monkeypatch: Any) -> None:
    """write_site emits the landing page, browse.html, and an autoindex index.html at EVERY
    directory level (intermediate dirs too) so the whole tree is folder-navigable."""
    site = tmp_path / "site"
    _touch(site / "release" / "ce-2.8" / "FreeBSD:15:amd64" / "pfSense-pkg-pfBlockerNG-devel-3.2.16.pkg")
    _touch(site / "release" / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg")
    _touch(site / "routing.json")

    manifest = {"name": "pfSense-pkg-pfBlockerNG-devel", "version": "3.2.16", "abi": "FreeBSD:15:amd64"}
    monkeypatch.setattr(gl, "read_manifest_zstd", lambda p: manifest)
    monkeypatch.setattr(gl, "_conf_via_addrepo", lambda addrepo, base, ch: f"{ch}-conf")

    n = gl.write_site(str(site), "https://pfblockerng.github.io/pkg/", "add-repo.sh")

    assert n == 1
    # Landing page (root) links to the browse entry; browse.html exists and lists the top dirs.
    assert (site / "index.html").is_file()
    assert '<a class="browse" href="./browse.html">' in (site / "index.html").read_text()
    browse = (site / "browse.html").read_text()
    assert '<a href="./release/">release/</a>' in browse
    # An autoindex index.html exists at EVERY level — intermediate dirs too, not just the leaf.
    for rel in ("release", "release/ce-2.8", "release/ce-2.8/FreeBSD:15:amd64"):
        assert (site / rel / "index.html").is_file(), f"missing autoindex at {rel}"
    # Intermediate dir lists its subdir; leaf lists the package + the catalog plumbing (a real
    # directory listing, unlike the old package-only view).
    assert '<a href="./ce-2.8/">ce-2.8/</a>' in (site / "release" / "index.html").read_text()
    leaf = (site / "release" / "ce-2.8" / "FreeBSD:15:amd64" / "index.html").read_text()
    assert "pfSense-pkg-pfBlockerNG-devel-3.2.16.pkg" in leaf
    assert "packagesite.pkg" in leaf  # the catalog files ARE shown in a directory listing
    # The generated index pages themselves are hidden from listings (not repository content).
    assert "browse.html" not in browse.split("<tbody>")[1]
