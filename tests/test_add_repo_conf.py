"""Drift guard for the client repo-conf (ADR-17 / ADR-39).

`scripts/add-repo.sh` (the client bootstrap), `scripts/build-repo.sh` (the
catalog generator), and `scripts/build-repo-portable.py` (the Python generator)
ALL emit the pkg(8) repo-conf the user ends up with.  They MUST never disagree
on ANY load-bearing field.

ADR-39 rework: the conf URL is now a DIRECT, fully-resolved GitHub Pages URL
(no Cloudflare Worker, no ``${ABI}`` token):

    https://pfblockerng.github.io/pkg/<channel>/<varver>/<arch>

The ``<varver>/<arch>`` segment is resolved at install time by ``detect_variant.sh``
(the Phase-1 helper) and baked into the conf.  The self-heal ``rc.d`` hook rewrites
only that segment on a pfSense OS upgrade.

Tests below pin:

* **byte-identity** across all three generators (release conf, ``--catalog-path
  ce-2.8/amd64`` supplied to all three so the resolved URL is deterministic);
* **resolved URL shape** for representative ``<varver>/<arch>`` values;
* **no ``${ABI}``** in any generated conf;
* **idempotence** (re-running add-repo.sh produces an identical conf file);
* **release / nightly non-clobber** (the two channels write distinct files that
  don't overwrite each other);
* **field contract** unchanged from ADR-17/20 except the url: value.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_ADD_REPO = _SCRIPTS / "add-repo.sh"
_BUILD_REPO = _SCRIPTS / "build-repo.sh"
_BUILD_REPO_PORTABLE = _SCRIPTS / "build-repo-portable.py"

_PAGES_BASE = "https://pfblockerng.github.io/pkg"
_OLD_WORKER_URL = "https://pkg.pfblockerng.workers.dev"

# Representative catalog paths for byte-identity and URL-shape tests.
_CE_28_AMD64 = "ce-2.8/amd64"
_PLUS_2603_AMD64 = "plus-26.03/amd64"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _print_conf_portable(catalog_path: str = _CE_28_AMD64, base_url: str = _PAGES_BASE) -> str:
    """Run ``build-repo-portable.py --print-conf`` and return stdout."""
    proc = subprocess.run(
        [
            sys.executable,
            str(_BUILD_REPO_PORTABLE),
            "--print-conf",
            "--catalog-path",
            catalog_path,
            "--base-url",
            base_url,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _print_conf_sh(script: Path, catalog_path: str = _CE_28_AMD64, base_url: str = _PAGES_BASE, *extra: str) -> str:
    """Run ``<script> --print-conf --catalog-path <path>`` and return stdout."""
    proc = subprocess.run(
        [
            "sh",
            str(script),
            "--print-conf",
            "--catalog-path",
            catalog_path,
            "--base-url",
            base_url,
            *extra,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _run_add_repo(root: str, *, nightly: bool = False) -> None:
    """Run add-repo.sh with PFBLOCKERNG_ROOT=root.

    PKG_BIN is overridden to a stub that exits 0 for every subcommand.
    PFB_PKG_CMD is set to the same stub so detect_variant.sh's ``pkg config abi``
    call returns "FreeBSD:15:amd64" (a minimal but parseable ABI).
    PFB_VERSION_FILE and PFB_GLOBALS_PLUS_INC are also stubbed to a CE 2.8.1 box.
    We assert only that the conf file was written; exit code is irrelevant (the
    verify step fails because the stub returns no rquery output).
    """
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)

    # pkg stub: exits 0 for everything; for `pkg config abi` prints a real ABI.
    fake_pkg = os.path.join(bin_dir, "pkg")
    with open(fake_pkg, "w") as fh:
        fh.write(
            "#!/bin/sh\n"
            "# fake pkg stub for tests\n"
            'case "$*" in\n'
            "  'config abi') printf 'FreeBSD:15:amd64' ;;\n"
            "esac\n"
            "exit 0\n"
        )
    os.chmod(fake_pkg, 0o755)

    # CE 2.8.1 version file.
    ver_dir = os.path.join(root, "etc")
    os.makedirs(ver_dir, exist_ok=True)
    ver_file = os.path.join(ver_dir, "version")
    with open(ver_file, "w") as fh:
        fh.write("2.8.1\n")

    # No globals.plus.inc → CE edition.
    # (We just don't create it; detect_variant.sh defaults to CE when absent.)

    env = {
        **os.environ,
        "PFBLOCKERNG_ROOT": root,
        "PKG_BIN": fake_pkg,
        # detect_variant.sh env overrides:
        "PFB_PKG_CMD": fake_pkg,
        "PFB_VERSION_FILE": ver_file,
        "PFB_GLOBALS_PLUS_INC": os.path.join(root, "etc", "inc", "globals.plus.inc"),
    }
    argv = ["sh", str(_ADD_REPO), *(["--nightly"] if nightly else [])]
    subprocess.run(argv, env=env, capture_output=True, text=True, check=False)


def _field(conf: str, key: str) -> str:
    """Extract a ``  key: value,`` field's value from a printed conf stanza."""
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?),?\s*$", conf, re.MULTILINE)
    assert m is not None, f"field {key!r} not found in conf:\n{conf}"
    return m.group(1).strip().rstrip(",").strip()


# --------------------------------------------------------------------------- #
# Byte-identity: all three generators must emit the SAME bytes
# --------------------------------------------------------------------------- #


def test_release_conf_byte_identical_across_all_three_generators() -> None:
    """The release conf from add-repo.sh == build-repo.sh == build-repo-portable.py, byte-for-byte.

    All three generators receive the SAME ``--catalog-path`` and ``--base-url`` so the
    resolved URL is deterministic and byte-identical output is meaningful.

    Before-state: before this test, no conf file exists (pure --print-conf mode, no writes).
    """
    add = _print_conf_sh(_ADD_REPO)  # default = release channel
    build = _print_conf_sh(_BUILD_REPO)
    portable = _print_conf_portable()

    # Before-state assertion: all three produce the SAME non-empty conf.
    assert add, "add-repo.sh --print-conf produced empty output"
    assert build, "build-repo.sh --print-conf produced empty output"
    assert portable, "build-repo-portable.py --print-conf produced empty output"

    # byte-identity
    assert add == build, f"add-repo.sh and build-repo.sh drifted:\nadd:\n{add}\nbuild:\n{build}"
    assert add == portable, f"add-repo.sh and build-repo-portable.py drifted:\nadd:\n{add}\nportable:\n{portable}"


def test_release_conf_byte_identical_plus_26_03_amd64() -> None:
    """Byte-identity holds for a Plus 26.03/amd64 box (second representative case)."""
    cat = _PLUS_2603_AMD64
    add = _print_conf_sh(_ADD_REPO, cat)
    build = _print_conf_sh(_BUILD_REPO, cat)
    portable = _print_conf_portable(cat)

    assert add == build, f"add-repo.sh vs build-repo.sh mismatch (plus-26.03/amd64):\nadd:\n{add}\nbuild:\n{build}"
    assert add == portable, f"add-repo.sh vs portable mismatch (plus-26.03/amd64):\nadd:\n{add}\nportable:\n{portable}"


# --------------------------------------------------------------------------- #
# Resolved URL shape for both representative boxes (release and nightly)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("catalog_path", "channel_args", "repo_name", "expected_url"),
    [
        # CE 2.8 / amd64 — release channel
        (
            _CE_28_AMD64,
            (),
            "pfblockerng",
            f"{_PAGES_BASE}/release/{_CE_28_AMD64}",
        ),
        # CE 2.8 / amd64 — nightly channel
        (
            _CE_28_AMD64,
            ("--nightly",),
            "pfblockerng-nightly",
            f"{_PAGES_BASE}/nightly/{_CE_28_AMD64}",
        ),
        # Plus 26.03 / amd64 — release channel
        (
            _PLUS_2603_AMD64,
            (),
            "pfblockerng",
            f"{_PAGES_BASE}/release/{_PLUS_2603_AMD64}",
        ),
        # Plus 26.03 / amd64 — nightly channel
        (
            _PLUS_2603_AMD64,
            ("--nightly",),
            "pfblockerng-nightly",
            f"{_PAGES_BASE}/nightly/{_PLUS_2603_AMD64}",
        ),
    ],
)
def test_add_repo_conf_resolved_url_shape(
    catalog_path: str,
    channel_args: tuple[str, ...],
    repo_name: str,
    expected_url: str,
) -> None:
    """The resolved url: is base/channel/varver/arch — no ${ABI}, no Worker URL.

    Scenario: given the specified catalog_path and channel,
    When  add-repo.sh --print-conf is run,
    Then  the url: field equals the expected fully-resolved GitHub Pages URL.
    """
    conf = _print_conf_sh(_ADD_REPO, catalog_path, _PAGES_BASE, *channel_args)

    # The repo stanza is keyed by the expected name.
    assert re.search(rf"^{re.escape(repo_name)}:\s*\{{", conf, re.MULTILINE), (
        f"repo name {repo_name!r} not found in conf:\n{conf}"
    )

    # The url: field is the exact expected resolved URL.
    url_val = _field(conf, "url").strip('"')
    assert url_val == expected_url, f"url mismatch: expected {expected_url!r}, got {url_val!r}"

    # ${ABI} must NOT appear anywhere (it is resolved at bootstrap time, not by pkg).
    assert "${ABI}" not in conf, f"${'{ABI}'} must not appear in conf:\n{conf}"


# --------------------------------------------------------------------------- #
# No ${ABI} in any emitted conf (all generators, both channels)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("channel_args", [(), ("--nightly",)])
@pytest.mark.parametrize(
    "generator",
    ["add-repo.sh", "build-repo.sh", "build-repo-portable.py"],
)
def test_no_abi_placeholder_in_any_generator_output(generator: str, channel_args: tuple[str, ...]) -> None:
    """No generator emits a conf containing the literal ``${ABI}`` token.

    ADR-39 contracts: the URL is fully resolved at bootstrap; the ${ABI} expansion
    trick from ADR-17/20 is retired because one ABI can map to multiple pfSense
    versions (varver keying is mandatory).
    """
    cat = _CE_28_AMD64
    if generator == "add-repo.sh":
        conf = _print_conf_sh(_ADD_REPO, cat, _PAGES_BASE, *channel_args)
    elif generator == "build-repo.sh":
        # build-repo.sh only has a release channel --print-conf
        if channel_args:
            pytest.skip("build-repo.sh does not support --nightly in --print-conf mode")
        conf = _print_conf_sh(_BUILD_REPO, cat)
    else:
        if channel_args:
            pytest.skip("build-repo-portable.py --print-conf only emits the release conf")
        conf = _print_conf_portable(cat)

    assert "${ABI}" not in conf, f"{generator} {channel_args}: found ${{ABI}} in conf:\n{conf}"


# --------------------------------------------------------------------------- #
# Fields: unchanged from ADR-17/20 (priority, mirror_type, signature_type, enabled)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("channel_args", "repo_name", "other_repo"),
    [
        ((), "pfblockerng", "pfblockerng-nightly"),
        (("--nightly",), "pfblockerng-nightly", "pfblockerng"),
    ],
)
def test_add_repo_conf_fields_per_channel(
    channel_args: tuple[str, ...],
    repo_name: str,
    other_repo: str,
) -> None:
    """Both channels carry priority 100, mirror_type/signature_type none, enabled yes.

    Default (no arg) -> ``pfblockerng`` (stable + devel); --nightly ->
    ``pfblockerng-nightly``.  The OTHER repo name must not appear as a stanza key.
    """
    conf = _print_conf_sh(_ADD_REPO, _CE_28_AMD64, _PAGES_BASE, *channel_args)

    # The stanza is keyed by the expected repo name.
    assert re.search(rf"^{re.escape(repo_name)}:\s*\{{", conf, re.MULTILINE), conf
    # The OTHER repo name must NOT appear as a stanza key.
    assert not re.search(rf"^{re.escape(other_repo)}:\s*\{{", conf, re.MULTILINE), conf

    # NONE-signed + above-Netgate priority + enabled — unchanged from ADR-17/20.
    assert _field(conf, "mirror_type") == "none"
    assert _field(conf, "signature_type") == "none"
    assert _field(conf, "priority") == "100"
    assert _field(conf, "enabled") == "yes"


# --------------------------------------------------------------------------- #
# Idempotence: re-running add-repo.sh produces the identical conf file
# --------------------------------------------------------------------------- #


def test_conf_written_once_invariant() -> None:
    """Running add-repo.sh twice produces the same conf (idempotent).

    Scenario:
    Given the conf is absent (before-state asserted),
    When  add-repo.sh runs a first time,
    Then  the conf is written with the resolved URL;
    When  add-repo.sh runs again,
    Then  the conf is byte-identical (no re-bootstrap drift).
    """
    with tempfile.TemporaryDirectory() as root:
        conf_path = Path(root) / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng.conf"

        # Given: conf does not exist (before-state)
        assert not conf_path.exists(), "conf should not exist before the first run"

        # When: first run writes the conf
        _run_add_repo(root)
        assert conf_path.exists(), "conf should be written by add-repo.sh"
        content_first = conf_path.read_text()

        # Before-state of second run: resolved URL present, no ${ABI}
        assert _PAGES_BASE in content_first
        assert "${ABI}" not in content_first

        # When: second run
        _run_add_repo(root)

        # Then: identical conf
        content_second = conf_path.read_text()
        assert content_first == content_second, (
            f"Second run must produce identical conf (idempotent):\nFirst:\n{content_first}\nSecond:\n{content_second}"
        )


# --------------------------------------------------------------------------- #
# Release / nightly non-clobber: two distinct conf files, channels independent
# --------------------------------------------------------------------------- #


def test_default_writes_release_conf_and_nightly_writes_its_own() -> None:
    """The default writes ONLY the shared release conf; --nightly writes ONLY the nightly one.

    Scenario:
    Given a fresh root (no conf files),
    When  add-repo.sh runs with no argument,
    Then  only ``pfblockerng.conf`` exists (no nightly conf, no legacy split conf);
    When  add-repo.sh --nightly runs into the same root,
    Then  ``pfblockerng-nightly.conf`` is added, and the release conf is byte-unchanged.
    """
    with tempfile.TemporaryDirectory() as root:
        repos = Path(root) / "usr" / "local" / "etc" / "pkg" / "repos"
        release = repos / "pfblockerng.conf"
        nightly = repos / "pfblockerng-nightly.conf"
        legacy_split = repos / "pfblockerng-devel.conf"

        # Given: fresh root — no conf files (before-state)
        assert not release.exists()
        assert not nightly.exists()

        # When: default (no arg) → only the shared release conf
        _run_add_repo(root)
        assert release.exists(), "default must write the shared pfblockerng.conf"
        assert not legacy_split.exists(), "default must NOT write a split pfblockerng-devel.conf"
        assert not nightly.exists(), "default must NOT write the nightly conf"
        release_bytes = release.read_text()
        assert _PAGES_BASE in release_bytes, "release conf must contain the Pages base URL"
        assert "${ABI}" not in release_bytes, "release conf must not contain ${ABI}"

        # When: --nightly → adds its own conf, leaves the release conf byte-unchanged
        _run_add_repo(root, nightly=True)
        assert nightly.exists(), "--nightly must write pfblockerng-nightly.conf"
        assert release.read_text() == release_bytes, "--nightly must not touch the release conf"
        assert not legacy_split.exists(), "no pfblockerng-devel.conf is ever created"

        # After-state: nightly conf has its own URL prefix
        nightly_content = nightly.read_text()
        assert "/nightly/" in nightly_content, "nightly conf must use the nightly/ channel path"
        assert "${ABI}" not in nightly_content, "nightly conf must not contain ${ABI}"


# --------------------------------------------------------------------------- #
# add-repo.sh writes a direct Pages URL, NOT the old Worker URL
# --------------------------------------------------------------------------- #


def test_primary_url_is_pages_url_not_worker() -> None:
    """add-repo.sh writes the direct GitHub Pages URL, NOT the Cloudflare Worker URL.

    Scenario:
    Given the conf does not exist yet (before-state: fresh tmpdir),
    When  add-repo.sh runs,
    Then  the written conf URL contains pfblockerng.github.io/pkg and does NOT
          contain pkg.pfblockerng.workers.dev (the retired Worker).
    """
    with tempfile.TemporaryDirectory() as root:
        conf_path = Path(root) / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng.conf"

        # Given: conf absent (before-state)
        assert not conf_path.exists()

        # When: run add-repo.sh
        _run_add_repo(root)

        # Then: conf written with Pages URL, not the old Worker URL
        assert conf_path.exists()
        content = conf_path.read_text()
        assert _PAGES_BASE in content, f"Pages URL not found in conf:\n{content}"
        assert _OLD_WORKER_URL not in content, f"Old Worker URL must not appear:\n{content}"
        assert "${ABI}" not in content, f"${'{ABI}'} must not appear in resolved conf:\n{content}"


# --------------------------------------------------------------------------- #
# add-repo.sh arg-parsing error cases (unchanged from pre-ADR-39)
# --------------------------------------------------------------------------- #


def test_add_repo_rejects_positional_argument() -> None:
    """A positional argument fails loud — the channel is a flag, not a word."""
    for bad in ("devel", "stable", "nightly", "bogus"):
        proc = subprocess.run(
            ["sh", str(_ADD_REPO), "--print-conf", bad],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode != 0, f"{bad!r} should be rejected"
        assert "unexpected argument" in proc.stderr.lower(), proc.stderr


def test_add_repo_base_url_requires_a_value() -> None:
    """`--base-url` with no following value errors cleanly."""
    proc = subprocess.run(
        ["sh", str(_ADD_REPO), "--print-conf", "--base-url"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "--base-url requires a value" in proc.stderr, proc.stderr
