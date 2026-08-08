"""Drift guard for the client repo-conf (ADR-17 / ADR-39).

`scripts/add-repo.sh` (the client bootstrap), `scripts/build-repo.sh` (the
catalog generator), and `scripts/build-repo-portable.py` (the Python generator)
ALL emit the pkg(8) repo-conf the user ends up with.  They MUST never disagree
on ANY load-bearing field.

ADR-39 rework: the conf URL is now a DIRECT, fully-resolved GitHub Pages URL
(no Cloudflare Worker, no ``${ABI}`` token). Arch-less since issue #1806
(NO_ARCH — all three pfSense-pkg-pfBlockerNG ports are NO_ARCH, so one varver
serves every arch of its FreeBSD major):

    https://pfblockerng.github.io/pkg/<channel>/<varver>

The ``<varver>`` segment is resolved by the boot-time ``rc.d`` generator hook
(``pfblockerng_repo_generate.sh``), whose detection is folded in (ADR-39): edition =
"/etc/product_label contains 'Plus'", version = major.minor of /etc/version.  The
hook regenerates the whole conf each boot, so the URL self-corrects after a pfSense
OS upgrade.

Tests below pin:

* **byte-identity** across all FOUR producers — the three ``--print-conf`` generators
  AND the hook (release conf, ``--catalog-path ce-2.8`` so the URL is
  deterministic);
* **resolved URL shape** for representative ``<varver>`` values;
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
_HOOK = _SCRIPTS / "rc.d" / "pfblockerng_repo_generate.sh"

_PAGES_BASE = "https://pfblockerng.github.io/pkg"
_OLD_WORKER_URL = "https://pkg.pfblockerng.workers.dev"

# Representative catalog paths for byte-identity and URL-shape tests.
_CE_28 = "ce-2.8"
_PLUS_2603 = "plus-26.03"

# The four channels (issue #2147 step B) — each owns its own <channel>/<varver>/
# catalog subtree, all serving the ONE canonical pfSense-pkg-pfBlockerNG package.
# `release` is the pre-existing legacy default (NOT one of the four; --channel
# release is rejected — see test_channel_release_rejected).
_CHANNELS = ("stable", "testing", "edge", "nightly")
_CHANNEL_REPO_NAMES = {
    "release": "pfblockerng",
    "stable": "pfblockerng-stable",
    "testing": "pfblockerng-testing",
    "edge": "pfblockerng-edge",
    "nightly": "pfblockerng-nightly",
}
_CHANNEL_CONF_NAMES = {
    "release": "pfblockerng.conf",
    "stable": "pfblockerng-stable.conf",
    "testing": "pfblockerng-testing.conf",
    "edge": "pfblockerng-edge.conf",
    "nightly": "pfblockerng-nightly.conf",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _print_conf_portable(catalog_path: str = _CE_28, base_url: str = _PAGES_BASE, *, channel: str | None = None) -> str:
    """Run ``build-repo-portable.py --print-conf`` and return stdout."""
    argv = [
        sys.executable,
        str(_BUILD_REPO_PORTABLE),
        "--print-conf",
        "--catalog-path",
        catalog_path,
        "--base-url",
        base_url,
    ]
    if channel is not None:
        argv += ["--channel", channel]
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _print_conf_sh(script: Path, catalog_path: str = _CE_28, base_url: str = _PAGES_BASE, *extra: str) -> str:
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


def _run_add_repo(
    root: str,
    *,
    nightly: bool = False,
    extra_args: tuple[str, ...] = (),
    catalogue_empty: bool = False,
    update_fails: bool = False,
    detection_fails: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run add-repo.sh with PFBLOCKERNG_ROOT=root.

    PKG_BIN is overridden to a stub that answers `pkg rquery` with a plausible
    package line, so the bootstrap reaches its success path; every other subcommand
    is a silent success. The generator hook no longer calls `pkg` at all (arch-less
    catalog; issue #1806 — it used to read `pkg config abi` only to derive the
    now-retired per-arch leaf), so `rquery` is the only answer that matters.
    add-repo.sh installs the generator hook into ``root`` and runs it; the hook
    resolves the conf from ``root/etc/product_label`` (CE here — no "Plus") and
    ``root/etc/version`` (2.8.1).

    The three keyword flags each select one of the bootstrap's failure gates, all of
    which must leave the box's repository configuration exactly as they found it
    (issue #2148):

    ``catalogue_empty``  `rquery` yields nothing — the channel has no build for this
                         box's variant.
    ``update_fails``     `pkg update` exits non-zero — any enabled repository failed
                         to refresh, including the one being switched away from.
    ``detection_fails``  ``/etc/version`` is blank, so the generator hook cannot
                         resolve a varver and never writes the conf's marker line.
    """
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)

    fake_pkg = os.path.join(bin_dir, "pkg")
    rquery_reply = "" if catalogue_empty else "  printf 'pfSense-pkg-pfBlockerNG 4.0.0\\n'\n"
    update_reply = "  exit 1\n" if update_fails else "  exit 0\n"
    with open(fake_pkg, "w") as fh:
        fh.write(
            "#!/bin/sh\n# fake pkg stub for tests\n"
            f'if [ "$1" = "rquery" ]; then\n{rquery_reply}  exit 0\nfi\n'
            f'if [ "$1" = "update" ]; then\n{update_reply}fi\n'
            "exit 0\n"
        )
    os.chmod(fake_pkg, 0o755)

    # CE 2.8.1 box fixture: /etc/version + /etc/product_label (no "Plus" → CE). A blank
    # version is how the hook's variant detection is made to fail.
    etc_dir = os.path.join(root, "etc")
    os.makedirs(etc_dir, exist_ok=True)
    with open(os.path.join(etc_dir, "version"), "w") as fh:
        fh.write("" if detection_fails else "2.8.1\n")
    with open(os.path.join(etc_dir, "product_label"), "w") as fh:
        fh.write("pfSense\n")

    env = {
        **os.environ,
        "PFBLOCKERNG_ROOT": root,
        "PKG_BIN": fake_pkg,
    }
    argv = ["sh", str(_ADD_REPO), *(["--nightly"] if nightly else []), *extra_args]
    return subprocess.run(argv, env=env, capture_output=True, text=True, check=False)


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


def test_release_conf_byte_identical_plus_26_03() -> None:
    """Byte-identity holds for a Plus 26.03 box (second representative case)."""
    cat = _PLUS_2603
    add = _print_conf_sh(_ADD_REPO, cat)
    build = _print_conf_sh(_BUILD_REPO, cat)
    portable = _print_conf_portable(cat)

    assert add == build, f"add-repo.sh vs build-repo.sh mismatch (plus-26.03):\nadd:\n{add}\nbuild:\n{build}"
    assert add == portable, f"add-repo.sh vs portable mismatch (plus-26.03):\nadd:\n{add}\nportable:\n{portable}"


def _hook_conf_env(repos: str) -> dict[str, str]:
    """Every ``PFB_*_CONF`` override the hook reads, pointed inside ``repos``.

    Passing ALL of them is mandatory for hermeticity: an override the test omits
    falls back to its ``/usr/local/etc/pkg/repos/`` default, so the hook would
    regenerate the REAL box's conf during a test run.
    """
    return {f"PFB_{channel.upper()}_CONF": os.path.join(repos, name) for channel, name in _CHANNEL_CONF_NAMES.items()}


def _run_hook(root: str, *, edition_label: str, version: str, channel: str) -> str:
    """Run the generator hook off-box against a stubbed box; return the conf it wrote.

    ``channel`` selects which conf the hook regenerates: we stage only that one so
    the orphan guard leaves every other channel absent. The hook runs the *_start
    path directly off-box (no /etc/rc.subr present). No `pkg` stub needed — the
    hook is arch-less (issue #1806) and no longer calls `pkg` at all.
    """
    repos = os.path.join(root, "repos")
    os.makedirs(repos, exist_ok=True)

    label = os.path.join(root, "product_label")
    ver = os.path.join(root, "version")
    with open(label, "w") as fh:
        fh.write(edition_label + "\n")
    with open(ver, "w") as fh:
        fh.write(version + "\n")

    conf_path = os.path.join(repos, _CHANNEL_CONF_NAMES[channel])
    with open(conf_path, "w") as fh:
        fh.write("# stub pending\n")

    env = {
        **os.environ,
        **_hook_conf_env(repos),
        "PFB_PRODUCT_LABEL": label,
        "PFB_VERSION_FILE": ver,
    }
    subprocess.run(["sh", str(_HOOK), "onestart"], env=env, capture_output=True, text=True, check=False)
    return Path(conf_path).read_text()


def test_hook_output_byte_identical_to_print_conf_release() -> None:
    """The rc.d hook writes the SAME bytes as ``add-repo.sh --print-conf`` (release).

    This is the 4th producer of the conf — the boot-time generator. It MUST match
    the three ``--print-conf`` generators byte-for-byte for a CE 2.8.1 box.
    """
    with tempfile.TemporaryDirectory() as root:
        hook_conf = _run_hook(root, edition_label="pfSense", version="2.8.1", channel="release")
    print_conf = _print_conf_sh(_ADD_REPO, _CE_28)
    assert hook_conf == print_conf, f"hook vs --print-conf drift:\nhook:\n{hook_conf}\nprint-conf:\n{print_conf}"


def test_hook_output_byte_identical_to_print_conf_nightly_plus() -> None:
    """The hook's nightly conf for a Plus 26.03 box matches --print-conf --nightly."""
    with tempfile.TemporaryDirectory() as root:
        hook_conf = _run_hook(root, edition_label="pfSense Plus", version="26.03.1", channel="nightly")
    print_conf = _print_conf_sh(_ADD_REPO, _PLUS_2603, _PAGES_BASE, "--nightly")
    assert hook_conf == print_conf, (
        f"hook nightly vs --print-conf drift:\nhook:\n{hook_conf}\nprint-conf:\n{print_conf}"
    )


@pytest.mark.parametrize("channel", _CHANNELS)
def test_hook_regenerates_every_channel_byte_identical_to_print_conf(channel: str) -> None:
    """The boot hook resolves EVERY channel's conf, byte-identical to --print-conf.

    Boot regeneration is what keeps a subscription correct across a pfSense OS
    upgrade (the varver moves). Before issue #2148 the hook knew only the legacy
    release conf and nightly, so a box subscribed to stable/testing/edge would keep
    a stale URL forever; every channel is now regenerated from the same body.
    """
    with tempfile.TemporaryDirectory() as root:
        hook_conf = _run_hook(root, edition_label="pfSense", version="2.8.1", channel=channel)
    print_conf = _print_conf_sh(_ADD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    assert hook_conf == print_conf, (
        f"hook {channel} vs --print-conf drift:\nhook:\n{hook_conf}\nprint-conf:\n{print_conf}"
    )


@pytest.mark.parametrize("channel", _CHANNELS)
def test_hook_orphan_guard_holds_for_every_channel(channel: str) -> None:
    """The hook never CREATES a conf: a channel the user did not subscribe to stays absent.

    This guard is what makes boot regeneration compatible with single-repository
    subscription — regenerating one channel must never re-enable a channel the user
    switched away from.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_hook(root, edition_label="pfSense", version="2.8.1", channel=channel)
        repos = Path(root) / "repos"
        present = sorted(p.name for p in repos.iterdir())
    assert present == [_CHANNEL_CONF_NAMES[channel]], (
        f"staging only {channel!r} must leave exactly that conf behind, found: {present}"
    )


# --------------------------------------------------------------------------- #
# Resolved URL shape for both representative boxes (release and nightly)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("catalog_path", "channel_args", "repo_name", "expected_url"),
    [
        # CE 2.8 — release channel
        (
            _CE_28,
            (),
            "pfblockerng",
            f"{_PAGES_BASE}/release/{_CE_28}",
        ),
        # CE 2.8 — nightly channel
        (
            _CE_28,
            ("--nightly",),
            "pfblockerng-nightly",
            f"{_PAGES_BASE}/nightly/{_CE_28}",
        ),
        # Plus 26.03 — release channel
        (
            _PLUS_2603,
            (),
            "pfblockerng",
            f"{_PAGES_BASE}/release/{_PLUS_2603}",
        ),
        # Plus 26.03 — nightly channel
        (
            _PLUS_2603,
            ("--nightly",),
            "pfblockerng-nightly",
            f"{_PAGES_BASE}/nightly/{_PLUS_2603}",
        ),
    ],
)
def test_add_repo_conf_resolved_url_shape(
    catalog_path: str,
    channel_args: tuple[str, ...],
    repo_name: str,
    expected_url: str,
) -> None:
    """The resolved url: is base/channel/varver — no ${ABI}, no Worker URL.

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
    cat = _CE_28
    if generator == "add-repo.sh":
        conf = _print_conf_sh(_ADD_REPO, cat, _PAGES_BASE, *channel_args)
    elif generator == "build-repo.sh":
        # build-repo.sh only has a release channel --print-conf
        if channel_args:
            pytest.skip("build-repo.sh does not support --nightly in --print-conf mode")
        conf = _print_conf_sh(_BUILD_REPO, cat)
    else:
        if channel_args:
            pytest.skip("build-repo-portable.py has no --nightly alias (channels use --channel)")
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
    conf = _print_conf_sh(_ADD_REPO, _CE_28, _PAGES_BASE, *channel_args)

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
# Single-repository subscription: one project conf on the box at a time
# --------------------------------------------------------------------------- #


def test_default_writes_release_conf_then_nightly_replaces_it() -> None:
    """The default writes ONLY the shared release conf; --nightly then REPLACES it.

    Scenario:
    Given a fresh root (no conf files),
    When  add-repo.sh runs with no argument,
    Then  only ``pfblockerng.conf`` exists (no nightly conf, no legacy split conf);
    When  add-repo.sh --nightly runs into the same root,
    Then  ``pfblockerng-nightly.conf`` is the box's ONLY project conf — the release
          conf is retired, because a box subscribes to one channel at a time.
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

        # When: --nightly → takes over the subscription
        _run_add_repo(root, nightly=True)
        assert nightly.exists(), "--nightly must write pfblockerng-nightly.conf"
        assert not release.exists(), "--nightly must retire the release subscription it replaced"
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


@pytest.mark.parametrize(
    ("argv", "needle"),
    [
        (["sh", str(_ADD_REPO), "--print-conf"], "catalog-path"),
        (["sh", str(_BUILD_REPO), "--print-conf"], "catalog-path"),
        ([sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf"], "catalog-path"),
    ],
)
def test_print_conf_requires_catalog_path(argv: list[str], needle: str) -> None:
    """All three generators FAIL `--print-conf` without `--catalog-path` (no unresolved URL).

    A bare `--print-conf` would otherwise emit a URL ending at the channel (no
    `<varver>`), violating the ADR-39 resolved-URL contract. Each generator must
    error loud instead of emitting an unusable conf.
    """
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode != 0, f"{argv!r} should fail without --catalog-path"
    assert needle in proc.stderr.lower(), proc.stderr


# --------------------------------------------------------------------------- #
# Four-channel expression (issue #2147 step B) — stable/testing/edge/nightly
# --------------------------------------------------------------------------- #
#
# Issue #2148 closed the deferral: all four channels now bootstrap live and the
# rc.d hook regenerates every one of them, so the byte-identity contract above is
# asserted against the hook per channel, not only for release + nightly.


@pytest.mark.parametrize("channel", _CHANNELS)
def test_four_channel_conf_byte_identical_across_all_three_generators(channel: str) -> None:
    """The <channel> conf from add-repo.sh == build-repo.sh == build-repo-portable.py.

    Mirrors test_release_conf_byte_identical_across_all_three_generators for each of
    the four new channels.
    """
    add = _print_conf_sh(_ADD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    build = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    portable = _print_conf_portable(_CE_28, _PAGES_BASE, channel=channel)

    assert add, f"add-repo.sh --channel {channel} produced empty output"
    assert build, f"build-repo.sh --channel {channel} produced empty output"
    assert portable, f"build-repo-portable.py --channel {channel} produced empty output"

    assert add == build, f"add-repo.sh vs build-repo.sh drift ({channel}):\nadd:\n{add}\nbuild:\n{build}"
    assert add == portable, (
        f"add-repo.sh vs build-repo-portable.py drift ({channel}):\nadd:\n{add}\nportable:\n{portable}"
    )


@pytest.mark.parametrize("channel", _CHANNELS)
def test_four_channel_url_path_segment_and_repo_name(channel: str) -> None:
    """The resolved url:'s path segment is the channel name; the stanza is keyed by its repo name."""
    conf = _print_conf_sh(_ADD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    repo_name = _CHANNEL_REPO_NAMES[channel]
    expected_url = f"{_PAGES_BASE}/{channel}/{_CE_28}"

    assert re.search(rf"^{re.escape(repo_name)}:\s*\{{", conf, re.MULTILINE), (
        f"repo name {repo_name!r} not found in conf:\n{conf}"
    )
    url_val = _field(conf, "url").strip('"')
    assert url_val == expected_url, f"url mismatch for {channel!r}: expected {expected_url!r}, got {url_val!r}"
    assert "${ABI}" not in conf


@pytest.mark.parametrize("channel", _CHANNELS)
def test_four_channel_priority_and_signature_type(channel: str) -> None:
    """Every channel carries the SAME priority 100 (equal project priority above Netgate's 0)."""
    conf = _print_conf_sh(_ADD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    assert _field(conf, "priority") == "100"
    assert _field(conf, "signature_type") == "none"
    assert _field(conf, "mirror_type") == "none"
    assert _field(conf, "enabled") == "yes"


@pytest.mark.parametrize("channel", _CHANNELS)
@pytest.mark.parametrize("generator", ["add-repo.sh", "build-repo.sh", "build-repo-portable.py"])
def test_four_channel_no_abi_placeholder(generator: str, channel: str) -> None:
    """No producer emits the literal ``${ABI}`` token for any of the four channels."""
    if generator == "add-repo.sh":
        conf = _print_conf_sh(_ADD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    elif generator == "build-repo.sh":
        conf = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    else:
        conf = _print_conf_portable(_CE_28, _PAGES_BASE, channel=channel)
    assert "${ABI}" not in conf, f"{generator} {channel}: found ${{ABI}} in conf:\n{conf}"


# --------------------------------------------------------------------------- #
# add-repo.sh live bootstrap — every channel (issue #2148)
# --------------------------------------------------------------------------- #


def _repos_dir(root: str) -> Path:
    return Path(root) / "usr" / "local" / "etc" / "pkg" / "repos"


@pytest.mark.parametrize("channel", _CHANNELS)
def test_add_repo_live_bootstrap_writes_the_channel_conf(channel: str) -> None:
    """Every channel bootstraps live: the box ends up with that channel's resolved conf.

    Scenario: given a CE 2.8.1 box fixture with no pfBlockerNG conf, when
    ``add-repo.sh --channel <ch>`` runs (no ``--print-conf``), then the box carries
    ``pfblockerng-<ch>.conf`` resolved by the boot hook — the stanza is keyed by the
    channel's own repo name and the url's channel segment is that channel.
    """
    with tempfile.TemporaryDirectory() as root:
        conf_path = _repos_dir(root) / _CHANNEL_CONF_NAMES[channel]
        assert not conf_path.exists(), "before-state: the channel conf must be absent"

        _run_add_repo(root, extra_args=("--channel", channel))

        assert conf_path.exists(), f"--channel {channel} must write {conf_path.name}"
        conf = conf_path.read_text()
        assert f"{_CHANNEL_REPO_NAMES[channel]}: {{" in conf, f"{channel}: wrong repo stanza:\n{conf}"
        assert f'url: "{_PAGES_BASE}/{channel}/ce-2.8"' in conf, f"{channel}: wrong resolved url:\n{conf}"
        assert "Generated at boot by pfblockerng_repo_generate" in conf, (
            f"{channel}: the boot hook did not resolve the conf:\n{conf}"
        )
        assert "pending" not in conf, f"{channel}: the staging stub survived:\n{conf}"


@pytest.mark.parametrize("channel", _CHANNELS)
def test_add_repo_live_bootstrap_leaves_other_channels_absent(channel: str) -> None:
    """A bootstrap creates exactly ONE project channel conf — never a sibling.

    The orphan guard is what makes single-repository subscription reachable: the boot
    hook regenerates only confs that exist, so a channel the user never bootstrapped
    must not appear as a side effect of bootstrapping another one.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_add_repo(root, extra_args=("--channel", channel))

        present = sorted(p.name for p in _repos_dir(root).iterdir()) if _repos_dir(root).is_dir() else []
        assert present == [_CHANNEL_CONF_NAMES[channel]], (
            f"--channel {channel} must leave exactly its own conf behind, found: {present}"
        )


@pytest.mark.parametrize("previous", ["release", "stable", "nightly"])
def test_add_repo_live_bootstrap_replaces_a_previously_enabled_channel(previous: str) -> None:
    """Single-repository subscription: bootstrapping a channel retires the other one.

    Scenario: given a box already subscribed to ``previous``, when the user bootstraps
    ``edge``, then the box is subscribed to edge ALONE — the previous channel's conf is
    gone and the removal is reported, so the box never ends up with two project
    repositories enabled at the same equal priority.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_add_repo(root, extra_args=() if previous == "release" else ("--channel", previous))
        previous_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES[previous]
        assert previous_conf.exists(), f"before-state: the box must be subscribed to {previous}"

        proc = _run_add_repo(root, extra_args=("--channel", "edge"))

        assert (_repos_dir(root) / _CHANNEL_CONF_NAMES["edge"]).exists(), "edge must be subscribed after the switch"
        assert not previous_conf.exists(), (
            f"{previous} must be unsubscribed by the switch — two project repos is not a supported configuration"
        )
        assert _CHANNEL_CONF_NAMES[previous] in (proc.stdout + proc.stderr), (
            f"the switch must report retiring {previous}:\n{proc.stdout}\n{proc.stderr}"
        )


def test_add_repo_unpublished_channel_leaves_the_previous_subscription_intact() -> None:
    """A channel with no build for this box must not cost the box its working subscription.

    Retiring the other project confs BEFORE proving the target catalogue serves this
    box would strand it: the previous channel is gone, the new one has nothing to
    install, and the box has no way back short of remembering which channel it was on.

    Scenario: given a box subscribed to nightly, when the user bootstraps edge and the
    edge catalogue turns out to carry nothing for this variant, then the run fails
    loudly AND the box is still subscribed to nightly alone — the staged edge conf is
    removed, so the repository configuration is exactly what it was before.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_add_repo(root, extra_args=("--channel", "nightly"))
        nightly_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES["nightly"]
        edge_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES["edge"]
        assert nightly_conf.exists(), "before-state: the box must be subscribed to nightly"
        nightly_before = nightly_conf.read_text()

        proc = _run_add_repo(root, extra_args=("--channel", "edge"), catalogue_empty=True)

        assert proc.returncode != 0, f"an unpublished channel must fail loudly:\n{proc.stdout}\n{proc.stderr}"
        assert nightly_conf.exists(), "the previous subscription must survive a failed switch"
        assert nightly_conf.read_text() == nightly_before, "the previous subscription must be left byte-identical"
        assert not edge_conf.exists(), (
            f"a failed switch must not leave the unusable conf behind:\n{proc.stdout}\n{proc.stderr}"
        )


def test_add_repo_failed_reswitch_restores_the_conf_it_did_not_create() -> None:
    """The failure cleanup restores what THIS run truncated, not merely leaves a file.

    Staging overwrites the conf in place, so re-running the bootstrap for the channel
    the box is already on destroys the working conf before it can fail. "The file still
    exists" is not enough — a one-line staging stub subscribes to nothing, which is the
    same stranded box the deferred retirement exists to prevent. The previous body has
    to come back byte-for-byte.

    Variant detection is what fails here, deliberately. It is the only gate that fires
    while the conf is still the stub: an empty catalogue fails later, by which point the
    hook has already regenerated the same body the box started with, so that path cannot
    tell a restore from a no-op.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_add_repo(root, extra_args=("--channel", "edge"))
        edge_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES["edge"]
        assert edge_conf.exists(), "before-state: the box must be subscribed to edge"
        # Re-subscribe once SUCCESSFULLY. This is the run that takes a backup — the
        # conf now pre-exists — so it is the only one that can show the backup being
        # cleaned up afterwards. The failing run below cannot: its restore consumes
        # the backup on the way past, whether or not the success path would have.
        _run_add_repo(root, extra_args=("--channel", "edge"))
        assert not list(_repos_dir(root).glob("*.pfb-prev.*")), (
            "a successful bootstrap must leave no conf backup behind"
        )
        edge_before = edge_conf.read_text()
        assert "pfblockerng-edge: {" in edge_before, "before-state: the conf must carry a real repo stanza"

        proc = _run_add_repo(root, extra_args=("--channel", "edge"), detection_fails=True)

        assert proc.returncode != 0, "an unresolvable conf must fail loudly"
        assert edge_conf.read_text() == edge_before, (
            f"the pre-existing conf must come back byte-identical, not as a stub:\n{edge_conf.read_text()}"
        )
        assert not list(_repos_dir(root).glob("*.pfb-prev.*")), "the restore must leave no backup file behind"


def test_add_repo_failed_detection_leaves_the_previous_subscription_intact() -> None:
    """The OTHER failure gate: the generator hook could not resolve a varver.

    A blank ``/etc/version`` leaves the staged conf without its marker line, and the
    bootstrap fails there — earlier than the catalogue verify, and before any
    retirement. The box must still come out of it subscribed exactly as it went in.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_add_repo(root, extra_args=("--channel", "nightly"))
        nightly_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES["nightly"]
        stable_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES["stable"]
        nightly_before = nightly_conf.read_text()

        proc = _run_add_repo(root, extra_args=("--channel", "stable"), detection_fails=True)

        assert proc.returncode != 0, "a hook that cannot resolve the conf must fail loudly"
        assert not stable_conf.exists(), (
            f"the unresolved conf this run staged must be removed:\n{proc.stdout}\n{proc.stderr}"
        )
        assert nightly_conf.read_text() == nightly_before, "the previous subscription must be untouched"


def test_add_repo_failed_pkg_update_leaves_exactly_one_project_conf() -> None:
    """``pkg update`` failing must not strand the box on TWO project repositories.

    ``pkg update`` exits non-zero when ANY enabled repository fails to refresh —
    including the channel the box is switching away from, whose catalogue going
    unpublished is precisely why someone switches. Retirement happens after this point,
    so an unhandled failure here would leave both confs enabled at the same priority,
    which the script itself documents as unsupported: ``pkg`` does not order across
    equal-priority repositories, so the build the box receives becomes undetermined.
    """
    with tempfile.TemporaryDirectory() as root:
        _run_add_repo(root, extra_args=("--channel", "testing"))
        testing_conf = _repos_dir(root) / _CHANNEL_CONF_NAMES["testing"]
        testing_before = testing_conf.read_text()

        proc = _run_add_repo(root, extra_args=("--channel", "edge"), update_fails=True)

        assert proc.returncode != 0, "a failed pkg update must fail loudly"
        present = {p.name for p in _repos_dir(root).glob("pfblockerng*.conf")}
        assert present == {_CHANNEL_CONF_NAMES["testing"]}, (
            f"expected the box to still be on testing alone, found {sorted(present)}:\n{proc.stdout}\n{proc.stderr}"
        )
        assert testing_conf.read_text() == testing_before, "the surviving subscription must be unchanged"


def test_add_repo_channel_nightly_live_bootstrap_matches_flag_nightly() -> None:
    """--channel nightly's live path behaves exactly like --nightly (allowed; same identity)."""
    with tempfile.TemporaryDirectory() as root_flag, tempfile.TemporaryDirectory() as root_channel:
        _run_add_repo(root_flag, nightly=True)
        _run_add_repo(root_channel, extra_args=("--channel", "nightly"))

        conf_flag = _repos_dir(root_flag) / "pfblockerng-nightly.conf"
        conf_channel = _repos_dir(root_channel) / "pfblockerng-nightly.conf"
        assert conf_flag.exists(), "--nightly must write pfblockerng-nightly.conf"
        assert conf_channel.exists(), "--channel nightly must write pfblockerng-nightly.conf"
        assert conf_flag.read_text() == conf_channel.read_text(), (
            "--channel nightly must byte-match --nightly's live-bootstrap output"
        )


def test_add_repo_help_advertises_the_canonical_identity_only() -> None:
    """``--help`` steers users to the four channels and the ONE canonical package.

    The legacy ``-devel`` install hint is retired: every channel serves
    ``pfSense-pkg-pfBlockerNG``, so advertising a suffixed identity would send users
    at a package no channel catalogue carries.
    """
    proc = subprocess.run(["sh", str(_ADD_REPO), "--help"], capture_output=True, text=True, check=True)
    assert "pfSense-pkg-pfBlockerNG-devel" not in proc.stdout, (
        f"--help must not advertise the retired -devel identity:\n{proc.stdout}"
    )
    assert "pkg install pfSense-pkg-pfBlockerNG" in proc.stdout, proc.stdout
    for channel in _CHANNELS:
        assert channel in proc.stdout, f"--help must name the {channel!r} channel:\n{proc.stdout}"


# --------------------------------------------------------------------------- #
# --channel hostile-input rows (all three generators where applicable)
# --------------------------------------------------------------------------- #


def test_add_repo_channel_requires_a_value() -> None:
    """`--channel` with no following value errors cleanly (exit 2)."""
    proc = subprocess.run(
        ["sh", str(_ADD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
    assert "--channel requires a value" in proc.stderr, proc.stderr


def test_build_repo_channel_requires_a_value() -> None:
    """`--channel` with no following value errors cleanly (exit 2)."""
    proc = subprocess.run(
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
    assert "--channel requires a value" in proc.stderr, proc.stderr


def test_build_repo_portable_channel_requires_a_value() -> None:
    """`--channel` with no following value errors cleanly (argparse exit 2)."""
    proc = subprocess.run(
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", str(_ADD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "bogus"],
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "bogus"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel", "bogus"],
    ],
    ids=["add-repo.sh", "build-repo.sh", "build-repo-portable.py"],
)
def test_channel_bogus_rejected_with_valid_list(argv: list[str]) -> None:
    """`--channel bogus` fails (exit 2) and the error names all four valid channels."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode == 2, proc.stderr
    stderr_lower = proc.stderr.lower()
    for ch in _CHANNELS:
        assert ch in stderr_lower, f"{argv[0]}: valid channel {ch!r} not listed in error:\n{proc.stderr}"


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", str(_ADD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "release"],
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "release"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel", "release"],
    ],
    ids=["add-repo.sh", "build-repo.sh", "build-repo-portable.py"],
)
def test_channel_release_rejected(argv: list[str]) -> None:
    """`--channel release` is REJECTED — release is the legacy default, not a four-channel name."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode == 2, proc.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", str(_ADD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "EDGE"],
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "EDGE"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel", "EDGE"],
    ],
    ids=["add-repo.sh", "build-repo.sh", "build-repo-portable.py"],
)
def test_channel_wrong_case_rejected(argv: list[str]) -> None:
    """`--channel EDGE` (wrong case) is rejected — exact lowercase match only."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode == 2, proc.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", str(_ADD_REPO), "--print-conf", "--channel", "edge"],
        ["sh", str(_BUILD_REPO), "--print-conf", "--channel", "edge"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--channel", "edge"],
    ],
    ids=["add-repo.sh", "build-repo.sh", "build-repo-portable.py"],
)
def test_print_conf_channel_still_requires_catalog_path(argv: list[str]) -> None:
    """`--print-conf --channel edge` without `--catalog-path` still fails (existing guard fires)."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode != 0, proc.stderr
    assert "catalog-path" in proc.stderr.lower(), proc.stderr
