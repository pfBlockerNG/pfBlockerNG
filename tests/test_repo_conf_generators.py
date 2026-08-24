"""Drift guard for the client repo-conf (ADR-17 / ADR-39).

`scripts/build-repo.sh` (the catalog generator) and `scripts/build-repo-portable.py`
(the Python generator) BOTH emit the pkg(8) repo-conf the user ends up with, and the
boot-time `rc.d` generator hook (`pfblockerng_repo_generate.sh`) regenerates it live
on the box. They MUST never disagree on ANY load-bearing field.

ADR-39 rework: the conf URL is now a DIRECT, fully-resolved GitHub Pages URL
(no Cloudflare Worker, no ``${ABI}`` token). Arch-less since issue #1806
(NO_ARCH — all three pfSense-pkg-pfBlockerNG ports are NO_ARCH, so one varver
serves every arch of its FreeBSD major):

    https://pkg.pfblockerng.com/<channel>/<varver>

The ``<varver>`` segment is resolved by the boot-time ``rc.d`` generator hook
(``pfblockerng_repo_generate.sh``), whose detection is folded in (ADR-39): edition =
"/etc/product_label contains 'Plus'", version = major.minor of /etc/version.  The
hook regenerates each EXISTING channel conf every boot, so the URL self-corrects
after a pfSense OS upgrade — except the legacy release conf (pfblockerng.conf),
retired by install.sh (issue #2416 follow-up) and left
byte-unchanged if a leftover survives.

Tests below pin:

* **byte-identity** across both remaining producers — the two ``--print-conf``
  generators AND the hook (per channel, ``--catalog-path ce-2.8`` so the URL is
  deterministic);
* **resolved URL shape** for representative ``<varver>`` values;
* **no ``${ABI}``** in any generated conf;
* **field contract** unchanged from ADR-17/20 except the url: value.

Bootstrap/live-install/verify/version-pick coverage now lives in
tests/test_channel_install.py, exercising the current SOLE client entry point,
install.sh --channel <channel>.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = _ROOT / "scripts"
_BUILD_REPO = _SCRIPTS / "build-repo.sh"
_BUILD_REPO_PORTABLE = _SCRIPTS / "build-repo-portable.py"
_HOOK = _ROOT / "src" / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"

# The catalogue base a box is given: plain HTTP, because pkg's CA store is Netgate-pinned
# on Plus and unreachable from the GUI (issue #2675). Authenticity rides the signature.
# gen_landing derives this from the site's HTTPS base when it bakes install.sh; nothing
# downstream rewrites a scheme, so a conf carries the base verbatim.
_PAGES_BASE = "http://pkg.pfblockerng.com"
_FINGERPRINT_DIR = "/usr/local/etc/pkg/fingerprints/pfblockerng"

# Representative catalog paths for byte-identity and URL-shape tests.
_CE_28 = "ce-2.8"
_PLUS_2603 = "plus-26.03"

# The four channels (issue #2147 step B) — each owns its own <channel>/<varver>/
# catalog subtree, all serving the ONE canonical pfSense-pkg-pfBlockerNG package.
# `release` is the legacy shared repo (pre-#2148, retired by the installers, issue
# #2416); NOT one of the four (--channel release is rejected — see
# test_channel_release_rejected).
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


def _field(conf: str, key: str) -> str:
    """Extract a ``  key: value,`` field's value from a printed conf stanza."""
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?),?\s*$", conf, re.MULTILINE)
    assert m is not None, f"field {key!r} not found in conf:\n{conf}"
    return m.group(1).strip().rstrip(",").strip()


# --------------------------------------------------------------------------- #
# Byte-identity: both generators must emit the SAME bytes
# --------------------------------------------------------------------------- #


def test_release_conf_byte_identical_across_producer_generators() -> None:
    """Producer --print-conf still defaults to the legacy release tree, byte-for-byte.

    install.sh no longer emits a release conf (--channel is required and release
    is rejected — issue #2384). The catalogue producers keep their internal default
    for assembling unpublished/legacy trees.
    """
    build = _print_conf_sh(_BUILD_REPO)
    portable = _print_conf_portable()

    assert build, "build-repo.sh --print-conf produced empty output"
    assert portable, "build-repo-portable.py --print-conf produced empty output"
    assert build == portable, (
        f"build-repo.sh and build-repo-portable.py drifted:\nbuild:\n{build}\nportable:\n{portable}"
    )


def test_release_default_body_never_names_release_as_a_channel() -> None:
    """N1 (issue #2416 review): the legacy ``release`` default's header line must
    never read "re-run install.sh --channel release to change" — install.sh
    REJECTS ``--channel release`` explicitly (issue #2384; ``release`` is not one
    of the four channels). The un-actionable clause must not name a channel
    install.sh refuses.
    """
    build = _print_conf_sh(_BUILD_REPO)
    portable = _print_conf_portable()

    assert "--channel release" not in build, build
    assert "--channel release" not in portable, portable


def test_release_conf_byte_identical_plus_26_03() -> None:
    """Producer byte-identity holds for a Plus 26.03 box (second representative case)."""
    cat = _PLUS_2603
    build = _print_conf_sh(_BUILD_REPO, cat)
    portable = _print_conf_portable(cat)

    assert build == portable, (
        f"build-repo.sh vs portable mismatch (plus-26.03):\nbuild:\n{build}\nportable:\n{portable}"
    )


def _hook_conf_env(repos: str) -> dict[str, str]:
    """Every ``PFB_*_CONF`` override the hook reads, pointed inside ``repos``.

    Passing ALL of them is mandatory for hermeticity: an override the test omits
    falls back to its ``/usr/local/etc/pkg/repos/`` default, so the hook would
    regenerate the REAL box's conf during a test run.
    """
    return {f"PFB_{channel.upper()}_CONF": os.path.join(repos, name) for channel, name in _CHANNEL_CONF_NAMES.items()}


def _run_hook(root: str, *, edition_label: str, version: str, channel: str, base_url: str | None = None) -> str:
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
        # Staged, like every other on-box path this harness overrides: without it the
        # hook writes the HOST's real /usr/local/etc/pkg/fingerprints — silent only
        # where that path happens not to be writable.
        "PFB_FINGERPRINT_DIR": os.path.join(root, "fingerprints", "pfblockerng"),
    }
    if base_url is not None:
        env["PFB_BASE_URL"] = base_url
    subprocess.run(["sh", str(_HOOK), "onestart"], env=env, capture_output=True, text=True, check=False)
    return Path(conf_path).read_text()


def test_hook_leaves_legacy_release_conf_untouched() -> None:
    """The rc.d hook no longer regenerates the legacy release conf (issue #2416):
    a leftover ``pfblockerng.conf`` from a pre-#2148 box survives byte-identical
    across a boot regeneration — only the four channel confs get regenerated now.
    """
    with tempfile.TemporaryDirectory() as root:
        hook_conf = _run_hook(root, edition_label="pfSense", version="2.8.1", channel="release")
    assert hook_conf == "# stub pending\n", f"legacy release conf must be left untouched by the hook:\n{hook_conf}"


@pytest.mark.parametrize("base", ["file:///srv/pfb-catalog", "https://fork.example.org/pkg"])
def test_hook_matches_print_conf_for_a_base_that_is_not_the_project_host(base: str) -> None:
    """The hook's unsigned arm is pinned too, not just the producers'.

    Only ``pkg.pfblockerng.com`` carries catalogues our key signs, so every other base —
    a local ``file://`` tree, a fork site — keeps its scheme and ``signature_type: none``.
    The three generators have to agree on that shape as exactly as they agree on the
    signed one, and until now nothing compared the hook against them for it.
    """
    with tempfile.TemporaryDirectory() as root:
        hook_conf = _run_hook(root, edition_label="pfSense", version="2.8.1", channel="stable", base_url=base)
    print_conf = _print_conf_portable(_CE_28, base, channel="stable")
    assert hook_conf == print_conf, (
        f"hook vs --print-conf drift for {base}:\nhook:\n{hook_conf}\nprint-conf:\n{print_conf}"
    )
    assert _field(hook_conf, "signature_type") == "none"


def test_hook_output_byte_identical_to_print_conf_nightly_plus() -> None:
    """The hook's nightly conf for a Plus 26.03 box matches --print-conf --channel nightly."""
    with tempfile.TemporaryDirectory() as root:
        hook_conf = _run_hook(root, edition_label="pfSense Plus", version="26.03.1", channel="nightly")
    print_conf = _print_conf_portable(_PLUS_2603, _PAGES_BASE, channel="nightly")
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
    print_conf = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
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
# No ${ABI} in any emitted conf (both generators)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("channel_args", [("--channel", "stable"), ("--channel", "nightly")])
@pytest.mark.parametrize("generator", ["build-repo.sh", "build-repo-portable.py"])
def test_no_abi_placeholder_in_any_generator_output(generator: str, channel_args: tuple[str, ...]) -> None:
    """No generator emits a conf containing the literal ``${ABI}`` token.

    ADR-39 contracts: the URL is fully resolved at bootstrap; the ${ABI} expansion
    trick from ADR-17/20 is retired because one ABI can map to multiple pfSense
    versions (varver keying is mandatory). Producers may still default to release
    when no channel is given.
    """
    cat = _CE_28
    if generator == "build-repo.sh":
        conf = _print_conf_sh(_BUILD_REPO, cat, _PAGES_BASE, *channel_args)
    else:
        conf = _print_conf_portable(cat, _PAGES_BASE, channel=channel_args[1])

    assert "${ABI}" not in conf, f"{generator} {channel_args}: found ${{ABI}} in conf:\n{conf}"


@pytest.mark.parametrize(
    ("argv", "needle"),
    [
        (["sh", str(_BUILD_REPO), "--print-conf"], "catalog-path"),
        ([sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf"], "catalog-path"),
    ],
    ids=["build-repo.sh", "build-repo-portable.py"],
)
def test_print_conf_requires_catalog_path(argv: list[str], needle: str) -> None:
    """Both generators FAIL `--print-conf` without `--catalog-path` (no unresolved URL).

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
def test_four_channel_conf_byte_identical_across_both_generators(channel: str) -> None:
    """The <channel> conf from build-repo.sh == build-repo-portable.py."""
    build = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    portable = _print_conf_portable(_CE_28, _PAGES_BASE, channel=channel)

    assert build, f"build-repo.sh --channel {channel} produced empty output"
    assert portable, f"build-repo-portable.py --channel {channel} produced empty output"

    assert build == portable, (
        f"build-repo.sh vs build-repo-portable.py drift ({channel}):\nbuild:\n{build}\nportable:\n{portable}"
    )


@pytest.mark.parametrize("channel", _CHANNELS)
def test_four_channel_url_path_segment_and_repo_name(channel: str) -> None:
    """The resolved url:'s path segment is the channel name; the stanza is keyed by its repo name."""
    conf = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    repo_name = _CHANNEL_REPO_NAMES[channel]
    # http, not the https base handed in: pkg fetches the catalogue with a CA store
    # pfSense Plus pins to Netgate, so TLS is not a trust anchor we can rely on.
    # Authenticity comes from the catalogue signature instead (issue #2675).
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
    conf = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    assert _field(conf, "priority") == "100"
    assert _field(conf, "signature_type") == "fingerprints"
    assert _field(conf, "fingerprints").strip('"') == _FINGERPRINT_DIR
    assert _field(conf, "mirror_type") == "none"
    assert _field(conf, "enabled") == "yes"


@pytest.mark.parametrize("channel", _CHANNELS)
def test_file_base_stays_unsigned_and_byte_identical(channel: str) -> None:
    """A ``file://`` catalogue keeps today's bytes: no scheme rewrite, signature_type none.

    Such a catalogue is built locally and carries no signature, and there is no TLS in
    the path to distrust — the live smoke fleet serves one this way. Emitting a
    signature-requiring conf for it would make `pkg update` fail against a catalogue that
    is fine.
    """
    base = "file:///srv/pfb-catalog"
    build = _print_conf_sh(_BUILD_REPO, _CE_28, base, "--channel", channel)
    portable = _print_conf_portable(_CE_28, base, channel=channel)

    assert build == portable, f"file:// drift ({channel}):\nbuild:\n{build}\nportable:\n{portable}"
    assert _field(build, "signature_type") == "none"
    assert _field(build, "url").strip('"') == f"{base}/{channel}/{_CE_28}"
    assert "fingerprints" not in build


@pytest.mark.parametrize("channel", _CHANNELS)
@pytest.mark.parametrize("generator", ["build-repo.sh", "build-repo-portable.py"])
def test_four_channel_no_abi_placeholder(generator: str, channel: str) -> None:
    """No producer emits the literal ``${ABI}`` token for any of the four channels."""
    if generator == "build-repo.sh":
        conf = _print_conf_sh(_BUILD_REPO, _CE_28, _PAGES_BASE, "--channel", channel)
    else:
        conf = _print_conf_portable(_CE_28, _PAGES_BASE, channel=channel)
    assert "${ABI}" not in conf, f"{generator} {channel}: found ${{ABI}} in conf:\n{conf}"


# --------------------------------------------------------------------------- #
# --channel hostile-input rows (both generators where applicable)
# --------------------------------------------------------------------------- #


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
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "bogus"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel", "bogus"],
    ],
    ids=["build-repo.sh", "build-repo-portable.py"],
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
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "release"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel", "release"],
    ],
    ids=["build-repo.sh", "build-repo-portable.py"],
)
def test_channel_release_rejected(argv: list[str]) -> None:
    """`--channel release` is REJECTED — release is not one of the four channel names."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode == 2, proc.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", str(_BUILD_REPO), "--print-conf", "--catalog-path", _CE_28, "--channel", "EDGE"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--catalog-path", _CE_28, "--channel", "EDGE"],
    ],
    ids=["build-repo.sh", "build-repo-portable.py"],
)
def test_channel_wrong_case_rejected(argv: list[str]) -> None:
    """`--channel EDGE` (wrong case) is rejected — exact lowercase match only."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode == 2, proc.stderr


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", str(_BUILD_REPO), "--print-conf", "--channel", "edge"],
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf", "--channel", "edge"],
    ],
    ids=["build-repo.sh", "build-repo-portable.py"],
)
def test_print_conf_channel_still_requires_catalog_path(argv: list[str]) -> None:
    """`--print-conf --channel edge` without `--catalog-path` still fails (existing guard fires)."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode != 0, proc.stderr
    assert "catalog-path" in proc.stderr.lower(), proc.stderr


def test_the_hooks_trusted_fingerprint_is_the_sha256_of_the_committed_public_key() -> None:
    """The hex the hook installs must be the SHA256 of the DER public key the catalogues
    embed — nothing else in the tree can tell a correct fingerprint from a plausible one.

    The public half is committed beside this test (it is public by construction: every
    signed catalogue carries it in a `.pub` member). A typo in the hook, or a key rotated
    on one side only, fails here instead of on every box at once with "No trusted public
    keys found".
    """
    der = (_ROOT / "tests" / "fixtures" / "pkg-signing" / "pfblockerng-repo.pub.der").read_bytes()
    hook = _HOOK.read_text()
    match = re.search(r"^CONF_FINGERPRINT_SHA256='([0-9a-f]{64})'", hook, re.MULTILINE)
    assert match is not None, "the hook no longer carries a CONF_FINGERPRINT_SHA256 literal"
    assert match.group(1) == hashlib.sha256(der).hexdigest()


def test_no_stale_dev_tooling_hook_path_reference() -> None:
    """Issue #2675: the hook moved out of the dev-tooling ``scripts/`` tree's
    ``rc.d`` directory into ``_HOOK`` (the shipped tree) so the package can install
    it. Guard against a stale reference to the old dev-tooling path creeping back
    into the live tree (``legacy/`` is an immutable historical corpus, exempt).

    The needle is assembled at runtime, not written as a literal in this file's own
    source (which would self-match and make the guard permanently red)."""
    # Two spellings. Both are assembled at runtime, never written as literals here:
    # a literal self-matches and pins the guard permanently red. The second spelling
    # exists because the first shipped blind to it — a path built from one quoted
    # directory segment per component carries no contiguous form of the old path,
    # and three live smoke references survived the relocation that way.
    _quote = "[\"']"
    _seg = _quote + "%s" + _quote
    stale_needle = "|".join(
        [
            "/".join(["scripts", r"rc\.d"]),
            (_seg % "scripts") + r",? */? *" + (_seg % r"rc\.d"),
        ]
    )
    proc = subprocess.run(
        [
            "grep",
            "-rlE",
            stale_needle,
            str(_ROOT),
            "--exclude-dir=.git",
            "--exclude-dir=legacy",
            "--exclude-dir=.codegraph",
            "--exclude-dir=graphify-out",
            "--exclude-dir=__pycache__",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    hits = [line for line in proc.stdout.splitlines() if line and "__pycache__" not in line]
    assert not hits, f"stale dev-tooling hook-path reference(s) found outside legacy/: {hits}"
