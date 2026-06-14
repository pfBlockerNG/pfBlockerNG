"""Drift guard for the client repo-conf (ADR-17 Phase 4 / ADR-20 Phase 4).

`scripts/add-repo.sh` (the client bootstrap) and `scripts/build-repo.sh` (the
catalog generator) BOTH emit the pkg(8) repo-conf the user ends up with — the
former writes it on the box, the latter is the published single source of truth
(`--print-conf`, also reused by the README). They MUST never disagree on the
load-bearing fields: the same `url:` (static base + the literal ``${ABI}`` pkg
variable), the same `priority:` (above the Netgate `pfSense` repo — the cross-repo
precedence lever, ADR §1 Context 4 / Phase 1), and `mirror_type`/`signature_type`
`none` (NONE-signed). This test FAILS if either script drifts.

ADR-20 Phase 4: the canonical url is the Cloudflare Worker URL
(https://pkg.pfblockerng.workers.dev) — written once, never needs re-running after
a pfSense OS upgrade (the Worker re-routes by User-Agent automatically).

These run the real shell scripts via `--print-conf` (a pure, side-effect-free
mode — no `pkg`, no writes), so the assertion is over the bytes a box would get.
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

_WORKER_URL = "https://pkg.pfblockerng.workers.dev"
_OLD_PAGES_URL = "https://pfblockerng.github.io/pkg"


def _print_conf_portable() -> str:
    """Run `build-repo-portable.py --print-conf` (the Python generator) and return stdout."""
    proc = subprocess.run(
        [sys.executable, str(_BUILD_REPO_PORTABLE), "--print-conf"],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _print_conf(script: Path, *args: str) -> str:
    """Run `<script> --print-conf [args]` and return its stdout (text)."""
    proc = subprocess.run(
        ["sh", str(script), "--print-conf", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _run_add_repo(channel: str, root: str) -> None:
    """Run add-repo.sh <channel> with PFBLOCKERNG_ROOT=root.

    PKG_BIN is overridden to a stub that satisfies `command -v` (it exists and
    is executable) and exits 0 for every subcommand — enough for the script to
    write the conf, run `pkg update`, and complete the verify step (rquery exits 0
    but returns no output, so the script reports the pkg missing and exits 1).
    We assert only that the conf file was written; exit code is irrelevant.
    """
    # Create a fake pkg stub under the temp root (any writable path is fine;
    # PKG_BIN env var overrides the hard-coded /usr/local/sbin/pkg).
    bin_dir = os.path.join(root, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    fake_pkg = os.path.join(bin_dir, "pkg")
    with open(fake_pkg, "w") as fh:
        fh.write("#!/bin/sh\n# fake pkg stub for tests\nexit 0\n")
    os.chmod(fake_pkg, 0o755)

    env = {**os.environ, "PFBLOCKERNG_ROOT": root, "PKG_BIN": fake_pkg}
    subprocess.run(
        ["sh", str(_ADD_REPO), channel],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _field(conf: str, key: str) -> str:
    """Extract a `  key: value,` field's value from a printed conf stanza."""
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?),?\s*$", conf, re.MULTILINE)
    assert m is not None, f"field {key!r} not found in conf:\n{conf}"
    return m.group(1).strip().rstrip(",").strip()


# --------------------------------------------------------------------------- #
# Devel: add-repo.sh must emit the EXACT bytes build-repo.sh publishes.
# --------------------------------------------------------------------------- #


def test_release_conf_byte_identical_across_stable_devel_and_build_repo() -> None:
    """stable and devel emit the SAME release conf, == build-repo.sh --print-conf.

    The stable and devel packages share ONE repo/catalog (`pfblockerng`, Netgate-style),
    so `add-repo.sh stable` and `add-repo.sh devel` must write byte-identical confs — and
    both must match build-repo.sh --print-conf, the published single source (Phase 2/3).
    A one-byte divergence (url, priority, repo name, comment) would split what is meant to
    be one repo, so this pins all three generators together.
    """
    stable = _print_conf(_ADD_REPO, "stable")
    devel = _print_conf(_ADD_REPO, "devel")
    build = _print_conf(_BUILD_REPO)
    portable = _print_conf_portable()
    assert stable == devel  # collapsed: stable + devel are one shared `pfblockerng` repo
    assert stable == build  # == the published single-source template (build-repo.sh)
    assert stable == portable  # == the portable Python generator — all THREE byte-equal


def test_add_repo_default_channel_matches_devel() -> None:
    """No channel arg defaults to devel (the documented default; the release conf)."""
    assert _print_conf(_ADD_REPO) == _print_conf(_ADD_REPO, "devel")


# --------------------------------------------------------------------------- #
# The load-bearing fields hold for BOTH channels (branch coverage).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("channel", "repo_name", "url"),
    [
        # stable + devel collapse onto the ONE shared `pfblockerng` release repo.
        ("devel", "pfblockerng", f'url: "{_WORKER_URL}/${{ABI}}"'),
        ("stable", "pfblockerng", f'url: "{_WORKER_URL}/${{ABI}}"'),
        # nightly is served from a DISTINCT `nightly/` catalog subtree (so it never
        # collides with the release tree on Pages) — its url carries the extra path.
        ("nightly", "pfblockerng-nightly", f'url: "{_WORKER_URL}/nightly/${{ABI}}"'),
    ],
)
def test_add_repo_conf_fields_per_channel(channel: str, repo_name: str, url: str) -> None:
    """stable/devel name the shared release repo; nightly its own — all share the rest.

    stable + devel -> `pfblockerng` (one shared repo); nightly -> `pfblockerng-nightly`
    (and a `nightly/${ABI}` url subtree). All carry priority 100 (above Netgate's 0) and
    none/none (NONE-signed). The repo NAME (and, for nightly, the url subpath) is the only
    varying field — and nightly's name must never collide with the release repo on a box.
    """
    conf = _print_conf(_ADD_REPO, channel)

    # The stanza is keyed by the expected repo name (and ONLY that name).
    assert re.search(rf"^{re.escape(repo_name)}:\s*\{{", conf, re.MULTILINE), conf
    # The OTHER repo name does not appear as a stanza key (the anchored `:` keeps
    # `pfblockerng:` from matching `pfblockerng-nightly:`).
    for other in {"pfblockerng", "pfblockerng-nightly"} - {repo_name}:
        assert not re.search(rf"^{re.escape(other)}:\s*\{{", conf, re.MULTILINE), conf

    # The literal ${ABI} survives (single-quoted on emission — pkg expands it, not the shell).
    assert url in conf
    assert "${ABI}" in conf

    # NONE-signed + above-Netgate priority + enabled — the precedence/trust contract.
    assert _field(conf, "mirror_type") == "none"
    assert _field(conf, "signature_type") == "none"
    assert _field(conf, "priority") == "100"
    assert _field(conf, "enabled") == "yes"


def test_add_repo_rejects_unknown_channel() -> None:
    """An unknown channel arg fails loud (exit != 0), never silently writing a conf.

    (devel/stable/nightly are the three valid channels; anything else is rejected.)
    """
    proc = subprocess.run(
        ["sh", str(_ADD_REPO), "--print-conf", "bogus"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "channel" in proc.stderr.lower()


# --------------------------------------------------------------------------- #
# ADR-20 Phase 4: Worker URL tests
# --------------------------------------------------------------------------- #


def test_primary_url_is_worker_url() -> None:
    """add-repo.sh writes the Cloudflare Worker URL, not the old GitHub Pages URL.

    Scenario: Given the conf does not exist (or exists with the old GitHub Pages URL),
    When  add-repo.sh devel is run,
    Then  the written conf URL contains pkg.pfblockerng.workers.dev and does NOT
          contain pfblockerng.github.io.

    Before-state asserted: conf either absent or contains the old Pages URL pattern
    (confirmed absent here — fresh tmpdir).
    """
    with tempfile.TemporaryDirectory() as root:
        conf_path = Path(root) / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng.conf"

        # Given: conf does not exist yet (before-state)
        assert not conf_path.exists(), "conf should not exist before first run"

        # When: run add-repo.sh devel (writes the shared release conf)
        _run_add_repo("devel", root)

        # Then: conf written with Worker URL
        assert conf_path.exists(), "conf should be written by add-repo.sh"
        content = conf_path.read_text()
        assert _WORKER_URL in content, f"Worker URL not found in conf:\n{content}"
        assert _OLD_PAGES_URL not in content, f"Old Pages URL must not appear in conf:\n{content}"


def test_worker_url_has_no_abi_placeholder() -> None:
    """The conf URL base does NOT contain the literal text '${ABI}'.

    pkg appends the ABI path component naturally from the conf url: field;
    the base Worker URL is clean (no ${ABI} in the host/base portion).
    The ${ABI} placeholder appears only in the full url: line (appended after
    the base), not embedded in the Worker hostname or path prefix.
    """
    conf = _print_conf(_ADD_REPO, "devel")
    url_line = _field(conf, "url").strip('"')
    # The Worker base itself must not contain ${ABI}
    base = url_line.split("${ABI}")[0]
    assert _WORKER_URL in base, f"Worker URL not in base portion: {base!r}"
    # Full url line does contain ${ABI} (pkg expands it at fetch time)
    assert "${ABI}" in url_line, f"Expected ${{ABI}} in url line: {url_line!r}"


def test_worker_url_unchanged_regardless_of_channel() -> None:
    """All three channels write the same Worker base URL; only repo section name differs.

    The Worker handles routing for all channels uniformly — the variant/version
    routing is User-Agent-based, not channel-based. The nightly channel adds the
    `nightly/` subpath prefix, but the Worker hostname is identical across all three.
    """
    for channel in ("devel", "stable", "nightly"):
        conf = _print_conf(_ADD_REPO, channel)
        url_line = _field(conf, "url")
        assert _WORKER_URL in url_line, f"Channel {channel!r}: Worker URL not in url field: {url_line!r}"
        assert _OLD_PAGES_URL not in url_line, f"Channel {channel!r}: old Pages URL must not appear: {url_line!r}"


def test_conf_written_once_invariant() -> None:
    """Running add-repo.sh devel twice produces the same URL (idempotent).

    Scenario: Given the conf is written by a first run (Worker URL present),
    When  add-repo.sh devel is run again,
    Then  the URL is unchanged — the conf is rewritten with the same Worker URL.
    """
    with tempfile.TemporaryDirectory() as root:
        conf_path = Path(root) / "usr" / "local" / "etc" / "pkg" / "repos" / "pfblockerng.conf"

        # Given: first run writes the conf
        _run_add_repo("devel", root)
        assert conf_path.exists()
        content_first = conf_path.read_text()
        assert _WORKER_URL in content_first  # before-state: Worker URL present

        # When: run again
        _run_add_repo("devel", root)

        # Then: URL unchanged
        content_second = conf_path.read_text()
        assert content_first == content_second, (
            f"Second run must produce identical conf (idempotent):\nFirst:\n{content_first}\nSecond:\n{content_second}"
        )


def test_stable_and_devel_collapse_onto_one_shared_conf_file() -> None:
    """stable and devel write the SAME on-box file — no separate per-channel conf.

    Scenario: the stable + devel packages share one repo, so both channels target
              /usr/local/etc/pkg/repos/pfblockerng.conf (never a `pfblockerng-devel.conf`).
    Given stable is bootstrapped first (writes the shared release conf),
    When  devel is bootstrapped into the same root,
    Then  it rewrites the SAME file with identical bytes, and no `pfblockerng-devel.conf`
          is ever created — proving the collapse (a regression that re-split the channels
          would leave two distinct files here).
    """
    with tempfile.TemporaryDirectory() as root:
        repos = Path(root) / "usr" / "local" / "etc" / "pkg" / "repos"
        shared = repos / "pfblockerng.conf"
        legacy_split = repos / "pfblockerng-devel.conf"

        # Given: stable writes the shared release conf (before-state)
        _run_add_repo("stable", root)
        assert shared.exists(), "stable must write the shared pfblockerng.conf"
        stable_bytes = shared.read_text()
        assert not legacy_split.exists(), "stable must not write a split pfblockerng-devel.conf"

        # When: devel is bootstrapped into the same root
        _run_add_repo("devel", root)

        # Then: same file, identical bytes, and still no split conf
        assert shared.read_text() == stable_bytes, "devel must rewrite the SAME shared conf, byte-identical"
        assert not legacy_split.exists(), "devel must NOT create a separate pfblockerng-devel.conf"
