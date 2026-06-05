"""Drift guard for the client repo-conf (ADR-17 Phase 4).

`scripts/add-repo.sh` (the client bootstrap) and `scripts/build-repo.sh` (the
catalog generator) BOTH emit the pkg(8) repo-conf the user ends up with — the
former writes it on the box, the latter is the published single source of truth
(`--print-conf`, also reused by the README). They MUST never disagree on the
load-bearing fields: the same `url:` (static base + the literal ``${ABI}`` pkg
variable), the same `priority:` (above the Netgate `pfSense` repo — the cross-repo
precedence lever, ADR §1 Context 4 / Phase 1), and `mirror_type`/`signature_type`
`none` (NONE-signed). This test FAILS if either script drifts.

These run the real shell scripts via `--print-conf` (a pure, side-effect-free
mode — no `pkg`, no writes), so the assertion is over the bytes a box would get.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_ADD_REPO = _SCRIPTS / "add-repo.sh"
_BUILD_REPO = _SCRIPTS / "build-repo.sh"


def _print_conf(script: Path, *args: str) -> str:
    """Run `<script> --print-conf [args]` and return its stdout (text)."""
    proc = subprocess.run(
        ["sh", str(script), "--print-conf", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def _field(conf: str, key: str) -> str:
    """Extract a `  key: value,` field's value from a printed conf stanza."""
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+?),?\s*$", conf, re.MULTILINE)
    assert m is not None, f"field {key!r} not found in conf:\n{conf}"
    return m.group(1).strip().rstrip(",").strip()


# --------------------------------------------------------------------------- #
# Devel: add-repo.sh must emit the EXACT bytes build-repo.sh publishes.
# --------------------------------------------------------------------------- #


def test_add_repo_devel_conf_is_byte_identical_to_build_repo() -> None:
    """The devel conf from add-repo.sh == build-repo.sh --print-conf, byte-for-byte.

    build-repo.sh --print-conf is the published single source (Phase 2/3). If
    add-repo.sh's devel stanza diverges by even a byte (url, priority, comment),
    the client would write a conf that disagrees with what CI publishes — this
    pins them together.
    """
    add = _print_conf(_ADD_REPO, "devel")
    build = _print_conf(_BUILD_REPO)
    assert add == build


def test_add_repo_devel_conf_default_channel_matches_explicit() -> None:
    """No channel arg defaults to devel (the documented default)."""
    assert _print_conf(_ADD_REPO) == _print_conf(_ADD_REPO, "devel")


# --------------------------------------------------------------------------- #
# The load-bearing fields hold for BOTH channels (branch coverage).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("channel", "repo_name", "url"),
    [
        ("devel", "pfblockerng-devel", 'url: "https://andrebrait.github.io/pfBlockerNG/${ABI}"'),
        ("stable", "pfblockerng", 'url: "https://andrebrait.github.io/pfBlockerNG/${ABI}"'),
    ],
)
def test_add_repo_conf_fields_per_channel(channel: str, repo_name: str, url: str) -> None:
    """Each channel names its repo distinctly but shares the precedence-bearing fields.

    devel -> repo `pfblockerng-devel`; stable -> repo `pfblockerng`. Both carry
    the SAME static ${ABI} url, priority 100 (above Netgate's 0), and none/none
    (NONE-signed). The repo NAME is the only channel-varying field — a stable conf
    that reused the devel repo name (or vice versa) would collide on a box.
    """
    conf = _print_conf(_ADD_REPO, channel)

    # The stanza is keyed by the channel-specific repo name (and ONLY that name).
    assert re.search(rf"^{re.escape(repo_name)}:\s*\{{", conf, re.MULTILINE), conf
    other = "pfblockerng" if channel == "devel" else "pfblockerng-devel"
    # `pfblockerng-devel:` must not match a bare `pfblockerng:` probe — anchor the colon.
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
    """An unknown channel arg fails loud (exit != 0), never silently writing a conf."""
    proc = subprocess.run(
        ["sh", str(_ADD_REPO), "--print-conf", "nightly"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "channel" in proc.stderr.lower()
