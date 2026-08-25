"""Release/3.3 assertions for the shipped boot-time repo-conf generator hook.

The hook reached a box only through the published ``install.sh``, which carries it
embedded — the package never delivered it, so a box could not pick up a newer one by
upgrading. It ships from ``src/`` here (pfBlockerNG issue #2675) so the stable and
testing ports install it, which is what lets an ordinary ``pkg upgrade`` move a 3.3 box
onto the signed, plain-HTTP repository instead of requiring a bootstrap re-run.

This line carries the hook as a shipped artefact only: its logic lives on ``devel`` and
is tested there. What has to hold HERE is that the file is installable and that the
contract 3.3's own PHP depends on is intact.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_HOOK = _ROOT / "src" / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"
_SOFTWARE_INC = _ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng" / "pfblockerng_software.inc"


def test_the_hook_is_shipped_and_executable() -> None:
    """rc.subr will not run a non-executable script, and pfblockerng_software.inc's
    is_executable() gate would read it as absent."""
    assert _HOOK.is_file(), f"the hook is not in the shipped tree: {_HOOK}"
    assert os.access(_HOOK, os.X_OK), "the shipped hook must carry the exec bit"


def test_the_hook_parses_as_posix_sh() -> None:
    """It runs at boot on the appliance; a parse error there wedges nothing but leaves
    the box on a stale conf for ever."""
    proc = subprocess.run(["sh", "-n", str(_HOOK)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


def test_the_hook_carries_the_verbs_this_line_dispatches() -> None:
    """`pfblockerng_software.inc` reads the installed hook's body and gates its
    login.conf controls on finding these verbs (issue #2630). A hook without them
    silently disables that page's controls rather than failing loudly.
    """
    body = _HOOK.read_text(encoding="utf-8")
    for verb in ("login-ca-sync", "login-ca-revoke"):
        assert verb in body, f"the shipped hook no longer offers {verb!r}"


def test_the_conf_names_the_on_box_fingerprint_directory() -> None:
    """The conf the hook writes tells pkg where the trusted fingerprint lives, and that
    path must be the one on the running box — never a staged prefix, which a chroot
    install would otherwise bake in.
    """
    body = _HOOK.read_text(encoding="utf-8")
    match = re.search(r"^CONF_FINGERPRINT_DIR='([^']+)'", body, re.MULTILINE)
    assert match is not None, "the hook no longer defines CONF_FINGERPRINT_DIR"
    assert match.group(1) == "/usr/local/etc/pkg/fingerprints/pfblockerng"


@pytest.mark.parametrize("channel", ["stable", "testing", "edge", "nightly"])
def test_the_hook_regenerates_every_channel_conf(tmp_path: Path, channel: str) -> None:
    """End to end on this line's own copy: a staged box with one channel conf gets that
    conf rewritten, the trusted fingerprint installed, and exit 0.
    """
    box = tmp_path / "box"
    repos = box / "repos"
    repos.mkdir(parents=True)
    (box / "product_label").write_text("pfSense\n", encoding="utf-8")
    (box / "version").write_text("2.8.1\n", encoding="utf-8")
    conf = repos / f"pfblockerng-{channel}.conf"
    conf.write_text("# stub pending\n", encoding="utf-8")

    absent = str(repos / ".no-such-conf")
    env = {
        **os.environ,
        "PFB_STABLE_CONF": absent,
        "PFB_TESTING_CONF": absent,
        "PFB_EDGE_CONF": absent,
        "PFB_NIGHTLY_CONF": absent,
        f"PFB_{channel.upper()}_CONF": str(conf),
        "PFB_PRODUCT_LABEL": str(box / "product_label"),
        "PFB_VERSION_FILE": str(box / "version"),
        "PFB_FINGERPRINT_DIR": str(box / "fingerprints" / "pfblockerng"),
        "PFB_CONFIG_XML": str(box / "config.xml"),
        "PFB_LOGIN_CONF": str(box / "login.conf"),
    }
    proc = subprocess.run(["sh", str(_HOOK), "onestart"], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr

    written = conf.read_text(encoding="utf-8")
    assert f"pfblockerng-{channel}: {{" in written, written
    assert 'url: "http://pkg.pfblockerng.com/' + channel + "/ce-2.8\"" in written, written
    assert "signature_type: fingerprints," in written, written
    trusted = box / "fingerprints" / "pfblockerng" / "trusted" / "pkg.pfblockerng.com"
    assert trusted.is_file(), f"no trusted fingerprint installed:\n{proc.stderr}"


def test_the_software_page_still_addresses_the_on_box_path() -> None:
    """The port installs to PREFIX/etc/rc.d; this line's PHP addresses the same path."""
    inc = _SOFTWARE_INC.read_text(encoding="utf-8")
    assert "'/usr/local/etc/rc.d/pfblockerng_repo_generate.sh'" in inc
