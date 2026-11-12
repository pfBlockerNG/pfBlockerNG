"""DNSBL chroot teardown stays wired to the shell's single source of truth.

`dnsbl_cache stage` owns ``PFB_PY_SHIPPED`` and both PHP consumers must invoke
`dnsbl_cache teardown`; the shell operation derives the static set, including
the same-basename PSL authority. No PHP teardown block may duplicate those basenames.
"""

from __future__ import annotations

import re
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng"
SHELL = PKG_DIR / "pfblockerng.sh"
INC = PKG_DIR / "pfblockerng.inc"

PSL_AUTHORITY_FILE = "dnsbl_psl"


def _shipped_files() -> list[str]:
    """The basenames in pfblockerng.sh's PFB_PY_SHIPPED -- the single source of the
    shipped (static) DNSBL python file set."""
    match = re.search(r"^\s*PFB_PY_SHIPPED='([^']*)'", SHELL.read_text(), re.MULTILINE)
    assert match is not None, "PFB_PY_SHIPPED assignment not found in pfblockerng.sh"
    files = match.group(1).split()
    assert files, "PFB_PY_SHIPPED parsed as empty -- the parser, not the code, is wrong"
    return files


def test_both_chroot_teardown_consumers_call_the_derived_shell_operation() -> None:
    source = INC.read_text()
    teardown_call = "exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache teardown >/dev/null 2>&1');"
    assert source.count(teardown_call) == 2
    assert not re.search(
        r"""unlink_if_exists\("\{\$g\['unbound_chroot_path'\]\}/pfb_[^"]+"\)""",
        source,
    )


def test_teardown_derivation_includes_the_psl_authority() -> None:
    source = SHELL.read_text()
    assert "for _f in ${PFB_PY_SHIPPED}; do" in source
    assert PSL_AUTHORITY_FILE in _shipped_files()
    assert '"${pfbchroot}/pfb_py_tld.txt"' not in source


RETIRED_CHROOT_FILES = [
    "pfb_unbound.py",
    "pfb_unbound_include.inc",
    "pfb_py_module.applied",
    "pfb_dnsbl_regex_rules.py",
    "pfb_python.sh",
]


def test_the_retired_chroot_files_are_cleaned_and_no_longer_staged() -> None:
    """#3791: `pfb_unbound.py` left the package and took with it its only chroot consumers' reasons to exist:
    its code fingerprint (`pfb_py_module.applied`), the regex rules it imported and the wrapper that launched it.
    The save-time probe and every other consumer run the host copies from `/usr/local`. An upgraded box still has
    the old chroot copies (and the fingerprint matches the `pfb_py_*` archive glob), which `dnsbl_cache stage` and
    `teardown` remove through `PFB_PY_RETIRED`."""
    source = SHELL.read_text()
    match = re.search(r"^\s*PFB_PY_RETIRED='([^']*)'", source, re.MULTILINE)
    assert match is not None, "PFB_PY_RETIRED assignment not found in pfblockerng.sh"
    assert match.group(1).split() == RETIRED_CHROOT_FILES
    shipped = _shipped_files()
    assert not set(RETIRED_CHROOT_FILES) & set(shipped), shipped


def test_the_shipped_set_actually_reaches_the_parity_check() -> None:
    """Guard against the check above passing vacuously: the shipped set must be
    non-trivial and must really contain the upstream observer, the one script Unbound still loads."""
    shipped = _shipped_files()
    assert "pfb_upstream_observer.py" in shipped
    assert len(shipped) >= 3, shipped
