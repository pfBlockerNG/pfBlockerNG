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


def test_an_imported_module_is_staged_before_the_file_that_imports_it() -> None:
    """`pfb_unbound.py` imports `pfb_dnsbl_regex_rules` at module scope and
    `dnsbl_cache_stage()` copies `PFB_PY_SHIPPED` in list order, so the dependency has
    to be staged first: a resolver load landing between the two copies would otherwise
    find the importer without its module and die with `ModuleNotFoundError`."""
    shipped = _shipped_files()
    assert shipped.index("pfb_dnsbl_regex_rules.py") < shipped.index("pfb_unbound.py"), shipped


def test_the_shipped_set_actually_reaches_the_parity_check() -> None:
    """Guard against the check above passing vacuously: the shipped set must be
    non-trivial and must really contain the resolver's own entry point."""
    shipped = _shipped_files()
    assert "pfb_unbound.py" in shipped
    assert len(shipped) >= 3, shipped
