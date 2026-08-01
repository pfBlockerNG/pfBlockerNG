"""Every shipped DNSBL Python file staged into Unbound's chroot must also be torn
down when DNSBL Python mode is disabled and when the package is uninstalled.

`dnsbl_cache stage` in pfblockerng.sh owns the shipped-file set as ONE list
(``PFB_PY_SHIPPED``) and pfblockerng.inc's *enable* branch defers to it by shelling
out. The *teardown* side does not: `pfb_unbound_dnsbl()`'s disable branch and
`pfblockerng_php_pre_deinstall_command()` each carry their own hardcoded
`unlink_if_exists()` list, so a newly shipped file is staged into `/var/unbound` by
the single source and then left orphaned there by both teardown paths.

Issue #1765 hit exactly that: `pfb_dnsbl_regex_rules.py` was added to
``PFB_PY_SHIPPED`` and neither teardown list. This pins the invariant until the
teardown lists are derived from the single source too (tracked separately) --
adding a file to ``PFB_PY_SHIPPED`` without updating both lists fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng"
SHELL = PKG_DIR / "pfblockerng.sh"
INC = PKG_DIR / "pfblockerng.inc"

# The TLD-Wildcard oracle is shipped under a DIFFERENT name than its chroot copy
# (issue #1255: source basename 'dnsbl_tld', chroot copy 'pfb_py_tld.txt'), so it is
# deliberately absent from PFB_PY_SHIPPED while still needing teardown. It is listed
# here so the teardown lists can be checked for it too, not just for the shipped set.
NAME_MAPPED_CHROOT_FILES = ("pfb_py_tld.txt",)


def _shipped_files() -> list[str]:
    """The basenames in pfblockerng.sh's PFB_PY_SHIPPED -- the single source of the
    shipped (static) DNSBL python file set."""
    match = re.search(r"^\s*PFB_PY_SHIPPED='([^']*)'", SHELL.read_text(), re.MULTILINE)
    assert match is not None, "PFB_PY_SHIPPED assignment not found in pfblockerng.sh"
    files = match.group(1).split()
    assert files, "PFB_PY_SHIPPED parsed as empty -- the parser, not the code, is wrong"
    return files


def _teardown_blocks() -> dict[str, set[str]]:
    """Every run of consecutive ``unlink_if_exists("{$g['unbound_chroot_path']}/...")``
    calls in pfblockerng.inc, keyed by the line number the run starts at, mapped to the
    set of chroot basenames it removes."""
    source = INC.read_text().splitlines()
    call = re.compile(r"""unlink_if_exists\("\{\$g\['unbound_chroot_path'\]\}/([^"]+)"\)""")
    blocks: dict[str, set[str]] = {}
    current: set[str] = set()
    start = 0
    for number, line in enumerate(source, start=1):
        found = call.search(line)
        if found:
            if not current:
                start = number
            current.add(found.group(1))
        elif current:
            blocks[f"pfblockerng.inc:{start}"] = current
            current = set()
    if current:
        blocks[f"pfblockerng.inc:{start}"] = current
    return blocks


def test_both_chroot_teardown_lists_cover_every_shipped_python_file() -> None:
    blocks = _teardown_blocks()
    # The disable branch of pfb_unbound_dnsbl() and pfblockerng_php_pre_deinstall_command().
    assert len(blocks) == 2, f"expected exactly 2 chroot teardown blocks, found: {sorted(blocks)}"

    expected = set(_shipped_files()) | set(NAME_MAPPED_CHROOT_FILES)
    for location, removed in blocks.items():
        missing = expected - removed
        assert not missing, (
            f"{location}: staged into the chroot but never torn down: {sorted(missing)}. "
            "Add an unlink_if_exists() line for each, or derive the list from PFB_PY_SHIPPED."
        )


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
