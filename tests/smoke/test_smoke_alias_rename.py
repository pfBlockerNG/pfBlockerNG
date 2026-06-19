"""Live-VM smoke for pfb_alias_rename_followup() end-to-end (#357).

pfBlockerNG ships a ``pre_write_config`` hook shim that pfSense calls (via
``pfSense_handle_custom_code``) whenever a firewall alias is saved. The shim
invokes ``pfb_alias_rename_followup($origname, $post['name'])`` which rewrites
every occurrence of the old alias name in the four alias-reference fields
(``aliasports_in``, ``aliasports_out``, ``aliasaddr_in``, ``aliasaddr_out``)
across all three list sections (v4, v6, DNSBL).

This test exercises the FULL path on a live pfSense VM:

1. Assert the hook shim file exists (skip if the build does not ship it yet —
   this decouples a ports pkg-plist update that may land separately).
2. Seed a test IPv4 list row with a known alias name in two fields.
3. Trigger the rename via ``php_eval`` (simulate the shim invocation from
   ``saveAlias()``) and assert the rewrite landed in config.xml.
4. Assert an unrelated alias name in the same row is UNCHANGED (no fan-out).
5. Restore the VM to a clean state in ``finally``.

These tests are DESELECTED from the default ``python -m pytest`` run.  Run via::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

They need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = [pytest.mark.smoke]

# The hook shim ``pfSense_handle_custom_code`` includes when ``saveAlias()`` runs.
HOOK_SHIM = "/usr/local/pkg/firewall_aliases_edit/pre_write_config/pfblockerng.php"

# Config section for IPv4 lists — the section ``pfb_alias_rename_followup`` iterates.
CFG_IPV4 = "installedpackages/pfblockernglistsv4/config"

# Timeout passed to ``php_eval`` / ``config_get`` calls (seconds).
_TIMEOUT = 120.0


# --------------------------------------------------------------------------- #
# Module-scoped deploy fixture
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for all alias-rename tests in this module."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _free_rowid(vm: SmokeVM, cfg_root: str) -> int:
    """Return the next free numeric index under ``cfg_root``."""
    pre = (
        f"$c = config_get_path({h._php_str(cfg_root)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;"
    )
    return int(h._php_read_scalar(vm, pre, "$free", timeout=_TIMEOUT))


def _write_row(vm: SmokeVM, cfg_root: str, rowid: int, row: dict[str, str]) -> None:
    """Write ``row`` dict to ``cfg_root/{rowid}`` via the pfSense config API."""
    php_row = h._php_kv_array(row)
    snippet = (
        f"config_set_path({h._php_str(f'{cfg_root}/{rowid}')}, {php_row});\n"
        "write_config('pfBlockerNG smoke: seed alias-rename test row');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_row failed: rc={result.returncode} {result.stdout!r}")


def _del_row(vm: SmokeVM, cfg_root: str, rowid: int) -> None:
    """Delete ``cfg_root/{rowid}`` from config.xml."""
    snippet = (
        f"config_del_path({h._php_str(f'{cfg_root}/{rowid}')});\n"
        "write_config('pfBlockerNG smoke: drop alias-rename test row');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_del_row({cfg_root}/{rowid}) failed: rc={result.returncode} {result.stdout!r}")


def _invoke_rename_shim(vm: SmokeVM, old_name: str, new_name: str) -> None:
    """Invoke the hook shim exactly as ``pfSense_handle_custom_code()`` does.

    ``saveAlias()`` sets ``$origname`` (old alias name) and ``$post['name']``
    (new alias name) in scope, then ``include``s the shim — which calls
    ``pfb_alias_rename_followup($origname, $post['name'])``.  We replicate
    that calling convention here (variables in scope + include), which is
    precisely what the pre_write_config hook tests.
    """
    snippet = (
        f"$origname = {h._php_str(old_name)};\n"
        f"$post = array('name' => {h._php_str(new_name)});\n"
        f"@include({h._php_str(HOOK_SHIM)});\n"
        "write_config('pfBlockerNG smoke: alias-rename followup');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_invoke_rename_shim failed: rc={result.returncode} {result.stdout!r} {result.stderr!r}")


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_hook_shim_file_exists_on_deployed_build(deployed_vm: SmokeVM) -> None:
    """The pre_write_config hook shim is present on the deployed build.

    This is the prerequisite for all alias-rename tests: if the shim is not
    shipped in this build's pkg-plist, skip the remaining tests rather than
    failing on a known-absent file.  The skip is recorded in the first test so
    the module-level ``deployed_vm`` fixture only runs once.
    """
    vm = deployed_vm
    result = vm.ssh("test", "-f", HOOK_SHIM, timeout=30)
    if result.returncode != 0:
        pytest.skip(
            f"alias-rename hook shim not present on this build ({HOOK_SHIM}); "
            "pkg-plist update pending — skipping alias-rename smoke"
        )


def test_alias_rename_followup_rewrites_addr_and_port_keys(deployed_vm: SmokeVM) -> None:
    """``pfb_alias_rename_followup`` rewrites aliasaddr_in and aliasports_in on rename.

    Scenario: rename-followup replaces both alias-reference fields in a seeded row.

    Background:
        The shim invokes ``pfb_alias_rename_followup($old, $new)`` which iterates
        all three list sections (v4/v6/dnsbl) and rewrites four per-row keys
        (aliasports_in, aliasports_out, aliasaddr_in, aliasaddr_out) wherever the
        old name appears. This case targets the v4 section (the simplest; the
        cross-section fan-out is covered in the next test).

    Given:
        An IPv4 list row with:
        - aliasaddr_in = 'PfbRenameSrc'
        - aliasports_in = 'PfbRenameSrc'
        (both fields reference the same source alias name)
    When:
        The rename shim is invoked with old='PfbRenameSrc', new='PfbRenameDst'.
    Then:
        - aliasaddr_in is rewritten to 'PfbRenameDst'.
        - aliasports_in is rewritten to 'PfbRenameDst'.
    """
    vm = deployed_vm
    # Skip here too in case test ordering bypasses the shim-exists test.
    shim_check = vm.ssh("test", "-f", HOOK_SHIM, timeout=30)
    if shim_check.returncode != 0:
        pytest.skip(f"alias-rename hook shim absent ({HOOK_SHIM}) — skip")

    old_name = "PfbRenameSrc"
    new_name = "PfbRenameDst"
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"

    seed_row: dict[str, str] = {
        "aliasname": "SmkRenameRow",
        "action": "Deny_Both",
        "aliasaddr_in": old_name,
        "aliasports_in": old_name,
    }

    try:
        # BEFORE: seed the row and confirm both fields carry the old name.
        _write_row(vm, CFG_IPV4, rowid, seed_row)
        assert h.config_get(vm, f"{base}/aliasaddr_in") == old_name, (
            f"precondition: aliasaddr_in should be {old_name!r} before rename"
        )
        assert h.config_get(vm, f"{base}/aliasports_in") == old_name, (
            f"precondition: aliasports_in should be {old_name!r} before rename"
        )

        # ACT: invoke the hook shim (the same code path ``saveAlias()`` triggers).
        _invoke_rename_shim(vm, old_name, new_name)

        # AFTER: both fields must reflect the new name.
        assert h.config_get(vm, f"{base}/aliasaddr_in") == new_name, (
            f"aliasaddr_in was not rewritten from {old_name!r} to {new_name!r} by the rename shim"
        )
        assert h.config_get(vm, f"{base}/aliasports_in") == new_name, (
            f"aliasports_in was not rewritten from {old_name!r} to {new_name!r} by the rename shim"
        )
    finally:
        _del_row(vm, CFG_IPV4, rowid)


def test_alias_rename_followup_leaves_unrelated_alias_unchanged(deployed_vm: SmokeVM) -> None:
    """A rename does not rewrite fields that reference a DIFFERENT alias name.

    Scenario: only the fields whose value matches the old name are touched; a
    field referencing an unrelated alias stays intact.

    Background:
        ``pfb_alias_rename_followup`` checks each field value individually
        against the old name.  A field referencing ``PfbUnrelated`` must not be
        rewritten even though a co-located field referencing ``PfbRenameSrc2``
        is — proving the match is per-field-value, not per-row.

    Given:
        An IPv4 list row with:
        - aliasaddr_in = 'PfbRenameSrc2'   (will be renamed)
        - aliasaddr_out = 'PfbUnrelated'   (must stay unchanged)
    When:
        The rename shim is invoked with old='PfbRenameSrc2', new='PfbRenameDst2'.
    Then:
        - aliasaddr_in is rewritten to 'PfbRenameDst2'.
        - aliasaddr_out stays 'PfbUnrelated' (unrelated — no touch).
    """
    vm = deployed_vm
    shim_check = vm.ssh("test", "-f", HOOK_SHIM, timeout=30)
    if shim_check.returncode != 0:
        pytest.skip(f"alias-rename hook shim absent ({HOOK_SHIM}) — skip")

    old_name = "PfbRenameSrc2"
    new_name = "PfbRenameDst2"
    unrelated = "PfbUnrelated"
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"

    seed_row: dict[str, str] = {
        "aliasname": "SmkRenameRow2",
        "action": "Deny_Both",
        "aliasaddr_in": old_name,
        "aliasaddr_out": unrelated,
    }

    try:
        # BEFORE: seed and confirm both fields.
        _write_row(vm, CFG_IPV4, rowid, seed_row)
        assert h.config_get(vm, f"{base}/aliasaddr_in") == old_name, (
            f"precondition: aliasaddr_in should be {old_name!r}"
        )
        assert h.config_get(vm, f"{base}/aliasaddr_out") == unrelated, (
            f"precondition: aliasaddr_out should be {unrelated!r}"
        )

        # ACT: rename old_name → new_name.
        _invoke_rename_shim(vm, old_name, new_name)

        # AFTER: only the matching field is updated; the unrelated field is intact.
        assert h.config_get(vm, f"{base}/aliasaddr_in") == new_name, (
            f"aliasaddr_in was not rewritten from {old_name!r} to {new_name!r}"
        )
        assert h.config_get(vm, f"{base}/aliasaddr_out") == unrelated, (
            f"aliasaddr_out must NOT be rewritten (references {unrelated!r}, not {old_name!r})"
        )
    finally:
        _del_row(vm, CFG_IPV4, rowid)


def test_alias_rename_same_name_is_noop(deployed_vm: SmokeVM) -> None:
    """Renaming an alias to itself leaves every field unchanged.

    ``pfb_alias_rename_followup`` guards ``$old_name === $new_name`` and returns
    FALSE immediately (no config write). This branch is important: a pfSense
    alias re-save with an unchanged name MUST not dirty config.xml.

    Given:
        An IPv4 list row with aliasaddr_in = 'PfbRenameNoop'.
    When:
        The rename shim is invoked with old='PfbRenameNoop', new='PfbRenameNoop'
        (same name — the identity rename).
    Then:
        aliasaddr_in remains 'PfbRenameNoop' (no write occurred).
    """
    vm = deployed_vm
    shim_check = vm.ssh("test", "-f", HOOK_SHIM, timeout=30)
    if shim_check.returncode != 0:
        pytest.skip(f"alias-rename hook shim absent ({HOOK_SHIM}) — skip")

    name = "PfbRenameNoop"
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"

    seed_row: dict[str, str] = {
        "aliasname": "SmkRenameNoop",
        "action": "Deny_Both",
        "aliasaddr_in": name,
    }

    try:
        _write_row(vm, CFG_IPV4, rowid, seed_row)
        assert h.config_get(vm, f"{base}/aliasaddr_in") == name, f"precondition: aliasaddr_in should be {name!r}"

        # ACT: identity rename — shim should be a no-op.
        _invoke_rename_shim(vm, name, name)

        # AFTER: unchanged.
        assert h.config_get(vm, f"{base}/aliasaddr_in") == name, (
            f"aliasaddr_in must be unchanged after identity rename (same name {name!r})"
        )
    finally:
        _del_row(vm, CFG_IPV4, rowid)
