"""Live DNSBL policy transitions and install-time migration preservation."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.test_issue3222_soa_wire import rr_has_type

from . import helpers as h
from .conftest import SmokeVM
from .test_repo_install import pkg_delete, pkg_installed_version, read_compact_version
from .test_smoke_matrix import _header_counts, _raw_dig, _raw_drill
from .test_smoke_matrix import deployed_vm as deployed_vm


@contextlib.contextmanager
def _hermetic_probe() -> Iterator[None]:
    """Bracket a DNS probe with the egress block (CaseContext's exact gate).

    Blocked/nulled/NODATA is asserted with NO upstream reachable, so a
    would-be false-green ("secretly resolved upstream") cannot occur; the
    escape hatch (``SMOKE_HERMETIC_PROBE=0``) mirrors CaseContext for local
    bisection.
    """
    if os.environ.get("SMOKE_HERMETIC_PROBE", "1") != "0":
        h.block_egress()
    try:
        yield
    finally:
        h.unblock_egress()


def _assert_nodata_soa(client_vm: SmokeVM, vm: SmokeVM, domain: str, *, context: str) -> None:
    """NOERROR + ANSWER=0 + AUTHORITY=1 (a synthetic SOA) on BOTH the LAN and
    on-box paths — the NODATA/NODATA_LOG block shape (issue #3243)."""
    for raw in (_raw_dig(client_vm, domain, "A"), _raw_drill(vm, domain, "A")):
        assert "NOERROR" in raw, f"{context}: {domain} expected NOERROR NODATA, got:\n{raw}"
        answers, authority, _ = _header_counts(raw)
        assert (answers, authority) == (0, 1), (
            f"{context}: {domain} expected ANSWER=0 AUTHORITY=1 (SOA), got ANSWER={answers} AUTHORITY={authority}:\n"
            f"{raw}"
        )
        assert rr_has_type(raw, "SOA"), f"{context}: {domain} expected an authority SOA:\n{raw}"


# --------------------------------------------------------------------------- #
# Raw multi-group injection — 'default' group logging and dnsbl/global_log_mode
# are not yet in helpers.DnsblMode/inject_dnsbl_lists' vocabulary (issue #3288
# is the feature that adds them); write the future schema directly.
# --------------------------------------------------------------------------- #


def _group_php(*, aliasname: str, header: str, url: str, logging: str) -> str:
    row = h._php_kv_array({"header": header, "url": url, "state": "Enabled", "format": "auto"})
    return (
        f"array('aliasname' => {h._php_str(aliasname)}, 'action' => 'unbound', 'cron' => 'EveryDay', "
        f"'order' => 'default', 'logging' => {h._php_str(logging)}, 'row' => array({row}))"
    )


def _write_policy_config(
    vm: SmokeVM,
    *,
    default_group: tuple[str, str, str],
    vip_group: tuple[str, str, str, str],
    global_log_mode: str,
    global_log: str,
    timeout: float = 90.0,
) -> None:
    """One-shot write: TWO DNSBL groups (one ``logging='default'``, one an
    explicit concrete choice) plus the shared policy fields — ``inject()``/
    ``inject_dnsbl_lists()`` cannot express either (see module docstring).

    ``default_group`` is ``(aliasname, header, url)``; its stored logging is
    always the literal ``'default'`` token. ``vip_group`` is
    ``(aliasname, header, url, logging)`` — an explicit concrete choice.
    """
    def_alias, def_hdr, def_url = default_group
    vip_alias, vip_hdr, vip_url, vip_logging = vip_group
    groups_php = ", ".join(
        [
            _group_php(aliasname=def_alias, header=def_hdr, url=def_url, logging="default"),
            _group_php(aliasname=vip_alias, header=vip_hdr, url=vip_url, logging=vip_logging),
        ]
    )
    settings = {"global_log_mode": global_log_mode, "global_log": global_log, "pfb_dnsbl": "on"}
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"{h._dnsbl_settings_replace_php(settings)}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, array({groups_php}));\n"
        "write_config('pfBlockerNG smoke: issue-3288 policy default/override');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_policy_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _set_global_policy(vm: SmokeVM, *, mode: str, mechanism: str, timeout: float = 60.0) -> None:
    """Flip ONLY the shared policy fields (mode + mechanism); the two DNSBL
    groups written by :func:`_write_policy_config` are left untouched — this is
    itself part of the proof (a merge, never a groups-root replace)."""
    snippet = (
        f"$s = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        f"$s['global_log_mode'] = {h._php_str(mode)};\n"
        f"$s['global_log'] = {h._php_str(mechanism)};\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $s);\n"
        "write_config('pfBlockerNG smoke: issue-3288 global policy transition');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_global_policy failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


# --------------------------------------------------------------------------- #
# 1) The default/override lifecycle — two groups, four policy phases
# --------------------------------------------------------------------------- #


@pytest.mark.smoke
@pytest.mark.timeout(300)  # FOUR restart-class updatednsbl reloads + 8 probes > the 30s default cap.
def test_dnsbl_policy_default_and_override_lifecycle(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Issue #3288 end-to-end: a ``'default'``-logging group and an explicit
    VIP group, driven through all four required transitions.

    Phase 1 (Default, shared=disabled_log/NULL): the default-logging group
      inherits NULL; the explicit VIP group is untouched (still VIP).
    Phase 2 (Default, shared changed to nodata_log): ONLY the default-logging
      group's answer changes (to NODATA/SOA); the explicit VIP group is
      unaffected by the shared-mechanism change.
    Phase 3 changes only the policy to Override: both groups answer NODATA.
    Phase 4 changes only the policy back to Default: the explicit VIP returns.
    """
    default_domain = h.unique_domain("policydefault")
    vip_domain = h.unique_domain("policyvip")
    default_alias = "smokepolicydef"
    vip_alias = "smokepolicyvip"
    default_feed = h.write_local_feed(deployed_vm, "smoke_policy_default.txt", f"{default_domain}\n")
    vip_feed = h.write_local_feed(deployed_vm, "smoke_policy_vip.txt", f"{vip_domain}\n")

    try:
        # ---- Phase 1: Default policy, shared mechanism = disabled_log (logged NULL) ----
        _write_policy_config(
            deployed_vm,
            default_group=(default_alias, default_alias, default_feed),
            vip_group=(vip_alias, vip_alias, vip_feed, "enabled"),
            global_log_mode="default",
            global_log="disabled_log",
        )
        # Lock in the group-index assumption every later raw config_get below relies on.
        stored_default_alias = h.config_get(deployed_vm, f"{h.CFG_DNSBL_LISTS}/0/aliasname")
        assert stored_default_alias == default_alias, (
            f"group-index assumption broke: index 0 is {stored_default_alias!r}, not {default_alias!r}"
        )
        stored_vip_alias0 = h.config_get(deployed_vm, f"{h.CFG_DNSBL_LISTS}/1/aliasname")
        assert stored_vip_alias0 == vip_alias, (
            f"group-index assumption broke: index 1 is {stored_vip_alias0!r}, not {vip_alias!r}"
        )
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            a1 = h.dns_probe_client(client_vm, default_domain, "A")
            assert h.is_null_ip(a1), f"phase1: 'default' group should inherit NULL (disabled_log), got {a1}"
            a1_aaaa = h.dns_probe_client(client_vm, default_domain, "AAAA")
            assert h.is_null_ip(a1_aaaa, null_ip="::0"), (
                f"phase1: 'default' group AAAA should inherit NULL (disabled_log), got {a1_aaaa}"
            )
            v1 = h.dns_probe_client(client_vm, vip_domain, "A")
            assert h.is_vip(v1), f"phase1: explicit VIP group must resolve VIP regardless of shared NULL, got {v1}"

        # ---- Phase 2: shared mechanism -> logged NODATA; ONLY the 'default' group tracks it ----
        _set_global_policy(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_nodata_soa(client_vm, deployed_vm, default_domain, context="phase2 (default group)")
            v2 = h.dns_probe_client(client_vm, vip_domain, "A")
            assert h.is_vip(v2), f"phase2: a shared-mechanism change must NOT alter the explicit VIP group, got {v2}"

        # Keep the mechanism fixed: this transition must react to the mode alone.
        _set_global_policy(deployed_vm, mode="override", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        # Raw storage proof: override must resolve, never REWRITE, the VIP group's saved choice.
        stored_vip_logging = h.config_get(deployed_vm, f"{h.CFG_DNSBL_LISTS}/1/logging")
        assert stored_vip_logging == "enabled", (
            f"phase3: override must not rewrite the VIP group's stored choice, got {stored_vip_logging!r}"
        )
        with _hermetic_probe():
            _assert_nodata_soa(client_vm, deployed_vm, default_domain, context="phase3 (default group)")
            _assert_nodata_soa(client_vm, deployed_vm, vip_domain, context="phase3 (overridden VIP group)")

        _set_global_policy(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        stored_default_logging = h.config_get(deployed_vm, f"{h.CFG_DNSBL_LISTS}/0/logging")
        assert stored_default_logging == "default", (
            f"phase4: the default-logging group's raw stored token must stay 'default' through every "
            f"transition (reload never persists a resolved value back), got {stored_default_logging!r}"
        )
        with _hermetic_probe():
            _assert_nodata_soa(client_vm, deployed_vm, default_domain, context="phase4 (default group)")
            v4 = h.dns_probe_client(client_vm, vip_domain, "A")
            assert h.is_vip(v4), f"phase4: returning to Default must restore the VIP group's PRESERVED choice, got {v4}"
    finally:
        h.reset(deployed_vm)


_POLICY_MIGRATION_ALIAS = "smokepolicymig"


def _seed_pre_migration_config(
    vm: SmokeVM, *, global_log: str | None, group_logging: str, missing_settings: bool
) -> None:
    """Write a legacy policy while the package is absent."""
    group = _group_php(
        aliasname=_POLICY_MIGRATION_ALIAS,
        header=_POLICY_MIGRATION_ALIAS,
        url=f"{h.PFB_DBDIR}/smoke_policy_migration_unread.txt",
        logging=group_logging,
    )
    if missing_settings:
        settings_php = f"config_del_path({h._php_str(h.CFG_DNSBL_SETTINGS)});\n"
    else:
        global_php = (
            "unset($s['global_log']);" if global_log is None else f"$s['global_log'] = {h._php_str(global_log)};"
        )
        settings_php = (
            f"$s = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
            "unset($s['global_log_mode']);\n"
            "$s['pfb_dnsbl'] = '';\n"
            f"{global_php}\n"
            f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $s);\n"
        )
    result = h.php_eval(
        vm,
        settings_php
        + f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, array({group}));\n"
        + "write_config('pfBlockerNG smoke: seed legacy mechanism policy'); echo 'OK';",
        timeout=60.0,
    )
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"legacy policy seed failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
    )


def _cleanup_policy_migration_config(vm: SmokeVM) -> None:
    snippet = (
        f"config_del_path({h._php_str(h.CFG_DNSBL_LISTS)});\n"
        f"$s = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        "unset($s['global_log'], $s['global_log_mode']);\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $s);\n"
        "write_config('pfBlockerNG issue-3288 smoke: cleanup migration config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_cleanup_policy_migration_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


@pytest.mark.smoke
@pytest.mark.timeout(600)
@pytest.mark.parametrize(
    "global_log,group_logging,missing_settings,expected_mode,expected_group",
    [
        ("enabled", "disabled", False, "override", "disabled"),
        ("", "enabled", False, "default", "default"),
        (None, "enabled", False, "default", "default"),
        (None, "enabled", True, "default", "default"),
    ],
    ids=["active-override", "no-override-empty", "no-override-absent", "groups-without-settings"],
)
def test_dnsbl_policy_install_preserves_legacy_mechanisms(
    smoke_vm: SmokeVM,
    global_log: str | None,
    group_logging: str,
    missing_settings: bool,
    expected_mode: str,
    expected_group: str,
) -> None:
    """The actual installer converts VIP groups without losing overrides or VIP defaults."""
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG must name the branch package"
    try:
        pkg_delete(smoke_vm)
        assert pkg_installed_version(smoke_vm) is None, "package must be absent before legacy seeding"
        _seed_pre_migration_config(
            smoke_vm, global_log=global_log, group_logging=group_logging, missing_settings=missing_settings
        )
        expected_global_state = (global_log is not None, global_log or "")
        assert h.config_get_state(smoke_vm, f"{h.CFG_DNSBL_SETTINGS}/global_log") == expected_global_state
        assert h.config_get_state(smoke_vm, f"{h.CFG_DNSBL_SETTINGS}/global_log_mode") == (False, "")
        assert h.config_get(smoke_vm, f"{h.CFG_DNSBL_LISTS}/0/logging") == group_logging

        h.deploy(smoke_vm, pkg)
        assert pkg_installed_version(smoke_vm) == read_compact_version(Path(pkg))

        actual = (
            h.config_get(smoke_vm, f"{h.CFG_DNSBL_SETTINGS}/global_log_mode"),
            h.config_get(smoke_vm, f"{h.CFG_DNSBL_SETTINGS}/global_log"),
            h.config_get(smoke_vm, f"{h.CFG_DNSBL_LISTS}/0/logging"),
        )
        assert actual == (expected_mode, "enabled", expected_group), (
            f"installer lost the legacy mechanism: expected {(expected_mode, 'enabled', expected_group)!r}, "
            f"got {actual!r}"
        )
    finally:
        pkg_delete(smoke_vm)
        _cleanup_policy_migration_config(smoke_vm)
