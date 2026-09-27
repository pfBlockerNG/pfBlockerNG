"""Live proof: built-in DNSBL blocks inherit the global response mechanism.

Issues #3291 / #3332: TLD Allow, All-IDN, user-regex (and ABP feed-regex, not
exercised here — same code path as user-regex) and TLD Blacklist blocks used to
hardcode ``log_type = "1"`` (VIP+log) in ``pfb_unbound.py``, ignoring the
operator's configured DNSBL Logging/Blocking mechanism (``dnsbl/global_log``).
They now read ``cfg["builtin_log_flag"]`` — the SAME flag
``pfb_dnsbl_mechanism_flag()`` computes for ordinary per-list blocks — carried
manifest -> ``BuildResult`` -> ``Snapshot`` -> ``_evaluate_cfg``.

This module drives the shared mechanism through all four concrete values
(``enabled``/``disabled_log``/``nxdomain_log``/``nodata_log``) and asserts every
built-in tracks it, on a REAL pfSense VM. TLD Allow gets its own test
(``test_dnsbl_builtin_mechanism_tld_allow``): its synthetic block fires for
EVERY name whose TLD is not in the allow list, so combining it with the other
built-ins in one config write would make it double-block the TLD Blacklist
probe (different mechanism, same response shape — a confound, not a bug) rather
than proving each built-in independently.
"""

from __future__ import annotations

import contextlib
import os
import re
import uuid
from collections.abc import Iterator

import pytest

from tests.test_issue3222_soa_wire import rr_has_type

from . import helpers as h
from .conftest import SmokeVM
from .test_smoke_matrix import _header_counts, _raw_dig, _raw_drill
from .test_smoke_matrix import deployed_vm as deployed_vm


@contextlib.contextmanager
def _hermetic_probe() -> Iterator[None]:
    """Bracket a DNS probe with the egress block (mirrors CaseContext's gate)."""
    if os.environ.get("SMOKE_HERMETIC_PROBE", "1") != "0":
        h.block_egress()
    try:
        yield
    finally:
        h.unblock_egress()


def _assert_nodata_soa(client_vm: SmokeVM, vm: SmokeVM, domain: str, *, context: str) -> None:
    """NOERROR + ANSWER=0 + AUTHORITY=1 (a synthetic SOA) on BOTH the LAN and
    on-box paths — the NODATA/NODATA_LOG block shape (issue #3243), here reached
    via a built-in (flag '5') rather than a per-list ``logging``."""
    for raw in (_raw_dig(client_vm, domain, "A"), _raw_drill(vm, domain, "A")):
        assert "NOERROR" in raw, f"{context}: {domain} expected NOERROR NODATA, got:\n{raw}"
        answers, authority, _ = _header_counts(raw)
        assert (answers, authority) == (0, 1), (
            f"{context}: {domain} expected ANSWER=0 AUTHORITY=1 (SOA), got ANSWER={answers} AUTHORITY={authority}:\n"
            f"{raw}"
        )
        assert rr_has_type(raw, "SOA"), f"{context}: {domain} expected an authority SOA:\n{raw}"


def _builtin_group_php(*, aliasname: str, header: str, url: str) -> str:
    """An inert, ``logging='default'`` DNSBL list-group — DNSBL needs at least one
    group to build at all, but this module's assertions are all about BUILT-IN
    blocks (TLD Allow/IDN/regex/TLD Blacklist), which have no group of their own."""
    row = h._php_kv_array({"header": header, "url": url, "state": "Enabled", "format": "auto"})
    return (
        f"array('aliasname' => {h._php_str(aliasname)}, 'action' => 'unbound', 'cron' => 'EveryDay', "
        f"'order' => 'default', 'logging' => {h._php_str('default')}, 'row' => array({row}))"
    )


def _write_builtin_config(
    vm: SmokeVM,
    *,
    group: tuple[str, str, str],
    regex_patterns: list[str],
    tld_blacklist: str,
    global_log_mode: str,
    global_log: str,
    timeout: float = 90.0,
) -> None:
    """One-shot write: the inert group, EVERY built-in this module exercises
    (user regex, All-IDN, TLD Blacklist, HSTS), and the shared policy fields.

    Mirrors ``test_smoke_dnsbl_policy_default_override._write_policy_config``'s
    shape (a raw ``config_set_path`` write — ``inject()`` hardcodes
    ``global_log_mode='default'``/``global_log='disabled_log'``
    (``helpers._dnsbl_mode_settings``), which would defeat the whole point of
    driving the shared mechanism through its four values).
    """
    alias, hdr, url = group
    settings = {
        "global_log_mode": global_log_mode,
        "global_log": global_log,
        "pfb_dnsbl": "on",
        "pfb_regex": "on",
        "pfb_regex_list": h._b64_textarea(regex_patterns),
        "pfb_idn": "on",  # PfbIdnMode::All backing value; the 4.0.0-alpha 'all' token was dropped
        "tld_wildcard": "on",
        "tld_wildcard_blacklist": h._b64_textarea([tld_blacklist]),
        "pfb_hsts": "on",
    }
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"{h._dnsbl_settings_replace_php(settings)}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, "
        f"array({_builtin_group_php(aliasname=alias, header=hdr, url=url)}));\n"
        "write_config('pfBlockerNG smoke: issue-3291/3332 builtin mechanism config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_builtin_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _write_tld_allow_config(
    vm: SmokeVM,
    *,
    group: tuple[str, str, str],
    global_log_mode: str,
    global_log: str,
    timeout: float = 90.0,
) -> None:
    """One-shot write for the TLD Allow test: the inert group + TLD Allow (only
    ``com`` in the gTLD allow-list) + the shared policy fields — nothing else."""
    alias, hdr, url = group
    settings = {
        "global_log_mode": global_log_mode,
        "global_log": global_log,
        "pfb_dnsbl": "on",
        "tld_allow": "on",
        "tld_allow_gtld": "com",
    }
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"{h._dnsbl_settings_replace_php(settings)}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, "
        f"array({_builtin_group_php(aliasname=alias, header=hdr, url=url)}));\n"
        "write_config('pfBlockerNG smoke: issue-3291 TLD Allow builtin mechanism config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_write_tld_allow_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _set_global_mechanism(vm: SmokeVM, *, mode: str, mechanism: str, timeout: float = 60.0) -> None:
    """Flip ONLY the shared policy fields (mode + mechanism) — every built-in
    toggle written by :func:`_write_builtin_config`/:func:`_write_tld_allow_config`
    is left untouched (a read-modify-write merge, mirrors
    ``test_smoke_dnsbl_policy_default_override._set_global_policy``)."""
    snippet = (
        f"$s = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        f"$s['global_log_mode'] = {h._php_str(mode)};\n"
        f"$s['global_log'] = {h._php_str(mechanism)};\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $s);\n"
        "write_config('pfBlockerNG smoke: issue-3291/3332 global mechanism transition');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_global_mechanism failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _tld_label(prefix: str) -> str:
    """A synthetic, unique top-level label. Not RFC 6761 (``test``/``example``/
    ``invalid``/``localhost``/``onion``/``home.arpa``) and not a real registered
    TLD (a fresh uuid4 hex suffix collides with nothing) — so Unbound's built-in
    ``local-zone``s cannot shadow it before DNSBL. Confirmed live: if it were
    shadowed, phase 1 below (expects VIP) would observe Unbound's own NXDOMAIN/
    NODATA instead and fail loudly, rather than silently passing for the wrong
    reason."""
    return f"{prefix}{uuid.uuid4().hex}"


# --------------------------------------------------------------------------- #
# 1) User regex / All-IDN / TLD Blacklist — driven through all four mechanisms
# --------------------------------------------------------------------------- #


@pytest.mark.smoke
@pytest.mark.timeout(600)  # 4 restart-class updatednsbl reloads + ~30 probes (3 built-ins x 4 phases + 2 HSTS rows).
def test_dnsbl_builtin_mechanism_regex_idn_tld_blacklist(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Issues #3291/#3332 end-to-end: user-regex, All-IDN, and TLD Blacklist
    blocks all track the shared DNSBL mechanism, across its four concrete
    values, exactly like an ordinary per-list block would.

    Phase 1 (``enabled``, flag '1'): every built-in -> VIP. The HSTS-preload
      regex-blocked name is forced to NULL (HSTS converts VIP only).
    Phase 2 (``disabled_log``, flag '0'): every built-in -> NULL.
    Phase 3 (``nxdomain_log``, flag '3'): every built-in -> NXDOMAIN, no
      records. The HSTS-preload name is STILL NXDOMAIN — HSTS never turns an
      NXDOMAIN block into an address (the override only fires for flag '1').
    Phase 4 (``nodata_log``, flag '5'): every built-in -> NOERROR ANSWER=0
      AUTHORITY=1 SOA.
    """
    regex_domain = h.unique_domain("bir")
    regex_label = regex_domain.split(".", 1)[0]
    hsts_domain = h.unique_domain("birhsts")
    hsts_label = hsts_domain.split(".", 1)[0]
    idn_domain = f"xn--{uuid.uuid4().hex}.com"
    blacklist_tld = _tld_label("pfbsmoketld")
    blacklist_domain = f"pfbtld-{uuid.uuid4().hex}.{blacklist_tld}"
    inert_alias = "smokebuiltininert"
    inert_feed = h.write_local_feed(deployed_vm, "smoke_builtin_inert.txt", f"{h.unique_domain('builtininert')}\n")

    # regex anchors on the unique label (not the bare full-domain string) so this
    # is a genuine regex match, not a literal-string comparison in disguise.
    regex_patterns = [f"^{re.escape(regex_label)}\\.", f"^{re.escape(hsts_label)}\\."]

    h.add_hsts_name(deployed_vm, hsts_domain)

    try:
        _write_builtin_config(
            deployed_vm,
            group=(inert_alias, inert_alias, inert_feed),
            regex_patterns=regex_patterns,
            tld_blacklist=blacklist_tld,
            global_log_mode="default",
            global_log="enabled",
        )
        # Verify the key semantics this module relies on before trusting the DNS
        # shape below to attribute a failure correctly.
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_regex") == "on"
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_idn") == "on"
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/tld_wildcard") == "on"
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_hsts") == "on"
        h.reload(deployed_vm, "updatednsbl")
        h.assert_hsts_loaded(deployed_vm, hsts_domain)

        # ---- Phase 1: enabled (flag '1') -> VIP; HSTS regex name -> NULL ----
        with _hermetic_probe():
            for name, domain in (("regex", regex_domain), ("all-idn", idn_domain), ("tld-blacklist", blacklist_domain)):
                a = h.dns_probe_client(client_vm, domain, "A")
                assert h.is_vip(a), f"phase1 ({name}): expected VIP (flag '1'), got {a} for {domain}"
            hsts_a = h.dns_probe_client(client_vm, hsts_domain, "A")
            assert h.is_null_ip(hsts_a), f"phase1 (hsts regex): expected NULL (HSTS forces VIP->NULL), got {hsts_a}"
            hsts_aaaa = h.dns_probe_client(client_vm, hsts_domain, "AAAA")
            assert h.is_null_ip(hsts_aaaa, null_ip="::0"), f"phase1 (hsts regex) AAAA: expected ::0, got {hsts_aaaa}"

        # ---- Phase 2: disabled_log (flag '0') -> NULL. Swap-freshness observation ----
        # (not asserted either way — the answer change below is the load-bearing proof).
        pid_before = h.unbound_pid(deployed_vm)
        _set_global_mechanism(deployed_vm, mode="default", mechanism="disabled_log")
        h.reload(deployed_vm, "updatednsbl")
        pid_after = h.unbound_pid(deployed_vm)
        print(
            f"[issue-3291 swap freshness] Unbound pid before={pid_before} after={pid_after} "
            f"(restarted={pid_before != pid_after}) across a mechanism-only reload"
        )
        with _hermetic_probe():
            for name, domain in (("regex", regex_domain), ("all-idn", idn_domain), ("tld-blacklist", blacklist_domain)):
                a = h.dns_probe_client(client_vm, domain, "A")
                assert h.is_null_ip(a), f"phase2 ({name}): expected NULL (flag '0'), got {a} for {domain}"
                aaaa = h.dns_probe_client(client_vm, domain, "AAAA")
                assert h.is_null_ip(aaaa, null_ip="::0"), f"phase2 ({name}) AAAA: expected ::0, got {aaaa}"

        # ---- Phase 3: nxdomain_log (flag '3') -> NXDOMAIN, even for the HSTS name ----
        _set_global_mechanism(deployed_vm, mode="default", mechanism="nxdomain_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            for name, domain in (
                ("regex", regex_domain),
                ("all-idn", idn_domain),
                ("tld-blacklist", blacklist_domain),
                ("hsts regex", hsts_domain),
            ):
                a = h.dns_probe_client(client_vm, domain, "A")
                assert h.is_nxdomain(a), f"phase3 ({name}): expected NXDOMAIN (flag '3'), got {a} for {domain}"
                assert not h.is_vip(a) and not h.is_null_ip(a), (
                    f"phase3 ({name}): must be a bare NXDOMAIN, not VIP/NULL: {a}"
                )

        # ---- Phase 4: nodata_log (flag '5') -> NOERROR ANSWER=0 AUTHORITY=1 SOA ----
        _set_global_mechanism(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            for name, domain in (("regex", regex_domain), ("all-idn", idn_domain), ("tld-blacklist", blacklist_domain)):
                _assert_nodata_soa(client_vm, deployed_vm, domain, context=f"phase4 ({name})")
    finally:
        h.reset(deployed_vm)


# --------------------------------------------------------------------------- #
# 2) TLD Allow — its own test (see module docstring for why it can't share the
#    settings write above)
# --------------------------------------------------------------------------- #


@pytest.mark.smoke
@pytest.mark.timeout(300)  # 4 restart-class updatednsbl reloads + 1 built-in x 4 phases (up to 2 probes each).
def test_dnsbl_builtin_mechanism_tld_allow(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Issue #3291: TLD Allow's synthetic block also tracks the shared mechanism.

    TLD Allow is configured to allow ONLY ``com`` (gTLD list); a query for a
    ``.net`` name (not on the allow list) is blocked by the synthetic
    ``TLD_Allow`` entry, which — before #3291 — always answered VIP regardless
    of the operator's configured mechanism.
    """
    allow_domain = f"pfballow-{uuid.uuid4().hex}.net"
    inert_alias = "smoketldallowinert"
    inert_feed = h.write_local_feed(deployed_vm, "smoke_tld_allow_inert.txt", f"{h.unique_domain('tldallowinert')}\n")

    try:
        _write_tld_allow_config(
            deployed_vm,
            group=(inert_alias, inert_alias, inert_feed),
            global_log_mode="default",
            global_log="enabled",
        )
        # Verify the key semantics this test relies on: 'tld_allow' + the gTLD
        # list are the ONLY fields that arm _tld_allow_blocks (pfb_unbound.py).
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/tld_allow") == "on"
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/tld_allow_gtld") == "com"
        h.reload(deployed_vm, "updatednsbl")

        with _hermetic_probe():
            a = h.dns_probe_client(client_vm, allow_domain, "A")
            assert h.is_vip(a), f"phase1 (tld-allow): expected VIP (flag '1'), got {a} for {allow_domain}"

        _set_global_mechanism(deployed_vm, mode="default", mechanism="disabled_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            a = h.dns_probe_client(client_vm, allow_domain, "A")
            assert h.is_null_ip(a), f"phase2 (tld-allow): expected NULL (flag '0'), got {a} for {allow_domain}"
            aaaa = h.dns_probe_client(client_vm, allow_domain, "AAAA")
            assert h.is_null_ip(aaaa, null_ip="::0"), f"phase2 (tld-allow) AAAA: expected ::0, got {aaaa}"

        _set_global_mechanism(deployed_vm, mode="default", mechanism="nxdomain_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            a = h.dns_probe_client(client_vm, allow_domain, "A")
            assert h.is_nxdomain(a), f"phase3 (tld-allow): expected NXDOMAIN (flag '3'), got {a} for {allow_domain}"
            assert not h.is_vip(a) and not h.is_null_ip(a), (
                f"phase3 (tld-allow): must be a bare NXDOMAIN, not VIP/NULL: {a}"
            )

        _set_global_mechanism(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_nodata_soa(client_vm, deployed_vm, allow_domain, context="phase4 (tld-allow)")
    finally:
        h.reset(deployed_vm)
