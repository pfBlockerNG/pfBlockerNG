"""Live proof: built-in DNSBL blocks inherit the global response mechanism.

Issues #3291 / #3332: TLD Allow, All-IDN, Confusable-IDN, and user-regex blocks
(plus TLD Blacklist, a separate build-time site) used to hardcode
``log_type = "1"`` (VIP+log) in ``pfb_unbound.py``, ignoring the operator's
configured DNSBL Logging/Blocking mechanism (``dnsbl/global_log``). They now
read ``cfg["builtin_log_flag"]`` — the SAME flag ``pfb_dnsbl_mechanism_flag()``
computes for ordinary per-list blocks — carried manifest -> ``BuildResult`` ->
``Snapshot`` -> ``_evaluate_cfg``.

ABP feed-regex (``$important``/``@@``) is deliberately NOT loaded here even
though it reaches the same ``evaluate_domain`` call sites as user-regex: any
ABP grammar flips ``important_rules`` True for the WHOLE snapshot, which
reroutes every row in this module (regex/IDN/TLD Blacklist/TLD Allow) onto the
numeric 6-band re-attribution site (``pfb_unbound.py`` ~6966) instead of the
fast-path site (~6929) this module actually puts under live proof. That numeric
path is already pinned off-appliance by
``TestBuiltinLogFlagCoverageMatrix::test_numeric_reattribution_to_higher_band_regex``;
loading a feed-regex here would silently swap which code path this module
exercises and leave the fast path unprobed live.

This module drives the shared mechanism through all four concrete values
(``enabled``/``disabled_log``/``nxdomain_log``/``nodata_log``) and asserts every
built-in tracks it, on a REAL pfSense VM. Three built-ins get their own test
instead of sharing the main settings write:

* TLD Allow (``test_dnsbl_builtin_mechanism_tld_allow``): its synthetic block
  fires for EVERY name whose TLD is not in the allow list, so combining it
  with the other built-ins would make it double-block the TLD Blacklist probe
  (different mechanism, same response shape — a confound, not a bug).
* Confusable-IDN (``test_dnsbl_builtin_mechanism_confusable_idn``): ``pfb_idn``
  stores exactly ONE ``PfbIdnMode`` token (``'on'`` = All, ``'confusable'`` =
  Confusable, ``''`` = Off — ``pfblockerng_extra.inc``), so All-IDN and
  Confusable cannot coexist in one settings write either.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from tests.test_issue3222_soa_wire import rr_has_type

from . import helpers as h
from .conftest import SmokeVM
from .test_smoke_dnsbl_policy_default_override import _group_php, _hermetic_probe
from .test_smoke_matrix import _header_counts, _raw_dig, _raw_drill
from .test_smoke_matrix import deployed_vm as deployed_vm

# xn--pple-43d = "аpple" (Latin+Cyrillic homograph) — the SAME fixed fixture
# domain test_pfb_unbound.py's TestBuiltinLogFlagCoverageMatrix::test_confusable_idn_block
# and test_adr08_confusable_matcher.py's MALICIOUS_NAME use. Not unique-able like
# unique_domain(): the Confusable analyzer needs this specific mixed-script shape
# to classify as malicious, a random uuid label would not. Safe under the two
# smoke.md domain rules regardless: '.com' is not an RFC 6761 reserved TLD, and
# the punycode label is not a real HSTS-preload host (only literal apple.com is).
CONFUSABLE_MALICIOUS_DOMAIN = "xn--pple-43d.com"


def _nodata_soa_ok(client_vm: SmokeVM, vm: SmokeVM, domain: str) -> tuple[bool, str]:
    """Non-asserting twin of ``test_smoke_dnsbl_policy_default_override._assert_nodata_soa``.

    That helper raises on the first miss; this module collects every row's
    verdict and asserts ONCE per phase (never hiding a later row behind an
    earlier failure), so a per-row check here must return a verdict instead.
    Checks the NOERROR + ANSWER=0 + AUTHORITY=1 SOA shape on BOTH the LAN
    (``dig``) and on-box (``drill``) paths, exactly like the asserting twin.
    """
    for raw, source in ((_raw_dig(client_vm, domain, "A"), "dig/LAN"), (_raw_drill(vm, domain, "A"), "drill/on-box")):
        if "NOERROR" not in raw:
            return False, f"{source}: not NOERROR:\n{raw}"
        answers, authority, _ = _header_counts(raw)
        if (answers, authority) != (0, 1):
            return False, f"{source}: ANSWER={answers} AUTHORITY={authority} (want 0/1):\n{raw}"
        if not rr_has_type(raw, "SOA"):
            return False, f"{source}: no authority SOA in answer:\n{raw}"
    return True, "NODATA+SOA confirmed on both dig/LAN and drill/on-box"


def _probe_row(client_vm: SmokeVM, vm: SmokeVM, domain: str, expected_shape: str) -> tuple[bool, str]:
    """Probe ``domain`` and report whether it matches ``expected_shape``.

    ``expected_shape`` is one of ``"vip"``/``"null"``/``"nxdomain"``/``"nodata"``.
    Returns ``(matched, actual_description)`` — never raises, so callers can
    collect every row's verdict before asserting (issue #3334 review F3).
    """
    if expected_shape == "vip":
        a = h.dns_probe_client(client_vm, domain, "A")
        return h.is_vip(a), str(a)
    if expected_shape == "null":
        a = h.dns_probe_client(client_vm, domain, "A")
        aaaa = h.dns_probe_client(client_vm, domain, "AAAA")
        matched = h.is_null_ip(a) and h.is_null_ip(aaaa, null_ip="::0")
        return matched, f"A={a} AAAA={aaaa}"
    if expected_shape == "nxdomain":
        a = h.dns_probe_client(client_vm, domain, "A")
        aaaa = h.dns_probe_client(client_vm, domain, "AAAA")
        matched = h.is_nxdomain(a) and not h.is_vip(a) and not h.is_null_ip(a) and h.is_nxdomain(aaaa)
        return matched, f"A={a} AAAA={aaaa}"
    if expected_shape == "nodata":
        return _nodata_soa_ok(client_vm, vm, domain)
    raise ValueError(f"unknown expected_shape {expected_shape!r}")


@dataclass
class _Row:
    """One built-in's probe domain, plus any PHASE-NUMBER -> shape overrides.

    The override is for the HSTS row only: it matches the phase's default
    shape everywhere except phase 1, where HSTS forces VIP (flag '1') to NULL.
    """

    name: str
    domain: str
    phase_shape_override: dict[int, str] = field(default_factory=dict)


def _assert_all_rows_match_phase(
    client_vm: SmokeVM,
    vm: SmokeVM,
    rows: Sequence[_Row],
    phase_num: int,
    default_shape: str,
) -> None:
    """Probe EVERY row for this phase and assert ONCE, listing every mismatch.

    issue #3334 review F3: asserting inside the per-row loop let the first
    failing row hide every other row's answer (the RED run only ever showed
    the ``regex`` row). Collecting first means a single RED run's failure
    message enumerates every built-in that is still wrong, not just the first.
    """
    mismatches: list[str] = []
    for row in rows:
        expected = row.phase_shape_override.get(phase_num, default_shape)
        matched, actual = _probe_row(client_vm, vm, row.domain, expected)
        if not matched:
            mismatches.append(f"{row.name}: expected {expected!r}, got: {actual}")
    assert not mismatches, (
        f"phase{phase_num} ({default_shape!r} mechanism) — {len(mismatches)} row(s) mismatched:\n"
        + "\n".join(mismatches)
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
    shape (a raw ``config_set_path`` write — ``inject()`` derives ``global_log``
    from the case's mode (``helpers._dnsbl_mode_settings``), so this module writes
    the policy fields directly to drive all four mechanism values.
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
        f"array({_group_php(aliasname=alias, header=hdr, url=url, logging='default')}));\n"
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
        f"array({_group_php(aliasname=alias, header=hdr, url=url, logging='default')}));\n"
        "write_config('pfBlockerNG smoke: issue-3291 TLD Allow builtin mechanism config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_write_tld_allow_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _write_confusable_config(
    vm: SmokeVM,
    *,
    group: tuple[str, str, str],
    global_log_mode: str,
    global_log: str,
    timeout: float = 90.0,
) -> None:
    """One-shot write for the Confusable-IDN test: the inert group + Confusable
    mode (with malicious-block on) + the shared policy fields — nothing else.

    ``pfb_idn`` = ``'confusable'`` (``PfbIdnMode::Confusable``'s backing value,
    ``pfblockerng_extra.inc``) — mutually exclusive with All-IDN's ``'on'``, so
    this cannot share a settings write with :func:`_write_builtin_config`.
    """
    alias, hdr, url = group
    settings = {
        "global_log_mode": global_log_mode,
        "global_log": global_log,
        "pfb_dnsbl": "on",
        "pfb_idn": "confusable",
        "pfb_idn_block_malicious": "on",
    }
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"{h._dnsbl_settings_replace_php(settings)}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, "
        f"array({_group_php(aliasname=alias, header=hdr, url=url, logging='default')}));\n"
        "write_config('pfBlockerNG smoke: issue-3291 Confusable-IDN builtin mechanism config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_write_confusable_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _set_global_mechanism(vm: SmokeVM, *, mode: str, mechanism: str, timeout: float = 60.0) -> None:
    """Flip ONLY the shared policy fields (mode + mechanism) — every built-in
    toggle written by the ``_write_*_config`` helpers above is left untouched (a
    read-modify-write merge, mirrors
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
@pytest.mark.timeout(600)  # 4 restart-class updatednsbl reloads + 4 rows x 4 phases, collected + asserted once each.
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

    Each phase probes EVERY row and asserts once (issue #3334 review F3): a
    RED run's single failure message lists every built-in still hardcoding VIP,
    not just the first one the old per-row loop happened to hit.
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

    rows = [
        _Row("regex", regex_domain),
        _Row("all-idn", idn_domain),
        _Row("tld-blacklist", blacklist_domain),
        _Row("hsts-regex", hsts_domain, phase_shape_override={1: "null"}),
    ]

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
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 1, "vip")

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
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 2, "null")

        # ---- Phase 3: nxdomain_log (flag '3') -> NXDOMAIN, even for the HSTS name ----
        _set_global_mechanism(deployed_vm, mode="default", mechanism="nxdomain_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 3, "nxdomain")

        # ---- Phase 4: nodata_log (flag '5') -> NOERROR ANSWER=0 AUTHORITY=1 SOA ----
        _set_global_mechanism(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 4, "nodata")
    finally:
        h.reset(deployed_vm)


# --------------------------------------------------------------------------- #
# 2) TLD Allow — its own test (see module docstring for why it can't share the
#    settings write above)
# --------------------------------------------------------------------------- #


@pytest.mark.smoke
@pytest.mark.timeout(300)  # 4 restart-class updatednsbl reloads + 1 row x 4 phases, collected + asserted once each.
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
    rows = [_Row("tld-allow", allow_domain)]

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
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 1, "vip")

        _set_global_mechanism(deployed_vm, mode="default", mechanism="disabled_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 2, "null")

        _set_global_mechanism(deployed_vm, mode="default", mechanism="nxdomain_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 3, "nxdomain")

        _set_global_mechanism(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 4, "nodata")
    finally:
        h.reset(deployed_vm)


# --------------------------------------------------------------------------- #
# 3) Confusable-IDN — its own test (mutually exclusive with All-IDN; see
#    module docstring)
# --------------------------------------------------------------------------- #


@pytest.mark.smoke
@pytest.mark.timeout(300)  # 4 restart-class updatednsbl reloads + 1 row x 4 phases, collected + asserted once each.
def test_dnsbl_builtin_mechanism_confusable_idn(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Issue #3291: the Confusable-IDN homoglyph BLOCK also tracks the shared
    mechanism — a distinct code path from All-IDN's blunt "every xn-- blocks"
    gate (``idn_mode_decision``): Confusable runs the TR39 analyzer
    (``classify_idn`` / ``idn_confusable_action``) and only blocks a name whose
    per-label severity is malicious (or escalated), attributing to
    ``IDN_FEED_MALICIOUS``/``IDN_GROUP_MALICIOUS`` rather than the blunt "IDN"
    feed/group All-IDN uses.
    """
    inert_alias = "smokeconfusableinert"
    inert_feed = h.write_local_feed(
        deployed_vm, "smoke_confusable_inert.txt", f"{h.unique_domain('confusableinert')}\n"
    )
    rows = [_Row("confusable-idn", CONFUSABLE_MALICIOUS_DOMAIN)]

    try:
        _write_confusable_config(
            deployed_vm,
            group=(inert_alias, inert_alias, inert_feed),
            global_log_mode="default",
            global_log="enabled",
        )
        # Verify the key semantics this test relies on before trusting the DNS
        # shape below to attribute a failure correctly.
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_idn") == "confusable"
        assert h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_idn_block_malicious") == "on"
        h.reload(deployed_vm, "updatednsbl")

        # The name is shared with test_smoke_matrix; flush any answer an earlier module cached.
        h.flush_unbound_name(deployed_vm, CONFUSABLE_MALICIOUS_DOMAIN)
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 1, "vip")

        _set_global_mechanism(deployed_vm, mode="default", mechanism="disabled_log")
        h.reload(deployed_vm, "updatednsbl")
        h.flush_unbound_name(deployed_vm, CONFUSABLE_MALICIOUS_DOMAIN)
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 2, "null")

        _set_global_mechanism(deployed_vm, mode="default", mechanism="nxdomain_log")
        h.reload(deployed_vm, "updatednsbl")
        h.flush_unbound_name(deployed_vm, CONFUSABLE_MALICIOUS_DOMAIN)
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 3, "nxdomain")

        _set_global_mechanism(deployed_vm, mode="default", mechanism="nodata_log")
        h.reload(deployed_vm, "updatednsbl")
        h.flush_unbound_name(deployed_vm, CONFUSABLE_MALICIOUS_DOMAIN)
        with _hermetic_probe():
            _assert_all_rows_match_phase(client_vm, deployed_vm, rows, 4, "nodata")
    finally:
        h.reset(deployed_vm)
