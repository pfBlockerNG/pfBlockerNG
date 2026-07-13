"""Tier-B functional WebUI flows over CSRF POST (ADR-14 Phase 3).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier is run with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

What this tier establishes (ADR §1 fact 3, §2 "Tier B functional"): the oracle
is the box's EFFECTIVE state -- ``config.xml`` (read via
:func:`tests.smoke.helpers.config_get`), and where a setting drives runtime,
``pfctl`` / ``unbound`` -- NEVER the HTTP response body. A 200 (or a clean
post-redirect page) does not prove the save took; re-reading config.xml does.

Every flow is a TRUE transition test (CLAUDE.md transition-test rule): it reads
and asserts the ORIGINAL config value FIRST, drives the form to flip it, asserts
the NEW value, then drives the form again to restore the original (asserting the
reverse transition) so the box is left clean for Tier A and the other flows on
the session-scoped VM. A green therefore proves the POST CAUSED the change, not
that the expected end-state happened to hold already; and the restore proves the
reverse direction too (both branches of the toggle exercised).

CSRF-per-POST: :meth:`tests.smoke.ui.webui.WebUI.post` re-GETs the form, scrapes
its current fields + the freshly-injected ``__csrf_magic`` token, applies the one
override, and POSTs back -- so every POST carries a current token and re-posts
the page's own state (the field-omission ``?:`` resets the save handler would
otherwise apply can't touch the box). See RESULTS/01 (the token is injected by
the output filter per render -- it must be re-extracted, never cached).
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e


@dataclass(frozen=True)
class ToggleFlow:
    """A functional flow that flips ONE on/off WebUI setting and reads it back.

    ``page`` is the form path; ``field`` the POST field name (a pfBlockerNG
    ``PFB_FILTER_ON_OFF`` checkbox: present+``on`` when set, absent when clear);
    ``config_path`` the ``config.xml`` node the save handler writes (the oracle
    reads THIS, not the response). ``on``/``off`` are the two stored values
    (``'on'`` and ``''`` -- an unchecked checkbox stores empty).
    """

    name: str
    page: str
    field: str
    config_path: str
    on: str = "on"
    off: str = ""
    # POST timeout: the General save calls sync_package_pfblockerng() (a full
    # config-rebuild pass) AFTER write_config, so its round-trip can run long;
    # the IP/DNSBL settings saves only write_config(). Generous default covers
    # the heavy one without hanging the job (pytest-timeout caps the test).
    post_timeout: float = 300.0


# The three Tier-B flows -- one per major settings page. Each toggles a pure-
# persistence on/off flag (no heavy reload / no egress side effect in the save
# handler) so the flow is fast, observable, and reversible:
#
#   general  pfb_keep       installedpackages/pfblockerng/config/0
#            "Keep Settings" -- run-state retention on install/upgrade. The
#            General save calls sync_package_pfblockerng() AFTER write_config, so
#            the config node is persisted synchronously before that pass; the
#            POST round-trip blocks until the post-redirect, so config.xml holds
#            the new value on return.
#   ip       enable_log     installedpackages/pfblockerngipsettings/config/0
#            "Enable Global Logging". The IP save validates ip_placeholder +
#            maxmind_locale and fires a MaxMind conversion ONLY on a locale
#            CHANGE -- re-posting the page's own (unchanged) locale avoids it, so
#            the toggle is hermetic under the egress block.
#   dnsbl    pfb_dnsbl_rule installedpackages/pfblockerngdnsblsettings/config/0
#            "Create Floating Pass rule". The DNSBL save validates the sinkhole
#            VIP (pfb_validate_vips, always in manual mode) and the lighttpd
#            ports, so the box MUST have a valid VIP first -- the fixture calls
#            helpers.ensure_dnsbl_vip(). The DNSBL settings save only
#            write_config()s (no reload), so config.xml is the oracle.
# Page URLs (DRY -- the validator tests below reuse them).
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
SAFESEARCH_PAGE = "/pfblockerng/pfblockerng_safesearch.php"
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"
# DNSBL_PAGE is defined further down (used by the auto-VIP test too).

FLOWS: tuple[ToggleFlow, ...] = (
    # ---- General settings (installedpackages/pfblockerng/config/0) ------------
    # PFB_FILTER_ON_OFF checkboxes. The General save runs sync_package_pfblockerng()
    # AFTER write_config -- a full config-rebuild pass that is SLOW but hermetic for
    # these flags (no feed download / MaxMind conversion is triggered by toggling
    # enable_cb / pfb_keep; feeds fetch only on a Force Update/CRON). The generous
    # post_timeout default (300s) covers that sync pass.
    ToggleFlow(
        name="general_enable_cb",
        page=GENERAL_PAGE,
        field="enable_cb",
        config_path="installedpackages/pfblockerng/config/0/enable_cb",
    ),
    ToggleFlow(
        name="general_keep_settings",
        page=GENERAL_PAGE,
        field="pfb_keep",
        config_path="installedpackages/pfblockerng/config/0/pfb_keep",
        # issue #484: the General save stores an explicit 'off' for an unchecked
        # pfb_keep (not '') so a default-on flag can persist a deliberate off.
        off="off",
    ),
    # ---- IP settings (installedpackages/pfblockerngipsettings/config/0) -------
    # The IP save validates ip_placeholder + maxmind_locale and fires a MaxMind
    # conversion ONLY on a locale CHANGE -- WebUI.post re-posts the page's own
    # (unchanged) locale, so every toggle here is hermetic under the egress block.
    # The save only write_config()s (no reload), so config.xml is the oracle.
    ToggleFlow(
        name="ip_dedup",
        page=IP_PAGE,
        field="enable_dup",
        config_path="installedpackages/pfblockerngipsettings/config/0/enable_dup",
    ),
    ToggleFlow(
        name="ip_cidr_aggregation",
        page=IP_PAGE,
        field="enable_agg",
        config_path="installedpackages/pfblockerngipsettings/config/0/enable_agg",
    ),
    ToggleFlow(
        name="ip_suppression",
        page=IP_PAGE,
        field="suppression",
        config_path="installedpackages/pfblockerngipsettings/config/0/suppression",
    ),
    ToggleFlow(
        name="ip_global_logging",
        page=IP_PAGE,
        field="enable_log",
        config_path="installedpackages/pfblockerngipsettings/config/0/enable_log",
    ),
    ToggleFlow(
        name="ip_database_cc",
        page=IP_PAGE,
        field="database_cc",
        config_path="installedpackages/pfblockerngipsettings/config/0/database_cc",
    ),
    ToggleFlow(
        name="ip_floating_rules",
        page=IP_PAGE,
        field="enable_float",
        config_path="installedpackages/pfblockerngipsettings/config/0/enable_float",
    ),
    ToggleFlow(
        name="ip_killstates",
        page=IP_PAGE,
        field="killstates",
        config_path="installedpackages/pfblockerngipsettings/config/0/killstates",
    ),
    # ---- DNSBL settings (installedpackages/pfblockerngdnsblsettings/config/0) -
    # The DNSBL save validates the sinkhole VIP (pfb_validate_vips, always in manual
    # mode) and the lighttpd ports, so the box MUST have a valid VIP first -- the
    # dnsbl_vip_ready fixture calls helpers.ensure_dnsbl_vip(). The save only
    # write_config()s (no reload), so config.xml is the oracle.
    ToggleFlow(
        name="dnsbl_floating_pass_rule",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_dnsbl_rule",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_rule",
    ),
    ToggleFlow(
        name="dnsbl_enable",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_dnsbl",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl",
    ),
    ToggleFlow(
        name="dnsbl_tld_wildcard",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_tld",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_tld",
    ),
    ToggleFlow(
        name="dnsbl_hsts_mode",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_hsts",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts",
    ),
    ToggleFlow(
        name="dnsbl_regex",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_regex",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex",
    ),
    ToggleFlow(
        name="dnsbl_noaaaa",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_noaaaa",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_noaaaa",
    ),
    ToggleFlow(
        name="dnsbl_global_bypass",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_gp",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_gp",
    ),
    ToggleFlow(
        name="dnsbl_cache",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_cache",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache",
    ),
    ToggleFlow(
        name="dnsbl_py_nolog",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_py_nolog",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_nolog",
    ),
    # ADR-08 Confusable sub-toggles (on/off checkboxes). The DNSBL save only
    # write_config()s, so config.xml is the oracle. block_malicious defaults 'on',
    # escalate_suspicious defaults '' -- the flow flips from whatever is stored.
    ToggleFlow(
        name="dnsbl_idn_block_malicious",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_idn_block_malicious",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious",
    ),
    ToggleFlow(
        name="dnsbl_idn_escalate_suspicious",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_idn_escalate_suspicious",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_escalate_suspicious",
    ),
    # issue #381: opt out of automatic DNSBL NAT-rule creation (default '' = NAT on).
    # The form POST exercises the new save handler; config.xml is the oracle.
    ToggleFlow(
        name="dnsbl_nonat",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_dnsbl_nonat",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat",
    ),
)


@pytest.fixture(scope="module")
def dnsbl_vip_ready(smoke_vm: helpers.SmokeVM) -> None:
    """Ensure the DNSBL sinkhole VIP exists so the DNSBL settings save validates.

    The DNSBL save runs ``pfb_validate_vips`` in manual mode on EVERY save (and
    ``is_port`` on the lighttpd ports). Without a valid VIP the save fails with
    an input error and config.xml is never written -- the flow would false-fail.
    ``ensure_dnsbl_vip`` injects the lo0 IP-Alias VIP + the default ports exactly
    as the matrix does (the default ``pfb_dnsvip_auto`` is OFF, so the manual VIP
    is required). Idempotent on the uniqid; module-scoped so it runs once.
    """
    helpers.ensure_dnsbl_vip(smoke_vm)


def _set_and_confirm(webui: WebUI, vm: helpers.SmokeVM, flow: ToggleFlow, target: str) -> None:
    """Drive ``flow``'s form to store ``target`` and assert config.xml landed it.

    ``target`` is ``flow.on`` or ``flow.off``. A checkbox set ON sends
    ``{field: 'on'}``; set OFF sends nothing for that field (a browser omits an
    unchecked box) -- :meth:`WebUI.post` re-posts every OTHER field at its
    current value, so only this flag changes. The oracle then re-reads the
    config node over SSH (effective state), never the POST response body.
    """
    # ON: send the checkbox value flow.on ('on'). OFF: send flow.off -- the form
    # had it checked (currently ON), so scrape_form_fields would otherwise re-submit
    # it as 'on'; overriding to flow.off ('' by default) makes pfBlockerNG's
    # PFB_FILTER_ON_OFF store the cleared value (any value != 'on' -> off). Use the
    # dataclass's off value, not a hardcoded '', so a flow with a different OFF
    # token stays correct.
    overrides = {flow.field: flow.on} if target == flow.on else {flow.field: flow.off}
    resp = webui.post(flow.page, overrides, timeout=flow.post_timeout)
    # Sanity only: the POST must not bounce to the login form (a dropped session
    # would otherwise read as "no change" against config). NOT the pass oracle.
    assert not looks_like_login_page(resp.text), f"{flow.name}: POST returned the login form (session lost)"
    got = helpers.config_get(vm, flow.config_path)
    assert got == target, (
        f"{flow.name}: config node {flow.config_path} is {got!r} after POSTing target {target!r} "
        f"(effective-state oracle: config.xml, not the HTTP body)"
    )


@pytest.mark.parametrize("flow", FLOWS, ids=lambda f: f.name)
def test_toggle_flow_changes_effective_config(
    flow: ToggleFlow,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """A CSRF-POST form toggle changes the EFFECTIVE config.xml value, both ways.

    True transition (CLAUDE.md): assert the ORIGINAL value, flip it via the form
    and assert the NEW value, then flip it back via the form and assert the
    ORIGINAL again -- so the green proves each POST CAUSED its change (not a
    pre-existing end-state) AND both branches of the toggle are exercised. The
    final restore leaves the box clean for Tier A / the sibling flows on the
    session VM. The oracle is config.xml read over SSH, never the POST response.
    """
    # An absent key reads as '' over the raw config path; normalise it to this flow's
    # canonical off token so the before-state assertion and the restore compare against a
    # real stored value (PfbLenient pfb_keep stores 'off', never ''). For the PfbToggle
    # flows whose off token IS '', this is a no-op.
    original = helpers.config_get(smoke_vm, flow.config_path) or flow.off
    # The toggle's "other" value -- we drive AWAY from original, then BACK.
    flipped = flow.off if original == flow.on else flow.on

    try:
        # 1) BEFORE-state: assert the original value as the box currently holds it.
        assert original in (flow.on, flow.off), (
            f"{flow.name}: unexpected starting value {original!r} for {flow.config_path} "
            f"(expected {flow.on!r} or {flow.off!r})"
        )
        # 2) Flip via the form; assert config.xml moved to the flipped value.
        _set_and_confirm(webui, smoke_vm, flow, flipped)
        # 3) Flip back via the form; assert config.xml returned to the original
        #    (the reverse transition -- proves the change is the POST's doing).
        _set_and_confirm(webui, smoke_vm, flow, original)
    finally:
        # Belt-and-suspenders: if an assertion above aborted mid-flip, force the
        # box back to its original value so a failure here can't poison Tier A or
        # the next flow on the session-scoped VM.
        if helpers.config_get(smoke_vm, flow.config_path) != original:
            overrides = {flow.field: flow.on} if original == flow.on else {flow.field: flow.off}
            webui.post(flow.page, overrides, timeout=flow.post_timeout)


# --------------------------------------------------------------------------- #
# VALIDATOR / SELECT-COERCION FLOWS (Batch 1)
#
# Beyond the on/off toggles above, each settings page validates or coerces
# scalar/textarea/select fields. These tests follow the SAME transition rule as
# the toggle test (assert BEFORE, drive VALID, assert stored, drive BOGUS, assert
# the reject outcome, restore the original) but exercise the non-checkbox save
# arms. The oracle is always config.xml over SSH, never the HTTP body.
#
# Two distinct reject behaviours coexist in the save handlers (load-bearing for
# the assertions):
#
#   * HARD-ABORT validators -- a bad value appends to $input_errors and the
#     `if (!$input_errors)` guard skips the ENTIRE config_set_path/write_config
#     block, so config.xml is UNCHANGED (the bad POST does NOT coerce to a
#     default; it simply does not persist). Covered by `_assert_reject_unchanged`.
#   * SOFT-COERCE selects -- a value that is an array or not a key of its
#     options_* whitelist is silently replaced with that field's DEFAULT and the
#     save SUCCEEDS, so config holds the DEFAULT (not the bogus value, not the
#     prior value). Covered by `_assert_reject_coerces_to`.
#
# Every flow here is HERMETIC: each save only write_config()s (the General page
# also runs sync_package_pfblockerng(), slow but no egress); none triggers a feed
# download / MaxMind conversion (no test OVERRIDES maxmind_locale, so WebUI.post
# re-posts the unchanged locale and no ugc conversion fires). The non-hermetic
# maxmind_locale change case is EXCLUDED from this batch.
# --------------------------------------------------------------------------- #

# Generous POST timeout matching the General save's sync_package_pfblockerng() pass.
SAVE_TIMEOUT = 300.0


def _post_and_get(
    webui: WebUI,
    vm: helpers.SmokeVM,
    page: str,
    overrides: dict[str, str],
    config_path: str,
) -> str:
    """POST ``overrides`` to ``page``'s form and return the EFFECTIVE config value.

    One browser-faithful CSRF round-trip (WebUI.post re-GETs the form, re-scrapes
    its current fields + the fresh ``__csrf_magic`` token, applies ``overrides``,
    POSTs back), with a login-bounce sanity check, then reads ``config_path`` over
    SSH as the oracle.
    """
    resp = webui.post(page, overrides, timeout=SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), (
        f"POST to {page} returned the login form (session lost) -- not a real save result"
    )
    return helpers.config_get(vm, config_path)


# --------------------------------------------------------------------------- #
# DNSBL settings — the ADR-08 "IDN Blocking" selector (a 3-value select, not the
# on/off ToggleFlow shape, so it round-trips here explicitly).
# --------------------------------------------------------------------------- #


def test_dnsbl_idn_mode_select_round_trips_all_modes(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """The 'IDN Blocking' select (``pfb_idn``) round-trips all three modes via config.xml.

    Off (``'off'``) / Confusable (``'confusable'``) / Always (``'on'``) are the options
    (ADR-08 reuses the legacy ``'on'`` token to back the "Always"/block-all-IDN mode, so it
    round-trips with no migration); the save stores the posted token verbatim for each
    (off->off, confusable->confusable, on->on). The 4.0.0-alpha ``'all'`` token no longer
    exists. Drives EACH mode and asserts the effective config node (branch coverage: every
    selectable value, not just one), restoring the original at the end. The DNSBL save only
    write_config()s (config.xml is the oracle) and needs the sinkhole VIP -- supplied by
    ``dnsbl_vip_ready``.
    """
    page = "/pfblockerng/pfblockerng_dnsbl.php"
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn"
    original = helpers.config_get(smoke_vm, cfg)
    try:
        for mode in ("confusable", "on", "off"):
            got = _post_and_get(webui, smoke_vm, page, {"pfb_idn": mode}, cfg)
            assert got == mode, f"pfb_idn select: POSTing {mode!r} stored {got!r} (expected {mode!r})"
    finally:
        # Restore the original; fall back to 'off' since the save validator rejects an
        # empty/absent value (only off/confusable/on are accepted), leaving the box clean.
        _post_and_get(webui, smoke_vm, page, {"pfb_idn": original or "off"}, cfg)


def test_dnsbl_top1m_token_masked_field_persists_and_is_never_echoed(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """The masked ``top1m_token`` field (ADR-59 P5) persists via config.xml -- the
    HTTP body is never proof of a save (ADR §1 fact 3) -- and is a WRITE-ONLY field
    with a "blank preserves" contract distinct from every ToggleFlow above:

    * a real-looking token POSTed is stored verbatim in config.xml (transition 1);
    * the very next GET's raw HTML never echoes it back (masked, write-only);
    * a BLANK top1m_token POSTed afterwards -- simulating an ordinary settings save
      that didn't touch this field, since the form always renders it blank -- must
      PRESERVE the already-stored token rather than clearing it (transition 2, the
      safe-on-missing-token contract: a user saving unrelated settings must never
      silently wipe their Cloudflare Radar token).

    The web form cannot blank/clear this field by design, so the original value is
    restored directly via the config API in `finally` (mirrors the `pfSsh.php`
    restore idiom already used by ``test_alerts_render_verify.py``), leaving the
    box clean for the other flows on this session-scoped VM.
    """
    page = "/pfblockerng/pfblockerng_dnsbl.php"
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/top1m_token"
    token = "cf-test-token.ABC123~_+/=-9"
    original = helpers.config_get(smoke_vm, cfg)
    try:
        # WHEN: a real-looking token is posted -- THEN: it persists verbatim.
        got = _post_and_get(webui, smoke_vm, page, {"top1m_token": token}, cfg)
        assert got == token, f"top1m_token should persist the posted value, got {got!r}"

        # THEN: the very next GET never echoes it back in the raw HTML (write-only).
        resp = webui.get(page)
        assert token not in resp.text, "top1m_token must never be echoed back on GET (write-only masked field)"

        # WHEN: a blank top1m_token rides a save (the form always renders this field
        # blank, so this is what EVERY unrelated settings save actually posts).
        got_after_blank = _post_and_get(webui, smoke_vm, page, {"top1m_token": ""}, cfg)
        # THEN: unchanged -- a blank submit must never clear an already-stored token.
        assert got_after_blank == token, (
            f"a blank top1m_token POST must preserve the existing stored token, got {got_after_blank!r}"
        )
    finally:
        # Restore directly via the config API -- the web form cannot blank this field
        # by design (proven above), so a normal POST can't be used for cleanup.
        restore = helpers.php_eval(
            smoke_vm,
            f"config_set_path({helpers._php_str(cfg)}, {helpers._php_str(original)});\n"
            "write_config('ADR-59 P5 smoke: restore top1m_token');\necho 'OK';",
        )
        assert "OK" in restore.stdout, f"failed to restore top1m_token: {restore.stdout!r}"


MAXMIND_KEY_CFG = "installedpackages/pfblockerngipsettings/config/0/maxmind_key"


def test_ip_maxmind_key_masked_field_persists_and_is_never_echoed(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The masked ``maxmind_key`` field (issue #924) persists via config.xml -- the
    HTTP body is never proof of a save (ADR §1 fact 3) -- and is a WRITE-ONLY field
    with the same "blank preserves" contract as ``top1m_token`` (ADR-59 P5) above,
    mirrored here for the MaxMind GeoIP license key on the IP-settings page.

    Scenario: masked/write-only maxmind_key on the IP-settings page (issue #924).
      Background: pfBlockerNG deployed; webConfigurator authenticated.

    Given an inert MaxMind license key is already stored (seeded directly via the
      config API -- the BEFORE state, independent of the save path under test),
    When the IP page is fetched, Then the raw HTML never echoes the stored key
      (write-only, masked field);
    When a BLANK maxmind_key rides a save (the form always renders this field
      blank, so this is what EVERY unrelated IP-settings save actually posts),
      Then the stored key is PRESERVED -- this is the red->green core of #924:
      pre-change, the save unconditionally wrote
      ``pfb_filter($_POST['maxmind_key'], PFB_FILTER_WORD, 'ip') ?: ''``, so a
      blank POST cleared the key (this assertion FAILS on that code); post-change,
      the blank-keeps guard skips the assignment entirely (this assertion PASSES);
    When a NEW inert key is posted, Then it REPLACES the stored key (branch
      coverage: a non-empty submission still writes through);
    When a non-word BOGUS key is posted, Then the WHOLE save aborts and the stored
      key is UNCHANGED (the shared ``PFB_FILTER_WORD`` reject branch also covered
      for maxmind_account/asn_token in test_ip_word_filter_field_valid_and_reject_
      unchanged -- maxmind_key keeps that reject behaviour, only its BLANK handling
      differs, so it is asserted here instead of in that shared parametrization).

    The web form cannot blank/clear this field by design (proven above), so the
    original value is restored directly via the config API in `finally` (mirrors
    the `pfSsh.php` restore idiom already used for top1m_token), leaving the box
    clean for the other flows on this session-scoped VM.
    """
    page = IP_PAGE
    cfg = MAXMIND_KEY_CFG
    seed_token = "PFBTESTKEY000001"
    new_token = "PFBTESTKEY000002"
    original = helpers.config_get(smoke_vm, cfg)
    try:
        # GIVEN: an inert key is already stored -- seeded directly (not via the form
        # under test), so the BEFORE state is established independently.
        seed = helpers.php_eval(
            smoke_vm,
            f"config_set_path({helpers._php_str(cfg)}, {helpers._php_str(seed_token)});\n"
            "write_config('#924 smoke: seed maxmind_key');\necho 'OK';",
        )
        assert "OK" in seed.stdout, f"failed to seed maxmind_key: {seed.stdout!r}"
        assert helpers.config_get(smoke_vm, cfg) == seed_token, "seed did not take before the GET/POST assertions"

        # THEN: a GET never echoes the stored key in the raw HTML (write-only, masked).
        # Guard against a false pass first: a redirect/login/error page also lacks the
        # token, so prove this is the real IP page (200 + the maxmind_key field present)
        # before trusting the absence check below.
        resp = webui.get(page)
        assert resp.status_code == 200, f"GET {page} -> HTTP {resp.status_code} (expected 200)"
        assert 'name="maxmind_key"' in resp.text, (
            f"{page} did not render the maxmind_key field -- not the expected IP page "
            f"(redirect/login/error?), which would make the never-leak check vacuous"
        )
        assert seed_token not in resp.text, (
            f"maxmind_key must never be echoed back on GET (write-only masked field) -- "
            f"searched for {seed_token!r} in the {page} response body"
        )

        # WHEN: a blank maxmind_key rides a save. THEN: unchanged (the red->green core).
        got_after_blank = _post_and_get(webui, smoke_vm, page, {"maxmind_key": ""}, cfg)
        assert got_after_blank == seed_token, (
            f"a blank maxmind_key POST must preserve the existing stored key: "
            f"expected {seed_token!r}, got {got_after_blank!r}"
        )

        # WHEN: a NEW key is posted. THEN: it replaces the stored key.
        got_after_new = _post_and_get(webui, smoke_vm, page, {"maxmind_key": new_token}, cfg)
        assert got_after_new == new_token, (
            f"maxmind_key should persist a new posted value: expected {new_token!r}, got {got_after_new!r}"
        )

        # WHEN: a non-word BOGUS key is posted. THEN: the whole save aborts -- config
        # UNCHANGED at new_token (not the bogus value, not blanked). Same
        # PFB_FILTER_WORD reject branch as maxmind_account/asn_token, unaffected by
        # this fix (only the blank-handling above changed).
        got_after_bogus = _post_and_get(webui, smoke_vm, page, {"maxmind_key": "bad/key"}, cfg)
        assert got_after_bogus == new_token, (
            f"a non-word maxmind_key must abort the save, leaving config unchanged: "
            f"expected {new_token!r}, got {got_after_bogus!r}"
        )
    finally:
        # Restore directly via the config API -- the web form cannot blank this field
        # by design (proven above), so a normal POST can't be used for cleanup.
        restore = helpers.php_eval(
            smoke_vm,
            f"config_set_path({helpers._php_str(cfg)}, {helpers._php_str(original)});\n"
            "write_config('#924 smoke: restore maxmind_key');\necho 'OK';",
        )
        assert "OK" in restore.stdout, f"failed to restore maxmind_key: {restore.stdout!r}"


# --------------------------------------------------------------------------- #
# General settings (installedpackages/pfblockerng/config/0)
# --------------------------------------------------------------------------- #


def test_general_cron_interval_select_coerces_bogus_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A CRON select takes a valid in-range key, coerces a bogus value to default 1.

    Representative ``log_max_``-adjacent CRON select (Hour Interval, ``pfb_interval``).
    Save loop: ``$options_pfb_interval`` keys are 1,2,3,4,6,8,12,24,'Disabled'. A
    valid key '2' is stored verbatim (truthy, survives the trailing ``?:1``); a
    bogus '999' is not a key -> ``$_POST`` is coerced to the default 1, then stored
    1 (the save still SUCCEEDS -- soft coerce, not an abort). '2' is chosen because
    it is truthy and distinct from the default 1 (a falsy '0'/'Disabled'-adjacent
    probe would be indistinguishable from the reject outcome).

    Transition: read the box's current value first, drive to '2' (assert '2'),
    drive back to the original, then prove the bogus POST coerces to 1.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerng/config/0/pfb_interval"
    original = helpers.config_get(vm, cfg)
    try:
        # BEFORE: a fresh image defaults to 1; assert whatever it currently is is a
        # known key so the transition is meaningful (not asserting it equals '2').
        assert original != "2", f"pfb_interval already '2' before the valid POST (original={original!r})"
        # VALID: '2' is a key -> stored verbatim.
        assert _post_and_confirm_general(webui, vm, {"pfb_interval": "2"}, cfg) == "2"
        # Restore to the original valid key.
        assert _post_and_confirm_general(webui, vm, {"pfb_interval": original or "1"}, cfg) == (original or "1")
        # BOGUS: not a key -> coerced to default 1 (save succeeds, value != '999').
        got = _post_and_confirm_general(webui, vm, {"pfb_interval": "999"}, cfg)
        assert got == "1", f"bogus pfb_interval should coerce to default 1, got {got!r}"
    finally:
        webui.post(GENERAL_PAGE, {"pfb_interval": original or "1"}, timeout=SAVE_TIMEOUT)


def test_general_log_max_select_coerces_bogus_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A ``log_max_*`` select takes a valid key, coerces a bogus value to default 20000.

    Representative ``log_max_log`` (pfBlockerNG General log, max lines). Save loop:
    ``strpos('log_max_', …)`` validates against ``$options_log_types`` (keys
    100,1000,2000,4000,6000,8000,10000,20000,40000,…,'nolimit'). Valid '40000' is a
    key -> stored verbatim (truthy, distinct from the 20000 default); bogus '12345'
    is not a key -> coerced to default 20000, save SUCCEEDS. Same coercion path
    covers all ten log_max_* fields.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerng/config/0/log_max_log"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "40000", f"log_max_log already '40000' before the valid POST (original={original!r})"
        assert _post_and_confirm_general(webui, vm, {"log_max_log": "40000"}, cfg) == "40000"
        assert _post_and_confirm_general(webui, vm, {"log_max_log": original or "20000"}, cfg) == (original or "20000")
        got = _post_and_confirm_general(webui, vm, {"log_max_log": "12345"}, cfg)
        assert got == "20000", f"bogus log_max_log should coerce to default 20000, got {got!r}"
    finally:
        webui.post(GENERAL_PAGE, {"log_max_log": original or "20000"}, timeout=SAVE_TIMEOUT)


def test_general_skipfeed_bogus_scalar_resets_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``skipfeed`` keeps a valid key and resets a non-key value to the default 0.

    The select-RESET negative exercising the is_array()/!array_key_exists arms.
    Save loop: ``if (is_array($_POST[$s_option])) $_POST[$s_option] = $s_default;``
    AND an ``elseif (!array_key_exists(...))`` that also coerces to the default 0.
    A valid scalar '3' is a key of ``$options_skipfeed`` (0..6) -> stored '3'.

    HARNESS CAVEAT: ``WebUI.post`` overrides a single scalar field (dict[str,str]);
    it cannot emit the array-bracket form (``skipfeed[]=x``) that PHP parses as an
    array, so the is_array arm cannot be hit through this client. We therefore use
    the equivalent bogus SCALAR '99' (not a key 0..6), which hits the
    ``!array_key_exists`` arm and also coerces to the default 0 -- same observable
    reset to 0 (NOT '99'). The valid probe is '3' because the default 0 is falsy
    and would be stored as 0 even when "valid" via the trailing ``?:0``.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerng/config/0/skipfeed"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "3", f"skipfeed already '3' before the valid POST (original={original!r})"
        assert _post_and_confirm_general(webui, vm, {"skipfeed": "3"}, cfg) == "3"
        # Restore (the default 0 is the safe baseline; original may be '' on a fresh box).
        _post_and_confirm_general(webui, vm, {"skipfeed": original or "0"}, cfg)
        # BOGUS scalar '99' is not a key -> coerced to the default 0.
        got = _post_and_confirm_general(webui, vm, {"skipfeed": "99"}, cfg)
        assert got == "0", f"bogus skipfeed should reset to default 0, got {got!r}"
    finally:
        webui.post(GENERAL_PAGE, {"skipfeed": original or "0"}, timeout=SAVE_TIMEOUT)


def test_general_log_trim_margin_pct_valid_and_bogus_coerces_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """issue #1109: ``pfb_log_trim_margin_pct`` persists a valid percent, coerces garbage to 0.

    Save loop mirrors ``log_max_days_*``'s ``is_array()``/``!ctype_digit`` guard (a plain
    number input, not a select -- no ``array_key_exists``). BEFORE: the registered default
    is '0' on config/0, asserted first (transition-test rule). VALID '50' stores verbatim,
    restored (asserted), THEN bogus 'abc' fails ``ctype_digit`` -> coerced to default '0'
    (the save still SUCCEEDS -- soft coerce, not an abort).
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct"
    original = helpers.config_get(vm, cfg)
    try:
        assert (original or "0") == "0", (
            f"pfb_log_trim_margin_pct already non-default before the save (original={original!r})"
        )
        assert _post_and_confirm_general(webui, vm, {"pfb_log_trim_margin_pct": "50"}, cfg) == "50"
        assert _post_and_confirm_general(webui, vm, {"pfb_log_trim_margin_pct": original or "0"}, cfg) == (
            original or "0"
        )
        got = _post_and_confirm_general(webui, vm, {"pfb_log_trim_margin_pct": "abc"}, cfg)
        assert got == "0", f"bogus pfb_log_trim_margin_pct should coerce to default 0, got {got!r}"
    finally:
        webui.post(GENERAL_PAGE, {"pfb_log_trim_margin_pct": original or "0"}, timeout=SAVE_TIMEOUT)


@pytest.mark.parametrize("bogus", ["-5", "1.5", "  50 ", ""])
def test_general_log_trim_margin_pct_hostile_digit_guard_coerces_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    bogus: str,
) -> None:
    """issue #1109: every ``ctype_digit``-rejected shape (sign, decimal, padding, empty)
    coerces to the default '0' -- same guard, same outcome as the 'abc' case above.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct"
    original = helpers.config_get(vm, cfg)
    try:
        got = _post_and_confirm_general(webui, vm, {"pfb_log_trim_margin_pct": bogus}, cfg)
        assert got == "0", f"bogus pfb_log_trim_margin_pct={bogus!r} should coerce to default 0, got {got!r}"
    finally:
        webui.post(GENERAL_PAGE, {"pfb_log_trim_margin_pct": original or "0"}, timeout=SAVE_TIMEOUT)


def test_general_log_trim_margin_pct_oversized_value_saves_without_crash(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """issue #1109: an oversized digit string passes ``ctype_digit`` and stores verbatim.

    The UI has no upper-bound rejection (by design -- the backend parser
    ``pfb_log_trim_margin_pct()`` clamps to 1000 when it is READ, not at save time; already
    pinned by ``LogTrimMarginPctTest``). This only proves the save/re-render round-trip
    itself never crashes on an oversized value.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct"
    original = helpers.config_get(vm, cfg)
    try:
        got = _post_and_confirm_general(webui, vm, {"pfb_log_trim_margin_pct": "999999999"}, cfg)
        assert got == "999999999", f"oversized pfb_log_trim_margin_pct should store verbatim, got {got!r}"
    finally:
        webui.post(GENERAL_PAGE, {"pfb_log_trim_margin_pct": original or "0"}, timeout=SAVE_TIMEOUT)


def test_general_log_trim_margin_pct_save_preserves_log_max_days_sibling(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The margin save must not disturb a sibling ``log_max_days_*`` value in the same POST
    (persist-loop ordering, #1109), and raises no new ``php_error.log`` line across the POST.
    """
    vm = smoke_vm
    margin_cfg = "installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct"
    days_cfg = "installedpackages/pfblockerng/config/0/log_max_days_log"
    margin_original = helpers.config_get(vm, margin_cfg)
    days_original = helpers.config_get(vm, days_cfg)
    guard = PhpErrorLogGuard(vm)
    guard.snapshot()
    try:
        resp = webui.post(
            GENERAL_PAGE,
            {"pfb_log_trim_margin_pct": "25", "log_max_days_log": "7"},
            timeout=SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp.text), "POST to General page bounced to the login form"
        assert helpers.config_get(vm, margin_cfg) == "25"
        assert helpers.config_get(vm, days_cfg) == "7", "log_max_days_log sibling was disturbed by the margin save"
        guard.assert_no_growth()
    finally:
        webui.post(
            GENERAL_PAGE,
            {"pfb_log_trim_margin_pct": margin_original or "0", "log_max_days_log": days_original or "0"},
            timeout=SAVE_TIMEOUT,
        )


def _post_and_confirm_general(
    webui: WebUI,
    vm: helpers.SmokeVM,
    overrides: dict[str, str],
    config_path: str,
) -> str:
    """:func:`_post_and_get` for the General page (its own slow sync save)."""
    return _post_and_get(webui, vm, GENERAL_PAGE, overrides, config_path)


# --------------------------------------------------------------------------- #
# IP settings (installedpackages/pfblockerngipsettings/config/0)
#
# Two reject behaviours on this page: HARD-ABORT validators (ip_placeholder,
# maxmind_account, maxmind_key, asn_token, v4suppression) leave config UNCHANGED;
# the SOFT-COERCE select (asn_reporting) coerces to its default. The interface
# multiselects are unvalidated (implode comma-join). No test overrides
# maxmind_locale, so the ugc conversion never fires -- every flow is hermetic.
#
# maxmind_key (issue #924) is a HARD-ABORT validator too (a non-word bogus value
# still aborts the whole save), but it is NOT in the parametrized WORD-filter flow
# below alongside maxmind_account/asn_token: it is now masked/write-only, so an
# EMPTY POST means "keep the stored key" rather than "overwrite with empty" --
# incompatible with that flow's shared "restore via a blank/original POST" idiom.
# Its own valid/blank-keeps/reject coverage lives in
# test_ip_maxmind_key_masked_field_persists_and_is_never_echoed above.
# --------------------------------------------------------------------------- #

IP_PLACEHOLDER_CFG = "installedpackages/pfblockerngipsettings/config/0/ip_placeholder"


def test_ip_placeholder_valid_isolated_ipv4_and_reject_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``ip_placeholder`` stores a valid isolated IPv4; a bogus value aborts the save.

    Save validates the POSTed value directly: ``is_ipaddrv4`` then
    ``where_is_ipaddr_configured(..., '')`` must return EMPTY (IP not configured on
    any iface). 127.1.7.8 is loopback-range, isolated -> passes both (pure config
    check, NO egress) and is written verbatim. A bogus '999.999.999.999' fails
    ``is_ipaddrv4`` -> ``$input_errors`` -> the ENTIRE save aborts at
    ``if (!$input_errors)`` -> config.xml is UNCHANGED (NOT coerced to the
    127.1.7.7 default -- that default applies only on the empty-config READ path).

    KEEP a valid placeholder in config afterward: the ip_global_logging toggle and
    every other IP save re-validate ip_placeholder, so a missing/invalid value
    would abort sibling flows. Restore to the captured original (a valid IP).
    """
    vm = smoke_vm
    cfg = IP_PLACEHOLDER_CFG
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "127.1.7.8", f"ip_placeholder already 127.1.7.8 before the valid POST ({original!r})"
        # VALID isolated loopback IPv4 -> stored verbatim.
        assert _post_and_get(webui, vm, IP_PAGE, {"ip_placeholder": "127.1.7.8"}, cfg) == "127.1.7.8"
        # Restore the original valid placeholder (fall back to the page default).
        restore = original or "127.1.7.7"
        assert _post_and_get(webui, vm, IP_PAGE, {"ip_placeholder": restore}, cfg) == restore
        # REJECT: a bogus IP aborts the whole save -> config UNCHANGED (stays `restore`).
        got = _post_and_get(webui, vm, IP_PAGE, {"ip_placeholder": "999.999.999.999"}, cfg)
        assert got == restore, f"bogus ip_placeholder must leave config unchanged at {restore!r}, got {got!r}"
    finally:
        webui.post(IP_PAGE, {"ip_placeholder": original or "127.1.7.7"}, timeout=SAVE_TIMEOUT)


@pytest.mark.parametrize(
    ("field", "valid", "bogus"),
    [
        ("maxmind_account", "Test_123", "bad-chars!"),
        ("asn_token", "Tok_789", "tok@en"),
    ],
    ids=["maxmind_account", "asn_token"],
)
def test_ip_word_filter_field_valid_and_reject_unchanged(
    field: str,
    valid: str,
    bogus: str,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A ``PFB_FILTER_WORD`` field stores a clean word; a non-word value aborts the save.

    ``PFB_FILTER_WORD`` = no non-word char (``/\\W/``): only ``[A-Za-z0-9_]`` passes.
    Save guard: ``!empty($_POST[field]) && empty(pfb_filter($_POST[field],
    PFB_FILTER_WORD, 'ip'))`` -> a field-specific input error -> the WHOLE save
    aborts -> config UNCHANGED. A valid word ('Test_123' / 'Tok_789') passes and is
    stored verbatim; a value with a non-word char ('bad-chars!', 'tok@en') is
    REJECTED -> config unchanged (NOT the bogus value, NOT empty). Empty input is
    allowed (the ``!empty`` guard) and stores ''. Pure regex validation, NO egress
    (these tokens only drive update/reload lookups, not this save). Same mechanism
    for both fields -> parametrized. (``maxmind_key`` shares the same
    ``PFB_FILTER_WORD`` reject branch but NOT this "blank stores empty" contract --
    see the masked-field test above.)
    """
    vm = smoke_vm
    cfg = f"installedpackages/pfblockerngipsettings/config/0/{field}"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != valid, f"{field} already {valid!r} before the valid POST"
        # VALID clean word -> stored verbatim.
        assert _post_and_get(webui, vm, IP_PAGE, {field: valid}, cfg) == valid
        # Restore the original (typically '' -- empty is allowed and stores '').
        assert _post_and_get(webui, vm, IP_PAGE, {field: original}, cfg) == original
        # REJECT: a non-word char aborts the save -> config UNCHANGED.
        got = _post_and_get(webui, vm, IP_PAGE, {field: bogus}, cfg)
        assert got == original, f"bogus {field} must leave config unchanged at {original!r}, got {got!r}"
    finally:
        webui.post(IP_PAGE, {field: original}, timeout=SAVE_TIMEOUT)


def test_ip_v4suppression_mask_validation_base64_and_reject_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``v4suppression`` accepts v4 masks /8-/32 (ADR-53 P4); out-of-range masks abort.

    Textarea, one subnet per line. Validation (``pfb_validate_suppression_line()``,
    ADR-53 P4): per non-comment line, the mask must fall in [/8, /32] AND
    ``is_subnetv4`` must pass; either failure -> ``$input_errors`` -> the WHOLE save
    aborts -> config UNCHANGED. STORAGE IS BASE64 (``base64_encode`` on save,
    ``base64_decode`` on read), so the oracle compares config_get against base64 of
    the expected textarea content. A valid '10.20.30.0/24' stores
    base64('10.20.30.0/24'); a '/16' ('10.20.0.0/16') is now ALSO valid -- Phase 3's
    iprange --except engine swap made suppression mask-agnostic, so Phase 4 lifted
    the UI ceiling from /24 to /8, wider than the old /32-or-/24-only rule -- and
    stores base64 of its own textarea; a '/7' ('10.20.0.0/7') is below the /8 floor
    -> rejected -> config unchanged. An empty textarea stores base64('') = '' so
    clearing/restoring to empty is clean. NO egress, NO reload.
    """
    import base64

    vm = smoke_vm
    cfg = "installedpackages/pfblockerngipsettings/config/0/v4suppression"
    valid_text = "10.20.30.0/24"
    valid_b64 = base64.b64encode(valid_text.encode()).decode()
    original = helpers.config_get(vm, cfg)
    try:
        assert original != valid_b64, f"v4suppression already holds {valid_text!r} (base64) before the valid POST"
        # VALID /24 (the legacy-accepted shape) -> base64 of the textarea is stored.
        assert _post_and_get(webui, vm, IP_PAGE, {"v4suppression": valid_text}, cfg) == valid_b64
        # VALID /16 -- NEW in ADR-53 P4: the widened /8-/32 range now accepts a
        # containing-block mask that the pre-Phase-4 /32-or-/24-only rule rejected.
        wide_text = "10.20.0.0/16"
        wide_b64 = base64.b64encode(wide_text.encode()).decode()
        assert _post_and_get(webui, vm, IP_PAGE, {"v4suppression": wide_text}, cfg) == wide_b64
        # Restore: an empty textarea stores base64('') = '' (clean clear).
        got_clear = _post_and_get(webui, vm, IP_PAGE, {"v4suppression": ""}, cfg)
        assert got_clear == "", f"clearing v4suppression should store '' (base64 of empty), got {got_clear!r}"
        # REJECT: a /7 is below the /8 floor -> aborts the whole save -> config UNCHANGED (stays '').
        got = _post_and_get(webui, vm, IP_PAGE, {"v4suppression": "10.20.0.0/7"}, cfg)
        assert got == "", f"below-floor /7 mask must leave v4suppression unchanged at '', got {got!r}"
    finally:
        # Restore whatever was there originally (re-encode if it was a plain capture
        # -- config_get returns the stored base64 verbatim, so re-post that decoded).
        restore = ""
        if original:
            try:
                restore = base64.b64decode(original).decode()
            except Exception:
                restore = ""
        webui.post(IP_PAGE, {"v4suppression": restore}, timeout=SAVE_TIMEOUT)


def test_ip_v6suppression_mask_validation_base64_and_reject_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``v6suppression`` accepts v6 masks /32-/128 (ADR-53 P6); out-of-range masks abort.

    Textarea, one subnet per line -- the v6 sibling of v4suppression's Tier B just
    above (this is the multi-step save->persist flow ADR-53 requires for the NEW v6
    textarea -- CLAUDE.md's "front-end changes require Tier B" for a new field).
    Validation (``pfb_validate_suppression_line()``, family='ipv6', ADR-53 P6): per
    non-comment line, the mask must fall in [/32, /128] AND ``is_subnetv6`` must
    pass; either failure -> ``$input_errors`` -> the WHOLE save aborts -> config
    UNCHANGED. STORAGE IS BASE64, so the oracle compares config_get against base64
    of the expected textarea content. A valid host mask '2001:db8::1/128' stores
    base64('2001:db8::1/128'); a containing '2001:db8::/64' is ALSO valid (any mask
    in the accepted range, not just /128) and stores base64 of its own textarea; a
    '2001:db8::/31' is below the /32 floor -> rejected -> config unchanged. An empty
    textarea stores base64('') = '' so clearing/restoring to empty is clean. NO
    egress, NO reload.
    """
    import base64

    vm = smoke_vm
    cfg = "installedpackages/pfblockerngipsettings/config/0/v6suppression"
    valid_text = "2001:db8::1/128"
    valid_b64 = base64.b64encode(valid_text.encode()).decode()
    original = helpers.config_get(vm, cfg)
    try:
        assert original != valid_b64, f"v6suppression already holds {valid_text!r} (base64) before the valid POST"
        # VALID /128 host mask -> base64 of the textarea is stored.
        assert _post_and_get(webui, vm, IP_PAGE, {"v6suppression": valid_text}, cfg) == valid_b64
        # VALID /64 -- a containing block within the accepted /32-/128 range.
        wide_text = "2001:db8::/64"
        wide_b64 = base64.b64encode(wide_text.encode()).decode()
        assert _post_and_get(webui, vm, IP_PAGE, {"v6suppression": wide_text}, cfg) == wide_b64
        # Restore: an empty textarea stores base64('') = '' (clean clear).
        got_clear = _post_and_get(webui, vm, IP_PAGE, {"v6suppression": ""}, cfg)
        assert got_clear == "", f"clearing v6suppression should store '' (base64 of empty), got {got_clear!r}"
        # REJECT: a /31 is below the /32 floor -> aborts the whole save -> config UNCHANGED (stays '').
        got = _post_and_get(webui, vm, IP_PAGE, {"v6suppression": "2001:db8::/31"}, cfg)
        assert got == "", f"below-floor /31 mask must leave v6suppression unchanged at '', got {got!r}"
    finally:
        restore = ""
        if original:
            try:
                restore = base64.b64decode(original).decode()
            except Exception:
                restore = ""
        webui.post(IP_PAGE, {"v6suppression": restore}, timeout=SAVE_TIMEOUT)


def _widget_suppression_count(webui: WebUI) -> int:
    """GET the widget's AJAX refresh endpoint and parse the ``Suppression||<n>||-`` line.

    ``pfBlockerNG_get_header('js')`` (hit via ``?getNewWidget=1``, the same AJAX
    path the dashboard widget's own JS polls) prints one ``<Type>||<value>||-``
    line per stat -- plain text, no HTML markup to scrape, the cheapest way to
    read the widget's Suppression count (ADR-53 P8: v4+v6 folded into one total,
    ``pfblockerng.widget.php`` ~:720).
    """
    resp = webui.get(WIDGET_PAGE, params={"getNewWidget": "1"})
    assert not looks_like_login_page(resp.text), "widget AJAX GET returned the login form (session lost)"
    for line in resp.text.splitlines():
        parts = line.split("||")
        if parts and parts[0] == "Suppression":
            return int(parts[1].replace(",", ""))
    raise AssertionError(f"no 'Suppression||<n>||-' line in widget AJAX response: {resp.text!r}")


def test_widget_suppression_count_folds_v4_and_v6(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The widget's Suppression stat is a v4+v6 TOTAL, not v4-only (ADR-53 P8).

    Before ADR-53 P8, the widget read only v4suppression; a v6-only entry was
    invisible in the stat. True transition test (CLAUDE.md before/after rule):
    given ONE v4 entry seeded (count == 1, matching even the OLD v4-only
    reader), THEN a v6 entry is ALSO seeded alongside it (v4 untouched) and the
    count becomes 2 -- provable only if the widget folds v6suppression in too.
    """
    import base64

    vm = smoke_vm
    v4_cfg = "installedpackages/pfblockerngipsettings/config/0/v4suppression"
    v6_cfg = "installedpackages/pfblockerngipsettings/config/0/v6suppression"
    original_v4 = helpers.config_get(vm, v4_cfg)
    original_v6 = helpers.config_get(vm, v6_cfg)
    try:
        # GIVEN: both families start empty.
        webui.post(IP_PAGE, {"v4suppression": ""}, timeout=SAVE_TIMEOUT)
        webui.post(IP_PAGE, {"v6suppression": ""}, timeout=SAVE_TIMEOUT)

        # WHEN: one v4 entry is seeded -- BEFORE state.
        webui.post(IP_PAGE, {"v4suppression": "203.0.113.9/32"}, timeout=SAVE_TIMEOUT)
        count_v4_only = _widget_suppression_count(webui)
        assert count_v4_only == 1, (
            f"expected Suppression=1 with one v4 entry seeded (v6 still empty); widget reported {count_v4_only}"
        )

        # THEN: a v6 entry is ALSO seeded (v4 untouched -- webui.post() scrapes
        # + re-posts the form's current fields, so the v4 textarea round-trips
        # unchanged) -- the count must rise to 2, provable only if v6suppression
        # is folded into the same stat.
        webui.post(IP_PAGE, {"v6suppression": "2001:db8:53::9/128"}, timeout=SAVE_TIMEOUT)
        count_v4_v6 = _widget_suppression_count(webui)
        assert count_v4_v6 == 2, (
            f"expected Suppression=2 after adding one v6 entry alongside the existing v4 one "
            f"(ADR-53 P8 v4+v6 fold-in); widget reported {count_v4_v6} -- stayed v4-only if this held at 1"
        )
    finally:
        restore_v4 = ""
        if original_v4:
            try:
                restore_v4 = base64.b64decode(original_v4).decode()
            except Exception:
                restore_v4 = ""
        restore_v6 = ""
        if original_v6:
            try:
                restore_v6 = base64.b64decode(original_v6).decode()
            except Exception:
                restore_v6 = ""
        webui.post(IP_PAGE, {"v4suppression": restore_v4}, timeout=SAVE_TIMEOUT)
        webui.post(IP_PAGE, {"v6suppression": restore_v6}, timeout=SAVE_TIMEOUT)


def test_ip_asn_reporting_select_coerces_bogus_to_disabled(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``asn_reporting`` takes a valid key; a bogus value coerces to the default 'disabled'.

    Select-validator: for each ``$select_options`` key, a POST value that is an
    array OR not a key of its ``$options_*`` array is COERCED to the default (the
    save still SUCCEEDS and writes the coerced value -- NOT an abort). asn_reporting
    default = 'disabled'; valid keys = disabled/week/24hour/12hour/4hour/1hour.
    Valid 'week' stores 'week'; bogus 'bogus_option' coerces to 'disabled' (the
    DEFAULT, NOT the bogus value, NOT unchanged). This differs from the hard-abort
    validators above. NO egress.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngipsettings/config/0/asn_reporting"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "week", f"asn_reporting already 'week' before the valid POST (original={original!r})"
        # VALID 'week' -> stored verbatim.
        assert _post_and_get(webui, vm, IP_PAGE, {"asn_reporting": "week"}, cfg) == "week"
        # Restore to 'disabled' (the default baseline).
        assert _post_and_get(webui, vm, IP_PAGE, {"asn_reporting": "disabled"}, cfg) == "disabled"
        # BOGUS -> coerced to the default 'disabled' (save succeeds, value != bogus).
        got = _post_and_get(webui, vm, IP_PAGE, {"asn_reporting": "bogus_option"}, cfg)
        assert got == "disabled", f"bogus asn_reporting should coerce to default 'disabled', got {got!r}"
    finally:
        webui.post(IP_PAGE, {"asn_reporting": "disabled"}, timeout=SAVE_TIMEOUT)


def test_ip_inbound_interface_multiselect_comma_join_and_empty_clear(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``inbound_interface`` stores the selection comma-joined; an empty selection stores ''.

    Multiselect, NOT validated against the options list: the save unconditionally
    does ``implode(',', (array)$_POST['inbound_interface']) ?: ''`` and the page
    READ does ``explode(',', …)``. A single selection 'lan' stores 'lan' (PHP casts
    the scalar POST to a 1-element array, so the implode yields 'lan'); an
    EMPTY/omitted selection stores '' (implode of empty -> '' then ``?:''``). 'lan'
    is the reliably-present interface key on the smoke image. The only "reject"
    branch is the empty selection -> '' store (the field is unvalidated -- any
    string passes implode). NO reload, NO egress.

    A two-key comma-join is only deterministic on a VM with >=2 selectable
    interfaces, so this asserts the single-key store + the empty-clear store; the
    same mechanism applies to ``outbound_interface``.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngipsettings/config/0/inbound_interface"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "lan", f"inbound_interface already 'lan' before the valid POST (original={original!r})"
        # VALID single key -> stored as 'lan'.
        assert _post_and_get(webui, vm, IP_PAGE, {"inbound_interface": "lan"}, cfg) == "lan"
        # CLEAR: empty selection -> implode of empty -> '' stored.
        got_clear = _post_and_get(webui, vm, IP_PAGE, {"inbound_interface": ""}, cfg)
        assert got_clear == "", f"empty inbound_interface selection should store '', got {got_clear!r}"
    finally:
        webui.post(IP_PAGE, {"inbound_interface": original}, timeout=SAVE_TIMEOUT)


# --------------------------------------------------------------------------- #
# SafeSearch settings (installedpackages/pfblockerngsafesearch -- BARE node, no
# /config/0 array). safesearch_enable / safesearch_youtube are <select>s rendered
# and SAVED ON THE SAFESEARCH PAGE; a bogus value coerces via ``$s_default='' ?:
# 'Disable'``. write_config() only -- hermetic.
#
# The DoH/DoT/DoQ fields (safesearch_doh / safesearch_doh_list) live in the SAME
# bare section but are rendered and SAVED ON THE DNSBL PAGE (ADR-29 foreign-section
# write via PfbConfig::write) -- so their tests POST to DNSBL_PAGE and need the
# sinkhole VIP (dnsbl_vip_ready), exactly like the other DNSBL-page saves. That save
# is ALL-OR-NOTHING: the doh-Enable-needs-a-list guard aborts the ENTIRE save (no
# field written); a non-key safesearch_doh coerces to 'Disable', a bogus doh_list key
# coerces to ''. write_config() only -- hermetic.
# --------------------------------------------------------------------------- #


def test_safesearch_enable_select_valid_and_bogus_coerces_to_disable(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``safesearch_enable`` stores a valid option; a bogus value coerces to 'Disable'.

    Select opts {Disable, Enable}; node default 'Disable'. Save validator coerces a
    non-key value to ``$s_default=''`` then ``?: 'Disable'`` rewrites '' to
    'Disable' -> a bogus POST stores 'Disable' (NOT the bogus token). Valid 'Enable'
    stores 'Enable'. CONFIG BASE is the BARE node (no /config/0). write_config()
    only -- hermetic.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngsafesearch/safesearch_enable"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "Enable", f"safesearch_enable already 'Enable' before the valid POST (original={original!r})"
        # VALID 'Enable' -> stored.
        assert _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_enable": "Enable"}, cfg) == "Enable"
        # Restore to 'Disable' (the default baseline).
        assert _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_enable": "Disable"}, cfg) == "Disable"
        # BOGUS -> coerced to 'Disable'.
        got = _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_enable": "Bogus"}, cfg)
        assert got == "Disable", f"bogus safesearch_enable should coerce to 'Disable', got {got!r}"
    finally:
        webui.post(SAFESEARCH_PAGE, {"safesearch_enable": "Disable"}, timeout=SAVE_TIMEOUT)


def test_safesearch_youtube_select_three_branches_and_bogus(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``safesearch_youtube`` covers all three options + the bogus coercion.

    Select opts {Disable, Strict, Moderate} -- branch coverage drives EACH valid
    option: 'Strict' stores 'Strict', 'Moderate' stores 'Moderate' (the third
    branch), and a bogus value coerces via ``$s_default=''`` then ``?: 'Disable'``
    to 'Disable'. write_config() only -- hermetic.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngsafesearch/safesearch_youtube"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "Strict", f"safesearch_youtube already 'Strict' before the valid POST ({original!r})"
        # VALID 'Strict'.
        assert _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_youtube": "Strict"}, cfg) == "Strict"
        # VALID 'Moderate' -- the third option branch.
        assert _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_youtube": "Moderate"}, cfg) == "Moderate"
        # Restore to 'Disable'.
        assert _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_youtube": "Disable"}, cfg) == "Disable"
        # BOGUS -> 'Disable'.
        got = _post_and_get(webui, vm, SAFESEARCH_PAGE, {"safesearch_youtube": "Bogus"}, cfg)
        assert got == "Disable", f"bogus safesearch_youtube should coerce to 'Disable', got {got!r}"
    finally:
        webui.post(SAFESEARCH_PAGE, {"safesearch_youtube": "Disable"}, timeout=SAVE_TIMEOUT)


def test_safesearch_doh_select_valid_needs_list_and_bogus_coerces(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """``safesearch_doh`` stores 'Enable' (with a list) and coerces a bogus value to 'Disable'.

    Rendered and saved on the DNSBL page (ADR-29 foreign-section write into the bare
    pfblockerngsafesearch node). Select opts {Disable, Enable}. CAVEAT: 'Enable' with an
    EMPTY safesearch_doh_list raises an input_error that aborts the WHOLE save, so the
    valid branch MUST also supply a valid list (overrides include
    ``safesearch_doh_list='dns.google'``) -> node == 'Enable'. The BOGUS branch ('Bogus')
    is not a key of $options_safesearch_doh -> coerced to 'Disable' (the empty-list guard
    compares to the literal 'Enable', so a bogus value does not trip it). Needs the sinkhole
    VIP (``dnsbl_vip_ready``) -- every DNSBL save runs pfb_validate_vips. write_config()
    only -- hermetic.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngsafesearch/safesearch_doh"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "Enable", f"safesearch_doh already 'Enable' before the valid POST (original={original!r})"
        # VALID 'Enable' REQUIRES a non-empty list (else the guard aborts the save).
        got = _post_and_get(
            webui, vm, DNSBL_PAGE, {"safesearch_doh": "Enable", "safesearch_doh_list": "dns.google"}, cfg
        )
        assert got == "Enable", f"safesearch_doh should store 'Enable' with a valid list, got {got!r}"
        # Restore: doh back to 'Disable' and clear the list.
        assert (
            _post_and_get(webui, vm, DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, cfg)
            == "Disable"
        )
        # BOGUS doh -> coerced to 'Disable' (the empty-list guard only fires for literal 'Enable').
        got = _post_and_get(webui, vm, DNSBL_PAGE, {"safesearch_doh": "Bogus", "safesearch_doh_list": ""}, cfg)
        assert got == "Disable", f"bogus safesearch_doh should coerce to 'Disable', got {got!r}"
    finally:
        webui.post(DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, timeout=SAVE_TIMEOUT)


def test_safesearch_doh_list_multiselect_valid_and_bogus_clears(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """``safesearch_doh_list`` stores a valid key (CSV); a bogus key coerces to ''.

    Rendered and saved on the DNSBL page (ADR-29 foreign-section write); needs the
    sinkhole VIP (``dnsbl_vip_ready``) since every DNSBL save runs pfb_validate_vips.
    Multi-select, valid keys are the ~180 entries of ``$options_safesearch_doh_list``
    (e.g. 'dns.google', 'cloudflare-dns.com'), stored as a CSV via
    ``implode(',', (array)$_POST[...])``. The validator sets the field to '' when a
    submitted key is NOT in the opts map -> implode of '' -> '' stored (NOT the
    bogus value). A valid 'dns.google' -> 'dns.google'. We pair the list save with
    ``safesearch_doh='Disable'`` so the doh-Enable-needs-a-list guard never fires
    while exercising the list validator in isolation. An explicit override is
    required (scrape_form_fields harvests only the first <selected>/first option of
    the multi-select). write_config() only -- hermetic.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngsafesearch/safesearch_doh_list"
    original = helpers.config_get(vm, cfg)
    try:
        assert original != "dns.google", (
            f"safesearch_doh_list already 'dns.google' before the valid POST (original={original!r})"
        )
        # VALID single key -> stored verbatim (doh kept Disable so the guard is inert).
        got = _post_and_get(
            webui, vm, DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": "dns.google"}, cfg
        )
        assert got == "dns.google", f"safesearch_doh_list should store 'dns.google', got {got!r}"
        # Restore/clear to '' (empty list).
        got_clear = _post_and_get(webui, vm, DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, cfg)
        assert got_clear == "", f"clearing safesearch_doh_list should store '', got {got_clear!r}"
        # BOGUS key -> not in the opts map -> coerced to '' (NOT the bogus value).
        got = _post_and_get(
            webui,
            vm,
            DNSBL_PAGE,
            {"safesearch_doh": "Disable", "safesearch_doh_list": "evil.example.invalid"},
            cfg,
        )
        assert got == "", f"bogus safesearch_doh_list key should coerce to '', got {got!r}"
    finally:
        webui.post(DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, timeout=SAVE_TIMEOUT)


def test_safesearch_doh_enable_requires_list_guard(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """Enabling DoH with an EMPTY list aborts the whole save (config unchanged).

    Rendered and saved on the DNSBL page (ADR-29 foreign-section write); needs the
    sinkhole VIP (``dnsbl_vip_ready``) since every DNSBL save runs pfb_validate_vips.
    The input_error guard: ``$_POST['safesearch_doh']=='Enable' &&
    empty($_POST['safesearch_doh_list'])`` -> ``$input_errors`` -> the
    ``if (!$input_errors)`` save block is skipped -> NO write_config, config
    UNCHANGED. Two sub-cases on field safesearch_doh:

    * PASS: ``{safesearch_doh:'Enable', safesearch_doh_list:'dns.google'}`` -> guard
      NOT tripped -> node == 'Enable' AND the list == 'dns.google'.
    * REJECT: ``{safesearch_doh:'Enable', safesearch_doh_list:''}`` (explicit empty,
      defeating the scraped first-option default) -> guard fires -> the ENTIRE save
      aborts -> safesearch_doh stays at its prior value (the captured before-state),
      NOT 'Enable'.

    Because the save is all-or-nothing, the reject assertion is "config == its
    pre-POST value". write_config() only on the pass path; no write on reject.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngsafesearch/safesearch_doh"
    list_cfg = "installedpackages/pfblockerngsafesearch/safesearch_doh_list"
    # Establish a known before-state: doh Disable, no list.
    webui.post(DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, timeout=SAVE_TIMEOUT)
    before = helpers.config_get(vm, cfg)
    try:
        # BEFORE: doh is 'Disable' (not 'Enable').
        assert before == "Disable", f"expected safesearch_doh 'Disable' baseline, got {before!r}"
        # PASS path: Enable WITH a valid list -> persists both fields.
        got = _post_and_get(
            webui, vm, DNSBL_PAGE, {"safesearch_doh": "Enable", "safesearch_doh_list": "dns.google"}, cfg
        )
        assert got == "Enable", f"safesearch_doh should persist 'Enable' with a valid list, got {got!r}"
        assert helpers.config_get(vm, list_cfg) == "dns.google", "safesearch_doh_list not persisted on the pass path"
        # Reset to the Disable baseline before the reject leg.
        assert (
            _post_and_get(webui, vm, DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, cfg)
            == "Disable"
        )
        # REJECT path: Enable WITHOUT a list -> the whole save aborts -> UNCHANGED.
        got = _post_and_get(webui, vm, DNSBL_PAGE, {"safesearch_doh": "Enable", "safesearch_doh_list": ""}, cfg)
        assert got == "Disable", f"DoH-Enable-with-empty-list must abort the save (config unchanged), got {got!r}"
    finally:
        webui.post(DNSBL_PAGE, {"safesearch_doh": "Disable", "safesearch_doh_list": ""}, timeout=SAVE_TIMEOUT)


# --------------------------------------------------------------------------- #
# DNSBL settings (installedpackages/pfblockerngdnsblsettings/config/0). Save is
# ALL-OR-NOTHING: any validation failure aborts the ENTIRE save -> config
# UNCHANGED (so each reject_result is 'unchanged'). PRECONDITION: dnsbl_vip_ready
# (the lo0 VIP + ports) -- every save runs pfb_validate_vips + is_port, else an
# unrelated input_error aborts every save. write_config() only -- hermetic.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field", "valid", "current_default", "bogus", "errlabel"),
    [
        ("pfb_dnsport", "8082", "8081", "99999", "DNSBL Port"),
        ("pfb_dnsport_ssl", "8444", "8443", "abc", "DNSBL SSL Port"),
    ],
    ids=["pfb_dnsport", "pfb_dnsport_ssl"],
)
def test_dnsbl_port_is_port_valid_and_reject_unchanged(
    field: str,
    valid: str,
    current_default: str,
    bogus: str,
    errlabel: str,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """A DNSBL port field accepts a valid port; a bad port aborts the whole save.

    ``is_port($_POST[field])``: a bogus value (99999 > 65535, or non-numeric 'abc')
    -> is_port FALSE -> ``$input_errors`` ('<label> is invalid!') -> the WHOLE save
    aborts -> node UNCHANGED. A valid port is stored verbatim. The fixture default
    is the listed ``current_default`` (8081/8443), so the VALID probe is a DIFFERENT
    valid port (8082/8444) to satisfy the before/after transition rule (prove the
    POST CAUSED the change). Restore to the fixture default afterward.
    """
    vm = smoke_vm
    cfg = f"installedpackages/pfblockerngdnsblsettings/config/0/{field}"
    original = helpers.config_get(vm, cfg)
    # Restore target: whatever was there, else the documented default.
    restore = original or current_default
    try:
        assert original != valid, f"{field} already {valid!r} before the valid POST (original={original!r})"
        # VALID port distinct from the current value -> stored verbatim.
        assert _post_and_get(webui, vm, DNSBL_PAGE, {field: valid}, cfg) == valid
        # Restore the original valid port.
        assert _post_and_get(webui, vm, DNSBL_PAGE, {field: restore}, cfg) == restore
        # REJECT: a bad port aborts the whole save -> config UNCHANGED.
        got = _post_and_get(webui, vm, DNSBL_PAGE, {field: bogus}, cfg)
        assert got == restore, f"bogus {field} must leave config unchanged at {restore!r}, got {got!r}"
    finally:
        webui.post(DNSBL_PAGE, {field: restore}, timeout=SAVE_TIMEOUT)


def test_dnsbl_py_cache_max_unlimited_and_reject_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """``pfb_py_cache_max`` accepts 0 (unlimited); a >5M value aborts the whole save.

    Validation: non-empty AND (NOT ctype_digit OR int > 5_000_000) -> input_error
    -> the WHOLE save aborts -> node UNCHANGED. So a bogus 9999999 (>5M, or a
    non-digit) leaves the prior value (NOT coerced to 10000 here -- the 10000
    fallback fires ONLY for an EMPTY post value, a separate coerce path). Valid '0'
    is meaningful (unlimited) and KEPT (``ctype_digit('0')`` true -> stored '0').
    The current default is 10000, so 0 is a real transition. Restore to 10000.
    """
    vm = smoke_vm
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_cache_max"
    original = helpers.config_get(vm, cfg)
    restore = original or "10000"
    try:
        assert original != "0", f"pfb_py_cache_max already '0' before the valid POST (original={original!r})"
        # VALID '0' (unlimited) -> stored verbatim.
        assert _post_and_get(webui, vm, DNSBL_PAGE, {"pfb_py_cache_max": "0"}, cfg) == "0"
        # Restore the prior value (the 10000 default baseline).
        assert _post_and_get(webui, vm, DNSBL_PAGE, {"pfb_py_cache_max": restore}, cfg) == restore
        # REJECT: >5M aborts the whole save -> config UNCHANGED.
        got = _post_and_get(webui, vm, DNSBL_PAGE, {"pfb_py_cache_max": "9999999"}, cfg)
        assert got == restore, f"bogus pfb_py_cache_max must leave config unchanged at {restore!r}, got {got!r}"
    finally:
        webui.post(DNSBL_PAGE, {"pfb_py_cache_max": restore}, timeout=SAVE_TIMEOUT)


def test_dnsbl_regex_list_ascii_base64_and_reject_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """``pfb_regex_list`` accepts ASCII (stored base64); a non-ASCII value aborts the save.

    Non-ASCII guard: ``!mb_detect_encoding($_POST['pfb_regex_list'], 'ASCII', TRUE)``
    -> input_error -> the WHOLE save aborts -> node UNCHANGED. STORED AS BASE64
    (``base64_encode`` on save, ``base64_decode`` on render), so the oracle compares
    config_get against base64 of the posted text. A valid ASCII '^ads\\.' stores
    base64('^ads\\.'); a 'café' (non-ASCII byte) is rejected -> config unchanged.
    NO egress.
    """
    import base64

    vm = smoke_vm
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_list"
    valid_text = "^ads\\."
    valid_b64 = base64.b64encode(valid_text.encode()).decode()
    original = helpers.config_get(vm, cfg)
    try:
        assert original != valid_b64, f"pfb_regex_list already holds {valid_text!r} (base64) before the valid POST"
        # VALID ASCII regex -> base64 of the text is stored.
        assert _post_and_get(webui, vm, DNSBL_PAGE, {"pfb_regex_list": valid_text}, cfg) == valid_b64
        # Restore/clear to '' (empty textarea -> base64('') -> '').
        got_clear = _post_and_get(webui, vm, DNSBL_PAGE, {"pfb_regex_list": ""}, cfg)
        assert got_clear == "", f"clearing pfb_regex_list should store '', got {got_clear!r}"
        # REJECT: a non-ASCII value aborts the whole save -> config UNCHANGED (stays '').
        got = _post_and_get(webui, vm, DNSBL_PAGE, {"pfb_regex_list": "café"}, cfg)
        assert got == "", f"non-ASCII pfb_regex_list must leave config unchanged at '', got {got!r}"
    finally:
        restore = ""
        if original:
            try:
                restore = base64.b64decode(original).decode()
            except Exception:
                restore = ""
        webui.post(DNSBL_PAGE, {"pfb_regex_list": restore}, timeout=SAVE_TIMEOUT)


def test_dnsbl_adv_inbound_proto_any_guard(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """Advanced inbound rules with protocol 'Any' abort the save; a real proto persists.

    Guard: IF ``autoports_in`` OR ``autoaddr_in`` is set AND ``autoproto_in`` is
    empty or 'any' -> input_error ("Protocol setting cannot be set to 'Any' with
    Advanced Inbound firewall rule settings.") -> the WHOLE save aborts -> config
    UNCHANGED. REQUIRES TWO FIELDS in the same POST:

    * PASS: ``autoports_in='on'`` + ``autoproto_in='tcp'`` -> save SUCCEEDS,
      autoproto_in stores 'tcp' ('tcp' is a key of get_ipprotocols() so it survives
      the select-coercion).
    * REJECT: ``autoports_in='on'`` + ``autoproto_in='any'`` -> guard fires -> save
      aborts -> autoproto_in UNCHANGED (its prior value).

    CLEANUP restores autoports_in='' and autoproto_in to its prior value so the box
    is not left with adv-inbound enabled. NO egress.
    """
    vm = smoke_vm
    proto_cfg = "installedpackages/pfblockerngdnsblsettings/config/0/autoproto_in"
    ports_cfg = "installedpackages/pfblockerngdnsblsettings/config/0/autoports_in"
    proto_orig = helpers.config_get(vm, proto_cfg)
    ports_orig = helpers.config_get(vm, ports_cfg)
    try:
        # BEFORE: autoproto_in is not 'tcp' (so the PASS leg is a real transition).
        assert proto_orig != "tcp", f"autoproto_in already 'tcp' before the valid POST (original={proto_orig!r})"
        # PASS: adv-inbound ports ON + a concrete protocol -> save succeeds, stores 'tcp'.
        got = _post_and_get(webui, vm, DNSBL_PAGE, {"autoports_in": "on", "autoproto_in": "tcp"}, proto_cfg)
        assert got == "tcp", f"autoproto_in should store 'tcp' with adv-inbound ports on, got {got!r}"
        assert helpers.config_get(vm, ports_cfg) == "on", "autoports_in not persisted on the pass path"
        # Reset autoproto_in to a concrete value baseline before the reject leg
        # (clear adv-inbound first so this intermediate save is itself valid).
        _post_and_get(webui, vm, DNSBL_PAGE, {"autoports_in": "", "autoproto_in": proto_orig or "any"}, proto_cfg)
        proto_baseline = helpers.config_get(vm, proto_cfg)
        # REJECT: adv-inbound ports ON + proto 'any' -> guard fires -> save aborts,
        # config UNCHANGED (autoproto_in stays at proto_baseline; ports stays cleared).
        got = _post_and_get(webui, vm, DNSBL_PAGE, {"autoports_in": "on", "autoproto_in": "any"}, proto_cfg)
        assert got == proto_baseline, (
            f"adv-inbound 'Any' guard must abort the save (autoproto_in unchanged at {proto_baseline!r}), got {got!r}"
        )
        assert helpers.config_get(vm, ports_cfg) != "on", "the rejected save must not have enabled autoports_in"
    finally:
        # Leave adv-inbound OFF and autoproto_in at its original value.
        webui.post(DNSBL_PAGE, {"autoports_in": ports_orig, "autoproto_in": proto_orig or "any"}, timeout=SAVE_TIMEOUT)


# --------------------------------------------------------------------------- #
# ADR-13 "Create VIPs automatically" (pfb_dnsvip_auto) -- driven via the DNSBL FORM
#
# The auto-VIP LIFECYCLE (config toggle -> VIP created/removed -> DNS sinks) is
# already covered by the smoke matrix (test_smoke_matrix.py) via the config helper
# `set_dnsvip_auto`. The UI tier's DISTINCT value is proving the DNSBL settings
# PAGE persists pfb_dnsvip_auto through a real CSRF form POST, with the same
# package machinery (pfb_create_dnsbl -> pfb_manage_dnsbl_vip) then provisioning
# the marked VIP end-to-end. Auto picks 172.16.53.53 (issue #473's first Class-B
# candidate, free in this topology), distinct from the manual VIP at 10.10.10.1
# (dnsbl_vip_ready), so the two coexist on one VM.
#
# TODO(ADR-12): add update-hooks UI coverage (add/toggle/remove a hook row + its
# config persistence) once ADR-12 lands on devel -- it is not merged there yet.
# --------------------------------------------------------------------------- #

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
AUTO_VIP_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto"


def test_dnsvip_auto_form_provisions_and_removes_marked_vip(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,
) -> None:
    """Ticking 'Create VIPs automatically' in the DNSBL FORM provisions the marked VIP.

    UI-faithful end-to-end with the CLAUDE.md transition rule (assert before-state,
    then prove the form POST caused the change):

    * BEFORE: pfb_dnsvip_auto is off in config and no package-owned pfB_AUTO_VIP_v4
      exists.
    * ENABLE via the form: the CSRF POST must PERSIST pfb_dnsvip_auto=on (the
      UI-specific assertion -- config.xml, not the HTTP body); the next Force
      Update runs pfb_create_dnsbl('enabled') -> pfb_manage_dnsbl_vip, which
      creates the marked VIP at 172.16.53.53 and brings it up live on lo0.
    * DISABLE via the form: the POST persists it off; a Force Update removes the
      marked VIP from config AND lo0.

    Oracle = effective box state (marked_vip_subnet / ifconfig), never the HTTP
    response. The manual VIP at 10.10.10.1 (dnsbl_vip_ready) is untouched. Left
    clean (auto off, marked VIP gone) for the sibling flows in `finally`.

    A DNSBL alias must be configured (write_local_feed + inject) for the Force
    Update to actually run pfb_create_dnsbl('enabled') -> pfb_manage_dnsbl_vip: a
    bare `update` with no DNSBL list does NOT reach the VIP-provisioning pass (the
    same setup the smoke matrix uses via CaseContext). The feed is a LOCAL file
    under /var/db/pfblockerng, so the update needs no egress. reload uses the full
    `update` scope (not the targeted `updatednsbl`, which skips the VIP pass), with
    egress open -- so this drives inject()+reload() directly rather than via
    CaseContext (whose body runs with egress BLOCKED).
    """
    vm = smoke_vm
    # A DNSBL list so the Force Update has work and runs the VIP-provisioning pass.
    domain = helpers.unique_domain("uiautovip")
    feed_path = helpers.write_local_feed(vm, "ui_autovip.txt", f"{domain}\n")
    spec = helpers.DnsblCase(aliasname="uiautovip", feed_url=feed_path, header="uiautovip", mode=helpers.DnsblMode.VIP)
    # DNSBL must be enabled so the Force Update runs pfb_create_dnsbl in 'enabled'
    # mode; configure the alias; start from a known baseline (auto off).
    helpers.set_dnsbl_enabled(vm, True)
    helpers.set_dnsvip_auto(vm, False)
    helpers.inject(vm, spec)
    try:
        # BEFORE.
        assert helpers.config_get(vm, AUTO_VIP_CFG) != "on", "pfb_dnsvip_auto already on before the form POST"
        assert helpers.marked_vip_subnet(vm, helpers.AUTO_VIP_DESCR_V4) == "", (
            "pfB_AUTO_VIP_v4 present before auto-create was enabled via the form"
        )

        # ENABLE through the real DNSBL form; the PAGE must persist the setting.
        resp = webui.post(DNSBL_PAGE, {"pfb_dnsvip_auto": "on"}, timeout=300.0)
        assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"
        assert helpers.config_get(vm, AUTO_VIP_CFG) == "on", (
            "the DNSBL form POST did not persist pfb_dnsvip_auto=on to config.xml"
        )
        # The next full Force Update provisions the marked VIP (same path as the matrix).
        helpers.reload(vm, "update")
        assert helpers.marked_vip_subnet(vm, helpers.AUTO_VIP_DESCR_V4) == helpers.AUTO_VIP_IP4, (
            f"auto VIP not created at {helpers.AUTO_VIP_IP4} after the form enabled it: "
            f"got {helpers.marked_vip_subnet(vm, helpers.AUTO_VIP_DESCR_V4)!r}"
        )
        assert helpers.vip_alias_live(vm, helpers.AUTO_VIP_IP4), (
            f"auto VIP {helpers.AUTO_VIP_IP4} not live on lo0 (ifconfig) after the form enabled it"
        )

        # DISABLE through the form; persisted off, then the Force Update removes it.
        resp = webui.post(DNSBL_PAGE, {"pfb_dnsvip_auto": ""}, timeout=300.0)
        assert not looks_like_login_page(resp.text), "DNSBL un-POST returned the login form"
        assert helpers.config_get(vm, AUTO_VIP_CFG) != "on", "the DNSBL form POST did not clear pfb_dnsvip_auto"
        helpers.reload(vm, "update")
        assert helpers.marked_vip_subnet(vm, helpers.AUTO_VIP_DESCR_V4) == "", (
            "auto VIP not removed from config after unticking the form setting"
        )
        assert not helpers.vip_alias_live(vm, helpers.AUTO_VIP_IP4), (
            f"auto VIP {helpers.AUTO_VIP_IP4} still live on lo0 after the form disabled it"
        )
    finally:
        # Leave the box clean for the sibling flows: auto off + drop the derived
        # state (reset = clearip/cleardnsbl + a blocking filter sync).
        helpers.set_dnsvip_auto(vm, False)
        helpers.reset(vm)


# ---------------------------------------------------------------------------
# ADR-43 Phase 6 — Update page Run Now updates the due ledger
# ---------------------------------------------------------------------------

_ENABLE_CB_CFG = "installedpackages/pfblockerng/config/0/enable_cb"
_LEDGER_PATH = f"{helpers.PFB_DBDIR}/pfb_due_ledger.json"


def test_update_runnow_scope_guard_and_ledger(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Phase-6 Run Now only advances the cron ledger entry when scope=both.

    Scenario: scope-guard — partial scope=ip must NOT advance cron.last_run.
      Background: pfBlockerNG deployed and enabled; no feeds configured (fast run).

    Given pfBlockerNG is enabled,
    And the VM clock is captured as before_ts,

    When the Update page Run Now form is submitted with scope=ip and force unchecked,

    Then the ``pfb_due_ledger.json`` 'cron' entry is UNCHANGED (last_run < before_ts) —
      proving pfb_runnow() guards mark_ran('cron') to scope=both only;

    When the Update page Run Now form is submitted a second time with scope=both,

    Then the 'cron' entry shows last_run >= before_ts —
      proving the full-pass scope=both DOES advance the ledger.

    The BEFORE assertion establishes the pre-state; the two-step ACT proves the guard
    fires on scope=ip and releases on scope=both (transition evidence per mandate).
    """
    vm = smoke_vm
    # Ensure pfBlockerNG is enabled; restore the original state at the end.
    original_enabled = helpers.config_get(vm, _ENABLE_CB_CFG)
    if original_enabled != "on":
        helpers.set_package_enabled(vm, True)

    try:
        # BEFORE: capture VM wall-clock timestamp so we can assert last_run was set
        # by THIS run and not an earlier one.  Use the VM clock (not the runner clock)
        # to avoid a cross-host time discrepancy.
        before_ts = int(vm.ssh("/bin/date", "+%s").stdout.strip())

        # BEFORE-state assertion: if a cron ledger entry exists, its last_run is older.
        pre = vm.ssh("/bin/cat", _LEDGER_PATH)
        if pre.returncode == 0:
            pre_data = json.loads(pre.stdout)
            pre_last = pre_data.get("cron", {}).get("last_run", 0)
            assert pre_last < before_ts, (
                f"cron.last_run ({pre_last}) already >= before_ts ({before_ts}) "
                "before the Run Now POST — cannot confirm the POST caused the update"
            )

        # ACT 1: POST scope=ip — a partial run; the cron ledger must NOT advance.
        # pfb_runnow() dispatches a detached process and returns immediately (the live log is
        # AJAX-polled since #671); mark_ran('cron') still runs synchronously in the page process,
        # so the ledger assertions below read the intended state regardless of the run's progress.
        resp = webui.post(
            UPDATE_PAGE,
            overrides={"pfb_scope": "ip"},
            submit=("run", "Run Now"),
            timeout=SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp.text), "scope=ip POST returned the login form (session lost)"

        # AFTER scope=ip: cron ledger must be UNCHANGED — the scope-guard fires.
        result = vm.ssh("/bin/cat", _LEDGER_PATH, timeout=30.0)
        cron_last_after_ip = 0
        if result.returncode == 0:
            ledger_ip = json.loads(result.stdout)
            cron_last_after_ip = ledger_ip.get("cron", {}).get("last_run", 0)
        assert cron_last_after_ip < before_ts, (
            f"ledger cron.last_run={cron_last_after_ip} >= before_ts={before_ts} after scope=ip — "
            "pfb_runnow() must NOT call mark_ran('cron') for a partial scope=ip run "
            "(would suppress the next DNSBL-inclusive full pass)"
        )

        # Run Now no longer blocks (the live log is AJAX-polled, #671), so the scope=ip dispatched
        # process may still be alive. Wait for it to exit before the next POST — otherwise
        # pfb_active_task_running() would refuse the scope=both dispatch and the cron ledger would
        # not advance (a race the old blocking pfb_livetail() masked). Mirrors isvalidpid: read the
        # pidfile daemon(8) self-clears on exit and probe the pid with kill -0.
        def _runnow_idle() -> bool:
            probe = vm.ssh(
                "/bin/sh",
                "-c",
                "p=$(cat /var/run/pfb_runnow.pid 2>/dev/null); "
                'if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then echo up; else echo down; fi',
            )
            return probe.stdout.strip() == "down"

        assert helpers.wait_until(_runnow_idle, timeout=25.0), (
            "scope=ip Run Now process did not exit before the scope=both POST — "
            "pfb_active_task_running() would refuse the next dispatch"
        )

        # ACT 2: POST scope=both — a full-pass run; the cron ledger MUST advance.
        ts_before_both = int(vm.ssh("/bin/date", "+%s").stdout.strip())
        resp2 = webui.post(
            UPDATE_PAGE,
            overrides={"pfb_scope": "both"},
            submit=("run", "Run Now"),
            timeout=SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp2.text), "scope=both POST returned the login form (session lost)"

        # AFTER scope=both: cron ledger must reflect the full-pass run.
        result2 = vm.ssh("/bin/cat", _LEDGER_PATH, timeout=30.0)
        assert result2.returncode == 0, (
            f"pfb_due_ledger.json not found after scope=both Run Now "
            f"(rc={result2.returncode} stderr={result2.stderr!r}) — "
            "pfb_due_ledger_mark_ran() may not have been called"
        )
        ledger_both = json.loads(result2.stdout)
        assert "cron" in ledger_both, f"ledger has no 'cron' key after scope=both: {ledger_both!r}"
        last_run_both = ledger_both["cron"].get("last_run", 0)
        assert last_run_both >= ts_before_both, (
            f"ledger cron.last_run={last_run_both} < ts_before_both={ts_before_both} after scope=both — "
            "Run Now with scope=both must advance the cron ledger entry"
        )

        # Re-render the Update page and confirm the Schedule section is present.
        page_resp = webui.get(UPDATE_PAGE)
        assert "Schedule" in page_resp.text, (
            "Schedule section missing after Run Now re-render — ledger section not rendered"
        )

    finally:
        if original_enabled != "on":
            helpers.set_package_enabled(vm, False)


def test_update_page_cron_status_reports_scheduled_tick(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Cron Status reports the scheduled tick, NOT "[ Missing cron task ]".

    ADR-43 installs ONE ``*/pfb_tick_interval`` cron tick whenever pfBlockerNG is
    enabled. The Update page previously probed the crontab with the legacy
    interval/min/24hour signature, which never matches that tick, so it falsely
    rendered "[ Missing cron task ]" and a time derived from the feed cadence. This
    pins the fix: with the tick installed, the page must report the next-tick
    wall-clock time and time-remaining instead.

    issue #1204 renamed the installed verb to ``cron-tick`` and added the harness's
    always-on ``.pfb_cron_disable`` sentinel (:func:`~tests.smoke.helpers.deploy`);
    the sentinel outranks this page's enabled/missing-cron arms (it would otherwise
    always show its own banner instead of the HH:MM time this test pins), so it is
    removed for the render and restored in a finally.

    Scenario:
      Given pfBlockerNG is enabled, a full reload has installed the cron-tick cron,
        and the harness sentinel is removed,
      And /etc/crontab actually contains the ``pfblockerng.php cron-tick`` entry
        (precondition, so "not Missing" is meaningful and not a false pass from a
        disabled box),
      When the Update page is rendered,
      Then the Cron Status shows "NEXT Scheduled CRON Event will run at" and does NOT
        contain "[ Missing cron task ]", and renders a HH:MM next-tick time (unless a
        run happens to be active at render time).

    Red→green: before the fix, pfblockerng_cron_exists() was called with the legacy
    minute/hour fields, so this asserted body still contained "[ Missing cron task ]".
    """
    vm = smoke_vm
    flag = helpers.PFB_CRON_DISABLE_PATH
    original_enabled = helpers.config_get(vm, _ENABLE_CB_CFG)
    if original_enabled != "on":
        helpers.set_package_enabled(vm, True)
    rm = vm.ssh("rm", "-f", flag)
    assert rm.returncode == 0, f"failed to remove {flag}: rc={rm.returncode} {rm.stderr!r}"
    try:
        # Install/refresh the cron-tick cron via a full reload (no feeds configured => no egress).
        helpers.reload(vm, "update")

        # PRECONDITION (effective state, not the HTTP body): the cron-tick IS in the crontab.
        crontab = vm.ssh("/usr/bin/grep", "pfblockerng.php cron-tick", "/etc/crontab")
        assert crontab.returncode == 0 and "cron-tick" in crontab.stdout, (
            "cron-tick cron absent from /etc/crontab after an enabled reload "
            f"(rc={crontab.returncode} stdout={crontab.stdout!r}) — "
            "cannot assert the page reports a scheduled tick"
        )

        body = webui.get(UPDATE_PAGE).text
        assert not looks_like_login_page(body), "Update page GET returned the login form (session lost)"
        assert "Missing cron task" not in body, (
            "Cron Status still shows '[ Missing cron task ]' although the cron-tick cron IS "
            "installed — the page must probe the */N cron-tick signature, not the legacy "
            "interval/min/24hour cron"
        )
        assert "NEXT Scheduled CRON Event will run at" in body, "Cron Status header missing from the Update page"
        # The next-tick HH:MM time, unless a run is active at render (which replaces the
        # status line with the spinner) — accept either so the assertion is not racy.
        at = body.find("will run at")
        excerpt = body[at : at + 160] if at >= 0 else ""
        assert re.search(r"\d{2}:\d{2}", excerpt) or "Active pfBlockerNG CRON JOB" in body, (
            f"no HH:MM next-tick time rendered in the Cron Status; excerpt={excerpt!r}"
        )
    finally:
        touch = vm.ssh("/usr/bin/touch", flag)
        if touch.returncode != 0:
            raise AssertionError(f"failed to restore {flag}: rc={touch.returncode} {touch.stderr!r}")
        if original_enabled != "on":
            helpers.set_package_enabled(vm, False)


# ---------------------------------------------------------------------------
# Force mode — Download / Both sidecar-clear wiring (ADR-43)
#
# These tests prove that pfb_force_clear_validators() is called by the handler
# and clears the right sidecar files before dispatching forcecheck.
#
# Full re-fetch / reload-if-changed / reload-all behaviour requires configured
# feeds and is validated on a maintainer live-VM run; the hermetic harness has
# no feeds, so these tests pin the side-effect (sidecar removal) only.
# ---------------------------------------------------------------------------

_IP_ORIG_DIR = f"{helpers.PFB_DBDIR}/original"
_DNSBL_ORIG_DIR = f"{helpers.PFB_DBDIR}/dnsblorig"


def test_force_mode_download_clears_validators(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Force=Download clears .orig.etag before dispatching forcecheck.

    Scenario: Download mode removes validator sidecars for in-scope feeds.
      Background: pfBlockerNG deployed and enabled.

    Given a synthetic feedA.orig.etag sidecar planted in the IP orig dir,
    And the .orig.etag file EXISTS (pre-state confirmed),

    When the Update page Run Now form is submitted with pfb_force_mode=download
      and pfb_scope=ip,

    Then the .orig.etag sidecar is GONE (the handler cleared it before dispatch) —
      proving pfb_force_clear_validators() was called with the correct dir and
      clear_hashes=FALSE.

    Red→green: before this change, force=download did not exist and no sidecar
    was cleared; the test would fail on the assertFileDoesNotExist equivalent.
    """
    vm = smoke_vm
    original_enabled = helpers.config_get(vm, _ENABLE_CB_CFG)
    if original_enabled != "on":
        helpers.set_package_enabled(vm, True)

    # Plant a synthetic validator sidecar under the IP orig dir.
    sidecar_etag = f"{_IP_ORIG_DIR}/pfbtest.orig.etag"
    try:
        # Ensure the orig dir exists and plant the sidecar.
        mk = subprocess.run(
            vm.ssh_argv("/bin/mkdir", "-p", _IP_ORIG_DIR),
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
        assert mk.returncode == 0, f"mkdir {_IP_ORIG_DIR} failed: {mk.stderr!r}"

        plant = subprocess.run(
            vm.ssh_argv("tee", sidecar_etag),
            input='"test-etag-download"',
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
        assert plant.returncode == 0, f"plant {sidecar_etag} failed: {plant.stderr!r}"

        # BEFORE: confirm the sidecar exists.
        before = vm.ssh("/bin/test", "-f", sidecar_etag)
        assert before.returncode == 0, f"{sidecar_etag} not found after planting — cannot prove the POST caused removal"

        # ACT: POST force_mode=download, scope=ip. Wait for a quiescent box first — the page's
        # guard skips Run Now (and the sidecar clear) if a prior test's run is still alive.
        helpers.wait_no_active_pfb_task(vm)
        resp = webui.post(
            UPDATE_PAGE,
            overrides={"pfb_scope": "ip", "pfb_force_mode": "download"},
            submit=("run", "Run Now"),
            timeout=SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp.text), "force=download POST returned the login form (session lost)"

        # AFTER: the .etag sidecar must be gone (handler cleared it).
        after = vm.ssh("/bin/test", "-f", sidecar_etag)
        assert after.returncode != 0, (
            f"{sidecar_etag} still exists after force=download POST — "
            "pfb_force_clear_validators(clear_hashes=FALSE) was not called for scope=ip"
        )

    finally:
        # Clean up: remove any leftover sidecar; restore enable state.
        vm.ssh("/bin/rm", "-f", sidecar_etag)
        if original_enabled != "on":
            helpers.set_package_enabled(vm, False)


def test_force_mode_both_clears_hash_sidecars(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Force=Both clears .orig.etag AND .orig.xxhash128 before dispatching forcecheck.

    Scenario: Both mode removes validator AND hash sidecars in EVERY in-scope orig dir.

    Given synthetic pfbtest.orig.etag AND pfbtest.orig.xxhash128 planted in BOTH the IP
      orig dir and the DNSBL orig dir,
    And all four files EXIST (pre-state confirmed),

    When the Update page is submitted with pfb_force_mode=both and pfb_scope=both,

    Then all four sidecars are GONE — proving pfb_force_clear_validators(clear_hashes=TRUE)
      ran over the scope=both dir set (both $pfb['origdir'] and $pfb['dnsorigdir']).

    scope=both is used deliberately so this covers the both-branch of the handler's
    scope→dirs map (both dirs at once); scope=dnsbl-alone is symmetric to the scope=ip
    download test and is the one documented out-of-CI gap.

    Red→green: before this change, force=both did not exist; no sidecar was cleared.
    """
    vm = smoke_vm
    original_enabled = helpers.config_get(vm, _ENABLE_CB_CFG)
    if original_enabled != "on":
        helpers.set_package_enabled(vm, True)

    # One etag + one hash sidecar in EACH in-scope orig dir (IP + DNSBL).
    planted = [
        (f"{_IP_ORIG_DIR}/pfbtest.orig.etag", '"test-etag-both"'),
        (f"{_IP_ORIG_DIR}/pfbtest.orig.xxhash128", "deadbeef"),
        (f"{_DNSBL_ORIG_DIR}/pfbtest.orig.etag", '"test-etag-both"'),
        (f"{_DNSBL_ORIG_DIR}/pfbtest.orig.xxhash128", "deadbeef"),
    ]
    try:
        for orig_dir in (_IP_ORIG_DIR, _DNSBL_ORIG_DIR):
            mk = subprocess.run(
                vm.ssh_argv("/bin/mkdir", "-p", orig_dir),
                capture_output=True,
                text=True,
                timeout=30.0,
                check=False,
            )
            assert mk.returncode == 0, f"mkdir {orig_dir} failed: {mk.stderr!r}"

        for path, content in planted:
            p = subprocess.run(
                vm.ssh_argv("tee", path),
                input=content,
                capture_output=True,
                text=True,
                timeout=30.0,
                check=False,
            )
            assert p.returncode == 0, f"plant {path} failed: {p.stderr!r}"

        # BEFORE: every planted sidecar must exist.
        for path, _ in planted:
            r = vm.ssh("/bin/test", "-f", path)
            assert r.returncode == 0, f"{path} not found before POST — cannot prove the POST caused removal"

        # ACT: scope=both exercises both orig dirs. Wait for a quiescent box first — the page's
        # guard skips Run Now (and the sidecar clear) if a prior test's run is still alive.
        helpers.wait_no_active_pfb_task(vm)
        resp = webui.post(
            UPDATE_PAGE,
            overrides={"pfb_scope": "both", "pfb_force_mode": "both"},
            submit=("run", "Run Now"),
            timeout=SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp.text), "force=both POST returned the login form (session lost)"

        # AFTER: every sidecar (etag + hash) in BOTH dirs must be gone.
        for path, _ in planted:
            r = vm.ssh("/bin/test", "-f", path)
            assert r.returncode != 0, (
                f"{path} still exists after force=both/scope=both POST — "
                "pfb_force_clear_validators(clear_hashes=TRUE) did not clear this in-scope orig dir"
            )

    finally:
        for path, _ in planted:
            vm.ssh("/bin/rm", "-f", path)
        if original_enabled != "on":
            helpers.set_package_enabled(vm, False)


def test_force_mode_parse_keeps_sidecars(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Force=Parse reparses cached lists (reuse=on) and does NOT clear any sidecars.

    Scenario: Parse is the one Force mode that takes the reuse=on path — reparse cached,
      no re-download — so it must NOT touch the conditional-GET sidecars (unlike
      Download/Both, which clear them to force a re-fetch).

    Given a synthetic pfbtest.orig.etag in the IP orig dir,
    And the .orig.etag EXISTS (pre-state confirmed),

    When the Update page is submitted with pfb_force_mode=parse and pfb_scope=ip,

    Then the .orig.etag sidecar STILL EXISTS afterwards — proving Parse routes to
      pfb_runnow(force=TRUE) and does NOT call pfb_force_clear_validators.

    Red→green: before this change there was no pfb_force_mode dispatch split; this pins
    that Parse and Download/Both take different paths (the former never clears sidecars).
    """
    vm = smoke_vm
    original_enabled = helpers.config_get(vm, _ENABLE_CB_CFG)
    if original_enabled != "on":
        helpers.set_package_enabled(vm, True)

    sidecar_etag = f"{_IP_ORIG_DIR}/pfbtest.orig.etag"
    try:
        mk = subprocess.run(
            vm.ssh_argv("/bin/mkdir", "-p", _IP_ORIG_DIR),
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
        assert mk.returncode == 0, f"mkdir {_IP_ORIG_DIR} failed: {mk.stderr!r}"

        plant = subprocess.run(
            vm.ssh_argv("tee", sidecar_etag),
            input='"test-etag-parse"',
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
        assert plant.returncode == 0, f"plant {sidecar_etag} failed: {plant.stderr!r}"

        # BEFORE: the sidecar exists.
        before = vm.ssh("/bin/test", "-f", sidecar_etag)
        assert before.returncode == 0, f"{sidecar_etag} not found after planting — cannot prove non-removal"

        # ACT: Parse. Wait for quiescence first (the page skips Run Now if a task runs).
        helpers.wait_no_active_pfb_task(vm)
        resp = webui.post(
            UPDATE_PAGE,
            overrides={"pfb_scope": "ip", "pfb_force_mode": "parse"},
            submit=("run", "Run Now"),
            timeout=SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp.text), "force=parse POST returned the login form (session lost)"

        # AFTER: Parse must NOT clear the sidecar (reuse=on path, not the forcecheck clear).
        after = vm.ssh("/bin/test", "-f", sidecar_etag)
        assert after.returncode == 0, (
            f"{sidecar_etag} was removed after force=parse POST — Parse must take the reuse=on "
            "path (reparse cached, no sidecar clear), NOT the Download/Both clear path"
        )
    finally:
        vm.ssh("/bin/rm", "-f", sidecar_etag)
        if original_enabled != "on":
            helpers.set_package_enabled(vm, False)
