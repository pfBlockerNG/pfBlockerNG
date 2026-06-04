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

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from .. import helpers
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
FLOWS: tuple[ToggleFlow, ...] = (
    ToggleFlow(
        name="general_keep_settings",
        page="/pfblockerng/pfblockerng_general.php",
        field="pfb_keep",
        config_path="installedpackages/pfblockerng/config/0/pfb_keep",
    ),
    ToggleFlow(
        name="ip_global_logging",
        page="/pfblockerng/pfblockerng_ip.php",
        field="enable_log",
        config_path="installedpackages/pfblockerngipsettings/config/0/enable_log",
    ),
    ToggleFlow(
        name="dnsbl_floating_pass_rule",
        page="/pfblockerng/pfblockerng_dnsbl.php",
        field="pfb_dnsbl_rule",
        config_path="installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_rule",
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
    original = helpers.config_get(smoke_vm, flow.config_path)
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
# ADR-13 "Create VIPs automatically" (pfb_dnsvip_auto) -- driven via the DNSBL FORM
#
# The auto-VIP LIFECYCLE (config toggle -> VIP created/removed -> DNS sinks) is
# already covered by the smoke matrix (test_smoke_matrix.py) via the config helper
# `set_dnsvip_auto`. The UI tier's DISTINCT value is proving the DNSBL settings
# PAGE persists pfb_dnsvip_auto through a real CSRF form POST, with the same
# package machinery (pfb_create_dnsbl -> pfb_manage_dnsbl_vip) then provisioning
# the marked VIP end-to-end. Auto picks 10.10.10.53, free alongside the manual VIP
# at 10.10.10.1 (dnsbl_vip_ready), so the two coexist on one VM.
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
      creates the marked VIP at 10.10.10.53 and brings it up live on lo0.
    * DISABLE via the form: the POST persists it off; a Force Update removes the
      marked VIP from config AND lo0.

    Oracle = effective box state (marked_vip_subnet / ifconfig), never the HTTP
    response. The manual VIP at 10.10.10.1 (dnsbl_vip_ready) is untouched. Left
    clean (auto off, marked VIP gone) for the sibling flows in `finally`.
    """
    vm = smoke_vm
    # DNSBL must be enabled so the Force Update runs pfb_create_dnsbl in 'enabled'
    # mode; start from a known baseline (auto off, no marked VIP).
    helpers.set_dnsbl_enabled(vm, True)
    helpers.set_dnsvip_auto(vm, False)
    helpers.reload(vm, "update")
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
        # The next Force Update provisions the marked VIP (same path as the matrix).
        helpers.reload(vm, "update")
        assert helpers.marked_vip_subnet(vm, helpers.AUTO_VIP_DESCR_V4) == helpers.AUTO_VIP_IP4, (
            f"auto VIP not created at {helpers.AUTO_VIP_IP4} after the form enabled it: "
            f"got {helpers.marked_vip_subnet(vm, helpers.AUTO_VIP_DESCR_V4)!r}"
        )
        assert helpers.vip_alias_live(vm, helpers.AUTO_VIP_IP4), (
            f"auto VIP {helpers.AUTO_VIP_IP4} not live on lo0 (ifconfig) after the form enabled it"
        )

        # DISABLE through the form; persisted off, then the VIP is removed.
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
        # Leave the box clean for the sibling flows: auto off, marked VIP gone.
        helpers.set_dnsvip_auto(vm, False)
        helpers.reload(vm, "update")
