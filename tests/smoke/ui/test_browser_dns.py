"""Tier-B browser regression (#3517, #3538, #3555, #3557, #3583, #3771): the pfB-DNS settings on DNS General.

Drives a headless Chromium on the live ADR-04 smoke VM against DNS General (``pfblockerng_dns_general.php``), which
holds the pfB-DNS settings since issue #3771, and measures the live DOM, not the markup:

* the DNS, DoT, DoH and DoQ interface multi-selects resolve by role ``listbox`` under their visible
  "... Interface(s)" label, and stay operable through that name;
* each "Experimental." disclosure keeps WCAG 2.1 SC 1.4.3 text contrast (4.5:1) against the
  backdrop it paints on;
* saving with a DNS interface list empty shows the input error and leaves config.xml alone, saving
  Localhost with DoT on and a certificate persists them, and stored virtual IP and gone-interface
  tokens render selected and survive a save that leaves the lists alone;
* the pfB-DNS form and DNS General's own form save independently: a browser posts only the clicked form;
* the retired ``pfblockerng_dns.php`` address ends on DNS General with the pfB-DNS enable visible;
* DNS General's Resolver addresses save off with no listener VIP;
* DDR's checkbox resolves by ``DDR`` and its interfaces multi-select by ``Advertise DoH on port 443``;
  the select offers the configured DoH interfaces without Localhost;
* the status panel is a collapsible section per transport holding a table of Interface | Address | State rows, each
  state an icon with a hover title and a screen-reader text, and an off transport's table is empty; on a phone the
  tables scroll inside their sections.
* the DNS top tab opens DNS General from the package General page and from the keyboard;
  each of the five second-row tabs (General, DNSBL, DNSBL Groups, DNSBL Category, DNSBL SafeSearch) opens its page
  with DNS selected, its own tab selected and the DNS breadcrumb, and the DNSBL group editor stays under DNSBL Groups.

Scope is the controls and disclosures on this page only: no whole-page axe claim, since the
header breadcrumb and other shared framework markup are outside it. Measured in the box's
current theme (a fresh box is light). The screenshot and the JSON of measured values are
artifacts in ``screenshot_dir``, not asserted baselines.
"""

from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest

from .. import helpers
from .test_browser_feeds import JS_TIMEOUT_MS, _contrast_ratio, _open, _shot
from .test_dns_general_forms import PFB_DNS_DOT_PORT, REPLY_LOGGING, _both_forms_seeded, _stored
from .test_dns_settings_order import PFB_DNS_SECTIONS

pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Locator, Page, ViewportSize

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The retired pfB-DNS page: it redirects to DNS General (issue #3771).
RETIRED_PFB_DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
DNS_GENERAL_PAGE = "/pfblockerng/pfblockerng_dns_general.php"
DNS_CFG = "installedpackages/pfblockerngdns/config/0/"
# Everything the pfB-DNS form's Save writes.
DNS_SAVED_KEYS = (
    "pfb_dns",
    "pfb_dns_interface",
    "pfb_dns_sslcertref",
    "pfb_dns_name",
    "pfb_dns_dot",
    "pfb_dns_dot_port",
    "pfb_dns_dot_port6",
    "pfb_dns_dot_interface",
    "pfb_dns_doh",
    "pfb_dns_doh_port",
    "pfb_dns_doh_port6",
    "pfb_dns_doh_interface",
    "pfb_dns_doh_trusted",
    "pfb_dns_doq",
    "pfb_dns_doq_port",
    "pfb_dns_doq_port6",
    "pfb_dns_doq_interface",
    "pfb_dns_ddr",
    "pfb_dns_ddr_doh_443_interfaces",
)
REPLY_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply"
INTERFACE_LABELS = ("DNS Interface(s)", "DoT Interface(s)", "DoH Interface(s)", "DoQ Interface(s)")
# The enable checkbox's, the DoT's, the DoH's, the DoQ's and the DDR's "Experimental." disclosure.
EXPERIMENTAL_DISCLOSURES = 5
WCAG_AA_TEXT_CONTRAST = 4.5

# The painted backdrop: the nearest ancestor with a non-transparent background, else the white canvas.
_BACKDROP_JS = """
(el) => {
  for (let node = el; node; node = node.parentElement) {
    const bg = getComputedStyle(node).backgroundColor;
    if (bg !== 'rgba(0, 0, 0, 0)') return bg;
  }
  return 'rgb(255, 255, 255)';
}
"""

_SELECTED_VALUES_JS = "el => [...el.selectedOptions].map(option => option.value)"


@pytest.mark.parametrize("label", INTERFACE_LABELS, ids=["dns", "dot", "doh", "doq"])
def test_interface_listbox_resolves_by_its_visible_label(browser_page: Page, webui: WebUI, label: str) -> None:
    """The interface multi-select's accessible name is its visible label."""
    page = browser_page
    _open(page, webui, DNS_GENERAL_PAGE)
    found = page.get_by_role("listbox", name=label, exact=True).count()
    assert found == 1, f"expected exactly one listbox named {label!r} on {DNS_GENERAL_PAGE}, got {found}"


@pytest.mark.parametrize("label", INTERFACE_LABELS, ids=["dns", "dot", "doh", "doq"])
def test_interface_listbox_selection_works_through_its_name(browser_page: Page, webui: WebUI, label: str) -> None:
    """Selecting an interface through the named listbox selects exactly that interface."""
    page = browser_page
    _open(page, webui, DNS_GENERAL_PAGE)
    listbox = page.get_by_role("listbox", name=label, exact=True)
    found = listbox.count()
    assert found == 1, f"expected exactly one listbox named {label!r} on {DNS_GENERAL_PAGE}, got {found}"
    values = listbox.locator("option").evaluate_all("options => options.map(option => option.value)")
    assert values, f"{label!r} lists no interfaces to select"
    before = listbox.evaluate(_SELECTED_VALUES_JS)
    target = next((value for value in values if value not in before), None)
    assert target is not None, f"{label!r} already selects every option {values}: nothing left to select"
    listbox.select_option(target)
    after = listbox.evaluate(_SELECTED_VALUES_JS)
    assert after == [target], f"{label!r} selected {after}, expected [{target!r}]"


def test_experimental_disclosures_keep_text_contrast(browser_page: Page, webui: WebUI, screenshot_dir: Path) -> None:
    """Each "Experimental." disclosure meets 4.5:1 against the backdrop it actually paints on."""
    page = browser_page
    _open(page, webui, DNS_GENERAL_PAGE)
    disclosures = page.locator("strong", has_text="Experimental.")
    found = disclosures.count()
    assert found == EXPERIMENTAL_DISCLOSURES, (
        f"expected {EXPERIMENTAL_DISCLOSURES} 'Experimental.' disclosures on {DNS_GENERAL_PAGE}, got {found}"
    )
    measured = []
    for index in range(found):
        node = disclosures.nth(index)
        color = node.evaluate("el => getComputedStyle(el).color")
        backdrop = node.evaluate(_BACKDROP_JS)
        measured.append(
            {"disclosure": index + 1, "color": color, "backdrop": backdrop, "ratio": _contrast_ratio(color, backdrop)}
        )
    (screenshot_dir / "pfb_dns_experimental_contrast.json").write_text(json.dumps(measured, indent=2))
    _shot(page, screenshot_dir, "pfb_dns_experimental")
    for row in measured:
        assert row["ratio"] >= WCAG_AA_TEXT_CONTRAST, (
            f"'Experimental.' disclosure #{row['disclosure']} text {row['color']} on {row['backdrop']} is "
            f"{row['ratio']:.2f}:1, expected at least {WCAG_AA_TEXT_CONTRAST}:1"
        )


def _save(page: Page) -> None:
    """Click DNS General's own Save (button ``save``) and wait for the page the POST answers with."""
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        page.locator('button[type="submit"][name="save"]').click()


def _save_pfb_dns(page: Page) -> None:
    """Click Save pfB-DNS settings (button ``save_pfb_dns``) and wait for the page the POST answers with."""
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        page.locator('button[type="submit"][name="save_pfb_dns"]').click()


def test_saving_with_no_dns_interface_selected_shows_the_input_error_and_leaves_config_unchanged(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3538: every interface list needs an entry. Deselecting each DNS Interface(s) option and saving shows the
    input error, keeps the empty selection in the form and leaves the stored list as it was."""
    page = browser_page
    _open(page, webui, DNS_GENERAL_PAGE)  # the first load seeds the list
    stored = helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_interface")
    assert stored, "the first page load must have seeded the DNS interface list"
    listbox = page.get_by_role("listbox", name="DNS Interface(s)", exact=True)
    listbox.evaluate("el => { for (const option of el.options) option.selected = false; }")
    assert listbox.evaluate(_SELECTED_VALUES_JS) == [], "the test could not deselect every option"

    _save_pfb_dns(page)

    errors = page.locator(".input-errors")
    assert errors.count() == 1, "the empty list must show the input errors box"
    assert "DNS: select at least one interface." in errors.inner_text()
    assert listbox.evaluate(_SELECTED_VALUES_JS) == [], "the form must come back as submitted"
    assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_interface") == stored, "a rejected save changed config.xml"


def test_saving_localhost_with_dot_on_and_a_certificate_persists_them(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3538: Localhost for plain DNS and DoT, DoT on, a certificate: the save persists all of it.

    The save rewrites every setting of the page and the first load seeds the unset ones, so each one is read before the
    page is opened and put back, presence included, afterwards.
    """
    page = browser_page
    paths = [helpers.dns_config_path(key) for key in DNS_SAVED_KEYS] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    try:
        _open(page, webui, DNS_GENERAL_PAGE)
        cert = page.locator('select[name="pfb_dns_sslcertref"]')
        assert cert.count() == 1, "the box offers no certificate with a private key: nothing to select"
        cert_ref = cert.locator("option").first.get_attribute("value")
        assert cert_ref, "the first certificate option has no refid"
        cert.select_option(cert_ref)
        page.get_by_role("listbox", name="DNS Interface(s)", exact=True).select_option("lo0")
        page.get_by_role("listbox", name="DoT Interface(s)", exact=True).select_option("lo0")
        page.locator('input[name="pfb_dns_dot"]').check()

        _save_pfb_dns(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        assert helpers.config_get(smoke_vm, helpers.dns_config_path("pfb_dns_dot")) == "on"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_interface") == "lo0"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_dot_interface") == "lo0"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_sslcertref") == cert_ref
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(smoke_vm, path, state)


# The DDR section's accessible checkbox names, in display order.
DDR_SECTION = "Discovery of Designated Resolvers (DDR)"
DDR_TOGGLES = (("DDR", "pfb_dns_ddr"),)
# issue #3694: one multi-select replaced the two per-family DoH-on-443 checkboxes
DOH_443_LABEL = "Advertise DoH on port 443"
DOH_443_CFG = helpers.dns_config_path("pfb_dns_ddr_doh_443_interfaces")
DOH_INTERFACE_CFG = helpers.dns_config_path("pfb_dns_doh_interface")


def test_dns_general_holds_the_pfb_dns_enable_and_reply_logging_each_in_its_own_form(
    browser_page: Page, webui: WebUI, screenshot_dir: Path
) -> None:
    """DNS General shows the pfB-DNS enable and the shared reply logging, each operable in the form of its own Save."""
    page = browser_page
    _open(page, webui, DNS_GENERAL_PAGE)
    _assert_dns_navigation(page, "General")
    titles = [title.strip() for title in page.locator(".panel-title").all_inner_texts()]
    expected = [*PFB_DNS_SECTIONS, "DNS Reply Logging", "Resolver addresses"]
    assert titles[: len(expected)] == expected, f"expected the first panels {expected}, got {titles}"
    reply = page.locator('input[name="pfb_py_reply"]')
    assert reply.is_visible() and reply.is_enabled()
    before = reply.is_checked()
    reply.set_checked(not before)
    assert reply.is_checked() is not before
    reply.set_checked(before)
    _shot(page, screenshot_dir, "dns_general_reply_logging")
    enable = page.locator('input[name="pfb_dns"]')
    assert enable.is_visible() and enable.is_enabled(), "the pfB-DNS enable is not operable on DNS General"
    pfb_dns_form = page.locator('form:has(button[name="save_pfb_dns"])')
    general_form = page.locator('form:has(button[name="save"])')
    assert pfb_dns_form.locator('input[name="pfb_dns"]').count() == 1, "the pfB-DNS enable is not in the pfB-DNS form"
    assert pfb_dns_form.locator('input[name="pfb_py_reply"]').count() == 0, "reply logging is in the pfB-DNS form"
    assert general_form.locator('input[name="pfb_py_reply"]').count() == 1, "reply logging is not in the General form"
    assert general_form.locator('input[name="pfb_dns"]').count() == 0, "the pfB-DNS enable is in the General form"


# The Resolver addresses controls on DNS General, as stored after a save with the option off and both VIPs at none.
RESOLVER_SAVED = {
    "pfb_dns_listen_vip": "",
    "pfb_dns_listen_vip4": "",
    "pfb_dns_listen_vip6": "",
    "pfb_dns_listen_interface": "lo0",
}


def _listener_vip_rows(vm: helpers.SmokeVM) -> int:
    """How many virtual IP rows carry a Resolver addresses marker (``pfB_DNS_LISTEN_VIP_v4`` or ``_v6``)."""
    snippet = (
        "$n = 0;\n"
        "foreach (config_get_path('virtualip/vip', array()) as $v) {\n"
        "  if (strpos($v['descr'] ?? '', 'pfB_DNS_LISTEN_VIP') === 0) { $n++; }\n"
        "}\n"
        "echo 'LISTENER_VIPS=' . $n . ';';"
    )
    result = helpers.php_eval(vm, snippet)
    match = re.search(r"LISTENER_VIPS=(\d+);", result.stdout)
    assert result.returncode == 0 and match, f"counting the listener VIPs failed: {result.stdout!r} {result.stderr!r}"
    return int(match.group(1))


def test_resolver_addresses_off_saves_with_no_listener_vip(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """DNS General: Resolver addresses off, both VIP selects at none and Automatic VIP interface Localhost, then Save.

    The stored option stays off and the save creates no listener VIP. "Create VIP automatically" is never selected:
    on the shared box it would create a live VIP.
    """
    page = browser_page
    paths = [f"{helpers.CFG_GLOBAL}/{key}" for key in (*RESOLVER_SAVED, "pfb_dns_listen_added")] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    vips_before = _listener_vip_rows(smoke_vm)
    try:
        _open(page, webui, DNS_GENERAL_PAGE)
        page.locator('input[name="pfb_dns_listen_vip"]').set_checked(False)
        page.locator('select[name="pfb_dns_listen_vip4"]').select_option("none")
        page.locator('select[name="pfb_dns_listen_vip6"]').select_option("none")
        page.locator('select[name="pfb_dns_listen_interface"]').select_option("lo0")

        _save(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        stored = {key: helpers.config_get(smoke_vm, f"{helpers.CFG_GLOBAL}/{key}") for key in RESOLVER_SAVED}
        assert stored == RESOLVER_SAVED, f"the Off save stored {stored}, expected {RESOLVER_SAVED}"
        assert _listener_vip_rows(smoke_vm) == vips_before, "the Off save created or removed a listener VIP"
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(smoke_vm, path, state)


def test_ddr_controls_resolve_by_their_visible_labels_inside_the_ddr_section(browser_page: Page, webui: WebUI) -> None:
    """The DDR checkbox and the DoH-on-443 select have distinct accessible names within the DDR panel."""
    page = browser_page
    _open(page, webui, DNS_GENERAL_PAGE)
    section = page.locator(".panel").filter(has=page.locator(".panel-title", has_text=DDR_SECTION)).last
    assert section.count() == 1, f"no panel on {DNS_GENERAL_PAGE} has the title {DDR_SECTION!r}"
    for label, name in DDR_TOGGLES:
        control = section.get_by_label(label, exact=True)
        found = control.count()
        assert found == 1, f"expected exactly one control labelled {label!r} in the DDR section, got {found}"
        assert control.get_attribute("type") == "checkbox" and control.get_attribute("name") == name, (
            f"{label!r}: expected the checkbox named {name!r}, got {control.evaluate('el => el.outerHTML')}"
        )
    select = section.get_by_role("listbox", name=DOH_443_LABEL, exact=True)
    assert select.count() == 1, f"expected exactly one listbox named {DOH_443_LABEL!r} in the DDR section"
    assert select.get_attribute("multiple") is not None, "the DoH-on-443 control must be a multi-select"
    for gone in ("pfb_dns_ddr_doh_443", "pfb_dns_ddr_doh_443_6"):
        assert page.locator(f'input[name="{gone}"]').count() == 0, f"the retired checkbox {gone} is still on the page"


def test_doh_on_port_443_select_offers_the_doh_interfaces_without_localhost_and_shows_its_choice(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM, screenshot_dir: Path
) -> None:
    """issue #3694: the select offers the stored DoH interfaces but not Localhost, with the stored choice selected.

    Given the stored DoH interface list `lo0,lan` and the stored choice `lan`, Then the select offers `lan` alone and
    has it selected. One screenshot is an artifact, not an asserted baseline.
    """
    page = browser_page
    paths = [helpers.dns_config_path(key) for key in DNS_SAVED_KEYS] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    try:
        helpers.config_set(smoke_vm, DOH_INTERFACE_CFG, "lo0,lan")
        helpers.config_set(smoke_vm, DOH_443_CFG, "lan")
        _open(page, webui, DNS_GENERAL_PAGE)
        select = page.get_by_role("listbox", name=DOH_443_LABEL, exact=True)
        _shot(page, screenshot_dir, "pfb_dns_ddr_doh_443_interfaces")
        offered = select.locator("option").evaluate_all("options => options.map(option => option.value)")
        assert offered == ["lan"], f"expected the DoH interfaces without Localhost, got {offered}"
        assert select.evaluate(_SELECTED_VALUES_JS) == ["lan"], "the stored choice must be selected"
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(smoke_vm, path, state)


def test_saving_ddr_and_a_doh_on_port_443_choice_persists_both(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM, screenshot_dir: Path
) -> None:
    """issues #3583, #3694: saving DDR and a choice under "Advertise DoH on port 443" stores both.

    DDR needs a DNS Name (issue #3694): the test types one into the DNS Name input and expects it stored.

    Given DDR and the choice stored empty and the DoH interface list `lan` (before-state, seeded directly), the save
    rewrites every setting of the page and the first load seeds the unset ones, so each one is read before the page is
    opened and put back.
    """
    page = browser_page
    paths = [helpers.dns_config_path(key) for key in DNS_SAVED_KEYS] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    ddr_path = helpers.dns_config_path("pfb_dns_ddr")
    try:
        helpers.config_set(smoke_vm, ddr_path, "")
        helpers.config_set(smoke_vm, DOH_443_CFG, "")
        helpers.config_set(smoke_vm, DOH_INTERFACE_CFG, "lan")
        before = (helpers.config_get(smoke_vm, ddr_path), helpers.config_get(smoke_vm, DOH_443_CFG))
        assert before == ("", ""), f"seed did not take: DDR and the choice must start empty, got {before}"
        _open(page, webui, DNS_GENERAL_PAGE)
        dns_name = page.locator('input[name="pfb_dns_name"]')
        named = page.get_by_label("DNS Name", exact=True)
        if named.count() != 1:
            _shot(page, screenshot_dir, "pfb_dns_name_accessible_name_failure")
            dom = dns_name.evaluate_all(
                "els => els.map(el => ({html: el.outerHTML, labels: [...el.labels].map(label => label.outerHTML), "
                "visible: !!el.getClientRects().length, disabled: el.disabled}))"
            )
            pytest.fail(
                f"DNS Name label resolves {named.count()} inputs; input count={dns_name.count()}; "
                f"DOM={dom}; "
                f"accessible snapshot={page.locator('form', has=dns_name).aria_snapshot()}"
            )
        page.get_by_label("DNS Name", exact=True).fill("fw.example.lan")
        page.locator('input[name="pfb_dns_ddr"]').check()
        page.get_by_role("listbox", name=DOH_443_LABEL, exact=True).select_option("lan")

        _save_pfb_dns(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        stored = (helpers.config_get(smoke_vm, ddr_path), helpers.config_get(smoke_vm, DOH_443_CFG))
        assert stored == ("on", "lan"), f"DDR must store on and the choice lan, got {stored}"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_name") == "fw.example.lan", "the DNS Name must persist"
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(smoke_vm, path, state)


# issue #3557: an IP-alias VIP only this test configures (config only: the page offers what config.xml lists) and a
# stored interface token that names no interface on the box.
_VIP_UNIQID = "pfb3557vip"
_VIP_ADDR = "198.51.100.57"
_GONE = "opt99"


def test_a_stored_vip_and_a_gone_interface_render_selected_and_an_unchanged_save_keeps_them(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3557: with every interface list stored as Localhost, a virtual IP and an interface that is gone, each list
    renders all three selected (the VIP under its address, the gone one labelled not currently available) and a Save
    that leaves the lists alone stores all three again."""
    page = browser_page
    vip = f"_vip{_VIP_UNIQID}"
    stored = f"lo0,{vip},{_GONE}"
    paths = [helpers.dns_config_path(key) for key in DNS_SAVED_KEYS] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    entry = {"mode": "ipalias", "interface": "lo0", "type": "single", "subnet": _VIP_ADDR, "subnet_bits": "32"}
    lists = [f"{DNS_CFG}pfb_dns{kind}_interface" for kind in ("", "_dot", "_doh", "_doq")]
    setup = (
        "$vips = config_get_path('virtualip/vip', array());\n"
        f"$vips[] = {helpers._php_kv_array(entry | {'descr': 'pfB-DNS issue 3557', 'uniqid': _VIP_UNIQID})};\n"
        "config_set_path('virtualip/vip', $vips);\n"
        + "".join(f"config_set_path({helpers._php_str(path)}, {helpers._php_str(stored)});\n" for path in lists)
        + "".join(
            f"config_set_path({helpers._php_str(helpers.dns_config_path(f'pfb_dns_{kind}'))}, '');\n"
            for kind in ("dot", "doh", "doq")
        )
        + "write_config('pfBlockerNG smoke: issue 3557 stored listener tokens');\n"
        "echo 'OK';"
    )
    try:
        result = helpers.php_eval(smoke_vm, setup)
        assert result.returncode == 0 and "OK" in result.stdout, f"setup failed: {result.stdout!r} {result.stderr!r}"
        _open(page, webui, DNS_GENERAL_PAGE)
        for label in INTERFACE_LABELS:
            listbox = page.get_by_role("listbox", name=label, exact=True)
            selected = listbox.evaluate(_SELECTED_VALUES_JS)
            assert selected == ["lo0", vip, _GONE], (
                f"{label!r} renders {selected}, expected every stored token selected"
            )
            vip_text = listbox.locator(f'option[value="{vip}"]').inner_text()
            assert _VIP_ADDR in vip_text, f"{label!r}: the VIP option reads {vip_text!r}, expected its address"
            gone_text = listbox.locator(f'option[value="{_GONE}"]').inner_text()
            assert gone_text == f"{_GONE} (not currently available)", f"{label!r}: the gone option reads {gone_text!r}"

        _save_pfb_dns(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        for path in lists:
            assert helpers.config_get(smoke_vm, path) == stored, f"{path}: the unchanged save dropped a token"
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(smoke_vm, path, state)
        cleanup = helpers.php_eval(
            smoke_vm,
            "$keep = array();\n"
            "foreach (config_get_path('virtualip/vip', array()) as $v) {\n"
            f"  if (($v['uniqid'] ?? '') !== {helpers._php_str(_VIP_UNIQID)}) {{ $keep[] = $v; }}\n"
            "}\n"
            "config_set_path('virtualip/vip', $keep);\n"
            "write_config('pfBlockerNG smoke: issue 3557 VIP removed');\n"
            "echo 'OK';",
        )
        assert cleanup.returncode == 0 and "OK" in cleanup.stdout, f"VIP cleanup failed: {cleanup.stdout!r}"


# The Resolver as pfB-DNS leaves it after a move, as a stored snapshot (the marker that makes the box "moved").
_MOVED_SNAPSHOT = base64.b64encode(
    json.dumps(
        {
            "active_interface": {"present": True, "value": "lan"},
            "enablessl": {"present": False, "value": None},
            "custom_options": {"present": True, "value": ""},
        }
    ).encode()
).decode("ascii")
PFB_INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
STATUS_TRANSPORTS = {"plain": "Plain DNS", "dot": "DNS over TLS", "doh": "DNS over HTTPS", "doq": "DNS over QUIC"}
PHONE: ViewportSize = {"width": 390, "height": 844}
# A row wider than a phone: a long interface description, the longest IPv6 listener and a refusal reason, put into the
# live table by the test, so the State cell (and its screen-reader text) starts beyond the screen's right edge.
WIDE_INTERFACE = "OPT12_GUEST_VLAN_4094_UPLINK_DESCRIPTION"
WIDE_ADDRESS = "[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:853"
WIDE_REASON = "listen tcp [2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:853: bind: address already in use"


def _write_rc_script(vm: helpers.SmokeVM, settings: dict[str, str] | None = None) -> None:
    """Store ``settings`` in the pfB-DNS section, if any, and have the package write its service script from what is
    stored, as an apply does: the status panel reads the addresses to list from that script."""
    stores = "".join(
        f"config_set_path({helpers._php_str(helpers.dns_config_path(key))}, {helpers._php_str(value)});\n"
        for key, value in (settings or {}).items()
    )
    store = (
        stores + "write_config('pfBlockerNG smoke: pfB-DNS settings for the #3555 status panel');\n" if settings else ""
    )
    php = f"require_once({helpers._php_str(PFB_INC)});\nglobal $pfb;\n{store}pfb_global();\npfb_dns_proxy_service();"
    result = helpers.php_eval(vm, f"{php}\necho 'OK';")
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"writing the pfB-DNS service script failed: rc={result.returncode} {result.stdout!r} {result.stderr!r}"
    )


def test_status_panel_is_a_section_per_transport_with_a_titled_icon_for_each_state(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM, screenshot_dir: Path
) -> None:
    """issue #3555: on a box whose Resolver is moved and whose proxy is stopped, with plain DNS on and DoT, DoH and DoQ
    off, the status panel has the four transport sections in order, each a table headed Interface, Address, State;
    plain DNS lists a Localhost row whose state is a visible icon titled "Configured, not bound" with the same words for
    a screen reader, and each of the three off transports is its header alone: no body and no row in the live DOM.

    issue #3586: each section collapses and reopens from the toggle in its title, like pfSense's collapsible panels,
    and on a phone a row wider than the screen scrolls inside its section while the page stays as wide as the screen.

    Settings and the service script are put back afterwards, presence included.
    """
    page = browser_page
    settings = {
        "pfb_dns": "on",
        "pfb_dns_saved": _MOVED_SNAPSHOT,
        "pfb_dns_interface": "lan",
        "pfb_dns_dot": "",
        "pfb_dns_doh": "",
        "pfb_dns_doq": "",
    }
    originals = {key: helpers.config_get_state(smoke_vm, helpers.dns_config_path(key)) for key in settings}
    try:
        _write_rc_script(smoke_vm, settings)
        _open(page, webui, DNS_GENERAL_PAGE)

        panel = page.locator("#pfb-dns-status")
        assert panel.count() == 1, "the page has no pfB-DNS status panel"
        assert panel.locator("#pfb-dns-status-service td").inner_text() == "Stopped"
        titles = [
            panel.locator(f"#pfb-dns-status-{key} .panel-title").inner_text().strip() for key in STATUS_TRANSPORTS
        ]
        assert titles == [f"{title} Listeners" for title in STATUS_TRANSPORTS.values()]
        for key in STATUS_TRANSPORTS:
            columns = panel.locator(f"#pfb-dns-status-{key} thead th").all_inner_texts()
            assert columns == ["Interface", "Address", "State"], f"{key}: the table's columns are {columns}"

        rows = panel.locator("#pfb-dns-status-plain tbody tr")
        assert rows.count() >= 2, "plain DNS lists Localhost and the LAN address at least"
        loopback = rows.nth(0).locator("td")
        assert loopback.nth(0).inner_text() == "Localhost", "loopback comes first"
        hosts = [line.rsplit(":", 1)[0] for line in loopback.nth(1).inner_text().split("\n")]
        assert hosts == ["127.0.0.1", "[::1]"], f"Localhost lists {hosts}, one address per line"
        icon = loopback.nth(2).locator("i.fa-exclamation-circle")
        assert icon.count() == 1, "a stopped proxy's configured address shows the warning icon"
        assert icon.get_attribute("title") == "Configured, not bound"
        assert icon.is_visible(), "the icon takes room on the page"
        assert loopback.nth(2).locator(".sr-only").text_content() == "Configured, not bound"

        for key in ("dot", "doh", "doq"):
            block = panel.locator(f"#pfb-dns-status-{key}")
            assert block.locator("table").count() == 1, f"{key}: an off transport keeps its table"
            bodies, rows_shown = block.locator("tbody").count(), block.locator("tbody tr").count()
            if bodies or rows_shown:
                stored = helpers.config_get(smoke_vm, helpers.dns_config_path(f"pfb_dns_{key}"))
                pytest.fail(
                    f"{key} is off ({stored!r} stored): its table must be a header alone, it has {bodies} tbody and "
                    f"{rows_shown} rows: {block.inner_html()}"
                )

        _shot(page, screenshot_dir, "dns_status_tables")
        # issue #3586: the title's toggle collapses and reopens its section, its icon following (pfSenseHelpers.js)
        body = panel.locator("#pfb-dns-status-plain_panel-body")
        toggle = panel.locator('#pfb-dns-status-plain .panel-title a[data-toggle="collapse"]')
        assert "fa-minus-circle" in (toggle.locator("i").get_attribute("class") or ""), "an open one offers to close"
        toggle.click()
        body.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
        toggle.click()
        body.wait_for(state="visible", timeout=JS_TIMEOUT_MS)

        page.set_viewport_size(PHONE)
        cells = rows.nth(0).locator("td")
        cells.nth(0).evaluate("(el, text) => { el.textContent = text; }", WIDE_INTERFACE)
        cells.nth(1).evaluate("(el, text) => { el.textContent = text; }", WIDE_ADDRESS)
        cells.nth(2).evaluate("(el, text) => el.append(' ' + text)", WIDE_REASON)
        # the precondition: the row is laid out past the screen's right edge
        right = cells.nth(2).evaluate("el => el.getBoundingClientRect().right")
        assert right > PHONE["width"], f"the wide row must reach past the screen, it ends at {right}"
        # Content wider than the screen is drawn past its edge, unreachable, unless something scrolls it sideways: the
        # nearest ancestor of the table that does must be inside the table's own section, and that section on screen
        scrolled_in = cells.nth(2).evaluate(
            """el => { for (let a = el.closest('table').parentElement; a; a = a.parentElement) {
                const x = getComputedStyle(a).overflowX;
                if ((x === 'auto' || x === 'scroll') && a.scrollWidth > a.clientWidth) {
                    const section = a.closest('.panel'); return section ? section.id : a.tagName; } }
                return null; }"""
        )
        section = panel.locator("#pfb-dns-status-plain").bounding_box()
        _shot(page, screenshot_dir, "dns_status_tables_phone")
        assert scrolled_in == "pfb-dns-status-plain", f"on a phone the wide table is scrolled by {scrolled_in!r}"
        assert section is not None and section["x"] + section["width"] <= PHONE["width"], f"the section is {section}"
    finally:
        for key, state in originals.items():
            helpers.config_restore_state(smoke_vm, helpers.dns_config_path(key), state)
        _write_rc_script(smoke_vm)


# DNS General is the DNS landing page and holds the pfB-DNS settings; the DNSBL pages are its sub-tabs.
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
UPDATE_PAGE = "/pfblockerng/pfblockerng_update.php"
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
GROUPS_PAGE = "/pfblockerng/pfblockerng_category.php?type=dnsbl"
BLACKLIST_PAGE = "/pfblockerng/pfblockerng_blacklist.php"
SAFESEARCH_PAGE = "/pfblockerng/pfblockerng_safesearch.php"
GROUP_EDITOR = "/pfblockerng/pfblockerng_category_edit.php"
DNS_SUBTABS = (
    ("General", DNS_GENERAL_PAGE),
    ("DNSBL", DNSBL_PAGE),
    ("DNSBL Groups", GROUPS_PAGE),
    ("DNSBL Category", BLACKLIST_PAGE),
    ("DNSBL SafeSearch", SAFESEARCH_PAGE),
)
# A tab row is a ``ul.nav``; the breadcrumb is not, so its crumbs are the matches outside every tab row.
_OUTSIDE_TAB_ROWS = '[not(ancestor::ul[contains(concat(" ", normalize-space(@class), " "), " nav ")])]'
_DNS_CRUMB = f'xpath=//a[normalize-space(.)="DNS"]{_OUTSIDE_TAB_ROWS}'
# (label, href, active) for each tab of a row, in order.
_TABS_JS = """row => [...row.querySelectorAll(':scope > li')].map(li => {
    const a = li.querySelector('a');
    return [(a && a.textContent.trim()) || '', a && a.getAttribute('href'), li.classList.contains('active')];
})"""


def _nav_row(page: Page, *hrefs: str) -> Locator:
    """The one tab row holding a link to each of ``hrefs``."""
    row = page.locator("ul.nav")
    for href in hrefs:
        row = row.filter(has=page.locator(f'a[href="{href}"]'))
    assert row.count() == 1, f"expected one tab row with links to {list(hrefs)}, found {row.count()}"
    return row


def _tabs(row: Locator) -> list[tuple[str, str | None, bool]]:
    return [(tab[0], tab[1], tab[2]) for tab in row.evaluate(_TABS_JS)]


def _target(url: str) -> str:
    """The path and query of ``url``, in the form a tab's ``href`` takes."""
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


def _follow(page: Page, link: Locator) -> None:
    """Click ``link`` and wait for the page it loads to settle."""
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        link.click()


def _assert_single_dns_top(top: list[tuple[str, str | None, bool]]) -> None:
    labels = [label for label, _, _ in top]
    assert labels.count("DNS") == 1 and "DNSBL" not in labels and "pfB-DNS" not in labels, (
        f"the top tabs are {labels}, expected one DNS tab and no separate DNSBL or pfB-DNS tab"
    )


def _assert_dns_navigation(page: Page, subtab: str) -> None:
    """DNS is the one selected top tab; the second row reads as approved, with ``subtab`` selected."""
    top = _tabs(_nav_row(page, UPDATE_PAGE))
    _assert_single_dns_top(top)
    selected = [(label, href) for label, href, active in top if active]
    assert selected == [("DNS", DNS_GENERAL_PAGE)], f"the selected top tab is {selected}, expected DNS -> General"
    row = _tabs(_nav_row(page, SAFESEARCH_PAGE, GROUPS_PAGE))
    shown = [(label, href) for label, href, _ in row]
    assert shown == list(DNS_SUBTABS), f"the DNS sub-tabs are {shown}, expected {list(DNS_SUBTABS)}"
    selected_subtabs = [label for label, _, active in row if active]
    assert selected_subtabs == [subtab], f"the selected DNS sub-tab is {selected_subtabs}, expected [{subtab!r}]"


def _assert_dns_crumb(page: Page) -> None:
    """The breadcrumb's DNS parent links to DNS General."""
    hrefs = page.locator(_DNS_CRUMB).evaluate_all("crumbs => crumbs.map(a => a.getAttribute('href'))")
    assert hrefs == [DNS_GENERAL_PAGE], f"the breadcrumb's DNS parent links {hrefs}, expected DNS General"


def test_dns_navigation_general_top_tab_opens_dns_general(
    browser_page: Page, webui: WebUI, screenshot_dir: Path
) -> None:
    """The package General page's DNS top tab opens DNS General."""
    page = browser_page
    _open(page, webui, GENERAL_PAGE)
    top = _tabs(_nav_row(page, UPDATE_PAGE))
    _assert_single_dns_top(top)
    assert ("DNS", DNS_GENERAL_PAGE, False) in top, f"General's top tabs are {top}, expected an unselected DNS tab"
    _follow(page, _nav_row(page, UPDATE_PAGE).locator(f'a[href="{DNS_GENERAL_PAGE}"]'))
    assert _target(page.url) == DNS_GENERAL_PAGE, f"the DNS tab opened {_target(page.url)}, expected DNS General"
    _assert_dns_navigation(page, "General")
    _assert_dns_crumb(page)
    _shot(page, screenshot_dir, "dns_navigation_from_general")


def test_dns_navigation_top_tab_opens_from_the_keyboard(browser_page: Page, webui: WebUI, screenshot_dir: Path) -> None:
    """Focusing the package General page's DNS top tab and pressing Enter opens DNS General."""
    page = browser_page
    _open(page, webui, GENERAL_PAGE)
    link = _nav_row(page, UPDATE_PAGE).locator(f'a[href="{DNS_GENERAL_PAGE}"]')
    assert link.count() == 1, f"General has {link.count()} DNS top-tab links, expected one"
    link.focus()
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        page.keyboard.press("Enter")
    assert _target(page.url) == DNS_GENERAL_PAGE, (
        f"Enter on the DNS tab opened {_target(page.url)}, expected DNS General"
    )
    _assert_dns_navigation(page, "General")
    _shot(page, screenshot_dir, "dns_navigation_keyboard_top_tab")


@pytest.mark.parametrize(
    ("label", "target", "shot"),
    [
        ("General", DNS_GENERAL_PAGE, "dns_navigation_dns_general"),
        ("DNSBL", DNSBL_PAGE, "dns_navigation_dnsbl"),
        ("DNSBL Groups", GROUPS_PAGE, "dns_navigation_dnsbl_groups"),
        ("DNSBL Category", BLACKLIST_PAGE, "dns_navigation_dnsbl_category"),
        ("DNSBL SafeSearch", SAFESEARCH_PAGE, "dns_navigation_dnsbl_safesearch"),
    ],
    ids=["general", "dnsbl", "dnsbl-groups", "dnsbl-category", "dnsbl-safesearch"],
)
def test_dns_navigation_subtab_opens_its_page_under_dns(
    browser_page: Page, webui: WebUI, screenshot_dir: Path, label: str, target: str, shot: str
) -> None:
    """Each second-row tab under DNS opens its own page, which keeps DNS selected and selects that tab."""
    page = browser_page
    # General is reached from a sibling page, so the click moves the browser; every other tab from General.
    start, selected = (DNSBL_PAGE, "DNSBL") if target == DNS_GENERAL_PAGE else (DNS_GENERAL_PAGE, "General")
    _open(page, webui, start)
    _assert_dns_navigation(page, selected)
    _follow(page, _nav_row(page, SAFESEARCH_PAGE, GROUPS_PAGE).get_by_role("link", name=label, exact=True))
    assert _target(page.url) == target, f"{label!r} opened {_target(page.url)}, expected {target}"
    _assert_dns_navigation(page, label)
    _assert_dns_crumb(page)
    _shot(page, screenshot_dir, shot)


def test_dns_navigation_group_editor_stays_under_dnsbl_groups(
    browser_page: Page, webui: WebUI, screenshot_dir: Path
) -> None:
    """Add on DNSBL Groups opens the DNSBL group editor, which stays under DNS with DNSBL Groups selected."""
    page = browser_page
    _open(page, webui, GROUPS_PAGE)
    _assert_dns_navigation(page, "DNSBL Groups")
    add = page.locator(f'nav.action-buttons a[href*="{GROUP_EDITOR}?type=dnsbl"]')
    assert add.count() == 1, f"the DNSBL Groups page has {add.count()} Add links, expected one"
    _follow(page, add)
    assert _target(page.url).startswith(f"{GROUP_EDITOR}?type=dnsbl&rowid="), (
        f"Add opened {_target(page.url)}, expected the DNSBL group editor"
    )
    _assert_dns_navigation(page, "DNSBL Groups")
    _assert_dns_crumb(page)
    crumb = page.locator("ol.breadcrumb").get_by_role("link", name="DNSBL Groups", exact=True)
    assert crumb.count() == 1, "the editor's breadcrumb does not contain DNSBL Groups"
    _shot(page, screenshot_dir, "dns_navigation_dnsbl_group_editor")


def test_the_retired_pfb_dns_address_ends_on_dns_general_with_the_pfb_dns_enable_visible(
    browser_page: Page, webui: WebUI, screenshot_dir: Path
) -> None:
    """issue #3771: opening pfblockerng_dns.php in the browser ends on DNS General, which shows the pfB-DNS enable."""
    page = browser_page
    _open(page, webui, RETIRED_PFB_DNS_PAGE)
    ended = _target(page.url)
    assert ended == DNS_GENERAL_PAGE, f"{RETIRED_PFB_DNS_PAGE} ended on {ended}, expected {DNS_GENERAL_PAGE}"
    enable = page.locator('input[name="pfb_dns"]')
    assert enable.count() == 1 and enable.is_visible(), "the pfB-DNS enable is not visible after the redirect"
    _assert_dns_navigation(page, "General")
    _shot(page, screenshot_dir, "dns_retired_pfb_dns_address")


def test_clicking_save_pfb_dns_stores_the_changed_pfb_dns_field_and_not_the_changed_dns_general_field(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Given both forms stored, When the DoT port and the reply logging are changed and Save pfB-DNS settings is
    clicked, Then the DoT port is stored and the reply logging keeps its stored value: only the clicked form posted.
    """
    page = browser_page
    with _both_forms_seeded(smoke_vm):
        before = _stored(smoke_vm, [PFB_DNS_DOT_PORT, REPLY_LOGGING])
        assert before == {PFB_DNS_DOT_PORT: "853", REPLY_LOGGING: "on"}, f"before-state: got {before}"
        _open(page, webui, DNS_GENERAL_PAGE)
        page.locator('input[name="pfb_dns_dot_port"]').fill("8853")
        page.locator('input[name="pfb_py_reply"]').set_checked(False)
        label = page.locator('button[type="submit"][name="save_pfb_dns"]').inner_text().strip()
        assert label == "Save pfB-DNS settings", f"the pfB-DNS save button reads {label!r}"

        _save_pfb_dns(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        after = _stored(smoke_vm, [PFB_DNS_DOT_PORT, REPLY_LOGGING])
        assert after == {PFB_DNS_DOT_PORT: "8853", REPLY_LOGGING: "on"}, (
            f"expected the DoT port stored as 8853 and the reply logging still on, got {after}"
        )


def test_clicking_save_dns_general_stores_the_changed_dns_general_field_and_not_the_changed_pfb_dns_field(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Given both forms stored, When the DoT port and the reply logging are changed and Save DNS General settings is
    clicked, Then the reply logging is stored and the DoT port keeps its stored value: only the clicked form posted.
    """
    page = browser_page
    with _both_forms_seeded(smoke_vm):
        before = _stored(smoke_vm, [PFB_DNS_DOT_PORT, REPLY_LOGGING])
        assert before == {PFB_DNS_DOT_PORT: "853", REPLY_LOGGING: "on"}, f"before-state: got {before}"
        _open(page, webui, DNS_GENERAL_PAGE)
        page.locator('input[name="pfb_dns_dot_port"]').fill("8853")
        page.locator('input[name="pfb_py_reply"]').set_checked(False)
        label = page.locator('button[type="submit"][name="save"]').inner_text().strip()
        assert label == "Save DNS General settings", f"the DNS General save button reads {label!r}"

        _save(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        after = _stored(smoke_vm, [PFB_DNS_DOT_PORT, REPLY_LOGGING])
        assert after == {PFB_DNS_DOT_PORT: "853", REPLY_LOGGING: ""}, (
            f"expected the reply logging stored off and the DoT port still 853, got {after}"
        )
