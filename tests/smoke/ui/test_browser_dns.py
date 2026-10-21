"""Tier-B browser regression (#3517, #3538, #3557): the pfB-DNS page's accessible names, legible warnings and saves.

Drives a headless Chromium on the live ADR-04 smoke VM against the pfB-DNS page
(``pfblockerng_dns.php``) and measures the live DOM, not the markup:

* the DNS, DoT, DoH and DoQ interface multi-selects resolve by role ``listbox`` under their visible
  "... Interface(s)" label, and stay operable through that name;
* each "Experimental." disclosure keeps WCAG 2.1 SC 1.4.3 text contrast (4.5:1) against the
  backdrop it paints on;
* saving with a DNS interface list empty shows the input error and leaves config.xml alone, saving
  Localhost with DoT on and a certificate persists them, and stored virtual IP and gone-interface
  tokens render selected and survive a save that leaves the lists alone.

Scope is the controls and disclosures on this page only: no whole-page axe claim, since the
header breadcrumb and other shared framework markup are outside it. Measured in the box's
current theme (a fresh box is light). The screenshot and the JSON of measured values are
artifacts in ``screenshot_dir``, not asserted baselines.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_browser_feeds import JS_TIMEOUT_MS, _contrast_ratio, _open, _shot

pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
DNS_CFG = "installedpackages/pfblockerngdns/config/0/"
# Everything the page's Save writes: the pfB-DNS toggle, the listener settings and the certificate (the Reply Logging
# preference lives in the DNSBL section).
DNS_SAVED_KEYS = (
    "pfb_dns",
    "pfb_dns_interface",
    "pfb_dns_sslcertref",
    "pfb_dns_dot",
    "pfb_dns_dot_port",
    "pfb_dns_dot_interface",
    "pfb_dns_doh",
    "pfb_dns_doh_port",
    "pfb_dns_doh_interface",
    "pfb_dns_doh_trusted",
    "pfb_dns_doq",
    "pfb_dns_doq_port",
    "pfb_dns_doq_interface",
)
REPLY_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply"
INTERFACE_LABELS = ("DNS Interface(s)", "DoT Interface(s)", "DoH Interface(s)", "DoQ Interface(s)")
# The enable checkbox's, the DoT's, the DoH's and the DoQ's "Experimental." disclosure.
EXPERIMENTAL_DISCLOSURES = 4
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
    _open(page, webui, DNS_PAGE)
    found = page.get_by_role("listbox", name=label, exact=True).count()
    assert found == 1, f"expected exactly one listbox named {label!r} on {DNS_PAGE}, got {found}"


@pytest.mark.parametrize("label", INTERFACE_LABELS, ids=["dns", "dot", "doh", "doq"])
def test_interface_listbox_selection_works_through_its_name(browser_page: Page, webui: WebUI, label: str) -> None:
    """Selecting an interface through the named listbox selects exactly that interface."""
    page = browser_page
    _open(page, webui, DNS_PAGE)
    listbox = page.get_by_role("listbox", name=label, exact=True)
    found = listbox.count()
    assert found == 1, f"expected exactly one listbox named {label!r} on {DNS_PAGE}, got {found}"
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
    _open(page, webui, DNS_PAGE)
    disclosures = page.locator("strong", has_text="Experimental.")
    found = disclosures.count()
    assert found == EXPERIMENTAL_DISCLOSURES, (
        f"expected {EXPERIMENTAL_DISCLOSURES} 'Experimental.' disclosures on {DNS_PAGE}, got {found}"
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
    """Click Save and wait for the page the POST answers with."""
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        page.locator('button[type="submit"][name="save"]').click()


def test_saving_with_no_dns_interface_selected_shows_the_input_error_and_leaves_config_unchanged(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3538: every interface list needs an entry. Deselecting each DNS Interface(s) option and saving shows the
    input error, keeps the empty selection in the form and leaves the stored list as it was."""
    page = browser_page
    _open(page, webui, DNS_PAGE)  # the first load seeds the list
    stored = helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_interface")
    assert stored, "the first page load must have seeded the DNS interface list"
    listbox = page.get_by_role("listbox", name="DNS Interface(s)", exact=True)
    listbox.evaluate("el => { for (const option of el.options) option.selected = false; }")
    assert listbox.evaluate(_SELECTED_VALUES_JS) == [], "the test could not deselect every option"

    _save(page)

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
    paths = [f"{DNS_CFG}{key}" for key in DNS_SAVED_KEYS] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    try:
        _open(page, webui, DNS_PAGE)
        cert = page.locator('select[name="pfb_dns_sslcertref"]')
        assert cert.count() == 1, "the box offers no certificate with a private key: nothing to select"
        cert_ref = cert.locator("option").first.get_attribute("value")
        assert cert_ref, "the first certificate option has no refid"
        cert.select_option(cert_ref)
        page.get_by_role("listbox", name="DNS Interface(s)", exact=True).select_option("lo0")
        page.get_by_role("listbox", name="DoT Interface(s)", exact=True).select_option("lo0")
        page.locator('input[name="pfb_dns_dot"]').check()

        _save(page)

        assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").inner_text()
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_dot") == "on"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_interface") == "lo0"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_dot_interface") == "lo0"
        assert helpers.config_get(smoke_vm, f"{DNS_CFG}pfb_dns_sslcertref") == cert_ref
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
    paths = [f"{DNS_CFG}{key}" for key in DNS_SAVED_KEYS] + [REPLY_CFG]
    originals = {path: helpers.config_get_state(smoke_vm, path) for path in paths}
    entry = {"mode": "ipalias", "interface": "lo0", "type": "single", "subnet": _VIP_ADDR, "subnet_bits": "32"}
    lists = [f"{DNS_CFG}pfb_dns{kind}_interface" for kind in ("", "_dot", "_doh", "_doq")]
    setup = (
        "$vips = config_get_path('virtualip/vip', array());\n"
        f"$vips[] = {helpers._php_kv_array(entry | {'descr': 'pfB-DNS issue 3557', 'uniqid': _VIP_UNIQID})};\n"
        "config_set_path('virtualip/vip', $vips);\n"
        + "".join(f"config_set_path({helpers._php_str(path)}, {helpers._php_str(stored)});\n" for path in lists)
        + "".join(
            f"config_set_path({helpers._php_str(f'{DNS_CFG}pfb_dns_{kind}')}, '');\n" for kind in ("dot", "doh", "doq")
        )
        + "write_config('pfBlockerNG smoke: issue 3557 stored listener tokens');\n"
        "echo 'OK';"
    )
    try:
        result = helpers.php_eval(smoke_vm, setup)
        assert result.returncode == 0 and "OK" in result.stdout, f"setup failed: {result.stdout!r} {result.stderr!r}"
        _open(page, webui, DNS_PAGE)
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

        _save(page)

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
