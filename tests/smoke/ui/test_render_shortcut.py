"""Tier-A (ui_render) + Tier-B (ui_browser) tests for the pfBlockerNG title-bar
syslog shortcut icon.

Every pfBlockerNG page sets ``$shortcut_section = 'pfblockerng'`` before including
``head.inc``.  ``head.inc`` reads ``$shortcuts['pfblockerng']['log']`` from
``shortcuts/pkg_pfblockerng.inc`` and renders a log-link anchor whose ``href`` is the
ROOT-ABSOLUTE ``/status_logs_packages.php?pkg=``.  These tests pin that contract.

The href MUST be root-absolute: pfBlockerNG's GUI pages live under ``/pfblockerng/`` and
head.inc emits the value verbatim, so a relative ``status_logs_packages.php?pkg=`` would
resolve to ``/pfblockerng/status_logs_packages.php`` and 404.  The tests therefore assert
the leading slash, not merely that the substring is present.

Tier-A (``ui_render``) -- hermetic HTTP GET only:
  ``test_shortcut_log_link_rendered`` — GET the General page and assert the rendered body
  contains the absolute ``href="/status_logs_packages.php?pkg=`` and does NOT contain the
  relative (subdir-resolving) ``href="status_logs_packages.php?pkg=``.

Tier-B (``ui_browser``) -- Playwright DOM inspection:
  ``test_shortcut_log_anchor_in_dom`` — load the General page in the authenticated browser
  and assert the title-bar log-shortcut anchor is present with a root-absolute ``href``
  (starts with ``/status_logs_packages.php?pkg=``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from .webui import WebUI

# The General page is the lightest pfBlockerNG page -- always hermetic, no external
# data needed, good witness for the shortcut chrome that appears on every page.
_GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"

# head.inc renders the log-shortcut as <a href="..."> with the 'log' value verbatim.
# The href MUST be root-absolute (leading slash) so it resolves from the web root, not
# from the /pfblockerng/ subdir the GUI pages live in.
_ABS_HREF = 'href="/status_logs_packages.php?pkg='
# The pre-fix relative form, which the browser resolves to /pfblockerng/...  -> 404.
_REL_HREF = 'href="status_logs_packages.php?pkg='


# ---------------------------------------------------------------------------
# Tier-A: ui_render
# ---------------------------------------------------------------------------


@pytest.mark.ui_render
def test_shortcut_log_link_rendered(webui: WebUI) -> None:
    """The General page renders the syslog shortcut link with a root-absolute href.

    Scenario: pfBlockerNG title-bar shortcut icon links to the package syslog.
      Background: pfBlockerNG deployed; shortcuts/pkg_pfblockerng.inc installed;
        every pfBlockerNG page sets $shortcut_section = 'pfblockerng'.

      Given the authenticated webConfigurator session,

      When GET /pfblockerng/pfblockerng_general.php,

      Then the response body contains the rendered log-shortcut anchor with a
        root-absolute href ``href="/status_logs_packages.php?pkg=`` and NOT the
        relative ``href="status_logs_packages.php?pkg=`` form.

    Fail-before / pass-after: the GUI pages live under /pfblockerng/, so the
    relative href the shortcut originally emitted resolved to
    /pfblockerng/status_logs_packages.php and 404'd.  Before the fix the body
    carries the relative form (no leading slash), so the absolute assertion FAILS;
    after the fix it carries the absolute form and PASSES.  The "relative absent"
    assertion guards against a regression back to the subdir-resolving href.
    """
    resp = webui.get(_GENERAL_PAGE)
    assert resp.status_code == 200, f"GET {_GENERAL_PAGE} -> HTTP {resp.status_code} (expected 200)"
    assert _ABS_HREF in resp.text, (
        f"Root-absolute syslog shortcut href {_ABS_HREF!r} not found in {_GENERAL_PAGE} body "
        f"-- expected head.inc to render the log-shortcut anchor from "
        f"$shortcuts['pfblockerng']['log'] with a leading slash (pkg_pfblockerng.inc + "
        f"$shortcut_section)"
    )
    assert _REL_HREF not in resp.text, (
        f"Relative syslog shortcut href {_REL_HREF!r} found in {_GENERAL_PAGE} body -- it "
        f"resolves against the /pfblockerng/ subdir and 404s; the href must be root-absolute"
    )


# ---------------------------------------------------------------------------
# Tier-B: ui_browser
# ---------------------------------------------------------------------------
# NOTE: the playwright import is scoped to the Tier-B test (not module-level) so a
# module-level importorskip does NOT skip the Tier-A ui_render test above, which is
# hermetic HTTP-only and must run in the render tier (no playwright installed there).

if TYPE_CHECKING:
    from playwright.sync_api import Page

# JS-driven DOM settles synchronously; this is a flake ceiling, not a wait knob.
JS_TIMEOUT_MS = 10_000


@pytest.mark.ui_browser
def test_shortcut_log_anchor_in_dom(
    browser_page: Page,
    webui: WebUI,
) -> None:
    """The title-bar log-shortcut anchor is present in the live DOM with a root-absolute href.

    Scenario: pfBlockerNG title-bar shortcut icon links to the package syslog (Tier B).
      Background: pfBlockerNG deployed with the shortcut file + $shortcut_section wired.

      Given the General page is loaded in the authenticated browser,

      When the DOM is inspected for the pfSense shortcuts log-link anchor,

      Then an anchor whose href STARTS WITH ``/status_logs_packages.php?pkg=``
        (root-absolute) is attached to the document, and no anchor carries the
        relative ``status_logs_packages.php?pkg=`` href -- proving the title-bar
        shortcut links to the web-root log page, not the /pfblockerng/ subdir.

    Fail-before / pass-after: before the fix the anchor's href is relative (no
    leading slash), so the ``[href^="/status_logs_packages.php?pkg="]`` selector
    matches nothing and the assertion FAILS; after the fix it matches and PASSES.
    """
    # The browser_page fixture already importorskips playwright, so it is present here.
    expect = pytest.importorskip("playwright.sync_api").expect

    page = browser_page
    page.goto(
        webui.url(_GENERAL_PAGE),
        wait_until="domcontentloaded",
        timeout=JS_TIMEOUT_MS * 3,
    )
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, (
        f"GET {_GENERAL_PAGE} showed the login form -- cookie not authenticated"
    )

    # head.inc renders the log-shortcut as an <a href="/status_logs_packages.php?pkg=...">
    # anchor in the title-bar shortcuts area.  Assert it is present and root-absolute.
    log_anchor = page.locator('a[href^="/status_logs_packages.php?pkg="]')
    assert log_anchor.count() > 0, (
        'No anchor with a root-absolute href starting "/status_logs_packages.php?pkg=" '
        f"found in the DOM of {_GENERAL_PAGE} -- title-bar syslog shortcut not rendered "
        f"or its href is relative (resolves to the /pfblockerng/ subdir and 404s)"
    )
    expect(log_anchor.first).to_be_attached(timeout=JS_TIMEOUT_MS)
