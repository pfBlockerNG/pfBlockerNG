"""Tier-A ``ui_render`` coverage for issue #1497 (PR #1506)'s page-level fixes.

PR #1506 burns the level-2 PHPStan ``variable.undefined`` cohort (#1493-#1497)
to zero across the pfBlockerNG www pages. Most of the touched render paths are
ALREADY GET-swept by ``test_render_smoke.py``'s ``PAGE_TABLE`` (the generic
Tier-A oracle: HTTP 200, no rendered PHP diagnostic SHAPE, a page marker, and no
``php_error.log`` growth -- see ``render_oracle.py``), so duplicating a plain
GET here would be coverage theater (CLAUDE.md "no coverage theater"):

* ``pfblockerng_blacklist.php`` plain GET -- the ``blacklist`` PAGE_TABLE entry
  already exercises the top-of-file ``$savemsg``/``$input_errors`` init (#1496),
  which runs unconditionally before the ``$_POST`` branch.
* ``pfblockerng_category.php`` plain GET -- ``$gtype`` with no ``?type`` param
  falls through the SAME switch case as ``category_dnsbl``
  (``case 'dnsbl': default:`` share one block, category.php:111-117), so the
  ``continue;`` invalid-prefix fix (#1496) is already exercised.
* ``pfblockerng_feeds.php`` plain GET -- ``$gtype`` defaults to ``'ipv4'`` with
  no ``?type`` param (feeds.php:42), identical to the ``feeds_ipv4`` entry; the
  ``$p_type``/``$p_tr_style`` defaults (#1497/#1496) run unconditionally on
  every type's Custom Feeds render, regardless of whether custom feeds exist.
* ``pfblockerng_general.php`` plain GET -- the fix there is an
  ``@phpstan-ignore`` annotation only (zero runtime change); the ``general``
  PAGE_TABLE entry already proves the page renders warning-free.

Two render paths genuinely have NO existing Tier-A coverage and are pinned here:

1. ``pfblockerng_alerts.php?view=unified`` -- the Unified-view first-pass
   cluster (``$p_query_port``/``$colspan``/``$fcounter``/``$pfbfilterlimit``/the
   ``$rtype`` coalesce, #1495) only runs when ``$logtype == 'Unified'`` reaches
   the render loop past the "skip empty table" gate, which only happens for
   ``$alert_view == 'unified'`` (alerts.php:4267-4272) -- the default
   ``alerts`` PAGE_TABLE entry (no ``?view``) uses ``$alert_view == 'alert'``,
   under which the ``Unified`` iteration ``continue 2``s at alerts.php:4257
   before ever reaching that cluster.
2. ``pfblockerng_category_edit.php?type=dnsbl&act=add&atype=<stale>`` -- the
   ``$a_aliasname``/``$a_description``/``$a_cron``/``$a_url``/``$a_header``
   defaults (#1496, category_edit.php:200) only run on the ``act=add``
   "no matching feed found" path (a stale/bookmarked ``atype`` the current DNSBL
   feed catalog no longer contains); the existing
   ``category_edit_fresh_addgroup_whitelist`` PAGE_TABLE entry uses
   ``act=addgroup`` with a ``Whitelist|...`` atype, which takes the Whitelist
   branch (category_edit.php:297-322) and never reads any of these 5 variables.

Both GETs are hermetic (no config write -- no ``$_POST['save']``, no feed
download) and reuse the exact oracle (``evaluate_render`` + ``PhpErrorLogGuard``)
every other Tier-A ``ui_render`` module uses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

ALERTS_UNIFIED_PAGE = "/pfblockerng/pfblockerng_alerts.php?view=unified"

# PFB_FILTER_ATYPE (pfblockerng.inc ~1728) accepts only [a-zA-Z0-9.|_]+ -- no
# hyphen. Deliberately does not match any real feed header/aliasname in the
# DNSBL catalog (a stale/bookmarked link after a catalog change), so
# $pfb_found stays FALSE and the page falls through to the fresh-row defaults
# this module pins.
_STALE_ATYPE = "Smoke1497StaleFeedNotInCatalog"
CATEGORY_EDIT_ADD_DNSBL_STALE_PAGE = (
    f"/pfblockerng/pfblockerng_category_edit.php?type=dnsbl&act=add&atype={_STALE_ATYPE}"
)


def test_alerts_unified_view_renders_clean(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """``?view=unified`` renders the Unified panel without a PHP diagnostic (#1495).

    Scenario:
      Given the default install (the ``pfbunicnt`` aglobal counter defaults to
        200 -- alerts.php:35 -- so the Unified panel's "skip empty table" guard
        does not skip it; no log content needs seeding).
      When  GET ``pfblockerng_alerts.php?view=unified``.
      Then  the Tier-A oracle passes (200, no PHP diagnostic shape, the Unified
            panel marker present) AND ``php_error.log`` gains no new gated-class
            diagnostic from a pfBlockerNG file --
            the two ways a suppressed ``variable.undefined`` regression would
            surface (#1495: ``$p_query_port``/``$colspan``/``$fcounter``/
            ``$pfbfilterlimit``/the ``$rtype`` coalesce all execute on this
            exact path, regardless of whether the unified log FILE exists).
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_UNIFIED_PAGE)
    # "Unified<small>" is the panel h2 title's gettext($logtype) output butted
    # directly against the literal <small> tag (alerts.php:4292, byte-verified
    # -- zero whitespace between the PHP short-echo and the tag), so it proves
    # the Unified panel itself rendered, not just the always-present "Unified"
    # sub-tab nav label.
    result = evaluate_render(ALERTS_UNIFIED_PAGE, resp.status_code, resp.text, ("Unified<small>",))
    assert result.ok, f"Tier-A render oracle failed for the Unified alerts view: {result.detail}"

    guard.assert_no_growth()


def test_category_edit_add_dnsbl_stale_atype_renders_clean(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """``act=add`` with a stale/unmatched DNSBL ``atype`` renders clean (#1496).

    Scenario:
      Given a bookmarked/stale add link: ``type=dnsbl&act=add`` with an
        ``atype`` that matches no feed header/aliasname in the current DNSBL
        catalog (the exact "catalog changed since the link was bookmarked"
        scenario the fix's comment names).
      When  GET the category-edit page with that link.
      Then  the Tier-A oracle passes (200, no PHP diagnostic shape, the page's
            marker present) AND ``php_error.log`` gains no new gated-class diagnostic
            from a pfBlockerNG file -- the
            page falls through to the ``!$pfb_found`` branch
            (category_edit.php:277-291), reading ``$a_aliasname``/
            ``$a_description``/``$a_cron``/``$a_url``/``$a_header`` before any
            assignment inside the (never-matched) feed loop. No config write
            happens (no ``$_POST['save']`` in the request), so no cleanup is
            needed.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(CATEGORY_EDIT_ADD_DNSBL_STALE_PAGE)
    # "Override Default Schedule" is unique to category_edit now that the IP tab
    # also has an Advanced Settings section.
    result = evaluate_render(
        CATEGORY_EDIT_ADD_DNSBL_STALE_PAGE, resp.status_code, resp.text, ("Override Default Schedule",)
    )
    assert result.ok, f"Tier-A render oracle failed for the stale-atype add path: {result.detail}"

    guard.assert_no_growth()
