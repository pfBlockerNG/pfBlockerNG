"""Tier-B functional WebUI flows for the Feeds page (ADR-14 Phase 3).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier runs with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

What this file establishes: the ``pfblockerng_feeds.php`` save handler persists
its two distinct deltas to the EFFECTIVE config.xml, and rejects a bad input
without mutating config. Per the ADR oracle rule, the test reads the box's
effective state (``config.xml`` via :func:`tests.smoke.helpers.config_get`),
NEVER the HTTP response body -- a 200 / clean post-redirect does not prove the
save took; re-reading the config node does.

The Feeds save handler (read END TO END):

* ``isset($_POST['save'])`` gates the whole save.
* RENAME / COMBINE: for every pre-defined alias the page renders a text input
  ``feed_<lower(aliasname)>``. A value with a non-word char (``preg_match
  "/\\W/"``) is rejected -> ``$input_errors`` -> the save aborts WITHOUT
  ``write_config`` (``if ($config_mod) { if (!$input_errors) { write_config... }
  }``), so a SINGLE bad field leaves config.xml UNCHANGED. A word-only value
  (letters/digits/underscore; empty also passes) is written to
  ``installedpackages/pfblockerngglobal/feed_<lower(aliasname)>``. An empty value
  is the "default name" state (no override).

ALT-URL save is intentionally NOT covered here -- it is deferred to the browser
tier (Batch 4). The handler iterates EVERY header in the hidden ``alt_selected``
CSV and, for each, requires a non-empty ``alt_<header>`` POST value, else it sets
``$input_errors`` and the whole save aborts before ``write_config``. The page
emits, per header, a same-named ``<input type=hidden value="">`` alongside the
checked base radio; reproducing the browser's multi-value same-name POST (hidden
"" + checked radio value) is exactly what :func:`scrape_form_fields` cannot do
faithfully -- it resolves the collision to the empty value, so every alt header
POSTs empty and the save errors. Driving the actual radio click (Playwright)
sends the right values, so this flow belongs in the browser tier, not here.

Every flow is a TRUE transition test (CLAUDE.md): it asserts the BEFORE value,
drives the CSRF form POST, asserts the AFTER value via the config oracle, then
RESTORES the box (asserting the reverse where it applies). Restore runs in a
``finally`` so a mid-test failure cannot poison the session-scoped VM for the
sibling flows. Branch coverage: the rename validator gets a VALID case (accepted,
config changes) AND a REJECTING case (config stays unchanged).

Target alias is a pre-defined entry shipped in ``pfblockerng_feeds.json`` and
stable across the support matrix: the IPv4 alias ``PRI1`` (field ``feed_pri1``)
for the rename flows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

FEEDS_PAGE = "/pfblockerng/pfblockerng_feeds.php"

# A pre-defined IPv4 alias shipped in pfblockerng_feeds.json. The page renders its
# rename input as feed_<lower(aliasname)>, and the save writes the override to
# installedpackages/pfblockerngglobal/feed_<lower(aliasname)>.
RENAME_ALIAS = "PRI1"
RENAME_FIELD = "feed_pri1"
RENAME_CFG = "installedpackages/pfblockerngglobal/feed_pri1"
# A word-only value (<=24 chars for a non-DNSBL alias, per the handler's length
# guard) -> accepted and stored verbatim.
RENAME_VALID = "PRI1renamed"
# A value containing a space -> preg_match "/\\W/" matches -> input error ->
# the whole save aborts before write_config, so config.xml stays unchanged.
RENAME_INVALID = "PRI1 bad"


def _config_del(vm: helpers.SmokeVM, path: str, *, timeout: float = 60.0) -> None:
    """Delete a config.xml node and persist, mirroring the package's own delete.

    Used to restore the box to its true pre-test state when a flow CREATES a
    config node that did not exist before (the form save can only WRITE a value,
    not remove the node, so a plain re-POST cannot un-create it).
    """
    snippet = (
        f"config_del_path({helpers._php_str(path)});\n"
        "write_config('pfBlockerNG smoke: feeds test cleanup');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_config_del({path!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def test_feed_rename_save_changes_effective_config(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A valid rename in the Feeds form persists feed_<alias> to config.xml, both ways.

    True transition (CLAUDE.md): the alias override starts empty (the default-name
    state -- no override stored), the form POST sets it to a word-only name, and
    config.xml holds that name; then a second POST clears it back to empty and
    config.xml returns to the default-name state. The green proves the POST CAUSED
    each change, and both directions of the rename are exercised. Oracle is
    config.xml read over SSH, never the POST response body.
    """
    vm = smoke_vm
    # Known baseline: no rename override for PRI1 (the default-name state).
    _config_del(vm, RENAME_CFG)
    try:
        # BEFORE: the override is empty (default name in effect).
        assert helpers.config_get(vm, RENAME_CFG) == "", (
            f"{RENAME_CFG} is not empty before the rename POST (expected the default-name state)"
        )

        # RENAME via the real CSRF form; the page must persist the override.
        resp = webui.post(FEEDS_PAGE, {RENAME_FIELD: RENAME_VALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "Feeds rename POST returned the login form (session lost)"
        assert helpers.config_get(vm, RENAME_CFG) == RENAME_VALID, (
            f"{RENAME_CFG} did not become {RENAME_VALID!r} after the rename POST (oracle: config.xml, not HTTP body)"
        )

        # RESTORE via the form: clear the override (empty value is accepted and
        # writes the default-name state back) -- proves the reverse transition.
        resp = webui.post(FEEDS_PAGE, {RENAME_FIELD: ""}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "Feeds rename-restore POST returned the login form"
        assert helpers.config_get(vm, RENAME_CFG) == "", (
            f"{RENAME_CFG} did not return to the default-name state after clearing the override"
        )
    finally:
        # Belt-and-suspenders: drop the node so a mid-test abort can't leave a
        # rename override on the session-scoped VM for the sibling flows.
        _config_del(vm, RENAME_CFG)


def test_feed_rename_invalid_alias_is_rejected_config_unchanged(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """An invalid alias name is rejected and config.xml stays UNCHANGED.

    Branch coverage paired with the valid case: a value containing a space hits
    ``preg_match "/\\W/"`` -> ``$input_errors`` -> the save aborts before
    ``write_config`` (a single bad field blocks the whole save). The transition
    rule still applies: the test seeds a KNOWN valid override first and asserts it,
    drives the rejecting POST, then asserts the override is STILL the seeded value
    -- so the green proves the bad POST did NOT mutate config (not that it merely
    happened to already hold the expected value).
    """
    vm = smoke_vm
    seeded = "PRI1seed"
    # Seed a known, valid override via the form so there is a concrete before-value
    # that a (wrongly) accepted bad POST would overwrite.
    resp = webui.post(FEEDS_PAGE, {RENAME_FIELD: seeded}, timeout=120.0)
    assert not looks_like_login_page(resp.text), "Feeds seed POST returned the login form (session lost)"
    try:
        # BEFORE: the seeded override is in effect.
        assert helpers.config_get(vm, RENAME_CFG) == seeded, (
            f"{RENAME_CFG} was not seeded to {seeded!r} before the reject POST"
        )

        # REJECT: a space makes the alias invalid -> the save aborts with no write.
        resp = webui.post(FEEDS_PAGE, {RENAME_FIELD: RENAME_INVALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "Feeds invalid-alias POST returned the login form"

        # AFTER: config.xml is UNCHANGED -- the invalid POST wrote nothing.
        assert helpers.config_get(vm, RENAME_CFG) == seeded, (
            f"{RENAME_CFG} changed after a rejected invalid-alias POST (it must stay {seeded!r}); "
            f"the handler should abort write_config when an alias contains a non-word char"
        )
    finally:
        _config_del(vm, RENAME_CFG)
