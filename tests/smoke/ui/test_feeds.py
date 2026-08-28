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

Target aliases are pre-defined entries shipped in ``pfblockerng_feeds.json`` and
stable across the support matrix, one per type so EACH type's rename round-trip is
pinned independently (ADR-16 Phase 2 -- the oracle the Phase-3 type-scoped save must
keep green): the IPv4 alias ``PRI1`` (field ``feed_pri1``), the IPv6 alias ``PRI1_6``
(field ``feed_pri1_6``), and the DNSBL group ``ADs`` (field ``feed_ads``). All three
are written to ``installedpackages/pfblockerngglobal/feed_<lower(aliasname)>``.

ADR-16 Phase 3 -- the split + type-scoped save. ``pfblockerng_feeds.php`` is now three
``?type=ipv4|ipv6|dnsbl`` sub-tabs: only the active type renders, and the save loops
ONLY ``$pfb['feeds_list'][$type]`` (the active type, carried in a hidden ``type`` form
field). The per-type rename oracles below are retargeted to the typed URL of the type
they pin (IPv4 -> ``?type=ipv4``, IPv6 -> ``?type=ipv6``, DNSBL -> ``?type=dnsbl``); the
type-scoped save must keep them green. :meth:`WebUI.post` re-scrapes the typed page, so
it re-POSTs only that type's fields plus the hidden ``type`` -- a partial, single-type
POST, which is what makes the cross-type non-clobber test below possible.

``test_feed_rename_cross_type_save_does_not_clobber`` is the headline contract guarantee
(ADR §2 A3): saving the IPv4 tab leaves a DNSBL rename intact, and saving the DNSBL tab
leaves an IPv4 rename intact -- proven a real transition in BOTH directions (seed both,
assert both present, POST one type, assert the OTHER unchanged; and vice-versa).

Save-handler quirk pinned here: the >24-char "Alternate Aliasname" length guard is
skipped for DNSBL aliases (``!in_array(..., $feeds_list['dnsbl'])``), so the DNSBL
reject branch is exercised via the ``preg_match "/\\W/"`` (non-word char) path, the
same validator the IPv4/IPv6 fields use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

# The Feeds page is split into ?type sub-tabs (ADR-16 Phase 3); each rename oracle posts
# to the typed URL of the type it pins, so the page renders that type's fields and the
# save is scoped to it.
FEEDS_PAGE = "/pfblockerng/pfblockerng_feeds.php"
FEEDS_PAGE_IPV4 = f"{FEEDS_PAGE}?type=ipv4"
FEEDS_PAGE_IPV6 = f"{FEEDS_PAGE}?type=ipv6"
FEEDS_PAGE_DNSBL = f"{FEEDS_PAGE}?type=dnsbl"

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

# A pre-defined IPv6 alias shipped in pfblockerng_feeds.json (the IPv6 Primary Tier
# collection, the IPv6 sibling of PRI1). Rename round-trip via feed_<lower(aliasname)>.
RENAME6_ALIAS = "PRI1_6"
RENAME6_FIELD = "feed_pri1_6"
RENAME6_CFG = "installedpackages/pfblockerngglobal/feed_pri1_6"
# Word-only (<=24 chars, per the non-DNSBL length guard) -> accepted, stored verbatim.
RENAME6_VALID = "PRI16renamed"

# A pre-defined DNSBL group shipped in pfblockerng_feeds.json. Same rename mechanism;
# the >24-char "Alternate Aliasname" length guard does NOT apply to DNSBL aliases.
DNSBL_RENAME_ALIAS = "ADs"
DNSBL_RENAME_FIELD = "feed_ads"
DNSBL_RENAME_CFG = "installedpackages/pfblockerngglobal/feed_ads"
# Word-only value -> accepted and stored verbatim (no length cap for DNSBL).
DNSBL_RENAME_VALID = "ADsRenamed"
# A value containing a space -> preg_match "/\\W/" matches -> input error -> the whole
# save aborts before write_config; pins the reject branch for the DNSBL field too.
DNSBL_RENAME_INVALID = "ADs bad"


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

        # RENAME via the real CSRF form (IPv4 tab); the page must persist the override.
        resp = webui.post(FEEDS_PAGE_IPV4, {RENAME_FIELD: RENAME_VALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "Feeds rename POST returned the login form (session lost)"
        assert helpers.config_get(vm, RENAME_CFG) == RENAME_VALID, (
            f"{RENAME_CFG} did not become {RENAME_VALID!r} after the rename POST (oracle: config.xml, not HTTP body)"
        )

        # RESTORE via the form: clear the override (empty value is accepted and
        # writes the default-name state back) -- proves the reverse transition.
        resp = webui.post(FEEDS_PAGE_IPV4, {RENAME_FIELD: ""}, timeout=120.0)
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
    resp = webui.post(FEEDS_PAGE_IPV4, {RENAME_FIELD: seeded}, timeout=120.0)
    assert not looks_like_login_page(resp.text), "Feeds seed POST returned the login form (session lost)"
    try:
        # BEFORE: the seeded override is in effect.
        assert helpers.config_get(vm, RENAME_CFG) == seeded, (
            f"{RENAME_CFG} was not seeded to {seeded!r} before the reject POST"
        )

        # REJECT: a space makes the alias invalid -> the save aborts with no write.
        resp = webui.post(FEEDS_PAGE_IPV4, {RENAME_FIELD: RENAME_INVALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "Feeds invalid-alias POST returned the login form"

        # AFTER: config.xml is UNCHANGED -- the invalid POST wrote nothing.
        assert helpers.config_get(vm, RENAME_CFG) == seeded, (
            f"{RENAME_CFG} changed after a rejected invalid-alias POST (it must stay {seeded!r}); "
            f"the handler should abort write_config when an alias contains a non-word char"
        )
    finally:
        _config_del(vm, RENAME_CFG)


def test_feed_rename_ipv6_save_changes_effective_config(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """An IPv6 group rename in the current Feeds form persists feed_<alias>, both ways.

    ADR-16 Phase 2 oracle: pins the per-type save for the IPv6 type on the CURRENT
    single all-types page, so Phase 3's type-scoped save (the IPv6 sub-tab POSTing
    only its own fields) must keep this green. True transition (CLAUDE.md): the
    PRI1_6 override starts empty (default-name state), the form POST sets it to a
    word-only name and config.xml holds that name, then a second POST clears it back
    to empty and config.xml returns to the default-name state. Oracle is config.xml
    read over SSH, never the POST response body.
    """
    vm = smoke_vm
    # Known baseline: no rename override for PRI1_6 (the default-name state).
    _config_del(vm, RENAME6_CFG)
    try:
        # BEFORE: the override is empty (default name in effect).
        assert helpers.config_get(vm, RENAME6_CFG) == "", (
            f"{RENAME6_CFG} is not empty before the rename POST (expected the default-name state)"
        )

        # RENAME via the real CSRF form (IPv6 tab); the page must persist the override.
        resp = webui.post(FEEDS_PAGE_IPV6, {RENAME6_FIELD: RENAME6_VALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "IPv6 rename POST returned the login form (session lost)"
        assert helpers.config_get(vm, RENAME6_CFG) == RENAME6_VALID, (
            f"{RENAME6_CFG} did not become {RENAME6_VALID!r} after the rename POST (oracle: config.xml, not HTTP body)"
        )

        # RESTORE via the form: clearing the override writes the default-name state
        # back -- proves the reverse transition.
        resp = webui.post(FEEDS_PAGE_IPV6, {RENAME6_FIELD: ""}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "IPv6 rename-restore POST returned the login form"
        assert helpers.config_get(vm, RENAME6_CFG) == "", (
            f"{RENAME6_CFG} did not return to the default-name state after clearing the override"
        )
    finally:
        _config_del(vm, RENAME6_CFG)


def test_feed_rename_dnsbl_save_changes_effective_config(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A DNSBL group rename in the current Feeds form persists feed_<alias>, both ways.

    ADR-16 Phase 2 oracle: pins the per-type save for the DNSBL type on the CURRENT
    single all-types page, so Phase 3's type-scoped save (the DNSBL sub-tab POSTing
    only its own fields) must keep this green. True transition (CLAUDE.md): the ADs
    override starts empty (default-name state), the form POST sets it to a word-only
    name and config.xml holds that name, then a second POST clears it back to empty
    and config.xml returns to the default-name state. Oracle is config.xml read over
    SSH, never the POST response body.
    """
    vm = smoke_vm
    # Known baseline: no rename override for ADs (the default-name state).
    _config_del(vm, DNSBL_RENAME_CFG)
    try:
        # BEFORE: the override is empty (default name in effect).
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == "", (
            f"{DNSBL_RENAME_CFG} is not empty before the rename POST (expected the default-name state)"
        )

        # RENAME via the real CSRF form (DNSBL tab); the page must persist the override.
        resp = webui.post(FEEDS_PAGE_DNSBL, {DNSBL_RENAME_FIELD: DNSBL_RENAME_VALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "DNSBL rename POST returned the login form (session lost)"
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == DNSBL_RENAME_VALID, (
            f"{DNSBL_RENAME_CFG} did not become {DNSBL_RENAME_VALID!r} after the rename POST "
            f"(oracle: config.xml, not HTTP body)"
        )

        # RESTORE via the form: clearing the override writes the default-name state
        # back -- proves the reverse transition.
        resp = webui.post(FEEDS_PAGE_DNSBL, {DNSBL_RENAME_FIELD: ""}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "DNSBL rename-restore POST returned the login form"
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == "", (
            f"{DNSBL_RENAME_CFG} did not return to the default-name state after clearing the override"
        )
    finally:
        _config_del(vm, DNSBL_RENAME_CFG)


def test_feed_rename_dnsbl_invalid_alias_is_rejected_config_unchanged(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """An invalid DNSBL alias name is rejected and config.xml stays UNCHANGED.

    Branch coverage for the DNSBL field, paired with the valid DNSBL case: a value
    containing a space hits ``preg_match "/\\W/"`` -> ``$input_errors`` -> the save
    aborts before ``write_config`` (a single bad field blocks the whole save). The
    transition rule still applies: the test seeds a KNOWN valid override first and
    asserts it, drives the rejecting POST, then asserts the override is STILL the
    seeded value -- so the green proves the bad POST did NOT mutate config (not that
    it merely happened to already hold the expected value). This pins the reject
    branch for the DNSBL type, where the >24-char length guard does not apply.
    """
    vm = smoke_vm
    seeded = "ADsSeed"
    # Seed a known, valid override via the form so there is a concrete before-value
    # that a (wrongly) accepted bad POST would overwrite.
    resp = webui.post(FEEDS_PAGE_DNSBL, {DNSBL_RENAME_FIELD: seeded}, timeout=120.0)
    assert not looks_like_login_page(resp.text), "DNSBL seed POST returned the login form (session lost)"
    try:
        # BEFORE: the seeded override is in effect.
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == seeded, (
            f"{DNSBL_RENAME_CFG} was not seeded to {seeded!r} before the reject POST"
        )

        # REJECT: a space makes the alias invalid -> the save aborts with no write.
        resp = webui.post(FEEDS_PAGE_DNSBL, {DNSBL_RENAME_FIELD: DNSBL_RENAME_INVALID}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "DNSBL invalid-alias POST returned the login form"

        # AFTER: config.xml is UNCHANGED -- the invalid POST wrote nothing.
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == seeded, (
            f"{DNSBL_RENAME_CFG} changed after a rejected invalid-alias POST (it must stay {seeded!r}); "
            f"the handler should abort write_config when an alias contains a non-word char"
        )
    finally:
        _config_del(vm, DNSBL_RENAME_CFG)


def test_feed_rename_cross_type_save_does_not_clobber(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Saving one type's Feeds tab leaves the OTHER types' renames UNCHANGED (ADR-16 A3).

    Scenario (the headline contract guarantee of the split): the page is three
    ``?type`` sub-tabs and the save is type-scoped -- it loops only
    ``$pfb['feeds_list'][$type]`` (the active type, carried in the hidden ``type``
    field). A per-type tab therefore POSTs only its own ``feed_*`` fields, and the
    handler must NOT reset any other type's ``feed_<alias>`` node to ''.

    Background: on the OLD single all-types page the save looped EVERY type and wrote
    each absent field as '' -- a partial single-type POST there would have clobbered
    the other types. That regression is exactly what this test forbids.

    True transition in BOTH directions (CLAUDE.md): seed an IPv4 rename AND a DNSBL
    rename and assert BOTH are present (the before-state). Then:
      * POST the IPv4 tab changing ONLY the IPv4 field  -> assert the DNSBL rename is
        STILL its seeded value (IPv4 save did not touch DNSBL).
      * POST the DNSBL tab changing ONLY the DNSBL field -> assert the IPv4 rename is
        STILL its (new) value (DNSBL save did not touch IPv4).
    Asserting the before-state first proves a green is the non-clobber guarantee, not
    a value that happened to already hold. Both overrides are dropped in ``finally``.
    Oracle is config.xml read over SSH, never the POST response body.
    """
    vm = smoke_vm
    ipv4_seed = "PRI1cross"
    ipv4_new = "PRI1cross2"
    dnsbl_seed = "ADsCross"
    dnsbl_new = "ADsCross2"

    # Known baseline: drop any stray override on both nodes.
    _config_del(vm, RENAME_CFG)
    _config_del(vm, DNSBL_RENAME_CFG)
    try:
        # GIVEN: seed an IPv4 rename (on the IPv4 tab) and a DNSBL rename (on the
        # DNSBL tab); each save is scoped to its own type.
        resp = webui.post(FEEDS_PAGE_IPV4, {RENAME_FIELD: ipv4_seed}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "IPv4 seed POST returned the login form (session lost)"
        resp = webui.post(FEEDS_PAGE_DNSBL, {DNSBL_RENAME_FIELD: dnsbl_seed}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "DNSBL seed POST returned the login form (session lost)"

        # BEFORE: BOTH renames are present (the cross-type starting state).
        assert helpers.config_get(vm, RENAME_CFG) == ipv4_seed, (
            f"{RENAME_CFG} was not seeded to {ipv4_seed!r} before the cross-type POSTs"
        )
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == dnsbl_seed, (
            f"{DNSBL_RENAME_CFG} was not seeded to {dnsbl_seed!r} before the cross-type POSTs"
        )

        # WHEN: POST the IPv4 tab changing ONLY the IPv4 field.
        resp = webui.post(FEEDS_PAGE_IPV4, {RENAME_FIELD: ipv4_new}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "IPv4 cross-type POST returned the login form"
        # THEN: the IPv4 node took the new value AND the DNSBL node is UNCHANGED
        # (the IPv4 tab's POST carries no DNSBL field, and the save is type-scoped).
        assert helpers.config_get(vm, RENAME_CFG) == ipv4_new, (
            f"{RENAME_CFG} did not become {ipv4_new!r} after the IPv4 tab POST"
        )
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == dnsbl_seed, (
            f"{DNSBL_RENAME_CFG} was CLOBBERED by an IPv4-tab save (it must stay {dnsbl_seed!r}); "
            f"the type-scoped save must not touch another type's feed_<alias> nodes"
        )

        # WHEN: POST the DNSBL tab changing ONLY the DNSBL field.
        resp = webui.post(FEEDS_PAGE_DNSBL, {DNSBL_RENAME_FIELD: dnsbl_new}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "DNSBL cross-type POST returned the login form"
        # THEN: the DNSBL node took the new value AND the IPv4 node is UNCHANGED.
        assert helpers.config_get(vm, DNSBL_RENAME_CFG) == dnsbl_new, (
            f"{DNSBL_RENAME_CFG} did not become {dnsbl_new!r} after the DNSBL tab POST"
        )
        assert helpers.config_get(vm, RENAME_CFG) == ipv4_new, (
            f"{RENAME_CFG} was CLOBBERED by a DNSBL-tab save (it must stay {ipv4_new!r}); "
            f"the type-scoped save must not touch another type's feed_<alias> nodes"
        )
    finally:
        _config_del(vm, RENAME_CFG)
        _config_del(vm, DNSBL_RENAME_CFG)
