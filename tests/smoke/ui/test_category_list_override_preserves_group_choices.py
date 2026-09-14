"""issue #3288: the DNSBL Category SUMMARY list page (pfblockerng_category.php)
must render each group's Logging/Blocking Mode select at its OWN true stored
value -- never overwritten to the active global mechanism -- so that an
otherwise-UNCHANGED bulk Save (the rowhelper ``act=update``/``postdata`` AJAX)
never erases a group's saved choice.

Before #3288, ``pfblockerng_category.php``:532-536 unconditionally replaced a
DNSBL row's rendered/selected value with the global override whenever
``dnsbl_global_log`` was non-empty:

    if (!empty($pfb['dnsbl_global_log'])) {
        $logtype                = $pfb['dnsbl_global_log'];
        $log_options[$logtype]  = "{$log_options[$logtype]} (Global)";
    }

Because ``$logtype`` feeds straight into the row's ``Form_Select`` as BOTH the
selected AND (via a real browser round-trip) the eventually re-POSTed value,
clicking Save on the list page with no edits at all would silently rewrite
every DNSBL group's stored ``logging`` to the global mechanism. #3288 makes
this strictly worse if naively ported forward -- ``dnsbl_global_log`` is now
ALWAYS non-empty (Default and Override both carry a concrete mechanism), so
the old unconditional ``!empty()`` gate would fire for EVERY installation,
not just ones with an active override. The real fix gates on
``global_log_mode`` and never substitutes into the SELECTED option; these
tests pin that as the load-bearing regression proof.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

import pytest

from .. import helpers
from .test_category import DNSBL_GROUPS, _ajax_post, _page_url, _php_row_literal, _restore_node, _snapshot_node
from .test_category_edit_new_group_logging_default import _legacy_no_override_system
from .test_dnsbl_blocking_modes import _option_values, _select_block, _selected_value
from .webui import looks_like_login_page, row_containing

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_CATEGORY_PAGE = _page_url("dnsbl")
GLOBAL_LOG_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log"
GLOBAL_LOG_MODE_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log_mode"

AJAX_TIMEOUT = 120.0

# Row 0: an EXPLICIT concrete choice. Row 1: the new 'default' (live-inheritance)
# token. Together these are the two categories acceptance calls out: "retains
# explicit and inherited group choices".
_EXPLICIT_ROW_LOGGING = "nxdomain_log"
_DEFAULT_ROW_LOGGING = "default"


def _seed_two_dnsbl_rows(vm: helpers.SmokeVM) -> None:
    """Replace the DNSBL groups node with exactly TWO known rows at indices 0, 1."""
    rows = [
        {
            "aliasname": "pfb3288explicit",
            "action": "unbound",
            "cron": "Never",
            "logging": _EXPLICIT_ROW_LOGGING,
            "description": "pfBlockerNG smoke #3288 explicit choice",
        },
        {
            "aliasname": "pfb3288default",
            "action": "unbound",
            "cron": "Never",
            "logging": _DEFAULT_ROW_LOGGING,
            "description": "pfBlockerNG smoke #3288 default token",
        },
    ]
    entries = []
    for row in rows:
        feed = {
            "header": row["aliasname"],
            "url": f"{helpers.PFB_DBDIR}/{row['aliasname']}",
            "state": "Enabled",
            "format": "auto",
        }
        entries.append(_php_row_literal(row, feed))
    snippet = (
        f"config_set_path({helpers._php_str(DNSBL_GROUPS)}, array(" + ", ".join(entries) + "));\n"
        "write_config('pfBlockerNG smoke: seed #3288 category list rows');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_two_dnsbl_rows failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


_LEGACY_ROW_ALIAS = "pfb3288legacybulk"
_EXPLICIT_ROW_ALIAS = "pfb3288explicitbulk"
_EXPLICIT_ROW_UNTOUCHED_LOGGING = "nxdomain_log"


def _seed_legacy_and_explicit_dnsbl_rows(vm: helpers.SmokeVM) -> None:
    """Replace the DNSBL groups node with TWO rows: index 0 a raw legacy
    VIP-equivalent (NO 'logging' key -- the absent-key spelling), index 1 an
    explicit non-VIP concrete choice (must stay untouched by migration)."""
    legacy_row = {
        "aliasname": _LEGACY_ROW_ALIAS,
        "action": "unbound",
        "cron": "Never",
        "description": "pfBlockerNG smoke #3288 legacy bulk-save row",
    }
    explicit_row = {
        "aliasname": _EXPLICIT_ROW_ALIAS,
        "action": "unbound",
        "cron": "Never",
        "logging": _EXPLICIT_ROW_UNTOUCHED_LOGGING,
        "description": "pfBlockerNG smoke #3288 explicit bulk-save row",
    }
    entries = []
    for row in (legacy_row, explicit_row):
        feed = {
            "header": row["aliasname"],
            "url": f"{helpers.PFB_DBDIR}/{row['aliasname']}",
            "state": "Enabled",
            "format": "auto",
        }
        entries.append(_php_row_literal(row, feed))
    snippet = (
        f"config_set_path({helpers._php_str(DNSBL_GROUPS)}, array(" + ", ".join(entries) + "));\n"
        "write_config('pfBlockerNG smoke: seed #3288 legacy bulk-save rows');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_seed_legacy_and_explicit_dnsbl_rows failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def test_category_list_legacy_bulk_save_migrates_and_preserves_non_vip_choice(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Main's "Include category bulk Save too": the Category LIST page's
    ``act=update``/``postdata`` bulk Save is ALSO a facade call site on a
    genuinely legacy ("old no-global-override") system -- not just
    category_edit.php's single-row Save and dnsbl.php's global-settings Save.

    1. GET renders row 0 (raw legacy, no 'logging' key) as 'default'
       (projected) and row 1 (explicit 'nxdomain_log') unaffected.
    2. An UNCHANGED bulk Save (re-submitting exactly the two rendered/scraped
       values together, via ONE ``postdata`` payload) runs the facade: the
       marker + grandfather shared mechanism persist, row 0's own choice
       lands as the literal 'default' token, and row 1's non-VIP explicit
       choice is completely untouched (migration only converts VIP-shaped
       groups; "non-VIP explicit mechanisms remain unchanged").
    """
    vm = smoke_vm
    dnsbl_snap = _snapshot_node(vm, DNSBL_GROUPS)
    with _legacy_no_override_system(vm):
        try:
            _seed_legacy_and_explicit_dnsbl_rows(vm)

            resp = webui.get(DNSBL_CATEGORY_PAGE)
            assert not looks_like_login_page(resp.text), "category GET returned the login form (session lost)"
            row0 = row_containing(resp.text, "logging-0")
            row1 = row_containing(resp.text, "logging-1")
            selected_row0 = _selected_value(_select_block(row0, "logging-0"))
            selected_row1 = _selected_value(_select_block(row1, "logging-1"))
            assert selected_row0 == "default", (
                f"a raw legacy row on a legacy system must render 'default' (projected), got {selected_row0!r}"
            )
            assert selected_row1 == _EXPLICIT_ROW_UNTOUCHED_LOGGING, (
                f"an explicit non-VIP row must render its own choice unaffected, got {selected_row1!r}"
            )

            # An UNCHANGED bulk Save (both rows' rendered values, in ONE postdata payload).
            postdata = urlencode({"logging-0": selected_row0, "logging-1": selected_row1})
            _ajax_post(
                webui,
                {"act": "update", "type": "dnsbl", "rowid": "0", "postdata": postdata},
                page=DNSBL_CATEGORY_PAGE,
            )

            assert helpers.config_get(vm, GLOBAL_LOG_MODE_CFG) == "default", (
                "a valid category.php bulk Save on a legacy no-override system must run the "
                "upgrade facade -> Default policy"
            )
            assert helpers.config_get(vm, GLOBAL_LOG_CFG) == "enabled", (
                "the facade must persist the old no-override grandfather shared mechanism ('enabled')"
            )
            assert helpers.config_get(vm, f"{DNSBL_GROUPS}/0/logging") == "default", (
                "the facade-then-write ordering must land the submitted 'default' choice for the legacy row"
            )
            assert helpers.config_get(vm, f"{DNSBL_GROUPS}/1/logging") == _EXPLICIT_ROW_UNTOUCHED_LOGGING, (
                "migration must never touch a non-VIP explicit choice, even during a bulk Save that also migrates"
            )
        finally:
            _restore_node(vm, DNSBL_GROUPS, dnsbl_snap)


def test_category_list_override_bulk_save_preserves_explicit_and_default_group_choices(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """An UNCHANGED bulk Save on the DNSBL category list, while
    global_log_mode=override is active, must not alter EITHER row's own
    stored 'logging' value."""
    vm = smoke_vm
    dnsbl_snap = _snapshot_node(vm, DNSBL_GROUPS)
    mode_state = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
    mechanism_state = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
    try:
        _seed_two_dnsbl_rows(vm)
        helpers.config_set(vm, GLOBAL_LOG_MODE_CFG, "override")
        # Deliberately different from BOTH rows' own stored value, so a leaked
        # override write into either row is unambiguous (never coincidentally
        # matches the row's true value).
        helpers.config_set(vm, GLOBAL_LOG_CFG, "nodata_log")

        resp = webui.get(DNSBL_CATEGORY_PAGE)
        assert not looks_like_login_page(resp.text), "category GET returned the login form (session lost)"

        row0 = row_containing(resp.text, "logging-0")
        row1 = row_containing(resp.text, "logging-1")

        # Each row's OWN select must render its true stored value selected -- the
        # active Override mechanism must never be substituted in as the SELECTED
        # (and therefore eventually re-submitted) option.
        selected_row0 = _selected_value(_select_block(row0, "logging-0"))
        selected_row1 = _selected_value(_select_block(row1, "logging-1"))
        assert selected_row0 == _EXPLICIT_ROW_LOGGING, (
            f"an explicit group choice must render selected, never coerced to the active Override mechanism "
            f"(got {selected_row0!r})"
        )
        assert selected_row1 == _DEFAULT_ROW_LOGGING, (
            f"a 'default' group token must render selected, never coerced to the active Override mechanism "
            f"(got {selected_row1!r})"
        )

        # Simulate an UNCHANGED bulk Save: re-post EXACTLY what the page itself
        # just rendered as selected (mirrors a real browser's unedited submit --
        # not an injected "correct" answer, so this reproduces the actual bug).
        postdata = urlencode({"logging-0": selected_row0, "logging-1": selected_row1})
        _ajax_post(
            webui,
            {"act": "update", "type": "dnsbl", "rowid": "0", "postdata": postdata},
            page=DNSBL_CATEGORY_PAGE,
        )

        assert helpers.config_get(vm, f"{DNSBL_GROUPS}/0/logging") == _EXPLICIT_ROW_LOGGING, (
            "an UNCHANGED bulk Save under Override must not erase an explicit group choice"
        )
        assert helpers.config_get(vm, f"{DNSBL_GROUPS}/1/logging") == _DEFAULT_ROW_LOGGING, (
            "an UNCHANGED bulk Save under Override must not erase a group's 'default' token"
        )
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, mode_state)
        helpers.config_restore_state(vm, GLOBAL_LOG_CFG, mechanism_state)
        _restore_node(vm, DNSBL_GROUPS, dnsbl_snap)


def test_category_list_default_policy_renders_each_groups_own_choice(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Under Default policy (the fresh-install / non-enforced state), each row's
    select renders ITS OWN stored value selected -- an explicit choice stays
    explicit, a 'default' token stays 'default' -- never silently promoted to
    the global mechanism's own key (which would misrepresent the render)."""
    vm = smoke_vm
    dnsbl_snap = _snapshot_node(vm, DNSBL_GROUPS)
    mode_state = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
    mechanism_state = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
    try:
        _seed_two_dnsbl_rows(vm)
        helpers.config_set(vm, GLOBAL_LOG_MODE_CFG, "default")
        helpers.config_set(vm, GLOBAL_LOG_CFG, "nodata_log")

        resp = webui.get(DNSBL_CATEGORY_PAGE)
        assert not looks_like_login_page(resp.text), "category GET returned the login form (session lost)"

        row0 = row_containing(resp.text, "logging-0")
        row1 = row_containing(resp.text, "logging-1")
        assert _selected_value(_select_block(row0, "logging-0")) == _EXPLICIT_ROW_LOGGING, (
            "under Default policy an explicit group choice must render selected"
        )
        assert _selected_value(_select_block(row1, "logging-1")) == _DEFAULT_ROW_LOGGING, (
            "under Default policy a group's own 'default' token must render selected, not promoted to a concrete value"
        )
        # The rendered option vocabulary is unaffected by policy state.
        assert _option_values(_select_block(row0, "logging-0")) == _option_values(_select_block(row1, "logging-1"))
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, mode_state)
        helpers.config_restore_state(vm, GLOBAL_LOG_CFG, mechanism_state)
        _restore_node(vm, DNSBL_GROUPS, dnsbl_snap)
