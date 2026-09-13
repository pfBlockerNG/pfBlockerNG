"""New DNSBL groups use logged null blocking without a global override.

Exercise manual/catalog creation and preserve existing group choices through
the real page and save handler.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import evaluate_render
from .test_category_edit import (
    CFG_DNSBL,
    CFG_IPV4,
    _del_rowid,
    _dnsbl_payload,
    _free_rowid,
    _ipv4_payload,
    _option_selected,
    _post_form,
)
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"
GLOBAL_LOG_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log"
POST_TIMEOUT = 120.0

# Real, current, shipped catalog entries (pfblockerng_feeds.json) -- the same
# 'ADs_Basic'/'StevenBlack_ADs'/'PRI1' the setup wizard defaults to.
_ADD_DNSBL_PAGE = f"{CATEGORY_PAGE}?type=dnsbl&act=add&atype=StevenBlack_ADs"
_ADDGROUP_DNSBL_PAGE = f"{CATEGORY_PAGE}?type=dnsbl&act=addgroup&atype=ADs_Basic"

_EXPLICIT_CHOICES = ("enabled", "disabled_log", "disabled", "nxdomain_log", "nxdomain", "nodata_log", "nodata")


def _alias_suffix_for(spelling: str) -> str:
    """A filesystem/aliasname-safe token for a parametrized legacy spelling."""
    return {"absent": "absent", "": "empty", "Enabled": "capital"}[spelling]


@contextlib.contextmanager
def _global_log_none(vm: helpers.SmokeVM):
    """Pin dnsbl/global_log to '' (No Global mode) for the block; restore after."""
    original = helpers.config_get(vm, GLOBAL_LOG_CFG)
    try:
        helpers.config_set(vm, GLOBAL_LOG_CFG, "")
        yield
    finally:
        helpers.config_set(vm, GLOBAL_LOG_CFG, original)


@contextlib.contextmanager
def _alias_name_parked(vm: helpers.SmokeVM, cfg_root: str, aliasname: str):
    """Prevent catalog adds from reusing an existing alias; restore its name afterward."""
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$rid = null;\n"
        f"foreach ($c as $k => $row) {{ if (($row['aliasname'] ?? null) === {helpers._php_str(aliasname)}) "
        "{ $rid = $k; break; } }\n"
        "$found = ($rid === null) ? '' : (string) $rid;"
    )
    rid = helpers._php_read_scalar(vm, pre, "$found", timeout=60.0)
    parked_path = f"{cfg_root}/{rid}/aliasname" if rid else None
    try:
        if parked_path is not None:
            helpers.config_set(vm, parked_path, aliasname + "__pfb3285_parked")
        yield
    finally:
        if parked_path is not None:
            helpers.config_set(vm, parked_path, aliasname)


# --------------------------------------------------------------------------- #
# Tier A -- render-smoke: every creation route's NEW-group default
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
def test_add_new_dnsbl_alias_renders_disabled_log_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A brand-new DNSBL alias via ``act=add`` (matching a real catalog feed
    header) renders 'Null Blocking (logging)' selected, not the VIP default."""
    with _alias_name_parked(smoke_vm, CFG_DNSBL, "ADs_Basic"):
        resp = webui.get(_ADD_DNSBL_PAGE)
        result = evaluate_render(_ADD_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
        assert result.ok, f"Tier-A render oracle failed for act=add: {result.detail}"
        assert _option_selected(resp.text, "disabled_log"), (
            "a brand-new DNSBL alias must render Logging/Blocking Mode = disabled_log selected (issue #3285)"
        )
        assert not _option_selected(resp.text, "enabled")


@pytest.mark.ui_render
def test_addgroup_new_dnsbl_alias_renders_disabled_log_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A brand-new DNSBL alias via ``act=addgroup`` (Feeds tab) renders the
    same disabled_log default."""
    with _alias_name_parked(smoke_vm, CFG_DNSBL, "ADs_Basic"):
        resp = webui.get(_ADDGROUP_DNSBL_PAGE)
        result = evaluate_render(_ADDGROUP_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
        assert result.ok, f"Tier-A render oracle failed for act=addgroup: {result.detail}"
        assert _option_selected(resp.text, "disabled_log"), (
            "a brand-new DNSBL alias (addgroup/Feeds tab) must render disabled_log selected (issue #3285)"
        )
        assert not _option_selected(resp.text, "enabled")


@pytest.mark.ui_render
def test_manual_new_dnsbl_group_renders_disabled_log_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The ORDINARY manual creation route -- the category list's plain "Add"
    button, a bare ``type=dnsbl&rowid=<free>`` GET with NO ``act`` at all
    (pfblockerng_category.php's Add link) -- must ALSO default to
    disabled_log, not just the Feeds-tab catalog shortcuts."""
    rowid = _free_rowid(smoke_vm, CFG_DNSBL)
    resp = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
    result = evaluate_render(CATEGORY_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the manual new-group route: {result.detail}"
    assert _option_selected(resp.text, "disabled_log"), (
        "a manually-created (no act=add/addgroup) brand-new DNSBL group must default to disabled_log too"
    )
    assert not _option_selected(resp.text, "enabled")


@pytest.mark.ui_render
def test_addgroup_ipv4_renders_no_logging_select(webui: WebUI) -> None:
    """The disabled_log default is confined to DNSBL: an IPv4 addgroup page
    (same mechanism, different type) must render NO logging select at all."""
    page = f"{CATEGORY_PAGE}?type=ipv4&act=addgroup&atype=PRI1"
    resp = webui.get(page)
    result = evaluate_render(page, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the IPv4 addgroup page: {result.detail}"
    assert 'name="logging"' not in resp.text, "an IPv4 group must never render the DNSBL-only logging select"


# --------------------------------------------------------------------------- #
# Tier B -- real POST: create -> persist, gate holds in storage, preservation
# --------------------------------------------------------------------------- #


@pytest.mark.ui_e2e
def test_add_new_dnsbl_alias_full_save_persists_disabled_log(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Save the real form's default, rather than injecting the desired mode."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        with _global_log_none(vm):
            response = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert response.ok and not looks_like_login_page(response.text), "new-group GET failed"
            selected = scrape_form_fields(response.text)["logging"]
            _post_form(webui, _dnsbl_payload(rowid, "smoke3285add", logging=selected))
            assert helpers.config_get(vm, f"{base}/logging") == "disabled_log", (
                "a brand-new DNSBL alias's disabled_log default must be accepted and persisted verbatim"
            )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_addgroup_ipv4_feeds_tab_save_never_writes_a_logging_key(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The gtype gate must hold at the config-storage level, not merely in the
    rendered form: a real IPv4 alias must persist with NO 'logging' key at
    all -- a rendered-select check alone cannot see a stray write the IPv4
    page never displays back."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"
    try:
        _post_form(webui, _ipv4_payload(rowid, "smoke3285ipv4"))
        assert helpers.config_get(vm, f"{base}/aliasname") == "smoke3285ipv4", "the new IPv4 alias did not persist"
        present, _ = helpers.config_get_state(vm, f"{base}/logging")
        assert not present, "an IPv4 group must never gain a logging key, even at the config-storage level"
    finally:
        _del_rowid(vm, CFG_IPV4, rowid)


@pytest.mark.ui_e2e
@pytest.mark.parametrize("choice", _EXPLICIT_CHOICES)
def test_existing_dnsbl_alias_preserves_explicit_choice_on_get_and_resave(
    webui: WebUI, smoke_vm: helpers.SmokeVM, choice: str
) -> None:
    """An EXISTING alias's own explicit Logging/Blocking choice is untouched
    by the new-group default: create it with `choice`, GET renders it
    selected, and re-saving unchanged still persists exactly `choice`."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        with _global_log_none(vm):
            _post_form(webui, _dnsbl_payload(rowid, f"smoke3285{choice}", logging=choice))
            assert helpers.config_get(vm, f"{base}/logging") == choice

            reload = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert not looks_like_login_page(reload.text), "reload GET returned the login form"
            assert _option_selected(reload.text, choice), f"explicit choice {choice!r} must render selected on reload"

            _post_form(webui, _dnsbl_payload(rowid, f"smoke3285{choice}", logging=choice))
            assert helpers.config_get(vm, f"{base}/logging") == choice, (
                f"re-saving an existing alias unchanged must preserve its explicit {choice!r} choice"
            )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
@pytest.mark.parametrize("spelling", ["absent", "", "Enabled"], ids=["absent-key", "empty-string", "capital-Enabled"])
def test_existing_dnsbl_alias_legacy_spelling_renders_and_resaves_as_vip(
    webui: WebUI, smoke_vm: helpers.SmokeVM, spelling: str
) -> None:
    """Every legacy "no real choice recorded" spelling (a genuinely absent
    key, a stored empty string, or the pre-existing capitalised 'Enabled'
    literal the save fallback itself can write) must still resolve to the
    VIP webserver default on GET, and re-saving unchanged must persist the
    canonical 'enabled' -- never silently pick up the new-group disabled_log
    default meant only for brand-new aliases."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        with _global_log_none(vm):
            _post_form(webui, _dnsbl_payload(rowid, f"smoke3285legacy{_alias_suffix_for(spelling)}", logging="enabled"))
            if spelling == "absent":
                result = helpers.php_eval(
                    vm,
                    f"config_del_path({helpers._php_str(f'{base}/logging')}); "
                    "write_config('pfBlockerNG smoke: strip legacy logging key'); echo 'OK';",
                    timeout=POST_TIMEOUT,
                )
                if result.returncode != 0 or "OK" not in result.stdout:
                    raise RuntimeError(f"legacy-key strip failed: rc={result.returncode} {result.stdout!r}")
            else:
                helpers.config_set(vm, f"{base}/logging", spelling)

            reload = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert not looks_like_login_page(reload.text), "reload GET returned the login form"
            # None of these three spellings is a valid <option value>, so pfSense's
            # Form_Select marks none of them 'selected' explicitly -- the EFFECTIVE
            # value is the select's own first-declared option (browser/page default),
            # which scrape_form_fields resolves identically (its docstring: "the
            # selected option's value, or the first option's when none is marked").
            # This reads ONE field's effective value; it is never used to build a POST.
            effective = scrape_form_fields(reload.text).get("logging")
            assert effective == "enabled", (
                f"legacy spelling {spelling!r} must resolve to the VIP webserver default, got {effective!r}"
            )

            _post_form(webui, _dnsbl_payload(rowid, f"smoke3285legacy{_alias_suffix_for(spelling)}", logging=effective))
            assert helpers.config_get(vm, f"{base}/logging") == "enabled", (
                "re-saving a legacy-spelling alias unchanged must persist the canonical 'enabled', never disabled_log"
            )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)
