"""DNSBL mechanism selection, Default/Override policy, and group inheritance.

Exercise real rendered controls and persisted choices across current and legacy
configurations. Global policy changes must not erase saved group choices.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import evaluate_render
from .test_category import _restore_node, _snapshot_node
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form
from .test_category_edit_new_group_logging_default import _legacy_no_override_system, _seed_raw_legacy_dnsbl_group
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
CATEGORY_EDIT_DNSBL_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"
GLOBAL_LOG_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log"
GLOBAL_LOG_MODE_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log_mode"

# The seven concrete mechanisms (issue #3288 keeps this vocabulary unchanged).
_CONCRETE_MECHANISMS = ("enabled", "disabled_log", "disabled", "nxdomain_log", "nxdomain", "nodata_log", "nodata")

POST_TIMEOUT = 120.0

_SELECT_RE = r'<select\b[^>]*\bname=["\']{name}["\'][^>]*>(.*?)</select>'
_OPTION_VALUE_RE = re.compile(r'<option\b[^>]*\bvalue=["\']([^"\']*)["\']')


def _select_block(body: str, name: str) -> str:
    match = re.search(_SELECT_RE.format(name=re.escape(name)), body, re.IGNORECASE | re.DOTALL)
    assert match is not None, f"<select name={name!r}> not found in the rendered page"
    return match.group(0)


def _option_values(select_block: str) -> set[str]:
    return set(_OPTION_VALUE_RE.findall(select_block))


def _selected_value(select_block: str) -> str | None:
    """The single option value carrying a `selected` boolean attribute, if any."""
    for opt_attrs, _opt_body in re.findall(r"<option\b([^>]*)>(.*?)</option>", select_block, re.IGNORECASE | re.DOTALL):
        if re.search(r"(?:^|\s)selected(?=\s|=|/|>|$)", opt_attrs, re.IGNORECASE):
            match = re.search(r'\bvalue=["\']([^"\']*)["\']', opt_attrs)
            if match:
                return match.group(1)
    return None


# --------------------------------------------------------------------------- #
# Tier A -- render-smoke: the option vocabulary itself
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
def test_global_log_select_exposes_only_the_seven_concrete_mechanisms(webui: WebUI) -> None:
    """issue #3288: ``global_log`` is now ALWAYS a concrete mechanism -- the empty
    'No Global mode' no-override token is GONE (split into the new
    ``global_log_mode`` Default/Override selector below)."""
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"

    values = _option_values(_select_block(resp.text, "global_log"))
    assert values == set(_CONCRETE_MECHANISMS), (
        f"global_log select must expose exactly the seven concrete mechanisms, got {sorted(values)!r}"
    )


@pytest.mark.ui_render
def test_global_log_mode_select_exposes_default_and_override(webui: WebUI) -> None:
    """issue #3288: the new Default/Override application selector."""
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"

    values = _option_values(_select_block(resp.text, "global_log_mode"))
    assert values == {"default", "override"}, (
        f"global_log_mode select must expose exactly Default/Override, got {sorted(values)!r}"
    )


@pytest.mark.ui_render
def test_category_edit_logging_select_exposes_default_and_seven_concrete(webui: WebUI) -> None:
    """issue #3288: the per-group Logging/Blocking Mode select gains the new
    'default' token (live inheritance of the global mechanism) alongside the
    seven concrete mechanisms; it must never carry the removed empty
    no-override value (a group cannot defer to itself)."""
    resp = webui.get(CATEGORY_EDIT_DNSBL_PAGE)
    result = evaluate_render(CATEGORY_EDIT_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL category-edit page: {result.detail}"

    values = _option_values(_select_block(resp.text, "logging"))
    assert values == {"default", *_CONCRETE_MECHANISMS}, (
        f"logging select must expose 'default' plus the seven concrete mechanisms, got {sorted(values)!r}"
    )


# --------------------------------------------------------------------------- #
# Tier B -- real POST persistence + choice preservation across a reload
# --------------------------------------------------------------------------- #


@pytest.mark.ui_e2e
def test_global_log_mode_persists_and_renders_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """POSTing global_log_mode=override/default is ACCEPTED and a reload renders
    the stored choice back as selected."""
    vm = smoke_vm
    original = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
    try:
        for token in ("override", "default"):
            resp = webui.post(DNSBL_PAGE, {"global_log_mode": token}, timeout=POST_TIMEOUT)
            assert not looks_like_login_page(resp.text), f"global_log_mode={token} POST returned the login form"
            stored = helpers.config_get(vm, GLOBAL_LOG_MODE_CFG)
            assert stored == token, f"global_log_mode must store {token!r} verbatim, got {stored!r} (coerced away)"

            reload = webui.get(DNSBL_PAGE)
            selected = _selected_value(_select_block(reload.text, "global_log_mode"))
            assert selected == token, f"reload must render {token!r} selected, got {selected!r}"
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, original)


@pytest.mark.ui_e2e
def test_global_log_always_concrete_persists_across_all_seven_and_renders_selected(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3288: global_log now always holds ONE of the seven concrete
    mechanisms (never the removed empty no-override token). Extends the
    #3243/#3285 NODATA-only coverage to the full vocabulary now that '' is no
    longer a legal stored value for this field."""
    vm = smoke_vm
    original = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
    try:
        for token in _CONCRETE_MECHANISMS:
            resp = webui.post(DNSBL_PAGE, {"global_log": token}, timeout=POST_TIMEOUT)
            assert not looks_like_login_page(resp.text), f"global_log={token} POST returned the login form"
            stored = helpers.config_get(vm, GLOBAL_LOG_CFG)
            assert stored == token, f"global_log must store {token!r} verbatim, got {stored!r} (coerced away)"

            reload = webui.get(DNSBL_PAGE)
            selected = _selected_value(_select_block(reload.text, "global_log"))
            assert selected == token, f"reload must render {token!r} selected, got {selected!r}"
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_CFG, original)


@pytest.mark.ui_e2e
def test_category_edit_logging_nodata_tokens_persist(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """POSTing logging=nodata_log/nodata on a DNSBL group is ACCEPTED (not coerced
    to the 'Enabled' select-options default), mirroring the existing FIVE-key
    coverage in test_category_edit.test_dnsbl_logging_select_valid_and_bogus_coerces_to_default."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    cfg = f"{CFG_DNSBL}/{rowid}/logging"
    try:
        for token in ("nodata_log", "nodata"):
            _post_form(webui, _dnsbl_payload(rowid, "smoke3288nodata", logging=token))
            got = helpers.config_get(vm, cfg)
            assert got == token, f"logging must store {token!r} verbatim, got {got!r} (coerced to the default)"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_changing_global_mechanism_never_touches_group_stored_values(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """issue #3288: resolution (Default inheritance / Override) is LIVE --
    computed at read/render time -- never baked into a group's own stored
    'logging' value. Changing the global mechanism AND/OR mode must never
    write to any group's config, regardless of which policy is active."""
    vm = smoke_vm
    explicit_rowid = _free_rowid(vm, CFG_DNSBL)
    try:
        _post_form(webui, _dnsbl_payload(explicit_rowid, "smoke3288untouched", logging="nxdomain_log"))
        default_rowid = _free_rowid(vm, CFG_DNSBL)
        try:
            _post_form(webui, _dnsbl_payload(default_rowid, "smoke3288defaultuntouched", logging="default"))
            explicit_cfg = f"{CFG_DNSBL}/{explicit_rowid}/logging"
            default_cfg = f"{CFG_DNSBL}/{default_rowid}/logging"
            assert helpers.config_get(vm, explicit_cfg) == "nxdomain_log", "seed did not land the explicit choice"
            assert helpers.config_get(vm, default_cfg) == "default", "seed did not land the 'default' token"

            mode_original = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
            mechanism_original = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
            try:
                for mode, mechanism in (("override", "nodata_log"), ("default", "disabled"), ("override", "enabled")):
                    resp = webui.post(
                        DNSBL_PAGE, {"global_log_mode": mode, "global_log": mechanism}, timeout=POST_TIMEOUT
                    )
                    assert not looks_like_login_page(resp.text), f"mode={mode}/mechanism={mechanism} POST failed"
                    assert helpers.config_get(vm, GLOBAL_LOG_MODE_CFG) == mode
                    assert helpers.config_get(vm, GLOBAL_LOG_CFG) == mechanism
                    # The two groups' OWN stored choices are untouched by every global transition.
                    assert helpers.config_get(vm, explicit_cfg) == "nxdomain_log", (
                        f"an explicit group choice must survive a global change to mode={mode}/mechanism={mechanism}"
                    )
                    assert helpers.config_get(vm, default_cfg) == "default", (
                        f"a 'default' group token must survive a global change to mode={mode}/mechanism={mechanism} "
                        "(Default is live inheritance, never copied into the group when the global changes)"
                    )
            finally:
                helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, mode_original)
                helpers.config_restore_state(vm, GLOBAL_LOG_CFG, mechanism_original)
        finally:
            _del_rowid(vm, CFG_DNSBL, default_rowid)
    finally:
        _del_rowid(vm, CFG_DNSBL, explicit_rowid)


@pytest.mark.ui_e2e
def test_dnsbl_page_renders_registered_defaults_when_absent(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A genuinely empty DNSBL domain uses the fresh Null/Default policy."""
    vm = smoke_vm
    settings_path = GLOBAL_LOG_CFG.rsplit("/", 1)[0]
    snapshots = {path: _snapshot_node(vm, path) for path in (settings_path, CFG_DNSBL)}
    try:
        result = helpers.php_eval(
            vm,
            f"config_del_path({helpers._php_str(settings_path)}); "
            f"config_del_path({helpers._php_str(CFG_DNSBL)}); "
            "write_config('pfBlockerNG smoke: empty DNSBL domain'); echo 'OK';",
        )
        assert result.returncode == 0 and "OK" in result.stdout, "fresh DNSBL setup failed"
        resp = webui.get(DNSBL_PAGE)
        rendered = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
        assert rendered.ok, f"fresh DNSBL page failed to render: {rendered.detail}"
        assert _selected_value(_select_block(resp.text, "global_log")) == "disabled_log"
        assert _selected_value(_select_block(resp.text, "global_log_mode")) == "default"
        assert helpers.config_get_state(vm, GLOBAL_LOG_CFG) == (False, ""), "GET must not initialize settings"
        assert helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG) == (False, ""), "GET must not write the marker"
    finally:
        for path, snapshot in snapshots.items():
            _restore_node(vm, path, snapshot)


@pytest.mark.ui_e2e
def test_dnsbl_page_legacy_prefill_get_and_unchanged_save_migrates_groups(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Main's lifecycle contract, dnsbl.php's own facade call site (PolicyCore:
    "a call site in your DNSBL settings page's Save handler, invoked BEFORE it
    persists the posted global_log/global_log_mode -- closes a gap where an
    ordinary Global Save on a restored/legacy box would mark the box migrated
    without ever converting its VIP groups").

    On a genuinely legacy, established "old no-global-override" system
    (dnsbl/global_log_mode absent, dnsbl/global_log present-but-empty -- an
    old release that WAS saved at least once, distinct from a truly fresh
    install which reads the plain registry default 'disabled_log', see
    test_dnsbl_page_renders_registered_defaults_when_absent):

    1. GET must PREFILL the grandfathered EFFECTIVE values -- global_log=
       'enabled', global_log_mode='default' -- pinning the user's VIP prefill,
       not blank/absent selects. This is READ-ONLY: the raw config stays
       byte-identical (marker absent, global_log still present-empty).
    2. An UNCHANGED Save (re-submitting exactly the prefilled/rendered form)
       runs the facade FIRST: it persists global_log_mode='default' and
       global_log='enabled' AND converts an untouched raw-legacy DNSBL group
       to the 'default' token -- proving the facade reaches every group, not
       just the two fields this page itself edits.
    """
    vm = smoke_vm
    with _legacy_no_override_system(vm):
        rowid = _free_rowid(vm, CFG_DNSBL)
        base = f"{CFG_DNSBL}/{rowid}"
        try:
            _seed_raw_legacy_dnsbl_group(vm, rowid, "smoke3288dnsblprefill")
            helpers.ensure_dnsbl_vip(vm)

            # (1) GET prefills the grandfathered effective values, read-only.
            mode_before = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
            mechanism_before = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
            resp = webui.get(DNSBL_PAGE)
            result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
            assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"
            assert _selected_value(_select_block(resp.text, "global_log")) == "enabled", (
                "a legacy no-override system must PREFILL global_log='enabled' (the grandfather VIP value), "
                "not the plain fresh-install registry default"
            )
            assert _selected_value(_select_block(resp.text, "global_log_mode")) == "default", (
                "a legacy no-override system must PREFILL global_log_mode='default'"
            )
            assert helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG) == mode_before, "a GET must never migrate"
            assert helpers.config_get_state(vm, GLOBAL_LOG_CFG) == mechanism_before, "a GET must never write global_log"

            # (2) An UNCHANGED Save runs the facade: persists the grandfather values
            # AND converts the untouched legacy group to 'default'.
            resp = webui.post(DNSBL_PAGE, {}, timeout=POST_TIMEOUT)
            assert not looks_like_login_page(resp.text), "unchanged DNSBL settings Save returned the login form"
            assert helpers.config_get(vm, GLOBAL_LOG_MODE_CFG) == "default", (
                "the unchanged Save must persist the prefilled global_log_mode='default'"
            )
            assert helpers.config_get(vm, GLOBAL_LOG_CFG) == "enabled", (
                "the unchanged Save must persist the prefilled global_log='enabled'"
            )
            assert helpers.config_get(vm, f"{base}/logging") == "default", (
                "the facade must reach and convert an untouched raw-legacy DNSBL group to 'default', "
                "not just persist the two fields this page itself edits"
            )
        finally:
            _del_rowid(vm, CFG_DNSBL, rowid)
