"""Issue #3243: DNSBL null-blocking-by-default + NODATA, UI coverage.

Tier A (``ui_render``): the Global Logging/Blocking Mode select
(``pfblockerng_dnsbl.php``) and the per-group Logging/Blocking Mode select
(``pfblockerng_category_edit.php?type=dnsbl``) must expose the two new NODATA
tokens (``nodata_log``/``nodata``). The global select additionally renames its
historical empty-string "No Global mode" option to the canonical ``none``
token (a '' grandfather-map output is banned -- see
``CfgRegistryGrandfatherGateTest`` -- so the no-override choice gets a new
spelling); the per-group select never gets ``none`` (a group cannot defer to
itself).

Tier B (``ui_e2e``): a real CSRF-POST proves the tokens are ACCEPTED, not
silently coerced away by each page's select-options validation loop
(``pfblockerng_dnsbl.php``:592-599 / ``pfblockerng_category_edit.php``:564-574
replace any POSTed value that is not a key of the page's own options array
with that loop's default) -- and that a reload renders the stored choice back
as ``selected`` (issue #3243's "preserving choices").
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import evaluate_render
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
CATEGORY_EDIT_DNSBL_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"
GLOBAL_LOG_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log"

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
def test_global_log_select_exposes_nodata_and_canonical_none(webui: WebUI) -> None:
    """The Global Logging/Blocking Mode select carries nodata_log/nodata AND the
    canonical none no-override value."""
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Webserver Configuration",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"

    values = _option_values(_select_block(resp.text, "global_log"))
    for expected in ("none", "nodata_log", "nodata"):
        assert expected in values, f"global_log select must expose {expected!r}; got {sorted(values)!r}"


@pytest.mark.ui_render
def test_category_edit_logging_select_exposes_nodata_only(webui: WebUI) -> None:
    """The per-group Logging/Blocking Mode select exposes the two NODATA tokens; it
    must never carry the global-only none token (a group cannot defer to itself)."""
    resp = webui.get(CATEGORY_EDIT_DNSBL_PAGE)
    result = evaluate_render(CATEGORY_EDIT_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL category-edit page: {result.detail}"

    values = _option_values(_select_block(resp.text, "logging"))
    for expected in ("nodata_log", "nodata"):
        assert expected in values, f"logging select must expose {expected!r}; got {sorted(values)!r}"
    assert "none" not in values, "the per-group logging select must never carry the global-only none token"


# --------------------------------------------------------------------------- #
# Tier B -- real POST persistence + choice preservation across a reload
# --------------------------------------------------------------------------- #


@pytest.mark.ui_e2e
def test_global_log_nodata_tokens_persist_and_render_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """POSTing nodata_log/nodata is ACCEPTED (not coerced by the select-options
    validation loop) and the reload renders the stored choice back as selected."""
    vm = smoke_vm
    original = helpers.config_get(vm, GLOBAL_LOG_CFG)
    try:
        for token in ("nodata_log", "nodata"):
            resp = webui.post(DNSBL_PAGE, {"global_log": token}, timeout=POST_TIMEOUT)
            assert not looks_like_login_page(resp.text), f"global_log={token} POST returned the login form"
            stored = helpers.config_get(vm, GLOBAL_LOG_CFG)
            assert stored == token, f"global_log must store {token!r} verbatim, got {stored!r} (coerced away)"

            reload = webui.get(DNSBL_PAGE)
            selected = _selected_value(_select_block(reload.text, "global_log"))
            assert selected == token, f"reload must render {token!r} selected, got {selected!r}"
    finally:
        webui.post(DNSBL_PAGE, {"global_log": original or "none"}, timeout=POST_TIMEOUT)


@pytest.mark.ui_e2e
def test_global_log_canonical_none_token_persists(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """POSTing the canonical none (no global override) token is accepted verbatim,
    not coerced to the historical empty-string byte the options loop no longer keys."""
    vm = smoke_vm
    original = helpers.config_get(vm, GLOBAL_LOG_CFG)
    try:
        resp = webui.post(DNSBL_PAGE, {"global_log": "none"}, timeout=POST_TIMEOUT)
        assert not looks_like_login_page(resp.text), "global_log=none POST returned the login form"
        stored = helpers.config_get(vm, GLOBAL_LOG_CFG)
        assert stored == "none", f"global_log must store 'none' verbatim, got {stored!r}"
    finally:
        webui.post(DNSBL_PAGE, {"global_log": original or "none"}, timeout=POST_TIMEOUT)


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
            _post_form(webui, _dnsbl_payload(rowid, "smokenodata", logging=token))
            got = helpers.config_get(vm, cfg)
            assert got == token, f"logging must store {token!r} verbatim, got {got!r} (coerced to the default)"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)
