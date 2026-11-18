"""DNSBL mechanism selection, Default/Override policy, and group inheritance.

Exercise real rendered controls and persisted choices across current and legacy
configurations. Global policy changes must not erase saved group choices.
"""

from __future__ import annotations

import html
import re
import subprocess
from typing import TYPE_CHECKING, Iterator

import pytest

from .. import helpers
from .render_oracle import evaluate_render
from .test_blacklist import (
    BLACKLIST_PAGE,
    CFG_LOGGING,
    _config_path_exists,
    _direct_post,
    _restore_scalar,
    _save_payload,
)
from .test_category import DNSBL_GROUPS, _page_url, _restore_node, _seed_three_rows, _snapshot_node
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form
from .test_category_edit_new_group_logging_default import _legacy_no_override_system, _seed_raw_legacy_dnsbl_group
from .test_dns_stats_review import _stats_data
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
CATEGORY_EDIT_DNSBL_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"
GLOBAL_LOG_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log"
GLOBAL_LOG_MODE_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log_mode"

# The six concrete mechanisms (issue #3288's vocabulary; issue #4053 removed the WebServer/VIP `enabled`).
_CONCRETE_MECHANISMS = ("disabled_log", "disabled", "nxdomain_log", "nxdomain", "nodata_log", "nodata")

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
def test_global_log_select_exposes_only_the_six_concrete_mechanisms(webui: WebUI) -> None:
    """issue #3288: ``global_log`` is now ALWAYS a concrete mechanism -- the empty
    'No Global mode' no-override token is GONE (split into the new
    ``global_log_mode`` Default/Override selector below)."""
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Group Policy",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"

    values = _option_values(_select_block(resp.text, "global_log"))
    assert values == set(_CONCRETE_MECHANISMS), (
        f"global_log select must expose exactly the six concrete mechanisms, got {sorted(values)!r}"
    )


@pytest.mark.ui_render
def test_global_log_mode_select_exposes_default_and_override(webui: WebUI) -> None:
    """issue #3288: the new Default/Override application selector."""
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Group Policy",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"

    values = _option_values(_select_block(resp.text, "global_log_mode"))
    assert values == {"default", "override"}, (
        f"global_log_mode select must expose exactly Default/Override, got {sorted(values)!r}"
    )


@pytest.mark.ui_render
def test_category_edit_logging_select_exposes_default_and_six_concrete(webui: WebUI) -> None:
    """issue #3288: the per-group Logging/Blocking Mode select gains the new
    'default' token (live inheritance of the global mechanism) alongside the
    six concrete mechanisms; it must never carry the removed empty
    no-override value (a group cannot defer to itself)."""
    resp = webui.get(CATEGORY_EDIT_DNSBL_PAGE)
    result = evaluate_render(CATEGORY_EDIT_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL category-edit page: {result.detail}"

    values = _option_values(_select_block(resp.text, "logging"))
    assert values == {"default", *_CONCRETE_MECHANISMS}, (
        f"logging select must expose 'default' plus the six concrete mechanisms, got {sorted(values)!r}"
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
def test_global_log_always_concrete_persists_across_all_six_and_renders_selected(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3288: global_log now always holds ONE of the six concrete
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
    to the select-options default), mirroring the existing
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
                for mode, mechanism in (("override", "nodata_log"), ("default", "disabled"), ("override", "nxdomain")):
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
        rendered = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Group Policy",))
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
    without ever converting its legacy groups").

    On a genuinely legacy, established "old no-global-override" system
    (dnsbl/global_log_mode absent, dnsbl/global_log present-but-empty -- an
    old release that WAS saved at least once, distinct from a truly fresh
    install which reads the plain registry default 'disabled_log', see
    test_dnsbl_page_renders_registered_defaults_when_absent):

    1. GET must PREFILL the grandfathered EFFECTIVE values -- global_log=
       'disabled_log' (issue #4053: no longer the VIP), global_log_mode='default',
       not blank/absent selects. This is READ-ONLY: the raw config stays
       byte-identical (marker absent, global_log still present-empty).
    2. An UNCHANGED Save (re-submitting exactly the prefilled/rendered form)
       runs the facade FIRST: it persists global_log_mode='default' and
       global_log='disabled_log' AND converts an untouched raw-legacy DNSBL group
       to the 'default' token -- proving the facade reaches every group, not
       just the two fields this page itself edits.
    """
    vm = smoke_vm
    with _legacy_no_override_system(vm):
        rowid = _free_rowid(vm, CFG_DNSBL)
        base = f"{CFG_DNSBL}/{rowid}"
        try:
            _seed_raw_legacy_dnsbl_group(vm, rowid, "smoke3288dnsblprefill")

            # (1) GET prefills the grandfathered effective values, read-only.
            mode_before = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
            mechanism_before = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
            resp = webui.get(DNSBL_PAGE)
            result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Group Policy",))
            assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"
            assert _selected_value(_select_block(resp.text, "global_log")) == "disabled_log", (
                "a legacy no-override system must PREFILL global_log='disabled_log' (issue #4053: never the VIP)"
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
            assert helpers.config_get(vm, GLOBAL_LOG_CFG) == "disabled_log", (
                "the unchanged Save must persist the prefilled global_log='disabled_log'"
            )
            assert helpers.config_get(vm, f"{base}/logging") == "default", (
                "the facade must reach and convert an untouched raw-legacy DNSBL group to 'default', "
                "not just persist the two fields this page itself edits"
            )
        finally:
            _del_rowid(vm, CFG_DNSBL, rowid)


# --------------------------------------------------------------------------- #
# Issue #4053 -- the WebServer/VIP response is removed from every surface that
# offered it; the Blacklist category keeps the Default/Override policy (#3539).
# --------------------------------------------------------------------------- #

_MECHANISM_LABELS = {
    "disabled_log": "Null Blocking (logging)",
    "disabled": "Null Blocking (no logging)",
    "nxdomain_log": "NXDOMAIN (logging)",
    "nxdomain": "NXDOMAIN (no logging)",
    "nodata_log": "NODATA (logging)",
    "nodata": "NODATA (no logging)",
}
_OPTION_RE = re.compile(r"<option\b([^>]*)>(.*?)</option>", re.IGNORECASE | re.DOTALL)
_WIZARD_DNSBL_STEP = "/wizard.php?xml=pfblockerng_wizard.xml&stepid=3"
ALERTS_DNSBL_STAT_PAGE = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat"
DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"


def _option_labels(select_block: str) -> dict[str, str]:
    """Option value -> its visible, HTML-unescaped label."""
    labels: dict[str, str] = {}
    for attrs, label in _OPTION_RE.findall(select_block):
        value = re.search(r'\bvalue=["\']([^"\']*)["\']', attrs)
        if value:
            labels[value.group(1)] = html.unescape(label).strip()
    return labels


def _assert_no_vip_choice(select_block: str, where: str) -> None:
    """No `enabled` option, and the six remaining labels are exact."""
    labels = _option_labels(select_block)
    assert "enabled" not in labels, f"{where}: still offers the removed WebServer/VIP option: {labels!r}"
    for token, expected in _MECHANISM_LABELS.items():
        assert labels.get(token) == expected, (
            f"{where}: the {token!r} label must stay {expected!r}, got {labels.get(token)!r}"
        )


@pytest.mark.ui_render
def test_dnsbl_page_offers_no_vip_mechanism_or_webserver_section(webui: WebUI) -> None:
    """issue #4053: the DNSBL page has no VIP choice, no VIP help and no web server settings."""
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, ("DNSBL Group Policy",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL page: {result.detail}"
    _assert_no_vip_choice(_select_block(resp.text, "global_log"), "DNSBL page global_log")
    assert "WebServer/VIP" not in resp.text, "the DNSBL page still names the WebServer/VIP response"
    assert "DNSBL Webserver Configuration" not in resp.text, "the web server section is still rendered"
    for name in ("dnsbl_interface", "pfb_dnsvip4", "pfb_dnsvip6", "pfb_dnsport", "dnsbl_webpage", "pfb_dnsvip_auto"):
        assert f'name="{name}"' not in resp.text, f"the DNSBL page still renders the {name} field"
    # issue #4053 slice 3: the HSTS list went with the block page.
    assert 'name="pfb_hsts"' not in resp.text, "the DNSBL page still renders the HSTS mode field"


@pytest.mark.ui_render
def test_category_edit_logging_offers_no_vip_choice(webui: WebUI) -> None:
    """issue #4053: the group editor's select and help no longer name the VIP response."""
    resp = webui.get(CATEGORY_EDIT_DNSBL_PAGE)
    result = evaluate_render(CATEGORY_EDIT_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL category-edit page: {result.detail}"
    _assert_no_vip_choice(_select_block(resp.text, "logging"), "category-edit logging")
    assert "WebServer/VIP" not in resp.text, "the group editor still names the WebServer/VIP response"


@pytest.mark.ui_render
def test_blacklist_logging_select_exposes_default_and_six_concrete_in_order(webui: WebUI) -> None:
    """issue #3539 D2 / #4053: the Blacklist tab's Logging select is Default + the six mechanisms
    (resolver order), with no VIP choice."""
    resp = webui.get(BLACKLIST_PAGE)
    result = evaluate_render(BLACKLIST_PAGE, resp.status_code, resp.text, ("DNSBL Category",))
    assert result.ok, f"Tier-A render oracle failed for the Blacklist page: {result.detail}"
    block = _select_block(resp.text, "blacklist_logging")
    values = _OPTION_VALUE_RE.findall(block)
    assert values == ["default", *_CONCRETE_MECHANISMS], (
        f"blacklist_logging must offer Default then the six mechanisms in resolver order, got {values!r}"
    )
    _assert_no_vip_choice(block, "Blacklist blacklist_logging")


@pytest.mark.ui_render
def test_wizard_dnsbl_step_names_no_vip(webui: WebUI) -> None:
    """issue #4053: the setup wizard's DNSBL step no longer mentions the WebServer/VIP response."""
    resp = webui.get(_WIZARD_DNSBL_STEP)
    result = evaluate_render(_WIZARD_DNSBL_STEP, resp.status_code, resp.text, ("DNSBL settings",))
    assert result.ok, f"wizard DNSBL-step render oracle failed: {result.detail}"
    assert "WebServer/VIP" not in resp.text, "the wizard DNSBL step still names the WebServer/VIP response"


@pytest.fixture
def _seeded_unknown_agent_rows(smoke_vm: helpers.SmokeVM) -> Iterator[None]:
    """Append two dnsbl.log rows with no blocking-type: one EMPTY agent field and one literal
    `Unknown`. Restores the DNSBL toggle and removes ONLY the rows it appended."""
    vm = smoke_vm
    toggle = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"
    prior = helpers.config_get_state(vm, toggle)

    domains = (helpers.unique_domain("pfb4053a"), helpers.unique_domain("pfb4053b"))
    # dnsbl.log CSV: l_type,ts,domain,src_ip,agent,block_mode,group,final_domain,feed,dup,qtype
    lines = "".join(
        f"DNSBL-python,2030-01-15 09:00:0{n},{dom},127.0.0.1,{agent},DNSBL_TLD,G4053,{dom},F4053,+,A\n"
        for n, (dom, agent) in enumerate(zip(domains, ("", "Unknown"), strict=True), 5)
    )
    try:
        helpers.set_dnsbl_enabled(vm, True)
        log_dir = DNSBL_LOG.rsplit("/", 1)[0]
        ensure = vm.ssh(f"mkdir -p {log_dir} && touch {DNSBL_LOG}", timeout=15)
        assert ensure.returncode == 0, f"failed to ensure {DNSBL_LOG} exists: {ensure.stderr!r}"
        append = subprocess.run(
            vm.ssh_argv("tee", "-a", DNSBL_LOG), input=lines, capture_output=True, text=True, timeout=30, check=False
        )
        assert append.returncode == 0, f"failed to append the fixture rows to {DNSBL_LOG}: stderr={append.stderr!r}"
        yield
    finally:
        # Drop only our rows (by their unique domains); never truncate, live rows may follow ours.
        patterns = " ".join(f"-e {dom}" for dom in domains)
        tmp = f"{DNSBL_LOG}.pfb4053.tmp"
        vm.ssh(
            f"{{ grep -vF {patterns} {DNSBL_LOG} || true; }} > {tmp} && cat {tmp} > {DNSBL_LOG}; rm -f {tmp}",
            timeout=30,
        )
        leftover = vm.ssh(f"grep -cF {patterns} {DNSBL_LOG} || true", timeout=15)
        helpers.config_restore_state(vm, toggle, prior)
        assert leftover.stdout.strip() == "0", f"fixture rows were not removed from {DNSBL_LOG}: {leftover.stdout!r}"


@pytest.mark.ui_render
def test_alerts_dnsbl_stat_unknown_blocking_type_rows_are_labelled_unknown(
    webui: WebUI, _seeded_unknown_agent_rows: None
) -> None:
    """issue #4053: rows without a blocking type are `Unknown`, never the removed WebServer/VIP label."""
    resp = webui.get(ALERTS_DNSBL_STAT_PAGE)
    result = evaluate_render(ALERTS_DNSBL_STAT_PAGE, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"
    # Since #2cdd83fe10 the stats panels arrive progressively as JSON, not in the plain page.
    body = "".join(panel["html"] for panel in _stats_data(webui, "dnsbl_stat")["panels"])
    assert not re.search(r"Web ?Server/VIP", body, re.IGNORECASE), "Alerts still renders the WebServer/VIP label"
    assert "Unknown" in body, "the seeded rows without a blocking type did not render as Unknown"


@pytest.mark.ui_e2e
def test_category_list_logging_offers_no_vip_choice(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """issue #4053: the DNSBL category list's per-group Logging select has no VIP choice."""
    vm = smoke_vm
    dnsbl_snap = _snapshot_node(vm, DNSBL_GROUPS)
    mode_state = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
    mechanism_state = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
    try:
        _seed_three_rows(vm, DNSBL_GROUPS, "dnsbl", ["pfb4053label"])
        helpers.config_set(vm, GLOBAL_LOG_MODE_CFG, "default")
        helpers.config_set(vm, GLOBAL_LOG_CFG, "nodata_log")
        resp = webui.get(_page_url("dnsbl"))
        assert not looks_like_login_page(resp.text), "category GET returned the login form (session lost)"
        assert "enabled" not in _option_labels(_select_block(resp.text, "logging-0")), (
            "the category list still offers the removed WebServer/VIP option"
        )
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, mode_state)
        helpers.config_restore_state(vm, GLOBAL_LOG_CFG, mechanism_state)
        _restore_node(vm, DNSBL_GROUPS, dnsbl_snap)


@pytest.mark.ui_e2e
def test_blacklist_logging_prefills_default_when_absent_and_reads_a_stored_vip_as_null_logging(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """issue #3539 D2 / #4053: an absent stored value renders Default selected; a stored `enabled`
    (the removed VIP response) renders Null Blocking (logging) selected."""
    vm = smoke_vm
    existed = _config_path_exists(vm, CFG_LOGGING)
    original = helpers.config_get(vm, CFG_LOGGING)
    try:
        result = helpers.php_eval(
            vm,
            f"config_del_path({helpers._php_str(CFG_LOGGING)});\n"
            "write_config('pfBlockerNG smoke: absent blacklist_logging'); echo 'OK';",
        )
        assert result.returncode == 0 and "OK" in result.stdout, f"failed to clear {CFG_LOGGING}: {result.stderr!r}"
        selected = _selected_value(_select_block(webui.get(BLACKLIST_PAGE).text, "blacklist_logging"))
        assert selected == "default", f"an absent blacklist_logging must render 'default' selected, got {selected!r}"

        helpers.config_set(vm, CFG_LOGGING, "enabled")
        selected = _selected_value(_select_block(webui.get(BLACKLIST_PAGE).text, "blacklist_logging"))
        assert selected == "disabled_log", f"a stored 'enabled' must render 'disabled_log' selected, got {selected!r}"
    finally:
        _restore_scalar(vm, CFG_LOGGING, original, existed)


@pytest.mark.ui_e2e
def test_blacklist_logging_every_option_persists_and_renders_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """issue #3539 D2: Default and each concrete mechanism POST-persist verbatim (never coerced)
    and a reload renders the stored choice selected."""
    vm = smoke_vm
    existed = _config_path_exists(vm, CFG_LOGGING)
    original = helpers.config_get(vm, CFG_LOGGING)
    try:
        for token in ("default", *_CONCRETE_MECHANISMS):
            _direct_post(webui, _save_payload(blacklist_logging=token))
            stored = helpers.config_get(vm, CFG_LOGGING)
            assert stored == token, f"blacklist_logging must store {token!r} verbatim, got {stored!r} (coerced away)"
            selected = _selected_value(_select_block(webui.get(BLACKLIST_PAGE).text, "blacklist_logging"))
            assert selected == token, f"reload must render {token!r} selected, got {selected!r}"
    finally:
        _restore_scalar(vm, CFG_LOGGING, original, existed)
