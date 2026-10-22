"""ADR-61 Phase 6 — Tier-A render coverage for the ledger-driven dashboard widget.

The dashboard widget (``pfblockerng.widget.php``) no longer reads ``error.log``/
``py_error.log``: both status icons (IP row ``PFBSTATUS``, DNSBL row
``DNSBLSTATUS``) and the reporting list (``pfBlockerNG_get_failed()``) are pure
readers of the sync-status ledger (``pfb_sync_status.json`` under
``$pfb['dbdir']``, merged with Python's own ``pfb_py_status.json`` under
``$pfb['dnsbldir']``). A plain authenticated GET of the widget page renders
BOTH the icon row (``pfBlockerNG_get_header()``) and the reporting list
(``pfBlockerNG_get_failed()``) inline (widget.php:1009/1027) -- no AJAX query
string is needed to exercise either.

Every ledger entry here is seeded DIRECTLY via ``pfb_sync_status_open()``
(the KILL-GATE's own mandate: prove the EXTRACTED widget logic reflects a
manually-seeded entry, not merely that unit tests pass in isolation), never
through a full pipeline failure -- this module only proves the RENDER side.

Hermeticity: the IP-row and "disabled" cases are config-only (no reload,
no network). The DNSBL live-state case needs Unbound actually running with
``pfb_unbound.py`` wired into ``unbound.conf``. A feed-free ``updatednsbl``
reload establishes the no-demand ledger transitions; a second applies an
inert built-in regex to verify the same live widget's VIP-demand state.

Marker discipline (``tests/smoke/ui/conftest.py`` ``_ui_pfb_isolation``):
Tier-A ``ui_render`` is normally read-only, but every test here that toggles
``enable_cb``/``pfb_dnsbl`` or seeds a throwaway alias is DUAL-MARKED
``ui_render`` + ``ui_e2e`` (the documented convention for "a mutating render
test rides the net") so the session-baseline config.xml is auto-restored.
The `clean_ledger` fixture separately backs up/restores the two ledger FILES
(outside config.xml, so `_ui_pfb_isolation` never touches them) around every
test, regardless of marker -- so a stray entry from an earlier suite module
can never leak into an "empty ledger" assertion here, and this module never
leaks state onward either.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .webui import WebUI

WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"

# $pfb['dbdir'] (PHP-owned ledger) / $pfb['dnsbldir'] (Python-owned ledger) --
# both confirmed real on-box paths (helpers.PFB_DBDIR; dnsbldir='/var/unbound'
# per test_smoke_matrix.py's own ADR-10 sentinel path citation).
_LEDGER_DIR = helpers.PFB_DBDIR
_PY_STATUS_DIR = "/var/unbound"
_LEDGER_PATH = f"{_LEDGER_DIR}/pfb_sync_status.json"
_PY_STATUS_PATH = f"{_PY_STATUS_DIR}/pfb_py_status.json"

ICON_GREEN = "fa-solid fa-check-circle text-success"
ICON_YELLOW = "fa-solid fa-exclamation-circle text-warning"
ICON_RED = "fa-solid fa-times-circle text-danger"

CFG_LISTSV4 = "installedpackages/pfblockernglistsv4/config"
CFG_DNSBL = "installedpackages/pfblockerngdnsblsettings/config/0"
CFG_PFB_DNS = "installedpackages/pfblockerngdns/config/0/pfb_dns"


@pytest.fixture
def dnsbl_demand_config(smoke_vm: helpers.SmokeVM) -> Iterator[None]:
    """Make the reload feed-free and explicitly no-demand, restoring all affected sections."""
    paths = [CFG_DNSBL, "installedpackages/pfblockerngdnsbl/config", "installedpackages/pfblockerngblacklist"]
    php_paths = "array(" + ",".join(helpers._php_str(path) for path in paths) + ")"
    snapshot = helpers._php_read_scalar(
        smoke_vm,
        f"$saved = array(); foreach ({php_paths} as $path) {{ $saved[$path] = config_get_path($path, NULL); }}",
        "base64_encode(serialize($saved))",
    )
    try:
        seed = (
            "config_set_path('installedpackages/pfblockerngdnsbl/config', array());"
            "config_set_path('installedpackages/pfblockerngblacklist', array('blacklist_enable' => 'Disable'));"
        )
        for key, value in {
            "global_log_mode": "default",
            "global_log": "disabled_log",
            "pfb_regex": "",
            "pfb_regex_list": "",
            "pfb_idn": "",
            "tld_allow": "",
            "tld_wildcard": "",
            "pfb_dnsvip_auto": "",
            "dnsbl_interface": helpers.SMOKE_VIP_IFACE,
            "pfb_dnsport": "8081",
            "pfb_dnsport_ssl": "8443",
        }.items():
            seed += f"config_set_path({helpers._php_str(f'{CFG_DNSBL}/{key}')}, {helpers._php_str(value)});"
        result = helpers.php_eval(smoke_vm, seed + "write_config('smoke: widget no-demand setup'); echo 'OK';")
        assert result.returncode == 0 and "OK" in result.stdout, f"widget setup failed: {result}"
        yield
    finally:
        restore = (
            f"$saved = unserialize(base64_decode({helpers._php_str(snapshot)}));"
            "foreach ($saved as $path => $value) {"
            " if ($value === NULL) { config_del_path($path); } else { config_set_path($path, $value); }"
            " if (config_get_path($path, NULL) !== $value) { throw new RuntimeException('restore failed: ' . $path); }"
            "} write_config('smoke: restore widget demand config'); echo 'OK';"
        )
        result = helpers.php_eval(smoke_vm, restore)
        assert result.returncode == 0 and "OK" in result.stdout, f"widget restore failed: {result}"


def _write_remote_file(vm: helpers.SmokeVM, path: str, contents: str) -> None:
    """Write ``contents`` verbatim to ``path`` on the guest via ``tee`` over SSH."""
    result = subprocess.run(
        vm.ssh_argv("tee", path),
        input=contents,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, f"writing {path!r} failed: rc={result.returncode} stderr={result.stderr!r}"


def _remove_remote_file(vm: helpers.SmokeVM, path: str) -> None:
    result = vm.ssh("rm", "-f", path, timeout=15)
    assert result.returncode == 0, f"removing {path!r} failed: rc={result.returncode} stderr={result.stderr!r}"


@pytest.fixture
def clean_ledger(smoke_vm: helpers.SmokeVM) -> Iterator[None]:
    """Snapshot + force-empty both ledger files; restore the ORIGINAL bytes after.

    Guarantees every test in this module starts from a verified-empty ledger
    (never an assumption) and never leaks a seeded entry into a sibling test
    or a later suite module -- mirrors the ``UI_CONFIG_SNAPSHOT`` backup/
    restore discipline ``conftest.py`` already uses for config.xml, applied
    here to the two files config isolation never touches.
    """
    php_backup = helpers.read_log_file(smoke_vm, _LEDGER_PATH)
    py_backup = helpers.read_log_file(smoke_vm, _PY_STATUS_PATH)
    _remove_remote_file(smoke_vm, _LEDGER_PATH)
    _remove_remote_file(smoke_vm, _PY_STATUS_PATH)
    try:
        yield
    finally:
        if php_backup:
            _write_remote_file(smoke_vm, _LEDGER_PATH, php_backup)
        else:
            _remove_remote_file(smoke_vm, _LEDGER_PATH)
        if py_backup:
            _write_remote_file(smoke_vm, _PY_STATUS_PATH, py_backup)
        else:
            _remove_remote_file(smoke_vm, _PY_STATUS_PATH)


def _ledger_open(vm: helpers.SmokeVM, facility: str, item: str, stage: str, message: str) -> None:
    """Seed one ledger entry via the REAL ``pfb_sync_status_open()`` (KILL-GATE mandate)."""
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        f"pfb_sync_status_open({helpers._php_str(facility)}, {helpers._php_str(item)}, "
        f"{helpers._php_str(stage)}, {helpers._php_str(message)}, {helpers._php_str(_LEDGER_DIR)});\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet)
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"pfb_sync_status_open({facility!r}, {item!r}, {stage!r}) failed: "
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _ledger_close(vm: helpers.SmokeVM, facility: str, item: str, stage: str) -> None:
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        f"pfb_sync_status_close({helpers._php_str(facility)}, {helpers._php_str(item)}, "
        f"{helpers._php_str(stage)}, {helpers._php_str(_LEDGER_DIR)});\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet)
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"pfb_sync_status_close({facility!r}, {item!r}, {stage!r}) failed: "
        f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _write_py_status_entries(vm: helpers.SmokeVM, entries: list[dict[str, object]]) -> None:
    """Write Python's OWN status file directly (no PHP writer exists for it)."""
    _write_remote_file(vm, _PY_STATUS_PATH, json.dumps(entries))


@pytest.fixture(scope="module")
def php_error_log_guard(smoke_vm: helpers.SmokeVM, webui: WebUI) -> Iterator[PhpErrorLogGuard]:  # noqa: ARG001
    """Snapshot ``php_error.log`` once before this module's tests, assert no growth
    after -- oracle condition (d), mirroring ``test_render_smoke.py``'s own fixture.
    A 200 + marker alone is never sufficient (pfSense logs but does not echo a PHP
    diagnostic); this is the source-of-truth catch for a Notice/Warning the new
    render code (``usort`` over ``last_seen``, ``str_starts_with``, the two-reader
    ``array_merge``) could log without changing the visible body at all.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


def _widget_body(webui: WebUI) -> str:
    resp = webui.get(WIDGET_PAGE)
    assert resp.status_code == 200, f"GET {WIDGET_PAGE} -> HTTP {resp.status_code} (expected 200)"
    return resp.text


def _pfbstatus_marker(icon_class: str, msg: str) -> str:
    """The exact rendered substring for the IP row (widget.php ~887-888)."""
    return f'title="{msg}"><i class="PFBSTATUS {icon_class}">'


def _dnsblstatus_marker(icon_class: str, msg: str) -> str:
    """The exact rendered substring for the DNSBL row (widget.php ~893-894)."""
    return f'title="{msg}"><i class="DNSBLSTATUS {icon_class}">'


def _dnsblstatus_class(icon_class: str) -> str:
    """Just the icon-class fragment -- used when the title embeds a variable
    vip/port (the green "DNSBL is Active on vip: ..." message)."""
    return f'<i class="DNSBLSTATUS {icon_class}">'


# --------------------------------------------------------------------------- #
# IP row -- config-only, no reload needed (enable_cb is a plain config read).
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
@pytest.mark.ui_e2e
def test_ip_row_green_then_yellow_on_open_entry_then_green_again(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """IP row: empty ledger -> green; ANY open facility='ip' entry -> yellow; clears -> green.

    True transition (CLAUDE.md before/after rule): asserts the ORIGINAL green
    state first, so the yellow assertion after seeding proves the ledger entry
    CAUSED the change, then closes the entry and re-asserts green -- proving
    the row is a live reader, not a one-shot page-load artifact.
    """
    vm = smoke_vm
    helpers.set_package_enabled(vm, True)

    # BEFORE: enabled, no open entries -> green.
    body = _widget_body(webui)
    assert _pfbstatus_marker(ICON_GREEN, "pfBlockerNG is Active.") in body, (
        "IP row not green with pfBlockerNG enabled and an empty ledger"
    )

    # WHEN: an apply-stage failure opens (an ordinary IP alias table, not dedup) --
    # the exact asymmetry this ADR targets: yellow with enable_dup never touched.
    _ledger_open(vm, "ip", "pfB_SmokeWidget_v4", "apply", "smoke: synthetic apply failure")
    try:
        body = _widget_body(webui)
        assert (
            _pfbstatus_marker(ICON_YELLOW, "pfBlockerNG has 1 open issue(s). See the Failed Downloads list below.")
            in body
        ), "IP row did not turn yellow with an open facility='ip' ledger entry"
    finally:
        _ledger_close(vm, "ip", "pfB_SmokeWidget_v4", "apply")

    # AFTER: closed -> green again (proves live re-read, not a cached artifact).
    body = _widget_body(webui)
    assert _pfbstatus_marker(ICON_GREEN, "pfBlockerNG is Active.") in body, (
        "IP row did not return to green after the ledger entry was closed"
    )


@pytest.mark.ui_render
@pytest.mark.ui_e2e
def test_ip_row_disabled_stays_red_with_open_entry(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """Semantics #1: a disabled facility stays RED even with an open ledger entry.

    Regression guard for the red/green "is it running" gate -- an open entry
    must never leak a yellow read into a genuinely-disabled row.
    """
    vm = smoke_vm
    helpers.set_package_enabled(vm, False)
    _ledger_open(vm, "ip", "pfB_SmokeWidget_v4", "apply", "smoke: synthetic apply failure")
    try:
        body = _widget_body(webui)
        assert _pfbstatus_marker(ICON_RED, "pfBlockerNG is Disabled.") in body, (
            "IP row must stay red (disabled) even with an open ledger entry present"
        )
        assert "PFBSTATUS fa-solid fa-exclamation-circle" not in body, (
            "IP row rendered yellow while pfBlockerNG is disabled -- the red gate leaked"
        )
    finally:
        _ledger_close(vm, "ip", "pfB_SmokeWidget_v4", "apply")


# --------------------------------------------------------------------------- #
# DNSBL row -- the disabled case is config-only (cheap); the live case needs
# one real (feed-free, hermetic) reload to get Unbound wired + running.
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
@pytest.mark.ui_e2e
def test_dnsbl_row_disabled_stays_red_with_open_entry(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """Semantics #1 for the DNSBL row: disabled stays red regardless of open entries.

    ``enable_cb`` off alone forces the DNSBL gate false (it AND-combines with
    the dnsbl/unbound_state/unbound.conf conditions), so this needs no live
    Unbound setup -- cheap. Before-state: disabled + a clean ledger keeps the
    plain "Disabled." wording; opening an entry keeps the row RED but flips the
    wording to the errors-remain variant -- sourced from the merged ledger, never
    from py_error.log content (that distinction is retired).
    """
    vm = smoke_vm
    helpers.set_package_enabled(vm, False)

    body = _widget_body(webui)
    assert _dnsblstatus_marker(ICON_RED, "DNSBL is Disabled.") in body, (
        "DNSBL row must show the plain disabled wording with an empty ledger"
    )

    _ledger_open(vm, "dnsbl", "dnsbl", "apply", "smoke: synthetic dnsbl apply failure")
    try:
        body = _widget_body(webui)
        errors_msg = "DNSBL is Disabled with errors! See the Failed Downloads list below."
        assert _dnsblstatus_marker(ICON_RED, errors_msg) in body, (
            "DNSBL row must stay red (disabled) but switch to the errors-remain wording with an open ledger entry"
        )
        assert "DNSBLSTATUS fa-solid fa-exclamation-circle" not in body, (
            "DNSBL row rendered yellow while disabled -- the red gate leaked"
        )
    finally:
        _ledger_close(vm, "dnsbl", "dnsbl", "apply")


@pytest.mark.ui_render
@pytest.mark.ui_e2e
def test_dnsbl_row_live_states_transition_on_php_and_python_entries(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    dnsbl_demand_config: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """DNSBL live: empty ledger -> green; a PHP entry -> yellow; a Python-only entry -> yellow.

    One real ``updatednsbl`` reload (no DNSBL lists configured, so no feed
    fetch -- still hermetic) gets ``unbound.conf`` wired with ``pfb_unbound.py``
    and Unbound running, satisfying the row's "is it live" gate (untouched by
    this ADR). From that single live setup: empty ledger asserts green FIRST
    (the before-state), a PHP-owned entry turns it yellow, closing it restores
    green, and a Python-ONLY entry (no py_error.log content at all -- the
    exact case the OLD monotonic filesize check would have missed) also turns
    it yellow via the merged read. An inert regex block then establishes real VIP demand.
    """
    vm = smoke_vm
    helpers.ensure_dnsbl_vip(vm)
    helpers.set_package_enabled(vm, True)
    helpers.set_dnsbl_enabled(vm, True)
    helpers.reload(vm, "updatednsbl")

    # BEFORE: live, no open entries -> green.
    body = _widget_body(webui)
    assert _dnsblstatus_class(ICON_GREEN) in body, (
        "DNSBL row not green after a live updatednsbl reload with an empty ledger"
    )
    assert _dnsblstatus_marker(ICON_GREEN, "DNSBL is Active.") in body, "no-demand DNSBL green message missing"
    assert "DNSBL is Active on vip:" not in body, "no-demand status names a VIP or ports"

    # WHEN: a PHP-owned entry opens -> yellow.
    _ledger_open(vm, "dnsbl", "dnsbl", "apply", "smoke: synthetic dnsbl apply failure")
    try:
        body = _widget_body(webui)
        assert (
            _dnsblstatus_marker(ICON_YELLOW, "DNSBL has 1 open issue(s). See the Failed Downloads list below.") in body
        ), "DNSBL row did not turn yellow with an open PHP-owned ledger entry"
    finally:
        _ledger_close(vm, "dnsbl", "dnsbl", "apply")

    # AFTER: closed -> green again.
    body = _widget_body(webui)
    assert _dnsblstatus_marker(ICON_GREEN, "DNSBL is Active.") in body, "DNSBL did not return to green after PHP close"
    assert "DNSBL is Active on vip:" not in body, "no-demand status regained a VIP after PHP close"

    # WHEN: ONLY a Python-side entry is open (no py_error.log content anywhere --
    # the old filesize-only trigger would have missed this entirely).
    _write_py_status_entries(
        vm,
        [
            {
                "facility": "dnsbl",
                "item": "pfb_py_zone.txt",
                "stage": "parse",
                "message": "Failed to load: pfb_py_zone.txt: smoke synthetic parse failure",
                "first_seen": 1,
                "last_seen": 1,
            }
        ],
    )
    try:
        body = _widget_body(webui)
        assert (
            _dnsblstatus_marker(ICON_YELLOW, "DNSBL has 1 open issue(s). See the Failed Downloads list below.") in body
        ), "DNSBL row did not turn yellow with only a Python-side ledger entry open"
    finally:
        _remove_remote_file(vm, _PY_STATUS_PATH)

    # AFTER: green again once the Python-side entry is gone too.
    body = _widget_body(webui)
    assert _dnsblstatus_marker(ICON_GREEN, "DNSBL is Active.") in body, (
        "DNSBL did not return to green after Python close"
    )
    assert "DNSBL is Active on vip:" not in body, "no-demand status regained a VIP after Python close"

    # A real built-in block now demands the VIP; the same live row must name its address and ports.
    helpers.config_set(vm, f"{CFG_DNSBL}/global_log", "enabled")
    helpers.config_set(vm, f"{CFG_DNSBL}/pfb_regex", "on")
    helpers.config_set(vm, f"{CFG_DNSBL}/pfb_regex_list", base64.b64encode(b"pfb3539inert\n").decode("ascii"))
    helpers.reload(vm, "updatednsbl")
    body = _widget_body(webui)
    expected = f"DNSBL is Active on vip: {helpers.DEFAULT_DNSBL_VIP4} ports: 8081 & 8443"
    assert _dnsblstatus_marker(ICON_GREEN, expected) in body, f"demanded VIP/port status missing: {expected!r}"


# --------------------------------------------------------------------------- #
# pfBlockerNG_get_failed() -- the reporting list, rendered inline (widget.php:1009).
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
def test_get_failed_empty_ledger_shows_maxmind_fallback(
    webui: WebUI,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """An empty (merged) ledger falls back to the MaxMind version line, same as today."""
    body = _widget_body(webui)
    assert "MaxMind:" in body, "empty ledger must fall back to the MaxMind version line"
    assert 'id="pfblockerngackicon"' not in body, "empty ledger must not render the issues list"


@pytest.mark.ui_render
@pytest.mark.ui_e2e
def test_get_failed_recognized_alias_builds_deep_link(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """A ledger entry whose ``item`` is a recognized ``pfB_``-prefixed alias links to its editor.

    Semantics #7: the alias-editor deep link. ``item`` is the STRUCTURED field
    the link is built from (an apply-stage table name is already
    ``pfB_<alias>_v{4,6}``) -- never the free-text ``message``.
    """
    vm = smoke_vm
    alias = "SmokeWidgetLink"
    original = helpers.config_get(vm, CFG_LISTSV4)
    snippet = (
        f"config_set_path({helpers._php_str(CFG_LISTSV4)}, "
        f"array(array('aliasname' => {helpers._php_str(alias)})));\n"
        "write_config('pfBlockerNG smoke: seed alias for widget deep-link test');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet)
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"seeding {CFG_LISTSV4} failed: rc={result.returncode} {result.stdout!r} {result.stderr!r}"
    )
    _ledger_open(vm, "ip", f"pfB_{alias}_v4", "apply", f"[pfctl] op=replace table=pfB_{alias}_v4 failed (rc=1)")
    try:
        body = _widget_body(webui)
        assert "pfblockerng_category_edit.php?type=ipv4&act=edit&rowid=0" in body, (
            "recognized alias item did not build the alias-editor deep link"
        )
        assert f"pfB_{alias}" in body
    finally:
        _ledger_close(vm, "ip", f"pfB_{alias}_v4", "apply")
        restore = (
            f"config_set_path({helpers._php_str(CFG_LISTSV4)}, {helpers._php_str(original) if original else '[]'});\n"
            "write_config('pfBlockerNG smoke: restore pfblockernglistsv4');\n"
            "echo 'OK';"
        )
        helpers.php_eval(vm, restore)


@pytest.mark.ui_render
def test_get_failed_python_side_entry_renders_as_plain_text(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """A Python-side (file-path) entry renders its message but never attempts a link."""
    vm = smoke_vm
    _write_py_status_entries(
        vm,
        [
            {
                "facility": "dnsbl",
                "item": "pfb_py_zone.txt",
                "stage": "parse",
                "message": "Failed to load: pfb_py_zone.txt: smoke synthetic parse failure",
                "first_seen": 1,
                "last_seen": 1,
            }
        ],
    )
    try:
        body = _widget_body(webui)
        assert "pfblockerng_category_edit.php" not in body, (
            "a Python-side file-path item must never attempt a deep link"
        )
        assert "pfb_py_zone.txt" in body, "the Python-side entry's message must still render"
    finally:
        _remove_remote_file(vm, _PY_STATUS_PATH)


# --------------------------------------------------------------------------- #
# pfB-DNS row (issue #3588) -- config-only: the Resolver is not moved, so the
# status is "Not in use" and the row's colours do not depend on a running proxy.
# --------------------------------------------------------------------------- #

_DNS_ANCHORS = [f"PFBDNSSTATUS_{key}" for key in ("service", "plain", "dot", "doh", "doq")]


def _widget_header_payload(webui: WebUI) -> str:
    """The widget's AJAX header refresh (pfblockerng.js ``getNewWidget``)."""
    resp = webui.get(WIDGET_PAGE, params={"getNewWidget": "1"})
    assert resp.status_code == 200, f"GET {WIDGET_PAGE}?getNewWidget -> HTTP {resp.status_code} (expected 200)"
    return resp.text


@pytest.mark.ui_render
@pytest.mark.ui_e2e
def test_pfb_dns_row_shows_only_while_pfb_dns_is_on(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """The pfB-DNS status row sits above the IP row while pfB-DNS is on, and is absent (page and poll) while off.

    Off first, so the on assertions prove the toggle CAUSED the row. On with the Resolver not moved: the
    service icon is yellow ("Not in use"), and the poll carries the same five anchors in the same order.
    """
    vm = smoke_vm
    helpers.set_package_enabled(vm, True)
    original = helpers.config_get_state(vm, CFG_PFB_DNS)
    try:
        helpers.config_set(vm, CFG_PFB_DNS, "")
        assert "PFBDNSSTATUS_" not in _widget_body(webui), "the page shows a pfB-DNS row while pfB-DNS is off"
        assert "PFBDNSSTATUS_" not in _widget_header_payload(webui), (
            "the poll carries pfB-DNS lines while pfB-DNS is off"
        )

        helpers.config_set(vm, CFG_PFB_DNS, "on")
        body = _widget_body(webui)
        icons = re.findall(r'<i class="(PFBDNSSTATUS_\w+) ([^"]*)"', body)
        assert [anchor for anchor, _ in icons] == _DNS_ANCHORS, f"the pfB-DNS icons are {icons}"

        first = body.index("PFBDNSSTATUS_")
        row = body[body.rindex("<tr", 0, first) : body.index("</tr>", first)]
        assert [anchor for anchor in _DNS_ANCHORS if anchor in row] == _DNS_ANCHORS, "the five icons are not in one row"
        assert row.count("<td") == 6, f"the pfB-DNS row has {row.count('<td')} cells, expected 5 icons and a link"
        assert first < body.index("PFBSTATUS"), "the pfB-DNS row is not above the IP row"

        assert icons[0][1] == ICON_YELLOW, f"the service icon is {icons[0][1]!r}, expected yellow while not in use"
        title = re.search(r'title="([^"]*)"><i class="PFBDNSSTATUS_service ', body)
        assert title is not None and title.group(1).startswith("Not in use: "), f"the service title is {title}"

        lines = [ln for ln in _widget_header_payload(webui).splitlines() if ln.startswith("PFBDNSSTATUS_")]
        assert [ln.split("||")[0] for ln in lines] == _DNS_ANCHORS, f"the poll's pfB-DNS lines are {lines}"
        assert all(len(ln.split("||")) == 3 for ln in lines), f"a poll line is not anchor||icon||title: {lines}"
        assert lines[0].split("||")[1] == ICON_YELLOW
        assert lines[0].split("||")[2].startswith("Not in use: ")
    finally:
        helpers.config_restore_state(vm, CFG_PFB_DNS, original)
