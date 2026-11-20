"""Tier-A render check of the dashboard widget's CrowdSec rows (issue #4161).

While the CrowdSec bouncer should run (pfBlockerNG on, CrowdSec on, a bouncer key stored), the widget lists its
two tables, ``crowdsec_v4`` and ``crowdsec_v6``, as IP rows linked to the CrowdSec Status subtab, each with its
table's entry count and the bouncer's two rules; otherwise no CrowdSec row. The bouncer itself never runs here: the
settings are stored without applying them and the table is filled by hand. The live bouncer's rows, packets
included, are ``test_smoke_crowdsec.py``'s.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

# Dual-marked ui_e2e: the test stores settings in config.xml and fills a pf table as setup.
pytestmark = [pytest.mark.ui_render, pytest.mark.ui_e2e]

WIDGET = "/widgets/widgets/pfblockerng.widget.php"
STATUS_PAGE = "/pfblockerng/pfblockerng_crowdsec_status.php"
SECTION = "installedpackages/pfblockerngcrowdsec/config/0"
MASTER = "installedpackages/pfblockerng/config/0/enable_cb"
TABLES = ("crowdsec_v4", "crowdsec_v6")
BANNED = ("192.0.2.201", "198.51.100.0/24")


@pytest.fixture(scope="module")
def php_error_log_guard(smoke_vm: SmokeVM, webui: WebUI) -> Iterator[PhpErrorLogGuard]:  # noqa: ARG001
    """Snapshot ``php_error.log`` before this module's test, assert no growth after (the widget's other modules'
    fixture)."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


def _widget_rows(webui: WebUI) -> dict[str, list[str]]:
    """The widget's table rows as its AJAX refresh gets them (alias, count, packets, updated, rule icon, group), keyed
    by the alias cell's text."""
    response = webui.get(f"{WIDGET}?getNewWidget=1")
    assert response.status_code == 200, f"the widget answered HTTP {response.status_code}"
    rows = [line.split("||") for line in response.text.splitlines()]
    return {re.sub(r"<[^>]+>", "", cols[0]): cols for cols in rows if len(cols) == 6}


def _php_ok(vm: SmokeVM, snippet: str) -> str:
    result = helpers.php_eval(vm, snippet + "\necho 'PFB_' . 'OK';")
    assert "PFB_OK" in result.stdout, f"{snippet!r}: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
    return result.stdout


@contextmanager
def _bouncer_should_run(vm: SmokeVM) -> Iterator[None]:
    """pfBlockerNG on, the CrowdSec settings on with a key and both families, and BANNED in ``crowdsec_v4``;
    afterwards the settings, the master enable and both tables are as they were (the tables absent)."""
    for table in TABLES:
        absent = vm.ssh(f"pfctl -t {table} -T show", timeout=30).returncode != 0
        assert absent, f"precondition: no {table} table on the session VM (it would be killed afterwards)"
    saved = _php_ok(vm, f"echo 'PFB_SAVED[' . base64_encode(json_encode(config_get_path('{SECTION}'))) . ']';")
    found = re.search(r"PFB_SAVED\[([A-Za-z0-9+/=]*)\]", saved)
    assert found, f"could not read {SECTION}: {saved!r}"
    section = json.loads(base64.b64decode(found.group(1)))
    master = helpers.config_get_state(vm, MASTER)
    settings = {
        "enable": "on",
        "lapi_url": "https://lapi.invalid/",
        "api_key": "k3y",
        "log_level": "info",
        "rules_all_interfaces": "on",
        "rules_interfaces": "",
        "rules_log": "",
        "rules_tag": "",
        "rule_v4": "on",
        "rule_v6": "on",
    }
    _php_ok(
        vm,
        f"config_set_path('{MASTER}', 'on');\n"
        f"config_set_path('{SECTION}', json_decode('{json.dumps(settings)}', TRUE));\n"
        "write_config('pfBlockerNG smoke: CrowdSec settings for a widget render check');",
    )
    try:
        result = vm.ssh(f"pfctl -t {TABLES[0]} -T add {' '.join(BANNED)}", timeout=30)
        assert result.returncode == 0, f"filling {TABLES[0]}: {result.stderr!r}"
        yield
    finally:
        vm.ssh(f"pfctl -t {TABLES[0]} -T kill; pfctl -t {TABLES[1]} -T kill; true", timeout=30)
        restore = (
            f"config_del_path('{SECTION}');"
            if section is None
            else f"config_set_path('{SECTION}', json_decode(base64_decode('{found.group(1)}'), TRUE));"
        )
        _php_ok(vm, restore + "\nwrite_config('pfBlockerNG smoke: restore the CrowdSec settings');")
        helpers.config_restore_state(vm, MASTER, master)


def test_the_widget_lists_the_crowdsec_tables_only_while_the_bouncer_should_run(
    smoke_vm: SmokeVM, webui: WebUI, php_error_log_guard: PhpErrorLogGuard
) -> None:
    """Given the bouncer not set up, the widget has no CrowdSec row;
    Given it should run, with two values in crowdsec_v4 and crowdsec_v6 not created yet,
    Then the widget renders cleanly and lists both tables as IP rows linked to the CrowdSec Status subtab, with
    2 and 0 entries and the bouncer's two rules on each;
    When the settings are put back, the CrowdSec rows go."""
    before = _widget_rows(webui)
    assert not set(TABLES) & set(before), f"before-state: no CrowdSec row: {sorted(before)}"

    with _bouncer_should_run(smoke_vm):
        page = webui.get(WIDGET)
        result = evaluate_render(WIDGET, page.status_code, page.text, ('id="pfblockerngack"',))
        assert result.ok, f"Widget render oracle failed: {result.detail}"

        rows = _widget_rows(webui)
        for table, entries in zip(TABLES, ("2", "0"), strict=True):
            assert table in rows, f"a row for {table}: {sorted(rows)}"
            alias, count, packets, _updated, img, group = rows[table]
            assert group == "ip", rows[table]
            assert f'href="{STATUS_PAGE}"' in alias and 'rel="noopener noreferrer"' in alias, alias
            assert count == entries, f"{table}: {entries} entries expected, the widget shows {count}"
            assert packets == "0", f"{table}: no rule loaded, so no packets: {packets}"
            assert "(2)" in img, f"{table}: the bouncer's two rules: {img}"

    after = _widget_rows(webui)
    assert not set(TABLES) & set(after), f"after: no CrowdSec row: {sorted(after)}"
