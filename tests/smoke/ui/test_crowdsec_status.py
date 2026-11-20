"""Tier-B proof of the CrowdSec tab's Status subtab (issue #4073; docs/specs/crowdsec-integration.md, D7).

Marker ``ui_e2e``: a new page, read on the smoke VM against a fixture status file and a stub LAPI.

* Service: running, stopped, or each reason the bouncer does not run (pfBlockerNG off, CrowdSec off, no key on this
  node).
* LAPI: the URL (never the key), the last successful pull, the last error with its time, the request and error counts.
* Decisions: banned values per family and origin, and each table's contents from ``pfctl -T show``, 100 per page.
* Lookup: ``GET /v1/decisions?ip=`` with the bouncer key shows each matching decision; an address that is not an IP is
  refused before any request.
* Counters: dropped packets and bytes per family. Log: the system log lines tagged ``pfb_crowdsec``.

The bouncer itself never runs here: the settings are written straight into config.xml, without the apply that would
start it, and "running" is a live process named by the bouncer's pidfile.
"""

from __future__ import annotations

import html as htmllib
import json
import re
import subprocess
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from .. import helpers

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

PAGE = "/pfblockerng/pfblockerng_crowdsec_status.php"
SECTION = "installedpackages/pfblockerngcrowdsec/config/0"
MASTER = f"{helpers.CFG_GLOBAL}/enable_cb"
STATUS_FILE = "/var/run/pfb_crowdsec.json"
PIDFILE = "/var/run/pfb_crowdsec.pid"
STUB_DIR = "/root/pfb_crowdsec_stub"
STUB_PORT = 18073

# A stub LAPI for php -S: every request is logged as "<method> <uri> <X-Api-Key>"; a wrong key is refused (403) as
# the LAPI does. GET /v1/decisions?ip= answers the decisions in decisions.json whose value is that address (null for
# none, as the LAPI does); the stream answers all of them on startup=true and no change otherwise; usage metrics are
# accepted.
STUB_LAPI_ROUTER = r"""<?php
$dir = __DIR__;
$key = $_SERVER['HTTP_X_API_KEY'] ?? '';
$line = "{$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']} {$key}\n";
file_put_contents("{$dir}/requests.log", $line, FILE_APPEND);
header('Content-Type: application/json');
if ($key !== trim((string) file_get_contents("{$dir}/key"))) {
	http_response_code(403);
	echo '{"message":"access forbidden"}';
	return;
}
$decisions = json_decode((string) file_get_contents("{$dir}/decisions.json"), TRUE);
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
parse_str((string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY), $query);
if ($path === '/v1/decisions') {
	$hits = array_values(array_filter($decisions, fn (array $d): bool => $d['value'] === ($query['ip'] ?? '')));
	echo json_encode($hits === [] ? NULL : $hits);
} elseif ($path === '/v1/decisions/stream') {
	echo json_encode(['new' => ($query['startup'] ?? '') === 'true' ? $decisions : [], 'deleted' => []]);
} elseif ($path === '/v1/usage-metrics') {
	http_response_code(201);
	echo '{}';
} else {
	http_response_code(404);
	echo '{"message":"not found"}';
}
"""

KEY = f"smoke4073-{uuid.uuid4().hex}"
BANNED = "192.0.2.77"
DECISIONS = [
    {
        "id": 1,
        "origin": "crowdsec",
        "type": "ban",
        "scope": "Ip",
        "value": BANNED,
        "duration": "3h59m58s",
        "scenario": "crowdsecurity/ssh-bf",
    },
    {
        "id": 2,
        "origin": "cscli",
        "type": "ban",
        "scope": "Ip",
        "value": BANNED,
        "duration": "23h0m1s",
        "scenario": "manual 'ban' from 'smoke'",
    },
    {
        "id": 3,
        "origin": "CAPI",
        "type": "ban",
        "scope": "Range",
        "value": "198.51.100.0/24",
        "duration": "1h",
        "scenario": "crowdsecurity/http-probing",
    },
]
LAST_PULL = 1763550000
LAST_ERROR_TIME = 1763540000
LAST_ERROR = 'Get "http://192.0.2.10:8080/v1/decisions/stream": dial tcp 192.0.2.10:8080: connect: <refused>'


def _status(updated_at: int) -> dict[str, object]:
    """The status file as go/pfb_crowdsec/status.go writes it."""
    return {
        "version": "0.1.0",
        "start_time": 1763500000,
        "update_frequency_seconds": 10,
        "updated_at": updated_at,
        "last_pull": LAST_PULL,
        "last_error_time": LAST_ERROR_TIME,
        "last_error": LAST_ERROR,
        "lapi_requests": 4242,
        "lapi_errors": 17,
        "banned": {
            "ipv4": {"total": 151, "origins": {"crowdsec": 100, "lists:firehol_level1": 51}},
            "ipv6": {"total": 2, "origins": {"cscli": 2}},
        },
        "dropped": {"ipv4": {"packets": 9876, "bytes": 543210}, "ipv6": {"packets": 12, "bytes": 960}},
    }


@dataclass(frozen=True)
class Stub:
    url: str

    def requests(self, vm: helpers.SmokeVM) -> list[str]:
        out = vm.ssh("/bin/sh", "-c", f"cat {STUB_DIR}/requests.log 2>/dev/null || true").stdout
        return [line for line in out.splitlines() if line]


def _write(vm: helpers.SmokeVM, path: str, contents: str) -> None:
    result = subprocess.run(
        vm.ssh_argv("tee", path), input=contents, capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, f"writing {path}: {result.stderr}"


def _sh(vm: helpers.SmokeVM, command: str) -> str:
    result = vm.ssh("/bin/sh", "-c", command)
    assert result.returncode == 0, f"{command}: rc={result.returncode} {result.stderr}"
    return result.stdout


def _stub_answers(vm: helpers.SmokeVM) -> bool:
    return vm.ssh("/bin/sh", "-c", f"/usr/local/bin/curl -s -o /dev/null http://127.0.0.1:{STUB_PORT}/").returncode == 0


@pytest.fixture
def stub(smoke_vm: helpers.SmokeVM) -> Iterator[Stub]:
    """The stub LAPI on the guest's loopback, with its own key and decisions; stopped and removed afterwards."""
    vm = smoke_vm
    _sh(vm, f"rm -rf {STUB_DIR} && mkdir -p {STUB_DIR}")
    _write(vm, f"{STUB_DIR}/router.php", STUB_LAPI_ROUTER)
    _write(vm, f"{STUB_DIR}/key", KEY)
    _write(vm, f"{STUB_DIR}/decisions.json", json.dumps(DECISIONS))
    _sh(
        vm,
        f"/usr/sbin/daemon -f -p {STUB_DIR}/pid /usr/local/bin/php -S 127.0.0.1:{STUB_PORT} {STUB_DIR}/router.php",
    )
    try:
        helpers.wait_until(lambda: _stub_answers(vm), timeout=20.0, interval=0.5, what="the stub LAPI answers")
        _sh(vm, f": > {STUB_DIR}/requests.log")
        yield Stub(f"http://127.0.0.1:{STUB_PORT}")
    finally:
        vm.ssh("/bin/sh", "-c", f"pkill -F {STUB_DIR}/pid; rm -rf {STUB_DIR}")


@pytest.fixture
def status_page(smoke_vm: helpers.SmokeVM, stub: Stub) -> Iterator[helpers.SmokeVM]:
    """pfBlockerNG on, the bouncer configured against the stub and a fresh fixture status file, its tables filled; no
    bouncer process. Everything is put back afterwards."""
    vm = smoke_vm
    master = helpers.config_get_state(vm, MASTER)
    settings = {"enable": "on", "lapi_url": stub.url, "api_key": KEY, "log_level": "info", "rules_all_interfaces": "on"}
    settings |= {"rule_v4": "on", "rule_v6": "on"}
    section = (
        f"config_set_path({helpers._php_str(SECTION)}, {helpers._php_kv_array(settings)});\n"
        "write_config('pfBlockerNG smoke: CrowdSec status fixture');\necho 'OK';"
    )
    result = helpers.php_eval(vm, section)
    assert result.returncode == 0 and "OK" in result.stdout, result.stderr
    helpers.config_set(vm, MASTER, "on")
    _write(vm, STATUS_FILE, json.dumps(_status(_now(vm))))
    v4 = "\n".join(f"192.0.2.{n}" for n in range(1, 151)) + "\n" + "198.51.100.0/24\n"
    _write(vm, f"{STUB_DIR}/v4.txt", v4)
    _write(vm, f"{STUB_DIR}/v6.txt", "2001:db8::77\n2001:db8:1::/48\n")
    _sh(vm, f"pfctl -t crowdsec_v4 -T add -f {STUB_DIR}/v4.txt && pfctl -t crowdsec_v6 -T add -f {STUB_DIR}/v6.txt")
    try:
        yield vm
    finally:
        vm.ssh(
            "/bin/sh",
            "-c",
            f"pkill -F {PIDFILE} -x sleep; rm -f {PIDFILE} {STATUS_FILE};"
            " pfctl -t crowdsec_v4 -T kill; pfctl -t crowdsec_v6 -T kill; true",
        )
        helpers.php_eval(
            vm,
            f"config_del_path({helpers._php_str(SECTION)});\n"
            "write_config('pfBlockerNG smoke: remove the CrowdSec fixture');",
        )
        helpers.config_restore_state(vm, MASTER, master)


def _now(vm: helpers.SmokeVM) -> int:
    return int(_sh(vm, "date +%s").strip())


def _fake_running(vm: helpers.SmokeVM) -> None:
    """A live process named by the bouncer's pidfile: what the page reads as a running service."""
    _sh(vm, f"/usr/sbin/daemon -f -p {PIDFILE} /bin/sleep 600")
    helpers.wait_until(
        lambda: vm.ssh("/bin/sh", "-c", f"pgrep -F {PIDFILE}").returncode == 0,
        timeout=10.0,
        interval=0.5,
        what="the pidfile names a live process",
    )


def _by_id(page: str, element_id: str) -> str:
    match = re.search(rf'<(\w+)[^>]*\bid="{re.escape(element_id)}"[^>]*>(.*?)</\1>', page, re.S)
    assert match, f'no element id="{element_id}" on the page'
    return match.group(2)


def _text(fragment: str) -> str:
    return htmllib.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment))).strip()


def _rows(page: str, css_class: str) -> list[list[str]]:
    rows = re.findall(rf'<tr[^>]*class="{css_class}"[^>]*>(.*?)</tr>', page, re.S)
    return [[_text(cell) for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)] for row in rows]


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get(webui: WebUI, query: str = "") -> str:
    response = webui.get(PAGE + query, timeout=60.0)
    assert response.status_code == 200, f"{PAGE}{query} answered HTTP {response.status_code}"
    return response.text


def test_the_status_sections_show_the_status_file_and_never_the_key(webui: WebUI, status_page: helpers.SmokeVM) -> None:
    vm = status_page
    _fake_running(vm)
    marker = f"smoke4073-{uuid.uuid4().hex}"
    _sh(vm, f"/usr/bin/logger -p daemon.info -t pfb_crowdsec 'level=info msg={marker}'")

    page = _get(webui)

    assert KEY not in page, "the bouncer key was rendered into the page"
    assert _text(_by_id(page, "cs-service")) == "Running"
    assert _text(_by_id(page, "cs-lapi-url")) == f"http://127.0.0.1:{STUB_PORT}"
    assert f'datetime="{_iso(LAST_PULL)}"' in _by_id(page, "cs-last-pull"), "the last successful pull, with its time"
    last_error = _by_id(page, "cs-last-error")
    assert f'datetime="{_iso(LAST_ERROR_TIME)}"' in last_error, "the last error's time"
    assert LAST_ERROR in _text(last_error), "the last error's text, escaped"
    assert "<refused>" not in last_error, "the error text is HTML-escaped"
    assert _text(_by_id(page, "cs-requests")) == "4242"
    assert _text(_by_id(page, "cs-errors")) == "17"
    assert _rows(page, "cs-banned") == [
        ["IPv4", "crowdsec", "100"],
        ["lists:firehol_level1", "51"],
        ["Total", "151"],
        ["IPv6", "cscli", "2"],
        ["Total", "2"],
    ]
    family_cells = re.findall(r'<tr class="cs-banned"><td rowspan="(\d+)"[^>]*>([^<]*)</td>', page)
    assert family_cells == [("3", "IPv4"), ("2", "IPv6")], "one Family cell spans each family's origins and Total"
    wrapped = page.count('<div class="table-responsive"><table')
    assert wrapped == 2, "the Decisions and Dropped tables scroll sideways on a phone"
    assert _rows(page, "cs-dropped") == [["IPv4", "9876", "543210"], ["IPv6", "12", "960"]]
    log = _text(_by_id(page, "cs-log"))
    assert marker in log, f"the pfb_crowdsec system log line is shown: {log[-500:]!r}"


def test_each_table_is_shown_from_pfctl_100_entries_per_page(webui: WebUI, status_page: helpers.SmokeVM) -> None:
    v4_all = [line.strip() for line in _sh(status_page, "pfctl -t crowdsec_v4 -T show").splitlines() if line.strip()]
    assert len(v4_all) == 151, f"before-state: the fixture table holds 151 entries, got {len(v4_all)}"

    first = _get(webui)
    second = _get(webui, "?page_ipv4=2")

    page1 = _text(_by_id(first, "cs-table-ipv4")).split()
    page2 = _text(_by_id(second, "cs-table-ipv4")).split()
    assert page1 == v4_all[:100], "page 1 holds pfctl's first 100 entries"
    assert page2 == v4_all[100:], "page 2 holds the remaining 51"
    assert "151" in _text(_by_id(first, "cs-table-ipv4-count"))
    assert 'href="?page_ipv4=2' in first or "page_ipv4=2" in first, "page 1 links to page 2"
    assert _text(_by_id(first, "cs-table-ipv6")).split() == ["2001:db8::77", "2001:db8:1::/48"]
    assert _text(_by_id(_get(webui, "?page_ipv4=0' OR 1"), "cs-table-ipv4")).split() == v4_all[:100], (
        "a page number that is not one reads as page 1"
    )


def test_the_lookup_shows_each_decision_the_lapi_holds_for_the_address(
    webui: WebUI, status_page: helpers.SmokeVM, stub: Stub
) -> None:
    page = _get(webui, f"?lookup={BANNED}")

    assert stub.requests(status_page) == [f"GET /v1/decisions?ip={BANNED} {KEY}"], "one LAPI request, with the key"
    assert _rows(page, "cs-decision") == [
        [BANNED, "Ip", "crowdsec", "crowdsecurity/ssh-bf", "ban", "3h59m58s"],
        [BANNED, "Ip", "cscli", "manual 'ban' from 'smoke'", "ban", "23h0m1s"],
    ]
    in_table = r"(?:(?!</table>).)*"  # within one table: never crosses a closing tag into the next
    lookup_table = rf'<div class="table-responsive"><table[^>]*>{in_table}class="cs-decision"{in_table}</table></div>'
    assert re.search(lookup_table, page, re.S), "the lookup table scrolls sideways on a phone"
    assert KEY not in page

    page = _get(webui, "?lookup=203.0.113.9")
    assert _rows(page, "cs-decision") == [], "an address with no decision lists none"
    assert "No decision" in _text(_by_id(page, "cs-lookup-result"))


@pytest.mark.parametrize("hostile", ["192.0.2.300", "192.0.2.0/24", "example.com", "192.0.2.1&scope=range", ""])
def test_a_lookup_that_is_not_an_ip_is_refused_before_any_request(
    webui: WebUI, status_page: helpers.SmokeVM, stub: Stub, hostile: str
) -> None:
    page = _get(webui, "?lookup=" + re.sub(r"[&=/ ]", lambda m: f"%{ord(m.group(0)):02X}", hostile))

    assert stub.requests(status_page) == [], "no request reaches the LAPI"
    assert _rows(page, "cs-decision") == []
    if hostile:
        assert "not an IP address" in _text(_by_id(page, "cs-lookup-error"))


def test_a_refused_key_is_reported_without_showing_it(webui: WebUI, status_page: helpers.SmokeVM, stub: Stub) -> None:
    _sh(status_page, f"echo other-key > {STUB_DIR}/key")

    page = _get(webui, f"?lookup={BANNED}")

    assert len(stub.requests(status_page)) == 1, "the request was sent"
    assert "403" in _text(_by_id(page, "cs-lookup-error"))
    assert KEY not in page


def test_a_stopped_bouncer_and_a_missing_status_file(webui: WebUI, status_page: helpers.SmokeVM) -> None:
    assert _text(_by_id(_get(webui), "cs-service")) == "Stopped", "should run, but no process"

    _sh(status_page, f"rm -f {STATUS_FILE}")
    page = _get(webui)

    assert "No status yet" in _text(_by_id(page, "cs-status-missing"))
    assert _rows(page, "cs-banned") == [] and _rows(page, "cs-dropped") == []


@pytest.mark.parametrize(
    ("reason", "path", "value", "expected"),
    [
        ("pfBlockerNG off", MASTER, "", "pfBlockerNG is disabled"),
        ("CrowdSec off", f"{SECTION}/enable", "", "CrowdSec is disabled"),
        ("no key", f"{SECTION}/api_key", "", "no bouncer API key is stored on this node"),
    ],
)
def test_each_reason_the_bouncer_does_not_run(
    webui: WebUI, status_page: helpers.SmokeVM, reason: str, path: str, value: str, expected: str
) -> None:
    assert _text(_by_id(_get(webui), "cs-service")) == "Stopped", "before-state: the bouncer should run"

    helpers.config_set(status_page, path, value)
    service = _text(_by_id(_get(webui), "cs-service"))

    assert service == f"Not running: {expected}", f"{reason}: {service!r}"
