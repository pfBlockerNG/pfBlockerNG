"""CrowdSec bouncer end to end (issue #4074; docs/specs/crowdsec-integration.md, criteria 1, 3-9, 11, 12 and 15).

The branch package's real ``pfb_crowdsec`` runs on the smoke VM against the stub LAPI (``tests/smoke/stub_lapi.py``,
fixture ``stub_lapi``) on the runner. The bouncer is turned on and off through the real Settings form; the engine's
decisions are added and deleted on the stub, which records every request the bouncer makes.

Criteria and their tests:

* 1  bans reach their table and leave it within 20 s; a value banned twice stays until both decisions go —
     ``test_a_ban_reaches_its_table_and_leaves_it_within_20_s``, ``test_a_value_banned_twice_stays_until_both_go``.
* 3  the config file (0600, the D3 values), absent with the bouncer off; the key in no log, page, status file,
     metrics file or sync payload — ``test_the_config_file_*``, ``test_the_key_appears_nowhere``, the off tests.
* 4  after either filter reload both tables are full again within 2 s; with the signal suppressed, by the next pull —
     ``test_a_filter_reload_*``.
* #4161 the dashboard widget lists both tables while the bouncer runs, none while it is off —
     ``test_the_widget_shows_each_table_*``, ``test_turning_the_bouncer_off_*``.
* #4159 a drop by the bouncer's rule is logged with that rule's own tracker —
     ``test_a_drop_by_the_bouncers_rule_is_logged_with_its_tracker``.
* #4164 that drop shows in Alerts under the bouncer's table — ``test_a_drop_by_the_bouncers_rule_shows_in_alerts``.
* 5  a first enable starts it on the first try — ``test_a_first_enable_starts_the_bouncer_on_the_first_try``.
* 6  stopping empties both tables; the bouncer off, or pfBlockerNG off, removes the rules and the config file and
     stops the process — ``test_stopping_the_service_*``, ``test_turning_*_off_*``.
* 7  a reboot brings it back with the full set — ``test_a_reboot_brings_the_bouncer_back_with_the_full_set``.
* 8  with the LAPI unreachable the tables keep their contents, the error is logged and shown, and pulls resume —
     ``test_while_the_lapi_is_unreachable_the_tables_hold_and_pulls_resume_after``.
* 9  nothing listens for the bouncer — ``test_the_bouncer_listens_on_no_port``.
* 11 the D6 families with ``source_up 1``, ``source_up 0`` with the other sources intact when stale or stopped —
     ``test_the_metrics_source_*``, ``test_stopping_the_service_*``.
* 12 the LAPI receives usage metrics — ``test_the_lapi_receives_usage_metrics``. The bouncer posts right after its
     first answered pull (#4117 amendment), so the post of the running process is there, or seconds away.
* 15 deinstall leaves nothing behind — ``test_deinstall_leaves_nothing_behind`` (last: it reinstalls the package).

Each log line reaches syslog at its level's severity (#4158) —
``test_each_log_line_reaches_syslog_at_its_levels_severity``.
pfSense CE 2.9 and Plus 26.x keep daemon lines in the system log only from the System Logs log level up (notice by
default), so the module raises it to info, which the tests' info lines need; CE 2.8 keeps daemon.info and up anyway.

Run::

    scripts/local-smoke.sh --marker smoke --filter crowdsec
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import shlex
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlsplit

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .stub_lapi import STREAM, USAGE, LapiRequest, StubLapi
from .ui.credgate import admin_password_decision
from .ui.webui import WebUI

if TYPE_CHECKING:
    from prometheus_client.metrics_core import Metric

# A test's own budget: polls are bounded by the criteria, the rest is GUI saves and SSH round trips.
pytestmark = [pytest.mark.smoke, pytest.mark.timeout(300)]

T = TypeVar("T")
Net = ipaddress.IPv4Network | ipaddress.IPv6Network

PAGE = "/pfblockerng/pfblockerng_crowdsec.php"
STATUS_PAGE = "/pfblockerng/pfblockerng_crowdsec_status.php"
ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
UNIFIED_LOG = f"{h.PFB_LOGDIR}/unified.log"
WIDGET = "/widgets/widgets/pfblockerng.widget.php"
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
SECTION = "installedpackages/pfblockerngcrowdsec/config/0"
SYNC_SECTION = "installedpackages/pfblockerngsync/config/0"
MASTER = f"{h.CFG_GLOBAL}/enable_cb"
CONFIG_FILE = "/usr/local/etc/pfb_crowdsec.json"
STATUS_FILE = "/var/run/pfb_crowdsec.json"
PIDFILE = "/var/run/pfb_crowdsec.pid"
DAEMON_PIDFILE = "/var/run/pfb_crowdsec_daemon.pid"
RC = "/usr/local/etc/rc.d/pfb_crowdsec.sh"
CROWDSEC_DIR = "/usr/local/pkg/pfblockerng/crowdsec"
# The bouncer's command line as daemon(8) runs it (pfb_crowdsec_child_pattern()), and its supervisor's title
CHILD = rf"^{CROWDSEC_DIR}/bin/freebsd-[a-z0-9]+/pfb_crowdsec -c "
SUPERVISOR = r"^(daemon: pfb_crowdsec\[|/usr/sbin/daemon .*-t pfb_crowdsec )"
TABLES = {4: "crowdsec_v4", 6: "crowdsec_v6"}
SYSLOG = "/var/log/system.log"
FILTER_LOG = "/var/log/filter.log"
SYSLOG_LEVEL = "syslog/default_log_level"
# A syslogd drop-in of this module: each severity of the bouncer's daemon-facility lines to a file of its own
SEVERITY_DROPIN = "/var/etc/syslog.d/zz_pfb_crowdsec_smoke.conf"
SEVERITY_LOG = "/var/log/pfb_crowdsec_smoke_{}.log"
SEVERITIES = ("debug", "info", "notice", "warning", "err")
PROM = "/var/tmp/node_exporter/pfblockerng.prom"
PFB_INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
PFB_EXTRA = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"

UPDATE_FREQUENCY = 10  # D3: the bouncer pulls every 10 s
USAGE_WINDOW = 15 * 60  # D1: every usage post reports the 15-minute window
BAN_BOUND = 20.0  # criterion 1
RELOAD_BOUND = 2.0  # criterion 4
SALVAGE = 120.0  # a cap on waiting for an asynchronous event that has no bound of its own; never an expected wait

SIGNALLED = "SIGUSR1: checking the tables"
FAILED = "LAPI pull failed"
PROGRAM = re.compile(r"\bpfb_crowdsec(\[\d+\])?: |\bpfb_crowdsec (\d+|-) \S+ ")
# syslog can join two of the bouncer's messages on one line: read every match on a line
RESTORED = re.compile(r"(crowdsec_v[46]): restored \d+ values \(table was missing\)")

# The engine's decisions for the whole module: what the tables must hold whenever no test has added its own. Plus three
# the bouncer must leave out: not a ban, not an ip or range scope, not an address.
SEEDS: list[dict[str, str]] = [
    {"value": "192.0.2.10"},
    {"value": "198.51.100.0/24", "scope": "Range", "origin": "CAPI", "scenario": "crowdsecurity/http-probing"},
    {"value": "2001:db8:4074::1", "origin": "cscli", "scenario": "manual 'ban' from 'smoke'"},
    {"value": "2001:db8:4075::/48", "scope": "Range"},
    {"value": "192.0.2.11", "type": "captcha"},
    {"value": "FR", "scope": "Country"},
    {"value": "not-an-address"},
]


# --------------------------------------------------------------------------------------------------------------------
# Reading the box
# --------------------------------------------------------------------------------------------------------------------


def _sh(vm: SmokeVM, command: str, *, timeout: float = 60.0) -> str:
    result = vm.ssh(command, timeout=timeout)
    assert result.returncode == 0, f"{command}: rc={result.returncode} {result.stdout!r} {result.stderr!r}"
    return result.stdout


def _within(
    seconds: float, probe: Callable[[], T], accept: Callable[[T], bool], what: str, *, since: float | None = None
) -> T:
    """Poll ``probe`` until ``accept`` holds, for at most ``seconds`` from ``since`` (a ``time.monotonic()`` reading,
    default now), the bound the criterion itself sets. A value counts only when the probe that read it ended within
    the bound; past it the criterion fails, showing the last value seen."""
    deadline = (time.monotonic() if since is None else since) + seconds
    while True:
        value = probe()
        left = deadline - time.monotonic()
        if left < 0:
            raise AssertionError(f"{what}: not within {seconds:g} s; last seen: {value!r}")
        if accept(value):
            return value
        time.sleep(min(0.25, left))


def _await(probe: Callable[[], T], accept: Callable[[T], bool], what: str, *, cap: float = SALVAGE) -> T:
    """Poll ``probe`` until ``accept`` holds, for an event with no bound of its own; ``cap`` salvages a stuck run."""
    deadline = time.monotonic() + cap
    while True:
        value = probe()
        if accept(value):
            return value
        if time.monotonic() >= deadline:
            raise RuntimeError(f"stuck/environment: {what} not observed within the {cap:g} s cap; last seen: {value!r}")
        time.sleep(0.5)


def _tables(vm: SmokeVM) -> dict[str, set[Net] | None]:
    """Each bouncer table's contents, or None when the table does not exist."""
    script = (
        "for t in crowdsec_v4 crowdsec_v6; do"
        ' if pfctl -sT 2>/dev/null | grep -qx "$t"; then echo "== $t"; pfctl -t "$t" -T show;'
        ' else echo "!! $t"; fi; done'
    )
    out: dict[str, set[Net] | None] = {}
    current: set[Net] | None = None
    for line in _sh(vm, script).splitlines():
        if line.startswith("== "):
            current = out[line[3:]] = set()
        elif line.startswith("!! "):
            out[line[3:]] = current = None
        elif line.strip() and current is not None:
            current.add(ipaddress.ip_network(line.strip(), strict=False))
    return out


def _expected(stub: StubLapi) -> dict[str, set[Net] | None]:
    """What the tables must hold: the engine's active ip and range bans whose value is an address or a prefix."""
    out: dict[str, set[Net] | None] = {table: set() for table in TABLES.values()}
    for d in stub.active():
        if d["type"].casefold() != "ban" or d["scope"].casefold() not in ("ip", "range"):
            continue
        try:
            net = ipaddress.ip_network(d["value"], strict=False)
        except ValueError:
            continue
        table = out[TABLES[net.version]]
        assert table is not None
        table.add(net)
    return out


def _holds(value: str) -> Callable[[dict[str, set[Net] | None]], bool]:
    net = ipaddress.ip_network(value, strict=False)
    return lambda tables: net in (tables.get(TABLES[net.version]) or set())


def _pid(vm: SmokeVM, pidfile: str, pattern: str) -> int | None:
    """The pid in ``pidfile`` while it names a live process matching ``pattern``."""
    result = vm.ssh(f"pgrep -F {pidfile} -f {shlex.quote(pattern)}")
    return int(result.stdout.split()[0]) if result.returncode == 0 and result.stdout.split() else None


def _child(vm: SmokeVM) -> int | None:
    return _pid(vm, PIDFILE, CHILD)


def _processes(vm: SmokeVM) -> str:
    """Every pfb_crowdsec process and its supervisor, for a failure message and for the "none left" checks."""
    # [p]: the pattern does not match the shell that runs pgrep
    return vm.ssh("pgrep -lf '[p]fb_crowdsec' || true").stdout.strip()


def _rules(vm: SmokeVM) -> list[str]:
    """The loaded rules that carry the bouncer's labels."""
    return [line for line in _sh(vm, "pfctl -sr").splitlines() if 'label "CrowdSec IPv' in line]


def _log_mark(vm: SmokeVM, log: str = SYSLOG) -> int:
    return int(_sh(vm, f"wc -l < {log}").strip())


def _log_since(vm: SmokeVM, log: str, since: int) -> list[str]:
    """The log's lines after line ``since`` (all of them after a rotation)."""
    script = f'n=$(wc -l < {log}); s={since}; [ "$n" -lt "$s" ] && s=0; tail -n "+$((s + 1))" {log}'
    return _sh(vm, script).splitlines()


def _bouncer_log(vm: SmokeVM, since: int = 0) -> list[str]:
    """The system log's lines whose program is pfb_crowdsec, in the BSD or the RFC 5424 format, after line ``since``
    (all of them after a rotation)."""
    return [line for line in _log_since(vm, SYSLOG, since) if PROGRAM.search(line)]


def _status(vm: SmokeVM) -> dict[str, Any]:
    return dict(json.loads(_sh(vm, f"cat {STATUS_FILE}")))


def _status_age(vm: SmokeVM) -> int:
    """The status file's age in seconds by the guest's clock (its ``updated_at`` against ``date +%s``)."""
    now, _, body = _sh(vm, f"date +%s; cat {STATUS_FILE}").partition("\n")
    return int(now) - int(json.loads(body)["updated_at"])


def _config_file(vm: SmokeVM) -> tuple[str, dict[str, Any]] | None:
    """(``mode owner group``, decoded content) of the config file, or None when it does not exist."""
    result = vm.ssh(f"test -f {CONFIG_FILE} && stat -f '%Lp %Su %Sg' {CONFIG_FILE} && cat {CONFIG_FILE}")
    if result.returncode != 0:
        return None
    meta, _, body = result.stdout.partition("\n")
    return meta.strip(), dict(json.loads(body))


def _php_ok(vm: SmokeVM, snippet: str) -> str:
    result = h.php_eval(vm, snippet + "\necho '<<OK>>';")
    assert result.returncode == 0 and "<<OK>>" in result.stdout, (
        f"rc={result.returncode} {result.stdout!r} {result.stderr!r}"
    )
    return result.stdout


# --------------------------------------------------------------------------------------------------------------------
# The bouncer's settings, through the Settings form
# --------------------------------------------------------------------------------------------------------------------


def _save(gui: WebUI, fields: dict[str, str]) -> str:
    response = gui.post(PAGE, fields, timeout=120.0)
    assert response.status_code == 200, f"the Settings save answered HTTP {response.status_code}"
    alert = re.search(r'<div[^>]*class="[^"]*alert-danger[^"]*"[^>]*>(.*?)</div>', response.text, re.S)
    assert alert is None, (
        f"the Settings save was refused: {re.sub(r'<[^>]+>', ' ', alert.group(1)).split() if alert else ''}"
    )
    return response.text


def _on_fields(stub: StubLapi) -> dict[str, str]:
    """The Settings an operator saves: the stub's URL and key, every interface, both families, no log or tag."""
    return {
        "enable": "on",
        "lapi_url": stub.url,
        "api_key": stub.key,
        "log_level": "info",
        "rules_all_interfaces": "on",
        "rule_v4": "on",
        "rule_v6": "on",
        "rules_log": "",
        "rules_tag": "",
    }


def _signals(vm: SmokeVM, since: int) -> int:
    return sum(SIGNALLED in line for line in _bouncer_log(vm, since))


def _serving(vm: SmokeVM, stub: StubLapi) -> bool:
    """On against this stub: the config file names it, the bouncer runs and its four rules are loaded."""
    stored = _config_file(vm)
    return (
        stored is not None and stored[1].get("api_url") == stub.url and _child(vm) is not None and len(_rules(vm)) == 4
    )


def _turn_on(vm: SmokeVM, gui: WebUI, stub: StubLapi) -> None:
    """Save the Settings on. A save that turns the bouncer on also reloads the filter, which ends by signalling the
    bouncer: wait for that, so no reload is still to come when the caller looks at the tables."""
    if h.config_get(vm, MASTER) != "on":
        h.set_package_enabled(vm, True)
    reloads = len(_rules(vm)) != 4
    mark = _log_mark(vm)
    _save(gui, _on_fields(stub))
    _await(
        lambda: (_child(vm), _signals(vm, mark), len(_rules(vm))),
        lambda s: s[0] is not None and s[2] == 4 and (s[1] > 0 or not reloads),
        "the bouncer running, its four rules loaded and the filter reload's signal",
    )


def _converged(vm: SmokeVM, stub: StubLapi) -> dict[str, set[Net] | None]:
    """Wait until both tables equal the engine's set (one pull at most, plus a pull's own time)."""
    want = _expected(stub)
    return _await(
        lambda: _tables(vm),
        lambda t: t == want,
        f"the tables equal to the engine's set {want}",
        cap=3 * UPDATE_FREQUENCY,
    )


def _syslogd_apply(vm: SmokeVM) -> None:
    """Regenerate syslogd's configuration from config.xml and restart it."""
    _php_ok(vm, "require_once('syslog.inc');\nsystem_syslogd_start();")


def _turn_off_and_forget(vm: SmokeVM) -> None:
    """Remove the CrowdSec section and apply that (the bouncer stops, its config file goes), reload the filter, and
    kill both tables: as if the bouncer had never been set up."""
    _php_ok(
        vm,
        f"config_del_path({h._php_str(SECTION)});\nwrite_config('pfBlockerNG smoke: remove the CrowdSec settings');\n"
        f"require_once({h._php_str(PFB_INC)});\npfb_global();\npfb_crowdsec_apply();",
    )
    h.apply_filter_sync(vm)
    _sh(vm, f"pfctl -t crowdsec_v4 -T kill; pfctl -t crowdsec_v6 -T kill; rm -f {STATUS_FILE}; true")


# --------------------------------------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The branch package, pfBlockerNG on; afterwards the CrowdSec settings are gone and the master enable restored."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    vm = smoke_vm
    h.deploy(vm)
    master = h.config_get_state(vm, MASTER)
    level = h.config_get_state(vm, SYSLOG_LEVEL)
    try:
        h.config_set(vm, SYSLOG_LEVEL, "info")
        _syslogd_apply(vm)
        h.set_package_enabled(vm, True)
        yield vm
    finally:
        try:
            _turn_off_and_forget(vm)
        finally:
            h.config_restore_state(vm, MASTER, master)
            h.config_restore_state(vm, SYSLOG_LEVEL, level)
            _syslogd_apply(vm)


@pytest.fixture(scope="module")
def engine(stub_lapi: StubLapi) -> StubLapi:
    """The stub LAPI holding the module's seed decisions."""
    for seed in SEEDS:
        stub_lapi.add(**seed)
    return stub_lapi


@pytest.fixture
def gui(deployed_vm: SmokeVM) -> WebUI:
    """A logged-in webConfigurator session (the UI tier's credentials)."""
    action, password = admin_password_decision(os.environ)
    if action == "fail":
        pytest.fail(password)
    https = (h.config_get(deployed_vm, "system/webgui/protocol").strip().lower() or "http") == "https"
    client = WebUI(
        host=deployed_vm.host,
        port=deployed_vm.web_port,
        username=os.environ.get("SMOKE_ADMIN_USER") or "admin",
        password=password,
        scheme="https" if https else "http",
        verify=not https,
    )
    client.login()
    return client


@pytest.fixture
def bouncer(deployed_vm: SmokeVM, engine: StubLapi, gui: WebUI) -> SmokeVM:
    """The bouncer on against the stub, its tables equal to the engine's set. Turned on only when it is not already,
    so the tests run on one bouncer process until one of them stops it."""
    if not _serving(deployed_vm, engine):
        _turn_on(deployed_vm, gui, engine)
    _converged(deployed_vm, engine)
    return deployed_vm


@pytest.fixture
def bans(engine: StubLapi) -> Iterator[Callable[..., int]]:
    """Add decisions on the engine; those still active are deleted afterwards."""
    added: list[int] = []

    def add(value: str, **fields: str) -> int:
        added.append(engine.add(value, **fields))
        return added[-1]

    yield add
    active = {d["id"] for d in engine.active()}
    engine.delete(*(i for i in added if i in active))


@pytest.fixture
def metrics_export(deployed_vm: SmokeVM) -> Iterator[Callable[[], dict[str, Metric]]]:
    """The metrics export on (its textfile directory made when missing); yields a scrape: run the metrics verb, as
    Core's lane does each minute, and parse the file it writes. Put back afterwards."""
    vm = deployed_vm
    folder = os.path.dirname(PROM)
    existed = vm.ssh(f"test -d {folder}").returncode == 0
    option = f"{h.CFG_GLOBAL}/pfb_metrics_export"
    before = h.config_get_state(vm, option)
    _sh(vm, f"install -d -m 0755 {folder}")

    def export_on() -> None:
        _php_ok(
            vm,
            f"require_once({h._php_str(PFB_EXTRA)});\n"
            "PfbConfig::writeSystem('gen/pfb_metrics_export', PfbToggle::On);\n"
            "write_config('pfBlockerNG smoke: metrics export on');",
        )
        h.tell_core_the_settings_changed(vm)

    def scrape() -> dict[str, Metric]:
        from prometheus_client.parser import text_string_to_metric_families

        _sh(vm, f"{h.PHP_BIN} {h.PFB_CLI} metrics")
        return {family.name: family for family in text_string_to_metric_families(_sh(vm, f"cat {PROM}"))}

    export_on()
    try:
        # The option takes effect with the update pass, which writes the export's sentinel the verb checks
        h.reload(vm, "update", wait_unbound=False)
        yield scrape
    finally:
        h.config_restore_state(vm, option, before)
        h.tell_core_the_settings_changed(vm)
        h.reload(vm, "update", wait_unbound=False)
        if not existed:
            vm.ssh(f"rm -f {PROM}; rmdir {folder}")


def _samples(families: dict[str, Metric]) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    return {(s.name, tuple(sorted(s.labels.items()))): s.value for f in families.values() for s in f.samples}


def _source_up(families: dict[str, Metric]) -> dict[str, float]:
    return {s.labels["source"]: s.value for s in families["pfblockerng_metrics_source_up"].samples}


def _crowdsec_samples(families: dict[str, Metric]) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    return {k: v for k, v in _samples(families).items() if k[0].startswith(("fw_bouncer_", "pfblockerng_crowdsec_"))}


# --------------------------------------------------------------------------------------------------------------------
# Criterion 5: a first enable
# --------------------------------------------------------------------------------------------------------------------


def test_a_first_enable_starts_the_bouncer_on_the_first_try(deployed_vm: SmokeVM, engine: StubLapi, gui: WebUI) -> None:
    """Given a box that has never had the bouncer (no settings, no config file, no tables, no status file),
    When the operator saves the Settings on with the engine's URL and a key,
    Then the bouncer starts once and keeps running: one start in the log and none refused, one startup pull that
      succeeded, the same process throughout, and both tables holding the engine's set within 20 s."""
    vm = deployed_vm
    _turn_off_and_forget(vm)
    assert (_config_file(vm), _child(vm), _tables(vm)) == (None, None, {"crowdsec_v4": None, "crowdsec_v6": None}), (
        f"before-state: never set up; processes: {_processes(vm)!r}"
    )
    assert vm.ssh(f"test -e {STATUS_FILE}").returncode == 1, "before-state: no status file"
    log_mark, lapi_mark = _log_mark(vm), engine.mark()

    _save(gui, _on_fields(engine))
    saved = time.monotonic()

    # The rc start returns once the supervisor's pidfile names it; the bouncer's own pidfile follows
    first = _await(lambda: _child(vm), lambda pid: pid is not None, "the bouncer's pidfile naming it")
    # The save also reloads the filter, which kills the new tables and signals the bouncer to restore them
    _await(lambda: (_signals(vm, log_mark), len(_rules(vm))), lambda s: s[0] > 0 and s[1] == 4, "the save's reload")
    _within(
        BAN_BOUND,
        lambda: _tables(vm),
        lambda t: t == _expected(engine),
        "both tables holding the engine's set after the save",
        since=saved,
    )
    pull = engine.wait_for(lambda r: r.is_stream, after=lapi_mark, timeout=SALVAGE, what="first stream pull")
    log = _bouncer_log(vm, log_mark)
    assert pull.startup, f"the first pull is a startup pull: {pull}"
    assert pull.query.get("scopes") == ["ip,range"], f"the bouncer asks for ip and range decisions: {pull}"
    assert [r for r in engine.requests()[lapi_mark:] if r.path == STREAM and r.status != 200] == [], "no pull failed"
    assert sum(" starting: LAPI " in line for line in log) == 1, "one start of the bouncer:\n" + "\n".join(log)
    assert not any("not started" in line for line in log), "\n".join(log)
    assert _child(vm) == first, f"the supervisor never had to restart the bouncer: {first} -> {_processes(vm)!r}"


# --------------------------------------------------------------------------------------------------------------------
# Criterion 1: bans in and out
# --------------------------------------------------------------------------------------------------------------------


def test_a_ban_reaches_its_table_and_leaves_it_within_20_s(
    bouncer: SmokeVM, engine: StubLapi, bans: Callable[..., int]
) -> None:
    """Given the bouncer running with both tables in place,
    When the engine bans an IPv4 and an IPv6 address,
    Then each is in its family's table within 20 s, and not in the other's;
    When the engine deletes both bans,
    Then both leave their tables within 20 s."""
    vm = bouncer
    v4, v6 = "192.0.2.41", "2001:db8:4074::41"
    before = _tables(vm)
    assert None not in before.values(), f"both tables exist: {before}"
    assert not _holds(v4)(before) and not _holds(v6)(before), f"before-state: neither is banned: {before}"

    ids = bans(v4), bans(v6, origin="cscli")
    tables = _within(BAN_BOUND, lambda: _tables(vm), lambda t: _holds(v4)(t) and _holds(v6)(t), f"{v4} and {v6} banned")
    assert ipaddress.ip_network(v4) not in (tables["crowdsec_v6"] or set())
    assert ipaddress.ip_network(v6) not in (tables["crowdsec_v4"] or set())

    engine.delete(*ids)
    _within(
        BAN_BOUND, lambda: _tables(vm), lambda t: not _holds(v4)(t) and not _holds(v6)(t), f"{v4} and {v6} unbanned"
    )


def test_a_value_banned_twice_stays_until_both_go(bouncer: SmokeVM, engine: StubLapi, bans: Callable[..., int]) -> None:
    """Given a value two decisions ban, in its table,
    When the engine deletes the first decision and the bouncer has pulled and applied that deletion,
    Then the value is still banned;
    When the engine deletes the second,
    Then the value leaves the table within 20 s."""
    vm = bouncer
    value = "192.0.2.42"
    first, second = bans(value), bans(value, origin="cscli", scenario="manual 'ban' from 'smoke'")
    _within(BAN_BOUND, lambda: _tables(vm), _holds(value), f"{value} banned")

    mark = engine.mark()
    engine.delete(first)
    served = engine.wait_for(
        lambda r: r.is_stream and first in r.deleted, after=mark, timeout=SALVAGE, what="the deletion's pull"
    )
    # The bouncer pulls, applies and reconciles in one loop: its next pull means the deletion is applied
    engine.wait_for(lambda r: r.path == STREAM, after=served.seq + 1, timeout=SALVAGE, what="the pull after it")
    assert _holds(value)(_tables(vm)), f"{value} left with one of its two decisions still active"

    engine.delete(second)
    _within(BAN_BOUND, lambda: _tables(vm), lambda t: not _holds(value)(t), f"{value} unbanned")


# --------------------------------------------------------------------------------------------------------------------
# Criterion 9: no listener
# --------------------------------------------------------------------------------------------------------------------


def test_the_bouncer_listens_on_no_port(bouncer: SmokeVM) -> None:
    """Given the bouncer running under its supervisor,
    Then `sockstat -l` lists no TCP or UDP socket of either process."""
    vm = bouncer
    pids = {_child(vm), _pid(vm, DAEMON_PIDFILE, SUPERVISOR)}
    assert None not in pids, f"before-state: the bouncer and its supervisor run: {_processes(vm)!r}"

    listing = _sh(vm, "sockstat -l -4 -6").splitlines()

    rows = [line.split() for line in listing[1:] if line.strip()]
    assert any(row[1] == "sshd" for row in rows), f"vacuity guard: sockstat lists the listeners: {listing}"
    theirs = [row for row in rows if row[1] in ("pfb_crowdsec", "daemon") or (row[2].isdigit() and int(row[2]) in pids)]
    assert theirs == [], f"the bouncer or its supervisor listens: {theirs}"


# --------------------------------------------------------------------------------------------------------------------
# Criterion 3: the config file and the key
# --------------------------------------------------------------------------------------------------------------------


def test_the_config_file_is_0600_with_the_d3_values(bouncer: SmokeVM, engine: StubLapi) -> None:
    """Given the bouncer on,
    Then its config file is root's, mode 0600, with the URL and key from the Settings and the rest D3 fixes."""
    stored = _config_file(bouncer)

    assert stored is not None, "the config file exists while the bouncer is on"
    meta, content = stored
    assert meta == "600 root wheel", f"mode, owner, group: {meta}"
    assert content == {
        "api_url": engine.url,
        "api_key": engine.key,
        "update_frequency": "10s",
        "table_v4": "crowdsec_v4",
        "table_v6": "crowdsec_v6",
        "log_level": "info",
        "status_file": STATUS_FILE,
    }


@pytest.fixture
def sync_target(deployed_vm: SmokeVM, engine: StubLapi) -> Iterator[Callable[[str], LapiRequest]]:
    """XMLRPC sync aimed at the stub (it records the POST to /xmlrpc.php and refuses it); yields a sync in the given
    scope, returning the request the stub received. The sync settings are put back afterwards."""
    vm = deployed_vm
    saved = h._php_read_scalar(vm, "", f"json_encode(config_get_path({h._php_str(SYNC_SECTION)}))")

    def sync(scope: str) -> LapiRequest:
        target = {
            "varsyncdestinenable": "on",
            "varsyncprotocol": "http",
            "varsyncipaddress": str(urlsplit(engine.url).hostname),
            "varsyncport": str(engine.port),
            "varsyncusername": "admin",
            "varsyncpassword": "smoke-sync",
        }
        mark = engine.mark()
        _php_ok(
            vm,
            f"config_set_path({h._php_str(SYNC_SECTION)}, ['varsynconchanges' => 'manual', 'varsynctimeout' => '15', "
            f"'syncscope' => {h._php_str(scope)}, 'row' => [{h._php_kv_array(target)}]]);\n"
            "write_config('pfBlockerNG smoke: XMLRPC sync to the stub');\n"
            f"require_once({h._php_str(PFB_INC)});\npfb_global();\npfblockerng_sync_on_changes();",
        )
        return engine.wait_for(lambda r: r.path == "/xmlrpc.php", after=mark, timeout=SALVAGE, what=f"the {scope} sync")

    try:
        yield sync
    finally:
        restore = (
            f"config_del_path({h._php_str(SYNC_SECTION)});"
            if saved in ("", "null")
            else f"config_set_path({h._php_str(SYNC_SECTION)}, json_decode({h._php_str(saved)}, TRUE));"
        )
        _php_ok(vm, restore + "\nwrite_config('pfBlockerNG smoke: put the sync settings back');")


def test_the_key_appears_nowhere(
    bouncer: SmokeVM,
    engine: StubLapi,
    gui: WebUI,
    metrics_export: Callable[[], dict[str, Metric]],
    sync_target: Callable[[str], LapiRequest],
) -> None:
    """Given the bouncer on, pulling with its key,
    Then the key is in no log under /var/log, neither the Settings nor the Status page, not the status file, not the
    metrics file, and not the XMLRPC sync payload of the policy scope (which carries the CrowdSec section's policy
    fields) or of the legacy scope 'all'."""
    vm = bouncer
    key = engine.key
    assert any(r.api_key == key and r.is_stream for r in engine.requests()), "vacuity guard: the bouncer sends the key"

    settings = gui.get(PAGE).text
    status_page = gui.get(STATUS_PAGE).text
    assert key not in settings, "the Settings page renders the key"
    assert "A key is stored" in settings, "vacuity guard: the Settings page knows a key is stored"
    assert key not in status_page, "the Status page renders the key"
    assert engine.url in status_page, "vacuity guard: the Status page shows the LAPI URL"

    raw_status = _sh(vm, f"stat -f %Lp {STATUS_FILE}; cat {STATUS_FILE}")
    assert key not in raw_status, "the status file holds the key"
    mode, body = raw_status.split("\n", 1)
    assert (mode, json.loads(body)["last_pull"] > 0) == ("644", True), f"status file mode and last pull: {raw_status}"

    families = metrics_export()
    assert any(name == "fw_bouncer_banned_ips" for name, _ in _samples(families)), f"vacuity guard: {sorted(families)}"
    assert key not in _sh(vm, f"cat {PROM}"), "the metrics file holds the key"

    policy = sync_target("policy").body.decode()
    assert engine.url in policy, "vacuity guard: the policy payload carries the CrowdSec section's LAPI URL"
    assert key not in policy, "the policy sync payload holds the key"
    legacy = sync_target("all").body.decode()
    assert "enable_cb" in legacy, f"vacuity guard: the legacy payload carries the General section: {legacy[:300]!r}"
    assert key not in legacy, "the legacy sync payload holds the key"
    assert "pfblockerngcrowdsec" not in legacy, "the legacy scopes never send the CrowdSec section"

    # Last, so the logs written by the pages, the metrics pass and the syncs above are searched too
    logs = vm.ssh(f"grep -rlF -e {shlex.quote(key)} /var/log /tmp/PHP_errors.log 2>/dev/null; true")
    assert logs.stdout == "", f"files holding the key: {logs.stdout!r}"
    assert _bouncer_log(vm), "vacuity guard: the bouncer logs to the system log"


# --------------------------------------------------------------------------------------------------------------------
# #4158: severities
# --------------------------------------------------------------------------------------------------------------------


@pytest.fixture
def by_severity(deployed_vm: SmokeVM) -> Iterator[Callable[[], dict[str, list[str]]]]:
    """syslogd also writes the bouncer's lines to one file per severity; yields a read of those files' bouncer lines
    (``level=`` lines), by severity. The drop-in and the files go afterwards."""
    vm = deployed_vm
    files = {sev: SEVERITY_LOG.format(sev) for sev in SEVERITIES}
    dropin = "!pfb_crowdsec\n" + "".join(f"daemon.={sev}\t{path}\n" for sev, path in files.items())
    _sh(vm, f"touch {' '.join(files.values())} && printf %s {shlex.quote(dropin)} > {SEVERITY_DROPIN}")
    _sh(vm, "pkill -HUP -F /var/run/syslog.pid syslogd")
    # syslogd reads the drop-in on the HUP, at a moment of its own: a probe line in the info file shows it has
    probe = "level=info msg=smoke probe"
    _await(
        lambda: _sh(vm, f"logger -p daemon.info -t pfb_crowdsec {shlex.quote(probe)}; cat {files['info']}"),
        lambda text: probe in text,
        "syslogd writing the drop-in's files",
    )

    def read() -> dict[str, list[str]]:
        return {
            sev: [line for line in _sh(vm, f"cat {path}").splitlines() if "level=" in line]
            for sev, path in files.items()
        }

    try:
        yield read
    finally:
        vm.ssh(f"rm -f {SEVERITY_DROPIN}; pkill -HUP -F /var/run/syslog.pid syslogd; rm -f {' '.join(files.values())}")


def test_each_log_line_reaches_syslog_at_its_levels_severity(
    bouncer: SmokeVM, engine: StubLapi, by_severity: Callable[[], dict[str, list[str]]]
) -> None:
    """Given the bouncer on, and syslogd writing its lines to one file per severity,
    When it logs an info line (a SIGUSR1 check) and error lines (pulls failing while the LAPI is unreachable),
    Then the info line arrives at info and the error lines at err, the text unchanged, and no line arrives at a
      severity other than its level's."""
    vm = bouncer
    _sh(vm, f"pkill -USR1 -F {PIDFILE} -f {shlex.quote(CHILD)}")
    with engine.outage():
        lines = _await(
            by_severity,
            lambda got: all(
                any(text in line for found in got.values() for line in found) for text in (SIGNALLED, FAILED)
            ),
            "the signal's info line and a failed pull's error line, at any severity",
        )
    assert any(SIGNALLED in line for line in lines["info"]), f"the signal's line at info: {lines}"
    assert any(FAILED in line for line in lines["err"]), f"the failed pull's line at err: {lines}"
    for severity, level in (("debug", "debug"), ("info", "info"), ("warning", "warning"), ("err", "error")):
        assert all(f"level={level} msg=" in line for line in lines[severity]), f"{severity}: {lines[severity]}"
    assert lines["notice"] == [], f"no bouncer line at notice: {lines['notice']}"


# --------------------------------------------------------------------------------------------------------------------
# Criterion 4: filter reloads
# --------------------------------------------------------------------------------------------------------------------


def _reload(vm: SmokeVM, gui: WebUI, path: str) -> None:
    if path == "rc.filter_configure_sync":
        h.apply_filter_sync(vm)
    else:  # Status > Filter Reload: the page asks check_reload_status for the reload, which runs it in a php-fpm worker
        response = gui.post("/status_filter_reload.php", {}, submit=("reloadfilter", "Reload Filter"), timeout=60.0)
        assert response.status_code == 200, f"Status > Filter Reload answered HTTP {response.status_code}"


@pytest.mark.parametrize("path", ["rc.filter_configure_sync", "status_filter_reload.php"])
def test_a_filter_reload_leaves_both_tables_full_within_2_s(
    bouncer: SmokeVM, engine: StubLapi, gui: WebUI, path: str
) -> None:
    """Given the bouncer on with both tables full, and its pull just done, so the next one is an interval away,
    When the filter reloads (pfSense kills both tables) and the rule hook signals the bouncer at the reload's end,
    Then both tables hold the full set again within 2 s of the reload's end (rc.filter_configure_sync returns at its
      end; the page only asks for the reload, whose end is the signal), with no pull in between: the signal restored
      them."""
    vm = bouncer
    want = _converged(vm, engine)
    mark = _log_mark(vm)
    pulled = engine.wait_for(lambda r: r.path == STREAM, after=engine.mark(), timeout=SALVAGE, what="the next pull")

    sent = time.monotonic()
    _reload(vm, gui, path)
    ended = time.monotonic()  # rc.filter_configure_sync returns at the reload's end
    if path != "rc.filter_configure_sync":
        # The page's reload ends with the signal, which came after the page was asked (it can end before the page
        # answers) and after the last poll that did not see it began
        ended, cap = sent, ended + SALVAGE
        while True:
            polled = time.monotonic()
            if _signals(vm, mark) > 0:
                break
            if polled > cap:
                raise RuntimeError(f"stuck/environment: no signal from the page's reload within {SALVAGE:g} s")
            ended = polled
            time.sleep(0.25)
    _within(RELOAD_BOUND, lambda: _tables(vm), lambda t: t == want, "both tables full again", since=ended)

    between = [str(r) for r in engine.requests()[pulled.seq + 1 :] if r.path == STREAM]
    assert between == [], (
        f"inconclusive: a pull came before the tables were seen full, it may have restored them: {between}"
    )
    log = _await(lambda: _bouncer_log(vm, mark), lambda lines: any(SIGNALLED in line for line in lines), "the signal")
    restored = {table for line in log for table in RESTORED.findall(line)}
    assert restored == set(TABLES.values()), (
        "the reload killed both tables and the signal restored them:\n" + "\n".join(log)
    )


def test_a_filter_reload_without_the_signal_is_repaired_by_the_next_pull(bouncer: SmokeVM, engine: StubLapi) -> None:
    """Given the bouncer on with both tables full, and its pidfile moved away so the rule hook signals nothing,
    When the filter reloads,
    Then the bouncer receives no signal, and both tables hold the full set again by its next pull."""
    vm = bouncer
    want = _converged(vm, engine)
    mark = _log_mark(vm)
    _sh(vm, f"mv {PIDFILE} {PIDFILE}.aside")
    try:
        h.apply_filter_sync(vm)
        # The next pull starts within one interval of the reload's end; allow it the same again to finish
        log = _within(
            2 * UPDATE_FREQUENCY,
            lambda: _bouncer_log(vm, mark),
            lambda lines: {table for line in lines for table in RESTORED.findall(line)} == set(TABLES.values()),
            "both tables restored after the reload killed them",
        )
    finally:
        _sh(vm, f"mv {PIDFILE}.aside {PIDFILE}")
    assert _tables(vm) == want
    assert not any(SIGNALLED in line for line in log), "\n".join(log)


# --------------------------------------------------------------------------------------------------------------------
# #4159: the rules' trackers
# --------------------------------------------------------------------------------------------------------------------


def test_a_drop_by_the_bouncers_rule_is_logged_with_its_tracker(bouncer: SmokeVM, engine: StubLapi, gui: WebUI) -> None:
    """Given the bouncer on with logging on, so each of its four loaded rules carries its own tracker and its name again
    as a descr= label,
    When the firewall sends a packet to a banned IPv4 address (a seed decision),
    Then filterlog logs the drop with the outbound IPv4 rule's tracker, not 0."""
    vm = bouncer
    banned = "192.0.2.10"
    assert _holds(banned)(_tables(vm)), f"before-state: {banned} is banned"
    _save(gui, {**_on_fields(engine), "rules_log": "on"})
    try:
        rules = _await(
            lambda: _rules(vm), lambda r: len(r) == 4 and all(" log " in line for line in r), "the four logged rules"
        )
        named = r'label "(CrowdSec [^"]+)"(?: label "[^"]*")*(?: ridentifier (\d+))?'
        trackers = dict(re.findall(named, "\n".join(rules)))
        assert all(trackers.values()) and len(set(trackers.values())) == 4, (
            "every rule carries its own tracker:\n" + "\n".join(rules)
        )
        assert all(f'label "{name}" label "descr={name}"' in "\n".join(rules) for name in trackers), (
            "every rule repeats its name as a descr= label:\n" + "\n".join(rules)
        )
        tracker = trackers["CrowdSec IPv4 out"]
        # The save's filter reload killed the tables; the bouncer refills them on the reload's signal
        _await(lambda: _tables(vm), _holds(banned), f"{banned} banned again after the reload")

        mark = _log_mark(vm, FILTER_LOG)
        # pf drops it on the way out; ping reports the refusal, which is the point
        vm.ssh(f"ping -c 1 -t 2 {banned}", timeout=30)
        lines = _await(
            lambda: [line for line in _log_since(vm, FILTER_LOG, mark) if f",{banned}," in line],
            bool,
            f"a filter.log line for {banned}",
            cap=30.0,
        )
        # filterlog's CSV, the line's last word: rule number, sub-rule, anchor, tracker, interface, reason, action, ...
        logged = {line.rsplit(" ", 1)[-1].split(",")[3] for line in lines}
        assert logged == {tracker}, f"the drop logged with tracker {tracker}, got {logged}:\n" + "\n".join(lines)
    finally:
        _save(gui, _on_fields(engine))


# --------------------------------------------------------------------------------------------------------------------
# #4164: the bouncer's drops in Alerts and Reports
# --------------------------------------------------------------------------------------------------------------------


def test_a_drop_by_the_bouncers_rule_shows_in_alerts(bouncer: SmokeVM, engine: StubLapi, gui: WebUI) -> None:
    """Given the bouncer on with logging on, and pfBlockerNG's filterlog daemon running,
    When the firewall sends a packet to a banned IPv4 address (a seed decision),
    Then ip_block.log gets an outbound block row under crowdsec_v4 with the outbound IPv4 rule's tracker, CrowdSec as
    the feed and the matched entry Unknown,
    And the Alerts page shows it, linking the address to the Status subtab's lookup."""
    vm = bouncer
    banned = "192.0.2.10"
    lookup = f"{STATUS_PAGE}?lookup={banned}"
    _save(gui, {**_on_fields(engine), "rules_log": "on"})
    try:
        _await(
            lambda: _rules(vm), lambda r: len(r) == 4 and all(" log " in line for line in r), "the four logged rules"
        )
        _await(lambda: _tables(vm), _holds(banned), f"{banned} banned again after the reload")
        # The filterlog daemon runs
        _sh(vm, "/bin/ps -waxo command | /usr/bin/grep -q '[p]fblockerng.inc filterlog'")
        # Earlier tests' drops of the address are in the logs already: start from empty ones
        _sh(vm, f": > {h.IP_BLOCK_LOG} && : > {UNIFIED_LOG}")
        assert lookup not in gui.get(ALERTS_PAGE).text, f"before-state: no Alerts row links {lookup}"

        # pf drops it on the way out; ping reports the refusal, which is the point
        vm.ssh(f"ping -c 1 -t 2 {banned}", timeout=30)
        rows = _await(
            lambda: [r for r in csv.reader(_log_since(vm, h.IP_BLOCK_LOG, 0)) if banned in r],
            bool,
            f"an ip_block.log row for {banned}",
            cap=30.0,
        )
        # [1] tracker, [4] action, [5] family, [9] destination, [12] direction, [14] alias, [15] matched entry,
        # [16] feed
        got = {(r[1], r[4], r[5], r[9], r[12], r[14], r[15], r[16]) for r in rows}
        assert got == {("177400402", "block", "4", banned, "out", "crowdsec_v4", "Unknown", "CrowdSec")}, rows

        page = gui.get(ALERTS_PAGE).text
        assert lookup in page, f"the Alerts page links {banned} to {lookup}"
    finally:
        _save(gui, _on_fields(engine))


# --------------------------------------------------------------------------------------------------------------------
# #4161: the dashboard widget's rows
# --------------------------------------------------------------------------------------------------------------------


def _widget_rows(gui: WebUI) -> dict[str, list[str]]:
    """The widget's table rows as its AJAX refresh gets them (alias, count, packets, updated, rule icon, group), keyed
    by the alias cell's text."""
    response = gui.get(f"{WIDGET}?getNewWidget=1")
    assert response.status_code == 200, f"the widget answered HTTP {response.status_code}"
    rows = [line.split("||") for line in response.text.splitlines()]
    return {re.sub(r"<[^>]+>", "", cols[0]): cols for cols in rows if len(cols) == 6}


def test_the_widget_shows_each_table_with_its_entries_rules_and_dropped_packets(
    bouncer: SmokeVM, engine: StubLapi, gui: WebUI
) -> None:
    """Given the bouncer on with both tables full,
    Then the widget lists each table as an IP row linked to the Status subtab, with the table's entry count and the
    bouncer's two rules on it;
    When the firewall sends a packet to a banned IPv4 address,
    Then the IPv4 row's packets grow by what the bouncer's rule dropped."""
    vm = bouncer
    tables = _converged(vm, engine)
    rows = _widget_rows(gui)
    for table in TABLES.values():
        assert table in rows, f"a row for {table}: {sorted(rows)}"
        alias, count, _packets, _updated, img, group = rows[table]
        assert group == "ip", rows[table]
        assert f'href="{STATUS_PAGE}"' in alias, f"linked to the Status subtab: {alias}"
        entries = len(tables[table] or set())
        assert count.replace(",", "") == str(entries), f"{table}: count {count}, table {tables[table]}"
        assert "(2)" in img, f"{table}: the bouncer's two rules: {img}"

    banned = "192.0.2.10"
    before = int(re.sub(r"<[^>]+>|,", "", rows["crowdsec_v4"][2]))
    # pf drops it on the way out; ping reports the refusal, which is the point
    vm.ssh(f"ping -c 1 -t 2 {banned}", timeout=30)
    after = int(re.sub(r"<[^>]+>|,", "", _widget_rows(gui)["crowdsec_v4"][2]))
    assert after > before, f"crowdsec_v4 packets: {before} before the drop, {after} after"


# --------------------------------------------------------------------------------------------------------------------
# Criterion 8: the LAPI unreachable
# --------------------------------------------------------------------------------------------------------------------


def _text_by_id(page: str, element_id: str) -> str:
    match = re.search(rf'<(\w+)[^>]*\bid="{re.escape(element_id)}"[^>]*>(.*?)</\1>', page, re.S)
    assert match, f'no element id="{element_id}" on the page'
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", match.group(2))).strip()


def test_while_the_lapi_is_unreachable_the_tables_hold_and_pulls_resume_after(
    bouncer: SmokeVM, engine: StubLapi, gui: WebUI, bans: Callable[..., int]
) -> None:
    """Given the bouncer on with both tables full,
    When the LAPI stops answering (connections refused) and the engine bans a new address meanwhile,
    Then the failed pulls change nothing in the tables, each is logged, and the Status page shows the error and the
      error count;
    When the LAPI answers again,
    Then the next pull is a full pull and the new ban is in its table within 20 s."""
    vm = bouncer
    want = _converged(vm, engine)
    before = _status(vm)
    mark = _log_mark(vm)
    fresh = "192.0.2.88"

    with engine.outage():
        bans(fresh)
        failed = _await(lambda: _status(vm), lambda s: s["lapi_errors"] > before["lapi_errors"], "a failed pull")
        assert _tables(vm) == want, "the tables keep their contents while the LAPI is unreachable"
        log = [line for line in _bouncer_log(vm, mark) if "LAPI pull failed" in line]
        assert log and all(f":{engine.port}" in line for line in log), f"each failed pull is logged: {log}"
        assert any("connection refused" in line for line in log), f"the refusal is logged: {log}"
        page = gui.get(STATUS_PAGE).text
        assert "connection refused" in _text_by_id(page, "cs-last-error"), "the Status page shows the error"
        assert int(_text_by_id(page, "cs-errors")) >= failed["lapi_errors"], "the Status page counts the errors"
        resumed = engine.mark()

    _within(BAN_BOUND, lambda: _tables(vm), _holds(fresh), f"{fresh} banned once the LAPI answers")
    first = next(r for r in engine.requests()[resumed:] if r.path == STREAM)
    assert first.startup and first.status == 200, f"the first pull after the outage is a full pull: {first}"
    # The status file follows the pull that applied the ban, or the bouncer's next status write
    _await(lambda: _status(vm), lambda s: s["last_pull"] >= failed["last_error_time"], "pulls succeeding again")


# --------------------------------------------------------------------------------------------------------------------
# Criteria 11 and 12: metrics
# --------------------------------------------------------------------------------------------------------------------


def test_the_metrics_source_is_up_while_running_and_down_while_stale(
    bouncer: SmokeVM, engine: StubLapi, metrics_export: Callable[[], dict[str, Metric]]
) -> None:
    """Given the bouncer running with the module's seed bans,
    Then the metrics file carries the D6 families from its status file, with `source_up{source="crowdsec"} 1`;
    When the bouncer is frozen until its status file is older than 3 update intervals,
    Then the source reports 0 and no CrowdSec family, with every other source as it was;
    When it runs again, the source is back to 1."""
    vm = bouncer
    status = _status(vm)  # before the scrape: the scrape's counters can only be newer
    running = metrics_export()
    up = _source_up(running)
    assert up.get("crowdsec") == 1, f"source_up while running: {up}"
    samples = _crowdsec_samples(running)
    banned = {
        dict(k[1])["origin"] + "/" + dict(k[1])["ip_type"]: v
        for k, v in samples.items()
        if k[0] == "fw_bouncer_banned_ips"
    }
    assert banned == {"crowdsec/ipv4": 1, "CAPI/ipv4": 1, "cscli/ipv6": 1, "crowdsec/ipv6": 1}, samples
    for name in ("fw_bouncer_dropped_packets", "fw_bouncer_dropped_bytes"):
        assert {dict(k[1])["ip_type"] for k in samples if k[0] == name} == {"ipv4", "ipv6"}, f"{name}: {samples}"
    for name, field in [
        ("pfblockerng_crowdsec_lapi_requests_total", "lapi_requests"),
        ("pfblockerng_crowdsec_lapi_errors_total", "lapi_errors"),
        ("pfblockerng_crowdsec_last_pull_timestamp_seconds", "last_pull"),
        ("pfblockerng_crowdsec_last_error_timestamp_seconds", "last_error_time"),
    ]:
        assert (name, ()) in samples, f"{name} missing: {sorted(samples)}"
        assert samples[(name, ())] >= status[field], (
            f"{name} {samples[(name, ())]} behind the status file's {status[field]}"
        )
    others = {s: v for s, v in up.items() if s != "crowdsec"}
    assert others, "vacuity guard: the other sources are exported"

    # Each scrape with the status file's age read just before and just after it: (before, after, source_up)
    scrapes: list[tuple[int, int, float | None]] = []

    def scrape_aged() -> dict[str, Metric]:
        before = _status_age(vm)
        families = metrics_export()
        scrapes.append((before, _status_age(vm), _source_up(families).get("crowdsec")))
        return families

    child = _child(vm)
    _sh(vm, f"kill -STOP {child}")
    try:
        stale = _await(scrape_aged, lambda f: _source_up(f).get("crowdsec") == 0, "the stale source reported down")
        limit = 3 * UPDATE_FREQUENCY
        early = [s for s in scrapes if s[2] == 0 and s[1] <= limit]
        late = [s for s in scrapes if s[2] != 0 and s[0] > limit]
        assert (early, late) == ([], []), (
            f"down only past {limit} s, and down once past it: (age before, age after, source_up) {scrapes}"
        )
        assert _crowdsec_samples(stale) == {}, "a down source exports none of its families"
        assert {s: v for s, v in _source_up(stale).items() if s != "crowdsec"} == others, "the other sources are intact"
    finally:
        _sh(vm, f"kill -CONT {child}")
    _await(
        metrics_export, lambda f: _source_up(f).get("crowdsec") == 1, "the source up again", cap=3 * UPDATE_FREQUENCY
    )


def test_the_lapi_receives_usage_metrics(bouncer: SmokeVM, engine: StubLapi) -> None:
    """Given the bouncer running with the module's seed bans,
    When the LAPI answers its first pull,
    Then the very next request is a usage post with the bouncer key: one remediation component of type pfb_crowdsec
    with its version and start time, a 900 s window, dropped packets and bytes per address family, and the active
    decisions per origin and family."""
    vm = bouncer
    status = _status(vm)

    def this_process(r: LapiRequest) -> bool:
        if r.method != "POST" or r.path != USAGE:
            return False
        components = json.loads(r.body).get("remediation_components") or [{}]
        return bool(components[0].get("utc_startup_timestamp") == status["start_time"])

    # Recorded already unless the bouncer has just started
    post = engine.wait_for(this_process, timeout=SALVAGE, what="usage metrics post of this bouncer process")

    before = engine.requests()[post.seq - 1] if post.seq else None
    assert before is not None and before.is_stream and before.startup, (
        f"the first post follows the first answered pull at once: {before} then {post}"
    )
    assert post.status == 201, f"the post carried the bouncer key: {post}"
    body = json.loads(post.body)
    (component,) = body["remediation_components"]
    assert (component["type"], component["version"], component["utc_startup_timestamp"]) == (
        "pfb_crowdsec",
        status["version"],
        status["start_time"],
    )
    (window,) = component["metrics"]
    assert window["meta"]["window_size_seconds"] == USAGE_WINDOW
    items = {(i["name"], i["unit"], tuple(sorted(i["labels"].items()))): i["value"] for i in window["items"]}
    for ip_type in ("ipv4", "ipv6"):
        for unit in ("packet", "byte"):
            assert ("dropped", unit, (("ip_type", ip_type),)) in items, f"dropped {unit}s for {ip_type}: {items}"
    active = {
        dict(labels)["origin"] + "/" + dict(labels)["ip_type"]: v
        for (name, unit, labels), v in items.items()
        if name == "active_decisions"
    }
    assert active == {"crowdsec/ipv4": 1, "CAPI/ipv4": 1, "cscli/ipv6": 1, "crowdsec/ipv6": 1}, items
    assert all(unit == "ip" for name, unit, _ in items if name == "active_decisions")


# --------------------------------------------------------------------------------------------------------------------
# Criterion 6 (with 11): stopping, and turning it off
# --------------------------------------------------------------------------------------------------------------------


def test_stopping_the_service_empties_both_tables_and_reports_the_source_down(
    bouncer: SmokeVM, engine: StubLapi, metrics_export: Callable[[], dict[str, Metric]]
) -> None:
    """Given the bouncer running with both tables full,
    When its service is stopped,
    Then no bouncer process is left, both tables are empty, and the metrics source reports 0 with no CrowdSec family
    and every other source as it was."""
    vm = bouncer
    full = _converged(vm, engine)
    assert all(full.values()), f"before-state: both tables hold bans: {full}"
    up = _source_up(metrics_export())
    assert up.get("crowdsec") == 1, up

    try:
        _sh(vm, f"{RC} stop")

        assert _processes(vm) == "", "no bouncer or supervisor is left"
        assert all(not table for table in _tables(vm).values()), f"both tables emptied: {_tables(vm)}"
        stopped = metrics_export()
        assert _source_up(stopped).get("crowdsec") == 0
        assert _crowdsec_samples(stopped) == {}
        assert {s: v for s, v in _source_up(stopped).items() if s != "crowdsec"} == {
            s: v for s, v in up.items() if s != "crowdsec"
        }, "the other sources are intact"
    finally:
        _sh(vm, f"{RC} start")


def test_turning_the_bouncer_off_removes_its_rules_config_and_process(
    bouncer: SmokeVM, engine: StubLapi, gui: WebUI
) -> None:
    """Given the bouncer on, with its config file, process and four rules,
    When the operator saves the Settings off,
    Then the config file is gone and no process is left when the save returns, and the filter reload it starts
    removes the rules."""
    vm = bouncer
    assert _config_file(vm) is not None and _child(vm) is not None and len(_rules(vm)) == 4, "before-state"

    try:
        _save(gui, {"enable": ""})

        assert _config_file(vm) is None, "off removes the config file"
        assert _processes(vm) == "", "off stops the bouncer"
        _await(lambda: _rules(vm), lambda rules: rules == [], "the rules removed by the reload")
        rows = _widget_rows(gui)
        assert not set(TABLES.values()) & set(rows), f"off: the widget shows no CrowdSec rows: {sorted(rows)}"
    finally:
        _turn_on(vm, gui, engine)


def test_turning_pfblockerng_off_removes_the_bouncers_rules_config_and_process(
    bouncer: SmokeVM, engine: StubLapi, gui: WebUI
) -> None:
    """Given the bouncer on, with its config file, process and four rules,
    When the operator saves pfBlockerNG's master enable off on the General page,
    Then the config file is gone and no process is left when the save returns, and the filter reload it starts removes
    the rules, though the CrowdSec settings stay on (#4139: the General save applies the bouncer, no update pass)."""
    vm = bouncer
    assert _config_file(vm) is not None and _child(vm) is not None and len(_rules(vm)) == 4, "before-state"

    try:
        response = gui.post(GENERAL_PAGE, {"enable_cb": ""}, timeout=300.0)
        assert response.status_code == 200, f"the General save answered HTTP {response.status_code}"
        assert h.config_get(vm, MASTER) == "", "vacuity guard: pfBlockerNG is off"

        assert _config_file(vm) is None, "pfBlockerNG off removes the config file"
        assert _processes(vm) == "", "pfBlockerNG off stops the bouncer"
        _await(lambda: _rules(vm), lambda rules: rules == [], "the rules removed by the save's reload")
        assert h.config_get(vm, f"{SECTION}/enable") == "on", "the CrowdSec settings are untouched"
    finally:
        _turn_on(vm, gui, engine)


# --------------------------------------------------------------------------------------------------------------------
# Criterion 7: reboot
# --------------------------------------------------------------------------------------------------------------------


@pytest.mark.timeout(1200)
def test_a_reboot_brings_the_bouncer_back_with_the_full_set(bouncer: SmokeVM, engine: StubLapi) -> None:
    """Given the bouncer on with both tables full,
    When the firewall reboots,
    Then with no other step the bouncer runs again (a new process), pulls the full set at start-up, and both tables hold
    it."""
    vm = bouncer
    want = _converged(vm, engine)
    before = _child(vm)
    mark = engine.mark()

    h.reboot_vm(vm, require_pkg_metadata=True)  # the deinstall after this runs pkg

    after = _await(lambda: _child(vm), lambda pid: pid is not None, "the bouncer running after the boot")
    assert after != before, f"a new process: {before} -> {after}"
    assert len(_processes(vm).splitlines()) == 2, f"one bouncer and its supervisor: {_processes(vm)}"
    # The old process may pull once more before the shutdown stops it: the new one starts with a full pull
    engine.wait_for(
        lambda r: r.is_stream and r.startup, after=mark, timeout=SALVAGE, what="the new process's full pull"
    )
    _within(BAN_BOUND, lambda: _tables(vm), lambda t: t == want, "both tables holding the full set after the boot")


# --------------------------------------------------------------------------------------------------------------------
# Criterion 15: deinstall
# --------------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Leftovers:
    files: list[str]
    tables: dict[str, set[Net] | None]
    processes: str


def _leftovers(vm: SmokeVM) -> _Leftovers:
    paths = f"{RC} {CONFIG_FILE} {STATUS_FILE} {PIDFILE} {DAEMON_PIDFILE} {CROWDSEC_DIR}"
    found = vm.ssh(f"find {paths} -type f 2>/dev/null; true").stdout.split()
    return _Leftovers(sorted(found), _tables(vm), _processes(vm))


@pytest.mark.timeout(1200)
def test_deinstall_leaves_nothing_behind(bouncer: SmokeVM, engine: StubLapi) -> None:
    """Given the bouncer on with both tables full,
    When the package is deleted,
    Then no rc file, binary, config file, status file or pidfile is left, no bouncer process runs, and neither table
    holds an address."""
    vm = bouncer
    _converged(vm, engine)
    present = _leftovers(vm)
    assert {RC, CONFIG_FILE, STATUS_FILE} <= set(present.files), f"before-state: {present.files}"
    assert any(path.endswith("/pfb_crowdsec") for path in present.files), f"before-state, the binary: {present.files}"
    pidfiles = _sh(vm, f"cat {PIDFILE} {DAEMON_PIDFILE}").split()
    assert len(present.processes.splitlines()) == 2, (
        f"before-state, one bouncer and its supervisor: {present.processes}"
    )
    mark = _log_mark(vm)

    try:
        deleted = vm.ssh("env ASSUME_ALWAYS_YES=yes pkg delete -y -g 'pfSense-pkg-pfBlockerNG*'", timeout=600.0)
        assert deleted.returncode == 0, f"pkg delete: rc={deleted.returncode}\n{deleted.stdout}\n{deleted.stderr}"

        left = _leftovers(vm)
        assert left.files == [], f"left behind: {left.files}"
        assert left.processes == "", (
            f"still running: {left.processes}\nbefore: {present.processes} (pidfiles {pidfiles})\n"
            f"log: {_bouncer_log(vm, mark)}\npkg delete:\n{deleted.stdout}"
        )
        assert all(not table for table in left.tables.values()), f"table contents left: {left.tables}"
    finally:
        _php_ok(
            vm,
            f"config_del_path({h._php_str(SECTION)});\nwrite_config('pfBlockerNG smoke: drop the CrowdSec settings');",
        )
        h.deploy(vm)
