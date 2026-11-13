"""issue #3841: the Core API daemon (pfb-core) on a real pfSense box, after the package install.

* PHP gets the documented version reply through pfb_core_call() (docs/misc/core-api-protocol.md);
* pfb-core holds no network socket, so no other host can reach it: its only listener is the Unix socket;
* the socket's directory is root's alone, so an unprivileged local user cannot connect, while root can;
* ``--socket-group`` opens the socket to a group, never the API: on a second Core opened to nobody's group, ``nobody``
  connects and is refused with ``401 unauthenticated`` (who is served stays decided by uid), while root is served;
* issue #3924: config.xml is the only store of ``settings/dns``: Core keeps no settings file and reads config.xml
  through the settings adapter. The install leaves Core at the revision config.xml projects, a change made without a
  page (or an older config restored) reaches Core with the next tick, a Core that was down when the setting changed
  reads it at its start, and a Core ``SaveSettings`` changes config.xml through the adapter and leaves a config history
  entry.
* issue #3908: two ``start`` calls at once leave one supervisor, the one the daemon pidfile names, and Core answers
  afterwards: the start is serialized by a lock and returns once the pidfile names the supervisor;

The module deploys the branch package once; its install starts the service, and the socket is awaited (bounded) before
anything is asked of it.
"""

from __future__ import annotations

import json
import os
import shlex
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

SOCKET = "/var/run/pfb_core/api.sock"
VERSION = {"service": "pfblockerng-core", "apiVersion": "v1", "status": "serving"}
OPEN, CLOSE = "<<<CORE>>>", "<<<CORE-END>>>"
# Outer bound on the service coming up after the install: salvage only, never an assertion about duration.
READY_WATCHDOG = 60.0
# Outer bound on Core reading a change (the service's start, a tick): salvage only, never an assertion about duration.
SYNC_WATCHDOG = 90.0
CORE_RC = "/usr/local/etc/rc.d/pfb_core.sh"
PHP = "/usr/local/bin/php"
PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"
HSTS = f"{h.CFG_DNSBL_SETTINGS}/pfb_hsts"
CORE_STATE = "/usr/local/etc/pfb_core"
CONFIG_HISTORY = "/conf/backup/config-*.xml"
SAVE_MESSAGE = "pfBlockerNG Core saved the settings"
RETIRED_SETTINGS = ("settings.json", "settings.json.tmp", "settings.lock")
ADAPTER = "/usr/local/pkg/pfblockerng/pfb_core_settings.sh"
# The package's pfb-core for this machine, as the rc script picks it (uname -p says aarch64 where the target is arm64)
CORE_BIN = "/usr/local/pkg/pfblockerng/core/bin/freebsd-$(uname -p | sed s/aarch64/arm64/)/pfb-core"
NOBODY_GROUP = 65534  # the group of the user `nobody`
CORE_DAEMON_PID = "/var/run/pfb_core_daemon.pid"
# The rc script's supervisor as pgrep -f finds it: by daemon(8)'s title, or by its command line until the title is set
SUPERVISORS = r"{ /bin/pgrep -f '^daemon: pfb_core\[' ; /bin/pgrep -f '^/usr/sbin/daemon .*-t pfb_core ' ; }"


@pytest.fixture(scope="module")
def core_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The branch package deployed once, with the Core socket present."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    deadline = time.monotonic() + READY_WATCHDOG
    while smoke_vm.ssh(f"test -S {SOCKET}", timeout=30).returncode != 0:
        if time.monotonic() > deadline:
            log = smoke_vm.ssh(
                "tail -n 20 /var/log/pfblockerng/core.log; ls -la /usr/local/pkg/pfblockerng/core/bin/*", timeout=30
            )
            pytest.fail(f"STUCK: {SOCKET} never appeared after the install:\n{log.stdout}{log.stderr}")
        time.sleep(1)
    yield smoke_vm


def test_php_gets_the_version_reply(core_vm: SmokeVM) -> None:
    result = h.php_eval(
        core_vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        f"echo '{OPEN}' . json_encode(pfb_core_call('GetVersion')) . '{CLOSE}';",
    )
    out = result.stdout
    assert OPEN in out and CLOSE in out, f"no reply printed: rc={result.returncode}\n{out}\n{result.stderr}"
    reply = json.loads(out.split(OPEN, 1)[1].split(CLOSE, 1)[0])
    assert reply == {"status": 200, "body": VERSION, "error": None}, f"pfb_core_call('GetVersion') = {reply}"


def test_pfb_core_holds_no_network_socket(core_vm: SmokeVM) -> None:
    # Before: the Unix listener is pfb-core's (the process this test inspects is the right one). FreeBSD 16 cuts the
    # local address at 21 columns unless -w widens it, so the path would read /var/run/pfb_core/api
    unix = core_vm.ssh("/usr/bin/sockstat -u -l -w", timeout=30)
    assert any("pfb-core" in line and SOCKET in line for line in unix.stdout.splitlines()), (
        f"pfb-core does not hold {SOCKET}:\n{unix.stdout}"
    )
    inet = core_vm.ssh("/usr/bin/sockstat -46 -w", timeout=30)
    assert inet.returncode == 0, inet.stderr
    held = [line for line in inet.stdout.splitlines() if line.split()[1:2] == ["pfb-core"]]
    assert held == [], "pfb-core holds an IPv4/IPv6 socket, reachable from another host:\n" + "\n".join(held)


def test_an_unprivileged_user_cannot_reach_the_api_and_root_can(core_vm: SmokeVM) -> None:
    call = f"/usr/local/bin/curl -sS -o /dev/null -w '%{{http_code}}' --unix-socket {SOCKET} -X POST http://localhost/v1/GetVersion"
    # Before: root reaches it, so the refusal below is the permission, not a dead socket
    root = core_vm.ssh(call, timeout=30)
    assert (root.returncode, root.stdout) == (0, "200"), f"root could not call the API: {root.stdout} {root.stderr}"
    modes = core_vm.ssh(f"/usr/bin/stat -f '%Sp %Su' {SOCKET.rsplit('/', 1)[0]} {SOCKET}", timeout=30)
    assert modes.stdout.split("\n")[:2] == ["drwx------ root", "srw------- root"], f"modes: {modes.stdout}"
    nobody = core_vm.ssh(f"/usr/bin/su -m nobody -c {shlex.quote(call)}", timeout=30)
    # curl's exit 7 (could not connect) with no HTTP status: the connect itself was refused
    assert (nobody.returncode, nobody.stdout) == (7, "000"), (
        f"nobody reached the Core API: {nobody.stdout} {nobody.stderr}"
    )
    # ...because the socket's directory is closed to it
    entry = core_vm.ssh(f"/usr/bin/su -m nobody -c {shlex.quote('ls ' + SOCKET)}", timeout=30)
    assert entry.returncode != 0 and "Permission denied" in entry.stderr, f"{entry.returncode} {entry.stderr}"


def await_group_socket(vm: SmokeVM, api: str, pid: str, log: str) -> None:
    """Block until the second Core's socket is open to its group (the mode is the last thing Core sets on it).

    A Core that exited fails at once with its log; the watchdog only salvages a stuck run.
    """
    deadline = time.monotonic() + READY_WATCHDOG
    while True:
        held = vm.ssh(f"/usr/bin/stat -f '%Sp %Sg' {api}", timeout=30)
        if held.returncode == 0 and held.stdout.strip() == "srw-rw---- nobody":
            return
        if vm.ssh(f"kill -0 {pid}", timeout=30).returncode != 0:
            pytest.fail(
                f"the second Core exited before it opened {api}:\n{vm.ssh(f'tail -n 20 {log}', timeout=30).stdout}"
            )
        if time.monotonic() > deadline:
            said = vm.ssh(f"tail -n 20 {log}", timeout=30).stdout
            pytest.fail(f"STUCK: {api} never opened to group nobody (stat: {held.stdout}{held.stderr}):\n{said}")
        time.sleep(1)


def test_a_socket_group_member_that_is_not_admitted_gets_401(core_vm: SmokeVM) -> None:
    """--socket-group lets a member of the group connect, never be served: who is served stays decided by uid."""
    made = core_vm.ssh("mktemp -d /tmp/pfbcorefence.XXXXXX", timeout=30)
    fence = made.stdout.strip()
    assert made.returncode == 0 and fence.startswith("/tmp/pfbcorefence."), (
        f"no scratch directory: {made.stdout}{made.stderr}"
    )
    api, log = f"{fence}/api.sock", f"{fence}/log"
    call = f"/usr/local/bin/curl -sS -w '\\n%{{http_code}}' --unix-socket {api} -X POST http://localhost/v1/GetVersion"
    pid = ""
    try:
        start = core_vm.ssh(
            f"nohup {CORE_BIN} --socket {api} --state-dir {fence}/state --socket-group {NOBODY_GROUP} "
            f"</dev/null >{log} 2>&1 & echo $!",
            timeout=30,
        )
        pid = start.stdout.strip()
        assert start.returncode == 0 and pid.isdigit(), f"the second Core did not start: {start.stdout}{start.stderr}"
        await_group_socket(core_vm, api, pid, log)

        # Before: root is admitted on the same socket, so the 401 below is the uid check, not a dead Core
        root = core_vm.ssh(call, timeout=30)
        root_body, _, root_status = root.stdout.rpartition("\n")
        assert (root.returncode, root_status) == (0, "200"), (
            f"root could not call the second Core: {root.stdout}{root.stderr}"
        )
        assert json.loads(root_body) == VERSION, f"root's reply: {root_body}"

        nobody = core_vm.ssh(f"/usr/bin/su -m nobody -c {shlex.quote(call)}", timeout=30)
        body, _, status = nobody.stdout.rpartition("\n")
        # curl exit 0 with a status: the connect succeeded (the group's permission) and the Core answered
        assert (nobody.returncode, status) == (0, "401"), (
            f"nobody was not refused with 401: {nobody.stdout}{nobody.stderr}"
        )
        assert json.loads(body)["error"]["code"] == "unauthenticated", f"nobody's reply: {body}"
    finally:
        # TERM, KILL after a bounded wait (salvage only); the scratch directory goes either way
        reap = (
            f"kill {pid}; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 {pid} 2>/dev/null || break; sleep 1; done; "
            f"kill -9 {pid} 2>/dev/null; "
        )
        core_vm.ssh(f"{reap if pid else ''}rm -rf {fence}", timeout=60)


def php_json(vm: SmokeVM, expression: str) -> Any:
    """``json_encode`` of a PHP expression evaluated on the box with the package's functions loaded."""
    result = h.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        f"echo '{OPEN}' . json_encode({expression}) . '{CLOSE}';",
    )
    out = result.stdout
    assert OPEN in out and CLOSE in out, (
        f"no value printed for {expression}: rc={result.returncode}\n{out}\n{result.stderr}"
    )
    return json.loads(out.split(OPEN, 1)[1].split(CLOSE, 1)[0])


def config_dns_settings(vm: SmokeVM) -> dict[str, Any]:
    """What config.xml says for ``settings/dns``: the 17 fields as ``pfb_core_dns_settings()`` projects them."""
    settings: dict[str, Any] = php_json(vm, "pfb_core_dns_settings()")
    return settings


def core_dns(vm: SmokeVM) -> tuple[int, dict[str, Any] | None] | None:
    """Core's revision and its ``settings/dns`` value (``None``: no settings yet); ``None`` when Core did not answer."""
    reply = php_json(vm, "pfb_core_call('GetSettings', ['projectionIds' => ['dns']])")
    body = reply["body"]
    if reply["status"] != 200 or body is None:
        return None
    held = next((p["value"] for p in body.get("projections", []) if p["resourceId"] == "settings/dns"), None)
    return int(body.get("revision", 0)), held


def await_core_dns(vm: SmokeVM, want: dict[str, Any], *, watchdog: float = SYNC_WATCHDOG) -> int:
    """Block until Core's ``settings/dns`` equals ``want``; returns its revision. The watchdog only salvages."""
    deadline = time.monotonic() + watchdog
    while True:
        held = core_dns(vm)
        if held is not None and held[1] == want:
            return held[0]
        if time.monotonic() > deadline:
            pytest.fail(f"STUCK: Core never held the settings config.xml has.\nwant: {want}\nheld: {held}")
        time.sleep(1)


def await_core_up(vm: SmokeVM, *, watchdog: float = READY_WATCHDOG) -> None:
    """Block until Core answers a settings read. The watchdog only salvages a stuck run."""
    deadline = time.monotonic() + watchdog
    while core_dns(vm) is None:
        if time.monotonic() > deadline:
            pytest.fail("STUCK: Core never answered after its start")
        time.sleep(1)


def config_revision(vm: SmokeVM) -> int:
    """What the settings adapter answers a read with: the revision of every projection config.xml holds."""
    revision: int = php_json(vm, "pfb_core_settings_revision(pfb_core_settings())")
    return revision


def tell_core(vm: SmokeVM) -> None:
    """A page save's notice, run by hand: Core reads config.xml again through its adapter, whatever it holds."""
    reason = php_json(vm, "pfb_core_settings_changed(NULL, TRUE)")
    assert reason is None, f"Core was not told that the settings changed: {reason}"


def run_tick(vm: SmokeVM) -> None:
    """One tick by hand: it tells Core when config.xml moved past the revision Core holds."""
    h.wait_no_active_pfb_task(vm)
    tick = vm.ssh(f"{PHP} {PFB_PHP} tick 2>&1", timeout=180)
    assert tick.returncode == 0, f"the tick failed: {tick.stdout}"


def core_save_hsts(vm: SmokeVM, revision: int, value: bool) -> dict[str, Any]:
    """Core's ``SaveSettings`` of hstsNullBlocking at ``revision``: the reply as ``pfb_core_call`` gives it."""
    flag = "TRUE" if value else "FALSE"
    reply: dict[str, Any] = php_json(
        vm,
        "pfb_core_call('SaveSettings', ['requestId' => bin2hex(random_bytes(16)), "
        f"'expectedRevision' => {revision}, 'changes' => ['dns' => ['hstsNullBlocking' => {flag}]]])",
    )
    return reply


def config_history(vm: SmokeVM) -> set[str]:
    """The config history files (``/conf/backup``) now on the box."""
    listing = vm.ssh(f"ls {CONFIG_HISTORY}", timeout=30)
    assert listing.returncode == 0, f"no config history: {listing.stderr}"
    return set(listing.stdout.split())


def retired_settings_present(state_dir: str, exists: Callable[[str], bool]) -> list[str]:
    """The #3842/#3913 settings files still in ``state_dir``, each asked on its own: one missing never hides another."""
    return [f"{state_dir}/{name}" for name in RETIRED_SETTINGS if exists(f"{state_dir}/{name}")]


def newest_config_backup(vm: SmokeVM) -> str:
    """The newest Config History backup: the configuration the last write_config() replaced."""
    listing = vm.ssh(f"ls -t {CONFIG_HISTORY} | head -n 1", timeout=30)
    assert listing.returncode == 0 and listing.stdout.strip(), f"no config history: {listing.stderr}"
    return listing.stdout.strip()


def adapter_seconds(vm: SmokeVM, request: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    """One run of the settings adapter as Core runs it: its wall time on the box (``time -p``) and its reply."""
    body = shlex.quote(json.dumps(request))
    run = vm.ssh(f"/usr/bin/time -p /bin/sh -c {shlex.quote(f'printf %s {body} | {ADAPTER}')}", timeout=60)
    assert run.returncode == 0, f"the adapter failed: {run.stdout}{run.stderr}"
    real = next(line.split()[1] for line in run.stderr.splitlines() if line.startswith("real "))
    reply: dict[str, Any] = json.loads(run.stdout)
    return float(real), reply


def _flipped(state: tuple[bool, str]) -> str:
    """The other toggle value for a stored one: On becomes the Off token, anything else On."""
    return "" if state[1] == "on" else "on"


def test_the_install_leaves_no_settings_file_for_core(core_vm: SmokeVM) -> None:
    """Core keeps no settings store: config.xml is it, so the state directory never holds a settings file."""
    lock = core_vm.ssh(f"test -f {CORE_STATE}/core.lock", timeout=30)
    assert lock.returncode == 0, f"before-state: {CORE_STATE} must be the running Core's directory (its lock is there)"
    on_box = lambda path: core_vm.ssh(f"test -e {path}", timeout=30).returncode == 0  # noqa: E731
    stray = retired_settings_present(CORE_STATE, on_box)
    assert stray == [], f"a settings store is left in Core's state directory: {stray}"


def test_the_install_leaves_core_at_the_revision_config_xml_projects(core_vm: SmokeVM) -> None:
    """Core read config.xml through the adapter at its start: its values and its revision are config.xml's."""
    want = config_dns_settings(core_vm)
    assert len(want) == 17, f"before-state: expected the 17 native fields, got {want}"

    await_core_dns(core_vm, want)

    held = core_dns(core_vm)
    assert held is not None and held[1] == want, f"Core holds {held}, config.xml says {want}"
    projected = config_revision(core_vm)
    assert held[0] == projected, f"Core is at revision {held[0]}, config.xml projects {projected}"


def test_a_change_made_without_a_page_reaches_core_with_the_next_tick(core_vm: SmokeVM) -> None:
    """A restore or an HA receive writes config.xml with no page save: the tick finds Core's revision differs."""
    original = h.config_get_state(core_vm, HSTS)
    try:
        tell_core(core_vm)
        before = config_dns_settings(core_vm)

        h.config_set(core_vm, HSTS, _flipped(original))

        after = config_dns_settings(core_vm)
        assert after["hstsNullBlocking"] != before["hstsNullBlocking"], f"before-state: the write did not change {HSTS}"
        held = core_dns(core_vm)
        assert held is not None and held[1] == before, f"before-state: Core must still hold the old value, holds {held}"
        run_tick(core_vm)
        await_core_dns(core_vm, after)
    finally:
        h.config_restore_state(core_vm, HSTS, original)
        tell_core(core_vm)


def test_core_that_was_down_when_the_setting_changed_reads_it_at_its_start(core_vm: SmokeVM) -> None:
    """A stopped Core never blocks or undoes a change: config.xml keeps the value, and Core reads it when it starts."""
    original = h.config_get_state(core_vm, HSTS)
    stopped = False
    try:
        tell_core(core_vm)
        before = config_dns_settings(core_vm)
        stop = core_vm.ssh(f"{CORE_RC} stop", timeout=60)
        assert stop.returncode == 0, f"{CORE_RC} stop failed: {stop.stdout}{stop.stderr}"
        stopped = True

        new = _flipped(original)
        h.config_set(core_vm, HSTS, new)

        assert h.config_get(core_vm, HSTS) == new, "config.xml must keep the value written while Core is down"
        down = php_json(core_vm, "pfb_core_call('GetVersion')")
        assert down["status"] == 0 and down["error"], f"before-state: Core must be unreachable, answered {down}"
        want = config_dns_settings(core_vm)
        assert want["hstsNullBlocking"] != before["hstsNullBlocking"], f"before-state: the write did not change {HSTS}"
        start = core_vm.ssh(f"{CORE_RC} start", timeout=60)
        assert start.returncode == 0, f"{CORE_RC} start failed: {start.stdout}{start.stderr}"
        stopped = False

        await_core_dns(core_vm, want)
        assert core_dns(core_vm) == (config_revision(core_vm), want), "Core is at config.xml's values and revision"
    finally:
        if stopped:
            core_vm.ssh(f"{CORE_RC} start", timeout=60)
        h.config_restore_state(core_vm, HSTS, original)
        await_core_up(core_vm)
        tell_core(core_vm)


def test_concurrent_starts_leave_one_supervisor(core_vm: SmokeVM) -> None:
    """Boot and package starts can overlap: the start lock lets one launch Core, and the other finds it serving."""
    try:
        stop = core_vm.ssh(f"{CORE_RC} stop", timeout=60)
        assert stop.returncode == 0, f"{CORE_RC} stop failed: {stop.stdout}{stop.stderr}"
        left = core_vm.ssh(SUPERVISORS, timeout=30).stdout.split()
        assert left == [], f"before-state: a supervisor is left after the stop: {left}"

        both = core_vm.ssh(
            f"{CORE_RC} start & a=$!; {CORE_RC} start & b=$!; wait $a; echo A=$?; wait $b; echo B=$?", timeout=120
        )
        assert both.stdout.split() == ["A=0", "B=0"], f"the starts did not both succeed: {both.stdout}{both.stderr}"

        supervisors = core_vm.ssh(SUPERVISORS, timeout=30).stdout.split()
        named = core_vm.ssh(f"cat {CORE_DAEMON_PID}", timeout=30).stdout.strip()
        assert supervisors == [named], f"supervisors running: {supervisors}; {CORE_DAEMON_PID} names {named!r}"
        await_core_up(core_vm)
    finally:
        core_vm.ssh(f"{CORE_RC} start", timeout=60)
        await_core_up(core_vm)


def test_a_core_save_changes_config_xml_and_leaves_a_config_history_entry(core_vm: SmokeVM) -> None:
    """Core's SaveSettings goes through the adapter: config.xml holds the value and pfSense keeps a revision of it."""
    original = h.config_get_state(core_vm, HSTS)
    try:
        tell_core(core_vm)
        before = config_dns_settings(core_vm)
        revision = await_core_dns(core_vm, before)
        history = config_history(core_vm)

        reply = core_save_hsts(core_vm, revision, not before["hstsNullBlocking"])

        assert reply["status"] == 200, f"Core refused the save: {reply}"
        after = config_dns_settings(core_vm)
        assert after == {**before, "hstsNullBlocking": not before["hstsNullBlocking"]}, f"config.xml now says {after}"
        assert core_dns(core_vm) == (config_revision(core_vm), after), "Core is at config.xml's values and revision"
        # write_config() backs up the configuration it replaces; Config History lists the new one by its description
        assert config_history(core_vm) - history, "the save left no new config history entry"
        description = h.config_get(core_vm, "revision/description")
        assert SAVE_MESSAGE in description, f"config.xml's revision says {description!r}, not the Core save"
    finally:
        h.config_restore_state(core_vm, HSTS, original)
        tell_core(core_vm)


def test_an_older_config_restored_reaches_core_with_the_next_tick(core_vm: SmokeVM) -> None:
    """Config History's restore (pfSense ``config_restore()``) of the config before a Core save: the tick tells Core."""
    original = h.config_get_state(core_vm, HSTS)
    try:
        tell_core(core_vm)
        older = config_dns_settings(core_vm)
        revision = await_core_dns(core_vm, older)
        saved = core_save_hsts(core_vm, revision, not older["hstsNullBlocking"])
        assert saved["status"] == 200, f"before-state: Core refused the save: {saved}"
        newer = config_dns_settings(core_vm)
        assert newer != older, "before-state: the Core save changed config.xml"
        backup = newest_config_backup(core_vm)

        restored = php_json(core_vm, f"config_restore({backup!r}, 'pfBlockerNG #3924 smoke')")
        assert restored is True, f"pfSense's config_restore({backup}) answered {restored}"

        assert config_dns_settings(core_vm) == older, "before-state: the older value is back in config.xml"
        held = core_dns(core_vm)
        assert held is not None and held[1] == newer, f"before-state: Core must still hold the newer value: {held}"
        run_tick(core_vm)
        await_core_dns(core_vm, older)
    finally:
        h.config_restore_state(core_vm, HSTS, original)
        tell_core(core_vm)


def test_the_settings_adapter_reads_and_writes_as_core_runs_it(core_vm: SmokeVM) -> None:
    """The adapter as Core runs it: five reads and two writes (a flip and back), each timed on the box and recorded."""
    original = h.config_get_state(core_vm, HSTS)
    try:
        reads = [adapter_seconds(core_vm, {"version": 1, "op": "read"}) for _ in range(5)]
        for _, reply in reads:
            assert reply["settings"]["dns"] == config_dns_settings(core_vm), f"the read answered {reply}"
        current = reads[-1][1]
        writes = []
        hsts = current["settings"]["dns"]["hstsNullBlocking"]
        for value in (not hsts, hsts):
            wanted = {**current["settings"], "dns": {**current["settings"]["dns"], "hstsNullBlocking": value}}
            seconds, reply = adapter_seconds(
                core_vm,
                {"version": 1, "op": "write", "expectedRevision": current["revision"], "settings": wanted},
            )
            assert "error" not in reply and config_dns_settings(core_vm) == wanted["dns"], f"the write answered {reply}"
            writes.append(seconds)
            current = {"revision": reply["revision"], "settings": wanted}
        read_times = [seconds for seconds, _ in reads]
        # A diagnostic, never an assertion: the Go unit tests pin the deadlines with controlled hangs
        print(f"PFB_ADAPTER_LATENCY read {read_times} write {writes}", flush=True)
    finally:
        h.config_restore_state(core_vm, HSTS, original)
        tell_core(core_vm)
