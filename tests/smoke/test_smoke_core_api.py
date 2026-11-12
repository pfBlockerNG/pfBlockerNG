"""issue #3841: the Core API daemon (pfb-core) on a real pfSense box, after the package install.

* PHP gets the documented version reply through pfb_core_call() (docs/misc/core-api-protocol.md);
* pfb-core holds no network socket, so no other host can reach it: its only listener is the Unix socket;
* the socket's directory is root's alone, so an unprivileged local user cannot connect, while root can;
* issue #3913: config.xml is the authority for ``settings/dns``: the install leaves Core holding what config.xml says,
  a change made without a page (a restore) reaches Core with the next tick, and a Core that was down when the setting
  changed gets it from the start of the service.

The module deploys the branch package once; its install starts the service, and the socket is awaited (bounded) before
anything is asked of it.
"""

from __future__ import annotations

import json
import os
import shlex
import time
from collections.abc import Iterator
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
# Outer bound on a push reaching Core (the service's start, a tick): salvage only, never an assertion about duration.
PUSH_WATCHDOG = 90.0
CORE_RC = "/usr/local/etc/rc.d/pfb_core.sh"
PHP = "/usr/local/bin/php"
PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"
HSTS = f"{h.CFG_DNSBL_SETTINGS}/pfb_hsts"


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
    # Before: the Unix listener is pfb-core's (the process this test inspects is the right one)
    unix = core_vm.ssh("/usr/bin/sockstat -u -l", timeout=30)
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


def await_core_dns(vm: SmokeVM, want: dict[str, Any], *, watchdog: float = PUSH_WATCHDOG) -> int:
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


def push_now(vm: SmokeVM) -> None:
    """The service start's forced push, run by hand: Core holds config.xml's settings afterwards."""
    reason = php_json(vm, "pfb_core_settings_push(NULL, TRUE)")
    assert reason is None, f"the push to Core failed: {reason}"


def _flipped(state: tuple[bool, str]) -> str:
    """The other toggle value for a stored one: On becomes the Off token, anything else On."""
    return "" if state[1] == "on" else "on"


def test_the_install_leaves_core_holding_what_config_xml_says(core_vm: SmokeVM) -> None:
    """The service's start pushed config.xml's ``settings/dns``: Core holds exactly those 17 values."""
    want = config_dns_settings(core_vm)
    assert len(want) == 17, f"before-state: expected the 17 native fields, got {want}"

    await_core_dns(core_vm, want)

    held = core_dns(core_vm)
    assert held is not None and held[1] == want, f"Core holds {held}, config.xml says {want}"


def test_a_change_made_without_a_page_reaches_core_with_the_next_tick(core_vm: SmokeVM) -> None:
    """A restore or an HA receive writes config.xml with no page save: the tick finds the difference and pushes it."""
    original = h.config_get_state(core_vm, HSTS)
    try:
        push_now(core_vm)
        before = config_dns_settings(core_vm)

        h.config_set(core_vm, HSTS, _flipped(original))

        after = config_dns_settings(core_vm)
        assert after["hstsNullBlocking"] != before["hstsNullBlocking"], f"before-state: the write did not change {HSTS}"
        held = core_dns(core_vm)
        assert held is not None and held[1] == before, f"before-state: Core must still hold the old value, holds {held}"
        h.wait_no_active_pfb_task(core_vm)
        tick = core_vm.ssh(f"{PHP} {PFB_PHP} tick 2>&1", timeout=180)
        assert tick.returncode == 0, f"the tick failed: {tick.stdout}"
        await_core_dns(core_vm, after)
    finally:
        h.config_restore_state(core_vm, HSTS, original)
        push_now(core_vm)


def test_core_that_was_down_when_the_setting_changed_gets_it_from_the_service_start(core_vm: SmokeVM) -> None:
    """A stopped Core never blocks or undoes a save: config.xml keeps the value, and the service's start sends it."""
    original = h.config_get_state(core_vm, HSTS)
    stopped = False
    try:
        push_now(core_vm)
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
    finally:
        if stopped:
            core_vm.ssh(f"{CORE_RC} start", timeout=60)
        h.config_restore_state(core_vm, HSTS, original)
        await_core_up(core_vm)
        push_now(core_vm)
