"""issue #3841: the Core API daemon (pfb-core) on a real pfSense box, after the package install.

* PHP gets the documented version reply through pfb_core_call() (docs/misc/core-api-protocol.md);
* pfb-core holds no network socket, so no other host can reach it: its only listener is the Unix socket;
* the socket's directory is root's alone, so an unprivileged local user cannot connect, while root can.

The package install starts the service; the socket is awaited (bounded) before anything is asked of it.
"""

from __future__ import annotations

import json
import shlex
import time

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

SOCKET = "/var/run/pfb_core/api.sock"
VERSION = {"service": "pfblockerng-core", "apiVersion": "v1", "status": "serving"}
OPEN, CLOSE = "<<<CORE>>>", "<<<CORE-END>>>"
# Outer bound on the service coming up after the install: salvage only, never an assertion about duration.
READY_WATCHDOG = 60.0


def _await_socket(vm: SmokeVM) -> None:
    deadline = time.monotonic() + READY_WATCHDOG
    while True:
        probe = vm.ssh(f"test -S {SOCKET}", timeout=30)
        if probe.returncode == 0:
            return
        if time.monotonic() > deadline:
            log = vm.ssh("tail -n 20 /var/log/pfblockerng/core.log; /usr/sbin/service pfb_core.sh status", timeout=30)
            pytest.fail(f"STUCK: {SOCKET} never appeared after the install; core.log tail:\n{log.stdout}{log.stderr}")
        time.sleep(1)


def test_php_gets_the_version_reply(smoke_vm: SmokeVM) -> None:
    _await_socket(smoke_vm)
    result = h.php_eval(
        smoke_vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        f"echo '{OPEN}' . json_encode(pfb_core_call('GetVersion')) . '{CLOSE}';",
    )
    out = result.stdout
    assert OPEN in out and CLOSE in out, f"no reply printed: rc={result.returncode}\n{out}\n{result.stderr}"
    reply = json.loads(out.split(OPEN, 1)[1].split(CLOSE, 1)[0])
    assert reply == {"status": 200, "body": VERSION, "error": None}, f"pfb_core_call('GetVersion') = {reply}"


def test_pfb_core_holds_no_network_socket(smoke_vm: SmokeVM) -> None:
    _await_socket(smoke_vm)
    # Before: the Unix listener is pfb-core's (the process this test inspects is the right one)
    unix = smoke_vm.ssh("/usr/bin/sockstat -u -l", timeout=30)
    assert any("pfb-core" in line and SOCKET in line for line in unix.stdout.splitlines()), (
        f"pfb-core does not hold {SOCKET}:\n{unix.stdout}"
    )
    inet = smoke_vm.ssh("/usr/bin/sockstat -46 -w", timeout=30)
    assert inet.returncode == 0, inet.stderr
    held = [line for line in inet.stdout.splitlines() if line.split()[1:2] == ["pfb-core"]]
    assert held == [], "pfb-core holds an IPv4/IPv6 socket, reachable from another host:\n" + "\n".join(held)


def test_an_unprivileged_user_cannot_reach_the_api_and_root_can(smoke_vm: SmokeVM) -> None:
    _await_socket(smoke_vm)
    call = f"/usr/local/bin/curl -sS -o /dev/null -w '%{{http_code}}' --unix-socket {SOCKET} -X POST http://localhost/v1/GetVersion"
    # Before: root reaches it, so the refusal below is the permission, not a dead socket
    root = smoke_vm.ssh(call, timeout=30)
    assert (root.returncode, root.stdout) == (0, "200"), f"root could not call the API: {root.stdout} {root.stderr}"
    modes = smoke_vm.ssh(f"/usr/bin/stat -f '%Sp %Su' {SOCKET.rsplit('/', 1)[0]} {SOCKET}", timeout=30)
    assert modes.stdout.split("\n")[:2] == ["drwx------ root", "srw------- root"], f"modes: {modes.stdout}"
    nobody = smoke_vm.ssh(f"/usr/bin/su -m nobody -c {shlex.quote(call)}", timeout=30)
    assert nobody.returncode != 0, f"nobody reached the Core API: {nobody.stdout} {nobody.stderr}"
    assert "Permission denied" in nobody.stderr or "Couldn't connect" in nobody.stderr, nobody.stderr
