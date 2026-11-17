"""Tier-A ``ui_render`` coverage for issue #3922: a DNS > DNSBL save that Core refuses changes nothing.

The page asks Core's dry run (ValidateSettings) before it writes config.xml. A refusal is shown as an input error and
nothing is saved. The oracle is the box, read back over SSH, never the HTTP body: the digest of config.xml, before and
after a save that changes a setting. (Issue #4053 removed the block page, the save's former file side effect.)

Core is made to refuse by stopping the ``pfb_core`` rc service and serving a PHP stand-in on its socket, run with the
appliance's PHP (the box's checkout carries ``tests/smoke`` and not ``tests/php``, so the script is written here). Core
is started again, and told to read config.xml, whatever the test did.
"""

from __future__ import annotations

import contextlib
import json
import shlex
import subprocess
import time
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from ..test_smoke_core_api import CORE_RC, PHP, SOCKET
from .render_oracle import NO_INPUT_ERRORS
from .test_dns_general_core_push import _core_in_step
from .test_dns_general_forms import SAVE_TIMEOUT
from .test_dnsbl_follows_pfb_dns import _errors_text

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
CACHE_MAX_CFG = f"{helpers.CFG_DNSBL_SETTINGS}/pfb_py_cache_max"
STAND_IN = "/tmp/pfb_core_stand_in_3922.php"
STAND_IN_RECORD = "/tmp/pfb_core_stand_in_3922.requests"
STAND_IN_OUT = "/tmp/pfb_core_stand_in_3922.out"
STAND_IN_PID = "/tmp/pfb_core_stand_in_3922.pid"
STAND_IN_WATCHDOG = 30.0
REFUSED = "refused by the stand-in"
REFUSAL = {
    "error": {
        "code": "invalid_argument",
        "message": "the settings are invalid",
        "fieldErrors": [{"field": "changes.dns.hstsNullBlocking", "message": REFUSED}],
    }
}
# The Core API's socket answered with one refusal for every request: argv are the socket, a file the request lines are
# appended to, and the reply body. Prints "ready" once it listens; gives up after 120 s.
STAND_IN_PHP = r"""<?php
[, $socket, $record, $reply] = $argv;
$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "listen: {$errstr}\n");
    exit(2);
}
fwrite(STDOUT, "ready\n");
$deadline = time() + 120;
while (time() < $deadline) {
    $conn = @stream_socket_accept($server, 1);
    if ($conn === false) {
        continue;
    }
    stream_set_timeout($conn, 5);
    $request = '';
    while (!str_contains($request, "\r\n\r\n")) {
        $chunk = fread($conn, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $request .= $chunk;
    }
    [$head, $body] = array_pad(explode("\r\n\r\n", $request, 2), 2, '');
    $length = preg_match('/^Content-Length:\s*(\d+)/mi', $head, $m) === 1 ? (int) $m[1] : 0;
    while (strlen($body) < $length) {
        $chunk = fread($conn, $length - strlen($body));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $body .= $chunk;
    }
    file_put_contents($record, strtok($head, "\r\n") . "\n", FILE_APPEND);
    fwrite($conn, "HTTP/1.1 400 Stand-in\r\nContent-Type: application/json\r\nContent-Length: " . strlen($reply)
        . "\r\nConnection: close\r\n\r\n{$reply}");
    fclose($conn);
}
@unlink($socket);
"""


def _put(vm: SmokeVM, path: str, content: str) -> None:
    """Write ``content`` to ``path`` on the guest (``tee`` keeps stdin free for the content)."""
    put = subprocess.run(
        vm.ssh_argv("tee", path), input=content, capture_output=True, text=True, timeout=30, check=False
    )
    assert put.returncode == 0, f"writing {path} failed: rc={put.returncode} {put.stderr!r}"


@contextlib.contextmanager
def _refusing_core(vm: SmokeVM) -> Iterator[None]:
    """Core stopped, its socket served by a stand-in that refuses every dry run; Core serving again after."""
    with _core_in_step(vm):
        stop = vm.ssh(f"{CORE_RC} stop", timeout=60)
        assert stop.returncode == 0, f"{CORE_RC} stop failed: {stop.stdout}{stop.stderr}"
        try:
            _put(vm, STAND_IN, STAND_IN_PHP)
            vm.ssh(f"rm -f {SOCKET} {STAND_IN_RECORD} {STAND_IN_OUT}")
            start = vm.ssh(
                f"/usr/sbin/daemon -f -p {STAND_IN_PID} -o {STAND_IN_OUT} "
                f"{PHP} {STAND_IN} {SOCKET} {STAND_IN_RECORD} {shlex.quote(json.dumps(REFUSAL))}"
            )
            assert start.returncode == 0, f"the stand-in did not start: {start.stdout}{start.stderr}"
            deadline = time.monotonic() + STAND_IN_WATCHDOG  # only salvages a stand-in that never listens
            while vm.ssh(f"grep -q ready {STAND_IN_OUT}").returncode != 0:
                if time.monotonic() > deadline:
                    pytest.fail(f"STUCK: the stand-in never listened: {vm.ssh(f'cat {STAND_IN_OUT}').stdout!r}")
                time.sleep(0.5)
            yield
        finally:
            vm.ssh(
                f"kill $(cat {STAND_IN_PID}); rm -f {SOCKET} {STAND_IN} {STAND_IN_RECORD} {STAND_IN_OUT} {STAND_IN_PID}"
            )


def test_a_dnsbl_save_that_core_refuses_leaves_config_xml_untouched(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """A refused save writes nothing.

    Given: Core refuses the dry run of every save
    When:  DNS > DNSBL is saved with a changed decision cache cap
    Then:  the page shows Core's refusal and config.xml is unchanged
    """
    vm = smoke_vm
    with _refusing_core(vm):
        assert helpers.config_get(vm, CACHE_MAX_CFG) != "3922", "before-state: the posted cap must be a change"
        config_before = helpers.pfb_config_digest(vm)

        saved = webui.post(DNSBL_PAGE, {"pfb_py_cache_max": "3922"}, allow_redirects=False, timeout=SAVE_TIMEOUT)

        errors = _errors_text(saved.text)
        assert errors != NO_INPUT_ERRORS and REFUSED in errors, f"the save must show Core's refusal, not: {errors}"
        requests = vm.ssh(f"cat {STAND_IN_RECORD}").stdout
        assert "POST /v1/ValidateSettings " in requests, f"the page's dry run never reached the stand-in: {requests!r}"
        assert helpers.pfb_config_digest(vm) == config_before, "the refused save changed config.xml"
