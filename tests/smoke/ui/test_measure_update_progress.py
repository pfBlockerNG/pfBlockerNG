"""issue #3941 measurement only (not for merge): Update-page progress delivery, polling versus streaming.

Prints, never asserts durations:
* the php-fpm pool and the webConfigurator nginx fastcgi settings;
* the cost of one authenticated Update-page poll (?ajax=tail) and of one PHP -> Core call (GetVersion);
* an SSE stream through nginx + php-fpm: whether events arrive unbuffered, and whether a normal page request
  still gets served while as many streams as there are php-fpm workers are held open.
"""

from __future__ import annotations

import base64
import re
import statistics
import threading
import time

import pytest
import requests

from .. import helpers as h
from ..conftest import SmokeVM
from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

SSE_PAGE = "/pfb_measure_sse.php"
SSE_PHP = r"""<?php
require_once('guiconfig.inc');
session_write_close();
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no');
while (ob_get_level() > 0) { ob_end_flush(); }
$end = time() + (int) ($_GET['secs'] ?? 20);
$n = 0;
while (time() < $end) {
	echo "data: " . (++$n) . " " . microtime(TRUE) . "\n\n";
	flush();
	sleep(1);
}
"""


def _ms(xs: list[float]) -> str:
    xs = sorted(xs)
    return f"n={len(xs)} median={statistics.median(xs) * 1000:.1f}ms p95={xs[int(len(xs) * 0.95) - 1] * 1000:.1f}ms max={xs[-1] * 1000:.1f}ms"  # noqa: E501


def test_measure_update_progress(webui: WebUI, deployed_vm: SmokeVM) -> None:
    vm = deployed_vm
    conf = vm.ssh(
        "for f in $(find /usr/local/lib /usr/local/etc /var/etc -maxdepth 2 -name 'php-fpm*.conf' 2>/dev/null); do "
        "echo \"## $f\"; grep -E '^\\s*(pm|listen|request_terminate|\\[)' $f; done; "
        "echo '## nginx'; grep -nE 'fastcgi_(buffer|read_timeout)|worker_processes|keepalive_timeout|fastcgi_pass' "
        "/var/etc/nginx-webConfigurator.conf; echo '## php-fpm processes'; pgrep -fl php-fpm | wc -l; sysctl -n hw.ncpu",  # noqa: E501
        timeout=60,
    )
    print(f"\n=== CONFIG ===\n{conf.stdout}{conf.stderr}")
    children = [int(x) for x in re.findall(r"pm\.max_children\s*=\s*(\d+)", conf.stdout)]
    workers = min(children) if children else 2

    polls = []
    for _ in range(40):
        t = time.monotonic()
        r = webui.get("/pfblockerng/pfblockerng_update.php?ajax=tail")
        polls.append(time.monotonic() - t)
        assert r.status_code == 200, r.text[:200]
    print(f"=== POLL ?ajax=tail (client wall) === {_ms(polls)}")

    core = h.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc'); global $pfb; pfb_global();\n"
        "$t = microtime(TRUE); for ($i = 0; $i < 200; $i++) { $r = pfb_core_call('GetVersion'); }\n"
        "printf(\"<<<M>>>%.3f ms/call status=%d<<<M>>>\", (microtime(TRUE) - $t) * 5, $r['status']);",
        timeout=120,
    )
    print(f"=== PHP -> Core GetVersion === {re.findall(r'<<<M>>>(.*?)<<<M>>>', core.stdout)} {core.stderr[-300:]}")

    b64 = base64.b64encode(SSE_PHP.encode()).decode()
    put = vm.ssh(
        f'/usr/local/bin/php -r \'file_put_contents("/usr/local/www{SSE_PAGE}", base64_decode("{b64}"));\'', timeout=30
    )
    assert put.returncode == 0, put.stderr

    def stream(secs: int, arrivals: list[float]) -> None:
        start = time.monotonic()
        with webui.get(f"{SSE_PAGE}?secs={secs}", stream=True, timeout=secs + 30) as r:
            for line in r.iter_lines():
                if line.startswith(b"data:"):
                    arrivals.append(time.monotonic() - start)

    arrivals: list[float] = []
    stream(8, arrivals)
    gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
    print(
        f"=== SSE single stream === first event {arrivals[0] * 1000 if arrivals else -1:.0f}ms, "
        f"events={len(arrivals)}, gaps {_ms(gaps) if gaps else '-'}"
    )

    for held in sorted({max(workers - 1, 1), workers, workers + 1}):
        threads = [threading.Thread(target=stream, args=(25, [])) for _ in range(held)]
        for t in threads:
            t.start()
        time.sleep(5)
        t0 = time.monotonic()
        try:
            r = webui.get("/pfblockerng/pfblockerng_update.php?ajax=tail", timeout=15)
            verdict = f"served HTTP {r.status_code} in {(time.monotonic() - t0) * 1000:.0f}ms"
        except requests.RequestException as e:
            verdict = f"NOT served within 15s ({type(e).__name__})"
        busy = vm.ssh("pgrep -fl php-fpm | wc -l", timeout=30).stdout.strip()
        print(f"=== {held} SSE streams held (max_children={workers}, php-fpm procs={busy}) -> poll {verdict}")
        for t in threads:
            t.join()
    vm.ssh(f"rm -f /usr/local/www{SSE_PAGE}", timeout=30)
