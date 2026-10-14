"""THROWAWAY exploration (never committed to the real branch): prints what the live pair does."""

# ruff: noqa: E501 -- throwaway exploration.

from __future__ import annotations

import json
import time
import traceback
from collections.abc import Callable

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .ha_pair import HaPair, wait_carp_state
from .ha_policy import (
    B_VIP_UNIQID,
    BASELINE_FEED_ADDR,
    BASELINE_FEED_ADDR6,
    DNSBL,
    configure_sender,
    emit,
    gateway_name,
    php_json,
    php_write,
    receive_state,
    seed_node,
    send_state,
    set_leaves,
    settle,
    write_feed,
)

pytestmark = pytest.mark.smoke


def _reporter() -> tuple[list[str], Callable[..., None], Callable[[str, Callable[[], None]], None]]:
    report: list[str] = []
    t00 = time.monotonic()

    def say(*parts: object) -> None:
        report.append(f"[{time.monotonic() - t00:7.1f}s] " + " ".join(str(p) for p in parts))

    def step(name: str, fn: Callable[[], None]) -> None:
        say(f"=== {name}")
        try:
            fn()
        except BaseException as exc:  # exploration: keep going, report everything
            say(f"!!! {name} raised {type(exc).__name__}: {str(exc)[:1500]}")
            say(traceback.format_exc()[-1500:])

    return report, say, step


@pytest.mark.timeout(1500)  # exploration
def test_x2_delay(ha_pair: HaPair) -> None:
    pair = ha_pair
    a, b = pair.primary, pair.secondary
    report, say, step = _reporter()
    wait_carp_state(a, "MASTER", node="primary")
    wait_carp_state(b, "BACKUP", node="secondary")
    say("B record at start:", json.dumps(receive_state(b)))
    say("A send at start:", json.dumps(send_state(a)))
    say(
        "xmlrpc_client.inc timeouts:",
        a.ssh(
            "grep -n -i 'timeout\\|retry\\|retries\\|connectionTimeout' /etc/inc/xmlrpc_client.inc | head -30"
        ).stdout,
    )
    say("nginx fastcgi timeouts on B:", b.ssh("grep -n -i 'timeout' /var/etc/nginx-webConfigurator.conf").stdout)
    say("B nginx/php-fpm procs:", b.ssh("ps ax | grep -E 'nginx|php-fpm' | grep -v grep | head -20").stdout)
    configure_sender(pair, "manual", timeout=5)
    say(
        "A sync section:",
        json.dumps(
            php_json(
                a,
                emit("config_get_path('installedpackages/pfblockerngsync/config/0', array())"),
                secret_values=[pair.sync_password],
            )
        ).replace(pair.sync_password, "REDACTED"),
    )

    def mechanism(label: str, stop: str, cont: str, value: str) -> None:
        set_leaves(a, {f"{DNSBL}/top1m_inclusion": value}, f"x2 {label}")
        before = receive_state(b).get("last")
        say(label, "B last before:", json.dumps(before))
        say(label, "stop:", b.ssh(stop + "; echo rc=$?").stdout.strip())
        t = time.monotonic()
        try:
            h.reload(a, "update", wait_unbound=False, timeout=300)
            say(label, "A update pass returned after", f"{time.monotonic() - t:.1f}s")
        except Exception as exc:
            say(label, "A update raised", type(exc).__name__, str(exc)[:500])
        finally:
            say(label, "A send record:", json.dumps(send_state(a)))
            say(label, "B last while stopped:", json.dumps(receive_state(b).get("last")))
            say(label, "cont:", b.ssh(cont + "; echo rc=$?").stdout.strip())
        landed = False
        for i in range(20):
            time.sleep(3)
            last = receive_state(b).get("last")
            if last != before:
                say(
                    label,
                    f"B record advanced after cont (+{(i + 1) * 3}s):",
                    json.dumps(last),
                    "apply:",
                    json.dumps(receive_state(b).get("apply")),
                )
                landed = True
                break
        if not landed:
            say(label, "B record did NOT advance within 60s after cont")
        t = time.monotonic()
        h.reload(a, "update", wait_unbound=False, timeout=300)
        say(label, "healthy retry took", f"{time.monotonic() - t:.1f}s", "A send:", json.dumps(send_state(a)))
        say(label, "B record after retry:", json.dumps(receive_state(b)))
        say(label, "B banners:", b.ssh(f"grep -c 'UPDATE PROCESS START' {h.PFB_LOG}").stdout.strip())
        try:
            settle(b)
        except Exception as exc:
            say(label, "settle:", str(exc)[:300])

    step("M0 baseline healthy send (no fault)", lambda: mechanism("M0", "true", "true", "x2-m0"))
    step("M1 php-fpm STOP", lambda: mechanism("M1", "pkill -STOP -f php-fpm", "pkill -CONT -f php-fpm", "x2-m1"))
    step("M2 nginx STOP", lambda: mechanism("M2", "pkill -STOP nginx", "pkill -CONT nginx", "x2-m2"))
    drop = "block drop quick inet proto tcp from 172.30.254.1 to any port 443"
    load = (
        f"awk -v r='{drop}' 'BEGIN{{d=0}} !d && /^(block|pass) /{{print r; d=1}} {{print}}' /tmp/rules.debug > /tmp/rules.delay && "
        "pfctl -f /tmp/rules.delay 2>&1 | tail -3"
    )
    step("M3 pf drop SYN", lambda: mechanism("M3", load, "pfctl -f /tmp/rules.debug 2>&1 | tail -2", "x2-m3"))
    pytest.fail("EXPLORATION X2 REPORT\n" + "\n".join(report))


@pytest.mark.timeout(1500)  # exploration
def test_x1_unbound(ha_pair: HaPair) -> None:
    pair = ha_pair
    a, b = pair.primary, pair.secondary
    report, say, step = _reporter()

    def unbound(vm: SmokeVM, label: str, wait: float = 90.0) -> None:
        t = time.monotonic()
        rc = 1
        while time.monotonic() - t < wait:
            r = vm.ssh("/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status", timeout=15.0)
            rc = r.returncode
            if rc == 0:
                break
            time.sleep(3)
        say(label, "unbound rc", rc, f"after {time.monotonic() - t:.1f}s")
        if rc != 0:
            say(label, "ps:", vm.ssh("ps auxww | grep -i '[u]nbound'").stdout)
            say(
                label,
                "checkconf:",
                vm.ssh("/usr/local/sbin/unbound-checkconf /var/unbound/unbound.conf 2>&1 | tail -15").stdout,
            )
            say(label, "resolver.log:", vm.ssh("tail -25 /var/log/resolver.log").stdout)
            say(label, "pfb log:", vm.ssh(f"tail -40 {h.PFB_LOG}").stdout)
            say(label, "system.log:", vm.ssh("grep -i -E 'unbound|resolver' /var/log/system.log | tail -15").stdout)

    for name, vm in (("A", a), ("B", b)):
        say(name, "unbound/enable:", json.dumps(php_json(vm, emit("config_get_path('unbound', array())"))))
        unbound(vm, f"{name} start", wait=10)
    gateway = gateway_name(a)
    say("gateway", gateway)

    def p1() -> None:
        h.inject_ip_lists(b, [])
        h.ensure_dnsbl_vip(b)
        h.set_dnsbl_enabled(b, True)
        h.reload(b, "update", wait_unbound=False)
        unbound(b, "P1 plain", wait=100)

    step("P1 B plain DNSBL enable + reload", p1)

    def p2() -> None:
        for alias, addr in {**BASELINE_FEED_ADDR, **BASELINE_FEED_ADDR6}.items():
            write_feed(b, alias, addr)
        seed_node(b, "B", gateway)
        h.reload(b, "update", wait_unbound=False)
        unbound(b, "P2 seeded", wait=100)

    step("P2 B seeded local values", p2)

    def p3() -> None:
        php_write(
            b,
            "$vips = config_get_path('virtualip/vip', array());\n"
            f"foreach ($vips as $i => $v) {{ if (($v['uniqid'] ?? '') === {h._php_str(h.SMOKE_VIP_UNIQID)}) {{ $vips[$i]['uniqid'] = {h._php_str(B_VIP_UNIQID)}; }} }}\n"
            "config_set_path('virtualip/vip', $vips);",
            "x1 B VIP uniqid",
        )
        say(
            "B dnsbl vip4 ref:",
            json.dumps(
                php_json(b, emit("config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4')"))
            ),
        )
        h.reload(b, "update", wait_unbound=False)
        unbound(b, "P3 renamed VIP", wait=100)

    step("P3 B VIP uniqid renamed", p3)
    pytest.fail("EXPLORATION X1 REPORT\n" + "\n".join(report))
