"""THROWAWAY exploration (never committed to the real branch): prints what the live pair does."""

from __future__ import annotations

# ruff: noqa: E501 -- throwaway exploration.
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
    configure_sender,
    diff_leaves,
    emit,
    feed_path,
    gateway_name,
    group_local_values,
    ip_group,
    node_state,
    php_json,
    php_write,
    read_sections,
    receive_state,
    seed_node,
    send_state,
    settle,
    sync_once,
    wait_filter_idle,
    write_feed,
    write_sections,
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
        except BaseException as exc:  # noqa: BLE001 -- exploration: keep going, report everything
            say(f"!!! {name} raised {type(exc).__name__}: {str(exc)[:1500]}")
            say(traceback.format_exc()[-1500:])

    return report, say, step


def _unbound(say: Callable[..., None], vm: SmokeVM, label: str, wait: float = 90.0) -> None:
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
        say(label, "system.log:", vm.ssh("grep -i -E 'unbound|resolver|xmlrpc' /var/log/system.log | tail -25").stdout)


@pytest.mark.timeout(1700)  # exploration
def test_x3_sync_plain(ha_pair: HaPair) -> None:
    """Automatic and manual sync without DNSBL on either node."""
    pair = ha_pair
    a, b = pair.primary, pair.secondary
    report, say, step = _reporter()
    wait_carp_state(a, "MASTER", node="primary")
    wait_carp_state(b, "BACKUP", node="secondary")
    gateway = gateway_name(a)
    for vm in (a, b):
        h.inject_ip_lists(vm, [])
    say("A pkg enable:", php_json(a, emit("config_get_path('installedpackages/pfblockerng/config/0/enable_cb')")))
    say("B pkg enable:", php_json(b, emit("config_get_path('installedpackages/pfblockerng/config/0/enable_cb')")))
    say(
        "B banners:",
        h.count_log_marker(b, h.PFB_LOG, "UPDATE PROCESS START"),
        "A banners:",
        h.count_log_marker(a, h.PFB_LOG, "UPDATE PROCESS START"),
    )
    sa0, sb0 = node_state(a), node_state(b)
    say(
        "baseline digests equal:",
        sa0.digest == sb0.digest,
        "projection n:",
        len(sa0.projection),
        "A local n:",
        len(sa0.local),
        "B local n:",
        len(sb0.local),
    )
    say("projection keys:", json.dumps(sorted(sa0.projection)[:60]))

    def add_group(alias: str, addr: str, tag: str) -> None:
        for vm in (a, b):
            write_feed(vm, alias, addr)
        tree = read_sections(a, ["pfblockernglistsv4"])["pfblockernglistsv4"] or {"config": []}
        tree.setdefault("config", []).append(ip_group(alias, feed_path(alias), local=group_local_values(tag, gateway)))
        write_sections(a, {"pfblockernglistsv4": tree}, f"x3 group {alias}")

    def one(transport: str, alias: str, addr: str) -> None:
        configure_sender(pair, transport)  # type: ignore[arg-type]
        say(
            transport,
            "A sender:",
            json.dumps(
                php_json(
                    a,
                    emit("config_get_path('installedpackages/pfblockerngsync/config/0')"),
                    secret_values=[pair.sync_password],
                )
            ).replace(pair.sync_password, "REDACTED"),
        )
        add_group(alias, addr, "A")
        pre_b = node_state(b)
        say(transport, "A vs B digests before:", node_state(a).digest[:12], pre_b.digest[:12])
        t0 = time.monotonic()
        sync = sync_once(pair, transport)  # type: ignore[arg-type]
        say(transport, f"sync took {time.monotonic() - t0:.1f}s", "send:", json.dumps(sync.send))
        say(transport, "receive:", json.dumps(sync.receive), "passes:", sync.passes)
        sa, sb = node_state(a), node_state(b)
        say(transport, "digests equal after:", sa.digest == sb.digest, "B core unchanged:", sb.core == pre_b.core)
        say(transport, "B local diff vs before:", json.dumps(diff_leaves(pre_b.local, sb.local))[:2500])
        say(transport, "B table:", b.ssh(f"pfctl -t pfB_{alias}_v4 -T show 2>&1").stdout)
        say(transport, "B filter reloads:", b.ssh("pgrep -fl 'rc[.]filter_configure' || true").stdout)
        say(transport, "B banners:", h.count_log_marker(b, h.PFB_LOG, "UPDATE PROCESS START"))
        say(
            transport,
            "B in-flight / A log tail:",
            a.ssh("grep -i -E 'xmlrpc|hasync|filter_synchronize' /var/log/system.log | tail -8").stdout,
        )

    step("auto", lambda: one("automatic", "pfbha_x3a", "198.51.100.61"))
    step("manual", lambda: one("manual", "pfbha_x3m", "198.51.100.62"))

    def repeat() -> None:
        sync = sync_once(pair, "manual")
        say("manual repeat send:", json.dumps(sync.send))
        say("manual repeat receive:", json.dumps(sync.receive), "passes:", sync.passes)

    step("manual repeat", repeat)

    def auto_repeat() -> None:
        configure_sender(pair, "automatic")
        sync = sync_once(pair, "automatic")
        say("auto repeat send:", json.dumps(sync.send))
        say("auto repeat receive:", json.dumps(sync.receive), "passes:", sync.passes)

    step("auto repeat", auto_repeat)

    def retry_after_timeout() -> None:
        """nginx stopped on B, short timeout; continue it as soon as A's client logged a retry."""
        import threading

        configure_sender(pair, "manual", timeout=5)
        php_write(
            a,
            "config_set_path('installedpackages/pfblockernglistsv4/config/0/action', 'Deny_Both');",
            "x3 policy change",
        )
        marker = "Retrying XMLRPC Request due to error"
        before = h.count_log_marker(a, "/var/log/system.log", marker)
        say("retry log marker count before:", before)
        b.ssh("pkill -STOP nginx; echo stopped")
        outcome: dict[str, object] = {}

        def run() -> None:
            try:
                h.reload(a, "update", wait_unbound=False, timeout=400)
                outcome["ok"] = True
            except Exception as exc:  # noqa: BLE001
                outcome["err"] = repr(exc)

        th = threading.Thread(target=run)
        t = time.monotonic()
        th.start()
        seen = before
        while time.monotonic() - t < 200 and seen == before:
            time.sleep(2)
            seen = h.count_log_marker(a, "/var/log/system.log", marker)
        say("retry marker seen:", seen, f"after {time.monotonic() - t:.1f}s")
        say("A log retry lines:", a.ssh(f"grep '{marker}' /var/log/system.log | tail -3").stdout)
        say("B last while stopped:", json.dumps(receive_state(b).get("last")))
        say("cont:", b.ssh("pkill -CONT nginx; echo rc=$?").stdout.strip())
        th.join(300)
        say(f"A pass done after {time.monotonic() - t:.1f}s", outcome)
        say("A send record:", json.dumps(send_state(a)))
        say("B record:", json.dumps(receive_state(b)))
        say("B banners:", h.count_log_marker(b, h.PFB_LOG, "UPDATE PROCESS START"))
        settle(b)
        say("B banners after settle:", h.count_log_marker(b, h.PFB_LOG, "UPDATE PROCESS START"))
        sync = sync_once(pair, "manual")
        say("resend receive:", json.dumps(sync.receive), "passes:", sync.passes)

    step("retry after timeout", retry_after_timeout)
    pytest.fail("EXPLORATION X3 REPORT\n" + "\n".join(report))


@pytest.mark.timeout(1700)  # exploration
def test_x1_baseline(ha_pair: HaPair) -> None:
    """The arrange_baseline sequence, instrumented on both nodes."""
    pair = ha_pair
    a, b = pair.primary, pair.secondary
    report, say, step = _reporter()
    gateway = gateway_name(a)

    def logs(vm: SmokeVM, pat: str, n: int = 25) -> str:
        return vm.ssh(f"grep -i -E {pat!r} /var/log/system.log | tail -{n}").stdout

    for tag, vm in (("A", a), ("B", b)):
        h.inject_ip_lists(vm, [])
        h.ensure_dnsbl_vip(vm)
        for alias, addr in {**BASELINE_FEED_ADDR, **BASELINE_FEED_ADDR6}.items():
            write_feed(vm, alias, addr)
        seed_node(vm, tag, gateway)
    php_write(
        b,
        "$vips = config_get_path('virtualip/vip', array());\n"
        f"foreach ($vips as $i => $v) {{ if (($v['uniqid'] ?? '') === {h._php_str(h.SMOKE_VIP_UNIQID)}) {{ $vips[$i]['uniqid'] = {h._php_str(B_VIP_UNIQID)}; }} }}\n"
        "config_set_path('virtualip/vip', $vips);",
        "x1 B VIP uniqid",
    )
    say("seeded both; A digest/B digest:", node_state(a).digest[:12], node_state(b).digest[:12])
    for name, vm in (("A", a), ("B", b)):
        _unbound(say, vm, f"{name} after seed", wait=10)

    def a_reload() -> None:
        h.set_dnsbl_enabled(a, True)
        h.reload(a, "update", wait_unbound=False)
        _unbound(say, a, "A after reload", wait=100)
        _unbound(say, b, "B while A reloaded", wait=10)
        say("B system.log:", logs(b, "xmlrpc|filter|sync"))
        say("A system.log:", logs(a, "xmlrpc|filter_sync|sync"))
        settle(a)
        wait_filter_idle(a)
        _unbound(say, b, "B after A settled", wait=20)

    step("A enable + reload", a_reload)

    def b_reload() -> None:
        h.set_dnsbl_enabled(b, True)
        h.reload(b, "update", wait_unbound=False)
        _unbound(say, b, "B after reload", wait=140)
        _unbound(say, a, "A after B reload", wait=10)
        say("B system.log:", logs(b, "xmlrpc|filter|sync|unbound"))

    step("B enable + reload", b_reload)
    pytest.fail("EXPLORATION X1 REPORT\n" + "\n".join(report))
