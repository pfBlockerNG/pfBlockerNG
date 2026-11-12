"""Issue #3515: pfB-DNS and the state of the DNS Resolver it moved, proven live.

pfB-DNS moves the DNS Resolver onto loopback (config.xml: ``active_interface`` lo0, DoT dropped, a marked ``server:``
clause appended to Custom Options, the previous values kept in the snapshot ``dns/pfb_dns_saved``). What the move does
to a Resolver must stay right while it is moved. Each case is driven the way an operator drives it: the real apply
(``pfb_trigger scope=dnsbl``), the real tick (``pfblockerng.php tick``) and, for the Resolver page, its own save
handler (services_unbound.php over HTTP). Nothing is faked on the box.

* Automatic EDNS size: pfSense advertises the smallest MTU of the Resolver's Network Interfaces minus 68; on lo0 that
  is 16316, where the LAN gave 1432. The marked clause carries pfSense's own value for the SAVED interfaces, read on
  the wire at the stub upstream (the OPT UDP size of the query Unbound sends), and carries none when the Advanced page
  sets a size or the admin's Custom Options do.
* An ``interface:``, ``port:`` or ``include:`` line the admin adds to Custom Options after the move changes nothing
  but the saved copy (the admin's line is kept in it for a later restore): pfB-DNS stays on and keeps serving, the
  Resolver stays moved, one notice names the line.
* Another process on Unbound's loopback port (127.0.0.1:5353, tcp and udp) while pfB-DNS is turned on: Unbound's backend
  pair moves to a free one (the marked clause), the live Unbound owns it, the gateway forwards to it, the
  holder is named in a notice, nothing is restored and a following Update keeps the pair (issue #3848).
* The same holder with no free pair left (a port of every pair the free-pair search scans is taken too) while pfB-DNS
  serves: pfB-DNS cannot serve and says so, and never gives the Resolver back. The gateway is stopped, the snapshot and
  every Resolver key stay as they were, port 53 answers nothing, the Service line says no free loopback port pair is
  left and the newest notice names the holder; when one pair frees up the next tick moves Unbound there and serves
  again (issue #3848).
* A Resolver disabled in Services > DNS Resolver while pfB-DNS fronts it: the proxy kept LAN:53 and answered SERVFAIL
  for every allowed name. A disabled Resolver is not the admin turning pfB-DNS off: the next apply, or the next tick,
  restores nothing and raises one notice that says pfB-DNS has no backend until the Resolver is enabled or pfB-DNS is
  turned off.
* The Resolver page's own save keeps pfBlockerNG's marked block (the textarea is filled from the stored Custom Options
  and posted back), so an admin who saves the page without touching Custom Options does not unmove the Resolver.

The module reuses the rig of ``test_smoke_dns_proxy`` (deploy, stub upstream, a DNSBL feed, a LAN client). Every test
ends with the box unmoved, pfB-DNS off, the Resolver enabled and the Resolver keys it changed back.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    scripts/local-smoke.sh --ref <pushed ref> --filter test_smoke_pfb_dns_resolver_state
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Self

import dns.message
import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer
from .test_smoke_dns_proxy import (
    CFG_MARKER,
    CFG_PROXY,
    DAEMON_PID_FILE,
    MARKER,
    MARKER_END,
    OCCUPANTS,
    PROXY_PID_FILE,
    PROXY_RC,
    RESOLVER_KEYS,
    Rig,
    State,
    _apply,
    _capture,
    _diagnostics,
    _dns_status,
    _listeners,
    _occupy,
    _php_cli,
    _php_ok,
    _pid_file,
    _query,
    _release,
    _service_status,
    _set_proxy_toggle,
    _sh,
    _toggle_on,
    _wait_proxy_serves,
    proxy_on,  # noqa: F401 -- a fixture of the rig module, requested by name below
    rig,  # noqa: F401 -- the module's fixture
)
from .ui.credgate import admin_password_decision
from .ui.webui import WebUI, scrape_form_fields

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(900)]

CFG_EDNS = "unbound/edns_buffer_size"
CFG_CUSTOM = "unbound/custom_options"
CFG_RESOLVER_ENABLE = "unbound/enable"
NOTICE_ID = "pfBlockerNG DNS Proxy"
NO_PAIR_STATUS = "Not serving: no free loopback port pair for the Resolver backend"
NOT_SERVED = "DNS is not served on port 53 until a loopback port pair is free or pfB-DNS is turned off"
# the PROXYv2 port of Unbound's loopback pair: the marked clause's own line is its only stored source
CLAUSE_BACKEND_PORT = re.compile(r"^proxy-protocol-port:\s*(\d+)\s*$", re.MULTILINE)
LAN_SIZE = 1432  # a 1500-byte LAN's pfSense-automatic size; the same box with lo0 as its only interface gives 16316
LOOPBACK_SIZE = 16316
RESOLVER_PAGE = "/services_unbound.php"
CLAUSE_SIZE_LINE = re.compile(r"^edns-buffer-size:\s*(\d+)\s*$", re.MULTILINE)
UNBOUND_SIZE_LINE = re.compile(r"^\s*edns-buffer-size:\s*(\d+)\s*$", re.MULTILINE)
# The keys the move changes (its snapshot) and the ones it leaves alone: all must be as before once it is undone.
RESTORED_KEYS = ("active_interface", "enablessl", "tlsport", "sslcertref")


class _UpstreamEdns:
    """Records the EDNS buffer size of every query the stub upstream receives (its own log drops the OPT record).

    dnspython moves a query's OPT record out of ``additional`` into ``message.edns`` and ``message.payload``, so the
    size is read from ``payload`` (``edns`` is -1 when the query carried no OPT record).
    """

    def __init__(self, stub: _StubDnsServer) -> None:
        self.stub = stub
        self.sizes: dict[str, int | None] = {}
        self.errors: list[str] = []

    def __enter__(self) -> Self:
        original = self.stub._build_response
        sizes = self.sizes
        errors = self.errors

        def record(data: bytes, client: str = "") -> bytes | None:
            try:
                request = dns.message.from_wire(data)
                if request.question:
                    key = request.question[0].name.to_text().lower().rstrip(".")
                    sizes[key] = request.payload if request.edns >= 0 else None
            except Exception as exc:  # noqa: BLE001 -- the recorder keeps the failure for the test, never breaks the stub
                errors.append(repr(exc))
            return original(data, client)

        self.stub._build_response = record  # type: ignore[method-assign]  # shadows the bound method on the instance
        return self

    def __exit__(self, *exc: object) -> None:
        self.stub.__dict__.pop("_build_response", None)


def _advertised_size(rig: Rig, stub: _StubDnsServer) -> int | None:
    """The EDNS buffer Unbound advertises to its upstream, read on the wire for a name nobody asked before."""
    name = h.unique_domain("edns")
    with _UpstreamEdns(stub) as seen:
        answer, raw = _query(rig.client, name)
    assert h.resolves_to(answer, STUB_DNS_A), f"the stub's answer did not come back through the Resolver: {raw}"
    assert not seen.errors, f"the recorder failed on a query: {seen.errors}"
    print(f"[3515] upstream saw {seen.sizes}", flush=True)
    return seen.sizes.get(name)


def _custom_options(vm: SmokeVM) -> str:
    present, value = h.config_get_state(vm, CFG_CUSTOM)
    return base64.b64decode(value).decode() if present and value else ""


def _put_custom_options(vm: SmokeVM, text: str) -> None:
    encoded = base64.b64encode(text.encode()).decode()
    _php_ok(
        vm,
        f"config_set_path({h._php_str(CFG_CUSTOM)}, {h._php_str(encoded)});\n"
        "write_config('pfBlockerNG smoke: Custom Options for the #3515 Resolver state smoke');",
        "Custom Options",
    )


def _clause(text: str) -> str:
    """Our marked clause, from its marker to its end marker ('' when absent)."""
    start = text.find(MARKER)
    end = text.find(MARKER_END)
    return text[start : end + len(MARKER_END)] if start != -1 and end != -1 else ""


def _backend_port(vm: SmokeVM) -> int | None:
    """The PROXYv2 port the clause in Custom Options names (None: no clause)."""
    match = CLAUSE_BACKEND_PORT.search(_clause(_custom_options(vm)))
    return int(match.group(1)) if match else None


def _clause_size(vm: SmokeVM) -> int | None:
    match = CLAUSE_SIZE_LINE.search(_clause(_custom_options(vm)))
    return int(match.group(1)) if match else None


def _unbound_conf_sizes(vm: SmokeVM) -> list[int]:
    return [int(v) for v in UNBOUND_SIZE_LINE.findall(vm.ssh("cat", h.UNBOUND_CONF).stdout)]


def _notices(vm: SmokeVM) -> list[str]:
    """The texts of the DNS proxy notices on the box, oldest first."""
    out = h.php_eval(
        vm,
        "require_once('notices.inc');\n"
        "$all = get_notices();\n"
        "$texts = array();\n"
        "if (is_array($all)) { ksort($all); foreach ($all as $n) {\n"
        f"  if (html_entity_decode($n['id'] ?? '') === {h._php_str(NOTICE_ID)}) "
        "{ $texts[] = html_entity_decode($n['notice'] ?? ''); }\n"
        "} }\n"
        "echo '<<<N>>>' . json_encode($texts) . '<<<E>>>';",
    )
    match = re.search(r"<<<N>>>(.*?)<<<E>>>", out.stdout, re.DOTALL)
    if out.returncode != 0 or match is None:
        raise RuntimeError(f"reading notices failed: rc={out.returncode}\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    texts: list[str] = json.loads(match.group(1))
    return texts


_NOTICE_CLEAR_LIMIT = 20


@pytest.fixture
def _clear_dns_proxy_notices(rig: Rig) -> None:
    """Disabled-Resolver and unsafe-line cases start with no NOTICE_ID row. pfb_dns_proxy_notify() files nothing while
    the newest row with the same id already says the same text, and an earlier case's row stands on the shared VM.
    Only NOTICE_ID rows go."""
    vm = rig.vm
    removed = 0
    while _notices(vm):
        assert removed < _NOTICE_CLEAR_LIMIT, f"notices with id {NOTICE_ID!r} survive {removed} close_notice calls"
        res = h.php_eval(vm, f"require_once('notices.inc');\nclose_notice({h._php_str(NOTICE_ID)});\necho 'OK';")
        assert res.returncode == 0 and "OK" in res.stdout, (
            f"close_notice failed: rc={res.returncode} stdout={res.stdout!r} stderr={res.stderr!r}"
        )
        removed += 1
    print(f"[3515] notice case starts with {removed} {NOTICE_ID!r} notice(s) closed", flush=True)


def _toggle_on_in_config(vm: SmokeVM) -> bool:
    """The requested pfB-DNS toggle as config.xml holds it."""
    present, value = h.config_get_state(vm, CFG_PROXY)
    return present and value == "on"


def _snapshot_present(vm: SmokeVM) -> bool:
    present, value = h.config_get_state(vm, CFG_MARKER)
    return present and bool(value)


def _resolver_enabled(vm: SmokeVM) -> bool:
    return h.config_get_state(vm, CFG_RESOLVER_ENABLE)[0]


def _config_text(vm: SmokeVM, path: str) -> str | None:
    """The element's text as config.xml holds it, None when the element is absent (State.resolver's convention)."""
    present, value = h.config_get_state(vm, path)
    return value if present else None


def _moved(rig: Rig) -> State:
    state = _capture(rig.vm)
    assert state.resolver["active_interface"] == "lo0" and state.service == "running", (
        f"before: the Resolver is not moved and served: {state.resolver} {state.service}"
    )
    return state


@contextlib.contextmanager
def _unmoved_afterwards(rig: Rig) -> Iterator[None]:
    """However the test ends: Resolver enabled, pfB-DNS off and applied (an ordinary restore if it is still moved),
    then the Advanced size and Custom Options as the rig left them (Custom Options as they were before the move)."""
    vm = rig.vm
    edns = h.config_get_state(vm, CFG_EDNS)
    try:
        yield
    finally:
        _php_ok(
            vm,
            f"config_set_path({h._php_str(CFG_RESOLVER_ENABLE)}, '');\n"
            "write_config('pfBlockerNG smoke: Resolver enabled again');",
            "Resolver enabled",
        )
        _set_proxy_toggle(vm, False)
        _apply(vm)
        h.config_restore_state(vm, CFG_EDNS, edns)
        original = rig.before.resolver["custom_options"]
        h.config_restore_state(vm, CFG_CUSTOM, (original is not None, original or ""))
        _php_ok(vm, "services_unbound_configure();", "regenerate Unbound")
        h.wait_unbound_ready(vm)


# --------------------------------------------------------------------------- #
# Automatic EDNS size
# --------------------------------------------------------------------------- #


def test_a_moved_resolver_advertises_the_size_it_advertised_before_the_move(rig: Rig, stub_dns: _StubDnsServer) -> None:
    """Given a LAN Resolver whose automatic size is the LAN's, When pfB-DNS moves it onto lo0,
    Then the size Unbound advertises upstream is still the LAN's (not the loopback MTU's) and the clause carries it.
    """
    vm = rig.vm
    with _unmoved_afterwards(rig):
        _php_ok(
            vm,
            f"config_del_path({h._php_str(CFG_EDNS)});\nwrite_config('pfBlockerNG smoke: EDNS automatic');",
            "automatic size",
        )
        _set_proxy_toggle(vm, False)
        _apply(vm)
        native = _advertised_size(rig, stub_dns)
        assert native == LAN_SIZE, f"before: the native automatic size on a 1500-byte LAN is {LAN_SIZE}, got {native}"

        _toggle_on(rig)
        _moved(rig)
        moved = _advertised_size(rig, stub_dns)

        assert moved == native, (
            f"the moved Resolver advertises {moved}, native advertised {native} (loopback gives {LOOPBACK_SIZE})"
        )
        assert _clause_size(vm) == native, f"the clause does not carry the size: {_clause(_custom_options(vm))!r}"
        assert _unbound_conf_sizes(vm)[-1] == native, (
            f"unbound.conf's last size line is not {native}: {_unbound_conf_sizes(vm)}"
        )


def test_an_explicit_size_and_an_admin_directive_keep_winning_while_moved(rig: Rig, stub_dns: _StubDnsServer) -> None:
    """Given a moved Resolver, When the Advanced page sets 1232, then the admin's Custom Options set 4096,
    Then each is what Unbound advertises, and the clause carries no size line of its own.
    """
    vm = rig.vm
    with _unmoved_afterwards(rig):
        _php_ok(
            vm,
            f"config_del_path({h._php_str(CFG_EDNS)});\nwrite_config('pfBlockerNG smoke: EDNS automatic');",
            "automatic size",
        )
        _toggle_on(rig)
        assert _clause_size(vm) == LAN_SIZE, "before: the automatic clause carries the LAN size"

        _php_ok(
            vm,
            f"config_set_path({h._php_str(CFG_EDNS)}, '1232');\nwrite_config('pfBlockerNG smoke: EDNS explicit 1232');",
            "explicit size",
        )
        _apply(vm)
        assert _clause_size(vm) is None, (
            f"an explicit size leaves the clause without a line: {_clause(_custom_options(vm))!r}"
        )
        assert _advertised_size(rig, stub_dns) == 1232

        _php_ok(
            vm,
            f"config_del_path({h._php_str(CFG_EDNS)});\nwrite_config('pfBlockerNG smoke: EDNS automatic');",
            "automatic size",
        )
        _put_custom_options(vm, f"server:\nedns-buffer-size: 4096\n{_custom_options(vm)}")
        # the Resolver page's Apply regenerates unbound.conf; the pfB apply below only does when it rewrites the clause
        _php_ok(vm, "services_unbound_configure();", "the Resolver page's Apply")
        h.wait_unbound_ready(vm)
        _apply(vm)
        assert _clause_size(vm) is None, (
            f"an admin directive leaves the clause without a line: {_clause(_custom_options(vm))!r}"
        )
        assert _advertised_size(rig, stub_dns) == 4096


# --------------------------------------------------------------------------- #
# Another process on Unbound's loopback port during activation
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("_clear_dns_proxy_notices")
def test_a_foreign_listener_on_unbounds_port_moves_its_backend_pair_and_pfb_dns_serves(rig: Rig) -> None:
    """Given working native Resolver DNS (pfB-DNS off, so no DNSBL: a listed name is answered by the upstream) and both
    transports of 127.0.0.1:5353 held by another process before enabling pfB-DNS,
    When the real toggle and apply run, Then pfB-DNS serves with Unbound's backend moved to a free pair (#3848): the
    stored port is not 5353, the live Unbound owns TCP and UDP on it, the gateway's --upstream names it, through pfB-DNS
    on port 53 over UDP and TCP DNSBL blocks a listed name and an allowed name resolves, one notice names the holder,
    nothing was restored, the holder still holds 5353, and a following Update keeps the pair.
    """
    vm = rig.vm
    held = {("tcp4", "127.0.0.1:5353"), ("udp4", "127.0.0.1:5353")}
    with _unmoved_afterwards(rig):
        _set_proxy_toggle(vm, False)
        _apply(vm)
        before = _capture(vm)
        assert not _toggle_on_in_config(vm) and not _snapshot_present(vm), (
            f"before: pfB-DNS must be off with no saved move: {before}"
        )
        assert before.service == "stopped" and not before.ps, (
            f"before: the proxy must be stopped: {before.service} {before.ps}"
        )
        assert before.unbound_dns(), f"before: native Unbound has no DNS listeners: {before.listeners}"
        prior_notices = len(_notices(vm))

        try:
            _occupy(vm, ["127.0.0.1"], "5353")
            _set_proxy_toggle(vm, True)
            try:
                h.reload(vm, "updatednsbl")
            finally:
                print(f"[3848] activation with 5353 held:\n{_diagnostics(vm)}", flush=True)
                print(
                    vm.ssh(f"tail -n 80 {h.PFB_LOGDIR}/error.log /var/log/resolver.log 2>&1").stdout,
                    flush=True,
                )

            after = _capture(vm)
            assert _toggle_on_in_config(vm) and _snapshot_present(vm), f"pfB-DNS stays on, the Resolver moved: {after}"
            assert after.resolver["active_interface"] == "lo0", f"the Resolver is moved: {after.resolver}"
            assert after.service == "running", f"the proxy serves: {after.service} {after.ps}"

            # Unbound's pair moved: stored, owned by the live Unbound on TCP and UDP, named by the rc script
            port = _backend_port(vm)
            assert port is not None and port != 5353, f"the clause's pair must have moved off 5353: {port!r}"
            ours = {
                (s.proto, s.local)
                for s in _listeners(vm)
                if s.command == "unbound" and s.pid == after.unbound_pid and s.port == port
            }
            assert {("tcp4", f"127.0.0.1:{port}"), ("udp4", f"127.0.0.1:{port}")} <= ours, (
                f"Unbound's pid {after.unbound_pid} must own TCP and UDP on 127.0.0.1:{port}: {sorted(ours)}"
            )
            rc = vm.ssh("cat", PROXY_RC).stdout
            assert f"--upstream '127.0.0.1:{port}'" in rc, f"the rc script's --upstream must name {port}:\n{rc}"
            assert any(local.endswith(":53") for _, local in after.proxy_sockets()), (
                f"the gateway serves port 53: {sorted(after.proxy_sockets())}"
            )

            # the holder is left alone and named
            holders = {
                (s.proto, s.local) for s in _listeners(vm, connected=True) if s.port == 5353 and s.command == "nc"
            }
            assert held <= holders, f"the other process must still hold 5353: {sorted(holders)}"
            new = _notices(vm)[prior_notices:]
            assert any(
                "nc (pid " in text
                and "on 127.0.0.1:5353" in text
                and f"moved from ports 5353/5354 to {port}/{port + 1}" in text
                for text in new
            ), f"a notice must name the holder and the move: {new}"
            assert not any("restored" in text.lower() for text in new), f"nothing is given back: {new}"

            # pfB-DNS serves port 53 through the moved pair: DNSBL blocks the listed name, the allowed one resolves
            for tcp in (False, True):
                blocked, raw = _query(rig.client, rig.names.blocked, tcp=tcp)
                assert h.is_vip(blocked), (
                    f"the listed name must be blocked by pfB-DNS with the DNSBL VIP (tcp={tcp}): {raw}"
                )
                allowed, raw = _query(rig.client, h.unique_domain("upstream-moved"), tcp=tcp)
                assert h.resolves_to(allowed, STUB_DNS_A), f"an allowed name must resolve (tcp={tcp}): {raw}"

            # a following Update keeps the pair, and the answers
            h.reload(vm, "updatednsbl")
            assert _backend_port(vm) == port, "a following Update keeps the new port"
            again = _capture(vm)
            assert again.service == "running" and _snapshot_present(vm), f"still moved and serving: {again.service}"
            allowed, raw = _query(rig.client, h.unique_domain("upstream-kept"), tcp=False)
            assert h.resolves_to(allowed, STUB_DNS_A), f"DNS still resolves after the Update: {raw}"
        finally:
            _release(vm)


def _stop_unbound(vm: SmokeVM, port: int) -> None:
    """Unbound exits, as it does when it dies or restarts, and its loopback pair is free for another process to take
    (a process cannot bind next to a live Unbound)."""
    killed = vm.ssh(f"kill {h.unbound_pid(vm)}")
    assert killed.returncode == 0, f"kill unbound failed: {killed.stdout!r} {killed.stderr!r}"
    h.wait_until(
        lambda: not [s for s in _listeners(vm) if s.command == "unbound" and s.port in (port, port + 1)],
        timeout=30.0,
        interval=1.0,
    )


def _backend_search(vm: SmokeVM) -> int:
    """PFB_DNS_PROXY_BACKEND_SEARCH as the installed package has it: how many pairs above Unbound's the search scans."""
    out = _php_cli(vm, "echo '<<<N>>>' . PFB_DNS_PROXY_BACKEND_SEARCH . '<<<E>>>';", "PFB_DNS_PROXY_BACKEND_SEARCH")
    found = re.search(r"<<<N>>>(\d+)<<<E>>>", out)
    assert found is not None, f"PFB_DNS_PROXY_BACKEND_SEARCH printed no number: {out!r}"
    return int(found.group(1))


def _hold_a_port_of_every_pair_above(vm: SmokeVM, port: int) -> tuple[int, list[int]]:
    """Hold 127.0.0.1:<p> with an nc(1) TCP listener on every second port of what pfb_dns_proxy_backend_pick() scans
    (the pairs P' from port+2 on, PFB_DNS_PROXY_BACKEND_SEARCH of them): each pair (P', P'+1) then has a port in use and
    none is free. Their pidfiles sit beside _occupy's, which must have run: _release ends them.

    :returns: the lowest candidate pair's P' (its P'+1 is held too; the caller frees that pair) and the ports held.
    """
    first = port + 2
    last = min(first + _backend_search(vm) - 1, 65534)
    held = list(range(first + 1, last + 2, 2))
    in_use = {s.port for s in _listeners(vm)}
    assert in_use.isdisjoint({first, first + 1}), (
        f"before: the lowest candidate pair {first}/{first + 1} must be free: {sorted(p for p in in_use if p)}"
    )
    lines = [
        f"/usr/sbin/daemon -f -p {OCCUPANTS}/fill-{p}.pid /usr/bin/nc -4 -l 127.0.0.1 {p} </dev/null >/dev/null 2>&1"
        for p in held
    ]
    started = _sh(vm, "\n".join(lines) + "\n")
    assert started.returncode == 0, f"starting the listeners failed: {started.stdout!r} {started.stderr!r}"
    h.wait_until(lambda: set(held) <= {s.port for s in _listeners(vm)}, timeout=60.0, interval=1.0)
    return first, held


def _stop_holding(vm: SmokeVM, port: int) -> None:
    """End the listener _hold_a_port_of_every_pair_above() started on `port`, until the port shows free."""
    stopped = _sh(vm, f"kill $(cat {OCCUPANTS}/fill-{port}.pid) && rm -f {OCCUPANTS}/fill-{port}.pid")
    assert stopped.returncode == 0, f"stopping the listener on {port} failed: {stopped.stdout!r} {stopped.stderr!r}"
    h.wait_until(lambda: port not in {s.port for s in _listeners(vm)}, timeout=30.0, interval=1.0)


@pytest.mark.timeout(1500)
@pytest.mark.usefixtures("proxy_on", "_clear_dns_proxy_notices")
def test_every_free_pair_taken_stops_pfb_dns_without_restoring_the_resolver_and_a_freed_pair_serves_again(
    rig: Rig,
) -> None:
    """Given pfB-DNS serving (a listed name is blocked with the DNSBL VIP) and another process holding both transports
    of 127.0.0.1:P, Unbound's loopback port (P is the marked clause's), and a port of every pair the free-pair search
    scans,
    When an Update runs,
    Then pfB-DNS cannot serve and says so (#3848): the gateway is stopped, nothing restores the Resolver (the snapshot
    and every Resolver key are as they were, pfB-DNS is still on), port 53 answers nothing, the Service line says no
    free loopback port pair is left, and the newest notice names the holder and that DNS is not served until a
    loopback port pair is free or pfB-DNS is turned off;
    and when one pair frees up the next tick moves Unbound to it, starts the gateway, blocks the listed name again and
    resolves an allowed one while the holder still holds P.

    Unbound is stopped before the holders bind, as when something else takes its port while it is down: nothing can
    bind next to a live Unbound. Unbound's own state is not read while it cannot bind.
    """
    vm = rig.vm
    with _unmoved_afterwards(rig):
        before = _moved(rig)
        port = _backend_port(vm)
        assert port is not None, f"before: the clause names no backend port: {before.resolver}"
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"before: pfB-DNS must block the listed name with the DNSBL VIP: {raw}"
        prior_notices = len(_notices(vm))

        try:
            _stop_unbound(vm, port)
            _occupy(vm, ["127.0.0.1"], str(port))
            holders = {s.pid for s in _listeners(vm, connected=True) if s.command == "nc" and s.port == port}
            lowest, held = _hold_a_port_of_every_pair_above(vm, port)
            try:
                # Returns before Unbound is awaited: with the pair held it cannot start, and nothing here needs it
                h.reload(vm, "updatednsbl", wait_unbound=False)
            finally:
                tail = f"tail -n 80 {h.PFB_LOGDIR}/error.log {h.PFB_DNS_PROXY_LOG} /var/log/resolver.log 2>&1"
                print(
                    f"[3848] update with every free pair taken ({len(held)} ports held):\n{vm.ssh(tail).stdout}",
                    flush=True,
                )

            # the gateway is stopped and the Resolver is kept as it was
            ps = vm.ssh("ps -axww -o pid,user,args | grep -E 'pfb_dns_prox[y]|/pfb-dn[s]'").stdout.splitlines()
            assert ps == [] and _service_status(vm) == "stopped", f"the gateway must be stopped: {ps}"
            assert _pid_file(vm, PROXY_PID_FILE) is None and _pid_file(vm, DAEMON_PID_FILE) is None, (
                "the gateway's pidfiles are gone"
            )
            assert _toggle_on_in_config(vm), "pfB-DNS stays on"
            assert {key: _config_text(vm, f"unbound/{key}") for key in RESOLVER_KEYS} == before.resolver, (
                "every Resolver key is as it was: nothing was restored or moved"
            )
            assert (_config_text(vm, CFG_MARKER) or "") == before.marker, "the snapshot is kept byte for byte"

            # port 53 answers nothing (the Update is over), and the status and the notice say why
            answer, raw = _query(rig.client, rig.names.blocked)
            assert answer.rcode == "UNKNOWN" and not answer.records, f"nothing may answer on port 53: {raw}"
            assert not [s for s in _listeners(vm) if s.port == 53], "nothing listens on port 53"
            assert _dns_status(vm)["service"] == NO_PAIR_STATUS, f"the Service line: {_dns_status(vm)['service']!r}"
            new = _notices(vm)[prior_notices:]
            assert new, "a notice must say DNS is not served"
            assert any(f"nc (pid {pid}) on 127.0.0.1:{port}" in new[-1] for pid in holders), (
                f"the newest notice must name nc and its pid {sorted(holders)}: {new[-1]}"
            )
            assert f"no free loopback port pair above {port}" in new[-1], f"it says no pair is left: {new[-1]}"
            assert NOT_SERVED in new[-1], f"it says what to do: {new[-1]}"
            assert not any("restored" in text.lower() for text in new), f"nothing is given back: {new}"

            # a pair frees up: the next tick moves Unbound there and pfB-DNS serves again, the holder still on P
            _stop_holding(vm, lowest + 1)
            h.reload(vm, "tick", wait_unbound=False)
            h.wait_until(lambda: _backend_port(vm) == lowest, timeout=120.0, interval=3.0)
            h.wait_until(lambda: _service_status(vm) == "running", timeout=120.0, interval=3.0)
            h.wait_unbound_ready(vm)
            _wait_proxy_serves(rig)
            blocked, raw = _query(rig.client, rig.names.blocked)
            assert h.is_vip(blocked), f"the listed name must be blocked again with the DNSBL VIP: {raw}"
            allowed, raw = _query(rig.client, h.unique_domain("pair-freed"))
            assert h.resolves_to(allowed, STUB_DNS_A), f"an allowed name must resolve: {raw}"
            assert _dns_status(vm)["service"] == "Running", f"the Service line: {_dns_status(vm)['service']!r}"
            still = {s.pid for s in _listeners(vm, connected=True) if s.command == "nc" and s.port == port}
            assert holders & still, f"the other process must still hold {port}: {sorted(still)}"
            new = _notices(vm)[prior_notices:]
            assert f"moved from ports {port}/{port + 1} to {lowest}/{lowest + 1}" in new[-1], (
                f"the newest notice must name the move: {new[-1]}"
            )
            assert not any("restored" in text.lower() for text in new), f"nothing is given back: {new}"
        finally:
            _release(vm)


# --------------------------------------------------------------------------- #
# An unsafe Custom Options line added after the move
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("_clear_dns_proxy_notices")
def test_an_unsafe_line_added_after_the_move_keeps_pfb_dns_serving_and_names_the_line(
    rig: Rig, proxy_on: State
) -> None:
    """Given a moved Resolver, When the admin adds `interface: 0.0.0.0@53` to Custom Options and the next apply runs,
    Then pfB-DNS stays on and nothing is restored: the Resolver stays moved with the line in Custom Options, the saved
    copy keeps the line for a restore the admin asks for later, the proxy keeps running, and one notice names the line
    and says pfB-DNS keeps serving (issue #3848). Unbound may not start with that line: the apply does not wait for it.
    """
    vm = rig.vm
    line = "interface: 0.0.0.0@53"
    prior_notices = len(_notices(vm))
    with _unmoved_afterwards(rig):
        assert _snapshot_present(vm) and _toggle_on_in_config(vm), "before: pfB-DNS is on and the Resolver is moved"
        _put_custom_options(vm, f"{_custom_options(vm)}\nserver:\n{line}\n")

        h.reload(vm, "updatednsbl", wait_unbound=False)

        after = _capture(vm)
        assert _toggle_on_in_config(vm), "pfB-DNS stays on"
        assert after.service == "running", f"the proxy keeps running: {after.service}"
        assert _snapshot_present(vm), "the snapshot stays: nothing is restored"
        assert after.resolver["active_interface"] == "lo0", f"the Resolver stays moved: {after.resolver}"
        custom = _custom_options(vm)
        assert line in custom.splitlines(), f"the admin's line stands in Custom Options:\n{custom}"
        assert MARKER in custom, f"our block stays:\n{custom}"
        saved = json.loads(base64.b64decode(after.marker, validate=True))
        kept = base64.b64decode(saved["custom_options"]["value"]).decode()
        assert line in kept.splitlines(), f"the saved copy keeps the line for a later restore:\n{kept}"
        new = _notices(vm)[prior_notices:]
        assert len(new) == 1 and line in new[0] and "keeps serving" in new[0], f"one notice naming the line: {new}"


# --------------------------------------------------------------------------- #
# A Resolver disabled underneath pfB-DNS
# --------------------------------------------------------------------------- #


def _disable_resolver_like_the_page(vm: SmokeVM) -> None:
    """Save the Resolver page with Enable cleared, then its Apply: the config key goes and Unbound is stopped."""
    _php_ok(
        vm,
        f"config_del_path({h._php_str(CFG_RESOLVER_ENABLE)});\n"
        "write_config('pfBlockerNG smoke: disable the Resolver under pfB-DNS');\n"
        "services_unbound_configure();",
        "disable the Resolver",
    )


@dataclass(frozen=True)
class _UnboundState:
    """Unbound as the box shows it at one moment, with how often pfBlockerNG's log says it started Unbound."""

    running: bool
    pids: str
    pidfile: str
    starts_logged: int


def _unbound_state(vm: SmokeVM, label: str) -> _UnboundState:
    pgrep = vm.ssh("pgrep -x unbound")
    pidfile = vm.ssh("cat", h.UNBOUND_PID_FILE)
    starts = vm.ssh(f"grep -c 'Starting Unbound Resolver' {h.PFB_LOG} 2>/dev/null; true").stdout.strip()
    state = _UnboundState(
        running=pgrep.returncode == 0,
        pids=pgrep.stdout.split()[0] if pgrep.returncode == 0 and pgrep.stdout.split() else "",
        pidfile=pidfile.stdout.strip() if pidfile.returncode == 0 else "",
        starts_logged=int(starts) if starts.isdigit() else -1,
    )
    print(f"[3515] unbound {label}: {state}", flush=True)
    return state


def _assert_kept_with_a_notice(rig: Rig, prior_notices: int, how: str, unbound: _UnboundState) -> None:
    vm = rig.vm
    assert _toggle_on_in_config(vm), f"{how}: pfB-DNS stays on"
    assert _service_status(vm) == "running", f"{how}: the proxy keeps running"
    assert _snapshot_present(vm), f"{how}: the snapshot stays: nothing is restored"
    assert _config_text(vm, "unbound/active_interface") == "lo0", f"{how}: the Resolver stays moved"
    assert not _resolver_enabled(vm), f"{how}: the Resolver stays disabled"
    assert not unbound.running, f"{how}: something started the Resolver the admin disabled: {unbound}"
    new = _notices(vm)[prior_notices:]
    assert len(new) == 1 and "disabled" in new[0] and "no backend" in new[0], (
        f"{how}: exactly one notice says the Resolver is disabled and pfB-DNS has no backend: {new}"
    )


def _say_the_resolver_is_disabled_on_its_own(vm: SmokeVM) -> None:
    """pfb_dns_proxy_backend_disabled_notice() alone, in a plain CLI php process as the package's own scripts load it"""
    code = (
        "require_once('config.inc'); require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc'); "
        "pfb_dns_proxy_backend_disabled_notice();"
    )
    result = vm.ssh(f"{h.PHP_BIN} -r {shlex.quote(code)} 2>&1", timeout=300.0)
    assert result.returncode == 0, (
        f"pfb_dns_proxy_backend_disabled_notice() failed: rc={result.returncode} {result.stdout[-1500:]}"
    )


_DISABLED_RESOLVER_TRIGGERS = {
    "apply": lambda vm: h.reload(vm, "updatednsbl", wait_unbound=False),
    "tick": lambda vm: h.reload(vm, "tick", wait_unbound=False),
    "direct": _say_the_resolver_is_disabled_on_its_own,
}


@pytest.mark.parametrize("how", list(_DISABLED_RESOLVER_TRIGGERS))
@pytest.mark.usefixtures("proxy_on", "_clear_dns_proxy_notices")
def test_a_resolver_disabled_under_pfb_dns_keeps_pfb_dns_and_says_so_on_the_next_apply_or_tick(
    rig: Rig, proxy_on: State, how: str
) -> None:
    """Given pfB-DNS serving and the Resolver then disabled (the proxy keeps LAN:53 and cannot answer an allowed name),
    When the next apply or tick runs (or the notice is raised on its own), Then pfB-DNS stays on and nothing is
    restored: the proxy keeps running, the Resolver stays moved and disabled with nothing started, one notice says the
    Resolver is disabled and pfB-DNS has no backend, and a second run raises no second notice (issue #3848).
    """
    vm = rig.vm
    trigger = _DISABLED_RESOLVER_TRIGGERS[how]
    prior_notices = len(_notices(vm))
    with _unmoved_afterwards(rig):
        _moved(rig)
        _disable_resolver_like_the_page(vm)
        outage, raw = _query(rig.client, h.unique_domain("allowed"))
        assert not h.resolves_to(outage, STUB_DNS_A), (
            f"before: an allowed name is answered although the Resolver is off: {raw}"
        )
        assert _toggle_on_in_config(vm) and _snapshot_present(vm), (
            "before: pfB-DNS is on and still holds the moved Resolver"
        )
        before = _unbound_state(vm, f"{how}: before the trigger")
        assert not before.running, f"before: the disable step left Unbound running: {before}"

        trigger(vm)
        after = _unbound_state(vm, f"{how}: after the trigger")
        _assert_kept_with_a_notice(rig, prior_notices, how, after)

        trigger(vm)
        assert len(_notices(vm)) == prior_notices + 1, f"{how}: a second run raised another notice"


# --------------------------------------------------------------------------- #
# The Resolver page's own save
# --------------------------------------------------------------------------- #


@pytest.fixture
def gui(rig: Rig) -> WebUI:
    """A logged-in webConfigurator session against the rig's box (the credentials the UI tier uses)."""
    action, password = admin_password_decision(os.environ)
    if action == "fail":
        pytest.fail(password)
    https = (h.config_get(rig.vm, "system/webgui/protocol").strip().lower() or "http") == "https"
    client = WebUI(
        host=rig.vm.host,
        port=rig.vm.web_port,
        username=os.environ.get("SMOKE_ADMIN_USER") or "admin",
        password=password,
        scheme="https" if https else "http",
        verify=not https,
    )
    client.login()
    return client


def test_the_resolver_pages_own_save_keeps_pfblockerngs_block_and_the_resolver_moved(
    rig: Rig, proxy_on: State, gui: WebUI
) -> None:
    """Given a moved Resolver, When the admin opens the Resolver page and saves it as a browser would (every field as
    rendered, the textarea with CRLF line ends) then applies, Then Custom Options still carry our block, the Resolver
    is still on lo0, and the proxy still answers a listed name (the page does not unmove or break the Resolver).
    """
    vm = rig.vm
    with _unmoved_afterwards(rig):
        before = _custom_options(vm)
        assert MARKER in before, "before: our block is in Custom Options"
        page = gui.get(RESOLVER_PAGE)
        assert page.status_code == 200
        fields = scrape_form_fields(page.text)
        assert MARKER in fields["custom_options"], "the page renders our block in the Custom Options textarea"

        saved = gui.post(RESOLVER_PAGE, {"custom_options": fields["custom_options"].replace("\n", "\r\n")})
        assert saved.status_code == 200
        assert gui.post(RESOLVER_PAGE, {}, submit=("apply", "Apply Changes")).status_code == 200
        h.wait_unbound_ready(vm)

        after = _custom_options(vm)
        assert _clause(after) == _clause(before), (
            f"our block changed through the page's save:\n{before}\n--- after ---\n{after}"
        )
        assert _moved_key(vm), "the Resolver is still on lo0"
        assert _snapshot_present(vm), "the snapshot is still there"
        h.wait_until(lambda: h.is_vip(_query(rig.client, rig.names.blocked)[0]), timeout=120.0, interval=3.0)


def _moved_key(vm: SmokeVM) -> bool:
    return h.config_get_state(vm, "unbound/active_interface") == (True, "lo0")
