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
* An ``interface:``, ``port:`` or ``include:`` line the admin adds to Custom Options after the move takes the pfB-DNS
  activation back like a failed one: pfB-DNS off, the Resolver restored, the admin's line kept, one notice naming it.
* A Resolver disabled in Services > DNS Resolver while pfB-DNS fronts it: the proxy kept LAN:53 and answered SERVFAIL
  for every allowed name. The next apply, or the next tick, stops pfB-DNS, restores the saved Resolver settings (the
  Resolver stays disabled), turns pfB-DNS off and raises one notice.
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
from collections.abc import Iterator
from typing import Self

import dns.message
import dns.rdatatype
import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer
from .test_smoke_dns_proxy import (
    CFG_MARKER,
    CFG_PROXY,
    MARKER,
    MARKER_END,
    Rig,
    State,
    _apply,
    _capture,
    _php_ok,
    _query,
    _service_status,
    _set_proxy_toggle,
    _toggle_on,
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
LAN_SIZE = 1432  # a 1500-byte LAN's pfSense-automatic size; the same box with lo0 as its only interface gives 16316
LOOPBACK_SIZE = 16316
RESOLVER_PAGE = "/services_unbound.php"
CLAUSE_SIZE_LINE = re.compile(r"^edns-buffer-size:\s*(\d+)\s*$", re.MULTILINE)
UNBOUND_SIZE_LINE = re.compile(r"^\s*edns-buffer-size:\s*(\d+)\s*$", re.MULTILINE)
# The keys the move changes (its snapshot) and the ones it leaves alone: all must be as before once it is undone.
RESTORED_KEYS = ("active_interface", "enablessl", "tlsport", "sslcertref")


class _UpstreamEdns:
    """Records the EDNS OPT UDP size of every query the stub upstream receives (its own log drops the OPT record)."""

    def __init__(self, stub: _StubDnsServer) -> None:
        self.stub = stub
        self.sizes: dict[str, int | None] = {}

    def __enter__(self) -> Self:
        original = self.stub._build_response
        sizes = self.sizes

        def record(data: bytes, client: str = "") -> bytes | None:
            with contextlib.suppress(Exception):  # the recorder must never break the stub's thread
                request = dns.message.from_wire(data)
                if request.question:
                    opt = [rr for rr in request.additional if rr.rdtype == dns.rdatatype.OPT]
                    sizes[request.question[0].name.to_text().lower().rstrip(".")] = int(opt[0].rdclass) if opt else None
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
        _apply(vm)
        assert _clause_size(vm) is None, (
            f"an admin directive leaves the clause without a line: {_clause(_custom_options(vm))!r}"
        )
        assert _advertised_size(rig, stub_dns) == 4096


# --------------------------------------------------------------------------- #
# An unsafe Custom Options line added after the move
# --------------------------------------------------------------------------- #


def test_an_unsafe_line_added_after_the_move_rolls_pfb_dns_back_and_keeps_the_line(rig: Rig, proxy_on: State) -> None:
    """Given a moved Resolver, When the admin adds `interface: 0.0.0.0@53` to Custom Options and the next apply runs,
    Then pfB-DNS is off, the proxy is stopped, the Resolver has its saved settings, the line is still in Custom
    Options, one notice names it, and Unbound (with the DNSBL module, as before) answers a listed name on 53.
    """
    vm = rig.vm
    line = "interface: 0.0.0.0@53"
    prior_notices = len(_notices(vm))
    with _unmoved_afterwards(rig):
        assert _snapshot_present(vm) and _toggle_on_in_config(vm), "before: pfB-DNS is on and the Resolver is moved"
        _put_custom_options(vm, f"{_custom_options(vm)}\nserver:\n{line}\n")

        _apply(vm)

        after = _capture(vm)
        assert not _toggle_on_in_config(vm), "pfB-DNS is turned off"
        assert after.service == "stopped", f"the proxy is stopped: {after.service}"
        assert not _snapshot_present(vm), "the snapshot is consumed"
        for key in RESTORED_KEYS:
            assert after.resolver[key] == rig.before.resolver[key], (
                f"{key}: {after.resolver[key]!r} != {rig.before.resolver[key]!r}"
            )
        custom = _custom_options(vm)
        assert line in custom.splitlines(), f"the admin's line is kept in Custom Options:\n{custom}"
        assert MARKER not in custom, f"our block is gone:\n{custom}"
        new = _notices(vm)[prior_notices:]
        assert len(new) == 1 and line in new[0] and "kept" in new[0], f"one notice naming the line: {new}"
        answer, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(answer), f"Unbound answers the listed name with the VIP on 53 again: {raw}"


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


def _assert_stood_down(rig: Rig, prior_notices: int, how: str) -> None:
    vm = rig.vm
    assert not _toggle_on_in_config(vm), f"{how}: pfB-DNS is turned off"
    assert _service_status(vm) == "stopped", f"{how}: the proxy is stopped"
    assert not _snapshot_present(vm), f"{how}: the snapshot is consumed"
    for key in RESTORED_KEYS:
        assert _config_text(vm, f"unbound/{key}") == rig.before.resolver[key], f"{how}: {key} is not as saved"
    assert not _resolver_enabled(vm), f"{how}: the Resolver stays disabled"
    assert vm.ssh("pgrep -x unbound").returncode != 0, f"{how}: nothing started the Resolver the admin disabled"
    new = _notices(vm)[prior_notices:]
    assert len(new) == 1 and "disabled" in new[0], f"{how}: exactly one notice says so: {new}"


@pytest.mark.parametrize("how", ["apply", "tick"])
def test_a_resolver_disabled_under_pfb_dns_is_stood_down_by_the_next_apply_or_tick(
    rig: Rig, proxy_on: State, how: str
) -> None:
    """Given pfB-DNS serving and the Resolver then disabled (the proxy keeps LAN:53 and cannot answer an allowed name),
    When the next apply or tick runs, Then pfB-DNS is stopped and off, the Resolver has its saved settings and stays
    disabled, one notice says why, and a second run raises no second notice.
    """
    vm = rig.vm
    scope = "updatednsbl" if how == "apply" else "tick"
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

        h.reload(vm, scope, wait_unbound=False)
        _assert_stood_down(rig, prior_notices, how)

        h.reload(vm, scope, wait_unbound=False)
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
