"""The smoke harness turns pfB-DNS on wherever it turns DNSBL on, and gives the Resolver back afterwards.

Issue #3774 (map #3511): #3770 makes DNSBL run only through pfB-DNS, so a harness that enables DNSBL with pfB-DNS off
would stop blocking. These pins are pure (no VM): the harness writers are string builders and the shared state
transitions are driven through stubbed collaborators, so the contract is enforced on every PR rather than only when
the live smoke lane runs.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.smoke import helpers

PFB_DNS_PATH = "installedpackages/pfblockerngdns/config/0/pfb_dns"
SAVED_PATH = "installedpackages/pfblockerngdns/config/0/pfb_dns_saved"
PFB_DNS_ON = f"config_set_path('{PFB_DNS_PATH}', 'on');"
PFB_DNS_OFF = f"config_set_path('{PFB_DNS_PATH}', '');"
LOG_TAIL = "dns_proxy.log tail marker line"


class _Vm:
    """Records every guest command in the shared event list, in call order."""

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def ssh(self, *argv: str, **_kw: object) -> SimpleNamespace:
        self.events.append("ssh:" + " ".join(argv))
        return SimpleNamespace(returncode=0, stdout=LOG_TAIL, stderr="")


def _case(**kwargs: object) -> helpers.DnsblCase:
    return helpers.DnsblCase(
        aliasname="smoke3774",
        feed_url="http://127.0.0.1:1/feed.txt",
        header="smoke3774",
        mode=helpers.DnsblMode.NULL,
        **kwargs,  # type: ignore[arg-type]
    )


def _capture_php_eval(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    captured: list[str] = []

    def php_eval(_vm: object, snippet: str, **_kw: object) -> SimpleNamespace:
        captured.append(snippet)
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(helpers, "php_eval", php_eval)
    return captured


# --- R1: every DNSBL settings replace that turns DNSBL on turns pfB-DNS on in the same write -----------------


def test_dnsbl_settings_replace_that_turns_dnsbl_on_also_turns_pfb_dns_on() -> None:
    """Given DNSBL settings with pfb_dnsbl 'on' When the replace PHP is built
    Then it also stores pfB-DNS 'on', so DNSBL keeps blocking once it runs only through pfB-DNS (#3770)."""
    php = helpers._dnsbl_settings_replace_php({"pfb_dnsbl": "on", "pfb_idn": "on"})

    assert PFB_DNS_ON in php, f"pfb_dnsbl is on but pfB-DNS is not turned on:\n{php}"


@pytest.mark.parametrize("settings", [{}, {"pfb_dnsbl": ""}, {"pfb_dnsbl": "off"}], ids=["absent", "empty", "off"])
def test_dnsbl_settings_replace_without_dnsbl_on_leaves_pfb_dns_alone(settings: dict[str, str]) -> None:
    """Given DNSBL settings that do not turn DNSBL on When the replace PHP is built
    Then it never mentions pfB-DNS: pfB-DNS with DNSBL off only forwards, so it is not this writer's business."""
    php = helpers._dnsbl_settings_replace_php(settings)

    assert PFB_DNS_PATH not in php, f"pfB-DNS touched although DNSBL is not turned on:\n{php}"


def test_inject_and_inject_dnsbl_lists_turn_pfb_dns_on_with_their_dnsbl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the two real DNSBL injectors When each builds its config write
    Then both carry the pfB-DNS 'on' line, so no test-local caller needs its own."""
    single = helpers._dnsbl_inject_snippet(_case())
    captured = _capture_php_eval(monkeypatch)
    helpers.inject_dnsbl_lists(_Vm([]), [(_case(), "Deny")])  # type: ignore[arg-type]

    assert PFB_DNS_ON in single, f"inject() does not turn pfB-DNS on:\n{single}"
    assert PFB_DNS_ON in captured[0], f"inject_dnsbl_lists() does not turn pfB-DNS on:\n{captured[0]}"


# --- R2: set_dnsbl_enabled ------------------------------------------------------------------------------------


def test_set_dnsbl_enabled_true_turns_pfb_dns_on_in_the_same_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given DNSBL is being enabled When set_dnsbl_enabled(True) writes
    Then pfB-DNS 'on' rides the same write_config as pfb_dnsbl 'on'."""
    captured = _capture_php_eval(monkeypatch)

    helpers.set_dnsbl_enabled(_Vm([]), True)  # type: ignore[arg-type]

    snippet = captured[0]
    assert "$d['pfb_dnsbl'] = 'on';" in snippet, f"DNSBL is not turned on:\n{snippet}"
    assert PFB_DNS_ON in snippet, f"pfB-DNS is not turned on with DNSBL:\n{snippet}"
    assert snippet.count("write_config(") == 1, f"pfB-DNS must ride the same write as DNSBL:\n{snippet}"
    assert snippet.index(PFB_DNS_ON) < snippet.index("write_config("), f"pfB-DNS is set after the write:\n{snippet}"


def test_set_dnsbl_enabled_false_leaves_pfb_dns_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given DNSBL is being disabled When set_dnsbl_enabled(False) writes
    Then pfB-DNS is not mentioned: the module teardown gives the Resolver back, not this toggle."""
    captured = _capture_php_eval(monkeypatch)

    helpers.set_dnsbl_enabled(_Vm([]), False)  # type: ignore[arg-type]

    snippet = captured[0]
    assert "$d['pfb_dnsbl'] = '';" in snippet, f"DNSBL is not turned off:\n{snippet}"
    assert PFB_DNS_PATH not in snippet, f"disabling DNSBL touched pfB-DNS:\n{snippet}"


# --- R4: release_pfb_dns ----------------------------------------------------------------------------------------


def _arrange_release(
    monkeypatch: pytest.MonkeyPatch, *, installed: bool = True, moved: tuple[bool, ...] = (False,), pfb_dns: str = ""
) -> list[str]:
    """Stub release_pfb_dns's collaborators; the returned list holds only its writes and reloads, in order."""
    events: list[str] = []
    moved_reads = iter(moved)

    def config_get(_vm: object, path: str, **_kw: object) -> str:
        if path == PFB_DNS_PATH:
            return pfb_dns
        raise AssertionError(f"unexpected config read: {path}")

    def php_eval(_vm: object, snippet: str, **_kw: object) -> SimpleNamespace:
        assert PFB_DNS_OFF in snippet and "write_config(" in snippet, f"unexpected write:\n{snippet}"
        events.append("store pfb_dns ''")
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    def reload(_vm: object, scope: str = "update", **_kw: object) -> None:
        events.append(f"reload:{scope}")

    monkeypatch.setattr(helpers, "pkg_installed", lambda _vm, **_kw: installed)
    monkeypatch.setattr(helpers, "config_get", config_get)
    monkeypatch.setattr(helpers, "_pfb_dns_moved", lambda _vm: next(moved_reads), raising=False)
    monkeypatch.setattr(helpers, "php_eval", php_eval)
    monkeypatch.setattr(helpers, "reload", reload)
    return events


def test_release_pfb_dns_does_nothing_when_pfb_dns_is_off_and_the_resolver_is_not_moved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _arrange_release(monkeypatch, moved=(False,), pfb_dns="")

    helpers.release_pfb_dns(_Vm([]))  # type: ignore[arg-type]

    assert events == [], f"nothing was moved, yet the harness wrote or reloaded: {events}"


def test_release_pfb_dns_only_stores_off_when_pfb_dns_is_on_but_the_resolver_was_never_moved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _arrange_release(monkeypatch, moved=(False,), pfb_dns="on")

    helpers.release_pfb_dns(_Vm([]))  # type: ignore[arg-type]

    assert events == ["store pfb_dns ''"], f"expected a store with no apply (nothing was moved): {events}"


def test_release_pfb_dns_stores_off_and_applies_when_the_resolver_is_moved(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given pfB-DNS holds the Resolver (a running proxy, or a valid snapshot / our block) When it is released
    Then pfB-DNS is stored off and the product's own DNSBL apply runs, and it returns once nothing holds it."""
    events = _arrange_release(monkeypatch, moved=(True, False))

    helpers.release_pfb_dns(_Vm([]))  # type: ignore[arg-type]

    assert events == ["store pfb_dns ''", "reload:updatednsbl"], f"wrong release sequence: {events}"


def test_release_pfb_dns_fails_loudly_when_the_apply_leaves_the_resolver_moved(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the apply leaves pfB-DNS holding the Resolver When it is released
    Then the harness raises with expected vs actual instead of wiping config under a running proxy."""
    events = _arrange_release(monkeypatch, moved=(True, True))

    with pytest.raises(RuntimeError, match=r"expected.*released.*still"):
        helpers.release_pfb_dns(_Vm([]))  # type: ignore[arg-type]

    assert events == ["store pfb_dns ''", "reload:updatednsbl"], f"the failure came before the apply ran: {events}"


def test_release_pfb_dns_does_nothing_when_the_package_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the package was uninstalled When the Resolver is released
    Then nothing is read, written or applied: the uninstall gave the Resolver back itself."""
    events = _arrange_release(monkeypatch, installed=False, moved=(True,), pfb_dns="on")

    helpers.release_pfb_dns(_Vm([]))  # type: ignore[arg-type]

    assert events == [], f"the harness touched an uninstalled package: {events}"


def test_a_resolver_counts_as_moved_only_by_a_running_proxy_or_the_products_own_ownership_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a test that plants a pfb_dns_saved value that is no valid snapshot (the wizard's refused-Finish cases)
    When the harness asks whether pfB-DNS holds the Resolver
    Then it asks the product (a live proxy pid, or pfb_dns_proxy_owns_resolver(): a valid snapshot or our block),
    never the raw marker: an apply cannot clear a planted invalid marker, so a raw-marker test would fail every later
    restore."""
    reads: list[str] = []

    def read_scalar(_vm: object, pre: str, expr: str, **_kw: object) -> str:
        reads.append(pre + "\n" + expr)
        return "true"

    monkeypatch.setattr(helpers, "_php_read_scalar", read_scalar)

    assert helpers._pfb_dns_moved(_Vm([])) is True  # type: ignore[arg-type]
    (php,) = reads
    assert "pfb_dns_proxy_running()" in php and "pfb_dns_proxy_owns_resolver()" in php, php
    assert "pfb_dns_saved" not in php, f"the raw marker decides a move: {php}"


# --- R5 / R6: the wipe and the restore give the Resolver back first ----------------------------------------------


def test_reset_pfb_baseline_releases_pfb_dns_before_it_wipes_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a module that left pfB-DNS on When the baseline is reset
    Then pfB-DNS is released while the module's config is still in place, and only then is it wiped."""
    events: list[str] = []

    def php_eval(_vm: object, _snippet: str, **_kw: object) -> SimpleNamespace:
        events.append("wipe")
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(helpers, "release_pfb_dns", lambda _vm, **_kw: events.append("release"), raising=False)
    monkeypatch.setattr(helpers, "php_eval", php_eval)
    monkeypatch.setattr(helpers, "teardown_geoip_dataset", lambda _vm, **_kw: None)
    monkeypatch.setattr(helpers, "pkg_installed", lambda _vm, **_kw: False)
    monkeypatch.setattr(helpers, "apply_filter_sync", lambda _vm, **_kw: None)

    helpers.reset_pfb_baseline(_Vm(events))  # type: ignore[arg-type]

    assert "release" in events, f"reset_pfb_baseline never released pfB-DNS: {events}"
    assert events.index("release") < events.index("wipe"), f"the wipe ran before the release: {events}"


def test_restore_pfb_config_baseline_releases_pfb_dns_before_it_copies_the_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a UI test that left pfB-DNS on When the session baseline is restored
    Then pfB-DNS is released before config.xml is replaced: a pre-move config under a running proxy would leave
    Unbound colliding with it on :53."""
    events: list[str] = []

    def php_eval(_vm: object, _snippet: str, **_kw: object) -> SimpleNamespace:
        events.append("regenerate")
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    monkeypatch.setattr(helpers, "release_pfb_dns", lambda _vm, **_kw: events.append("release"), raising=False)
    monkeypatch.setattr(helpers, "php_eval", php_eval)
    monkeypatch.setattr(helpers, "pkg_installed", lambda _vm, **_kw: False)
    monkeypatch.setattr(helpers, "apply_filter_sync", lambda _vm, **_kw: None)

    helpers.restore_pfb_config_baseline(_Vm(events), snapshot_path="/var/tmp/snap.xml")  # type: ignore[arg-type]

    copied = next((i for i, e in enumerate(events) if e.startswith("ssh:cp ")), None)
    assert "release" in events, f"restore_pfb_config_baseline never released pfB-DNS: {events}"
    assert copied is not None, f"the snapshot was never copied: {events}"
    assert events.index("release") < copied, f"the snapshot was copied before the release: {events}"


# --- R7: the module baseline tears down before the DNS config restore ---------------------------------------------


def test_pfb_module_baseline_requests_the_dns_config_restore_so_it_tears_down_first() -> None:
    """Given two module-scoped autouse teardowns When the baseline fixture requests the DNS config restore
    Then pytest tears the baseline (which releases pfB-DNS) down BEFORE restore_dns_config runs, while the module's
    DNS mutations are still in place."""
    conftest = Path(helpers.__file__).with_name("conftest.py")
    fixture = next(
        node
        for node in ast.walk(ast.parse(conftest.read_text()))
        if isinstance(node, ast.FunctionDef) and node.name == "_pfb_module_baseline"
    )

    requested = [arg.arg for arg in fixture.args.args]

    assert "_restore_dns_config_per_module" in requested, (
        f"_pfb_module_baseline does not depend on the DNS config restore: {requested}"
    )


# --- the HA pair restore gives the Resolver back before it copies the pre-pair config.xml ---------------------------


def test_ha_restore_node_releases_pfb_dns_before_it_copies_the_pre_pair_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given an HA node whose DNSBL turned pfB-DNS on When the pair is restored
    Then pfB-DNS is released before the pre-pair config.xml is copied back: that config predates the move, and
    restoring it under a running proxy leaves the next module's Unbound behind a proxy with no upstream (SERVFAIL)."""
    from tests.smoke import ha_pair

    events: list[str] = []

    def ssh_ok(_vm: object, command: str, **_kw: object) -> str:
        events.append("config-restore" if "/conf/config.xml" in command else "ssh")
        return ""

    monkeypatch.setattr(ha_pair, "_baseline_exists", lambda _vm, _node: True)
    monkeypatch.setattr(ha_pair, "_php_ok", lambda *_a, **_kw: events.append("runtime-teardown"))
    monkeypatch.setattr(ha_pair, "_ssh_ok", ssh_ok)
    monkeypatch.setattr(ha_pair, "clear_sshguard", lambda _vm: None)
    monkeypatch.setattr(ha_pair, "clear_pending_marker", lambda _vm: None)
    monkeypatch.setattr(ha_pair, "_verify_baseline", lambda _vm: None)
    monkeypatch.setattr(helpers, "apply_filter_sync", lambda _vm, **_kw: None)
    monkeypatch.setattr(helpers, "release_pfb_dns", lambda _vm, **_kw: events.append("release"))

    ha_pair.restore_node(object(), "primary")  # type: ignore[arg-type]

    assert "release" in events, f"restore_node never released pfB-DNS: {events}"
    assert events.index("release") < events.index("config-restore"), f"config.xml was restored first: {events}"


# --- R8: a DNSBL apply that leaves pfB-DNS on but not serving fails loudly -------------------------------------------


def _arrange_reload(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enable_cb: str = "on",
    dnsbl: str = "on",
    pfb_dns: str = "on",
    serving: bool | None = False,
) -> tuple[list[str], list[str]]:
    """Stub reload's collaborators: the guest verb succeeds, the one PHP read reports this state."""
    events: list[str] = []
    snippets: list[str] = []
    state = {"enable_cb": enable_cb, "dnsbl": dnsbl, "pfb_dns": pfb_dns, "serving": serving}

    def php_eval(_vm: object, snippet: str, **_kw: object) -> SimpleNamespace:
        events.append("php_eval")
        snippets.append(snippet)
        fenced = f"banner{helpers._CFG_VAL_OPEN}{json.dumps(state)}{helpers._CFG_VAL_CLOSE}"
        return SimpleNamespace(returncode=0, stdout=fenced, stderr="")

    monkeypatch.setattr(helpers, "php_eval", php_eval)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda _vm, **_kw: events.append("wait_unbound_ready"))
    monkeypatch.setattr(helpers, "count_log_marker", lambda *_a, **_kw: 0)
    monkeypatch.setattr(helpers, "wait_zero_downtime_swap", lambda _vm, **_kw: events.append("wait_swap"))
    return events, snippets


@pytest.mark.parametrize("data_path", [False, True], ids=["wait_unbound", "data_path"])
def test_reload_fails_when_dnsbl_and_pfb_dns_are_on_but_the_proxy_is_not_serving(
    monkeypatch: pytest.MonkeyPatch, data_path: bool
) -> None:
    """Given DNSBL and pfB-DNS are both on and the apply left the proxy not serving
    When reload returns Then it raises with expected vs actual and the proxy log tail, on either readiness path,
    after the readiness wait (so a still-starting Unbound is not misread as a dead proxy)."""
    events, _ = _arrange_reload(monkeypatch, serving=False)

    with pytest.raises(RuntimeError, match=r"pfb_dns_proxy_serving_ready\(\).*expected True.*actual False") as caught:
        helpers.reload(_Vm(events), "updatednsbl", data_path=data_path)  # type: ignore[arg-type]

    assert LOG_TAIL in str(caught.value), f"the failure does not carry the dns_proxy.log tail: {caught.value}"
    readiness = "wait_swap" if data_path else "wait_unbound_ready"
    assert events.index(readiness) < events.index("php_eval"), f"the serving check ran before readiness: {events}"


@pytest.mark.parametrize("data_path", [False, True], ids=["wait_unbound", "data_path"])
def test_reload_accepts_a_serving_proxy(monkeypatch: pytest.MonkeyPatch, data_path: bool) -> None:
    events, _ = _arrange_reload(monkeypatch, serving=True)

    helpers.reload(_Vm(events), "updatednsbl", data_path=data_path)  # type: ignore[arg-type]

    assert "php_eval" in events, f"the serving check never ran: {events}"


@pytest.mark.parametrize(
    "off",
    [{"enable_cb": ""}, {"dnsbl": ""}, {"pfb_dns": ""}],
    ids=["package-off", "dnsbl-off", "pfb-dns-off"],
)
def test_reload_requires_no_serving_proxy_unless_all_of_enable_dnsbl_and_pfb_dns_are_on(
    monkeypatch: pytest.MonkeyPatch, off: dict[str, str]
) -> None:
    """Given any one of the package, DNSBL and pfB-DNS is off When reload returns
    Then no proxy readiness is required: with one of them off the proxy is not the DNSBL path."""
    events, _ = _arrange_reload(monkeypatch, serving=False, **off)

    helpers.reload(_Vm(events), "update")  # type: ignore[arg-type]

    assert "php_eval" in events, f"the state read never ran: {events}"


def test_reload_without_the_unbound_wait_does_not_check_the_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a pf-level caller that passes wait_unbound=False When reload returns
    Then the guest is not asked about the proxy at all: that caller never probes DNS."""
    events, _ = _arrange_reload(monkeypatch, serving=False)

    helpers.reload(_Vm(events), "update", wait_unbound=False)  # type: ignore[arg-type]

    assert "php_eval" not in events, f"reload(wait_unbound=False) still queried the proxy: {events}"


def test_reload_reads_the_three_switches_and_the_serving_predicate_in_one_php_eval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given a reload When the readiness read is built Then ONE snippet reads enable_cb, pfb_dnsbl and pfb_dns and
    asks the product's own pfb_dns_proxy_serving_ready() (the readiness the apply itself waits for)."""
    events, snippets = _arrange_reload(monkeypatch, serving=True)

    helpers.reload(_Vm(events), "update")  # type: ignore[arg-type]

    assert events.count("php_eval") == 1, f"expected one PHP read: {events}"
    snippet = snippets[0]
    required = [
        f"{helpers.CFG_GLOBAL}/enable_cb",
        f"{helpers.CFG_DNSBL_SETTINGS}/pfb_dnsbl",
        PFB_DNS_PATH,
        "/usr/local/pkg/pfblockerng/pfblockerng.inc",
        "pfb_dns_proxy_serving_ready()",
    ]
    assert all(part in snippet for part in required), f"the readiness snippet lacks one of {required}:\n{snippet}"


# --- the Resolver mutators edit the Resolver only while pfB-DNS does not hold it ---------------------------------

RESOLVER_MUTATORS = [
    pytest.param(lambda vm: helpers.use_system_dns_upstream(vm), id="use_system_dns_upstream"),
    pytest.param(lambda vm: helpers.set_unbound_forwarding(vm, True), id="set_unbound_forwarding"),
    pytest.param(lambda vm: helpers.use_stub_for_safesearch(vm, False), id="use_stub_for_safesearch-recursive"),
    pytest.param(lambda vm: helpers.use_stub_for_safesearch(vm, True), id="use_stub_for_safesearch-forwarding"),
]


def _arrange_resolver_edit(monkeypatch: pytest.MonkeyPatch, *, pfb_dns: str) -> tuple[SimpleNamespace, list[str]]:
    """Stub a Resolver mutator's collaborators; the returned list records them in call order.

    The toggle is stateful (release clears it, the store-on sets it): a mutator reading it after the release sees off.
    """
    events: list[str] = []
    state = {"pfb_dns": pfb_dns}

    def config_get(_vm: object, path: str, **_kw: object) -> str:
        assert path == PFB_DNS_PATH, f"unexpected config read: {path}"
        return state["pfb_dns"]

    def release_pfb_dns(_vm: object) -> None:
        if state["pfb_dns"] == "on":  # the real release is a no-op when pfB-DNS is off and holds nothing
            events.append("release")
            state["pfb_dns"] = ""

    def php_eval(_vm: object, snippet: str, **_kw: object) -> SimpleNamespace:
        if "services_unbound_configure()" in snippet:
            events.append("resolver write")
        elif PFB_DNS_ON in snippet and "write_config(" in snippet:
            events.append("store pfb_dns on")
            state["pfb_dns"] = "on"
        else:
            raise AssertionError(f"unexpected PHP:\n{snippet}")
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    def dns_probe(_vm: object, *_a: object, **_kw: object) -> object:
        events.append("probe")
        return object()

    monkeypatch.setattr(helpers, "config_get", config_get)
    monkeypatch.setattr(helpers, "release_pfb_dns", release_pfb_dns)
    monkeypatch.setattr(helpers, "_remember_dns_baseline", lambda _vm, **_kw: events.append("baseline"))
    monkeypatch.setattr(helpers, "php_eval", php_eval)
    monkeypatch.setattr(helpers, "wait_unbound_ready", lambda _vm, **_kw: events.append("wait unbound"))
    monkeypatch.setattr(helpers, "dns_probe", dns_probe)
    monkeypatch.setattr(helpers, "resolves_to", lambda *_a, **_kw: True)
    return SimpleNamespace(upstream_dns_port=None), events


@pytest.mark.parametrize("mutate", RESOLVER_MUTATORS)
def test_a_resolver_mutator_edits_the_resolver_only_while_pfb_dns_does_not_hold_it(
    monkeypatch: pytest.MonkeyPatch, mutate: Callable[[SimpleNamespace], None]
) -> None:
    """Given pfB-DNS is on (DNSBL turned it on, so it holds the Resolver) When a test edits the Resolver
    Then pfB-DNS is released before the baseline and the write, the edit is verified with pfB-DNS off, and pfB-DNS is
    stored on again last, so the caller's next reload moves the edited Resolver and its marked clause survives."""
    vm, events = _arrange_resolver_edit(monkeypatch, pfb_dns="on")

    mutate(vm)

    assert events.count("release") == 1, f"expected exactly one release: {events}"
    assert events.count("store pfb_dns on") == 1, f"expected pfB-DNS stored on exactly once: {events}"
    assert events.index("release") < events.index("baseline"), f"the baseline snapshot saw a moved Resolver: {events}"
    assert events.index("release") < events.index("resolver write"), f"the Resolver was edited while moved: {events}"
    assert events[-1] == "store pfb_dns on", f"pfB-DNS was not stored on again after the edit and its checks: {events}"


@pytest.mark.parametrize("mutate", RESOLVER_MUTATORS)
def test_a_resolver_mutator_never_turns_pfb_dns_on_when_it_was_off(
    monkeypatch: pytest.MonkeyPatch, mutate: Callable[[SimpleNamespace], None]
) -> None:
    """Given pfB-DNS is off When a test edits the Resolver
    Then the edit is written and pfB-DNS stays off: a mutator that turned it on would move the Resolver for tests
    that never asked for it."""
    vm, events = _arrange_resolver_edit(monkeypatch, pfb_dns="")

    mutate(vm)

    assert "resolver write" in events, f"the mutator never wrote the Resolver: {events}"
    assert "store pfb_dns on" not in events, f"pfB-DNS was turned on although it was off: {events}"
