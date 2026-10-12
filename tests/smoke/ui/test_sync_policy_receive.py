"""Tier-B live proof (#3452): an authenticated XMLRPC policy receive applies once; a retry or refusal applies nothing.

The box calls ITSELF through pfSense's real XMLRPC endpoint -- ``xmlrpc.php`` authenticates the admin (real HA
privilege), runs the package ``plugin_xmlrpc_recv`` hook, writes the returned paths, reloads the filter and then
runs ``plugin_xmlrpc_recv_done``. The client is pfSense's own ``pfsense_xmlrpc_client``, driven from
:func:`tests.smoke.helpers.php_eval` (the full pfSsh.php bootstrap). No transport, endpoint, credential path or test
double is invented here. The payload is built the way the manual sender builds it, from the box's OWN stored
config: the gate leaf forced to ``policy`` plus the policy projection of the sections with ONE intended change (a new
IPv4 group fed by a local file), copied path by path with the expression core uses for the automatic transport.

Scheduled ticks stay inhibited (``.pfb_cron_disable``; the ``tick`` verb is not gated by it), so the only thing that
can apply a change here is the receive-triggered ``pfblockerng.php tick``.

  Scenario: a changed policy payload is received
    Given cron is inhibited, the package is on, no apply is pending and the group's alias table does not exist
    When  the payload is received
    Then  the call returns true, the receive record says ``changed`` and the group is stored; once the apply is over
          the alias table holds the feed address, exactly ONE update pass ran, the receive record still says
          ``changed`` and the separate apply record says ``applied``

  Scenario: the identical payload is received again (client retry)
    Given the changed payload was received and its apply is over
    When  the same payload is received
    Then  the record says ``unchanged``; nothing is pending, no tick is running, no second update pass ran and the
          stored ``installedpackages`` is byte-identical

  Scenario: a payload the receiver must refuse (a duplicate ``aliasname``)
    Given a box without the group
    When  the payload is received
    Then  core still returns true, the record says ``refused`` with a reason; nothing is stored, pending or applied

  Scenario: the Sync page after a real receive (#3453)
    Given the real refusal above, and the real changed receive once its apply is over
    Then  the receiver panel shows the state file's own values (outcome wording, digests, reason escaped) and the
          apply row apart from the receipt; no peer check control is on the page

  Scenario: a real manual policy sync to a closed local port and to the box's own webGUI (#3453)
    Then  the sender panel lists each target with its own result and the state file's digest; no secret is in it

Completion is synchronized on records -- the pending marker, the tick process, the receive state file -- never on
sleeps. The only wait is the bounded poll for the apply to finish. The password travels only in the stdin snippet
and is redacted from every message.
"""

from __future__ import annotations

import copy
import json
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .conftest import _redact_values_from_env
from .test_sync import CFG_SYNC, _seed_sync
from .test_sync_status_panels import (
    DASH,
    SEND,
    TIME,
    _receiver,
    _sender,
    assert_no_peer_check,
    assert_row,
    php_escape,
    plain,
    preserved_state,
    read_state,
    receiver_cell,
    render_sync_page,
    seed,
    sender_rows,
)

if TYPE_CHECKING:
    from .webui import WebUI

# The only reasons the sender panel may give for a failed attempt (never the client's raw message).
FAILURE_CLASSES = (
    "authentication failed",
    "the peer returned an XMLRPC fault",
    "timeout",
    "TLS error",
    "connection error",
    "transport error",
)

pytestmark = pytest.mark.ui_e2e

ALIAS = "pfbsync3452"
TABLE = f"pfB_{ALIAS}_v4"
FEED_NAME = f"{ALIAS}_feed.txt"
FEED_ADDR = "198.51.100.89"  # RFC 5737 TEST-NET-2: unique to this module
GATE_PATH = "installedpackages/pfblockerngsync/config/0/syncscope"
V4_LISTS = "installedpackages/pfblockernglistsv4/config"
# Written once per pass by sync_package_pfblockerng(); with cron inhibited, nothing else prints it.
APPLY_BANNER = "UPDATE PROCESS START"
# Salvage cap for the receive-triggered apply (an update pass + filter reload), never an assertion.
SETTLE_TIMEOUT = 300.0
MEMBER_TIMEOUT = 60.0  # the apply's own filter reload is detached; the table fills a few seconds after the pass ends
SYNC_TIMEOUT = 300.0  # cap for a whole sync pass: the dead target's client retries, then the self-send

_OPEN, _CLOSE = "<<<PFB3452>>>", "<<<END3452>>>"
# `global $pfb` binds the package globals whichever scope pfSsh.php evals the buffer in.
_PRELUDE = (
    "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
    "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
    "global $pfb;\n"
    "pfb_global();\n"
)


@dataclass(frozen=True)
class _Box:
    """The guest, how it reaches its own XMLRPC endpoint, and the paths this module arranged."""

    vm: helpers.SmokeVM
    protocol: str
    port: int
    user: str
    password: str = field(repr=False)
    marker: str = ""
    feed: str = ""


def _redact(text: str, *secrets: str) -> str:
    for value in (*secrets, *_redact_values_from_env()):
        if value:
            text = text.replace(value, helpers.REDACTED)
    return text


def _emit(expr: str) -> str:
    """PHP that echoes ``json_encode(expr)`` between sentinels (pfSsh.php prints a banner of its own)."""
    return f"echo {helpers._php_str(_OPEN)} . json_encode({expr}) . {helpers._php_str(_CLOSE)};"


def _guest_json(vm: helpers.SmokeVM, php: str, *, secret: str = "", timeout: float = 120.0) -> Any:
    """Run ``php`` after the package prelude and return the JSON it emitted; never leak ``secret``."""
    result = helpers.php_eval(vm, _PRELUDE + php, timeout=timeout)
    out = result.stdout
    start, end = out.find(_OPEN), out.find(_CLOSE)
    assert result.returncode == 0 and start != -1 and end != -1, _redact(
        f"guest snippet emitted no result: rc={result.returncode} stdout={out!r} stderr={result.stderr!r}", secret
    )
    return json.loads(out[start + len(_OPEN) : end])


_STATE_PHP = _emit(
    "array("
    "'receive' => pfb_sync_receive_state_read($pfb['dbdir']), "
    "'installedpackages_sha256' => hash('sha256', serialize(config_get_path('installedpackages'))), "
    "'v4_aliasnames' => array_column(config_get_path('" + V4_LISTS + "', array()), 'aliasname')"
    ")"
)


def _state(vm: helpers.SmokeVM) -> dict[str, Any]:
    """Receive record, digest of the stored ``installedpackages`` and the stored IPv4 group names."""
    state: dict[str, Any] = _guest_json(vm, _STATE_PHP)
    return state


def _changed_payload(box: _Box) -> dict[str, Any]:
    """The policy payload for the box's own config plus one new IPv4 group, built guest-side."""
    spec = helpers.IpCase(aliasname=ALIAS, feed_url=box.feed, header=ALIAS, action="Deny_Inbound", family="v4")
    gate, lists = helpers._php_str(GATE_PATH), helpers._php_str(V4_LISTS)
    php = (
        "$normalized = config_get_path('');\n"
        f"array_set_path($normalized, {gate}, 'policy');\n"
        f"$rows = array_get_path($normalized, {lists}, array());\n"
        f"$rows[] = {helpers._ip_list_php(spec)};\n"
        f"array_set_path($normalized, {lists}, $rows);\n"
        "$sections = array();\n"
        "foreach (pfblockerng_sync_sections(TRUE) as $s) {\n"
        "    $sections[$s] = array_get_path($normalized, 'installedpackages/' . $s);\n"
        "}\n"
        f"$paths = array_merge(array({gate}), array_keys(pfb_sync_policy_projection($sections)));\n"
        "$payload = array();\n"
        "foreach ($paths as $p) { array_set_path($payload, $p, array_get_path($normalized, $p, array())); }\n"
        + _emit("$payload")
    )
    payload: dict[str, Any] = _guest_json(box.vm, php)
    packages = payload.get("installedpackages", {})
    gate_value = packages.get("pfblockerngsync", {}).get("config", [{}])[0].get("syncscope")
    rows = packages.get("pfblockernglistsv4", {}).get("config")
    assert gate_value == "policy", f"payload gate leaf: expected 'policy', got {gate_value!r}"
    assert isinstance(rows, list) and [r.get("aliasname") for r in rows] == [ALIAS], (
        f"payload IPv4 groups: expected exactly [{ALIAS!r}], got {rows!r}"
    )
    return payload


def _send(box: _Box, payload: dict[str, Any]) -> dict[str, Any]:
    """Receive ``payload`` through ``restore_config_section``; returns ``{'t0': guest time, 'result': reply}``."""
    php = (
        "require_once('xmlrpc_client.inc');\n"
        f"$payload = json_decode({helpers._php_str(json.dumps(payload))}, TRUE);\n"
        "$t0 = time();\n"
        "try {\n"
        "    $c = new pfsense_xmlrpc_client();\n"
        f"    $c->setConnectionData('127.0.0.1', {box.port}, {helpers._php_str(box.user)}, "
        f"{helpers._php_str(box.password)}, {helpers._php_str(box.protocol)});\n"
        "    $r = $c->xmlrpc_method('restore_config_section', $payload, 60);\n"
        "} catch (Throwable $e) {\n"
        "    $r = 'EXCEPTION ' . get_class($e) . ': ' . $e->getMessage();\n"
        "}\n" + _emit("array('t0' => $t0, 'result' => $r)")
    )
    sent: dict[str, Any] = _guest_json(box.vm, php, secret=box.password)
    assert sent["result"] is True, _redact(
        f"restore_config_section: expected True, got {sent['result']!r}", box.password
    )
    return sent


def _assert_record(state: dict[str, Any], sent: dict[str, Any], outcome: str) -> dict[str, Any]:
    """The receive record is THIS call's (not stale) and carries ``outcome``."""
    last = (state["receive"] or {}).get("last") or {}
    assert last.get("outcome") == outcome, f"receive record: expected outcome {outcome!r}, got {last!r}"
    assert last.get("time", 0) >= sent["t0"], f"receive record is stale: {last!r} predates the call at {sent['t0']}"
    return last


def _in_flight(box: _Box) -> list[str]:
    """The apply's signals still set: ``pending`` (marker present) and ``tick`` (a tick process alive)."""
    # Bracketed `[.]` keeps pgrep -f from matching this probe's own shell command line.
    probe = (
        f"if /bin/test -e {shlex.quote(box.marker)}; then echo pending; fi; "
        "if /bin/pgrep -f 'pfblockerng[.]php tick' >/dev/null 2>&1; then echo tick; fi"
    )
    result = box.vm.ssh(probe)
    assert result.returncode == 0, f"in-flight probe failed: rc={result.returncode} stderr={result.stderr!r}"
    return result.stdout.split()


def _settle(box: _Box) -> None:
    """Block until the receive-triggered apply is over: marker cleared and no tick process left."""
    seen = ["<never probed>"]

    def over() -> bool:
        seen[:] = _in_flight(box)
        return not seen

    try:
        helpers.wait_until(over, timeout=SETTLE_TIMEOUT, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; still in flight: {seen}") from exc


def _apply_banners(vm: helpers.SmokeVM) -> int:
    return helpers.count_log_marker(vm, helpers.PFB_LOG, APPLY_BANNER)


def _table_members(vm: helpers.SmokeVM) -> list[str]:
    """Members of the group's pf table; ``[]`` while the table does not exist."""
    result = vm.ssh(helpers.PFCTL, "-t", TABLE, "-T", "show")
    if result.returncode != 0 and "does not exist" in result.stderr:
        return []
    assert result.returncode == 0, f"pfctl -t {TABLE} -T show: rc={result.returncode} stderr={result.stderr!r}"
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _await_member(vm: helpers.SmokeVM) -> list[str]:
    """Poll the group's table until ``FEED_ADDR`` is in it (cap ``MEMBER_TIMEOUT``); return the members seen last."""
    seen: list[str] = []

    def present() -> bool:
        seen[:] = _table_members(vm)
        return helpers.member_present(seen, FEED_ADDR)

    try:
        helpers.wait_until(present, timeout=MEMBER_TIMEOUT, interval=2.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; table {TABLE}: expected {FEED_ADDR!r} among {seen!r}") from exc
    return seen


def _receive_and_apply(box: _Box) -> dict[str, Any]:
    """Given-step of the no-op scenarios: receive the changed payload and wait until its apply is over."""
    payload = _changed_payload(box)
    _send(box, payload)
    _settle(box)
    _await_member(box.vm)  # the apply's own filter reload is detached: the table is filled once it lands
    return payload


@pytest.fixture
def box(deployed_vm: helpers.SmokeVM, admin_credentials: tuple[str, str], webgui_protocol: str) -> Iterator[_Box]:
    """Arrange the Given shared by every scenario; remove the feed file afterwards.

    The config baseline restore (``_ui_pfb_isolation``) clears the derived pf state, so only the feed file is ours.
    """
    vm = deployed_vm
    assert vm.ssh("/bin/test", "-f", helpers.PFB_CRON_DISABLE_PATH).returncode == 0, (
        f"scheduled ticks must be inhibited: {helpers.PFB_CRON_DISABLE_PATH} is absent"
    )
    # Core's loop guard answers `true` and does nothing when synchronizetoip equals the caller (127.0.0.1 here).
    sync_to_ip = helpers.config_get(vm, "hasync/synchronizetoip")
    assert sync_to_ip != "127.0.0.1", "hasync/synchronizetoip is 127.0.0.1: core would swallow the self-call"
    configured_port = helpers.config_get(vm, "system/webgui/port")
    port = int(configured_port) if configured_port else (443 if webgui_protocol == "https" else 80)

    # Package on, IP interfaces set, both list roots empty: the group below exists only in the payload.
    helpers.inject_ip_lists(vm, [])
    feed = helpers.write_local_feed(vm, FEED_NAME, f"{FEED_ADDR}/32\n")
    try:
        marker: str = _guest_json(vm, _emit("pfb_pending_changes_marker()"))
        cleared = vm.ssh("rm", "-f", marker)
        assert cleared.returncode == 0, f"could not clear the pending marker {marker}: {cleared.stderr!r}"

        user, password = admin_credentials
        arranged = _Box(vm, webgui_protocol, port, user, password, marker, feed)
        assert _in_flight(arranged) == [], "before-state: an apply is already pending or a tick is running"
        assert _table_members(vm) == [], f"before-state: table {TABLE} must not exist yet"
        yield arranged
    finally:
        vm.ssh("rm", "-f", feed)


def test_changed_policy_receive_applies_exactly_once_with_cron_inhibited(box: _Box) -> None:
    """A changed policy becomes effective through the receive-triggered apply, and one apply is all that runs."""
    vm = box.vm
    banners_before = _apply_banners(vm)

    sent = _send(box, _changed_payload(box))
    state = _state(vm)
    _assert_record(state, sent, "changed")
    assert state["v4_aliasnames"] == [ALIAS], (
        f"stored IPv4 groups: expected [{ALIAS!r}], got {state['v4_aliasnames']!r}"
    )

    _settle(box)
    members = _await_member(vm)
    assert helpers.member_present(members, FEED_ADDR), f"table {TABLE}: expected {FEED_ADDR!r} among {members!r}"
    applies = _apply_banners(vm) - banners_before
    assert applies == 1, f"update passes ({APPLY_BANNER!r} in {helpers.PFB_LOG}): expected 1, got {applies}"

    after = _state(vm)
    _assert_record(after, sent, "changed")  # the receive record still reads accepted, whatever the apply did
    apply = (after["receive"] or {}).get("apply") or {}
    assert apply.get("outcome") == "applied", f"apply record: expected 'applied', got {apply!r}"
    assert apply.get("reason") == "update pass completed; firewall reload started", (
        f"apply record: the new group's table needs a reload, got {apply!r}"
    )
    assert apply.get("time", 0) >= sent["t0"], f"apply record is stale: {apply!r} predates the call at {sent['t0']}"


def test_identical_retry_is_a_noop(box: _Box) -> None:
    """The same payload received again changes nothing and starts no second apply."""
    vm = box.vm
    payload = _receive_and_apply(box)
    digest_before = _state(vm)["installedpackages_sha256"]
    banners_before = _apply_banners(vm)

    sent = _send(box, payload)
    in_flight = _in_flight(box)  # first read after the call: a wrongly dispatched apply is still pending here
    state = _state(vm)

    _assert_record(state, sent, "unchanged")
    assert in_flight == [], f"unchanged receive left an apply in flight: expected [], got {in_flight!r}"
    assert _apply_banners(vm) == banners_before, f"update passes after the retry: expected {banners_before}"
    assert state["installedpackages_sha256"] == digest_before, "installedpackages changed on an identical retry"


def test_refused_payload_stores_nothing_and_applies_nothing(box: _Box) -> None:
    """A payload that fails validation leaves the stored policy byte-identical and applies nothing."""
    vm = box.vm
    payload = _changed_payload(box)
    rows = payload["installedpackages"]["pfblockernglistsv4"]["config"]
    rows.append(copy.deepcopy(rows[0]))  # two groups named ALIAS: the receiver's identity check refuses the snapshot
    before = _state(vm)
    assert before["v4_aliasnames"] == [], (
        f"before-state: stored IPv4 groups expected [], got {before['v4_aliasnames']!r}"
    )
    banners_before = _apply_banners(vm)

    sent = _send(box, payload)  # core answers true for every outcome
    in_flight = _in_flight(box)
    state = _state(vm)

    last = _assert_record(state, sent, "refused")
    assert isinstance(last.get("reason"), str) and last["reason"].strip(), f"refusal must say why: got {last!r}"
    assert state["installedpackages_sha256"] == before["installedpackages_sha256"], "refused payload changed config"
    assert state["v4_aliasnames"] == [], (
        f"stored IPv4 groups after refusal: expected [], got {state['v4_aliasnames']!r}"
    )
    assert in_flight == [], f"refused receive left an apply in flight: expected [], got {in_flight!r}"
    assert _apply_banners(vm) == banners_before, f"update passes after the refusal: expected {banners_before}"


# The panels' oracle is the state the package itself wrote, read with its own readers; times are formatted guest-side.
_PANEL_STATE_PHP = "$r = pfb_sync_receive_state_read($pfb['dbdir']);\n" + _emit(
    "array('receive' => $r, "
    "'drift' => pfb_sync_receive_drift($pfb['dbdir']), "
    "'findings' => pfb_sync_findings_read($pfb['dbdir'])['findings'], "
    "'receive_at' => date('Y-m-d H:i:s', (int) ($r['last']['time'] ?? 0)), "
    "'apply_at' => date('Y-m-d H:i:s', (int) ($r['apply']['time'] ?? 0)))"
)
_DRIFT_WORDING = {
    True: "policy changed locally since the last accepted receive",
    False: "none",
    None: "no accepted digest to compare",
}
_APPLY_WORDING = {
    "applied": "applied: the update pass completed",
    "failed": "failed",
    "waiting": "waiting for the quiet-hours window",
}


def _panel_state(vm: helpers.SmokeVM) -> dict[str, Any]:
    """Receive record, drift, findings and the guest-formatted receive/apply times, as the package reads them."""
    state: dict[str, Any] = _guest_json(vm, _PANEL_STATE_PHP)
    return state


def _flat(text: str) -> str:
    """A stored string as the page shows it: escaped, tags gone, whitespace collapsed."""
    return re.escape(plain(php_escape(text)))


def _assert_apply_and_context_rows(receiver: str, state: dict[str, Any]) -> None:
    """The apply, drift, effective-policy and copied rows reflect the state, whatever earlier tests left in it."""
    apply = state["receive"].get("apply")
    if apply is None:
        assert_row(receiver, "apply", "no apply record")
    else:
        text = plain(receiver_cell(receiver, "apply"))
        assert text.startswith(_APPLY_WORDING[apply["outcome"]]), (
            f"apply row: expected {_APPLY_WORDING[apply['outcome']]!r} first for {apply!r}, got {text!r}"
        )
        if apply["outcome"] in ("applied", "failed"):
            assert text.endswith(f"({state['apply_at']})"), (
                f"apply row: expected ({state['apply_at']}) last, got {text!r}"
            )
        if apply["outcome"] == "failed" and apply.get("reason"):
            assert plain(php_escape(apply["reason"])) in text, f"apply row: expected the escaped reason, got {text!r}"
    assert_row(receiver, "drift", re.escape(_DRIFT_WORDING[state["drift"]]))
    findings = state["findings"]
    assert_row(receiver, "findings", " ".join(_flat(f) for f in findings) if findings else "none")
    assert plain(receiver_cell(receiver, "copied")), "copied row is empty"


def test_refused_receive_shows_on_the_sync_page(box: _Box, webui: WebUI) -> None:
    """The real refusal reads as a refusal with its reason, and claims no digest of its own.

    Red when: the receive row says accepted for a refusal; the reason differs from the state file's (or is not
    escaped); the incoming/accepted rows show a digest the refused record never carried; the apply row stops
    mirroring the (older) apply record or drift/findings stop mirroring the state; a peer check control appears.
    The receive, findings and send files are kept and put back, mode included.
    """
    with preserved_state(box.vm):
        payload = _changed_payload(box)
        rows = payload["installedpackages"]["pfblockernglistsv4"]["config"]
        rows.append(copy.deepcopy(rows[0]))  # two groups named ALIAS: the receiver's identity check refuses it
        sent = _send(box, payload)
        _settle(box)
        state = _panel_state(box.vm)
        last = _assert_record(state, sent, "refused")
        reason = last.get("reason")
        assert isinstance(reason, str) and reason.strip(), f"refusal must say why: got {last!r}"

        html = render_sync_page(box.vm, webui)
        receiver = _receiver(html)
        assert_row(receiver, "receive", f"{re.escape(state['receive_at'])} {DASH} refused: {_flat(reason)}")
        assert_row(receiver, "incoming", DASH)
        assert_row(receiver, "accepted", DASH)
        assert_row(receiver, "ignored", "none")
        _assert_apply_and_context_rows(receiver, state)
        assert_no_peer_check(html)


def test_changed_receive_shows_on_the_sync_page_with_its_apply_apart(box: _Box, webui: WebUI) -> None:
    """The real changed receive reads accepted with the state file's digests, and its apply is a row of its own.

    Red when: the receive row stops saying "accepted with changes"; the incoming or accepted digest on the page
    differs from the state file's; ignored paths are not listed (escaped); the apply row stops following the apply
    record that the settled pass wrote (applied/failed with its time); drift or findings stop mirroring the state.
    The receive, findings and send files are kept and put back, mode included, once the apply is over.
    """
    with preserved_state(box.vm):
        sent = _send(box, _changed_payload(box))
        _settle(box)
        state = _panel_state(box.vm)
        last = _assert_record(state, sent, "changed")
        apply = state["receive"].get("apply") or {}
        assert apply.get("outcome") in ("applied", "failed"), f"apply record after the settle: got {apply!r}"
        for key in ("incoming_digest", "accepted_digest"):
            assert re.fullmatch(r"[0-9a-f]{64}", str(last.get(key))), (
                f"receive record {key}: expected 64 hex, got {last!r}"
            )

        html = render_sync_page(box.vm, webui)
        receiver = _receiver(html)
        assert_row(receiver, "receive", f"{re.escape(state['receive_at'])} {DASH} accepted with changes")
        assert_row(receiver, "incoming", last["incoming_digest"])
        assert_row(receiver, "accepted", last["accepted_digest"])
        ignored = [path for path in last.get("ignored", []) if isinstance(path, str)]
        count = last.get("ignored_count", len(ignored))
        assert_row(
            receiver,
            "ignored",
            " ".join([rf"{count} ignored path\(s\)", *(_flat(path) for path in ignored)]) if count else "none",
        )
        _assert_apply_and_context_rows(receiver, state)
        assert_no_peer_check(html)


def _seed_targets(box: _Box) -> int:
    """Store a manual ``policy`` sync with two enabled targets and return the closed port of the first.

    Target one is a loopback port that was bound and released, so nothing listens there; target two is this box's own
    webGUI under the admin credentials. The password only travels in the stdin snippet.
    """
    protocol, user, password = (helpers._php_str(v) for v in (box.protocol, box.user, box.password))
    php = (
        "$server = stream_socket_server('tcp://127.0.0.1:0');\n"
        "$dead = (int) substr(strrchr(stream_socket_get_name($server, FALSE), ':'), 1);\n"
        "fclose($server);\n"
        f"$c = config_get_path({helpers._php_str(CFG_SYNC)}, array());\n"
        "$c['varsynconchanges'] = 'manual';\n"
        "$c['varsynctimeout'] = '20';\n"
        "$c['syncscope'] = 'policy';\n"
        "$c['row'] = array(\n"
        "    array('varsyncprotocol' => 'http', 'varsyncipaddress' => '127.0.0.1', 'varsyncport' => (string) $dead, "
        "'varsyncusername' => 'admin', 'varsyncpassword' => 'unreachable', 'varsyncdestinenable' => 'on'),\n"
        f"    array('varsyncprotocol' => {protocol}, 'varsyncipaddress' => '127.0.0.1', 'varsyncport' => '{box.port}', "
        f"'varsyncusername' => {user}, 'varsyncpassword' => {password}, 'varsyncdestinenable' => 'on'),\n"
        ");\n"
        f"config_set_path({helpers._php_str(CFG_SYNC)}, $c);\n"
        "write_config('pfBlockerNG smoke #3453: sender panel targets');\n" + _emit("$dead")
    )
    dead: int = _guest_json(box.vm, php, secret=box.password)
    return dead


def test_sender_panel_lists_each_target_of_a_real_manual_sync(box: _Box, webui: WebUI) -> None:
    """A real manual policy sync records one attempt per target; the page shows each, and no secret.

    The first target's port is closed, the second is this box's own webGUI. The self-send makes the box record its
    own receive too, so the receive, findings and send files are kept and put back.

    Red when: one target hides the other (the dead target must not stop the pass); the live target is not
    "sent, acceptance unconfirmed" with the state file's 64-hex digest; the dead target is not "failed: " plus one
    fixed failure class (expected "connection error" for a closed port; the client's raw message or the fallback
    "no response from the XMLRPC client" is not a class); the page differs from pfb_sync_send.json; the admin password
    is in pfb_sync_send.json or in the sender panel. The whole page is not scanned for the password: the page's own
    Replication Targets form takes each stored password as an input value, which the panel does not control.
    """
    vm = box.vm
    with preserved_state(vm):
        try:
            seed(vm, receive=None, findings=None, send=None)  # no accepted digest: nothing suppresses the pass
            dead = _seed_targets(box)
            _guest_json(
                vm, "pfblockerng_sync_on_changes();\n" + _emit("TRUE"), secret=box.password, timeout=SYNC_TIMEOUT
            )
            _settle(box)  # a self-receive that changed anything would start an apply

            raw = read_state(vm, SEND)
            assert raw is not None, "the sync pass recorded nothing: pfb_sync_send.json is absent"
            attempts = json.loads(raw)["attempts"]
            dead_target, own_target = f"127.0.0.1:{dead}", f"127.0.0.1:{box.port}"
            assert [a["target"] for a in attempts] == [dead_target, own_target], f"attempts: got {attempts!r}"
            failed, sent = attempts
            digest = _guest_json(vm, _emit("pfb_sync_policy_current_digest()"))
            assert re.fullmatch(r"[0-9a-f]{64}", digest), f"policy digest: expected 64 hex, got {digest!r}"
            assert sent["outcome"] == "sent" and sent.get("digest") == digest, f"own webGUI attempt: got {sent!r}"
            error = failed.get("error")
            assert failed["outcome"] == "failed" and failed.get("digest") == digest, f"dead target: got {failed!r}"
            assert isinstance(error, str) and error.strip(), (
                f"dead target must carry the client's error: got {failed!r}"
            )
            assert error != "no response from the XMLRPC client", (
                "dead target recorded the fallback, not the client error"
            )
            assert helpers.redact_values(raw, [box.password]) == raw, "the admin password is in pfb_sync_send.json"

            html = render_sync_page(vm, webui)
            sender = _sender(html)
            rows = sender_rows(sender)
            assert [row[0] for row in rows] == [dead_target, own_target], f"sender rows: got {rows!r}"
            assert [len(row) for row in rows] == [4, 4], f"expected rows of Target|Time|Digest|Result, got {rows!r}"
            assert all(re.fullmatch(TIME, row[1]) for row in rows), f"sender times: got {rows!r}"
            assert rows[0][2] == digest, f"dead target digest: got {rows[0]!r}"
            failure = rows[0][3]
            assert failure in {f"failed: {cls}" for cls in FAILURE_CLASSES}, f"dead target result: got {failure!r}"
            assert rows[1][2:] == [digest, "sent, acceptance unconfirmed"], f"own webGUI row: got {rows[1]!r}"
            assert helpers.redact_values(sender, [box.password]) == sender, "the admin password is in the sender panel"
            assert_no_peer_check(html)
        finally:
            _seed_sync(vm)
