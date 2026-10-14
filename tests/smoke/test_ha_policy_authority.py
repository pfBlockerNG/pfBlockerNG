"""Issue #3455, rows R10-R14 and X2-X6: who may send, what a refusal leaves behind, and what a dead peer looks like.

Node A (``pair.primary``) sends, node B (``pair.secondary``) receives, on two real pfSense guests joined by the
HA sync link. Nothing is doubled: policy travels through the real sender (a package apply pass on A for the manual
transport, core's ``rc.filter_synchronize`` for the automatic one) and the real XMLRPC endpoint, and every
assertion reads a record the package wrote (``pfb_sync_send.json`` on A, ``pfb_sync_receive.json``,
``pfb_sync_findings.json`` and ``pfb_sync_copied.json`` on B), or the page that renders them. ``.pfb_cron_disable``
stays on both nodes, so the only update pass B ever runs is the receive-triggered one or one the test starts.

  Scenario: an invalid policy that A's real sender transmits (R10)
    Then  B refuses it whole and says why on its Sync page, B's ``installedpackages`` is byte-identical and no apply
          opens, and A's sender panel says only "sent, acceptance unconfirmed"; harness requests with a malformed
          shape, a gate leaf other than ``policy``, wrong types or bad credentials change nothing either

  Scenario: pfSense HA copies A's pfB_* rules to B (R11, X5)
    Then  B names the copied rules whose ``interface`` differs from what it generates, names nothing when they
          match, and its generated pfB aliases, rules and NAT are byte-identical with or without that detector state

  Scenario: B lists A as a target, A is demoted, B's Sync page is saved (R12, R14, X2)
    Then  a receive from A is never echoed (any of B's three scopes), a demoted A makes B originate nothing, saving
          B's Sync page lets B's next send and a later local edit reach A, and an unreachable target of two does
          not stop the other

  Scenario: B is unreachable (R13, X6) / B defers or fails its apply (X3) / the feed header contract (X4)
    Then  A's record carries the client's transport error (manual) or only "handed" (automatic, with core's own
          failure line); B holds A's policy while its apply waits or failed with the pending mark kept; headers
          reach B as the producer normalised them and B's findings list exactly what cannot take effect

Deviations from a naive reading, each from source (see the tests' docstrings): core's XMLRPC server swallows a call
from the host it syncs to (``xmlrpc.php`` ``loop_detected``), so the role flip first takes A off the HA primary role;
the legacy ``all``/``lists`` scopes call ``merge_installedpackages_section``, which has no package hook, so A shows
no receive record for them; ``gen/pfb_quiet_hours`` is a policy leaf, so the window travels from A.
"""

# ruff: noqa: E501 -- embedded PHP is one statement per line (pfSsh buffers by line).

from __future__ import annotations

import contextlib
import json
import os
import re
import socket
import subprocess
from collections.abc import Iterator
from contextlib import ExitStack
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .ha_pair import (
    HA_USER,
    NOPRIV_USER,
    PRIMARY_SYNC_IP,
    SECONDARY_SYNC_IP,
    SYNC_NIC,
    HaPair,
    carp_state,
    clear_sshguard,
    configure_primary_hasync,
    configure_secondary_users,
    set_carp_maintenance,
    wait_carp_state,
    xmlrpc_call,
)
from .ha_policy import (
    B_VIP_UNIQID,
    DNSBL,
    GEN,
    IP,
    LISTS_V4,
    SETTLE_TIMEOUT,
    SYNC,
    TRANSPORTS,
    Baseline,
    Sync,
    Transport,
    apply_banners,
    arrange_baseline,
    assert_applied_once,
    assert_receive,
    assert_sent,
    configure_sender,
    diff_leaves,
    emit,
    feed_path,
    group_local_values,
    in_flight,
    ip_group,
    node_state,
    node_time,
    php_json,
    read_json_file,
    read_leaves,
    read_sections,
    receive_state,
    reset_pair,
    seed_node,
    send_state,
    sender_section,
    set_leaves,
    settle,
    sync_once,
    token,
    trigger_send,
    wait_apply,
    wait_filter_idle,
    write_feed,
    write_sections,
)
from .ui.credgate import admin_password_decision
from .ui.test_sync_status_panels import (
    BANNED,
    DASH,
    TIME,
    _receiver,
    _sender,
    assert_row,
    php_escape,
    render_sync_page,
    sender_rows,
)
from .ui.webui import WebUI, extract_csrf_token, looks_like_login_page

pytestmark = pytest.mark.smoke

V4 = f"{LISTS_V4}/config"
GATE = f"{SYNC}/syncscope"
FINDINGS_FILE = f"{h.PFB_DBDIR}/pfb_sync_findings.json"
COPIED_FILE = f"{h.PFB_DBDIR}/pfb_sync_copied.json"
SYSTEM_LOG = "/var/log/system.log"
RELOAD_SCRIPT = "/etc/rc.filter_configure_sync"
# What the sender logs once it is past every early return (pfb_logger() writes it to pfblockerng.log).
SEND_MARKER = "===[  XMLRPC Sync ]"
DEAD_IP = "172.30.254.9"  # on the sync subnet, owned by nobody: ARP never resolves
SYNC_TIMEOUT = 10  # varsynctimeout: an unreachable target fails in seconds, not minutes
# What the client may report for a peer it cannot reach (never an authentication or fault class).
TRANSPORT_ERRORS = ("connection error", "timeout")
COPIED_REPORT = "Copied pfB objects differ from this node's generated objects"
SCOPES = ("policy", "all", "lists")


# --------------------------------------------------------------------------- #
# Pure oracles (pinned off-box in tests/test_issue3455_ha_authority.py)
# --------------------------------------------------------------------------- #


def quiet_window(clock: str) -> str:
    """A Sync-page-valid ``HH:MM-HH:MM`` apply window that starts about three hours after ``clock`` (``HH:MM``).

    Starts on a quarter hour and is one hour long, so the current time is never inside it, midnight included.
    """
    hour, minute = (int(part) for part in clock.split(":"))
    start = ((hour * 60 + minute + 180) // 15 * 15) % 1440
    end = (start + 60) % 1440
    return f"{start // 60:02d}:{start % 60:02d}-{end // 60:02d}:{end % 60:02d}"


def rule_labels(rules: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``label -> row`` of pfB-owned rules as the copied-object detector indexes them (``descr#n``, created/updated dropped)."""
    seen: dict[str, int] = {}
    labels: dict[str, dict[str, Any]] = {}
    for rule in rules:
        row = {key: value for key, value in rule.items() if key not in ("created", "updated")}
        descr = str(row.get("descr", ""))
        seen[descr] = seen.get(descr, -1) + 1
        labels[re.sub(r"[^A-Za-z0-9_. ?-]", "?", descr) + f"#{seen[descr]}"] = row
    return labels


def expected_rule_findings(copied: list[dict[str, Any]], generated: list[dict[str, Any]]) -> dict[str, list[str]]:
    """``label -> differing top-level attributes`` between rules copied from the peer and the ones this node generates.

    Both lists must hold the same rules (same labels): the copy and the node generate one rule set, and only the
    local values may differ. Anything else is a broken premise and raises, never a quiet empty answer.
    """
    have, want = rule_labels(copied), rule_labels(generated)
    if have.keys() != want.keys():
        raise AssertionError(
            f"the copied and the generated pfB rules are not the same rules: only copied {sorted(have.keys() - want.keys())}, "
            f"only generated {sorted(want.keys() - have.keys())}"
        )
    findings: dict[str, list[str]] = {}
    for label, row in have.items():
        differing = sorted(key for key in row.keys() | want[label].keys() if row.get(key) != want[label].get(key))
        if differing:
            findings[label] = differing
    return findings


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def assert_dnsbl_vips(pair: HaPair, when: str) -> None:
    """Each node still owns the DNSBL VIP object its policy refers to (B's has another uniqid than A's, #3441)."""
    for name, vm, expected in (("A", pair.primary, h.SMOKE_VIP_UNIQID), ("B", pair.secondary, B_VIP_UNIQID)):
        owned = php_json(vm, emit("array_column(config_get_path('virtualip/vip', array()), 'uniqid')"))
        assert expected in owned, f"{when}: node {name} lost its DNSBL VIP {expected!r}; its virtual IPs are {owned!r}"


def core_ha_on(pair: HaPair) -> None:
    """Point A's pfSense HA sync (rules, NAT, aliases) at B, as ``ha_pair`` arranged it; a config write, no event."""
    configure_primary_hasync(pair.primary, pair.sync_password)


@pytest.fixture(scope="module")
def baseline(ha_pair: HaPair) -> Baseline:
    """Both nodes at one policy and different local values; A also holds the HA user, so B can send to A (R12).

    The user joins the baseline snapshot, so every per-test reset keeps it. A has no core HA sync target in it: core
    syncs A's rules, NAT and aliases to B after every filter reload of A (the "filter sync" event), and that call
    lands on B at an unpredictable moment, where its stale write of B's config can undo a harness write (a lost DNSBL
    VIP on B, a baseline restore that does not stay). The rows that exercise core's sync call :func:`core_ha_on`.
    """
    configure_secondary_users(ha_pair.primary, ha_pair.sync_password, ha_pair.nopriv_password)
    set_leaves(ha_pair.primary, {"hasync": None}, "pfBlockerNG smoke: HA A without core HA sync")
    base = arrange_baseline(ha_pair)
    reset_pair(ha_pair, base)
    assert_dnsbl_vips(ha_pair, "at the module baseline")
    return base


@pytest.fixture(autouse=True)
def undo(ha_pair: HaPair, baseline: Baseline) -> Iterator[ExitStack]:
    """Per-test undo callbacks first (NIC, CARP, file modes), then both nodes back at the baseline, failing loudly."""
    stack = ExitStack()
    try:
        yield stack
    finally:
        try:
            stack.close()
        finally:
            reset_pair(ha_pair, baseline)
            assert_dnsbl_vips(ha_pair, "after the per-test reset")
            wait_carp_state(ha_pair.primary, "MASTER", node="primary")
            wait_carp_state(ha_pair.secondary, "BACKUP", node="secondary")


# --------------------------------------------------------------------------- #
# Plumbing
# --------------------------------------------------------------------------- #


def show(label: str, value: Any) -> None:
    """Print the record an assertion is about to read (records hold digests, outcomes and counts, never a secret)."""
    print(f"[HA3455] {label}: {json.dumps(value, sort_keys=True, default=str)}", flush=True)


def json_php(value: Any) -> str:
    """A PHP expression that decodes ``value`` (JSON) to an associative array: ``''`` stays ``''``, ``[]`` stays ``array()``."""
    return f"json_decode({h._php_str(json.dumps(value))}, TRUE)"


@contextlib.contextmanager
def guest_webui(vm: SmokeVM) -> Iterator[WebUI]:
    """A logged-in webConfigurator session on ``vm``'s HTTPS port, through an SSH tunnel to the guest's own 443.

    The harness forwards only the guest's port 80, which redirects to HTTPS once the pair serves HTTPS, so a page
    request reaches the real webConfigurator (self-signed certificate) over a tunnel the test closes itself.
    """
    action, password = admin_password_decision(os.environ)
    if action == "fail":
        pytest.fail(password)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    tunnel = subprocess.Popen(
        [
            "ssh",
            "-i",
            vm.ssh_key_path,
            "-p",
            str(vm.ssh_port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "LogLevel=ERROR",
            "-N",
            "-L",
            f"127.0.0.1:{port}:127.0.0.1:443",
            vm.ssh_target,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:

        def listening() -> bool:
            if tunnel.poll() is not None:
                raise RuntimeError(
                    f"ssh tunnel to the guest's HTTPS port exited: rc={tunnel.returncode} {tunnel.stderr and tunnel.stderr.read()!r}"
                )
            with socket.socket() as sock:
                sock.settimeout(2.0)
                return sock.connect_ex(("127.0.0.1", port)) == 0

        h.wait_until(listening, timeout=30.0, interval=0.5)
        client = WebUI(
            host="127.0.0.1",
            port=port,
            username=os.environ.get("SMOKE_ADMIN_USER") or "admin",
            password=password,
            scheme="https",
            verify=False,
        )
        client.login()
        yield client
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            tunnel.kill()


def save_sync_page(client: WebUI, fields: dict[str, str]) -> None:
    """POST the Sync page's save exactly as a browser form submit does: fresh CSRF token, ``save``, then the fields."""
    page = "/pfblockerng/pfblockerng_sync.php"
    form = client.get(page)
    assert not looks_like_login_page(form.text), "GET of the Sync page returned the login form (session lost)"
    data = {"__csrf_magic": extract_csrf_token(form.text), "save": "save", **fields}
    resp = client.session.post(client.url(page), data=data, verify=False, timeout=120.0, allow_redirects=True)
    assert not looks_like_login_page(resp.text), "the Sync page POST returned the login form (session lost)"
    assert resp.status_code == 200, f"Sync page save: expected HTTP 200, got {resp.status_code}"


def policy_payload(vm: SmokeVM) -> dict[str, Any]:
    """The payload ``vm``'s own policy would put on the wire (gate leaf plus projection paths), built the way core does."""
    gate = h._php_str(GATE)
    php = (
        "$normalized = config_get_path('');\n"
        f"array_set_path($normalized, {gate}, 'policy');\n"
        "$sections = array();\n"
        "foreach (pfblockerng_sync_sections(TRUE) as $s) { $sections[$s] = array_get_path($normalized, 'installedpackages/' . $s); }\n"
        f"$paths = array_merge(array({gate}), array_keys(pfb_sync_policy_projection($sections)));\n"
        "$payload = array();\n"
        "foreach ($paths as $p) { array_set_path($payload, $p, array_get_path($normalized, $p, array())); }\n"
        + emit("$payload")
    )
    payload: dict[str, Any] = php_json(vm, php)
    assert payload["installedpackages"]["pfblockerngsync"]["config"][0]["syncscope"] == "policy", (
        f"payload gate leaf: expected 'policy', got {payload['installedpackages']['pfblockerngsync']!r}"
    )
    return payload


def restore_call(pair: HaPair, params: Any, *, user: str = HA_USER, password: str | None = None) -> dict[str, Any]:
    """One single-shot ``restore_config_section`` from A to B; ``params`` is JSON-able or a ready PHP expression (str)."""
    expression = params if isinstance(params, str) else json_php(params)
    return xmlrpc_call(
        pair,
        user=user,
        password=pair.sync_password if password is None else password,
        method="restore_config_section",
        params_php=expression,
    )


def add_group(
    pair: HaPair,
    base: Baseline,
    alias: str,
    address: str,
    *,
    on: SmokeVM,
    tag: str,
    group: dict[str, Any] | None = None,
) -> int:
    """Append one IPv4 deny group to ``on``'s policy (feed files on both nodes); returns its row index."""
    for vm in (pair.primary, pair.secondary):
        write_feed(vm, alias, address)
    rows = list(read_sections(on, ["pfblockernglistsv4"])["pfblockernglistsv4"]["config"])
    rows.append(group or ip_group(alias, feed_path(alias), local=group_local_values(tag, base.gateway)))
    write_sections(on, {"pfblockernglistsv4": {"config": rows}}, f"pfBlockerNG smoke: HA {alias}")
    return len(rows) - 1


def aliasnames(vm: SmokeVM) -> list[str]:
    rows = read_sections(vm, ["pfblockernglistsv4"])["pfblockernglistsv4"]["config"]
    return [str(row["aliasname"]) for row in rows]


def list_a_as_target(pair: HaPair, scope: str) -> None:
    """B's Sync page as stored: manual mode, A's sync IP with the HA user, ``scope`` as B's own scope."""
    section = sender_section(
        "manual", scope=scope, password=pair.sync_password, timeout=SYNC_TIMEOUT, ip=PRIMARY_SYNC_IP
    )
    set_leaves(pair.secondary, {SYNC: section}, "pfBlockerNG smoke: HA B lists A", secret_values=[pair.sync_password])


def receive_from_a(pair: HaPair, base: Baseline, scope: str, alias: str, address: str) -> Sync:
    """B (scope ``scope``, listing A as its manual target) receives a changed policy from A and applies it once."""
    configure_sender(pair, "manual", timeout=SYNC_TIMEOUT)
    list_a_as_target(pair, scope)
    add_group(pair, base, alias, address, on=pair.primary, tag="A")
    sync = sync_once(pair, "manual")
    wait_filter_idle(pair.secondary)
    show("A's send record", sync.send)
    show("B's receive record", sync.receive)
    last = assert_receive(sync, "changed")
    assert_applied_once(sync)
    a_state, b_state = node_state(pair.primary), node_state(pair.secondary)
    moved = diff_leaves(a_state.projection, b_state.projection)
    assert last["accepted_digest"] == a_state.digest == b_state.digest, (
        f"B did not end up holding A's policy: A {a_state.digest}, B accepted {last['accepted_digest']}, "
        f"B stored {b_state.digest}; policy leaves that differ A -> B: {moved!r}; B's send record {send_state(pair.secondary)!r}"
    )
    return sync


def tick_running(vm: SmokeVM) -> bool:
    # Bracketed `[.]` keeps pgrep -f from matching this probe's own shell command line.
    result = vm.ssh("if /bin/pgrep -f 'pfblockerng[.]php tick' >/dev/null 2>&1; then echo tick; fi")
    assert result.returncode == 0, f"tick probe failed: rc={result.returncode} stderr={result.stderr!r}"
    return bool(result.stdout.split())


def wait_tick_gone(vm: SmokeVM) -> None:
    """Block until the receive-spawned tick process has ended (it wrote the record this test already read)."""
    try:
        h.wait_until(lambda: not tick_running(vm), timeout=SETTLE_TIMEOUT, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; a tick process is still running") from exc


def wait_deferred(vm: SmokeVM, *, since: int) -> dict[str, Any]:
    """Block until the tick that the receive spawned wrote ``waiting: outside the apply window`` (its own record)."""
    seen: dict[str, Any] = {}

    def deferred() -> bool:
        seen.clear()
        seen.update(receive_state(vm))
        apply = seen.get("apply") or {}
        return (
            apply.get("opened", 0) >= since
            and apply.get("outcome") == "waiting"
            and apply.get("reason") == "outside the apply window"
        )

    try:
        h.wait_until(deferred, timeout=SETTLE_TIMEOUT, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; last receive record: {seen}") from exc
    return seen


def table_members(vm: SmokeVM, table: str) -> list[str]:
    """Members of a pf table; ``[]`` while the table does not exist."""
    result = vm.ssh(h.PFCTL, "-t", table, "-T", "show")
    if result.returncode != 0 and "does not exist" in result.stderr:
        return []
    assert result.returncode == 0, f"pfctl -t {table} -T show: rc={result.returncode} stderr={result.stderr!r}"
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def enforcement(vm: SmokeVM, alias: str, address: str) -> dict[str, bool]:
    """One probe of the running firewall: is the feed address in the group's table, is a loaded rule using the table."""
    table = f"pfB_{alias}_v4"
    rules = vm.ssh(h.PFCTL, "-sr")
    assert rules.returncode == 0, f"pfctl -sr: rc={rules.returncode} stderr={rules.stderr!r}"
    return {"member": h.member_present(table_members(vm, table), address), "rule": table in rules.stdout}


def log_length(vm: SmokeVM, path: str = SYSTEM_LOG) -> int:
    result = vm.ssh(f"/usr/bin/wc -l < {path}")
    assert result.returncode == 0, f"wc -l {path}: rc={result.returncode} stderr={result.stderr!r}"
    return int(result.stdout.strip())


def log_since(vm: SmokeVM, start: int, path: str = SYSTEM_LOG) -> list[str]:
    """Lines appended to ``path`` after line ``start`` (a count from :func:`log_length`)."""
    result = vm.ssh(f"/usr/bin/tail -n +{start + 1} {path}")
    assert result.returncode == 0, f"tail {path}: rc={result.returncode} stderr={result.stderr!r}"
    return result.stdout.splitlines()


def sync_nic_up(pair: HaPair) -> None:
    """Bring B's sync NIC back and prove A reaches B again (bounded poll: the link has no completion record)."""
    up = pair.secondary.ssh("/sbin/ifconfig", SYNC_NIC, "up")
    assert up.returncode == 0, f"ifconfig {SYNC_NIC} up on B failed: rc={up.returncode} {up.stderr!r}"
    seen: list[dict[str, Any]] = []

    def reachable() -> bool:
        seen[:] = [xmlrpc_call(pair, user=HA_USER, password=pair.sync_password, method="host_firmware_version")]
        return seen[0].get("ok") is True

    try:
        h.wait_until(reachable, timeout=120.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"stuck/environment: B's sync NIC is up but A still cannot reach it: {seen}") from exc
    wait_carp_state(pair.secondary, "BACKUP", node="secondary")


def sync_nic_down(pair: HaPair, undo: ExitStack) -> None:
    """Cut B off the sync link (reversible), flush A's cached ARP entry for B, and prove B is unreachable."""
    undo.callback(sync_nic_up, pair)
    down = pair.secondary.ssh("/sbin/ifconfig", SYNC_NIC, "down")
    assert down.returncode == 0, f"ifconfig {SYNC_NIC} down on B failed: rc={down.returncode} {down.stderr!r}"
    pair.primary.ssh("/usr/sbin/arp", "-d", SECONDARY_SYNC_IP)  # exit 1 when no entry was cached: fine
    probe = xmlrpc_call(pair, user=HA_USER, password=pair.sync_password, method="host_firmware_version")
    assert probe.get("ok") is not True, f"non-vacuity: B still answers A with its sync NIC down: {probe}"
    show("A's probe of the cut-off B", probe)


def restore_carp(pair: HaPair) -> None:
    set_carp_maintenance(pair.primary, False)
    wait_carp_state(pair.primary, "MASTER", node="primary")
    wait_carp_state(pair.secondary, "BACKUP", node="secondary")


def managed_objects(vm: SmokeVM) -> dict[str, list[dict[str, Any]]]:
    """The package-generated config objects, created/updated stamps dropped: pfB_ aliases, pfB_ rules (and the owned subset), pfB_ NAT."""
    php = (
        "$strip = static function (array $rows): array { foreach ($rows as $i => $r) { unset($rows[$i]['created'], $rows[$i]['updated']); } return array_values($rows); };\n"
        "$pick = static function (string $path, string $key): array { return array_values(array_filter(config_get_path($path, array()), static fn ($o) => is_array($o) && str_starts_with((string) ($o[$key] ?? ''), 'pfB_'))); };\n"
        + emit(
            "array("
            "'aliases' => $strip($pick('aliases/alias', 'name')), "
            "'filter' => $strip($pick('filter/rule', 'descr')), "
            "'owned' => $strip(array_values(array_filter($pick('filter/rule', 'descr'), 'pfb_rule_is_pfb_owned'))), "
            "'nat' => $strip($pick('nat/rule', 'descr')))"
        )
    )
    objects: dict[str, list[dict[str, Any]]] = php_json(vm, php)
    return objects


def refused(sync: Sync) -> dict[str, Any]:
    last: dict[str, Any] = sync.receive.get("last") or {}
    assert last.get("outcome") == "refused", f"B's receive record: expected refused, got {last!r}"
    return last


# --------------------------------------------------------------------------- #
# R10: no partial mutation, B shows the refusal, A claims nothing more than "sent"
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(1500)  # a send, a refusal and two rendered Sync pages exceed the suite's 30 s function timeout
def test_invalid_payload_is_refused_whole(ha_pair: HaPair, baseline: Baseline, undo: ExitStack) -> None:
    """Two IPv4 groups with one ``aliasname`` leave A through its real sender and B refuses the whole payload.

    Red when: B stores any part of the payload (its ``installedpackages`` moves), opens an apply record or a tick,
    records anything but ``refused`` with the merge's reason, or shows the refusal as accepted on its Sync page; or A
    claims more than "sent, acceptance unconfirmed", or does not send the invalid policy at all.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    dup = f"pfbha_dup{token()}"
    configure_sender(ha_pair, "manual", timeout=SYNC_TIMEOUT)
    write_feed(a, dup, "198.51.100.31")
    rows = list(read_sections(a, ["pfblockernglistsv4"])["pfblockernglistsv4"]["config"])
    first = len(rows)
    rows += [ip_group(dup, feed_path(dup)), ip_group(dup, feed_path(dup))]
    write_sections(a, {"pfblockernglistsv4": {"config": rows}}, "pfBlockerNG smoke: HA duplicate aliasname")
    before = node_state(b)
    banners = apply_banners(b)
    assert receive_state(b) == {}, f"B starts with a receive record: {receive_state(b)!r}"

    sync = sync_once(ha_pair, "manual")

    digest = node_state(a).digest
    show("A's send record", sync.send)
    show("B's receive record", sync.receive)
    assert_sent(sync, "manual", digest)
    last = refused(sync)
    reason = f"pfb_sync_policy_merge: invalid incoming value at pfblockernglistsv4/*/{first + 1}"
    assert last.get("reason") == reason, f"B's refusal reason: expected {reason!r}, got {last.get('reason')!r}"
    after = node_state(b)
    assert after.installedpackages_sha256 == before.installedpackages_sha256, (
        "B's installedpackages moved under a refused receive"
    )
    assert after.digest == before.digest, f"B's policy digest moved: {before.digest} -> {after.digest}"
    assert sync.receive.get("accepted_digest") is None, f"B holds an accepted digest: {sync.receive!r}"
    assert "apply" not in sync.receive, f"a refusal opened an apply record: {sync.receive.get('apply')!r}"
    assert apply_banners(b) == banners and in_flight(b) == [], "a refused receive started an update pass or tick on B"

    with guest_webui(a) as ui_a:
        page_a = render_sync_page(a, ui_a)
    rows_a = sender_rows(_sender(page_a))
    assert len(rows_a) == 1, f"A's sender panel: expected one attempt row, got {rows_a!r}"
    target, when, shown_digest, result = rows_a[0]
    assert (target, shown_digest, result) == (f"{SECONDARY_SYNC_IP}:443", digest, "sent, acceptance unconfirmed"), (
        f"A's sender panel: expected the sent attempt with A's digest, got {rows_a[0]!r}"
    )
    assert re.fullmatch(TIME, when), f"A's sender panel time: expected a date, got {when!r}"
    claimed = BANNED.search(_sender(page_a))
    assert claimed is None, f"A's sender panel claims {claimed and claimed.group(0)!r} for a call it cannot see through"

    with guest_webui(b) as ui_b:
        receiver = _receiver(render_sync_page(b, ui_b))
    assert_row(receiver, "receive", f"{TIME} {DASH} refused: {re.escape(php_escape(reason))}")
    assert_row(receiver, "incoming", DASH)
    assert_row(receiver, "accepted", DASH)
    assert_row(receiver, "apply", "no apply record")


@pytest.mark.timeout(1800)  # seven XMLRPC round trips, a deliberate login failure pair and one real apply
def test_malformed_and_unauthenticated_requests_change_nothing(
    ha_pair: HaPair, baseline: Baseline, undo: ExitStack
) -> None:
    """Harness requests to B's real endpoint: refused ones leave B untouched, bad credentials never reach the plugin.

    The same request with valid credentials DOES change B (control, last), so none of the "unchanged" results is
    vacuous. Refusals are recorded where the source records them (B's ``last``); an authentication failure writes
    no receive record at all.

    Red when: any malformed, wrong-gate or wrong-typed payload moves B's ``installedpackages``, opens an apply, or is
    recorded as anything but ``refused`` with its path-only reason; a wrong password or an unprivileged user changes
    B's config or writes a receive record; or the control request is not applied.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    alias = f"pfbha_r10{token()}"
    base = policy_payload(a)
    packages = "installedpackages"

    def gated(value: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = json.loads(json.dumps(base))
        payload[packages]["pfblockerngsync"]["config"][0] = {"syncscope": value, **(extra or {})}
        return payload

    def replaced(section: str, value: Any) -> dict[str, Any]:
        payload = json.loads(json.dumps(base))
        payload[packages][section] = value
        return payload

    def quiet_leaf(leaf: Any) -> dict[str, Any]:
        return replaced("pfblockerng", {"config": [{"pfb_quiet_hours": leaf}]})

    refusals: list[tuple[str, dict[str, Any], str]] = [
        ("gate leaf 'all'", gated("all"), "syncscope is not policy"),
        ("gate leaf 'lists'", gated("lists"), "syncscope is not policy"),
        ("gate leaf []", gated([]), "syncscope is not policy"),
        (
            "gate leaf 'all' with varsynconchanges=auto",
            gated("all", {"varsynconchanges": "auto"}),
            "syncscope is not policy",
        ),
        (
            "section that is not an array",
            replaced("pfblockernglistsv4", "text"),
            "pfb_sync_policy_merge: invalid incoming value at pfblockernglistsv4",
        ),
        (
            "non-empty array at a scalar key",
            quiet_leaf({"x": "y"}),
            "pfb_sync_policy_merge: invalid incoming value at pfblockerng/*/0/*",
        ),
        ("non-string leaf", quiet_leaf(5), "pfb_sync_policy_merge: invalid incoming value at pfblockerng/*/0/*"),
    ]
    before = node_state(b)
    banners = apply_banners(b)

    def assert_untouched(label: str) -> None:
        now = node_state(b)
        assert now.installedpackages_sha256 == before.installedpackages_sha256, f"{label}: B's installedpackages moved"
        assert now.digest == before.digest, f"{label}: B's policy digest moved: {before.digest} -> {now.digest}"
        state = receive_state(b)
        assert state.get("accepted_digest") is None and "apply" not in state, (
            f"{label}: B accepted or applied: {state!r}"
        )
        assert apply_banners(b) == banners and in_flight(b) == [], f"{label}: B started an update pass or tick"

    shape = restore_call(ha_pair, "'not-an-array'")
    show("non-array payload", shape)
    assert shape.get("ok") is not True, f"a payload that is not an array was answered as accepted: {shape}"
    assert_untouched("non-array payload")
    assert receive_state(b) == {}, f"a payload that is not an array reached the plugin: {receive_state(b)!r}"

    for label, payload, reason in refusals:
        t0 = node_time(b)
        result = restore_call(ha_pair, payload)
        last = receive_state(b).get("last") or {}
        show(f"{label}: reply {result}, B's last", last)
        assert result.get("ok") is True, f"{label}: core answers a refused policy with True, got {result}"
        assert (last.get("outcome"), last.get("reason")) == ("refused", reason), (
            f"{label}: B's receive record: expected refused with {reason!r}, got {last!r}"
        )
        assert last.get("time", 0) >= t0, f"{label}: B's receive record is stale: {last!r} predates {t0}"
        assert_untouched(label)

    last_before_auth = receive_state(b)
    changed = json.loads(json.dumps(base))
    changed[packages]["pfblockernglistsv4"]["config"].append(ip_group(alias, feed_path(alias)))
    write_feed(a, alias, "198.51.100.32")
    write_feed(b, alias, "198.51.100.32")
    wrong = restore_call(ha_pair, changed, password="not-" + ha_pair.sync_password)
    clear_sshguard(b)
    nopriv = restore_call(ha_pair, changed, user=NOPRIV_USER, password=ha_pair.nopriv_password)
    clear_sshguard(b)
    show("wrong password", wrong)
    show("unprivileged user", nopriv)
    assert wrong.get("fault") == -1, f"wrong password: expected fault -1, got {wrong}"
    assert nopriv.get("fault") == -2, f"user without the HA privilege: expected fault -2, got {nopriv}"
    assert receive_state(b) == last_before_auth, (
        "an authentication failure reached the plugin: B's receive record moved"
    )
    assert_untouched("authentication failure")

    t0 = node_time(b)
    banners = apply_banners(b)
    accepted = restore_call(ha_pair, changed)
    show("control: valid credentials", accepted)
    assert accepted.get("ok") is True, f"control: the valid request was not answered: {accepted}"
    last = receive_state(b).get("last") or {}
    assert last.get("outcome") == "changed" and last.get("time", 0) >= t0, (
        f"control: B's record: expected changed, got {last!r}"
    )
    wait_apply(b, since=t0)
    settle(b)
    wait_filter_idle(b)
    assert alias in aliasnames(b), f"control: B did not store the group {alias}: {aliasnames(b)}"
    assert node_state(b).installedpackages_sha256 != before.installedpackages_sha256, (
        "control: B's installedpackages did not move"
    )


# --------------------------------------------------------------------------- #
# R11 + X5: copied pfB_* rules are reported, never changed
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("inbound", ["different", "equal"])
@pytest.mark.timeout(2400)  # four update passes on B, two HA syncs from A and their reloads
def test_copied_pfb_rules_report_only_real_differences(
    ha_pair: HaPair, baseline: Baseline, undo: ExitStack, inbound: str
) -> None:
    """pfSense HA copies A's pfB_* rules to B; B's next apply reports the copies that are not what it generates.

    B's rule-affecting local values start equal to A's, then (``different``) only B's ``inbound_interface`` differs:
    B must name exactly the copied rules whose ``interface`` differs and nothing else (the oracle compares A's
    copied rules with B's own generated ones), log the notice, and (X5) leave B's generated pfB aliases, rules and
    NAT byte-identical to a run where the detector state was removed. ``equal`` reports nothing.

    Red when: a copy is not reported (or reported with attributes that did not differ), an identical copy is
    reported, the notice line is missing, or the detector's state changes what B generates.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    core_ha_on(ha_pair)  # core's HA sync is the copier under test
    seed_node(b, "A", baseline.gateway)
    if inbound == "different":
        set_leaves(b, {f"{IP}/inbound_interface": "wan"}, "pfBlockerNG smoke: HA B inbound interface")
    h.reload(b, "update", wait_unbound=False)  # B records what it generates
    settle(b)
    wait_filter_idle(b)
    own = managed_objects(b)
    recorded = (read_json_file(b, COPIED_FILE) or {}).get("recorded") or {}
    show("B's own pfB rule interfaces", [(r["descr"], r.get("interface")) for r in own["owned"]])
    assert recorded.get("filter"), f"non-vacuity: B recorded no generated filter rules: {recorded!r}"
    assert own["owned"], "non-vacuity: B generates no pfB-owned rules"
    mark = log_length(b)

    def copy_then_detect() -> dict[str, Any]:
        trigger_send(ha_pair, "automatic")  # core's HA sync: rules, NAT and aliases (A's pfB_* ones included)
        arrived = managed_objects(b)
        assert arrived["aliases"] == managed_objects(a)["aliases"], "B did not receive A's pfB aliases through HA sync"
        assert rule_labels(arrived["owned"]) == rule_labels(managed_objects(a)["owned"]), (
            "B did not receive A's pfB rules through HA sync"
        )
        h.reload(b, "update", wait_unbound=False)
        settle(b)
        wait_filter_idle(b)
        return arrived

    copied = copy_then_detect()
    state = read_json_file(b, COPIED_FILE) or {}
    findings = state.get("findings")
    show("B's copied-object findings", findings)
    notices = [line for line in log_since(b, mark) if COPIED_REPORT in line]
    if inbound == "equal":
        assert not findings, f"B reported identical copies: {findings!r}"
        assert notices == [], f"B logged a copied-object report for identical copies: {notices!r}"
        assert (state.get("recorded") or {}).get("filter"), (
            "non-vacuity: the detector recorded nothing on the equal run"
        )
        return

    expected = expected_rule_findings(copied["owned"], own["owned"])
    # pfb_tracker() hashes the interface (alias + interface + its address and subnet) into the rule's tracker, so a
    # different inbound interface moves both attributes; nothing else may differ.
    assert expected and all(attrs in (["interface"], ["interface", "tracker"]) for attrs in expected.values()), (
        f"premise: the copies and B's own rules must differ in interface (and the tracker derived from it), got {expected!r}"
    )
    assert findings == {"filter": expected}, (
        f"B's findings: expected exactly {{'filter': {expected!r}}}, got {findings!r}"
    )
    assert notices, "B logged no copied-object report"
    assert all(label in notices[0] and "interface" in notices[0] for label in expected), (
        f"the notice line must name every affected rule and the interface attribute: {notices[0]!r}"
    )

    after_finding = managed_objects(b)
    assert json.dumps(after_finding) == json.dumps(own), (
        "a finding changed what B generates: B's pfB aliases/rules/NAT differ from the ones it generated before the copy"
    )
    clean = b.ssh("rm", "-f", COPIED_FILE)
    assert clean.returncode == 0 and read_json_file(b, COPIED_FILE) is None, "pfb_sync_copied.json was not removed"
    mark = log_length(b)
    copy_then_detect()
    quiet = read_json_file(b, COPIED_FILE) or {}
    assert not quiet.get("findings"), f"without recorded state B still reported: {quiet.get('findings')!r}"
    assert (quiet.get("recorded") or {}).get("filter"), (
        "non-vacuity: the detector did not run on the removed-state pass"
    )
    assert [line for line in log_since(b, mark) if COPIED_REPORT in line] == [], "B logged a report without findings"
    without_state = managed_objects(b)
    assert json.dumps(without_state) == json.dumps(after_finding), (
        "B's generated pfB objects differ between a run with the detector finding and one with its state removed"
    )


# --------------------------------------------------------------------------- #
# R12 (+ R14, X2): authority
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.timeout(1500)  # one send, B's receive-triggered apply and B's own (silent) apply
def test_receiver_never_echoes(ha_pair: HaPair, baseline: Baseline, undo: ExitStack, scope: str) -> None:
    """B lists A as a manual target; A's policy reaches B, and B's apply sends nothing back, whatever B's own scope.

    B's own scope is ``policy``, ``all`` or ``lists`` (R14: B in ``lists`` still accepts A's ``policy`` payload; X2).
    The receive is ``changed`` with equal digests, B's own apply pass ran (one update pass) and still B's send record
    does not exist, B's log never shows the sender past its early return, and A's receive record did not move.

    Red when: B echoes (a send record appears on B or its sender log marker does), A's receive record moves, or B
    refuses/ignores A's policy because of its own scope.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    a_receive = receive_state(a)
    sent_before = {n: h.count_log_marker(vm, h.PFB_LOG, SEND_MARKER) for n, vm in (("A", a), ("B", b))}

    receive_from_a(ha_pair, baseline, scope, f"pfbha_e{token()}", "198.51.100.51")

    assert send_state(b) == {}, f"B echoed: its send record exists after a received policy: {send_state(b)!r}"
    assert receive_state(a) == a_receive, f"A's receive record moved: {a_receive!r} -> {receive_state(a)!r}"
    sent_after = {n: h.count_log_marker(vm, h.PFB_LOG, SEND_MARKER) for n, vm in (("A", a), ("B", b))}
    assert sent_after["B"] == sent_before["B"], f"B's log shows its sender ran: {sent_before!r} -> {sent_after!r}"
    assert sent_after["A"] > sent_before["A"], (
        f"non-vacuity: A's own log never shows its sender running, so the marker proves nothing: {sent_before!r} -> {sent_after!r}"
    )
    stored = read_leaves(b, [GATE])[GATE]
    assert stored == scope, f"B's own stored scope: expected {scope!r}, got {stored!r}"


@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.timeout(2400)  # a receive, three apply passes and a second receive on A
def test_sync_page_save_flips_the_role(ha_pair: HaPair, baseline: Baseline, undo: ExitStack, scope: str) -> None:
    """Saving B's Sync page (a real page POST) lets B's next apply send to A, and so does a later local edit.

    Before the save B holds A's accepted policy and stays silent (it would send otherwise: same stored targets,
    same scope). In ``policy`` scope the row first shows that, while A is still the HA primary (core syncs A to B),
    B's send does not show on A: core's XMLRPC server discards a call from the host it syncs to (``xmlrpc.php``
    loop guard). A then leaves the HA primary role (the deliberate flip) and A's receive record advances
    (``unchanged``, then ``changed`` with B's new group, applied once). ``all``/``lists`` use core's
    ``merge_installedpackages_section``, which has no package hook: A shows no receive record, and the evidence is
    B's ``sent`` attempt and A's stored sections equal to B's.

    Red when: the save does not clear B's suppression (B stays silent), B sends before the save, A does not hold
    B's edit afterwards, or (policy) A's record does not carry the digests of what B sent.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    receive_from_a(ha_pair, baseline, scope, f"pfbha_f{token()}", "198.51.100.61")
    assert send_state(b) == {}, f"B sent before the Sync page was saved: {send_state(b)!r}"

    # A's package is a plain receiver for the rest of the row.
    set_leaves(
        a,
        {SYNC: {"syncscope": "policy", "varsynconchanges": "disabled"}},
        "pfBlockerNG smoke: HA A plain receiver",
    )
    if scope == "policy":
        # A is the HA primary again (hasync -> B, the spec's topology): core's XMLRPC server on A drops a call from the
        # host A itself syncs to (xmlrpc.php loop guard), so B's first send below must not show on A.
        core_ha_on(ha_pair)
    fields = {
        "varsynconchanges": "manual",
        "varsynctimeout": str(SYNC_TIMEOUT),
        "syncscope": scope,
        "varsyncprotocol-0": "https",
        "varsyncipaddress-0": PRIMARY_SYNC_IP,
        "varsyncport-0": "443",
        "varsyncusername-0": HA_USER,
        "varsyncpassword-0": ha_pair.sync_password,
        "varsyncdestinenable-0": "on",
    }
    with guest_webui(b) as ui_b:
        save_sync_page(ui_b, fields)
    stored = read_leaves(
        b, [f"{SYNC}/varsynconchanges", GATE, f"{SYNC}/row/0/varsyncipaddress", f"{SYNC}/row/0/varsyncpassword"]
    )
    assert stored[f"{SYNC}/varsynconchanges"] == "manual" and stored[GATE] == scope, (
        f"the Sync page did not store B's mode and scope: {stored[f'{SYNC}/varsynconchanges']!r} {stored[GATE]!r}"
    )
    assert stored[f"{SYNC}/row/0/varsyncipaddress"] == PRIMARY_SYNC_IP, "the Sync page did not store A as B's target"
    assert stored[f"{SYNC}/row/0/varsyncpassword"] == ha_pair.sync_password, (
        "the Sync page stored a different HA password"
    )
    cleared = receive_state(b)
    assert cleared.get("accepted_digest") is None and (cleared.get("last") or {}).get("outcome") == "changed", (
        f"the save must drop B's accepted digest and keep its last record: {cleared!r}"
    )

    def b_sends() -> tuple[int, dict[str, Any]]:
        t0_a = node_time(a)
        h.reload(b, "update", wait_unbound=False)  # B's real apply pass: its sender runs at the end
        settle(b)
        wait_filter_idle(b)
        return t0_a, send_state(b)

    t0_a, sent = b_sends()
    show("B's send record after the save", sent)
    (attempt,) = sent["attempts"]
    assert (attempt["target"], attempt["outcome"]) == (f"{PRIMARY_SYNC_IP}:443", "sent"), f"B's attempt: {attempt!r}"
    b_digest = node_state(b).digest
    if scope == "policy":
        assert attempt.get("digest") == b_digest, f"B's digest: expected {b_digest!r}, got {attempt.get('digest')!r}"
        show("A's receive record while A is the HA primary", receive_state(a))
        assert receive_state(a) == {}, (
            f"core's loop guard should have dropped B's call while A syncs to B, yet A recorded {receive_state(a)!r}"
        )
        # The deliberate flip: A stops being the HA primary, so B's next send is an ordinary call to a receiver.
        set_leaves(a, {"hasync": None}, "pfBlockerNG smoke: HA A leaves the primary role")
        t0_a, sent = b_sends()
        show("B's send record after A left the primary role", sent)
        (attempt,) = sent["attempts"]
        assert (attempt["target"], attempt["outcome"]) == (f"{PRIMARY_SYNC_IP}:443", "sent"), (
            f"B's attempt: {attempt!r}"
        )
        last = receive_state(a).get("last") or {}
        show("A's receive record", receive_state(a))
        assert last.get("outcome") == "unchanged" and last.get("time", 0) >= t0_a, (
            f"A's receive record did not advance: {last!r}"
        )
        assert last.get("incoming_digest") == last.get("accepted_digest") == b_digest, (
            f"A's digests: {last!r} vs B {b_digest!r}"
        )
    else:
        assert "digest" not in attempt, f"a legacy scope sends no digest: {attempt!r}"
        assert receive_state(a) == {}, (
            f"core's merge call has no package hook, yet A recorded a receive: {receive_state(a)!r}"
        )

    alias = f"pfbha_g{token()}"
    add_group(ha_pair, baseline, alias, "198.51.100.62", on=b, tag="B")
    t0_a, sent = b_sends()
    show("B's send record after a local edit", sent)
    (attempt,) = sent["attempts"]
    assert (attempt["target"], attempt["outcome"]) == (f"{PRIMARY_SYNC_IP}:443", "sent"), f"B's attempt: {attempt!r}"
    if scope == "policy":
        wait_apply(a, since=t0_a)
        settle(a)
        wait_filter_idle(a)
        last = receive_state(a).get("last") or {}
        show("A's receive record", receive_state(a))
        assert last.get("outcome") == "changed" and last.get("time", 0) >= t0_a, f"A did not receive B's edit: {last!r}"
        assert node_state(a).digest == node_state(b).digest == attempt.get("digest"), (
            "A's policy is not B's after the edit"
        )
    assert alias in aliasnames(a), f"B's local edit never reached A: A holds {aliasnames(a)}"
    if scope != "policy":
        assert read_sections(a, ["pfblockernglistsv4"]) == read_sections(b, ["pfblockernglistsv4"]), (
            "A's IPv4 groups are not the sections B sent"
        )


@pytest.mark.timeout(1800)  # a receive, a CARP flip, one apply pass and one filter synchronize on B
def test_carp_demotion_leaves_b_silent(ha_pair: HaPair, baseline: Baseline, undo: ExitStack) -> None:
    """With A demoted, B is CARP master and holds A's policy; a B apply pass and B's filter synchronize send nothing.

    Red when: B (now master) originates a send, A's receive record moves, or B's own apply pass did not really run.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    receive_from_a(ha_pair, baseline, "policy", f"pfbha_c{token()}", "198.51.100.71")
    a_receive = receive_state(a)
    undo.callback(restore_carp, ha_pair)
    set_carp_maintenance(a, True)
    wait_carp_state(b, "MASTER", node="secondary")
    wait_carp_state(a, "BACKUP", node="primary")
    banners = apply_banners(b)

    h.reload(b, "update", wait_unbound=False)
    settle(b)
    wait_filter_idle(b)
    synced = b.ssh("/etc/rc.filter_synchronize", timeout=300.0)

    show("A's receive record", receive_state(a))
    assert apply_banners(b) == banners + 1, "non-vacuity: B's own apply pass did not run after the demotion"
    assert synced.returncode == 0, f"rc.filter_synchronize on B failed: rc={synced.returncode} {synced.stderr!r}"
    assert (carp_state(a), carp_state(b)) == ("BACKUP", "MASTER"), "the demotion did not hold through the test"
    assert send_state(b) == {}, f"B originated a send after A was demoted: {send_state(b)!r}"
    assert receive_state(a) == a_receive, f"A received something from B: {a_receive!r} -> {receive_state(a)!r}"


@pytest.mark.timeout(1500)  # one send that waits out a dead target, then B's receive-triggered apply
def test_one_unreachable_target_does_not_block_the_other(ha_pair: HaPair, baseline: Baseline, undo: ExitStack) -> None:
    """Two manual targets on A, the first one dead: the second still updates B and each target has its own outcome.

    Red when: the dead target stops the pass (B is not updated), the record merges the two outcomes, or the failed
    entry carries anything but a transport error class.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    section = sender_section("manual", scope="policy", password=ha_pair.sync_password, timeout=SYNC_TIMEOUT)
    live = section["row"][0]
    section["row"] = [{**live, "varsyncipaddress": DEAD_IP}, live]
    set_leaves(a, {SYNC: section}, "pfBlockerNG smoke: HA two targets", secret_values=[ha_pair.sync_password])
    add_group(ha_pair, baseline, f"pfbha_d{token()}", "198.51.100.81", on=a, tag="A")

    sync = sync_once(ha_pair, "manual")
    wait_filter_idle(b)

    show("A's send record", sync.send)
    digest = node_state(a).digest
    attempts = sync.send.get("attempts") or []
    assert [(x.get("target"), x.get("outcome")) for x in attempts] == [
        (f"{DEAD_IP}:443", "failed"),
        (f"{SECONDARY_SYNC_IP}:443", "sent"),
    ], f"A's per-target outcomes: expected the dead target failed and the live one sent, got {attempts!r}"
    dead, live_attempt = attempts
    assert dead.get("error") in TRANSPORT_ERRORS, f"dead target: expected a transport error class, got {dead!r}"
    assert dead.get("digest") == live_attempt.get("digest") == digest, (
        f"per-target digests: {attempts!r} vs A {digest!r}"
    )
    assert "error" not in live_attempt, f"the reachable target carries an error: {live_attempt!r}"
    assert_receive(sync, "changed", digest)
    assert_applied_once(sync)


# --------------------------------------------------------------------------- #
# R13 / X6: a dead peer
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.timeout(1500)  # a send that fails against a dead peer, then the restore and its reachability proof
def test_unreachable_peer_is_reported_truthfully(
    ha_pair: HaPair, baseline: Baseline, undo: ExitStack, transport: Transport
) -> None:
    """B's sync NIC is down: the manual target records the client's transport error, the automatic path only "handed".

    Red when: a manual attempt reads ``sent`` (or any non-transport class), an automatic run records anything but
    ``handed`` with the digest, pfSense's own failure line is missing, or B's receive record moves.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    configure_sender(ha_pair, transport, timeout=SYNC_TIMEOUT)
    if transport == "automatic":
        core_ha_on(ha_pair)
    b_receive = receive_state(b)
    sync_nic_down(ha_pair, undo)
    mark = log_length(a)

    if transport == "manual":
        h.reload(a, "update", wait_unbound=False)
    else:
        synced = a.ssh("/etc/rc.filter_synchronize", timeout=300.0)
        show(
            "rc.filter_synchronize on A",
            {"rc": synced.returncode, "stdout": synced.stdout[-400:], "stderr": synced.stderr[-400:]},
        )
    send = send_state(a)
    digest = node_state(a).digest
    lines = [line for line in log_since(a, mark) if SECONDARY_SYNC_IP in line or "XMLRPC" in line]
    show("A's send record", send)
    show("A's system log lines about the sync", lines)

    attempts = send.get("attempts") or []
    assert len(attempts) == 1, f"A's send record: expected one attempt, got {send!r}"
    (attempt,) = attempts
    if transport == "manual":
        assert (attempt.get("target"), attempt.get("outcome")) == (f"{SECONDARY_SYNC_IP}:443", "failed"), (
            f"A's attempt: {attempt!r}"
        )
        assert attempt.get("error") in TRANSPORT_ERRORS, (
            f"A's error class: expected one of {TRANSPORT_ERRORS}, got {attempt!r}"
        )
    else:
        assert (attempt.get("target"), attempt.get("outcome")) == ("pfSense HA sync", "handed"), (
            f"automatic transport: A's package may only record handed, got {attempt!r}"
        )
        assert "error" not in attempt, f"a handed attempt carries an error: {attempt!r}"
        assert any("XMLRPC" in line and SECONDARY_SYNC_IP in line for line in lines), (
            f"pfSense's own failure report for the dead peer is missing from A's system log: {lines!r}"
        )
    assert attempt.get("digest") == digest, f"A's digest: expected {digest!r}, got {attempt.get('digest')!r}"
    assert receive_state(b) == b_receive, "B's receive record moved while B was cut off"


# --------------------------------------------------------------------------- #
# X3: accepted configuration versus applied runtime
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode", ["window", "reload-failure"])
@pytest.mark.timeout(2100)  # a receive, the deferred or failed apply, then the recovery pass and its reload
def test_apply_window_defers_and_failure_keeps_pending(
    ha_pair: HaPair, baseline: Baseline, undo: ExitStack, mode: str
) -> None:
    """B holds A's policy (digests equal) while its apply waits (``window``) or fails (``reload-failure``).

    ``window``: A's ``gen/pfb_quiet_hours`` (a policy leaf, so it travels) excludes the current time, B's tick
    writes ``waiting: outside the apply window``. ``reload-failure``: B's firewall reload script is not executable
    (restored by the test), so the apply fails with the pending mark kept. Either way one enforcement probe of the new
    group finds nothing enforced; the control then lets the apply finish and the same probe sees it enforced.

    Red when: B does not store A's policy, the apply record is not the expected one, the pending mark is lost, or the
    group is enforced before the apply could have run.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    alias, address = f"pfbha_x3{token()}", "198.51.100.41"
    configure_sender(ha_pair, "manual", timeout=SYNC_TIMEOUT)
    window = ""
    if mode == "window":
        window = quiet_window(str(php_json(b, emit("date('H:i')"))))
        inside = php_json(b, emit(f"pfb_quiet_hours_in_window(time(), {h._php_str(window)})"))
        assert inside is False, f"premise: the window {window!r} contains the current time on B"
        set_leaves(a, {f"{GEN}/pfb_quiet_hours": window}, "pfBlockerNG smoke: HA apply window")
    else:
        original = b.ssh("/usr/bin/stat", "-f", "%Lp", RELOAD_SCRIPT).stdout.strip()
        assert re.fullmatch(r"[0-7]{3,4}", original), f"could not read the mode of {RELOAD_SCRIPT} on B: {original!r}"

        def restore_script() -> None:
            restored = b.ssh("/bin/chmod", original, RELOAD_SCRIPT)
            assert restored.returncode == 0, f"chmod {original} {RELOAD_SCRIPT} on B failed: {restored.stderr!r}"

        def drop_pending_mark() -> None:
            # The failed apply keeps its pending mark on purpose; the baseline reset settles first, so it must go here.
            dropped = b.ssh("rm", "-f", baseline.marker)
            assert dropped.returncode == 0, f"could not remove B's pending mark: {dropped.stderr!r}"

        undo.callback(drop_pending_mark)
        undo.callback(restore_script)
        locked = b.ssh("/bin/chmod", "a-x", RELOAD_SCRIPT)
        assert locked.returncode == 0, f"chmod of {RELOAD_SCRIPT} on B failed: {locked.stderr!r}"
    add_group(ha_pair, baseline, alias, address, on=a, tag="A")
    banners = apply_banners(b)
    mark = log_length(b)

    sync = sync_once(ha_pair, "manual", wait=False)

    last = assert_receive(sync, "changed")
    digest = node_state(a).digest
    if mode == "window":
        state = wait_deferred(b, since=sync.t0_b)
        wait_tick_gone(b)
        expected = ("waiting", "outside the apply window")
    else:
        state = wait_apply(b, since=sync.t0_b)
        wait_tick_gone(b)
        expected = ("failed", "firewall reload not confirmed; pending changes kept")
    apply = state["apply"]
    show("B's receive record", state)
    show(
        "B's system log lines about the filter",
        [x for x in log_since(b, mark) if re.search(r"filter|reload|XMLRPC", x, re.I)],
    )
    assert (apply.get("outcome"), apply.get("reason")) == expected, (
        f"B's apply record: expected {expected!r}, got {apply!r}"
    )
    assert last["accepted_digest"] == digest == node_state(b).digest, "B's stored policy is not A's"
    if mode == "window":
        assert read_leaves(b, [f"{GEN}/pfb_quiet_hours"])[f"{GEN}/pfb_quiet_hours"] == window, (
            "B did not store A's apply window"
        )
        assert apply_banners(b) == banners, "an update pass ran on B although the apply window is closed"
    else:
        assert apply_banners(b) == banners + 1, (
            "the apply pass did not run on B (the failure must come from its reload)"
        )
    assert in_flight(b) == ["pending"], f"the pending mark must be kept and the tick gone: {in_flight(b)!r}"
    probe = enforcement(b, alias, address)
    show("B's enforcement probe", probe)
    assert probe == {"member": False, "rule": False}, (
        f"B enforces A's group although its apply has not completed: {probe!r}"
    )

    if mode == "window":
        set_leaves(b, {f"{GEN}/pfb_quiet_hours": ""}, "pfBlockerNG smoke: HA open the apply window")
        h.reload(b, "tick", wait_unbound=False)  # the first tick inside the window applies what was kept
    else:
        restore_script()
        h.apply_filter_sync(b)  # the reload pfSense itself performs: the missing step the failed apply reported
    if mode == "window":
        settle(b)
    wait_filter_idle(b)
    control = enforcement(b, alias, address)
    show("B's enforcement probe after the control", control)
    assert control == {"member": True, "rule": True}, (
        f"non-vacuity: the probe does not see the group once it is applied: {control!r}"
    )


# --------------------------------------------------------------------------- #
# X4: feed-header contract and effective findings
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.timeout(2400)  # up to two sends, their receive-triggered apply and one more pass on B
def test_feed_header_contract_and_effective_findings(
    ha_pair: HaPair, baseline: Baseline, undo: ExitStack, transport: Transport
) -> None:
    """A stores a header the apply would normalise and a reserved one; B stores what the producer contract says.

    The producer's apply persists the ``\\W`` strip before the manual send, so B receives ``PfbHeader1``. Core's
    automatic sync reads A's stored config as it is: the raw header is refused whole by B until A's apply has
    normalised it. A reserved name (``DNSBLIP``) passes validation untouched and B's apply skips it: B's findings
    file lists exactly that string, plus the drift string once B's policy is edited locally.

    Red when: B stores a header A's apply did not normalise, accepts the raw header, or its findings differ by one
    character from the contract.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    alias = f"pfbha_h{token()}"
    raw, normalized, reserved = "Pfb Header!1", "PfbHeader1", "DNSBLIP"
    configure_sender(ha_pair, transport, timeout=SYNC_TIMEOUT)
    write_feed(a, f"{alias}r", "198.51.100.92")
    write_feed(b, f"{alias}r", "198.51.100.92")
    group = ip_group(alias, feed_path(alias), local=group_local_values("A", baseline.gateway))
    group["row"] = [
        {**group["row"][0], "header": raw},
        {"header": reserved, "url": feed_path(f"{alias}r"), "state": "Enabled", "format": "auto"},
    ]
    index = add_group(ha_pair, baseline, alias, "198.51.100.91", on=a, tag="A", group=group)
    headers = [f"{V4}/{index}/row/0/header", f"{V4}/{index}/row/1/header"]
    assert read_leaves(a, headers) == dict(zip(headers, [raw, reserved], strict=True)), (
        "premise: A stores the raw headers"
    )

    if transport == "automatic":
        core_ha_on(ha_pair)
        refused_sync = sync_once(ha_pair, "automatic")
        reason = f"pfb_sync_policy_merge: invalid incoming value at pfblockernglistsv4/*/{index}/*/0/*"
        last = refused(refused_sync)
        show("B's receive record for the raw header", refused_sync.receive)
        assert last.get("reason") == reason, (
            f"B's refusal of a raw header: expected {reason!r}, got {last.get('reason')!r}"
        )
        assert alias not in aliasnames(b), "B stored a group whose header A's apply had not normalised"
        # The producer's own apply persists the normalisation. Its filter reload would make core sync by itself (the
        # "filter sync" event), so the pass runs with the HA sync target taken off and put back for the explicit send.
        set_leaves(a, {"hasync": None}, "pfBlockerNG smoke: HA A without core HA sync")
        h.reload(a, "update", wait_unbound=False)
        settle(a)
        wait_filter_idle(a)
        core_ha_on(ha_pair)

    sync = sync_once(ha_pair, transport)
    wait_filter_idle(b)
    show("A's send record", sync.send)
    show("B's receive record", sync.receive)
    digest = node_state(a).digest
    assert read_leaves(a, headers) == dict(zip(headers, [normalized, reserved], strict=True)), (
        "A's apply did not normalise the header"
    )
    assert_sent(sync, transport, digest)
    assert_receive(sync, "changed", digest)
    apply = sync.receive.get("apply") or {}
    assert apply.get("outcome") == "applied", f"B's apply record: expected applied, got {apply!r}"
    show("B's update passes for the receive", sync.passes)
    assert read_leaves(b, headers) == dict(zip(headers, [normalized, reserved], strict=True)), (
        "B did not store the normalised headers"
    )

    skipped = f"Header skipped as reserved: {reserved} (pfblockernglistsv4)"
    findings = read_json_file(b, FINDINGS_FILE) or {}
    show("B's findings", findings)
    assert findings.get("findings") == [skipped], (
        f"B's effective findings: expected exactly {[skipped]!r}, got {findings!r}"
    )

    set_leaves(b, {f"{DNSBL}/top1m_inclusion": "pfbha-incl-local"}, "pfBlockerNG smoke: HA local edit on B")
    h.reload(b, "update", wait_unbound=False)
    settle(b)
    wait_filter_idle(b)
    drifted = read_json_file(b, FINDINGS_FILE) or {}
    show("B's findings after a local edit", drifted)
    expected = [skipped, "Policy changed locally since the last accepted receive"]
    assert drifted.get("findings") == expected, (
        f"B's findings after a local edit: expected exactly {expected!r}, got {drifted!r}"
    )
