"""ADR-65 live-VM smoke rows: fail-loud + self-heal (SS7 checklist row (b)).

ADR-65 makes the DNSBL manifest the single source of truth for Python-mode DNSBL
and retires the interchange-file (``pfb_py_data.txt``/``pfb_py_zone.txt``) grep
that used to attribute a block. These rows automate SS7's manual-smoke checklist
for the delta a real box can prove and an off-appliance harness cannot. Issue #4053
removed the query channel and the block-page hit, so rows (a) and (c) are gone:

* **D3** (``test_manifest_absent_fails_loud_and_force_reload_self_heals``): an
  absent manifest yields NO stale block, a widget-visible open ledger entry, and
  a GUI notice -- then a Force Reload self-heals (block resumes, ledger closes).

Plus one teardown-contract row (``test_notice_teardown_closes_every_row_of_its_id``,
issue #2478): the module's notice teardown drains EVERY row carrying its id, so the
next case's before-state is genuinely clean.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

_MANIFEST_PATH = "/var/unbound/pfb_py_sources.json"
_MANIFEST_NOTICE_ID = "pfBlockerNG DNSBL"


@pytest.fixture(scope="module")
def adr65_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for this module.

    Mirrors ``test_smoke_adr40.py``'s ``adr40_vm``: egress stays OPEN throughout
    (each ``CaseContext`` manages its own per-case block); ``inject()`` writes a
    SINGLE-element DNSBL list config (replacing, not appending), so no other feed
    ever competes for egress during a reload here.

    ``use_system_dns_upstream`` forwards Unbound to the runner-side ``stub_dns`` mock
    (issue #3321): under the per-case egress block a non-blocked name otherwise has
    no reachable upstream and hangs until Unbound gives up, so the manifest-absent
    probes only passed when an earlier module had left forwarding on.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# dnsbl.log helpers. ONE path only: pfB-DNS writes dnsbl.log on the host; the
# chroot copy an older package's nullfs mount exposed was the SAME file, so
# grepping both would count every line twice, which an exact-count assertion
# (this module pins "the query adds NO line") cannot tolerate.
# --------------------------------------------------------------------------- #


def _unbound_pid(vm: SmokeVM, *, timeout: float = 30.0) -> str:
    """Current Unbound PID ('' when it is not running)."""
    res = vm.ssh("pgrep -x unbound || true", timeout=timeout)
    return res.stdout.strip().split("\n")[0].strip()


def _restart_unbound(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Restart Unbound through pfSense's own service path and wait for the NEW process to
    serve DNS -- RAISE loudly on timeout.

    ``services_unbound_configure()`` restarts asynchronously. Waiting for "unbound-control
    answers" or even "some answer comes back" is NOT enough: the OUTGOING process keeps
    serving during the gap, satisfies the check, and then dies under the next query (that
    is precisely how the CI legs failed with "could not send or receive"). So pin the
    handover: the PID must CHANGE, and the new process must answer a throwaway name --
    never the name under test, whose first post-restart answer must stay authoritative.
    """
    before = _unbound_pid(vm)
    res = h.php_eval(vm, "services_unbound_configure();\necho 'OK';", timeout=timeout)
    if res.returncode != 0 or "OK" not in res.stdout:
        raise RuntimeError(
            f"_restart_unbound: services_unbound_configure failed: rc={res.returncode} "
            f"stdout={res.stdout!r} stderr={res.stderr!r}"
        )
    h.wait_unbound_ready(vm)

    ready_name = h.unique_domain("adr65ready")
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        now = _unbound_pid(vm)
        if now and now != before:
            try:
                h.dns_probe(vm, ready_name)
                return
            except RuntimeError as exc:
                last = str(exc)
        else:
            last = f"pid still {now!r} (was {before!r})"
        time.sleep(2.0)
    raise AssertionError(f"Unbound never handed over to a new, answering process within {timeout:.0f}s: {last}")


def _wait_resolver_answers(vm: SmokeVM, *, deadline_s: float = 120.0) -> None:
    """Block until the resolver answers again -- RAISE loudly on timeout.

    Used after a DNSBL update pass, which can also leave the resolver briefly unreachable
    on the CI boxes. Queries a THROWAWAY name so the name under test keeps its first
    authoritative answer (a readiness gate, never a poll for an expected value).
    """
    ready_name = h.unique_domain("adr65ready")
    deadline = time.monotonic() + deadline_s
    last = ""
    while time.monotonic() < deadline:
        try:
            h.dns_probe(vm, ready_name)
            return
        except RuntimeError as exc:
            last = str(exc)
            time.sleep(2.0)
    raise AssertionError(f"resolver never answered again within {deadline_s:.0f}s: {last}")


def _sync_status_list_open(
    vm: SmokeVM, *, dnsbldir: str = "/var/unbound", timeout: float = 60.0
) -> list[dict[str, Any]]:
    """The widget's own ledger reader: pfb_py_sync_status_list_open($pfb['dnsbldir'])."""
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        f"echo '<<<L>>>' . json_encode(pfb_py_sync_status_list_open({h._php_str(dnsbldir)})) . '<<<LE>>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    start, end = out.find("<<<L>>>"), out.find("<<<LE>>>")
    if res.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(
            f"pfb_py_sync_status_list_open failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )
    data = json.loads(out[start + len("<<<L>>>") : end])
    assert isinstance(data, list), f"expected a JSON list from pfb_py_sync_status_list_open, got {data!r}"
    return data


def _manifest_failure_notice_fired(vm: SmokeVM, *, timeout: float = 60.0) -> bool:
    """Call the production epilogue function that raises the GUI notice for an open
    manifest parse-stage ledger entry (pfblockerng.inc:8954)."""
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        "$fired = pfb_dnsbl_manifest_failure_notice();\n"
        "echo '<<<N>>>' . ($fired ? '1' : '0') . '<<<NE>>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    start, end = out.find("<<<N>>>"), out.find("<<<NE>>>")
    if res.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(
            f"pfb_dnsbl_manifest_failure_notice() call failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )
    return out[start + len("<<<N>>>") : end] == "1"


def _count_matching_notices(vm: SmokeVM, needle: str, *, timeout: float = 120.0) -> int:
    """How many get_notices() rows carry ``needle`` -- mirrors test_software_update's
    count_matching_notices (module-local copy; this module imports no other test module)."""
    snippet = (
        "$n = 0;\n"
        "foreach ((get_notices() ?: []) as $row) {\n"
        f"  if (strpos((string)($row['notice'] ?? ''), {h._php_str(needle)}) !== FALSE) {{ $n++; }}\n"
        "}\n"
        "echo '<<<NC>>>' . $n . '<<<NCE>>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    start, end = out.find("<<<NC>>>"), out.find("<<<NCE>>>")
    if res.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(
            f"count_matching_notices({needle!r}) failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )
    return int(out[start + len("<<<NC>>>") : end])


def _close_all_notices(vm: SmokeVM, notice_id: str, *, timeout: float = 60.0) -> None:
    """Close EVERY notice carrying ``notice_id`` -- teardown, leaves the VM clean.

    ``close_notice($id)`` removes ONE row per call -- the first row in queue order carrying
    that id -- and ``file_notice`` appends a timestamp-keyed row per call without replacing
    an earlier row of the same id, so a single call leaves every later row standing (issue
    #2478, the ``pfBlockerNG`` sibling of #2465). Close by timestamp key, one call per
    matching row, then re-count: the teardown is its own oracle and raises if any row of
    ``notice_id`` survives.
    """
    snippet = (
        "foreach ((get_notices() ?: []) as $key => $row) {\n"
        f"  if ((string)($row['id'] ?? '') === {h._php_str(notice_id)}) {{ close_notice($key); }}\n"
        "}\n"
        "$left = 0;\n"
        "foreach ((get_notices() ?: []) as $row) {\n"
        f"  if ((string)($row['id'] ?? '') === {h._php_str(notice_id)}) {{ $left++; }}\n"
        "}\n"
        "echo '<<<NL>>>' . $left . '<<<NLE>>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    start, end = out.find("<<<NL>>>"), out.find("<<<NLE>>>")
    if res.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(
            f"_close_all_notices({notice_id!r}) failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )
    left = int(out[start + len("<<<NL>>>") : end])
    if left != 0:
        raise RuntimeError(f"_close_all_notices left {left} notice(s) with id {notice_id!r} standing")


def _file_two_notice_rows(vm: SmokeVM, notice_id: str, notice: str, *, timeout: float = 60.0) -> None:
    """File TWO queue rows carrying ``notice_id`` and ``notice``.

    ``file_notice`` keys each row by timestamp and bumps the key while one is taken, so
    two calls in the same second still yield two rows; the caller's ``== 2`` precondition
    fails loudly if that ever stops holding.
    """
    snippet = (
        f"file_notice({h._php_str(notice_id)}, {h._php_str(notice)});\n"
        f"file_notice({h._php_str(notice_id)}, {h._php_str(notice)});\n"
        "echo '<<<NF>>>OK<<<NFE>>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    if res.returncode != 0 or "<<<NF>>>OK<<<NFE>>>" not in out:
        raise RuntimeError(
            f"file_notice({notice_id!r}) failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )


@pytest.mark.timeout(300)  # six pfSsh.php round-trips exceed the smoke tier's 30s default
def test_notice_teardown_closes_every_row_of_its_id(smoke_vm: SmokeVM) -> None:
    """The teardown drains EVERY row carrying our id, not just the oldest (issue #2478).

    pfSense's ``close_notice($id)`` removes ONE row per call -- the first row in queue
    order carrying that id -- and ``file_notice`` appends a timestamp-keyed row per call
    without de-duplicating by id, so a two-row queue survives a single close. Five
    production sites file the ``pfBlockerNG DNSBL`` id (the ``pfblockerng.inc`` VIP
    notice, manifest-not-loaded x3, raw-generation publish failure), so this module's
    teardown routinely faces more than one row.
    """
    needle = f"adr65 teardown probe {h.unique_domain('adr65notice')}"
    assert _count_matching_notices(smoke_vm, needle) == 0, f"probe needle {needle!r} was already in the queue"

    try:
        _file_two_notice_rows(smoke_vm, _MANIFEST_NOTICE_ID, needle)
        filed = _count_matching_notices(smoke_vm, needle)
        assert filed == 2, f"expected both filed probe rows to be queued, got {filed}"

        _close_all_notices(smoke_vm, _MANIFEST_NOTICE_ID)
        left = _count_matching_notices(smoke_vm, needle)
        assert left == 0, f"the teardown left {left} probe row(s) standing"
    finally:
        _close_all_notices(smoke_vm, _MANIFEST_NOTICE_ID)


@pytest.mark.timeout(300)  # a full DNSBL update pass + the swap-applied wait exceeds the smoke tier's 30s default
def test_manifest_absent_fails_loud_and_force_reload_self_heals(adr65_vm: SmokeVM) -> None:
    """ADR-65 D3: an absent DNSBL manifest yields NO stale block, a widget-visible
    open ledger entry, and a GUI notice -- then a Force Reload self-heals.

    Given: a unique domain VIP-blocks while the manifest is healthy (before-state).
    When: the manifest file is deleted and Unbound is raw-bounced (``init()`` re-runs
      ``dnsbl_build_from_manifest`` against the now-absent file -- opens a 'parse'
      ledger entry, D3's fail-loud arm); the domain no longer answers the VIP or
      NULL block shape (no stale serve); the widget's own status reader shows the
      open ledger entry; and the production ``pfb_dnsbl_manifest_failure_notice()``
      fires a GUI notice naming it.
    Then: unblocking egress + a Force Reload rebuilds the manifest -- the domain
      VIP-blocks again AND the ledger entry is gone (closed on success, ADR §2.3).
    """
    domain = h.unique_domain("adr65heal")
    feed = h.write_local_feed(adr65_vm, "adr65_heal.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="adr65heal", feed_url=feed, header="adr65healhdr")

    try:
        with h.CaseContext(adr65_vm, spec):
            # BEFORE: the domain blocks while the manifest is healthy.
            answer = h.dns_probe(adr65_vm, domain)
            assert h.is_null_ip(answer), f"expected null for {domain!r} before breaking the manifest, got {answer!r}"

            # BREAK: delete the manifest, then restart the DNSBL host so init() re-runs
            # dnsbl_build_from_manifest against the now-absent file: pfB-DNS while it
            # hosts the module (#3770), else Unbound.
            rm = adr65_vm.ssh(f"rm -f {_MANIFEST_PATH}")
            assert rm.returncode == 0, f"failed to remove {_MANIFEST_PATH}: rc={rm.returncode} stderr={rm.stderr!r}"
            if not h.restart_pfb_dns_if_hosting_dnsbl(adr65_vm):
                _restart_unbound(adr65_vm)

            # NO STALE BLOCK: with the manifest absent, DNSBL is empty, so the domain
            # forwards to the stub_dns mock (adr65_vm) and must come back as its
            # non-block sentinel -- never the VIP or NULL block shape.
            broken = h.dns_probe(adr65_vm, domain)
            assert h.resolves_to(broken, h.STUB_DNS_A), (
                f"expected the stub_dns sentinel {h.STUB_DNS_A} for {domain!r} with the manifest absent "
                f"(no stale serve, ADR-65 D3), got {broken!r}"
            )

            # WIDGET OUT-OF-SYNC: the manifest's own status reader shows the open
            # parse-stage ledger entry for pfb_py_sources.json.
            entries = _sync_status_list_open(adr65_vm)
            parse_entries = [
                e
                for e in entries
                if e.get("stage") == "parse" and os.path.basename(str(e.get("item", ""))) == "pfb_py_sources.json"
            ]
            assert parse_entries, f"expected an open parse-stage ledger entry for pfb_py_sources.json: {entries!r}"

            # FILE_NOTICE: the production epilogue function fires the GUI notice.
            fired = _manifest_failure_notice_fired(adr65_vm)
            assert fired, "pfb_dnsbl_manifest_failure_notice() did not report firing a notice"
            matching = _count_matching_notices(adr65_vm, "DNSBL manifest not loaded")
            assert matching >= 1, f"expected a get_notices() row containing 'DNSBL manifest not loaded', got {matching}"

            # SELF-HEAL: unblock egress (the update pass needs it) and Force Reload --
            # this regenerates the manifest via pfb_unbound_python_sources.
            h.unblock_egress()
            # data_path=True waits on the zero-downtime swap-applied signal (and RAISES if
            # it never appears). The default only polls `unbound-control status`, which the
            # restart already satisfied -- the probe would race the module's rebuild.
            h.reload(adr65_vm, "updatednsbl", data_path=True)
            # The no-stale-block probe above cached the mock's sentinel answer for this
            # exact name; a feed allow->block is TTL-bounded by design, so clear that one
            # cached answer to observe the swapped block inside the test window.
            h.flush_unbound_name(adr65_vm, domain)
            # The update pass can leave the resolver briefly unreachable on the CI boxes too
            # (same async-restart gap as above) -- gate on a real answer before the probe
            # whose value we assert.
            _wait_resolver_answers(adr65_vm)

            healed = h.dns_probe(adr65_vm, domain)
            assert h.is_null_ip(healed), f"expected null for {domain!r} again after the self-heal, got {healed!r}"

            entries_after = _sync_status_list_open(adr65_vm)
            parse_after = [
                e
                for e in entries_after
                if e.get("stage") == "parse" and os.path.basename(str(e.get("item", ""))) == "pfb_py_sources.json"
            ]
            assert not parse_after, (
                f"expected the parse-stage ledger entry for pfb_py_sources.json to be CLOSED "
                f"after the self-heal, still open: {parse_after!r}"
            )
    finally:
        _close_all_notices(adr65_vm, _MANIFEST_NOTICE_ID)


# --------------------------------------------------------------------------- #
# Row (c): a real sinkhole hit attributes via the query channel; the widget
# counter increments by exactly the observed event count (ADR-65 D4).
# --------------------------------------------------------------------------- #
