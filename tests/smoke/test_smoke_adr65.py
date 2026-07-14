"""ADR-65 live-VM smoke rows: the read-only query channel, fail-loud + self-heal,
and webserver-hit widget attribution (SS7 checklist rows (a)-(c)).

ADR-65 makes the DNSBL manifest the single source of truth for Python-mode DNSBL
and retires the interchange-file (``pfb_py_data.txt``/``pfb_py_zone.txt``) grep
that used to attribute a block. These rows automate SS7's manual-smoke checklist
for the three accepted deltas a real box can prove and an off-appliance harness
cannot (the query channel only answers on a live matcher):

* **D4 + Semantic 3** (``test_query_channel_verdict_matches_block_with_no_side_effects``):
  ``pfb_dnsbl_query()`` mirrors a real block's group/feed exactly, and the query
  itself adds NO dnsbl.log line, NO counter bump, NO ``dnsblcache`` row -- proven
  by a second, independent real block (an ordering barrier) whose own effects are
  the only ones that land after the query.
* **D3** (``test_manifest_absent_fails_loud_and_force_reload_self_heals``): an
  absent manifest yields NO stale block, a widget-visible open ledger entry, and
  a GUI notice -- then a Force Reload self-heals (block resumes, ledger closes).
* **D4** (``test_vip_hit_increments_widget_counter_with_query_group``): a real
  sinkhole (VIP block-page) hit attributes via the SAME query channel the DNS
  path uses, and its widget counter increments by exactly the observed event count.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Iterator
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

_MANIFEST_PATH = "/var/unbound/pfb_py_sources.json"
_DNSBL_SQLITE = "/var/unbound/pfb_py_dnsbl.sqlite"
_DNSBL_CACHE_DB = "/var/unbound/pfb_py_cache.sqlite"
_UNBOUND_PY_DATA = "/var/unbound/pfb_py_data.txt"
_UNBOUND_PY_ZONE = "/var/unbound/pfb_py_zone.txt"
_MANIFEST_NOTICE_ID = "pfBlockerNG DNSBL"


@pytest.fixture(scope="module")
def adr65_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for this module + inject the DNSBL sinkhole VIP.

    Mirrors ``test_smoke_adr40.py``'s ``adr40_vm``: egress stays OPEN throughout
    (each ``CaseContext`` manages its own per-case block); ``inject()`` writes a
    SINGLE-element DNSBL list config (replacing, not appending), so no other feed
    ever competes for egress during a reload here.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# dnsbl.log helpers. ONE path only: pfb_unbound_include.inc nullfs-mounts
# /var/log/pfblockerng rw at {chroot}/var/log/pfblockerng, so the chroot path is
# the SAME file -- grepping both counts every line twice, which an exact-count
# assertion (this module pins "the query adds NO line") cannot tolerate.
# --------------------------------------------------------------------------- #

_DNSBL_LOG_PATHS = ("/var/log/pfblockerng/dnsbl.log",)


def _dnsbl_log_hits(vm: SmokeVM, needle: str, *, timeout: float = 30.0) -> int:
    """Count dnsbl.log lines containing ``needle`` across host + chroot paths (summed)."""
    res = vm.ssh("grep", "-hcF", "--", needle, *_DNSBL_LOG_PATHS, timeout=timeout)
    return sum(int(tok) for tok in res.stdout.split() if tok.isdigit())


def _dnsbl_log_line(vm: SmokeVM, needle: str, *, timeout: float = 30.0) -> str:
    """First dnsbl.log line (host or chroot) containing ``needle``; raises loudly if none."""
    res = vm.ssh("grep", "-hF", "--", needle, *_DNSBL_LOG_PATHS, timeout=timeout)
    lines = [ln for ln in res.stdout.splitlines() if ln]
    if not lines:
        raise RuntimeError(
            f"no dnsbl.log line found for {needle!r}: rc={res.returncode} stdout={res.stdout!r} stderr={res.stderr!r}"
        )
    return lines[0]


# --------------------------------------------------------------------------- #
# Per-group dnsbl SQLite counter -- mirrors test_smoke_upstream_block's
# _read_upstream_counter (busyTimeout, absent-vs-error distinction), parametrized
# on the group instead of the fixed 'Upstream' row.
# --------------------------------------------------------------------------- #

_CTR_OPEN, _CTR_CLOSE = "<<<ADR65CTR>>>", "<<<ADR65CTREND>>>"


def _parse_counter_output(out: str) -> tuple[int, str]:
    start, end = out.find(_CTR_OPEN), out.find(_CTR_CLOSE)
    if start == -1 or end == -1:
        return -2, f"no delimited counter in pfSsh.php output: {out[-500:]!r}"
    payload = out[start + len(_CTR_OPEN) : end]
    if "|" not in payload:
        return -2, f"unparsable counter payload (no '|' separator): {payload!r}"
    value_str, _, message = payload.partition("|")
    try:
        return int(value_str), message
    except ValueError:
        return -2, f"non-integer counter value {value_str!r} in payload {payload!r}"


def _read_group_counter(vm: SmokeVM, group: str, *, timeout: float = 60.0) -> tuple[int, str]:
    """Read the on-box dnsbl SQLite 'counter' for ``groupname = group``.

    Returns ``(-1, "")`` absent, ``(-2, detail)`` errored, else ``(counter, "")``.
    """
    snippet = (
        "$__c = -1; $__m = '';\n"
        "try {\n"
        f"    $__db = new SQLite3({h._php_str(_DNSBL_SQLITE)});\n"
        "    $__db->enableExceptions(TRUE);\n"
        "    $__db->busyTimeout(15000);\n"
        f"    $__g = $__db->escapeString({h._php_str(group)});\n"
        "    $__r = $__db->querySingle(\"SELECT counter FROM dnsbl WHERE groupname = '{$__g}'\");\n"
        "    if ($__r === NULL) { $__c = -1; }\n"
        "    elseif ($__r === FALSE) { $__c = -2; $__m = 'querySingle returned FALSE'; }\n"
        "    else { $__c = (int) $__r; }\n"
        "    try { $__db->close(); } catch (Throwable $__ignored) {}\n"
        "} catch (Throwable $__e) { $__c = -2; $__m = $__e->getMessage(); }\n"
        f"echo '{_CTR_OPEN}' . $__c . '|' . $__m . '{_CTR_CLOSE}';\n"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    if res.returncode != 0:
        return -2, f"php_eval failed (rc={res.returncode}): stderr={res.stderr[-500:]!r}"
    return _parse_counter_output(res.stdout or "")


def _wait_group_counter_at_least(
    vm: SmokeVM, group: str, target: int, *, timeout: float = 30.0, poll: float = 2.0
) -> tuple[int, str]:
    """Poll the group's counter until it is >= ``target`` or the deadline expires.

    The counter flush rides the async db_worker thread, so a freshly-logged
    block does not appear instantly. Returns the final observed value (may be
    below ``target`` on timeout -- the caller asserts).
    """
    deadline = time.monotonic() + timeout
    current: tuple[int, str] = (-1, "")
    while time.monotonic() < deadline:
        current = _read_group_counter(vm, group)
        if current[0] >= target:
            return current
        time.sleep(poll)
    return current


# --------------------------------------------------------------------------- #
# dnsblcache row count -- a plain busyTimeout'd SQLite3 read (no package opener
# needed: this is a read-only count, not the render-verify harness's guarded
# write probe).
# --------------------------------------------------------------------------- #

_CACHE_OPEN, _CACHE_CLOSE = "<<<ADR65CACHE>>>", "<<<ADR65CACHEEND>>>"


def _cache_row_count(vm: SmokeVM, domain: str, *, timeout: float = 60.0) -> int:
    snippet = (
        "$__n = -1;\n"
        "try {\n"
        f"    $__db = new SQLite3({h._php_str(_DNSBL_CACHE_DB)});\n"
        "    $__db->enableExceptions(TRUE);\n"
        "    $__db->busyTimeout(15000);\n"
        f"    $__d = $__db->escapeString({h._php_str(domain)});\n"
        "    $__r = $__db->querySingle(\"SELECT COUNT(*) FROM dnsblcache WHERE domain = '{$__d}'\");\n"
        "    $__n = ($__r === FALSE || $__r === NULL) ? -2 : (int) $__r;\n"
        "    try { $__db->close(); } catch (Throwable $__ignored) {}\n"
        "} catch (Throwable $__e) { $__n = -2; }\n"
        f"echo '{_CACHE_OPEN}' . $__n . '{_CACHE_CLOSE}';\n"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    start, end = out.find(_CACHE_OPEN), out.find(_CACHE_CLOSE)
    if res.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(
            f"_cache_row_count({domain!r}) failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )
    return int(out[start + len(_CACHE_OPEN) : end])


def _query_domain(vm: SmokeVM, domain: str, *, timeout: float = 60.0) -> dict[str, Any]:
    """Call the ADR-65 read-only query channel (pfb_dnsbl_query) for ``domain``."""
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        f"$v = pfb_dnsbl_query({h._php_str(domain)});\n"
        "echo '<<<Q>>>' . json_encode($v) . '<<<QE>>>';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    out = res.stdout or ""
    start, end = out.find("<<<Q>>>"), out.find("<<<QE>>>")
    if res.returncode != 0 or start == -1 or end == -1:
        raise RuntimeError(
            f"pfb_dnsbl_query({domain!r}) php_eval failed: rc={res.returncode} stdout={out!r} stderr={res.stderr!r}"
        )
    verdict = json.loads(out[start + len("<<<Q>>>") : end])
    assert isinstance(verdict, dict), f"expected a JSON object from pfb_dnsbl_query, got {verdict!r}"
    return verdict


# --------------------------------------------------------------------------- #
# Row (a): the query channel is decision-equal and side-effect-free
# (ADR-65 D4 + Semantic 3; folds in the D1 no-interchange-files assert).
# --------------------------------------------------------------------------- #


def test_query_channel_verdict_matches_block_with_no_side_effects(adr65_vm: SmokeVM) -> None:
    """ADR-65 D4 + Semantic 3: pfb_dnsbl_query mirrors a real block, with ZERO query side effects.

    Given: two unique domains share one feed; domain1 is the query subject,
    domain2 is a later real block used as an ORDERING BARRIER -- its own log
    line / counter bump / cache row bound how far any query side effect (if
    one existed) could have propagated by the time it settles.

    When: domain1 is drilled on-box (the real block -- writes exactly one
    dnsbl.log line and bumps its group's counter), then ``pfb_dnsbl_query``
    asks the same question over the read-only channel.

    Then: the query verdict's group/feed equal the log line's own group/feed
    byte-for-byte, AND after domain2's real block settles, domain1's own
    log-hit count / counter / cache-row count are UNCHANGED from their
    real-block values -- the query added nothing.
    """
    domain1 = h.unique_domain("adr65q1")
    domain2 = h.unique_domain("adr65q2")
    feed = h.write_local_feed(adr65_vm, "adr65_query.txt", f"{domain1}\n{domain2}\n")
    spec = h.DnsblCase(aliasname="adr65query", feed_url=feed, header="adr65queryhdr", mode=h.DnsblMode.VIP)

    with h.CaseContext(adr65_vm, spec):
        # BEFORE: neither domain has ever been logged.
        assert _dnsbl_log_hits(adr65_vm, domain1) == 0, f"{domain1} already in dnsbl.log before listing"
        assert _dnsbl_log_hits(adr65_vm, domain2) == 0, f"{domain2} already in dnsbl.log before listing"

        # Real block #1 (the query subject): domain1.
        answer1 = h.dns_probe(adr65_vm, domain1)
        assert h.is_vip(answer1), f"expected VIP block for {domain1!r}, got {answer1!r}"

        deadline = time.monotonic() + 30.0
        hits1 = 0
        while time.monotonic() < deadline:
            hits1 = _dnsbl_log_hits(adr65_vm, domain1)
            if hits1 >= 1:
                break
            time.sleep(1.0)
        assert hits1 == 1, f"expected exactly one dnsbl.log line for {domain1}, got {hits1}"

        line1 = _dnsbl_log_line(adr65_vm, domain1)
        fields1 = line1.split(",")
        assert len(fields1) > 8, f"unexpected dnsbl.log line shape for {domain1}: {line1!r}"
        group1, feed1 = fields1[6], fields1[8]
        assert group1, f"empty group parsed from dnsbl.log line: {line1!r}"

        c1, detail1 = _wait_group_counter_at_least(adr65_vm, group1, 0)
        assert c1 >= 0, f"could not read the {group1!r} counter after {domain1}'s block: {detail1}"

        # THE QUERY: same domain, read-only channel.
        verdict = _query_domain(adr65_vm, domain1)
        assert verdict["blocked"] is True, f"expected blocked=true for {domain1!r}, got {verdict!r}"
        assert verdict["group"] == group1, (
            f"query group {verdict['group']!r} != dnsbl.log group {group1!r} for {domain1!r} (line: {line1!r})"
        )
        assert verdict["feed"] == feed1, (
            f"query feed {verdict['feed']!r} != dnsbl.log feed {feed1!r} for {domain1!r} (line: {line1!r})"
        )

        cache1_before_barrier = _cache_row_count(adr65_vm, domain1)
        assert cache1_before_barrier == 1, (
            f"expected exactly one dnsblcache row for {domain1} right after its own block, got {cache1_before_barrier}"
        )

        # BARRIER: a real block for domain2 (SAME group -- one feed, one list) --
        # its own log line + counter bump + cache row bound how far the query's
        # side effects (if any) could have reached by the time it settles.
        answer2 = h.dns_probe(adr65_vm, domain2)
        assert h.is_vip(answer2), f"expected VIP block for {domain2!r}, got {answer2!r}"

        deadline = time.monotonic() + 30.0
        hits2 = 0
        c2 = c1
        cache2 = 0
        while time.monotonic() < deadline:
            hits2 = _dnsbl_log_hits(adr65_vm, domain2)
            c2, _ = _read_group_counter(adr65_vm, group1)
            cache2 = _cache_row_count(adr65_vm, domain2)
            if hits2 >= 1 and c2 >= c1 + 1 and cache2 >= 1:
                break
            time.sleep(1.0)
        assert hits2 == 1, f"expected exactly one dnsbl.log line for {domain2}, got {hits2}"
        assert c2 == c1 + 1, (
            f"expected group {group1!r} counter to be EXACTLY {c1 + 1} after {domain2}'s block "
            f"(baseline {c1} included domain1's own increment) -- got {c2}: the query between them "
            "must not have added its own increment"
        )
        assert cache2 >= 1, f"expected a dnsblcache row for {domain2} after its real block, got {cache2}"

        # ZERO-SIDE-EFFECT (Semantic 3): domain1's own hit-count/cache-row are
        # UNCHANGED by the query that ran between its block and domain2's block.
        hits1_after = _dnsbl_log_hits(adr65_vm, domain1)
        assert hits1_after == 1, (
            f"expected {domain1}'s dnsbl.log hit count to stay 1 after the query, got {hits1_after} "
            "-- pfb_dnsbl_query must add no log line (ADR-65 Semantic 3)"
        )
        cache1_after = _cache_row_count(adr65_vm, domain1)
        assert cache1_after == 1, (
            f"expected exactly one dnsblcache row for {domain1}, got {cache1_after} "
            "-- pfb_dnsbl_query must add no dnsblcache row (ADR-65 Semantic 3)"
        )

        # D1 fold-in (RESULTS/06 carry-forward): the retired interchange files are
        # never (re)written by this update pass.
        for retired in (_UNBOUND_PY_DATA, _UNBOUND_PY_ZONE):
            check = adr65_vm.ssh(f"test -f {retired} && echo PRESENT || echo ABSENT")
            assert "ABSENT" in check.stdout, (
                f"ADR-65 D1: {retired} unexpectedly present after an update pass -- the retired "
                f"interchange file must never be (re)written: {check.stdout!r}"
            )


# --------------------------------------------------------------------------- #
# Row (b): manifest-absent fails loud + self-heals on Force Reload (ADR-65 D3).
# --------------------------------------------------------------------------- #


def _raw_bounce_unbound(vm: SmokeVM, *, timeout: float = 90.0) -> None:
    """Kill + restart Unbound directly (mirrors helpers.py's raw-bounce block used by
    ``inject_safesearch_cname_entries``) so ``init()`` re-runs against the just-edited
    on-disk manifest state.

    Fed to ``/bin/sh`` on stdin (never the ``ssh_argv`` one-arg convention): pfSense
    root's login shell is tcsh, which mangles ``$(...)``/for-loops -- feeding a POSIX
    script on stdin to an explicit ``/bin/sh`` sidesteps it entirely.
    """
    bounce_cmd = (
        "kill -TERM $(cat /var/run/unbound.pid)\n"
        "for i in $(seq 1 30); do\n"
        "  pgrep -x unbound >/dev/null || break\n"
        "  sleep 1\n"
        "done\n"
        "/usr/local/sbin/unbound -c /var/unbound/unbound.conf\n"
    )
    bounce = subprocess.run(
        vm.ssh_argv("/bin/sh"), input=bounce_cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    if bounce.returncode != 0:
        raise RuntimeError(f"_raw_bounce_unbound: Unbound bounce failed: rc={bounce.returncode} {bounce.stderr!r}")
    h.wait_unbound_ready(vm)


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
        "foreach (get_notices() as $row) {\n"
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


def _close_notice(vm: SmokeVM, notice_id: str, *, timeout: float = 60.0) -> None:
    """Close every notice carrying ``notice_id`` -- best-effort teardown, leaves the VM clean."""
    h.php_eval(vm, f"close_notice({h._php_str(notice_id)});\necho 'OK';", timeout=timeout)


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
    spec = h.DnsblCase(aliasname="adr65heal", feed_url=feed, header="adr65healhdr", mode=h.DnsblMode.VIP)

    try:
        with h.CaseContext(adr65_vm, spec):
            # BEFORE: the domain blocks while the manifest is healthy.
            answer = h.dns_probe(adr65_vm, domain)
            assert h.is_vip(answer), f"expected VIP block for {domain!r} before breaking the manifest, got {answer!r}"

            # BREAK: delete the manifest, then raw-bounce Unbound so init() re-runs
            # dnsbl_build_from_manifest against the now-absent file.
            rm = adr65_vm.ssh(f"rm -f {_MANIFEST_PATH}")
            assert rm.returncode == 0, f"failed to remove {_MANIFEST_PATH}: rc={rm.returncode} stderr={rm.stderr!r}"
            _raw_bounce_unbound(adr65_vm)

            # NO STALE BLOCK: with the manifest absent, DNSBL is empty -- egress is
            # blocked inside CaseContext, so the honest expectation for a domain that
            # is no longer matched is a non-block-shaped answer (SERVFAIL/NXDOMAIN
            # both satisfy it -- there is no upstream to resolve it either way).
            broken = h.dns_probe(adr65_vm, domain)
            assert not h.is_vip(broken) and not h.is_null_ip(broken), (
                f"expected a non-block answer for {domain!r} with the manifest absent "
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
            # raw bounce already satisfied -- the probe would race the module's rebuild.
            h.reload(adr65_vm, "updatednsbl", data_path=True)

            healed = h.dns_probe(adr65_vm, domain)
            assert h.is_vip(healed), f"expected VIP block for {domain!r} again after the self-heal, got {healed!r}"

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
        _close_notice(adr65_vm, _MANIFEST_NOTICE_ID)


# --------------------------------------------------------------------------- #
# Row (c): a real sinkhole hit attributes via the query channel; the widget
# counter increments by exactly the observed event count (ADR-65 D4).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)  # sinkhole bind poll + block-page hit + log/counter settle exceed the 30s default
def test_vip_hit_increments_widget_counter_with_query_group(adr65_vm: SmokeVM) -> None:
    """ADR-65 D4: a real sinkhole (VIP block-page) hit attributes via the query
    channel, and its widget counter increments by exactly the observed event count.

    Given: a unique domain VIP-blocks (writes the Python-side dnsbl.log line).
    When: ``pfb_dnsbl_query`` records the expected group/feed BEFORE any HTTP hit
      (independent of the hit itself), then a real on-box curl to the sinkhole
      VIP with ``Host: domain`` triggers the PHP-side lighttpd-log daemon
      (``pfb_log_event``), which re-attributes via the SAME query channel.
    Then: the webserver-hit (host) dnsbl.log gains >=1 "DNSBL-Full," line for the
      domain whose group/feed equal the query's expected values (neither
      'Unknown' -- NULL/blocked=false both rewrite to 'Unknown', so a correct
      group is real evidence the query answered), AND the widget counter for
      that group increases by EXACTLY the observed line count (pfb_log_event
      increments once per event line, dup or not).
    """
    domain = h.unique_domain("adr65vip")
    feed = h.write_local_feed(adr65_vm, "adr65_vip.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="adr65vip", feed_url=feed, header="adr65viphdr", mode=h.DnsblMode.VIP)

    # scope="update" (not the default "updatednsbl"): only a FULL update pass
    # provisions the sinkhole NAT/lighttpd-conf/restart -- test_dnsbl_block_page.py
    # documents the same split.
    with h.CaseContext(adr65_vm, spec, scope="update"):
        answer = h.dns_probe(adr65_vm, domain)
        assert h.is_vip(answer), f"expected VIP block for {domain!r}, got {answer!r}"

        verdict = _query_domain(adr65_vm, domain)
        assert verdict["blocked"] is True, f"expected blocked=true for {domain!r}, got {verdict!r}"
        expected_group, expected_feed = verdict["group"], verdict["feed"]
        assert expected_group and expected_group != "Unknown", (
            f"expected a real (non-Unknown) group from pfb_dnsbl_query({domain!r}), got {verdict!r}"
        )

        c0, detail0 = _wait_group_counter_at_least(adr65_vm, expected_group, 0)
        assert c0 >= 0, f"could not read the baseline counter for group {expected_group!r}: {detail0}"

        curl_argv = (
            h.GUEST_CURL,
            "-sS",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "-H",
            f"Host: {domain}",
            f"http://{h.DEFAULT_DNSBL_VIP4}/",
        )
        attempts, delay = 10, 1.5  # lighttpd's post-fork bind is normally sub-second; generous headroom
        result: subprocess.CompletedProcess[str] | None = None
        for attempt in range(attempts):
            result = adr65_vm.ssh(*curl_argv, timeout=15.0)
            if result.returncode == 0 and "Site blocked via DNSBL" in result.stdout:
                break
            if attempt < attempts - 1:
                time.sleep(delay)
        assert result is not None  # attempts >= 1, loop always assigns

        if result.returncode != 0 or "Site blocked via DNSBL" not in result.stdout:
            diag = adr65_vm.ssh(
                "ps auxww | grep -i '[l]ighttpd_pfb'; "
                "/usr/bin/sockstat -4 -l 2>/dev/null | grep -E ':80([[:space:]]|$)' || echo NO_LISTENER",
                timeout=15.0,
            )
            pytest.fail(
                f"sinkhole curl never succeeded after {attempts} attempts: "
                f"rc={result.returncode} stderr={result.stderr!r}\n"
                f"lighttpd_pfb/:80 snapshot (rc={diag.returncode}):\n{diag.stdout}{diag.stderr}"
            )

        deadline = time.monotonic() + 30.0
        n = 0
        first_line = ""
        while time.monotonic() < deadline:
            res_lines = adr65_vm.ssh("grep", "-hF", "--", "DNSBL-Full,", "/var/log/pfblockerng/dnsbl.log", timeout=15.0)
            matching = [ln for ln in res_lines.stdout.splitlines() if ln and domain in ln]
            n = len(matching)
            if n >= 1:
                first_line = matching[0]
                break
            time.sleep(2.0)
        assert n >= 1, f"expected >=1 'DNSBL-Full,' host dnsbl.log line for {domain}, found {n}"

        fields = first_line.split(",")
        assert len(fields) > 8, f"unexpected webserver-hit dnsbl.log line shape: {first_line!r}"
        group_seen, feed_seen = fields[6], fields[8]
        assert group_seen == expected_group and group_seen != "Unknown", (
            f"webserver-hit log group {group_seen!r} != query group {expected_group!r} for {domain!r} "
            f"(line: {first_line!r})"
        )
        assert feed_seen == expected_feed and feed_seen != "Unknown", (
            f"webserver-hit log feed {feed_seen!r} != query feed {expected_feed!r} for {domain!r} "
            f"(line: {first_line!r})"
        )

        c_after, detail_after = _wait_group_counter_at_least(adr65_vm, expected_group, c0 + n)
        assert c_after == c0 + n, (
            f"expected group {expected_group!r} counter to be EXACTLY {c0 + n} (baseline {c0} + "
            f"{n} observed 'DNSBL-Full,' line(s)), got {c_after} ({detail_after})"
        )
