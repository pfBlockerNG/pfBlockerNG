"""issue #2832 — appliance-tier pfblockerng.php verb deferral exit-code smoke tests.

A static source oracle over pfblockerng.php cannot be trusted (PR #2826 fooled five
review rounds); the exit-code contract for a lost scheduler dispatcher-lock race can
only be pinned by RUNNING the real CLI on a real appliance. Covers, against the REAL
guest CLI:

1. All 11 verbs sharing `pfb_extras_process_begin()`'s guard exit 1 while another
   process holds `/usr/local/etc/pfb_schedule_dispatch.lock`, with BOTH diagnostics
   present (the main log line + a `NOTICE [pfBlockerNG]` syslog line).
2. The `scheduled` argv bypass for all 8 verbs that read it (dc/dcc/bu/al/asn/
   asn_shell/bl/bls): neither diagnostic fires, and each reaches its own real,
   verb-specific logic with a deterministic outcome.
3. Releasing the lock: dc/dcc (each establishing its own contended before-state
   first) no longer defer, and their real GeoIP pipeline completes deterministically.

External hosts a scheduled run can legitimately reach (MaxMind, the default TOP1M
provider, ipinfo.io) are NXDOMAIN-stubbed via the existing controlled-DNS smoke
infrastructure (`stub_dns` + `helpers.use_system_dns_upstream`), so every real
network attempt stays hermetic and deterministic — never a live third-party call.

Dispatch: scripts/local-smoke.sh --filter "test_extras_dispatcher_deferral"
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import NamedTuple

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

_PHP = h.PHP_BIN
_PFB_PHP = h.PFB_CLI
# General pfSense system log; ADR-38's dedicated pfblockerng_syslog.log deliberately
# excludes ordinary logger() notices, so this plain global logger() call lands here
# like any other package's syslog line.
_SYSTEM_LOG = "/var/log/system.log"
_EXTRAS_LOG = f"{h.PFB_LOGDIR}/extras.log"

# The real cross-process lock pfb_extras_process_begin() contends on
# (pfblockerng_extra.inc default `schedule_state_dir` = '/usr/local/etc'; nothing in
# production ever overrides it, so this IS the real appliance path).
_LOCK_PATH = "/usr/local/etc/pfb_schedule_dispatch.lock"
_HOLDER = "/tmp/pfb_smoke_dispatch_lock_holder.php"
_READY = "/tmp/pfb_smoke_dispatch_lock_ready"
_STOP = "/tmp/pfb_smoke_dispatch_lock_stop"
_PIDFILE = "/tmp/pfb_smoke_dispatch_lock_holder.pid"
_HOLDER_OUT = "/tmp/pfb_smoke_dispatch_lock_holder.out"

# Real on-box lock holder: a raw flock on the SAME path pfb_schedule_dispatch_begin()
# opens (a bare fopen()+flock(), unlike the feed-pass lock's pfb_feed_pass_acquire()
# helper). Bounded acquisition (LOCK_EX|LOCK_NB retried for 10s, not an unconditional
# blocking flock) and an explicit LOCK_UN+fclose BEFORE the ready marker is removed,
# so a caller polling for that removal never races the actual release. Self-terminating
# (120s deadline) so an orphaned holder can never wedge the box.
_HOLDER_PHP = f"""<?php
$fp = fopen('{_LOCK_PATH}', 'c');
if (!is_resource($fp)) {{
    fwrite(STDOUT, "OPEN_FAILED\\n");
    exit(2);
}}
$deadline = microtime(true) + 10.0;
$locked = false;
while (microtime(true) < $deadline) {{
    if (flock($fp, LOCK_EX | LOCK_NB)) {{
        $locked = true;
        break;
    }}
    usleep(50000);
}}
if (!$locked) {{
    fwrite(STDOUT, "LOCK_FAILED\\n");
    exit(3);
}}
touch('{_READY}');
for ($i = 0; $i < 1200 && !file_exists('{_STOP}'); $i++) {{
    usleep(100000);
}}
flock($fp, LOCK_UN);
fclose($fp);
@unlink('{_READY}');
"""

# The guard's two sinks (issue #2592). Severity is asserted alongside the message
# (F3): pfSense's real syslog line format is `<ts> <host> php[<pid>]: NOTICE
# [pfBlockerNG] <message>` — a message-only match would still pass if LOG_NOTICE
# regressed to LOG_ERR/LOG_WARNING, since both land in the same file.
_MAIN_LOG_LINE = "Extras process deferred: dispatcher lock unavailable."
_SYSLOG_SEVERITY_AND_MESSAGE = (
    "NOTICE [pfBlockerNG] Feed pass [ extras ] deferred - the scheduler dispatcher lock is unavailable."
)

# pfblockerng.php's 11 verb labels sharing the `pfb_extras_process_begin()` guard.
ALL_VERBS = ("dc", "dcc", "bu", "al", "asn", "asn_shell", "bl", "bls", "uc", "gc", "ugc")
# The 8 siblings that read a `scheduled` argv[2] and skip the guard entirely (the
# parent tick already owns the lock); uc/gc/ugc take no such argument.
SCHEDULED_VERBS = ("dc", "dcc", "bu", "al", "asn", "asn_shell", "bl", "bls")

# External hosts a scheduled verb can legitimately try to reach; NXDOMAIN-stubbed so
# none of them ever leaves the guest for real.
_MAXMIND_HOST = "download.maxmind.com"
_TOP1M_HOST = "tranco-list.eu"  # PfbTop1mSource default provider (pfblockerng_extra.inc)
_ASN_HOST = "ipinfo.io"
_NXDOMAIN_HOSTS = (_MAXMIND_HOST, _TOP1M_HOST, _ASN_HOST)
_ERROR_LOG = f"{h.PFB_LOGDIR}/error.log"
# The dispatcher-lock deferral's guest-side search-domain fallback is read live
# from /etc/resolv.conf per-fixture (see _guest_search_domain) rather than
# hardcoded here: the WAN DHCP lease that supplies it is environment-specific.


class _ScheduledExpectation(NamedTuple):
    """A `<verb> scheduled` outcome under this fixture, VERIFIED by running the real
    CLI (not inferred from source structure — the exact failure mode #2832 exists to
    guard against). ``sink``/``marker`` distinguish real post-guard execution from an
    unrecognized-command no-op; empty ``marker`` (bl/bls) relies on that SAME test's
    own before-state contended-standalone check instead of a distinct log line."""

    rc: int
    sink: str
    marker: str


_SCHEDULED_EXPECTATIONS: dict[str, _ScheduledExpectation] = {
    # dc: pfb_filter(PFB_FILTER_URL) itself resolves the host as part of validation --
    # NXDOMAIN fails it BEFORE pfb_download_fetch() ever reaches curl, logged (case 2)
    # to error.log AND main log; the distinct, unambiguous line lives in error.log.
    "dc": _ScheduledExpectation(1, _ERROR_LOG, "Invalid URL (cannot resolve)"),
    # dcc: with database_cc=on (see deployed_vm's cred_fields) AND empty MaxMind
    # credentials, pfblockerng_uc_countries() never runs at all (pfblockerng.inc:
    # 3326, pfblockerng.php:372) -- verified against the real appliance below.
    "dcc": _ScheduledExpectation(0, _EXTRAS_LOG, "Download Process Starting"),
    # bu/asn/asn_shell: credential/token-less early `return` before any network call.
    "bu": _ScheduledExpectation(0, h.PFB_LOG, "Terminating MaxMind download due to invalid Account or Key"),
    "asn": _ScheduledExpectation(0, h.PFB_LOG, "ASN Token not defined. Terminating Download."),
    "asn_shell": _ScheduledExpectation(0, h.PFB_LOG, "ASN Token not defined. Terminating Download."),
    # al: no early-return guard at all; always reaches pfblockerng_download_extras().
    # Its URL passes pfb_filter(PFB_FILTER_URL) syntactically, so it fails one gate
    # later, at pfb_feed_host_allowed()'s resolve step (extras.log, logtype 3). No
    # exit() call on this path either way, so rc=0 is a structural fact, not a
    # success claim.
    "al": _ScheduledExpectation(0, _EXTRAS_LOG, "feed host did not resolve"),
    # bl/bls: credential-less fast path (no Blacklist Category selected) is a silent
    # `break` with no exit() call -- deterministic rc=0. No distinct downstream log
    # marker exists on this path, so the test itself (not a sibling) first proves
    # bl/bls is a real recognized verb via a same-test contended-standalone check.
    "bl": _ScheduledExpectation(0, "", ""),
    "bls": _ScheduledExpectation(0, "", ""),
}

_JSON_OPEN, _JSON_CLOSE = "<<<PFBSECTION>>>", "<<<PFBSECTIONEND>>>"


def _capture_section(vm: SmokeVM, path: str) -> str:
    """Whole config section as a base64'd JSON blob (array-safe -- config_get_state
    is scalar-only, but DNS settings like `system/dnsserver` are arrays)."""
    snippet = f"echo '{_JSON_OPEN}' . base64_encode(json_encode(config_get_path('{path}', array()))) . '{_JSON_CLOSE}';"
    result = h.php_eval(vm, snippet)
    assert result.returncode == 0, (
        f"capture of config section {path!r} failed: rc={result.returncode} {result.stderr!r}"
    )
    out = result.stdout
    start, end = out.find(_JSON_OPEN), out.find(_JSON_CLOSE)
    assert start != -1 and end != -1, f"capture of config section {path!r}: no delimited value in {out!r}"
    return out[start + len(_JSON_OPEN) : end]


def _restore_section(vm: SmokeVM, path: str, b64_blob: str) -> None:
    """Restore a whole config section from a :func:`_capture_section` blob.

    A corrupt/truncated blob makes `json_decode()` return `NULL`; `?? array()`
    would then silently substitute an EMPTY array and write THAT over the whole
    live section instead of failing before any write. Validated explicitly here
    (`is_array()`, matching PHP's own truthy-empty-array quirk safely) so a
    decode failure aborts loudly instead of erasing unrelated config.
    """
    snippet = (
        f"$__pfb_restore = json_decode(base64_decode('{b64_blob}'), true);\n"
        "if (!is_array($__pfb_restore)) { echo 'DECODE_FAILED'; exit; }\n"
        f"config_set_path('{path}', $__pfb_restore);\n"
        "write_config('pfBlockerNG smoke: restore DNS config section');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    assert result.returncode == 0 and "OK" in result.stdout and "DECODE_FAILED" not in result.stdout, (
        f"restore of config section {path!r} failed -- possibly a corrupt capture blob, refused "
        f"rather than risk writing an empty array over live config: rc={result.returncode} "
        f"{result.stderr!r} {result.stdout!r}"
    )


def _capture_stub_records(stub: _StubDnsServer, names: Iterable[str]) -> dict[str, "dict[str, object] | None"]:
    """Snapshot the CURRENT record (or the sentinel ``None``) for each name, keyed
    by its normalized FQDN, for a later :func:`_restore_stub_records`.

    ``stub_dns`` is session-scoped (shared with any other module that also requests
    it); a blanket ``clear_cname()`` on teardown erases every OTHER name's override
    too, not just this fixture's own (gate-probed: an unrelated A record reverted to
    the stub's sentinel default after `clear_cname()`). Restoring exactly what was
    there before -- including "nothing" -- is the only safe teardown.
    """
    with stub._lock:
        return {stub._fqdn(name): stub._records.get(stub._fqdn(name)) for name in names}


def _restore_stub_records(stub: _StubDnsServer, snapshot: dict[str, "dict[str, object] | None"]) -> None:
    """Restore exactly the records :func:`_capture_stub_records` observed."""
    with stub._lock:
        for fqdn, rec in snapshot.items():
            if rec is None:
                stub._records.pop(fqdn, None)
            else:
                stub._records[fqdn] = rec


def _set_registered_toggle(vm: SmokeVM, key: str, *, on: bool) -> None:
    """Write a registered PfbConfig toggle field through its typed system-context
    gateway (``PfbConfig::writeSystem``) rather than a raw ``config_set_path`` --
    matching how the SAME field is written in production (pfblockerng.inc's
    registered read/write adapters), so this fixture can never drift from that
    canonical stored representation if either adapter's validation changes.
    Precedent: ``helpers.set_feed_sanity`` uses the identical pattern for another
    registered toggle.
    """
    value = "PfbToggle::On" if on else "PfbToggle::Off"
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        f"PfbConfig::writeSystem('{key}', {value});\n"
        "write_config('pfBlockerNG smoke: set registered field');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"_set_registered_toggle({key!r}, on={on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
    )


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy once; route DNS to the controlled stub; pin a credential-less config.

    NXDOMAINs every external host a scheduled verb can legitimately reach so a real
    fetch fails FAST and DETERMINISTICALLY through the guest's REAL resolver path —
    never a live third-party call. Every altered piece of state (DNS config
    sections, credential fields, the stub's per-name overrides) is captured before
    ANY mutation and restored EXACTLY in `finally` — including when setup itself
    fails partway — and the resolver is re-resynced (services_unbound_configure +
    wait_unbound_ready), not just config.xml, so a later module never inherits a
    live DNS path still pointed at this fixture's (by-then-stopped) stub.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)

    dns_sections = ("system", "unbound")
    # Unregistered credential fields -- no PfbConfig entry exists for these
    # (confirmed against pfb_cfg_registry()), so a raw config_set/config_get_state
    # round-trip IS the canonical representation; there is no adapter to bypass.
    raw_fields = {
        f"{h.CFG_IP_SETTINGS}/maxmind_key": "",
        f"{h.CFG_IP_SETTINGS}/maxmind_account": "",
        f"{h.CFG_IP_SETTINGS}/asn_token": "",
    }
    # Registered PfbConfig toggle fields -- written through the SAME typed
    # system-context gateway (`PfbConfig::writeSystem`) production code uses
    # (precedent: helpers.set_feed_sanity does the identical thing for another
    # registered toggle), not a raw config_set_path, so this fixture can never
    # drift from the canonical stored representation if either adapter's
    # validation changes. (registry key, config.xml path for capture/restore, on)
    registered_toggle_fields = (
        ("dnsbl/top1m_enable", f"{h.CFG_DNSBL_SETTINGS}/top1m_enable", False),
        # dcc's release-test rc depends on pfblockerng_uc_countries() (the MaxMind
        # locale CSV conversion) never running at all: with empty MaxMind
        # credentials AND this ON, pfblockerng.php's dc/dcc arm (pfblockerng.inc:
        # 3326, pfblockerng.php:372) skips the conversion call outright. An
        # earlier fixture revision instead moved the real locale CSV file aside
        # on disk and restored it afterward -- a whole class of filesystem-
        # mutation bugs (byte/metadata loss, ambiguous partial-failure states
        # under a transport failure mid-move) that using this EXISTING, already-
        # supported toggle avoids by construction: nothing on the guest's
        # filesystem is ever touched.
        ("ip/database_cc", f"{h.CFG_IP_SETTINGS}/database_cc", True),
    )
    cred_paths = tuple(raw_fields) + tuple(path for _, path, _ in registered_toggle_fields)
    dns_originals = [(section, _capture_section(smoke_vm, section)) for section in dns_sections]
    cred_originals = [(path, h.config_get_state(smoke_vm, path)) for path in cred_paths]
    stub_snapshot: dict[str, "dict[str, object] | None"] = {}

    def _restore_all() -> None:
        """Run EVERY independent restore step even when an earlier one raises --
        a linear abort here would skip the resolver resync and stub-record
        restore whenever a DNS/credential restore failed, leaving the shared VM
        pointed at this fixture's test DNS/stub state for whatever runs next.
        Accumulates every failure and raises them together at the end.
        """
        errors: list[Exception] = []
        for section, blob in dns_originals:
            try:
                _restore_section(smoke_vm, section, blob)
            except Exception as exc:  # noqa: BLE001 -- collected, not swallowed; see raise below
                errors.append(exc)
        for path, state in cred_originals:
            try:
                h.config_restore_state(smoke_vm, path, state)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        try:
            # Config sections alone are the PERSISTED state; the resolver only
            # applies them on its own reload. Re-run the same resync
            # use_system_dns_upstream() performs so the box's EFFECTIVE DNS path
            # is restored too.
            resync = h.php_eval(smoke_vm, "services_unbound_configure(); echo 'OK';")
            assert resync.returncode == 0 and "OK" in resync.stdout, (
                f"DNS resync after restore failed: rc={resync.returncode} {resync.stderr!r} {resync.stdout!r}"
            )
            h.wait_unbound_ready(smoke_vm)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        try:
            _restore_stub_records(stub_dns, stub_snapshot)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        if errors:
            raise ExceptionGroup(f"{len(errors)} independent teardown step(s) failed", errors)

    try:
        h.use_system_dns_upstream(smoke_vm)
        search_domain = _guest_search_domain(smoke_vm)
        for host in _NXDOMAIN_HOSTS:
            names = (host, f"{host}.{search_domain}") if search_domain else (host,)
            for name in names:
                stub_snapshot.update(_capture_stub_records(stub_dns, (name,)))
                stub_dns.register_nxdomain(name)
                # Unbound is a CACHING resolver; an earlier query for this exact name
                # (e.g. a package post-install connectivity check) could have cached an
                # answer before the NXDOMAIN registration above took effect. Flush it so
                # the verification below is never fooled by a stale cache entry.
                h.flush_unbound_name(smoke_vm, name)
        for host in _NXDOMAIN_HOSTS:
            # gethostbyname()'s "unchanged" return proves NOTHING by itself about
            # WHY the lookup failed -- SERVFAIL and every other resolver failure
            # mode return the input unchanged too. Pair it with the RCODE the
            # stub actually sent, via the SAME on-box resolver path (Unbound at
            # 127.0.0.1, matching how gethostbyname() itself resolves), to prove
            # this specific host is genuinely NXDOMAIN before trusting anything
            # downstream on that assumption.
            answer = h.dns_probe(smoke_vm, host, "A")
            assert h.is_nxdomain(answer), (
                f"{host} must resolve NXDOMAIN via the guest's real resolver path for this "
                f"fixture to be hermetic -- got rcode={answer.rcode!r} records={answer.records!r}"
            )
            # gethostbyname() rides the SAME real PHP/libc resolver path curl's
            # default resolver uses (unlike `drill` above, which can take a
            # different path); it returns the input unchanged on failure.
            # Delimited: pfSsh.php prints a startup banner before any echoed output.
            snippet = f"echo '{_JSON_OPEN}' . gethostbyname('{host}') . '{_JSON_CLOSE}';"
            check = h.php_eval(smoke_vm, snippet)
            out = check.stdout
            start, end = out.find(_JSON_OPEN), out.find(_JSON_CLOSE)
            assert start != -1 and end != -1, f"gethostbyname({host!r}) probe: no delimited value in {out!r}"
            resolved = out[start + len(_JSON_OPEN) : end]
            assert resolved == host, (
                f"{host} must resolve to NXDOMAIN via the guest's real resolver path for "
                f"this fixture to be hermetic; gethostbyname returned {resolved!r} (a real "
                f"answer or the stub's unregistered-name sentinel, either way not NXDOMAIN)"
            )
        for path, value in raw_fields.items():
            h.config_set(smoke_vm, path, value)
        for key, _cfg_path, on in registered_toggle_fields:
            _set_registered_toggle(smoke_vm, key, on=on)
    except Exception:
        _restore_all()
        raise

    try:
        yield smoke_vm
    finally:
        _restore_all()
        h.collect_host_diagnostics(smoke_vm)


def _guest_search_domain(vm: SmokeVM) -> str:
    """The guest's actual DNS search-domain suffix from /etc/resolv.conf (empty if
    none). Read live rather than hardcoded: the WAN DHCP lease that supplies it is
    environment-specific, not a fixed constant of this harness."""
    result = vm.ssh("awk '/^search /{print $2; exit}' /etc/resolv.conf")
    return result.stdout.strip()


def _guest_file_exists(vm: SmokeVM, path: str) -> bool:
    """Whether ``path`` exists on the guest -- a BOUNDED probe (5s, well under the
    15s poll-loop budgets that call this) accepting only `test`'s own 0/1 exit
    codes. An SSH transport failure (255) is NEITHER "true" NOR "false" -- it means
    this probe learned nothing, and treating it as "gone" could let cleanup remove
    marker files and declare a lock holder released while the real process is
    still live and unobserved.
    """
    result = vm.ssh("test", "-f", path, timeout=5.0)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"file-exists probe for {path!r} got rc={result.returncode} (not test's own 0/1 -- "
            f"likely an SSH transport failure): {result.stderr!r}"
        )
    return result.returncode == 0


def _pid_alive(vm: SmokeVM, pid: str) -> bool:
    """Whether ``pid`` is alive on the guest -- same bounded-probe, same-exit-code
    discipline as :func:`_guest_file_exists`, and for the same reason: cleanup
    must never mistake "couldn't ask" for "confirmed dead"."""
    result = vm.ssh("kill", "-0", pid, timeout=5.0)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"pid-alive probe for pid={pid!r} got rc={result.returncode} (not kill's own 0/1 -- "
            f"likely an SSH transport failure): {result.stderr!r}"
        )
    return result.returncode == 0


def _geoip_update_exists(vm: SmokeVM) -> bool:
    """Whether the on-box ``geoip.update`` marker (pfblockerng.php:376) currently
    exists -- READ-ONLY: this fixture never creates or removes it. Its presence
    flips dc/dcc's SCHEDULED exit code (``dcc_changed=true`` routes through the
    3/2 branch instead of 1/0), and this session's VM persists across smoke
    modules, so a marker touched by an unrelated earlier run must be observed
    fresh immediately before dispatch rather than assumed absent.
    """
    result = vm.ssh("test", "-f", f"{h.PFB_DBDIR}/geoip.update", timeout=10.0)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"geoip.update existence probe got rc={result.returncode} (not test's own 0/1): {result.stderr!r}"
        )
    return result.returncode == 0


def _log_window(vm: SmokeVM, path: str) -> str:
    """Plant a unique marker at the current end of ``path`` (creating it if it
    does not yet exist) and return it as the baseline for a later
    :func:`_log_delta` read.

    Byte offsets and inodes both fail to survive a newsyslog rotation cleanly:
    a rename-then-regrow can put the fresh file's size back at or above an old
    offset within one test's window (gate-probed: 288 -> 736 bytes), silently
    reading the wrong region; and bzip2/gzip ALWAYS write a brand-new file when
    compressing a rotated-away backup, so its inode can never equal the original's
    by construction, no matter how a comparison is written. Marking the log's
    CONTENT instead sidesteps both: the marker text survives a rename and a
    decompression byte-for-byte, so its presence is direct, positive proof this
    is the right generation -- never an offset guess or an assumption about which
    backup is "the" backup.
    """
    marker = f"PFB_SMOKE_BASELINE_{uuid.uuid4().hex}"
    result = vm.ssh(f"echo {marker} >> {path}")
    assert result.returncode == 0, f"baseline marker write failed for {path}: rc={result.returncode} {result.stderr!r}"
    return marker


def _after_marker(text: str, idx: int, baseline: str) -> str:
    """The content strictly AFTER the marker's own line: `_log_window` always
    plants the marker via a plain `echo`, so it is immediately followed by its
    own newline -- skip that one character too, or every delta would carry a
    spurious leading blank line before the actual first appended line."""
    end = idx + len(baseline)
    if text[end : end + 1] == "\n":
        end += 1
    return text[end:]


def _log_delta(vm: SmokeVM, path: str, baseline: str) -> str:
    """Everything written to ``path`` after the unique marker ``baseline`` (from
    :func:`_log_window`), located by CONTENT SEARCH rather than a byte offset or
    an inode comparison.

    Search order: the live file, then ``path.0``, then ``path.0.bz2``
    (via ``bzcat``) and ``path.0.gz`` (via ``zcat``) — each candidate's own
    presence AND (for the compressed forms) its own decompression exit code is
    checked EXPLICITLY and SEPARATELY from the marker search, never piped into a
    downstream reader that would mask a decompression failure behind ITS healthy
    exit status. If the marker is found nowhere reachable -- e.g. a SECOND
    rotation already displaced it past ``.0``/``.0.bz2``/``.0.gz`` entirely, or
    the one remaining compressed candidate is corrupt -- this raises rather than
    returning a possibly-incomplete delta that could make an absence assertion
    falsely pass.
    """
    live = vm.ssh(f"cat {path}")
    assert live.returncode == 0, f"log delta read failed for {path}: rc={live.returncode} {live.stderr!r}"
    idx = live.stdout.rfind(baseline)
    if idx != -1:
        return _after_marker(live.stdout, idx, baseline)

    zero_exists = vm.ssh(f"test -f {path}.0")
    if zero_exists.returncode == 0:
        zero = vm.ssh(f"cat {path}.0")
        assert zero.returncode == 0, f"rotated-backup read failed for {path}.0: rc={zero.returncode} {zero.stderr!r}"
        idx = zero.stdout.rfind(baseline)
        if idx != -1:
            return _after_marker(zero.stdout, idx, baseline) + live.stdout

    for suffix, reader in ((".0.bz2", "bzcat"), (".0.gz", "zcat")):
        candidate = f"{path}{suffix}"
        exists = vm.ssh(f"test -f {candidate}")
        if exists.returncode != 0:
            continue
        decompressed = vm.ssh(f"{reader} {candidate}")
        if decompressed.returncode != 0:
            # Corrupt/unreadable backup -- detected via bzcat/zcat's OWN exit code,
            # never masked by piping into a downstream reader; not usable as a
            # candidate, but not fatal by itself either -- another candidate (or
            # the final raise below) still applies.
            continue
        idx = decompressed.stdout.rfind(baseline)
        if idx != -1:
            return _after_marker(decompressed.stdout, idx, baseline) + live.stdout

    raise RuntimeError(
        f"log rotation boundary lost for {path}: baseline marker {baseline!r} was not found in the live "
        f"file, {path}.0, or a readable {path}.0.bz2/{path}.0.gz -- refusing to guess, since a narrowed "
        f"window could make an absence assertion falsely pass."
    )


def _poll_delta_contains(vm: SmokeVM, path: str, baseline: str, needle: str, *, timeout: float = 15.0) -> str:
    """Poll ``path``'s delta until it contains ``needle``, or return the last-seen
    delta at the salvage cap. A PRESENCE check taken immediately after a command
    returns can race an asynchronous sink (syslogd); this consumes readiness instead
    of asserting on a single snapshot."""
    deadline = time.monotonic() + timeout
    delta = _log_delta(vm, path, baseline)
    while needle not in delta and time.monotonic() < deadline:
        time.sleep(1.0)
        delta = _log_delta(vm, path, baseline)
    return delta


def _drained_delta(vm: SmokeVM, path: str, baseline: str, *, timeout: float = 15.0) -> str:
    """The delta up to (not including) a fresh drain marker — an async-sink barrier
    for ABSENCE checks. ``logger``'s syslogd write is asynchronous; an absence check
    taken immediately after a command returns can race the daemon. Emitting one more,
    uniquely-tagged line through the SAME path and waiting for IT to land proves every
    earlier write from this invocation already landed too (syslogd processes in
    receipt order)."""
    marker = f"PFB_SMOKE_DRAIN_{uuid.uuid4().hex}"
    sent = vm.ssh("logger", "-p", "user.notice", marker)
    assert sent.returncode == 0, f"drain marker send failed: rc={sent.returncode} {sent.stderr!r}"
    delta = _poll_delta_contains(vm, path, baseline, marker, timeout=timeout)
    assert marker in delta, f"drain marker {marker!r} never landed in {path} within {timeout}s; got: {delta!r}"
    return delta[: delta.index(marker)]


class _LockHolder:
    """A real on-box dispatcher-lock holder: bounded acquisition, PID-tracked,
    cleanly released (never inferred solely from the ready marker's removal)."""

    def __init__(self, vm: SmokeVM) -> None:
        self.vm = vm
        self.pid = ""

    def start(self) -> None:
        vm = self.vm
        setup = vm.ssh(
            f"rm -f {_READY} {_STOP} {_PIDFILE} {_HOLDER_OUT}; cat > {_HOLDER} << 'PFBEOF'\n{_HOLDER_PHP}\nPFBEOF"
        )
        assert setup.returncode == 0, f"holder file write failed: rc={setup.returncode} {setup.stderr!r}"
        launch = vm.ssh(f"nohup {_PHP} {_HOLDER} >{_HOLDER_OUT} 2>&1 & echo $! > {_PIDFILE}; cat {_PIDFILE}")
        assert launch.returncode == 0 and launch.stdout.strip().isdigit(), (
            f"holder launch failed to report a PID: rc={launch.returncode} "
            f"stdout={launch.stdout!r} stderr={launch.stderr!r}"
        )
        self.pid = launch.stdout.strip()
        acquired = False
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if _guest_file_exists(vm, _READY):
                acquired = True
                break
            time.sleep(0.5)
        if not acquired:
            out = vm.ssh("cat", _HOLDER_OUT).stdout
            raise AssertionError(f"holder pid={self.pid} never signaled ready within 15s; its output: {out!r}")

    def stop(self) -> None:
        """Signal, wait, and — if the owned process ignores the signal (e.g. `start()`
        never got far enough for the stop-file poll loop to even begin) — terminate
        it directly. Never removes the marker files while the process might still be
        live: an orphan must be actually gone before its flock-holding evidence is
        erased, not just assumed gone from marker cleanup.
        """
        vm = self.vm
        vm.ssh("touch", _STOP)
        deadline = time.monotonic() + 15.0
        released = False
        while time.monotonic() < deadline:
            if not _guest_file_exists(vm, _READY):
                released = True
                break
            time.sleep(0.5)
        exited = True
        if self.pid:
            exited = False
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                if not _pid_alive(vm, self.pid):
                    exited = True
                    break
                time.sleep(0.5)
            for sig in ("-TERM", "-KILL"):
                if exited:
                    break
                vm.ssh("kill", sig, self.pid, timeout=5.0)
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    if not _pid_alive(vm, self.pid):
                        exited = True
                        break
                    time.sleep(0.5)
        if exited:
            vm.ssh("rm", "-f", _HOLDER, _READY, _STOP, _PIDFILE, _HOLDER_OUT)
        assert released and exited, (
            f"holder pid={self.pid!r} did not fully release+exit: ready_gone={released} pid_exited={exited}"
        )


@contextmanager
def _held_dispatcher_lock(vm: SmokeVM) -> Iterator[None]:
    holder = _LockHolder(vm)
    try:
        holder.start()
    except Exception:
        # A launched-but-never-ready holder is still an owned process holding a
        # real flock; reap it before propagating the setup failure, never leak it.
        holder.stop()
        raise
    try:
        yield
    finally:
        holder.stop()


# --------------------------------------------------------------------------- #
# 1. Standalone deferral: all 11 verbs exit 1 with both diagnostics.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("verb", ALL_VERBS)
def test_verb_defers_with_rc1_and_both_diagnostics_while_dispatcher_lock_held(deployed_vm: SmokeVM, verb: str) -> None:
    """Scenario: another process holds the scheduler dispatcher lock.

    Given <verb> is dispatched standalone (no `scheduled` argv),
    When it reaches the shared `pfb_extras_process_begin()` guard,
    Then it exits 1, AND the deferral is diagnosable in BOTH sinks issue #2592
    wired -- the main pfBlockerNG log and a `NOTICE [pfBlockerNG]` syslog line
    (severity included, not message-text-only) -- proving the rc=1 is genuinely the
    dispatcher-lock guard and not an unrelated failure.
    """
    vm = deployed_vm
    h.wait_no_active_pfb_task(vm)
    with _held_dispatcher_lock(vm):
        main_baseline = _log_window(vm, h.PFB_LOG)
        sys_baseline = _log_window(vm, _SYSTEM_LOG)
        run = vm.ssh(_PHP, _PFB_PHP, verb, timeout=60.0)
        assert run.returncode == 1, (
            f"{verb!r} must exit 1 on a lost dispatcher-lock race: "
            f"got rc={run.returncode} stdout={run.stdout!r} stderr={run.stderr!r}"
        )
        main_delta = _log_delta(vm, h.PFB_LOG, main_baseline)
        assert _MAIN_LOG_LINE in main_delta, (
            f"{verb!r}: expected the guard's diagnostic {_MAIN_LOG_LINE!r} in the main log delta, got: {main_delta!r}"
        )
        sys_delta = _poll_delta_contains(vm, _SYSTEM_LOG, sys_baseline, _SYSLOG_SEVERITY_AND_MESSAGE)
        assert _SYSLOG_SEVERITY_AND_MESSAGE in sys_delta, (
            f"{verb!r}: expected {_SYSLOG_SEVERITY_AND_MESSAGE!r} in the system log delta, got: {sys_delta!r}"
        )


# --------------------------------------------------------------------------- #
# 2. Scheduled bypass: the parent tick already owns the lock -- no deferral.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("verb", SCHEDULED_VERBS)
def test_scheduled_verb_bypasses_dispatcher_lock(deployed_vm: SmokeVM, verb: str) -> None:
    """Scenario: the parent tick already owns the dispatcher lock (issue #2832 item 2).

    Given <verb>'s own before-state: while ANOTHER process holds the lock, <verb>
        defers standalone (rc=1 + the main-log diagnostic) -- established by THIS
        test itself, never dependent on a sibling test having already run,
    When the SAME lock is held and <verb> is instead dispatched with `scheduled`,
    Then the `$scheduled` short-circuit skips `pfb_extras_process_begin()` entirely --
    NEITHER deferral sink fires -- and <verb> reaches its own real, verb-specific
    logic (proven by a distinct downstream marker for every verb but bl/bls, which
    rely on the before-state phase above instead of a distinct log line), completing
    with a deterministic outcome.
    """
    vm = deployed_vm
    h.wait_no_active_pfb_task(vm)
    expected = _SCHEDULED_EXPECTATIONS[verb]

    # Before-state: standalone + contended -> deferred. Self-contained proof that
    # <verb> is a real, recognized verb reaching the guard (not an unrecognized-
    # command no-op) -- load-bearing for bl/bls, whose bypass phase has no marker.
    with _held_dispatcher_lock(vm):
        main_baseline = _log_window(vm, h.PFB_LOG)
        sys_baseline = _log_window(vm, _SYSTEM_LOG)
        contended = vm.ssh(_PHP, _PFB_PHP, verb, timeout=60.0)
        assert contended.returncode == 1, (
            f"before-state: {verb!r} must defer (rc=1) while the lock is held standalone: "
            f"got rc={contended.returncode} stdout={contended.stdout!r} stderr={contended.stderr!r}"
        )
        main_delta = _log_delta(vm, h.PFB_LOG, main_baseline)
        assert _MAIN_LOG_LINE in main_delta, (
            f"before-state: expected {_MAIN_LOG_LINE!r} in main log delta, got: {main_delta!r}"
        )
        # Drain (not just check) the syslog record HERE: its write is asynchronous,
        # and the after-state phase below takes its OWN fresh syslog baseline --
        # an undrained record from THIS run could land after that baseline and get
        # mis-attributed to the scheduled invocation, failing its absence assertion
        # intermittently for a completely unrelated reason.
        sys_delta = _poll_delta_contains(vm, _SYSTEM_LOG, sys_baseline, _SYSLOG_SEVERITY_AND_MESSAGE)
        assert _SYSLOG_SEVERITY_AND_MESSAGE in sys_delta, (
            f"before-state: expected {_SYSLOG_SEVERITY_AND_MESSAGE!r} in syslog delta, got: {sys_delta!r}"
        )

    # After-state: scheduled bypass.
    h.wait_no_active_pfb_task(vm)
    with _held_dispatcher_lock(vm):
        main_baseline = _log_window(vm, h.PFB_LOG)
        sink_baseline = _log_window(vm, expected.sink) if expected.sink else ""
        sys_baseline = _log_window(vm, _SYSTEM_LOG)
        geoip_update_before = _geoip_update_exists(vm) if verb in ("dc", "dcc") else False
        run = vm.ssh(_PHP, _PFB_PHP, verb, "scheduled", timeout=90.0)
        assert _guest_file_exists(vm, _READY), (
            f"{verb!r} scheduled: the dispatcher-lock holder self-expired (its 120s cap) before "
            f"this run completed, so the lock was NOT genuinely held throughout -- a passing "
            f"bypass assertion here would be vacuous (no contention to bypass), not proof of one"
        )
        main_delta = _log_delta(vm, h.PFB_LOG, main_baseline)
        sys_delta = _drained_delta(vm, _SYSTEM_LOG, sys_baseline)
        assert _MAIN_LOG_LINE not in main_delta, (
            f"{verb!r} scheduled must bypass the dispatcher guard entirely: unexpected "
            f"{_MAIN_LOG_LINE!r} in main log delta: {main_delta!r}"
        )
        assert _SYSLOG_SEVERITY_AND_MESSAGE not in sys_delta, (
            f"{verb!r} scheduled must bypass the dispatcher guard entirely: unexpected "
            f"{_SYSLOG_SEVERITY_AND_MESSAGE!r} in drained syslog delta: {sys_delta!r}"
        )
        if expected.marker:
            sink_delta = _log_delta(vm, expected.sink, sink_baseline)
            assert expected.marker in sink_delta, (
                f"{verb!r} scheduled must reach its own real logic (not an unrecognized-"
                f"command no-op): expected {expected.marker!r} in {expected.sink}, got: {sink_delta!r}"
            )
        # dc/dcc's SCHEDULED rc also depends on a pre-existing geoip.update marker
        # (pfblockerng.php:376's dcc_changed -> the 3/2 branch instead of 1/0) --
        # read-only probed just above, immediately before dispatch, never mutated:
        # this session's VM persists across smoke modules, so a marker touched by
        # an unrelated earlier run must never silently break a fixed expectation.
        expected_rc = expected.rc
        if verb in ("dc", "dcc") and geoip_update_before:
            expected_rc = 3 if verb == "dc" else 2
        assert run.returncode == expected_rc, (
            f"{verb!r} scheduled: expected rc={expected_rc} under this fixture's NXDOMAIN+"
            f"credential-less config (geoip_update_before={geoip_update_before}), got rc={run.returncode} "
            f"stdout={run.stdout!r} stderr={run.stderr!r}"
        )


# --------------------------------------------------------------------------- #
# 3. Released lock: dc/dcc no longer defer (issue #2832 item 4).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("verb", ("dc", "dcc"))
def test_verb_release_completes_deterministically(deployed_vm: SmokeVM, verb: str) -> None:
    """Scenario: the dispatcher lock is contended, then released.

    Given <verb>'s own before-state: while ANOTHER process holds the lock, <verb>
        defers with rc=1 and both diagnostics (established by THIS test, never
        order-dependent on a sibling),
    When the lock is released and <verb> is dispatched again,
    Then neither deferral sink fires, and the real GeoIP pipeline -- NXDOMAIN-
        stubbed, credential-less -- reaches its own real logic and completes with
        a DETERMINISTIC, verb-specific outcome: dc's download itself genuinely
        fails (rc=1); dcc's conversion step never runs at all (database_cc=on
        skips it -- see deployed_vm), so it reaches a clean rc=0 (F4: never a
        tautological "0 or 1" range assumed for either).
    """
    vm = deployed_vm
    h.wait_no_active_pfb_task(vm)

    # Before-state: contended -> deferred.
    with _held_dispatcher_lock(vm):
        main_baseline = _log_window(vm, h.PFB_LOG)
        sys_baseline = _log_window(vm, _SYSTEM_LOG)
        contended = vm.ssh(_PHP, _PFB_PHP, verb, timeout=60.0)
        assert contended.returncode == 1, (
            f"before-state: {verb!r} must defer (rc=1) while the lock is held: "
            f"got rc={contended.returncode} stdout={contended.stdout!r} stderr={contended.stderr!r}"
        )
        main_delta = _log_delta(vm, h.PFB_LOG, main_baseline)
        assert _MAIN_LOG_LINE in main_delta, (
            f"before-state: expected {_MAIN_LOG_LINE!r} in main log, got: {main_delta!r}"
        )
        sys_delta = _poll_delta_contains(vm, _SYSTEM_LOG, sys_baseline, _SYSLOG_SEVERITY_AND_MESSAGE)
        assert _SYSLOG_SEVERITY_AND_MESSAGE in sys_delta, (
            f"before-state: expected {_SYSLOG_SEVERITY_AND_MESSAGE!r} in syslog, got: {sys_delta!r}"
        )

    # After-state: released -> the real pipeline runs to completion.
    h.wait_no_active_pfb_task(vm)
    sink = _ERROR_LOG if verb == "dc" else _EXTRAS_LOG
    marker = "Invalid URL (cannot resolve)" if verb == "dc" else "Download Process Starting"
    expected_rc = 1 if verb == "dc" else 0
    main_baseline = _log_window(vm, h.PFB_LOG)
    sink_baseline = _log_window(vm, sink)
    sys_baseline = _log_window(vm, _SYSTEM_LOG)
    run = vm.ssh(_PHP, _PFB_PHP, verb, timeout=90.0)
    main_delta = _log_delta(vm, h.PFB_LOG, main_baseline)
    sys_delta = _drained_delta(vm, _SYSTEM_LOG, sys_baseline)
    assert _MAIN_LOG_LINE not in main_delta, (
        f"after-state: {verb!r} with a free lock must not report a deferral: main log delta {main_delta!r}"
    )
    assert _SYSLOG_SEVERITY_AND_MESSAGE not in sys_delta, (
        f"after-state: {verb!r} with a free lock must not report a deferral: drained syslog delta {sys_delta!r}"
    )
    sink_delta = _log_delta(vm, sink, sink_baseline)
    assert marker in sink_delta, (
        f"after-state: {verb!r} must reach real pipeline logic: expected {marker!r} in {sink}, got: {sink_delta!r}"
    )
    assert run.returncode == expected_rc, (
        f"after-state: {verb!r}'s real pipeline deterministically reaches rc={expected_rc} under this "
        f"fixture's NXDOMAIN+credential-less config (F4: never a tautological 0-or-1 range assumed): "
        f"got rc={run.returncode} stdout={run.stdout!r} stderr={run.stderr!r}"
    )
    h.wait_no_active_pfb_task(vm)
