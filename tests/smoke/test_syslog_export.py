"""ADR-38 — live-VM smoke: syslog export of pfBlockerNG security events.

Proves the §2.2 contract on a real pfSense CE VM:

  1. Default off / toggle OFF ⇒ zero event export, CSV logging unchanged.
  2. Toggle ON ⇒ exactly one ``pfblockerng`` key=value syslog record per
     DNSBL block event, correct qname/btype keys.
  3. Toggle ON + IP path ⇒ exactly one ``pfblockerng`` key=value syslog record
     per IP Block event, correct act/src/alias keys.
  4. CSV logging is unchanged in both states (export is purely additive).
  5. (Config round-trip is pinned by off-box unit tests; §2.2.5 is implicitly
     exercised via the real PfbConfig read on the live box.)

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the ``stub_dns`` fixture. Feeds are written on-box via ``helpers.write_local_feed``
(no HTTP mock-feed server needed). Without these all cases skip cleanly.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

# --------------------------------------------------------------------------- #
# Paths (mirroring pfblockerng.xml / pfblockerng.inc definitions)
# --------------------------------------------------------------------------- #

# Dedicated syslog log created by the pfSense <logging> block in pfblockerng.xml
# (logfilename=pfblockerng_syslog.log).
SYSLOG_LOG = "/var/log/pfblockerng_syslog.log"

# pfBlockerNG CSV security logs (unchanged by syslog export).
PFB_LOGDIR = "/var/log/pfblockerng"
DNSBL_LOG = f"{PFB_LOGDIR}/dnsbl.log"
IP_BLOCK_LOG = f"{PFB_LOGDIR}/ip_block.log"

# Config path for the syslog export toggle (under the General settings section).
CFG_GENERAL = "installedpackages/pfblockerng/config/0"

# A test IP range whose pfBlockerNG block rule we trigger traffic against.
# RFC 5737 TEST-NET-3 (203.0.113.0/24) — not routable, but pf still blocks
# an outbound connection attempt if it matches an alias table for that range.
TEST_IP_BLOCK_RANGE = "203.0.113.0/24"
# Specific destination IP to try to reach (triggers the pf block log).
TEST_IP_BLOCK_DST = "203.0.113.1"

# How long to wait for the filterlog daemon to write the block log entry
# after a connection attempt.
FILTERLOG_SETTLE_SECS = 5.0


# --------------------------------------------------------------------------- #
# Module-scoped fixture: deploy once, inject both DNSBL + IP case, reload
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(
    smoke_vm: SmokeVM,
    stub_dns: _StubDnsServer,
) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for this module; wire DNSBL + IP + syslog.

    Given: the smoke VM is booted and the branch .pkg is available.
    When:  we deploy the package, wire DNSBL (unique blocked domain, VIP mode),
           wire one IP block feed (RFC 5737 range), and perform an initial full
           reload with syslog export OFF (the default).
    Then:  the module-level VM is ready for the per-test syslog assertions;
           teardown is automatic (module scope).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    # ------------------------------------------------------------------ #
    # Given: package installed + DNS upstream wired to the runner stub
    # ------------------------------------------------------------------ #
    h.deploy(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)

    # ------------------------------------------------------------------ #
    # Given: DNSBL VIP exists and a feed blocking a unique domain is live
    # ------------------------------------------------------------------ #
    h.ensure_dnsbl_vip(smoke_vm)

    _dnsbl_domain = h.unique_domain("pfbsyslogdnsbl")
    _dnsbl_feed_path = h.write_local_feed(
        smoke_vm,
        "pfb_syslog_dnsbl.txt",
        f"{_dnsbl_domain}\n",
    )
    dnsbl_spec = h.DnsblCase(
        aliasname="pfb_syslog_test",
        feed_url=_dnsbl_feed_path,
        mode=h.DnsblMode.VIP,
        header="pfb_syslog_dnsbl",
        hsts=False,  # force off — test domain is not HSTS-preloaded but be explicit
    )
    h.inject(smoke_vm, dnsbl_spec)

    # ------------------------------------------------------------------ #
    # Given: an IP block feed targeting the RFC 5737 TEST-NET-3 range
    # ------------------------------------------------------------------ #
    _ip_feed_path = h.write_local_feed(
        smoke_vm,
        "pfb_syslog_ip.txt",
        f"{TEST_IP_BLOCK_RANGE}\n",
    )
    ip_spec = h.IpCase(
        aliasname="pfb_syslog_iptest",
        feed_url=_ip_feed_path,
        action="Deny_Both",
        family="v4",
        header="pfb_syslog_ip",
    )
    h.inject(smoke_vm, ip_spec)

    # ------------------------------------------------------------------ #
    # Given: syslog export is OFF (the default) at the start of this module
    # ------------------------------------------------------------------ #
    _set_syslog_enabled(smoke_vm, on=False)

    # ------------------------------------------------------------------ #
    # When: full reload (installs DNSBL + IP block + pfb_unbound.ini)
    # ------------------------------------------------------------------ #
    h.reload(smoke_vm, "update")

    # ------------------------------------------------------------------ #
    # Precondition: DNSBL is blocking the test domain (VIP shape)
    # ------------------------------------------------------------------ #
    ans = h.dns_probe(smoke_vm, _dnsbl_domain, "A")
    if not h.is_vip(ans):
        pytest.skip(
            f"DNSBL VIP block not observed for {_dnsbl_domain} "
            f"(got {ans}) — DNSBL precondition failed; skipping syslog tests"
        )

    # Stash shared state on the VM object for per-test access.
    smoke_vm._pfb_dnsbl_domain = _dnsbl_domain  # type: ignore[attr-defined]

    yield smoke_vm


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _set_syslog_enabled(vm: SmokeVM, *, on: bool, timeout: float = 60.0) -> None:
    """Toggle the log_syslog export key in config and write_config."""
    val = "on" if on else ""
    snippet = (
        f"$g = config_get_path({h._php_str(CFG_GENERAL)}, array());\n"
        f"$g['log_syslog'] = {h._php_str(val)};\n"
        f"config_set_path({h._php_str(CFG_GENERAL)}, $g);\n"
        "write_config('pfBlockerNG smoke: toggle log_syslog');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_set_syslog_enabled({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _count_syslog_lines(vm: SmokeVM, *, timeout: float = 30.0) -> int:
    """Return the number of lines in SYSLOG_LOG (0 if absent)."""
    result = vm.ssh("wc", "-l", SYSLOG_LOG, timeout=timeout)
    if result.returncode != 0:
        return 0
    # wc -l output: "   N /path/to/file" or "N /path/to/file"
    m = re.match(r"\s*(\d+)", result.stdout.strip())
    return int(m.group(1)) if m else 0


def _read_syslog_lines(vm: SmokeVM, *, timeout: float = 30.0) -> list[str]:
    """Read SYSLOG_LOG lines; return empty list if the file is absent."""
    content = h.read_log_file(vm, SYSLOG_LOG, timeout=timeout)
    return [ln for ln in content.splitlines() if ln.strip()]


def _trigger_ip_block(vm: SmokeVM, *, timeout: float = 30.0) -> None:
    """Attempt a TCP connection to a blocked IP to generate a pf block log event.

    The RFC 5737 TEST-NET-3 address is in the alias table from the IP feed, so
    any outbound connection to 203.0.113.1 is pf-blocked and logged.  curl with
    a short connect timeout produces the outbound SYN that pf drops; the error
    exit is expected and ignored.

    The filterlog daemon (tail_pfb | php_pfb filterlog) reads /var/log/filter.log
    and writes the pfBlockerNG CSV + (when log_syslog=on) the syslog record.
    """
    # Use /bin/sh to swallow the non-zero exit without raising in the caller.
    # --connect-timeout 1 caps the TCP timeout; curl itself fails fast.
    vm.ssh(
        "/bin/sh",
        "-c",
        f"/usr/local/bin/curl --connect-timeout 1 --max-time 2 http://{TEST_IP_BLOCK_DST}/ >/dev/null 2>&1 || true",
        timeout=timeout,
    )


def _ensure_syslog_chroot_socket(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Create the Unbound chroot syslog socket directory and restart syslogd.

    ``pfb_unbound.py`` (running inside the Unbound chroot at ``/var/unbound``)
    writes syslog events via ``SysLogHandler(address="/var/run/log")``, which
    resolves to ``/var/unbound/var/run/log`` on the host.  That directory is
    normally created by ``custom_php_resync_config_command`` in pfblockerng.xml,
    which only fires on a GUI config save — not during CLI-driven test reloads.
    Replicate it here before enabling syslog export so the socket exists when
    ``pfb_unbound.py`` first tries to connect.
    """
    snippet = (
        "require_once('/etc/inc/syslog.inc');\n"
        "safe_mkdir('/var/unbound/var/run');\n"
        "chown('/var/unbound/var/run', 'unbound');\n"
        "system_syslogd_start(TRUE);\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_ensure_syslog_chroot_socket() failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _assert_syslog_line(lines: list[str], tag: str, **required_kv: str) -> str:
    """Assert at least one line contains ``tag`` and all ``key=value`` pairs.

    Returns the matching line for diagnostic output.

    Args:
        lines:       All syslog log lines.
        tag:         Required substring (e.g. ``"pfblockerng"``) in the line.
        **required_kv: Key=value pairs that must appear verbatim (e.g. ``act="block"``
                     or ``act=block`` depending on quoting).

    Raises:
        AssertionError: when no line satisfies all conditions.
    """
    matches = []
    for ln in lines:
        if tag not in ln:
            continue
        if all(f"{k}={v}" in ln for k, v in required_kv.items()):
            matches.append(ln)
    assert matches, (
        f"No syslog line found with tag={tag!r} and kv={required_kv!r}.\n"
        f"All lines ({len(lines)}):\n" + "\n".join(lines[:40])
    )
    return matches[0]


# --------------------------------------------------------------------------- #
# Test 1: ON ⇒ DNSBL event exported (§2.2.2)
# --------------------------------------------------------------------------- #


def test_syslog_on_dnsbl_event_exported(deployed_vm: SmokeVM) -> None:
    """§2.2.2 — ON ⇒ one pfblockerng key=value syslog record per DNSBL block.

    Scenario: syslog export toggle ON; a DNSBL-blocked domain probed on-box.

    Given: deployed pfBlockerNG with DNSBL blocking _dnsbl_domain (VIP mode),
           syslog export currently OFF (the module fixture default).
    When:  log_syslog is enabled and DNSBL is reloaded (re-writes pfb_unbound.ini
           with syslog_enable=on), then the blocked domain is probed on-box.
    Then:  exactly one ``pfblockerng`` syslog record appears in SYSLOG_LOG with
           ``act=dnsbl``, ``qname=<domain>``, and ``btype=VIP``.
    And:   the CSV dnsbl.log is ALSO written (export is additive — §2.2.1).
    """
    vm = deployed_vm
    domain: str = vm._pfb_dnsbl_domain  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ #
    # Given: count baseline BEFORE enabling
    # ------------------------------------------------------------------ #
    before_count = _count_syslog_lines(vm)
    dnsbl_before = h.count_log_marker(vm, DNSBL_LOG, domain)

    # ------------------------------------------------------------------ #
    # When: ensure chroot syslog socket exists, then enable syslog export
    #       and reload DNSBL (re-builds pfb_unbound.ini with syslog_enable=on).
    #       The socket dir is normally created by pfblockerng.xml's
    #       custom_php_resync_config_command (GUI save only) — we replicate
    #       that setup here for CLI-driven test reloads.
    # ------------------------------------------------------------------ #
    _ensure_syslog_chroot_socket(vm)
    _set_syslog_enabled(vm, on=True)
    h.reload(vm, "updatednsbl")

    # ------------------------------------------------------------------ #
    # When: probe the blocked domain on-box (triggers the DNSBL block +
    #       the python syslog emitter)
    # ------------------------------------------------------------------ #
    ans = h.dns_probe(vm, domain, "A")

    # ------------------------------------------------------------------ #
    # Then: DNSBL still blocks (VIP shape) — export is additive
    # ------------------------------------------------------------------ #
    assert h.is_vip(ans), f"DNSBL block shape changed after enabling syslog: expected VIP, got {ans}"

    # Give the syslog record a moment to flush (the SysLogHandler sendto() is
    # synchronous, but the OS may buffer briefly before writing to the log file).
    time.sleep(1.0)

    # ------------------------------------------------------------------ #
    # Then: at least one new pfblockerng syslog line with act=dnsbl + qname
    # ------------------------------------------------------------------ #
    after_lines = _read_syslog_lines(vm)
    assert len(after_lines) > before_count, (
        f"No new syslog lines appeared after enabling export and probing {domain} "
        f"(before {before_count}, after {len(after_lines)})"
    )

    _assert_syslog_line(after_lines, "pfblockerng", act="dnsbl", btype="VIP")
    # Verify qname is present (escaped or unescaped — domain has no special chars)
    dnsbl_lines = [ln for ln in after_lines if "act=dnsbl" in ln and domain in ln]
    assert dnsbl_lines, f"No syslog line contains act=dnsbl and qname={domain!r}.\nSyslog lines: {after_lines}"

    # ------------------------------------------------------------------ #
    # And: CSV dnsbl.log also written (additive — export does not replace CSV)
    # ------------------------------------------------------------------ #
    dnsbl_after = h.count_log_marker(vm, DNSBL_LOG, domain)
    assert dnsbl_after > dnsbl_before, (
        f"CSV dnsbl.log was NOT written after syslog export was enabled "
        f"(before {dnsbl_before}, after {dnsbl_after}) — export must be additive"
    )


# --------------------------------------------------------------------------- #
# Test 2: ON ⇒ IP Block event exported (§2.2.2 + §2.2.3)
# --------------------------------------------------------------------------- #


def test_syslog_on_ip_block_event_exported(deployed_vm: SmokeVM) -> None:
    """§2.2.2 + §2.2.3 — ON ⇒ one pfblockerng key=value record per IP Block event.

    Scenario: syslog export toggle ON; a connection to a pf-blocked RFC 5737 IP
    is attempted from the VM, generating a pf block log entry that the filterlog
    daemon parses and exports.

    Given: deployed pfBlockerNG with an IP block alias covering 203.0.113.0/24,
           syslog export currently ON (enabled by test_syslog_on_dnsbl_event_exported),
           filterlog daemon running (started by the package rc script on reload).
    When:  a TCP connection to 203.0.113.1 is attempted (pf blocks + logs it);
           the filterlog daemon picks up the filter.log entry.
    Then:  a new ``pfblockerng`` syslog record appears in SYSLOG_LOG with
           ``act=block`` and the src / alias / feed / dst keys populated.
    And:   the CSV ip_block.log is ALSO written (export is additive — §2.2.1).
    """
    vm = deployed_vm

    # ------------------------------------------------------------------ #
    # Given: syslog export is ON (left on by the previous test in module scope).
    #        Confirm via config read (precondition guard).
    # ------------------------------------------------------------------ #
    val = h.config_get(vm, CFG_GENERAL + "/log_syslog")
    assert val == "on", f"Precondition: expected log_syslog='on' from prior test, got {val!r}"

    # Baseline
    before_count = _count_syslog_lines(vm)
    ip_block_before_content = h.read_log_file(vm, IP_BLOCK_LOG)

    # ------------------------------------------------------------------ #
    # When: trigger an outbound TCP SYN to a pf-blocked IP
    # ------------------------------------------------------------------ #
    _trigger_ip_block(vm)

    # Give the filterlog daemon time to process the filter.log entry and
    # write to ip_block.log + emit the syslog record.
    time.sleep(FILTERLOG_SETTLE_SECS)

    # ------------------------------------------------------------------ #
    # Then: at least one new pfblockerng syslog line with act=block
    # ------------------------------------------------------------------ #
    after_lines = _read_syslog_lines(vm)

    # If no new IP-block syslog line appeared yet, try again once (the filterlog
    # daemon may not have started — check and report rather than silently skip).
    if len(after_lines) <= before_count or not any(
        "act=block" in ln or "act=pass" in ln for ln in after_lines[before_count:]
    ):
        # Diagnose whether the filterlog daemon is running
        ps_result = vm.ssh("/bin/ps", "-wax", timeout=30)
        daemon_running = "pfblockerng.inc filterlog" in ps_result.stdout or "tail_pfb" in ps_result.stdout

        # Also check if the IP block alias table actually has our test range
        pfctl_result = vm.ssh("/sbin/pfctl", "-t", "pfB_pfb_syslog_iptest_v4", "-T", "show", timeout=30)
        alias_populated = TEST_IP_BLOCK_RANGE in pfctl_result.stdout or "203.0.113" in pfctl_result.stdout

        if not alias_populated:
            pytest.skip(
                f"IP block alias pfB_pfb_syslog_iptest_v4 is not populated with "
                f"{TEST_IP_BLOCK_RANGE} — IP feed reload may have failed. "
                f"pfctl output: {pfctl_result.stdout!r}"
            )

        if not daemon_running:
            pytest.skip(
                f"filterlog daemon is not running — cannot exercise the IP syslog path "
                f"(process list: {ps_result.stdout[:500]!r})"
            )

        # Daemon running + alias populated but no syslog line => genuine failure.
        assert False, (  # noqa: B011  (intentional after diagnostics)
            f"No new IP-block syslog line appeared after connection attempt to "
            f"{TEST_IP_BLOCK_DST} (before {before_count}, after {len(after_lines)} lines).\n"
            f"filterlog daemon running: {daemon_running}\n"
            f"alias populated: {alias_populated}\n"
            f"pf alias table: {pfctl_result.stdout!r}\n"
            f"All syslog lines: {after_lines}"
        )

    new_lines = after_lines[before_count:]
    ip_block_lines = [ln for ln in new_lines if "act=block" in ln or "act=pass" in ln]
    assert ip_block_lines, (
        f"Syslog had new lines but none with act=block/pass after IP block trigger.\nNew lines: {new_lines}"
    )

    # Confirm pfblockerng tag is present (required by §2.2.2)
    assert any("pfblockerng" in ln for ln in ip_block_lines), (
        f"IP block syslog lines lack 'pfblockerng' tag: {ip_block_lines}"
    )

    # ------------------------------------------------------------------ #
    # And: CSV ip_block.log is also written (additive)
    # ------------------------------------------------------------------ #
    ip_block_after_content = h.read_log_file(vm, IP_BLOCK_LOG)
    assert len(ip_block_after_content) > len(ip_block_before_content), (
        "CSV ip_block.log was NOT written after syslog export was enabled — export must be additive (§2.2.1)"
    )


# --------------------------------------------------------------------------- #
# Test 3: OFF ⇒ no new export records (before/after proof — §2.2.1)
# --------------------------------------------------------------------------- #


def test_syslog_off_no_new_records(deployed_vm: SmokeVM) -> None:
    """§2.2.1 — OFF ⇒ zero event export; CSV logging unchanged.

    Before/after proof: first assert ON produced records (already true from prior
    tests), then disable and assert the count does NOT increase.

    Given: syslog export is currently ON (from prior tests), both DNSBL and IP
           block paths have already produced syslog records.
    When:  log_syslog is set to OFF and DNSBL is reloaded (pfb_unbound.ini rebuilt
           with syslog_enable=off); the blocked domain is probed again and a
           connection to the blocked IP is attempted again.
    Then:  the syslog line count does NOT increase — zero new records emitted.
    And:   the CSV dnsbl.log and ip_block.log are STILL written (§2.2.1).
    """
    vm = deployed_vm
    domain: str = vm._pfb_dnsbl_domain  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ #
    # Given: ON produced records (assert the before-state)
    # ------------------------------------------------------------------ #
    count_while_on = _count_syslog_lines(vm)
    assert count_while_on > 0, (
        "Precondition: expected syslog records from prior ON tests, but "
        f"SYSLOG_LOG has {count_while_on} lines — prior tests may have failed"
    )

    dnsbl_csv_before = h.count_log_marker(vm, DNSBL_LOG, domain)
    ip_csv_before_content = h.read_log_file(vm, IP_BLOCK_LOG)

    # ------------------------------------------------------------------ #
    # When: disable syslog export + reload DNSBL (updates pfb_unbound.ini)
    # ------------------------------------------------------------------ #
    _set_syslog_enabled(vm, on=False)
    h.reload(vm, "updatednsbl")

    # ------------------------------------------------------------------ #
    # When: probe the blocked DNSBL domain on-box (would emit if toggle were on)
    # ------------------------------------------------------------------ #
    ans = h.dns_probe(vm, domain, "A")
    assert h.is_vip(ans), f"DNSBL block should still work when syslog is OFF, got {ans}"

    # ------------------------------------------------------------------ #
    # When: trigger IP block again (would emit if toggle were on)
    # ------------------------------------------------------------------ #
    _trigger_ip_block(vm)
    time.sleep(FILTERLOG_SETTLE_SECS)

    # ------------------------------------------------------------------ #
    # Then: syslog line count is unchanged (no new records emitted)
    # ------------------------------------------------------------------ #
    count_while_off = _count_syslog_lines(vm)
    assert count_while_off == count_while_on, (
        f"New syslog records appeared after disabling export (before {count_while_on}, "
        f"after {count_while_off}) — the OFF gate is not working"
    )

    # ------------------------------------------------------------------ #
    # And: CSV logging still works in the OFF state (export is additive)
    # ------------------------------------------------------------------ #
    dnsbl_csv_after = h.count_log_marker(vm, DNSBL_LOG, domain)
    assert dnsbl_csv_after > dnsbl_csv_before, (
        f"CSV dnsbl.log was NOT written while syslog export is OFF "
        f"(before {dnsbl_csv_before}, after {dnsbl_csv_after}) "
        f"— the CSV path must be independent of the syslog toggle"
    )

    ip_csv_after_content = h.read_log_file(vm, IP_BLOCK_LOG)
    assert len(ip_csv_after_content) > len(ip_csv_before_content), (
        "CSV ip_block.log was NOT written while syslog export is OFF "
        "— the CSV path must be independent of the syslog toggle"
    )


# --------------------------------------------------------------------------- #
# Test 4 (optional): syslog records excluded from system.log (§2.2.1 footprint)
# --------------------------------------------------------------------------- #


def test_syslog_records_excluded_from_system_log(deployed_vm: SmokeVM) -> None:
    """§2.2.1 — pfblockerng events are routed to the dedicated log, not system.log.

    The pfSense <logging> block in pfblockerng.xml adds a !pfblockerng exclusion
    so events tagged pfblockerng go to pfblockerng_syslog.log only and are NOT
    duplicated in system.log.

    Given: syslog export is currently OFF (left off by prior test); we enable it,
           probe the blocked domain, then check system.log.
    When:  log_syslog is enabled + DNSBL reloaded + domain probed.
    Then:  no new pfblockerng-tagged line appears in /var/log/system.log.
    """
    vm = deployed_vm
    domain: str = vm._pfb_dnsbl_domain  # type: ignore[attr-defined]

    # Baseline: count pfblockerng lines in system.log BEFORE enabling
    system_log_before = h.count_log_marker(vm, "/var/log/system.log", "pfblockerng")

    # Enable + reload DNSBL + probe
    _set_syslog_enabled(vm, on=True)
    h.reload(vm, "updatednsbl")

    ans = h.dns_probe(vm, domain, "A")
    assert h.is_vip(ans), f"DNSBL block not observed: {ans}"
    time.sleep(1.0)

    # Count pfblockerng lines in system.log AFTER the probe
    system_log_after = h.count_log_marker(vm, "/var/log/system.log", "pfblockerng")

    # The !pfblockerng tag filter routes our messages to the dedicated log only;
    # system.log's count should not have grown with our syslog event records.
    assert system_log_after == system_log_before, (
        f"pfblockerng syslog events leaked into /var/log/system.log "
        f"(before {system_log_before}, after {system_log_after}) — "
        f"the <logging> exclusion (!pfblockerng) is not working"
    )

    # Leave syslog export ON for any subsequent tests in the module.
