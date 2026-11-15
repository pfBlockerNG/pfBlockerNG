"""Run the pre-script process-group contracts on FreeBSD and retain native source audit evidence."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from . import helpers
from .conftest import SmokeVM
from .test_smoke_dns_gateway import (  # noqa: F401 -- pytest fixture re-export
    GoToolchain,
    _goarch,
    _upload,
    go_toolchain,
)

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(900)]

GO_DIR = Path(__file__).resolve().parents[2] / "go" / "pfb_core"
TESTS = (
    "TestPreScriptKillsAnIgnoringChildAfterItsLeaderDiesOnTerm",
    "TestPreScriptImmediatelyCleansAnAttachedChildAfterSuccessfulLeaderExit",
    "TestPreScriptKeepsTheRunningLeadersTermGrace",
    "TestPreScriptAllowsAnIntentionallyDetachedSurvivor",
)

# Read sources only: backgrounding alone does not establish that a service detaches.
SOURCE_AUDIT = r"""
status=0
captured='|'
capture() {
    path=$1
    case "$captured" in *"|$path|"*) return ;; esac
    mode=FULL
    if [ ! -f "$path" ] || [ ! -r "$path" ]; then
        printf 'UNREADABLE REQUIRED SOURCE %s\n' "$path"
        status=1
        return
    fi
    digest=$(sha256 -q "$path") || { status=1; return; }
    captured="${captured}${path}|"
    printf '\n=== SOURCE %s SHA256 %s MODE %s ===\n' "$path" "$digest" "$mode"
    cat "$path" || status=1
    printf '\n=== END SOURCE ===\n'
}
capture /etc/rc.filter_configure_sync
capture /usr/sbin/service
found_mwexec=0
for path in /etc/inc/*.inc; do
    if [ -f "$path" ] && [ -r "$path" ] && \
        grep -Eq '^[[:space:]]*function[[:space:]]+&?[[:space:]]*mwexec(_bg)?[[:space:]]*\(' "$path"; then
        capture "$path" FULL
        found_mwexec=1
    fi
done
if [ "$found_mwexec" -ne 1 ]; then
    printf 'MWEXEC DEFINITION SOURCE ABSENT: no matching global definition in readable /etc/inc/*.inc\n'
fi
capture /etc/inc/filter.inc
capture /etc/inc/syslog.inc
for pattern in /etc/inc/*service*.inc /etc/inc/*unbound*.inc /etc/inc/*dhcp*.inc \
    /etc/inc/*radv*.inc /etc/inc/*router*.inc /etc/inc/*ra.inc \
    /usr/local/etc/rc.d/*unbound* /usr/local/etc/rc.d/*dhcp* /usr/local/etc/rc.d/*radv* \
    /usr/local/etc/rc.d/kea* /etc/rc.d/*kea* \
    /etc/rc.d/*unbound* /etc/rc.d/*dhcp* /etc/rc.d/*radv* \
    /usr/local/etc/rc.d/*lighttpd* /usr/local/etc/rc.d/*filter* /usr/local/etc/rc.d/*xinetd* \
    /etc/rc.d/*syslog* /usr/local/etc/rc.d/*syslog* \
    /usr/local/etc/rc.d/pfb_* /etc/rc.d/pfb_*; do
    if [ -f "$pattern" ]; then
        capture "$pattern"
    else
        printf 'OPTIONAL SOURCE ABSENT %s\n' "$pattern"
    fi
done
found_service=0
for path in /etc/inc/*service*.inc; do
    if [ -f "$path" ] && [ -r "$path" ]; then found_service=1; fi
done
if [ "$found_service" -ne 1 ]; then
    printf 'REQUIRED service include discovery found no readable source\n'
    status=1
fi
for name in daemon radvd dhcpd dhcpleases6 kea-dhcp4 kea-dhcp6 unbound lighttpd filterlog filterdns xinetd syslogd; do
    path=$(command -v "$name" 2>/dev/null)
    if [ -n "$path" ] && [ -f "$path" ]; then
        printf '\n=== BINARY %s ===\n' "$path"
        sha256 "$path" || status=1
        file "$path" || status=1
        pkg which "$path" 2>&1 || :
    else
        printf 'OPTIONAL BINARY ABSENT %s\n' "$name"
    fi
    for page in /usr/share/man/man8/"$name".8* /usr/local/share/man/man8/"$name".8*; do
        [ -f "$page" ] || continue
        printf '\n=== MANUAL %s ===\n' "$page"
        case "$page" in
            *.gz) gzip -cd "$page" || status=1 ;;
            *) cat "$page" || status=1 ;;
        esac
        printf '\n=== END MANUAL ===\n'
    done
done
printf '\n=== DAEMON USAGE (nonzero usage exit expected) ===\n'
/usr/sbin/daemon -? 2>&1
printf 'daemon usage exit=%s\n' "$?"
for path in /var/unbound/unbound.conf /usr/local/etc/unbound/unbound.conf; do
    if [ -f "$path" ] && [ -r "$path" ]; then
        printf '\n=== UNBOUND DAEMON CONFIG %s ===\n' "$path"
        sha256 "$path" || status=1
        grep -nE '^[[:space:]]*(do-daemonize|include):' "$path" || :
    else
        printf 'OPTIONAL UNBOUND CONFIG ABSENT %s\n' "$path"
    fi
done
exit "$status"
"""


def test_pre_script_group_lifetime_on_freebsd(
    smoke_vm: SmokeVM,
    go_toolchain: GoToolchain,  # noqa: F811 -- the fixture imported above
    tmp_path: Path,
) -> None:
    """Deploy the branch package, audit actual sources, then require all four real Go lifetime checks."""
    helpers.deploy(smoke_vm)
    audit = smoke_vm.ssh(SOURCE_AUDIT, timeout=60)
    helpers.DIAG_DIR.mkdir(parents=True, exist_ok=True)
    evidence = helpers.DIAG_DIR / f"prescript-native-source-{uuid4().hex}.txt"
    evidence.write_text(
        f"AUDIT EVIDENCE ONLY; no detach conclusion. SSH exit={audit.returncode}\n"
        f"{audit.stdout}\nSTDERR:\n{audit.stderr}",
        encoding="utf-8",
    )
    print(f"Native source audit evidence (not a behavioral check or detach conclusion): {evidence}")
    source = ""
    full_source = False
    line_number = 0
    launch = re.compile(r"\b(function|exec|daemon|service|setsid|procctl|mwexec\w*|shell_exec|system|popen)\b|&\s*$")
    for line in audit.stdout.splitlines():
        if line.startswith("=== SOURCE "):
            source = line
            full_source = line.endswith(" MODE FULL ===")
            line_number = 0
            print(line)
        elif line == "=== END SOURCE ===":
            source = ""
        elif source:
            line_number += 1
            if full_source or launch.search(line):
                print(f"  {line_number}: {line}")
        elif line.strip():
            print(line)
    assert audit.returncode == 0, f"native source audit failed; full evidence: {evidence}\n{audit.stderr}"
    for name in ("services.inc", "filter.inc", "unbound.inc"):
        assert re.search(
            rf"^=== SOURCE /etc/inc/{re.escape(name)} SHA256 [0-9a-f]{{64}} MODE FULL ===$",
            audit.stdout,
            re.MULTILINE,
        ), f"{name} must retain multiline launcher arguments in stdout; full evidence: {evidence}"

    binary = tmp_path / "prescript.test"
    built = subprocess.run(
        [str(go_toolchain.go), "test", "-c", "-o", str(binary), "./feedparse"],
        cwd=GO_DIR,
        env={**go_toolchain.env, "GOOS": "freebsd", "GOARCH": _goarch(smoke_vm, "pfSense")},
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert built.returncode == 0, f"go test -c ./feedparse for FreeBSD failed:\n{built.stdout}\n{built.stderr}"
    guest_binary = f"/root/pfb_smoke_prescript-{uuid4().hex}.test"
    try:
        _upload(smoke_vm, binary, guest_binary, "root:wheel")
        run = smoke_vm.ssh(
            f"{guest_binary} -test.v -test.count=1 -test.timeout=150s -test.run '^({'|'.join(TESTS)})$'",
            timeout=180,
        )
        print(run.stdout)
    finally:
        cleanup = smoke_vm.ssh(f"rm -f {guest_binary} {guest_binary}.new", timeout=30)
        assert cleanup.returncode == 0, f"removing owned guest binary/staging file failed: {cleanup.stderr}"
    assert run.returncode == 0, f"pre-script tests failed on FreeBSD: rc={run.returncode}\n{run.stdout}\n{run.stderr}"
    for test in TESTS:
        assert re.search(rf"^--- PASS: {re.escape(test)} \([^\n]+\)$", run.stdout, re.MULTILINE), (
            f"{test} did not explicitly pass at top level:\n{run.stdout}"
        )
    assert re.search(r"^PASS$", run.stdout, re.MULTILINE), f"Go suite did not report PASS:\n{run.stdout}"
