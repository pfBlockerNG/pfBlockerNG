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
capture() {
    path=$1
    if [ ! -f "$path" ] || [ ! -r "$path" ]; then
        printf 'UNREADABLE REQUIRED SOURCE %s\n' "$path"
        status=1
        return
    fi
    digest=$(sha256 -q "$path") || { status=1; return; }
    printf '\n=== SOURCE %s SHA256 %s ===\n' "$path" "$digest"
    cat "$path" || status=1
    printf '\n=== END SOURCE ===\n'
}
capture /etc/rc.filter_configure_sync
capture /usr/sbin/service
capture /etc/inc/filter.inc
for pattern in /etc/inc/*service*.inc /etc/inc/*unbound*.inc /etc/inc/*dhcp*.inc \
    /etc/inc/*radv*.inc /etc/inc/*router*.inc /etc/inc/*ra.inc \
    /usr/local/etc/rc.d/*unbound* /usr/local/etc/rc.d/*dhcp* /usr/local/etc/rc.d/*radv* \
    /etc/rc.d/*unbound* /etc/rc.d/*dhcp* /etc/rc.d/*radv* \
    /usr/local/etc/rc.d/pfb_*.sh /etc/rc.d/pfb_*.sh; do
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
exit "$status"
"""


def test_pre_script_group_lifetime_on_freebsd(
    smoke_vm: SmokeVM,
    go_toolchain: GoToolchain,  # noqa: F811 -- the fixture imported above
    tmp_path: Path,
) -> None:
    """Audit actual service sources, then require all four real Go lifetime checks."""
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
    line_number = 0
    launch = re.compile(r"\b(function|exec|daemon|service|setsid|procctl|mwexec\w*|shell_exec|system|popen)\b|&\s*$")
    for line in audit.stdout.splitlines():
        if line.startswith("=== SOURCE "):
            source = line
            line_number = 0
            print(line)
        elif line == "=== END SOURCE ===":
            source = ""
        elif source:
            line_number += 1
            if launch.search(line):
                print(f"  {line_number}: {line}")
        elif line.strip():
            print(line)
    assert audit.returncode == 0, f"native source audit failed; full evidence: {evidence}\n{audit.stderr}"

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
