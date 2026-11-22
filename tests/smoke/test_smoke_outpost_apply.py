"""issue #4037 (slice 8e): the version 2 Outpost apply on a real pfSense box, against a real pfb-core serving a store.

* a request with no cursor is answered ``full``: the table, its mirror and the cursor file hold the generation served;
* a cursor at generation 1 is answered ``delta``: the parts are fetched as plain text, merged, and ``pfctl -T show``
  equals the canonical set of generation 2, the mirror's digest the store's;
* the apply lock held: exit status 75, no result line, no cursor moved.

A second pfb-core is started with ``--resource-dir`` over a store written in its on-disk format, as
``test_smoke_core_api.py`` does; the update command's entry, ``pfb_core_update_serve()``, is run with the request on
stdin and its result file, pointed at that Core's socket. The package's own Core and rc script are not changed.
"""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Iterator
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

PHP = "/usr/local/bin/php"
CURL = "/usr/local/bin/curl"
CORE_BIN = "/usr/local/pkg/pfblockerng/core/bin/freebsd-$(uname -p | sed s/aarch64/arm64/)/pfb-core"
WORK = "/var/tmp/pfb_smoke_outpost_apply"
ALIAS = "pfB_smokev2_v4"
RID = "ip-set/smokev2/ipv4"
CURSORS = "/var/db/pfblockerng/pfb_apply_cursors.json"
MIRROR = f"/var/db/aliastables/{ALIAS}.txt"
FEED_LOCK = "/var/db/pfblockerng/pfb_feed_pass.lock"
# Outer bound on the second Core answering: salvage only, never an assertion about duration.
READY_WATCHDOG = 60.0
GEN1 = ["192.0.2.10", "192.0.2.11", "198.51.100.0/24"]
GEN2 = ["192.0.2.10", "198.51.100.0/24", "203.0.113.7"]

# A store of two generations of RID in Core's on-disk format: index.json, <id with / as ~>.<generation>.body, and the
# delta from generation 1 as <id>.2.1.add and .remove (issue #4049).
STORE_PHP = r"""<?php
[, $dir, $gen1, $gen2] = $argv;
$gen1 = json_decode($gen1, TRUE); $gen2 = json_decode($gen2, TRUE);
$write = function (string $name, array $members) use ($dir): array {
    sort($members, SORT_STRING);
    $body = $members === [] ? '' : implode("\n", $members) . "\n";
    file_put_contents("$dir/$name", $body);
    chmod("$dir/$name", 0600);
    return ['digest' => hash('xxh128', $body), 'length' => strlen($body), 'entries' => count($members)];
};
$metadata = ['action' => 'deny', 'direction' => ['ingress', 'egress']];
$g1 = ['generation' => '1'] + $write('ip-set~smokev2~ipv4.1.body', $gen1) + ['metadata' => $metadata];
$g2 = ['generation' => '2'] + $write('ip-set~smokev2~ipv4.2.body', $gen2) + ['metadata' => $metadata];
$parts = ['add' => $write('ip-set~smokev2~ipv4.2.1.add', array_values(array_diff($gen2, $gen1))),
    'remove' => $write('ip-set~smokev2~ipv4.2.1.remove', array_values(array_diff($gen1, $gen2)))];
file_put_contents("$dir/index.json", json_encode(['version' => 1, 'resources' => ['ip-set/smokev2/ipv4' =>
    ['current' => $g2, 'applied' => $g1, 'delta' => ['from' => '1'] + $parts]]], JSON_UNESCAPED_SLASHES));
chmod("$dir/index.json", 0600);
chmod($dir, 0700);
"""
# The update command's entry with the Core socket of the second Core: argv is the socket, the request file, the result
# file and a file that gets one JSON line per fetch (the reply's kind, and whether it fell back to the full body); the
# exit status is what the update command exits with.
APPLY_PHP = r"""<?php
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
[, $socket, $request, $result, $kinds] = $argv;
$pfb['core_socket'] = $socket;
$fetch = static function (mixed ...$args) use ($kinds): array {
    $got = pfb_outpost_fetch(...$args);
    $line = json_encode(['kind' => $got['kind'], 'fellBack' => $got['fellBack']]);
    file_put_contents($kinds, "{$line}\n", FILE_APPEND);
    return $got;
};
exit(pfb_core_update_serve((string) file_get_contents($request), $result, ['fetch' => $fetch]));
"""


def body(lines: list[str]) -> str:
    return "".join(f"{line}\n" for line in sorted(lines))


@pytest.fixture(scope="module")
def apply_vm(smoke_vm: SmokeVM) -> Iterator[tuple[SmokeVM, str]]:
    """The branch package, one IP group built by an update pass, and a second Core serving the store."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    feed = h.write_local_feed(smoke_vm, "smoke_outpost_apply.txt", "192.0.2.10\n")
    h.inject(smoke_vm, h.IpCase(aliasname="smokev2", feed_url=feed, header="smokev2", action="Deny_Both"))
    h.reload(smoke_vm, "update")
    h.apply_filter_sync(smoke_vm)
    vm = smoke_vm
    setup = vm.ssh(
        f"rm -rf {WORK} && mkdir -p -m 700 {WORK}/store {WORK}/state {WORK}/run && "
        f"cat > {WORK}/store.php <<'EOF'\n{STORE_PHP}\nEOF\n"
        f"cat > {WORK}/apply.php <<'EOF'\n{APPLY_PHP}\nEOF\n"
        f"{PHP} {WORK}/store.php {WORK}/store {shlex.quote(json.dumps(GEN1))} {shlex.quote(json.dumps(GEN2))}",
        timeout=60,
    )
    assert setup.returncode == 0, f"the store was not written: {setup.stdout}{setup.stderr}"
    api = f"{WORK}/run/api.sock"
    try:
        command = f"{CORE_BIN} --socket {api} --state-dir {WORK}/state --resource-dir {WORK}/store"
        with h.start_core(vm, command, api, f"{WORK}/core.log", watchdog=READY_WATCHDOG):
            yield vm, api
    finally:
        vm.ssh(f"rm -f {CURSORS}", timeout=30)


def apply(vm: SmokeVM, api: str, request: dict[str, Any], *, locked: bool = False) -> tuple[int, list[dict[str, Any]]]:
    """Run the apply with ``request``; its exit status and result lines. ``locked`` holds the apply lock meanwhile."""
    hold = (
        f'{PHP} -r \'$f = fopen("{FEED_LOCK}", "c"); flock($f, LOCK_EX); echo "held\\n"; fgets(STDIN);\' '
        f"< {WORK}/lockfifo > {WORK}/lock.out & "
        if locked
        else ""
    )
    pre = f"rm -f {WORK}/lockfifo; mkfifo {WORK}/lockfifo; exec 9<>{WORK}/lockfifo; {hold}" if locked else ""
    wait = f"until grep -q held {WORK}/lock.out 2>/dev/null; do sleep 1; done; " if locked else ""
    release = "; echo >&9" if locked else ""
    run = vm.ssh(
        f"{pre}{wait}printf %s {shlex.quote(json.dumps(request))} > {WORK}/request.json && "
        f"rm -f {WORK}/result {WORK}/kinds && "
        f"{PHP} {WORK}/apply.php {api} {WORK}/request.json {WORK}/result {WORK}/kinds; rc=$?{release}; "
        f"echo; echo RC=$rc; cat {WORK}/result 2>/dev/null",
        timeout=600,
    )
    tail = run.stdout.split("\nRC=", 1)[1]
    status, _, lines = tail.partition("\n")
    return int(status), [json.loads(line) for line in lines.splitlines() if line.strip()]


def fetched(vm: SmokeVM) -> list[dict[str, Any]]:
    """What each fetch of the last apply got: the reply's kind, and whether it fell back to the full body."""
    out = vm.ssh(f"cat {WORK}/kinds 2>/dev/null", timeout=30).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def seed_generation_one(vm: SmokeVM) -> None:
    """The table, its mirror and the cursor file at generation 1."""
    seeded = vm.ssh(
        f"printf %s {shlex.quote(body(GEN1))} > {MIRROR} && pfctl -t {ALIAS} -T replace -f {MIRROR} && "
        f'{PHP} -r \'echo json_encode(["schema" => 1, "resources" => ["{RID}" => ["generation" => "1", '
        f'"digest" => hash_file("xxh128", "{MIRROR}"), "entries" => {len(GEN1)}]]], JSON_UNESCAPED_SLASHES);\' '
        f"> {CURSORS}",
        timeout=60,
    )
    assert seeded.returncode == 0, seeded.stdout + seeded.stderr


def request(generation: str, entries: int) -> dict[str, Any]:
    return {
        "version": 2,
        "trigger": "manual",
        "scope": "ip",
        "resources": [
            {
                "id": RID,
                "generation": generation,
                "action": "deny",
                "direction": ["ingress", "egress"],
                "entries": entries,
            }
        ],
    }


def test_with_no_cursor_the_full_body_becomes_the_table(apply_vm: tuple[SmokeVM, str]) -> None:
    vm, api = apply_vm
    vm.ssh(f"rm -f {CURSORS}", timeout=30)
    status, lines = apply(vm, api, request("2", len(GEN2)))
    assert status == 0, lines
    assert lines and lines[-1].get("applied") == {RID: "2"}, lines
    assert sorted(h.pfctl_table_members(vm, ALIAS)) == sorted(GEN2)
    assert vm.ssh(f"cat {MIRROR}", timeout=30).stdout == body(GEN2)
    cursors = json.loads(vm.ssh(f"cat {CURSORS}", timeout=30).stdout)
    assert cursors["resources"][RID]["generation"] == "2"


def test_a_cursor_at_generation_one_applies_the_delta(apply_vm: tuple[SmokeVM, str]) -> None:
    vm, api = apply_vm
    seed_generation_one(vm)
    assert sorted(h.pfctl_table_members(vm, ALIAS)) == sorted(GEN1), "before: the table holds generation 1"
    status, lines = apply(vm, api, request("2", len(GEN2)))
    assert status == 0, lines
    assert fetched(vm) == [{"kind": "delta", "fellBack": False}], "the delta from generation 1, not the full body"
    assert lines[-1].get("applied") == {RID: "2"}, lines
    assert lines[-1].get("changedAliases") == [ALIAS], lines
    assert sorted(h.pfctl_table_members(vm, ALIAS)) == sorted(GEN2), "pfctl -T show equals the canonical set"
    store_body = f"{WORK}/store/ip-set~smokev2~ipv4.2.body"
    digests = vm.ssh(
        f'{PHP} -r \'echo hash_file("xxh128", "{MIRROR}"), " ", hash_file("xxh128", "{store_body}");\'',
        timeout=30,
    ).stdout.split()
    assert len(digests) == 2 and digests[0] == digests[1], f"the mirror is not the store's generation 2: {digests}"


def test_a_held_apply_lock_defers_with_no_result_line(apply_vm: tuple[SmokeVM, str]) -> None:
    vm, api = apply_vm
    # a cursor older than the request: an apply that moved it while locked would change it
    seed_generation_one(vm)
    before = vm.ssh(f"cat {CURSORS} 2>/dev/null", timeout=30).stdout
    assert json.loads(before)["resources"][RID]["generation"] == "1", "before: the cursor is at generation 1"
    status, lines = apply(vm, api, request("2", len(GEN2)), locked=True)
    assert status == 75, lines
    assert lines == []
    assert vm.ssh(f"cat {CURSORS} 2>/dev/null", timeout=30).stdout == before, "no cursor moved"
    assert fetched(vm) == [], "nothing was fetched"
