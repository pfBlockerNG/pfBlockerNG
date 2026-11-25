"""issue #4252: pfB-DNS on the Core input, end to end on a real box, before the cutover makes it the default.

The rc scripts do not run pfB-DNS on the Core input yet, so this module starts both halves by hand, beside the package's
own services:

* a second Core (the package's pfb-core) over a store of its own, seeded with a ``dnsbl/manifest`` and one feed, with
  the package's settings adapter (``config.xml``) and ``--client-uid``/``--socket-group`` for ``unbound``, as the
  package's rc line admits pfB-DNS (#4250);
* a second pfB-DNS (the package's pfb-dns) on 127.0.0.1:15353, ``--user unbound``, ``--core-socket`` that Core, and a
  module directory of its own, so its cache folder is ``<module dir>/pfb_dns`` (#4251).

What it proves:

* a domain of the published feed is blocked after the first poll, and the generation served is reported to Core
  (``applied.json``);
* while Core is stopped (SIGSTOP), pfB-DNS keeps serving the last generation; a restart of pfB-DNS with Core down serves
  the cache it kept (owner, 2026-11-25: no time limit, no watchdog);
* the 5,000,000-domain measurement: the start time and peak memory of a pfB-DNS that builds from the cache, printed
  (``PFB_CORE_INPUT_MEASURE``), never asserted. It needs a box with at least 4 GiB.

A settings change that reaches pfB-DNS by a swap is not driven here: it needs a ``config.xml`` edit through the
adapter. The decider tests cover the swap (``core_settings_test.go``).
"""

from __future__ import annotations

import json
import os
import shlex
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

CORE_BIN = "/usr/local/pkg/pfblockerng/core/bin/freebsd-$(uname -p | sed s/aarch64/arm64/)/pfb-core"
DNS_BIN = "/usr/local/pkg/pfblockerng/dns_proxy/bin/freebsd-$(uname -p | sed s/aarch64/arm64/)/pfb-dns"
ADAPTER = "/usr/local/pkg/pfblockerng/pfb_core_settings.sh"
PHP = "/usr/local/bin/php"
PORT = 15353
# Outer bounds that only salvage a stuck run, never an assertion about duration
READY_WATCHDOG = 60.0
SERVE_WATCHDOG = 120.0
MEASURE_ENTRIES = 5_000_000
MEASURE_MIN_RAM = 4 << 30
OPEN, CLOSE = "<<<SEED>>>", "<<<SEED-END>>>"

# The store Core serves: a dnsbl/manifest naming one feed, both generation 1, written as Core's store holds them
# (index.json + <id with / as ~>.<generation>.body). argv: the store, the feed's domains file, the count it holds.
SEED_PHP = r"""<?php
[, $dir, $domains, $n] = $argv;
$put = function (string $id, string $file) use ($dir): array {
    $name = str_replace('/', '~', $id) . '.1.body';
    rename($file, "$dir/$name");
    chmod("$dir/$name", 0600);
    return ['generation' => '1', 'digest' => hash_file('xxh128', "$dir/$name"), 'length' => filesize("$dir/$name"),
        'entries' => 0, 'metadata' => new stdClass()];
};
$feed = $put('dnsbl/feed-F', $domains);
$feed['entries'] = (int) $n;
$rows = [
    json_encode(['kind' => 'config', 'builtinLogFlag' => '0', 'top1mEnabled' => false]),
    json_encode(['kind' => 'feed', 'position' => 1, 'feed' => 'F', 'group' => 'G', 'logFlag' => '1',
        'provenance' => 'feed', 'mode' => 'deny', 'top1m' => false, 'resource' => 'dnsbl/feed-F', 'generation' => '1',
        'digest' => $feed['digest'], 'entries' => (int) $n]),
];
sort($rows, SORT_STRING);
file_put_contents("$dir/manifest.tmp", implode("\n", $rows) . "\n");
$manifest = $put('dnsbl/manifest', "$dir/manifest.tmp");
$manifest['entries'] = count($rows);
$index = ['dnsbl/feed-F' => ['current' => $feed], 'dnsbl/manifest' => ['current' => $manifest]];
file_put_contents("$dir/index.json", json_encode(['version' => 1, 'resources' => $index], JSON_UNESCAPED_SLASHES));
chmod("$dir/index.json", 0600);
echo '@OPEN@ok@CLOSE@';
"""


@dataclass
class Rig:
    vm: SmokeVM
    fence: str

    @property
    def api(self) -> str:
        return f"{self.fence}/core/api.sock"

    @property
    def module(self) -> str:
        return f"{self.fence}/mod"

    def ask(self, name: str) -> h.DnsAnswer:
        """The first answer pfB-DNS gives for name (A), or a failure when it gives none."""
        got = self.vm.ssh(f"{h.DRILL_BIN} -p {PORT} {shlex.quote(name)} A @127.0.0.1", timeout=30)
        assert "rcode:" in got.stdout, f"pfB-DNS gave no answer for {name}: {got.stdout}{got.stderr}"
        return h._parse_drill(got.stdout, "A")

    def blocked(self, name: str) -> bool:
        return self.ask(name).records == ["0.0.0.0"]


def seed_store(vm: SmokeVM, fence: str, domains: list[str] | None, count: int = 0) -> None:
    """Seed the fence's store with one feed: the given domains, or ``count`` generated ones."""
    vm.ssh(f"mkdir -m 700 {fence}/store", timeout=30)
    if domains is not None:
        listed = "\n".join(sorted(domains)) + "\n"
        wrote = vm.ssh(f"printf %s {shlex.quote(listed)} > {fence}/feed.txt", timeout=60)
        count = len(domains)
    else:  # sorted as Core keeps members: d<i>.<run>.com sorted as strings
        wrote = vm.ssh(f"jot -w 'd%d.pfbmeasure.com' {count} 1 | LC_ALL=C sort > {fence}/feed.txt", timeout=600)
    assert wrote.returncode == 0, f"could not write the feed: {wrote.stderr}"
    script = SEED_PHP.replace("@OPEN@", OPEN).replace("@CLOSE@", CLOSE)
    vm.ssh(f"printf %s {shlex.quote(script)} > {fence}/seed.php", timeout=60)
    seeded = vm.ssh(f"{PHP} -d memory_limit=-1 {fence}/seed.php {fence}/store {fence}/feed.txt {count}", timeout=600)
    assert OPEN in seeded.stdout, f"the store was not seeded: rc={seeded.returncode} {seeded.stdout}{seeded.stderr}"


def start_dns(vm: SmokeVM, fence: str, log: str) -> str:
    """pfB-DNS on the Core input, as unbound, on 127.0.0.1:PORT; its pid once it serves."""
    command = (
        f"{DNS_BIN} --listen 127.0.0.1 --port {PORT} --upstream 127.0.0.1:5353 --ctl-socket {fence}/ctl.sock "
        f"--module-dir {fence}/mod --core-socket {fence}/core/api.sock --user unbound --ready-file {fence}/mod/ready"
    )
    start = vm.ssh(f"nohup {command} </dev/null >{log} 2>&1 & echo $!", timeout=30)
    pid = start.stdout.strip()
    assert start.returncode == 0 and pid.isdigit(), f"pfB-DNS did not start: {start.stdout}{start.stderr}"
    deadline = time.monotonic() + READY_WATCHDOG
    while vm.ssh(f"test -s {fence}/mod/ready", timeout=30).returncode != 0:  # the real condition: it serves
        if vm.ssh(f"kill -0 {pid}", timeout=30).returncode != 0 or time.monotonic() > deadline:
            pytest.fail(f"STUCK: pfB-DNS never became ready:\n{vm.ssh(f'tail -n 30 {log}', timeout=30).stdout}")
        time.sleep(1)
    return pid


def stop(vm: SmokeVM, pid: str) -> None:
    vm.ssh(
        f"kill -CONT {pid} 2>/dev/null; kill {pid} 2>/dev/null; sleep 1; kill -9 {pid} 2>/dev/null; true", timeout=30
    )


@pytest.fixture(scope="module")
def box(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The branch package deployed once."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    yield smoke_vm


@pytest.fixture
def fence(box: SmokeVM) -> Iterator[str]:
    """A scratch folder unbound can pass through (0711), with a module directory of unbound's own."""
    made = box.ssh("mktemp -d /tmp/pfbcoreinput.XXXXXX", timeout=30)
    path = made.stdout.strip()
    assert made.returncode == 0 and path.startswith("/tmp/pfbcoreinput."), f"no scratch: {made.stdout}{made.stderr}"
    box.ssh(f"chmod 711 {path} && mkdir -m 700 {path}/core {path}/mod && chown unbound:unbound {path}/mod", timeout=30)
    yield path
    box.ssh(f"rm -rf {path}", timeout=120)


def core_command(fence: str) -> str:
    return (
        f"{CORE_BIN} --socket {fence}/core/api.sock --state-dir {fence}/state --resource-dir {fence}/store "
        f"--settings-backend-cmd {ADAPTER} --client-uid $(id -u unbound) --socket-group $(id -g unbound)"
    )


def test_pfb_dns_serves_what_core_publishes_and_keeps_serving_without_core(box: SmokeVM, fence: str) -> None:
    blocked, other = h.unique_domain(), h.unique_domain()
    seed_store(box, fence, [blocked])
    rig = Rig(box, fence)
    with h.start_core(box, core_command(fence), rig.api, f"{fence}/core.log", watchdog=READY_WATCHDOG) as core:
        dns = start_dns(box, fence, f"{fence}/dns.log")
        try:
            # Served after the first poll; a name the feed does not list is not blocked
            deadline = time.monotonic() + SERVE_WATCHDOG
            while not rig.blocked(blocked):  # the real condition: the generation is served
                if time.monotonic() > deadline:
                    said = box.ssh(f"tail -n 30 {fence}/dns.log", timeout=30).stdout
                    pytest.fail(f"STUCK: {blocked} was never blocked from Core's data:\n{said}")
                time.sleep(2)
            assert not rig.blocked(other), f"{other}, which no feed lists, is blocked"

            # Reported: Core keeps the generation pfB-DNS serves
            report = box.ssh(f"cat {fence}/state/applied.json", timeout=30)
            assert report.returncode == 0, f"no report reached Core: {report.stderr}"
            assert json.loads(report.stdout)["resources"]["dnsbl/feed-F"]["generation"] == "1", report.stdout

            # Core stuck: pfB-DNS keeps serving the generation it has
            box.ssh(f"kill -STOP {core}", timeout=30)
            assert rig.blocked(blocked), "pfB-DNS stopped blocking while Core was stopped"
            box.ssh(f"kill -CONT {core}", timeout=30)
        finally:
            stop(box, dns)

    # Core down: a restart of pfB-DNS serves the cache it kept in its folder
    cache = box.ssh(f"/usr/bin/stat -f '%Lp %Su' {fence}/mod/pfb_dns", timeout=30).stdout.strip()
    assert cache == "700 unbound", f"the cache folder is {cache!r}, want unbound's alone"
    dns = start_dns(box, fence, f"{fence}/dns2.log")
    try:
        assert rig.blocked(blocked), "a restart with Core down does not serve the cached generation"
    finally:
        stop(box, dns)


def test_measure_a_start_from_a_cache_of_five_million_domains(box: SmokeVM, fence: str) -> None:
    """The start time and peak memory of pfB-DNS building 5,000,000 domains from its cache: printed, never asserted."""
    ram = int(box.ssh("sysctl -n hw.physmem", timeout=30).stdout.strip() or 0)
    if ram < MEASURE_MIN_RAM:
        pytest.skip(f"the box has {ram >> 20} MiB; the measurement needs {MEASURE_MIN_RAM >> 20} MiB")
    seed_store(box, fence, None, MEASURE_ENTRIES)
    rig = Rig(box, fence)
    probe = "d1.pfbmeasure.com"
    with h.start_core(box, core_command(fence), rig.api, f"{fence}/core.log", watchdog=READY_WATCHDOG):
        began = time.monotonic()
        dns = start_dns(box, fence, f"{fence}/dns.log")
        try:
            deadline = time.monotonic() + 1800
            while not rig.blocked(probe):  # the real condition: the five million are served
                assert time.monotonic() < deadline, "STUCK: the measured generation was never served"
                time.sleep(5)
            from_core = time.monotonic() - began
        finally:
            stop(box, dns)
    began = time.monotonic()
    dns = start_dns(box, fence, f"{fence}/dns2.log")
    try:
        assert rig.blocked(probe), "a start from the cache does not serve the measured generation"
        from_cache = time.monotonic() - began
        rss = box.ssh(f"/usr/bin/procstat -r {dns} | awk '/maximum RSS/ {{print $NF}}'", timeout=30).stdout.strip()
    finally:
        stop(box, dns)
    print(
        "PFB_CORE_INPUT_MEASURE "
        + json.dumps(
            {
                "entries": MEASURE_ENTRIES,
                "first_start_s": round(from_core, 1),
                "cached_start_s": round(from_cache, 1),
                "cached_max_rss_kb": rss,
                "box_ram_mib": ram >> 20,
            }
        )
    )
