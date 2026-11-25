"""issue #4252: pfB-DNS on the Core input, end to end on a real box, before the cutover makes it the default.

The rc scripts do not run pfB-DNS on the Core input yet, so this module starts both halves by hand, beside the package's
own services:

* a second Core (the package's pfb-core) over a store of its own, seeded with a ``dnsbl/manifest`` and one feed, with
  the package's settings adapter (``config.xml``) and ``--client-uid``/``--socket-group`` for ``unbound``, as the
  package's rc line admits pfB-DNS (#4250);
* a second pfB-DNS (the package's pfb-dns) on 127.0.0.1:15353, ``--user unbound``, ``--core-socket`` that Core, and a
  module directory of its own, so its cache folder is ``<module dir>/pfb_dns`` (#4251). Its upstream is the box's
  127.0.0.1:53, which answers whether or not the package's own pfB-DNS stands in front of Unbound, and its control
  socket has a folder of its own: pfB-DNS closes that folder to 0700, which would shut unbound out of the fence.

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
# where the package's own pfB-DNS writes its ready file, under a name of this module's
READY = "/var/unbound/pfb_dns_ready_smoke4252"
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

    def blocked(self, name: str) -> bool:
        """Whether pfB-DNS answers name (A) with its block, 0.0.0.0. A name it does not block is forwarded to the box's
        resolver, which may not answer here; that is no block either."""
        got = self.vm.ssh(f"{h.DRILL_BIN} -p {PORT} {shlex.quote(name)} A @127.0.0.1", timeout=30)
        return "rcode:" in got.stdout and h._parse_drill(got.stdout, "A").records == ["0.0.0.0"]


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
        f"{DNS_BIN} --listen 127.0.0.1 --port {PORT} --upstream 127.0.0.1:53 --ctl-socket {fence}/ctl/ctl.sock "
        f"--module-dir {fence}/mod --core-socket {fence}/core/api.sock --user unbound --ready-file {READY}"
    )
    start = vm.ssh(f"nohup {command} </dev/null >{log} 2>&1 & echo $!", timeout=30)
    pid = start.stdout.strip()
    assert start.returncode == 0 and pid.isdigit(), f"pfB-DNS did not start: {start.stdout}{start.stderr}"
    deadline = time.monotonic() + READY_WATCHDOG
    while vm.ssh(f'test -s {READY} && test "$(cat {READY})" = {pid}', timeout=30).returncode != 0:  # it serves
        if vm.ssh(f"kill -0 {pid}", timeout=30).returncode != 0 or time.monotonic() > deadline:
            said = vm.ssh(f"tail -n 30 {log}; ls -ld {fence} {fence}/mod; id unbound", timeout=30).stdout
            pytest.fail(f"STUCK: pfB-DNS never became ready:\n{said}")
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


def make_fence(box: SmokeVM) -> str:
    """A scratch folder unbound can pass through (0711), with a module directory of unbound's own."""
    made = box.ssh("mktemp -d /tmp/pfbcoreinput.XXXXXX", timeout=30)
    path = made.stdout.strip()
    assert made.returncode == 0 and path.startswith("/tmp/pfbcoreinput."), f"no scratch: {made.stdout}{made.stderr}"
    made = box.ssh(
        f"chmod 711 {path} && mkdir -m 700 {path}/core {path}/mod && chown unbound:unbound {path}/mod", timeout=30
    )
    assert made.returncode == 0, f"could not make the fence: {made.stderr}"
    return path


def core_command(fence: str) -> str:
    return (
        f"{CORE_BIN} --socket {fence}/core/api.sock --state-dir {fence}/state --resource-dir {fence}/store "
        f"--settings-backend-cmd {ADAPTER} --client-uid $(id -u unbound) --socket-group $(id -g unbound)"
    )


@dataclass
class Observation:
    blocked: bool  # the feed's domain, after the first poll
    other_blocked: bool  # a domain no feed lists
    report: str  # Core's applied.json
    blocked_while_core_stopped: bool
    cache_folder: str  # mode and owner of <module dir>/pfb_dns
    blocked_after_restart_without_core: bool


@pytest.fixture(scope="module")
def observed(box: SmokeVM) -> Iterator[Observation]:
    """All the box work, in the fixture (the smoke tier caps a test body at 30 s): what pfB-DNS did, for the tests."""
    fence = make_fence(box)
    try:
        listed, other = h.unique_domain(), h.unique_domain()
        seed_store(box, fence, [listed])
        rig = Rig(box, fence)
        with h.start_core(box, core_command(fence), rig.api, f"{fence}/core.log", watchdog=READY_WATCHDOG) as core:
            dns = start_dns(box, fence, f"{fence}/dns.log")
            try:
                deadline = time.monotonic() + SERVE_WATCHDOG
                while not rig.blocked(listed):  # the real condition: the generation is served
                    if time.monotonic() > deadline:
                        probe = (
                            f"tail -n 12 {fence}/dns.log; ls -ld {fence} {fence}/core {rig.api}; "
                            f"/usr/bin/su -m unbound -c '/usr/local/bin/curl -sS -o /dev/null -w %{{http_code}} "
                            f"--unix-socket {rig.api} -X POST http://localhost/v1/GetVersion'; echo; "
                            f"procstat -s $(pgrep -f 'pfb-dns --listen 127.0.0.1 --port {PORT}') 2>&1 | tail -2"
                        )
                        said = box.ssh(probe, timeout=30).stdout + box.ssh(probe, timeout=30).stderr
                        pytest.fail(f"STUCK: {listed} was never blocked from Core's data:\n{said}")
                    time.sleep(2)
                other_blocked = rig.blocked(other)
                report = box.ssh(f"cat {fence}/state/applied.json 2>&1", timeout=30).stdout
                box.ssh(f"kill -STOP {core}", timeout=30)
                while_stopped = rig.blocked(listed)
                box.ssh(f"kill -CONT {core}", timeout=30)
            finally:
                stop(box, dns)
        cache = box.ssh(f"/usr/bin/stat -f '%Lp %Su' {fence}/mod/pfb_dns 2>&1", timeout=30).stdout.strip()
        dns = start_dns(box, fence, f"{fence}/dns2.log")
        try:
            after_restart = rig.blocked(listed)
        finally:
            stop(box, dns)
        yield Observation(True, other_blocked, report, while_stopped, cache, after_restart)
    finally:
        box.ssh(f"rm -rf {fence} {READY}", timeout=120)


def test_pfb_dns_blocks_what_core_publishes_and_only_that(observed: Observation) -> None:
    assert observed.blocked
    assert not observed.other_blocked, "a domain no feed lists is blocked"


def test_pfb_dns_reports_the_generation_it_serves_to_core(observed: Observation) -> None:
    resources = json.loads(observed.report)["resources"]
    assert resources["dnsbl/feed-F"]["generation"] == "1", observed.report


def test_pfb_dns_keeps_serving_while_core_is_stopped(observed: Observation) -> None:
    assert observed.blocked_while_core_stopped, "pfB-DNS stopped blocking while Core was stopped"


def test_pfb_dns_keeps_its_cache_in_a_folder_of_unbounds_alone(observed: Observation) -> None:
    assert observed.cache_folder == "700 unbound", f"the cache folder is {observed.cache_folder!r}"


def test_a_restart_with_core_down_serves_the_cache(observed: Observation) -> None:
    assert observed.blocked_after_restart_without_core, "a restart with Core down does not serve the cache"


@pytest.fixture(scope="module")
def measured(box: SmokeVM) -> Iterator[dict[str, object]]:
    """The 5,000,000-domain start, timed in the fixture: from Core, then from the cache."""
    ram = int(box.ssh("sysctl -n hw.physmem", timeout=30).stdout.strip() or 0)
    if ram < MEASURE_MIN_RAM:
        pytest.skip(f"the box has {ram >> 20} MiB; the measurement needs {MEASURE_MIN_RAM >> 20} MiB")
    fence = make_fence(box)
    try:
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
            served = rig.blocked(probe)
            from_cache = time.monotonic() - began
            rss = box.ssh(f"/usr/bin/procstat -r {dns} | awk '/maximum RSS/ {{print $NF}}'", timeout=30).stdout.strip()
        finally:
            stop(box, dns)
        yield {
            "entries": MEASURE_ENTRIES,
            "first_start_s": round(from_core, 1),
            "cached_start_s": round(from_cache, 1),
            "cached_max_rss_kb": rss,
            "box_ram_mib": ram >> 20,
            "served": served,
        }
    finally:
        box.ssh(f"rm -rf {fence} {READY}", timeout=120)


def test_measure_a_start_from_a_cache_of_five_million_domains(measured: dict[str, object]) -> None:
    """The start time and peak memory of pfB-DNS building 5,000,000 domains: printed, never asserted."""
    print("PFB_CORE_INPUT_MEASURE " + json.dumps(measured))
    assert measured["served"], "a start from the cache does not serve the measured generation"
