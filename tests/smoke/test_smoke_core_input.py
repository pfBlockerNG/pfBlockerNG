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
* while Core is stopped (SIGSTOP) with a poll of pfB-DNS waiting on it, pfB-DNS keeps serving the last generation;
  once Core is back, it serves and reports the next one, with no restart; a restart of pfB-DNS with Core down serves
  the cache it kept (owner, 2026-11-25: no time limit, no watchdog);
* the 5,000,000-domain measurement: the start time and peak memory of a pfB-DNS that builds from Core, then from the
  cache, printed (``PFB_CORE_INPUT_MEASURE``), never asserted. It runs only with ``PFB_CORE_INPUT_MEASURE=1``, on a
  box with at least 4 GiB.

A settings change that reaches pfB-DNS by a swap is not driven here: it needs a ``config.xml`` edit through the
adapter. The decider tests cover the swap (``core_settings_test.go``).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from collections.abc import Callable, Iterator
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
MANIFEST_ASK = json.dumps({"resources": {"dnsbl/manifest": {}}})

# The store Core serves: a dnsbl/manifest naming one feed and the PSL, all generation 1, written as Core's store holds
# them (index.json + <id with / as ~>.<generation>.body). argv: the store, the feed's domains file, the count it holds,
# the generation. Core reads index.json on each call, so a later seed publishes the next generation to a running Core.
SEED_PHP = r"""<?php
[, $dir, $domains, $n, $g] = $argv;
$put = function (string $id, string $file) use ($dir, $g): array {
    $name = str_replace('/', '~', $id) . ".$g.body";
    rename($file, "$dir/$name");
    chmod("$dir/$name", 0600);
    return ['generation' => $g, 'digest' => hash_file('xxh128', "$dir/$name"), 'length' => filesize("$dir/$name"),
        'entries' => 0, 'metadata' => new stdClass()];
};
$feed = $put('dnsbl/feed-F', $domains);
$feed['entries'] = (int) $n;
// The PSL Core always publishes: the build refuses to run without one. One ICANN rule is enough here.
file_put_contents("$dir/psl.tmp", json_encode(['section' => 'icann', 'rule' => 'com']) . "\n");
$psl = $put('dnsbl/psl', "$dir/psl.tmp");
$psl['entries'] = 1;
$rows = [
    json_encode(['kind' => 'config', 'builtinLogFlag' => '0', 'top1mEnabled' => false]),
    json_encode(['kind' => 'feed', 'position' => 1, 'feed' => 'F', 'group' => 'G', 'logFlag' => '1',
        'provenance' => 'feed', 'mode' => 'deny', 'top1m' => false, 'resource' => 'dnsbl/feed-F', 'generation' => $g,
        'digest' => $feed['digest'], 'entries' => (int) $n]),
    json_encode(['kind' => 'member', 'resource' => 'dnsbl/psl', 'generation' => $g, 'digest' => $psl['digest'],
        'entries' => 1]),
];
sort($rows, SORT_STRING);
file_put_contents("$dir/manifest.tmp", implode("\n", $rows) . "\n");
$manifest = $put('dnsbl/manifest', "$dir/manifest.tmp");
$manifest['entries'] = count($rows);
$index = ['dnsbl/feed-F' => ['current' => $feed], 'dnsbl/psl' => ['current' => $psl],
    'dnsbl/manifest' => ['current' => $manifest]];
file_put_contents("$dir/index.tmp", json_encode(['version' => 1, 'resources' => $index], JSON_UNESCAPED_SLASHES));
chmod("$dir/index.tmp", 0600);
rename("$dir/index.tmp", "$dir/index.json"); // whole, for a Core that reads it meanwhile
echo '@OPEN@ok@CLOSE@';
"""


@dataclass
class Rig:
    vm: SmokeVM
    fence: str

    @property
    def api(self) -> str:
        return f"{self.fence}/core/api.sock"

    def holds_a_request(self) -> bool:
        """Whether a connection to Core's socket holds bytes Core has not read (netstat -f unix: Recv-Q, Addr)."""
        rows = self.vm.ssh("/usr/bin/netstat -f unix -n", timeout=30).stdout.splitlines()
        return any(
            len(cols) > 3 and cols[-1] == self.api and cols[2].isdigit() and int(cols[2]) > 0
            for cols in (row.split() for row in rows)
        )

    def reported(self, applied: str) -> str:
        """The feed's generation in Core's applied.json; "" before Core has one."""
        held = self.vm.ssh(f"cat {applied} 2>/dev/null", timeout=30).stdout
        try:
            return str(json.loads(held)["resources"]["dnsbl/feed-F"]["generation"])
        except (ValueError, KeyError, TypeError):
            return ""

    def blocked(self, name: str) -> bool:
        """Whether pfB-DNS answers name (A) with its block, 0.0.0.0. A name it does not block is forwarded to the box's
        resolver, which may not answer here; that is no block either."""
        got = self.vm.ssh(f"{h.DRILL_BIN} -p {PORT} {shlex.quote(name)} A @127.0.0.1", timeout=30)
        return "rcode:" in got.stdout and h._parse_drill(got.stdout, "A").records == ["0.0.0.0"]


def seed_store(vm: SmokeVM, fence: str, domains: list[str] | None, count: int = 0, generation: int = 1) -> None:
    """Seed the fence's store with one feed at generation: the given domains, or ``count`` generated ones."""
    vm.ssh(f"mkdir -p -m 700 {fence}/store", timeout=30)
    if domains is not None:
        listed = "\n".join(sorted(domains)) + "\n"
        wrote = vm.ssh(f"printf %s {shlex.quote(listed)} > {fence}/feed.txt", timeout=60)
        count = len(domains)
    else:  # sorted as Core keeps members: d<i>.pfbmeasure.com sorted as strings
        wrote = vm.ssh(f"jot -w 'd%d.pfbmeasure.com' {count} 1 | LC_ALL=C sort > {fence}/feed.txt", timeout=600)
    assert wrote.returncode == 0, f"could not write the feed: {wrote.stderr}"
    script = SEED_PHP.replace("@OPEN@", OPEN).replace("@CLOSE@", CLOSE)
    vm.ssh(f"printf %s {shlex.quote(script)} > {fence}/seed.php", timeout=60)
    seeded = vm.ssh(
        f"{PHP} -d memory_limit=-1 {fence}/seed.php {fence}/store {fence}/feed.txt {count} {generation}", timeout=600
    )
    assert OPEN in seeded.stdout, f"the store was not seeded: rc={seeded.returncode} {seeded.stdout}{seeded.stderr}"


def start_dns(vm: SmokeVM, fence: str, log: str, watchdog: float = READY_WATCHDOG) -> str:
    """pfB-DNS on the Core input, as unbound, on 127.0.0.1:PORT; its pid once it serves. It builds a trusted cache
    first and allows itself 300 s for that: a 5,000,000-domain start passes a watchdog of its own."""
    command = (
        f"{DNS_BIN} --listen 127.0.0.1 --port {PORT} --upstream 127.0.0.1:53 --ctl-socket {fence}/ctl/ctl.sock "
        f"--module-dir {fence}/mod --core-socket {fence}/core/api.sock --user unbound --ready-file {READY}"
    )
    start = vm.ssh(f"nohup {command} </dev/null >{log} 2>&1 & echo $!", timeout=30)
    pid = start.stdout.strip()
    assert start.returncode == 0 and pid.isdigit(), f"pfB-DNS did not start: {start.stdout}{start.stderr}"
    deadline = time.monotonic() + watchdog
    try:
        while vm.ssh(f'test -s {READY} && test "$(cat {READY})" = {pid}', timeout=30).returncode != 0:  # it serves
            if vm.ssh(f"kill -0 {pid}", timeout=30).returncode != 0 or time.monotonic() > deadline:
                said = vm.ssh(f"tail -n 30 {log}; ls -ld {fence} {fence}/mod; id unbound", timeout=30).stdout
                pytest.fail(f"STUCK: pfB-DNS never became ready:\n{said}")
            time.sleep(1)
    except BaseException:
        stop(vm, pid)  # no caller's cleanup holds the pid until it is returned
        raise
    return pid


def stop(vm: SmokeVM, pid: str) -> None:
    """TERM, then KILL only when the process outlives ten one-second checks: a drain cut in its commit leaves no
    trusted cache."""
    vm.ssh(
        f"kill -CONT {pid} 2>/dev/null; kill {pid} 2>/dev/null; "
        f"for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 {pid} 2>/dev/null || exit 0; sleep 1; done; kill -9 {pid}; true",
        timeout=60,
    )


def max_rss_kb(vm: SmokeVM, pid: str) -> int:
    """The process's peak resident set so far, in KiB (procstat -r)."""
    usage = vm.ssh(f"/usr/bin/procstat -r {pid}", timeout=30).stdout
    held = re.search(r"maximum RSS\s+(\d+)", usage)
    assert held, f"no maximum RSS row from procstat -r {pid}:\n{usage}"
    return int(held.group(1))


def wait_for(what: str, ready: Callable[[], bool], watchdog: float = SERVE_WATCHDOG) -> None:
    """Block until ready() holds; the watchdog only salvages a stuck run."""
    deadline = time.monotonic() + watchdog
    while not ready():
        if time.monotonic() > deadline:
            pytest.fail(f"STUCK: {what}")
        time.sleep(1)


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
    blocked: bool  # the feed's domain, asked again once the first poll served it
    other_blocked: bool  # a domain no feed lists
    report: str  # Core's applied.json
    blocked_while_core_stopped: bool
    next_blocked_after_core_returned: bool  # a domain only the next generation lists, once Core is back
    report_after_core_returned: str
    cache_folder: str  # mode and owner of <module dir>/pfb_dns
    blocked_after_restart_without_core: bool


@pytest.fixture(scope="module")
def observed(box: SmokeVM) -> Iterator[Observation]:
    """All the box work, in the fixture (the smoke tier caps a test body at 30 s): what pfB-DNS did, for the tests."""
    fence = make_fence(box)
    try:
        listed, other, following = h.unique_domain(), h.unique_domain(), h.unique_domain()
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
                            f"procstat -s $(pgrep -f 'pfb-dns --listen 127.0.0.1 --port {PORT}') 2>&1 | tail -2; "
                            f"/usr/local/bin/curl -sS --unix-socket {rig.api} -X POST "
                            f"-H 'Content-Type: application/json' --data {shlex.quote(MANIFEST_ASK)} "
                            f"http://localhost/v1/GetResources; echo; "
                            f"cat {fence}/mod/pfb_py_status.json; echo; tail -n 8 /var/log/pfblockerng/py_error.log; "
                            f"ls -la {fence}/mod {fence}/mod/pfb_dns {fence}/store; tail -n 5 {fence}/core.log"
                        )
                        ran = box.ssh(probe, timeout=30)
                        said = ran.stdout + ran.stderr
                        pytest.fail(f"STUCK: {listed} was never blocked from Core's data:\n{said}")
                    time.sleep(2)
                blocked, other_blocked = rig.blocked(listed), rig.blocked(other)
                # The report follows the swap: Core has it once applied.json names the generation served
                applied = f"{fence}/state/applied.json"
                wait_for(
                    "Core never recorded the generation pfB-DNS serves",
                    lambda: '"dnsbl/feed-F"' in box.ssh(f"cat {applied} 2>/dev/null", timeout=30).stdout,
                )
                report = box.ssh(f"cat {applied}", timeout=30).stdout
                # Core stuck: asked only once a request of pfB-DNS waits unread on the stopped Core. An open connection
                # alone is no proof: the client keeps idle ones, so the barrier is Core's side holding unread bytes.
                box.ssh(f"kill -STOP {core}", timeout=30)
                wait_for(
                    "no request of pfB-DNS reached the stopped Core",
                    rig.holds_a_request,
                )
                while_stopped = rig.blocked(listed)
                # Core back: the next generation, a feed that also lists another domain, is served and reported
                seed_store(box, fence, [listed, following], generation=2)
                box.ssh(f"kill -CONT {core}", timeout=30)
                wait_for("pfB-DNS never served the generation Core published once back", lambda: rig.blocked(following))
                wait_for("Core never recorded the next generation", lambda: rig.reported(applied) == "2")
                next_blocked = rig.blocked(following)
                report_back = box.ssh(f"cat {applied}", timeout=30).stdout
            finally:
                stop(box, dns)
        cache = box.ssh(f"/usr/bin/stat -f '%Lp %Su' {fence}/mod/pfb_dns 2>&1", timeout=30).stdout.strip()
        dns = start_dns(box, fence, f"{fence}/dns2.log")
        try:
            after_restart = rig.blocked(listed)
        finally:
            stop(box, dns)
        yield Observation(
            blocked, other_blocked, report, while_stopped, next_blocked, report_back, cache, after_restart
        )
    finally:
        box.ssh(f"rm -rf {fence} {READY} {READY}.sha256", timeout=120)


def test_pfb_dns_blocks_what_core_publishes_and_only_that(observed: Observation) -> None:
    assert observed.blocked
    assert not observed.other_blocked, "a domain no feed lists is blocked"


def test_pfb_dns_reports_the_generation_it_serves_to_core(observed: Observation) -> None:
    resources = json.loads(observed.report)["resources"]
    assert resources["dnsbl/feed-F"]["generation"] == "1", observed.report


def test_pfb_dns_keeps_serving_while_core_is_stopped(observed: Observation) -> None:
    assert observed.blocked_while_core_stopped, "pfB-DNS stopped blocking while Core was stopped"


def test_pfb_dns_takes_the_next_generation_once_core_is_back(observed: Observation) -> None:
    assert observed.next_blocked_after_core_returned, "pfB-DNS did not serve the generation Core published once back"
    resources = json.loads(observed.report_after_core_returned)["resources"]
    assert resources["dnsbl/feed-F"]["generation"] == "2", observed.report_after_core_returned


def test_pfb_dns_keeps_its_cache_in_a_folder_of_unbounds_alone(observed: Observation) -> None:
    assert observed.cache_folder == "700 unbound", f"the cache folder is {observed.cache_folder!r}"


def test_a_restart_with_core_down_serves_the_cache(observed: Observation) -> None:
    assert observed.blocked_after_restart_without_core, "a restart with Core down does not serve the cache"


@pytest.fixture(scope="module")
def measured(box: SmokeVM) -> Iterator[dict[str, object]]:
    """The 5,000,000-domain start, timed in the fixture: from Core, then from the cache. It runs only when asked
    (``PFB_CORE_INPUT_MEASURE=1``): its seed and builds take many minutes."""
    if os.environ.get("PFB_CORE_INPUT_MEASURE") != "1":
        pytest.skip("the 5,000,000-domain measurement runs only with PFB_CORE_INPUT_MEASURE=1")
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
            dns = start_dns(box, fence, f"{fence}/dns.log", watchdog=1800)
            try:
                deadline = time.monotonic() + 1800
                while not rig.blocked(probe):  # the real condition: the five million are served
                    assert time.monotonic() < deadline, "STUCK: the measured generation was never served"
                    time.sleep(5)
                from_core = time.monotonic() - began
                rss_core = max_rss_kb(box, dns)
            finally:
                stop(box, dns)
        began = time.monotonic()
        dns = start_dns(box, fence, f"{fence}/dns2.log", watchdog=1800)
        try:
            served = rig.blocked(probe)
            from_cache = time.monotonic() - began
            rss = max_rss_kb(box, dns)
        finally:
            stop(box, dns)
        yield {
            "entries": MEASURE_ENTRIES,
            "first_start_s": round(from_core, 1),
            "first_max_rss_kb": rss_core,
            "cached_start_s": round(from_cache, 1),
            "cached_max_rss_kb": rss,
            "box_ram_mib": ram >> 20,
            "served": served,
        }
    finally:
        box.ssh(f"rm -rf {fence} {READY} {READY}.sha256", timeout=120)


def test_measure_a_start_from_a_cache_of_five_million_domains(measured: dict[str, object]) -> None:
    """The start time and peak memory of pfB-DNS building 5,000,000 domains: printed, never asserted."""
    print("PFB_CORE_INPUT_MEASURE " + json.dumps(measured))
    assert measured["served"], "a start from the cache does not serve the measured generation"
