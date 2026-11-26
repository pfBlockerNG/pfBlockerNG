"""issue #4259: on a RAM-disk box, a pfB-DNS stop writes the DNSBL archive with the Core input's cache folder in it.

``/var/unbound/pfb_dns`` (#4251) is what pfB-DNS last fetched from Core. On a RAM-disk ``/var`` (``use_mfs_tmpvar``) the
pfb_dns_proxy rc script's stop, the one pfSense makes with no argument, archives it (``pfblockerng.inc dnsbl_cache``)
once pfB-DNS has exited. The test plants the folder beside a serving pfB-DNS, turns the RAM-disk switch on in
``config.xml`` (no reboot: the stop reads the switch, the RAM disks themselves come only with one) and runs the stop.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

CACHE = "/var/unbound/pfb_dns"
ARCHIVE = "/usr/local/etc/pfb_dnsbl_cache.tar"
RC = "/usr/local/etc/rc.d/pfb_dns_proxy.sh"


@pytest.fixture(scope="module")
def serving_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The branch package deployed, DNSBL on, so pfB-DNS serves; the Resolver is given back after."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.set_package_enabled(smoke_vm, on=True)
    h.set_dnsbl_enabled(smoke_vm, on=True)
    h.reload(smoke_vm, "updatednsbl")
    try:
        yield smoke_vm
    finally:
        h.release_pfb_dns(smoke_vm)


def _running(vm: SmokeVM) -> bool:
    pre = "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
    return h._php_read_scalar(vm, pre, "json_encode(pfb_dns_proxy_running())") == "true"


def test_a_pfb_dns_stop_leaves_an_archive_that_holds_the_core_input_folder(serving_vm: SmokeVM) -> None:
    vm = serving_vm
    assert _running(vm), "before: pfB-DNS is not serving"
    if h.php_eval(vm, "echo config_path_enabled('system', 'use_mfs_tmpvar') ? 'on' : 'off';").stdout.strip() != "off":
        pytest.skip("the box already has RAM disks: turning the switch on and off would lose the box's own setting")
    listed = vm.ssh(f'for a in {ARCHIVE}.zst {ARCHIVE}.bz2; do if [ -e "$a" ]; then echo "$a"; fi; done', timeout=30)
    assert listed.returncode == 0, f"could not list the box's archives: {listed.stderr}"
    had = listed.stdout.split()
    assert vm.ssh(f"test -e {CACHE}", timeout=30).returncode != 0, f"before: {CACHE} already exists"
    moved: list[str] = []  # the box's own archives, set aside so that the archive found after the stop is the stop's
    passed = False
    try:
        for a in had:
            aside = vm.ssh(f"test ! -e {a}.aside4259 && mv {a} {a}.aside4259", timeout=30)
            assert aside.returncode == 0, f"could not set {a} aside (or {a}.aside4259 exists): {aside.stderr}"
            moved.append(a)
        planted = vm.ssh(
            f"mkdir -m 700 {CACHE} && echo feed-body > {CACHE}/feed-F && chmod 600 {CACHE}/feed-F && "
            f"chown -R unbound:unbound {CACHE}",
            timeout=30,
        )
        assert planted.returncode == 0, f"could not plant {CACHE}: {planted.stdout}{planted.stderr}"
        h.set_ramdisk(vm, True)

        stopped = vm.ssh(RC, "stop", timeout=120)

        assert stopped.returncode == 0, f"stop: {stopped.stdout}{stopped.stderr}"
        assert not _running(vm), "after the stop pfB-DNS still runs"
        archive = vm.ssh(f"ls {ARCHIVE}.zst {ARCHIVE}.bz2 2>/dev/null", timeout=30).stdout.split()
        assert len(archive) == 1, f"the stop left {archive}: one archive expected"
        held = vm.ssh(f"tar -xOf {archive[0]} {CACHE}/feed-F", timeout=60)
        assert held.returncode == 0 and held.stdout.split() == ["feed-body"], (
            f"the archive does not hold {CACHE}/feed-F: {held.stdout}{held.stderr}"
        )
        passed = True
    finally:
        h.set_ramdisk(vm, False)
        vm.ssh(f"rm -rf {CACHE}", timeout=30)
        if len(moved) == len(had):
            vm.ssh(f"rm -f {ARCHIVE}.zst {ARCHIVE}.bz2", timeout=30)
        back = [a for a in moved if vm.ssh(f"mv {a}.aside4259 {a}", timeout=30).returncode != 0]
        if back:
            print(f"WARNING: the box's archive was not put back: {back} (still at .aside4259)")
        started = vm.ssh(RC, "start", timeout=120)
    assert passed and not back, f"the box's archive was not put back: {back} (still at .aside4259)"
    assert started.returncode == 0, f"pfB-DNS did not start again: {started.stdout}{started.stderr}"
