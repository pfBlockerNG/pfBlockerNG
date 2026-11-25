"""issue #4251: the Core input's cache folder rides the RAM-disk archive whole.

On the Core input pfB-DNS keeps what it fetched from Core in ``/var/unbound/pfb_dns`` (0700, its files 0600, owned by
``unbound``, which pfB-DNS runs as). On a RAM-disk ``/var`` a reboot wipes it; ``pfblockerng.sh dnsbl_cache save``
archives it and the boot's ``dnsbl_cache restore`` brings it back. pfB-DNS trusts a cache file only when it is its own
and no other user may write it (``coreinput.Owned``), so the restore must keep the owner and the modes. Core's PSL in
the folder stays Core's: the shipped ``dnsbl_psl`` the restore stages goes to the chroot's top, never into the folder.

The test runs the save and the restore as the boot runs them, by hand, without a reboot: what a reboot does to the
folder is the ``rm -rf`` between them.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

SCRIPT = "/usr/local/pkg/pfblockerng/pfblockerng.sh"
CACHE = "/var/unbound/pfb_dns"
ARCHIVE = "/usr/local/etc/pfb_dnsbl_cache.tar"


@pytest.fixture(scope="module")
def cache_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The branch package deployed once."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    yield smoke_vm


def test_the_core_input_cache_folder_comes_back_with_its_owner_and_modes(cache_vm: SmokeVM) -> None:
    vm = cache_vm
    # The box's own archives: an inventory that fails stops the test, so that a save never replaces an archive unseen
    listed = vm.ssh(f'for a in {ARCHIVE}.zst {ARCHIVE}.bz2; do if [ -e "$a" ]; then echo "$a"; fi; done', timeout=30)
    assert listed.returncode == 0, f"could not list the box's archives: {listed.stderr}"
    had = listed.stdout.split()
    assert vm.ssh(f"test -e {CACHE}", timeout=30).returncode != 0, f"before: {CACHE} already exists"
    plant = (
        f"mkdir -m 700 {CACHE} && mkdir -m 700 {CACHE}/pfb_py_raw {CACHE}/pfb_py_raw/g7.abc && "
        f"echo core-psl > {CACHE}/dnsbl_psl && echo feed-body > {CACHE}/pfb_py_raw/g7.abc/feed-F && "
        f"echo '{{}}' > {CACHE}/pfb_py_core.json && "
        f"chmod 600 {CACHE}/dnsbl_psl {CACHE}/pfb_py_core.json {CACHE}/pfb_py_raw/g7.abc/feed-F && "
        f"chown -R unbound:unbound {CACHE}"
    )
    files = (CACHE, f"{CACHE}/pfb_py_core.json", f"{CACHE}/dnsbl_psl", f"{CACHE}/pfb_py_raw/g7.abc/feed-F")
    stat = f"/usr/bin/stat -f '%Lp %Su %Sg' {' '.join(files)}"
    moved: list[str] = []  # the box's own archives, set aside because the save below replaces them; put back after
    passed = False
    try:
        for a in had:
            # an earlier run's set-aside copy is the box's own: never overwritten
            aside = vm.ssh(f"test ! -e {a}.aside4251 && mv {a} {a}.aside4251", timeout=30)
            assert aside.returncode == 0, f"could not set {a} aside (or {a}.aside4251 exists): {aside.stderr}"
            moved.append(a)
        planted = vm.ssh(plant, timeout=30)
        assert planted.returncode == 0, f"could not plant {CACHE}: {planted.stdout}{planted.stderr}"
        before = vm.ssh(stat, timeout=30).stdout.split("\n")[:4]
        assert before == ["700 unbound unbound"] + ["600 unbound unbound"] * 3, f"before: {before}"

        saved = vm.ssh(f"{SCRIPT} dnsbl_cache save", timeout=120)
        assert saved.returncode == 0, f"save: {saved.stdout}{saved.stderr}"
        wiped = vm.ssh(f"rm -rf {CACHE} && test ! -e {CACHE}", timeout=30)
        assert wiped.returncode == 0, f"could not wipe {CACHE}: {wiped.stderr}"
        restored = vm.ssh(f"{SCRIPT} dnsbl_cache restore", timeout=120)
        assert restored.returncode == 0, f"restore: {restored.stdout}{restored.stderr}"

        after = vm.ssh(stat, timeout=30)
        assert after.stdout.split("\n")[:4] == before, f"after the restore: {after.stdout}{after.stderr}"
        said = vm.ssh(f"cat {CACHE}/dnsbl_psl {CACHE}/pfb_py_raw/g7.abc/feed-F", timeout=30).stdout.split()
        assert said == ["core-psl", "feed-body"], f"the restored folder holds {said}: Core's PSL must stay Core's"
        passed = True
    finally:
        vm.ssh(f"rm -rf {CACHE}", timeout=30)
        # Only what this test wrote goes: an archive the box had and that was not set aside stays where it is
        if len(moved) == len(had):
            vm.ssh(f"rm -f {ARCHIVE}.zst {ARCHIVE}.bz2", timeout=30)
        back = [a for a in moved if vm.ssh(f"mv {a}.aside4251 {a}", timeout=30).returncode != 0]
        if back:
            print(f"WARNING: the box's archive was not put back: {back} (still at .aside4251)")
    assert passed and not back, f"the box's archive was not put back: {back} (still at .aside4251)"
