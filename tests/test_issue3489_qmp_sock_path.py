"""Issue #3489 -- the QEMU QMP control socket must live in a fresh private directory.

``tempfile.mktemp`` only *names* a file in a shared tmp dir; another local user can
claim that name between naming and QEMU's bind. ``_qmp_sock_path`` now creates a
0700 directory (``mkdtemp``) and returns the socket path inside it: boot_vm.sh still
``rm -f``s the (absent) socket and QEMU binds it, but nobody else can reach the name.
The path must still fit AF_UNIX ``sun_path`` (108 bytes), which is why the directory is
anchored under RUNNER_TEMP or /tmp rather than pytest's deep tmp_path tree.
"""

from __future__ import annotations

import inspect
import os
import shutil
import stat
from pathlib import Path

import pytest

from tests.smoke import conftest as smoke_conftest

SUN_PATH_MAX = 108  # AF_UNIX sun_path size on Linux, trailing NUL included

# The tag boot_and_probe() uses for the pfSense VM, read from its signature so the
# length check follows the real default instead of a copy of it.
PFSENSE_TAG = inspect.signature(smoke_conftest.boot_and_probe).parameters["diag_name"].default


def test_qmp_socket_lives_in_a_fresh_private_directory_under_runner_temp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    first = Path(smoke_conftest._qmp_sock_path("civm"))
    second = Path(smoke_conftest._qmp_sock_path("civm"))

    for sock in (first, second):
        assert sock.parent.is_dir(), f"{sock.parent} must exist so QEMU can bind inside it"
        assert sock.parent.parent == tmp_path, f"{sock.parent} must sit directly under RUNNER_TEMP={tmp_path}"
        assert stat.S_IMODE(sock.parent.stat().st_mode) == 0o700, f"{sock.parent} must be private to the owner"
        assert not sock.exists(), f"{sock} must not pre-exist: QEMU creates the socket"
    assert first.parent != second.parent, "each call needs its own directory"


@pytest.mark.parametrize("tag", ["civm", PFSENSE_TAG])
def test_qmp_socket_path_fits_sun_path_under_the_tmp_fallback(monkeypatch: pytest.MonkeyPatch, tag: str) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)

    sock = smoke_conftest._qmp_sock_path(tag)
    parent = Path(sock).parent
    try:
        assert len(os.fsencode(sock)) < SUN_PATH_MAX, f"{sock} is too long for an AF_UNIX socket"
    finally:
        # Only ever remove the directory this call made; never a shared base like /tmp itself.
        if parent.name.startswith("pfb-qmp-"):
            shutil.rmtree(parent, ignore_errors=True)
