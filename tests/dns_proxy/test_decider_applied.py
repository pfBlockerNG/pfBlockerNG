"""Issue #3566: a package upgrade has to restart only the half of pfB-DNS whose code changed.

The decider (a) runs as the account the gateway already dropped to (`--user unbound` when started by an unprivileged
gateway) without trying to switch, and (b) publishes `pfb_dns_decider.applied` in --module-dir before READY: the md5
hex digests of its seven code files, concatenated. The REAL pfb_dns_proxy.py runs against a private layout of copies,
as an unprivileged account (`nobody` when this test runs as root).
"""

from __future__ import annotations

import hashlib
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from frontend_constants import PROTO_DIR
from frontend_helpers import WATCHDOG, watched
from test_decision_transport import READY, Gateway
from test_privilege_drop import _interpreter_for, _module_dir_for_any_user

RECORD = "pfb_dns_decider.applied"
OWN_FILES = ("pfb_dns_proxy.py", "decision_service.py", "dns_reply_log.py", "dnswire.py", "unbound_shim.py")
MODULE_FILES = ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py")
ACCOUNT = pwd.getpwnam("nobody") if os.geteuid() == 0 else pwd.getpwuid(os.geteuid())


@dataclass
class Layout:
    own: Path  # the decider's own directory: copies of the five shipped files
    module: Path  # --module-dir: the two shipped module files, writable by anyone

    def expected(self) -> str:
        paths = [self.own / name for name in OWN_FILES] + [self.module / name for name in MODULE_FILES]
        return "".join(hashlib.md5(path.read_bytes()).hexdigest() for path in paths)


@pytest.fixture
def layout() -> Iterator[Layout]:
    own = Path(tempfile.mkdtemp(prefix="pfb-own-"))
    own.chmod(0o755)
    for name in OWN_FILES:
        shutil.copyfile(PROTO_DIR / name, own / name)
        (own / name).chmod(0o644)
    with (own / "dns_reply_log.py").open("a", encoding="utf-8") as handle:
        handle.write("\n# differs from the shipped file: the record must digest THIS copy\n")
    module = _module_dir_for_any_user()
    try:
        yield Layout(own, module)
    finally:
        shutil.rmtree(own, ignore_errors=True)
        shutil.rmtree(module, ignore_errors=True)


def _start(
    layout: Layout,
    *flags: str,
    user: str | None = None,
    as_account: bool = True,
    extra_fds: tuple[int, ...] = (),
    group: int | None = None,
) -> tuple[subprocess.Popen[str], socket.socket]:
    """The decider from `layout.own` on one end of a socketpair, as ACCOUNT (or as the current user)."""
    go, py = socket.socketpair()
    go.settimeout(WATCHDOG)
    identity: dict[str, object] = {}
    if as_account and os.geteuid() == 0:
        identity = {"user": ACCOUNT.pw_uid, "group": ACCOUNT.pw_gid if group is None else group, "extra_groups": []}
    interpreter = _interpreter_for(ACCOUNT.pw_name) if identity else sys.executable
    child = subprocess.Popen(
        [interpreter, str(layout.own / "pfb_dns_proxy.py"), "--decision-fd", str(py.fileno())]
        + ["--module-dir", str(layout.module), *(["--user", user] if user else []), *flags],
        pass_fds=(py.fileno(), *extra_fds),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        **identity,  # type: ignore[call-overload]
    )
    py.close()
    return child, go


def _ready(layout: Layout, *flags: str, user: str | None = None, as_account: bool = True) -> tuple[str, str]:
    """Run the decider to READY, snapshot the record the moment READY arrived, end it by EOF: (record or '', stderr)."""
    child, go = _start(layout, *flags, user=user, as_account=as_account)
    try:
        try:
            got = Gateway(go, child).recv()
        except AssertionError as exc:  # the decider died before READY: say why
            _, died = child.communicate(timeout=WATCHDOG)
            raise AssertionError(f"{exc}; exit {child.returncode}, stderr: {died!r}") from None
        record_path = layout.module / RECORD
        record = record_path.read_text(encoding="utf-8") if record_path.exists() else ""
        go.close()
        with watched("the decider to exit after EOF"):
            _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert got == (READY, 0, b""), stderr
    assert child.returncode == 0, stderr
    return record, stderr


# --- F2: serving as the account the process already is --------------------------------------------


@pytest.mark.parametrize("flags", [("--no-module",), ()], ids=["no-module", "module"])
def test_a_decider_already_running_as_the_named_user_reaches_ready_without_switching(
    layout: Layout, flags: tuple[str, ...]
) -> None:
    _ready(layout, *flags, user=ACCOUNT.pw_name)


def test_an_unprivileged_decider_asked_to_become_another_user_still_exits_1_with_the_reason(layout: Layout) -> None:
    child, go = _start(layout, "--no-module", user="root")
    try:
        with watched("the decider to exit"):
            _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert child.returncode == 1, stderr
    assert stderr == "pfb_dns_proxy: cannot switch to user 'root': [Errno 1] Operation not permitted\n"


@pytest.mark.skipif(os.geteuid() != 0, reason="setting a different effective GID for a non-root child requires root")
def test_the_named_user_with_a_different_effective_group_must_not_skip_its_switch(layout: Layout) -> None:
    child, go = _start(layout, "--no-module", user=ACCOUNT.pw_name, group=0)
    try:
        with watched("the decider with the wrong effective group to exit"):
            _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert child.returncode == 1, f"the wrong GID was silently accepted: exit={child.returncode}, stderr={stderr!r}"
    assert f"cannot switch to user '{ACCOUNT.pw_name}'" in stderr, stderr


# --- C2: the code record ---------------------------------------------------------------------------


@pytest.mark.parametrize("flags", [("--no-module",), ()], ids=["no-module", "module"])
def test_the_record_is_the_md5_concatenation_of_the_seven_code_files_and_exists_at_ready(
    layout: Layout, flags: tuple[str, ...]
) -> None:
    record, stderr = _ready(layout, *flags, user=ACCOUNT.pw_name)
    assert record == layout.expected(), stderr
    assert len(record) == 7 * 32


def test_a_module_dir_member_that_is_missing_leaves_no_record_and_removes_a_stale_one(layout: Layout) -> None:
    (layout.module / "pfb_dnsbl_regex_rules.py").unlink()
    (layout.module / RECORD).write_text("stale", encoding="utf-8")
    record, stderr = _ready(layout, "--no-module", user=ACCOUNT.pw_name)
    assert (record, (layout.module / RECORD).exists()) == ("", False), stderr


def test_a_module_dir_that_cannot_be_written_still_reaches_ready_with_one_error_line(layout: Layout) -> None:
    layout.module.chmod(0o555)  # nobody owns nothing here; as a non-root owner 0555 refuses the write too
    record, stderr = _ready(layout, "--no-module", user=ACCOUNT.pw_name)
    errors = [line for line in stderr.splitlines() if line.startswith("pfb_dns_proxy error:")]
    assert (record, len(errors)) == ("", 1), stderr
    assert RECORD in errors[0], errors[0]


def test_a_record_that_cannot_be_written_removes_the_existing_one_so_it_never_passes_for_this_code(
    layout: Layout,
) -> None:
    (layout.module / RECORD).write_text("stale", encoding="utf-8")
    (layout.module / RECORD).chmod(0o666)  # the account could rewrite it in place
    (layout.module / f"{RECORD}.tmp").mkdir()  # the temp file cannot be created; an in-place write would succeed
    record, stderr = _ready(layout, "--no-module", user=ACCOUNT.pw_name)
    errors = [line for line in stderr.splitlines() if line.startswith("pfb_dns_proxy error:")]
    assert (record, (layout.module / RECORD).exists(), len(errors)) == ("", False, 1), stderr


def test_a_module_that_fails_to_boot_exits_1_before_any_record_is_written(layout: Layout) -> None:
    (layout.module / "pfb_unbound.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    child, go = _start(layout, user=ACCOUNT.pw_name)
    try:
        with watched("the decider to exit"):
            _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert (child.returncode, (layout.module / RECORD).exists()) == (1, False), stderr
    assert "boom" in stderr, stderr


@pytest.mark.parametrize("changed", ["pfb_unbound.py", "dnswire.py"])
def test_code_replaced_during_boot_never_gets_a_record_for_code_the_decider_did_not_load(
    layout: Layout, changed: str
) -> None:
    parent, barrier = socket.socketpair()
    parent.settimeout(WATCHDOG)
    with (layout.module / "pfb_unbound.py").open("a", encoding="utf-8") as handle:
        handle.write(
            "\n_init_before_barrier = init_standard\n"
            "def init_standard(*args):\n"
            f"    with __import__('socket').socket(fileno={barrier.fileno()}) as gate:\n"
            "        gate.sendall(b'L')\n"
            "        if gate.recv(1) != b'R':\n"
            "            raise RuntimeError('boot barrier closed')\n"
            "    return _init_before_barrier(*args)\n"
        )
    child, go = _start(layout, user=ACCOUNT.pw_name, extra_fds=(barrier.fileno(),))
    barrier.close()
    try:
        assert parent.recv(1) == b"L", "the decider never reached its loaded-module initialization barrier"
        path = (layout.module if changed == "pfb_unbound.py" else layout.own) / changed
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n# package replaced this already-imported file during initialization\n")
        parent.sendall(b"R")
        got = Gateway(go, child).recv()
        assert got == (READY, 0, b""), f"the replacement changed readiness: {got!r}"
        record = layout.module / RECORD
        assert not record.exists(), (
            f"{changed} changed after import, but the old decider vouched for installed code: {record.read_text()}"
        )
    finally:
        parent.close()
        go.close()
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=WATCHDOG)
