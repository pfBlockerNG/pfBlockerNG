"""`--user NAME` (issue #3517): the decider, started as root by the gateway, gives up root for NAME after it has the
gateway's decision socket and before it boots pfb_unbound.py, so every file that init_standard() and the watchers create
belongs to NAME. The order, and an unknown user, are in test_decision_service.py.
"""

from __future__ import annotations

import errno
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import BLOCKED, INI, PROTO_DIR, SHIPPED_DIR
from frontend_helpers import WATCHDOG, build_query
from test_decision_transport import ANSWER, DATAGRAM, FORWARD, READY, REPLY, Gateway, frame, query_frame

NEEDS_ROOT = pytest.mark.skipif(
    os.geteuid() != 0, reason="giving up root needs root: the decider is started as root on the appliance"
)


@pytest.mark.parametrize("failing", ["setgroups", "setgid", "setuid"])
def test_a_drop_the_os_refuses_exits_1_with_a_message_before_the_module_boots(
    failing: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_args: Any) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    for name in ("setgroups", "setgid", "setuid"):
        monkeypatch.setattr(os, name, refuse if name == failing else lambda *_a: None)
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_a: pytest.fail("the module must not boot"))
    gateway_end, decider_end = socket.socketpair()
    with gateway_end:
        assert pfb_dns_proxy.main(["--decision-fd", str(decider_end.detach()), "--user", "root"]) == 1
    err = capsys.readouterr().err
    assert err == "pfb_dns_proxy: cannot switch to user 'root': [Errno 1] Operation not permitted\n"


# --- a real drop ---------------------------------------------------------------------------------


def _interpreter_for(user: str) -> str:
    """An interpreter `user` can execute and import the standard library with (the module boots after the drop)."""
    candidates = dict.fromkeys([sys.executable, shutil.which("python3") or "", "/usr/bin/python3"])
    for candidate in filter(None, candidates):
        try:
            probe = subprocess.run(
                [candidate, "-c", "import asyncio, ipaddress, json, sqlite3, ssl"],
                user=user,
                capture_output=True,
                timeout=60,
                check=False,
            )
        except OSError:  # PermissionError: the interpreter sits somewhere `user` cannot reach, such as /root
            continue
        if probe.returncode == 0:
            return candidate
    pytest.fail(f"no Python interpreter that user {user!r} can run was found among {list(candidates)}")


def _module_dir_for_any_user() -> Path:
    """A 0777 module dir (the user the proxy drops to must write into it) with copies of the shipped modules in it."""
    directory = Path(tempfile.mkdtemp(prefix="pfb-drop-"))
    directory.chmod(0o777)
    for name in ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py"):
        shutil.copyfile(SHIPPED_DIR / name, directory / name)  # a symlink into a checkout under /root is unreadable
        (directory / name).chmod(0o644)
    (directory / "pfb_py_raw").mkdir()
    (directory / "pfb_py_raw" / "feed.txt").write_text(f"{BLOCKED}\n", encoding="utf-8")
    feed = {"raw": "pfb_py_raw/feed.txt", "feed": "F", "group": "G", "log_flag": "0"}  # "0": no /var/log writes
    manifest = json.dumps({"version": 1, "config": {}, "feeds": [feed]})
    (directory / "pfb_py_sources.json").write_text(manifest, encoding="utf-8")
    (directory / "pfb_unbound.ini").write_text(INI, encoding="utf-8")
    return directory


def _status_ids(pid: int) -> dict[str, list[int]]:
    """The Uid, Gid and Groups lines of /proc/PID/status as integers."""
    fields = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition(":")
        if key in ("Uid", "Gid", "Groups"):
            fields[key] = [int(number) for number in value.split()]
    return fields


def _decider_as(user: str, *flags: str) -> tuple[subprocess.Popen[str], Gateway]:
    """The real decider on one end of a socketpair, started as the current user with `--user user`; READY is read."""
    go, py = socket.socketpair()
    go.settimeout(WATCHDOG)
    child = subprocess.Popen(
        [_interpreter_for(user), str(PROTO_DIR / "pfb_dns_proxy.py"), "--decision-fd", str(py.fileno())]
        + ["--user", user, *flags],
        pass_fds=[py.fileno()],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    py.close()
    gateway = Gateway(go, child)
    assert gateway.recv() == (READY, 0, b"")
    return child, gateway


@NEEDS_ROOT
@pytest.mark.parametrize("user", ["nobody", "root"])
def test_the_real_decider_serves_as_the_named_user_and_its_files_belong_to_that_user(user: str) -> None:
    account = pwd.getpwnam(user)
    module_dir = _module_dir_for_any_user()
    child, gateway = _decider_as(user, "--module-dir", str(module_dir))
    try:
        gateway.send(query_frame(1, build_query(BLOCKED, qid=0x3515), DATAGRAM))
        ftype, fid, wire = gateway.recv()
        ids = _status_ids(child.pid)
        created = os.stat(module_dir / "pfb_py_count").st_uid  # written by init_standard()
        provided = os.stat(module_dir / "pfb_unbound.ini").st_uid  # written by this test, as root
        gateway.sock.close()  # EOF: the decider shuts the module down and exits 0
        _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        gateway.sock.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
        shutil.rmtree(module_dir, ignore_errors=True)

    assert (ftype, fid) == (ANSWER, 1)
    assert [rr.rdata for rr in dnswire.parse(wire).answers] == [
        bytes(4)
    ]  # the module's null block (log_flag 0: no VIP)
    assert ids == {"Uid": [account.pw_uid] * 4, "Gid": [account.pw_gid] * 4, "Groups": []}
    assert (created, provided) == (account.pw_uid, 0)
    assert child.returncode == 0, stderr


@NEEDS_ROOT
@pytest.mark.parametrize("user", ["nobody", "root"])
def test_the_real_decider_without_a_module_serves_as_the_named_user_and_needs_no_module_dir(
    user: str, tmp_path: Path
) -> None:
    account = pwd.getpwnam(user)
    child, gateway = _decider_as(user, "--no-module", "--module-dir", str(tmp_path / "absent"))
    try:
        query = build_query(BLOCKED, qid=0x3515)
        gateway.send(query_frame(1, query, DATAGRAM))
        assert gateway.recv() == (FORWARD, 1, query)
        ids = _status_ids(child.pid)
        gateway.send(frame(REPLY, 1))  # Unbound said nothing
        ftype, fid, wire = gateway.recv()
        gateway.sock.close()
        _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        gateway.sock.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert ids == {"Uid": [account.pw_uid] * 4, "Gid": [account.pw_gid] * 4, "Groups": []}
    assert (ftype, fid, dnswire.parse(wire).rcode) == (ANSWER, 1, 2)  # as that user: nothing answered, so SERVFAIL
    assert child.returncode == 0, stderr
