"""`--user NAME`: the proxy binds its sockets and builds its TLS context as the user it was started as (root on the
appliance, for port 53), then gives up root for NAME, and only then boots pfb_unbound.py, so every file that
init_standard() and the watchers create belongs to NAME.
"""

from __future__ import annotations

import asyncio
import errno
import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import dnswire
import pfb_dns_proxy
import pfsense_dot
import pytest
from dot_helpers import REFID, b64, cert_element, config_xml, free_port
from frontend_constants import BLOCKED, INI, PROTO_DIR, SHIPPED_DIR
from frontend_helpers import WATCHDOG, FakeProxyUpstream, FakeUnbound, build_query, running_proxy, serving, udp_exchange

NO_SUCH_USER = "pfb-no-such-user-3515"
NEEDS_ROOT = pytest.mark.skipif(
    os.geteuid() != 0, reason="giving up root needs root: the proxy is started as root on the appliance"
)


def test_user_defaults_to_no_drop() -> None:
    assert pfb_dns_proxy.parse_args([]).user is None
    assert pfb_dns_proxy.parse_args(["--user", "unbound"]).user == "unbound"


# --- the order -----------------------------------------------------------------------------------


@pytest.mark.parametrize("no_module", [False, True], ids=["with-module", "no-module"])
def test_sockets_and_tls_are_made_as_the_starting_user_then_root_is_dropped_then_the_module_boots_if_there_is_one(
    no_module: bool,
    module_dir: Path,
    tmp_path: Path,
    certificate: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pwd.getpwnam("root")
    crt, key = certificate
    config = tmp_path / "config.xml"
    entries = cert_element(REFID, b64(crt), b64(key))
    config.write_text(config_xml(enablessl=False, tlsport=free_port(), entries=entries), encoding="utf-8")
    events: list[tuple[Any, ...]] = []

    def spy(name: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            events.append((name, *args[:1]) if name == "bind" else (name,))
            return real(*args, **kwargs)

        return wrapper

    def record(name: str) -> Callable[[Any], None]:
        return lambda value: events.append((name, value))  # the real call needs root; the order is what is pinned

    real_boot = pfb_dns_proxy.boot

    def boot_without_log_files(directory: str) -> Any:
        events.append(("boot",))
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)  # the module logs to /var/log/pfblockerng
        return module

    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    monkeypatch.setattr(pfsense_dot, "server_context", spy("tls-context", pfsense_dot.server_context))
    monkeypatch.setattr(pfb_dns_proxy, "bind", spy("bind", pfb_dns_proxy.bind))
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot_without_log_files)
    monkeypatch.setattr(os, "setgroups", record("setgroups"))
    monkeypatch.setattr(os, "setgid", record("setgid"))
    monkeypatch.setattr(os, "setuid", record("setuid"))

    async def scenario() -> None:
        async with FakeProxyUpstream(FakeUnbound({})) as upstream:
            args = pfb_dns_proxy.parse_args(
                ["--listen", "127.0.0.1", "--port", "0", "--upstream", f"127.0.0.1:{upstream.port}"]
                + ["--module-dir", str(module_dir), "--dot", "--pfsense-config", str(config), "--user", "root"]
                + (["--no-module"] if no_module else [])
            )
            async with serving(args):
                pass

    asyncio.run(scenario())
    assert events == [
        ("tls-context",),
        ("bind", "127.0.0.1"),  # UDP+TCP
        ("bind", "127.0.0.1"),  # DoT
        ("setgroups", []),
        ("setgid", root.pw_gid),
        ("setuid", root.pw_uid),
        *([] if no_module else [("boot",)]),
    ]


# --- the user ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [NO_SUCH_USER, ""], ids=["unknown", "empty"])
def test_an_unknown_or_empty_user_exits_1_before_anything_is_bound(
    name: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "bind", lambda *_a, **_k: pytest.fail("nothing may be bound"))
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_a: pytest.fail("the module must not boot"))
    assert pfb_dns_proxy.main(["--user", name, "--listen", "127.0.0.1", "--port", "0"]) == 1
    assert capsys.readouterr().err == f"pfb_dns_proxy: unknown user {name!r}\n"


@pytest.mark.parametrize("name", [NO_SUCH_USER, ""], ids=["unknown", "empty"])
def test_an_unknown_or_empty_user_makes_the_real_process_exit_1(tmp_path: Path, name: str) -> None:
    run = subprocess.run(
        [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--user", name, "--listen", "127.0.0.1"]
        + ["--port", "0", "--module-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert (run.returncode, run.stdout, run.stderr) == (1, "", f"pfb_dns_proxy: unknown user {name!r}\n")


@pytest.mark.parametrize("failing", ["setgroups", "setgid", "setuid"])
def test_a_drop_the_os_refuses_exits_1_with_a_message_before_the_module_boots(
    failing: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_args: Any) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    for name in ("setgroups", "setgid", "setuid"):
        monkeypatch.setattr(os, name, refuse if name == failing else lambda *_a: None)
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_a: pytest.fail("the module must not boot"))
    assert pfb_dns_proxy.main(["--user", "root", "--listen", "127.0.0.1", "--port", "0"]) == 1
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


@NEEDS_ROOT
@pytest.mark.parametrize("user", ["nobody", "root"])
def test_the_real_process_serves_as_the_named_user_and_its_files_belong_to_that_user(user: str) -> None:
    account = pwd.getpwnam(user)
    interpreter = _interpreter_for(user)
    module_dir = _module_dir_for_any_user()
    command = [interpreter, str(PROTO_DIR / "pfb_dns_proxy.py"), "--listen", "127.0.0.1", "--port", "0"]
    command += ["--upstream", f"127.0.0.1:{free_port()}", "--module-dir", str(module_dir), "--user", user]
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    watchdog = threading.Timer(WATCHDOG, child.kill)  # a proxy that never says it listens fails at EOF, not forever
    watchdog.start()
    try:
        assert child.stderr is not None
        seen: list[str] = []
        port = None
        for line in child.stderr:
            seen.append(line)
            if match := re.search(r"listening on 127\.0\.0\.1:(\d+)", line):
                port = int(match.group(1))
                break
        assert port is not None, f"the proxy never listened; it printed:\n{''.join(seen)}"

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:  # the sockets bound before the drop serve
            client.settimeout(WATCHDOG)
            client.sendto(build_query(BLOCKED, qid=0x3515), ("127.0.0.1", port))
            reply = dnswire.parse(client.recvfrom(4096)[0])
        ids = _status_ids(child.pid)
        created = os.stat(module_dir / "pfb_py_count").st_uid  # written by init_standard()
        provided = os.stat(module_dir / "pfb_unbound.ini").st_uid  # written by this test, as root
        child.send_signal(signal.SIGTERM)
        status = child.wait(timeout=WATCHDOG)
    finally:
        watchdog.cancel()
        if child.poll() is None:
            child.kill()
        child.wait()
        if child.stderr is not None:
            child.stderr.close()
        shutil.rmtree(module_dir, ignore_errors=True)

    assert [rr.rdata for rr in reply.answers] == [
        bytes(4)
    ]  # the module's null block (log_flag 0: no VIP); Unbound is down
    assert ids == {"Uid": [account.pw_uid] * 4, "Gid": [account.pw_gid] * 4, "Groups": []}
    assert (created, provided) == (account.pw_uid, 0)
    assert status == 0


@NEEDS_ROOT
@pytest.mark.parametrize("user", ["nobody", "root"])
def test_the_real_process_without_a_module_serves_as_the_named_user_and_needs_no_module_dir(
    user: str, tmp_path: Path
) -> None:
    account = pwd.getpwnam(user)
    argv = ["--no-module", "--listen", "127.0.0.1", "--port", "0", "--upstream", f"127.0.0.1:{free_port()}"]
    argv += ["--module-dir", str(tmp_path / "absent"), "--user", user]
    with running_proxy(argv, interpreter=_interpreter_for(user)) as (child, port):
        reply = dnswire.parse(asyncio.run(udp_exchange(("127.0.0.1", port), build_query(BLOCKED, qid=0x3515)))[0])
        ids = _status_ids(child.pid)
    assert ids == {"Uid": [account.pw_uid] * 4, "Gid": [account.pw_gid] * 4, "Groups": []}
    assert reply.rcode == 2  # as that user: Unbound is down, and with no module nothing else answers
