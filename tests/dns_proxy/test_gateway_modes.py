"""pfB-DNS's modes through the REAL Go gateway, the REAL decider and a real Unbound in Docker (issue #3513).

DNSBL off is the gateway's `--no-module [--reply-log]`: the decider boots no pfb_unbound.py, a name on a feed is
Unbound's own answer, the Resolver ACL is still enforced before any forward, and with the DNS Reply Logging preference
on each reply is one row of the existing DNS Reply log. With DNSBL on and the Resolver forwarding it is `--observer`:
the decider hosts the module and hears Unbound's observer, so an upstream block is logged for the real client.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import stat
import subprocess
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import dnswire
import pytest
from dot_helpers import REFID, b64, cert_element, config_xml, dot_exchange, free_port, make_certificate
from frontend_constants import BLOCKED, REPO_ROOT
from frontend_helpers import UpstreamVerdict, build_query
from test_gateway_e2e import ACL_FILE, Running, _answers, _gateway_process, _tcp, _udp, gateway_binary  # noqa: F401
from test_integration_unbound import (  # noqa: F401  (fixtures: the Docker Unbound, with and without the observer)
    ALLOWED_CLIENT,
    ALLOWED_CLIENT_TCP,
    EDE_BLOCKED,
    NXDOMAIN,
    REFUSED_CLIENT,
    RunningUnbound,
    observed_unbound,
    unbound,
)

ROWS = json.loads((REPO_ROOT / "tests" / "fixtures" / "dns_reply_standalone_rows.json").read_text(encoding="utf-8"))
UNBOUNDS_ANSWER_FOR_BLOCKED = (BLOCKED, dnswire.TYPE_A, bytes([192, 0, 2, 99]))
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
OBSERVER_SOCKET = "pfb_upstream.sock"  # in the module dir, which is the decider's working directory

StartGateway = Callable[..., Running]


def _fresh(prefix: str) -> str:
    """A name nothing has asked for yet: Unbound's cache would answer a repeat without asking upstream."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}.example."


@pytest.fixture
def no_module_dir(tmp_path: Path) -> Path:
    """What --no-module is given: nothing there, no pfb_unbound.py, ini, manifest or feed."""
    return tmp_path / "no-module-here"


@pytest.fixture
def start_gateway(gateway_binary: Path, unbound: RunningUnbound, tmp_path: Path) -> Iterator[StartGateway]:
    """start(module_dir, *mode_flags, behind=...): the gateway in front of `behind` (the plain Unbound by default)."""
    stack = contextlib.ExitStack()
    started = 0

    def start(module_dir: Path, *flags: str, behind: RunningUnbound | None = None) -> Running:
        nonlocal started
        started += 1
        rig = tmp_path / f"gateway-{started}"
        rig.mkdir()
        process, log_dir = stack.enter_context(
            _gateway_process(gateway_binary, module_dir, behind or unbound, rig, ACL_FILE, list(flags))
        )
        return Running(process, process.server(), log_dir)

    try:
        yield start
    finally:
        stack.close()


# --- DNSBL off ---------------------------------------------------------------------------------------------


def test_with_dnsbl_off_a_listed_name_is_unbounds_own_answer_and_unbound_logs_the_real_client(
    start_gateway: StartGateway, no_module_dir: Path, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()
    pfb_dns = start_gateway(no_module_dir, "--no-module")
    udp = _udp(pfb_dns.server, BLOCKED, ALLOWED_CLIENT)
    tcp = _tcp(pfb_dns.server, BLOCKED, ALLOWED_CLIENT_TCP)

    for reply in (udp, tcp):
        assert _answers(reply) == [UNBOUNDS_ANSWER_FOR_BLOCKED], "Unbound's answer, not the DNSBL VIP"
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {BLOCKED} A IN", since=mark)
    assert any(f"{ALLOWED_CLIENT} {BLOCKED} A IN" in line for line in logged)
    assert not any(f"127.0.0.1 {BLOCKED}" in line for line in logged), "the client, not the gateway"
    assert not no_module_dir.exists(), "the decider needed no module directory at all"


def test_with_dnsbl_off_the_resolver_acl_still_refuses_before_anything_is_forwarded(
    start_gateway: StartGateway, no_module_dir: Path, unbound: RunningUnbound
) -> None:
    pfb_dns = start_gateway(no_module_dir, "--no-module")
    mark = unbound.tail.mark()

    for send in (_udp, _tcp):
        parsed = dnswire.parse(send(pfb_dns.server, BLOCKED, REFUSED_CLIENT))
        assert (parsed.rcode, parsed.answers) == (5, []), "REFUSED from the gateway's own early ACL"
    assert _answers(_udp(pfb_dns.server, BLOCKED, ALLOWED_CLIENT)) == [UNBOUNDS_ANSWER_FOR_BLOCKED]  # the barrier
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT} {BLOCKED} A IN", since=mark)
    assert not any(REFUSED_CLIENT in line for line in logged), "the refused client never reached Unbound"


def test_with_dnsbl_off_dot_forwards_a_listed_name_and_unbound_logs_the_tls_client(
    start_gateway: StartGateway, no_module_dir: Path, unbound: RunningUnbound, tmp_path: Path
) -> None:
    crt, key = make_certificate(tmp_path)
    config = tmp_path / "config.xml"
    config.write_text(config_xml(tlsport=free_port(), entries=cert_element(REFID, b64(crt), b64(key))), "utf-8")
    mark = unbound.tail.mark()
    pfb_dns = start_gateway(no_module_dir, "--no-module", "--dot", "--pfsense-config", str(config))

    reply = asyncio.run(
        dot_exchange(
            pfb_dns.process.listening("dot"), build_query(BLOCKED), tmp_path / "server.crt", source=ALLOWED_CLIENT_TCP
        )
    )[0]

    assert _answers(reply) == [UNBOUNDS_ANSWER_FOR_BLOCKED], "Unbound's answer, not the DNSBL VIP"
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {BLOCKED} A IN", since=mark)
    assert not any(f"127.0.0.1 {BLOCKED}" in line for line in logged), "the TLS client, not the gateway"
    assert not no_module_dir.exists(), "the decider needed no module directory at all"


def _reply_rows(running: Running) -> list[str]:
    path = running.log_dir / "dns_reply.log"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_with_dnsbl_off_and_reply_logging_on_the_reply_is_one_row_the_reports_tab_reads(
    start_gateway: StartGateway, no_module_dir: Path, unbound: RunningUnbound
) -> None:
    name = _fresh("replylog")
    unbound.zone[(name, dnswire.TYPE_A)] = [f"{name} 300 IN A 192.0.2.77"]
    pfb_dns = start_gateway(no_module_dir, "--no-module", "--reply-log")

    reply = _udp(pfb_dns.server, name, ALLOWED_CLIENT)
    pfb_dns.process.stop()  # the decider flushes the rows it still holds when the gateway ends its session

    assert _answers(reply) == [(name, dnswire.TYPE_A, bytes([192, 0, 2, 77]))]
    [line] = _reply_rows(pfb_dns)
    fields = line.split(",")
    assert STAMP.match(fields[1]), f"stamped as the module stamps: {fields[1]!r}"
    [expected] = ROWS["rows"]["a"]  # the row the PHP viewer tests read, for a reply of this shape
    shaped = expected.split(",")
    shaped[1], shaped[6], shaped[7] = fields[1], name.rstrip("."), ALLOWED_CLIENT
    assert fields == shaped, "the existing row, with the name and the real client of this query"
    php = "echo json_encode(fgetcsv(STDIN, 0, ',', '\"', ''));"  # the Reports readers' own call
    parsed = json.loads(
        subprocess.run(["php", "-r", php], input=line, capture_output=True, check=True, text=True).stdout
    )
    assert len(parsed) == 10 and parsed[0] == "DNS-reply"


def test_with_dnsbl_off_and_reply_logging_off_no_log_is_written(
    start_gateway: StartGateway, no_module_dir: Path
) -> None:
    pfb_dns = start_gateway(no_module_dir, "--no-module")

    assert _answers(_udp(pfb_dns.server, BLOCKED, ALLOWED_CLIENT)) == [UNBOUNDS_ANSWER_FOR_BLOCKED]
    pfb_dns.process.stop()

    assert sorted(path.name for path in pfb_dns.log_dir.iterdir()) == [], "not a log file was created"


# --- DNSBL on and the Resolver forwarding: the observer -----------------------------------------------------


def test_an_upstream_ede_block_is_logged_for_the_real_client_in_observer_mode(
    start_gateway: StartGateway, module_dir: Path, forwarding_ini: None, observed_unbound: RunningUnbound
) -> None:
    shutil.copytree(
        module_dir, observed_unbound.conf_dir, symlinks=True, dirs_exist_ok=True
    )  # Unbound's cwd hosts both
    name = _fresh("ede")
    observed_unbound.verdicts[name] = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))
    pfb_dns = start_gateway(observed_unbound.conf_dir, "--observer", behind=observed_unbound)

    reply = _udp(pfb_dns.server, name, ALLOWED_CLIENT)

    assert dnswire.parse(reply).rcode == NXDOMAIN
    [row] = pfb_dns.dnsbl_rows(1)  # the module logs from a thread of its own
    assert (row[2], row[3], row[5], row[7], row[8]) == (
        name.rstrip("."), ALLOWED_CLIENT, "Upstream_Block", "EDE15 (Blocked)", "Blocked",
    ), "an upstream block, logged for the client that asked (through PROXYv2), not for the gateway"  # fmt: skip


@pytest.mark.parametrize(("flags", "serves"), [((), False), (("--observer",), True)], ids=["no-flag", "observer"])
def test_the_observer_socket_exists_only_with_the_observer_flag(
    start_gateway: StartGateway, module_dir: Path, unbound: RunningUnbound, flags: tuple[str, ...], serves: bool
) -> None:
    start_gateway(module_dir, *flags)  # READY has been read: the decider has made its choice
    path = module_dir / OBSERVER_SOCKET

    assert path.exists() is serves, f"the observer socket {'must' if serves else 'must not'} exist"
    if serves:
        assert (stat.S_ISSOCK(path.stat().st_mode), stat.S_IMODE(path.stat().st_mode)) == (True, 0o600)
