"""Integration: which directives the real Unbound reads from the admin's Custom Options text (Docker).

Each case asks the installed Unbound (unbound-checkconf -o) which value it takes for one option from a given
Custom Options text, and whether a listed value is effective. That is the lexing the guard in pfblockerng.inc
(pfb_dns_proxy_directive_text() and pfb_dns_proxy_listener_directive()) models before the Resolver is moved.
This test never calls the guard; the PHP suite pins the guard with its own hand-copied case lists
(DnsProxyResolverMoveTest), so the two can drift apart. No Docker (or an image that cannot be built) is a
FAILURE, never a skip, like the other integration tests.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest
from test_integration_unbound import BUILD_TIMEOUT, DOCKERFILE, IMAGE, _docker

BASE = "server:\n    do-ip6: no\n    port: 53\n    interface: 127.0.0.1\n    access-control: 127.0.0.0/8 allow\n"
INCLUDED = "server:\n    port: 5300\n"

# (option, the admin's text after BASE, the value to look for, whether Unbound takes that value)
CASES = [
    pytest.param("port", "    prefetch: yes port: 5300\n", "5300", True, id="port after a value on its line"),
    pytest.param("port", "server: port: 5300\n", "5300", True, id="port after the clause name"),
    pytest.param("port", '    log-identity: "#" port: 5300\n', "5300", True, id="port after a quoted hash"),
    pytest.param("port", "    log-identity: a#b port: 5300\n", "5300", True, id="port after a hash inside a word"),
    pytest.param(
        "port", "    log-identity: a\\ #x port: 5300\n", "5300", True, id="port after an escaped space and hash"
    ),
    pytest.param("port", "    log-identity: '#' port: 5300\n", "5300", True, id="port after a single-quoted hash"),
    pytest.param(
        "port", '    log-identity: "a\\" # " port: 5300\n', "5300", True, id="port after an escaped quote in quotes"
    ),
    pytest.param(
        "port", "    log-identity: 'a\\' # x' port: 5300\n", "5300", True, id="port after an escaped single quote"
    ),
    pytest.param("port", "    log-identity: x\f port: 5300\n", "5300", True, id="port after a formfeed"),
    pytest.param(
        "port", '    log-identity: "a\\\\" port: 5300\n', "5300", True, id="a doubled backslash closes the string"
    ),
    pytest.param("port", "    # x\\\n    port: 5300\n", "5300", True, id="a comment ending in a backslash ends at LF"),
    pytest.param("port", "    # port: 5300\n", "5300", False, id="a comment naming a port"),
    pytest.param("port", "    prefetch: yes # port: 5300\n", "5300", False, id="a comment after a value"),
    pytest.param("port", '    log-identity: "x" # port: 5300\n', "5300", False, id="a comment after a quoted value"),
    pytest.param(
        "port", '    log-identity: x\\" # y" port: 5300\n', "5300", False, id="an escaped quote outside strings"
    ),
    pytest.param("port", '    log-identity: "# not a comment"\n', "5300", False, id="a quoted hash with no directive"),
    pytest.param(
        "interface", "    prefetch: yes interface: 0.0.0.0@5300\n", "0.0.0.0@5300", True, id="interface after a value"
    ),
    pytest.param(
        "interface",
        '    log-identity: "#" interface: 0.0.0.0@5300\n',
        "0.0.0.0@5300",
        True,
        id="interface after a quoted hash",
    ),
    pytest.param(
        "interface", "    # interface: 0.0.0.0@5300\n", "0.0.0.0@5300", False, id="a comment naming an interface"
    ),
    pytest.param(
        "port", '    log-identity: "x" include: /conf/included.conf\n', "5300", True, id="include after a value"
    ),
    pytest.param("port", "    # include: /conf/included.conf\n", "5300", False, id="a comment naming an include"),
]


def _checkconf(conf_dir: Path, option: str) -> subprocess.CompletedProcess[str]:
    probe = _docker("version", "--format", "{{.Server.Version}}")
    if probe.returncode != 0:
        pytest.fail(f"docker daemon unreachable (this must fail, not skip): {probe.stderr.strip()}")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        build = _docker("build", "-t", IMAGE, "-", stdin=DOCKERFILE, timeout=BUILD_TIMEOUT)
        if build.returncode != 0:
            pytest.fail(f"cannot build the Unbound test image:\n{build.stdout}\n{build.stderr}")
    return _docker(
        "run", "--rm", "--network", "none", "--name", f"pfb-lexer-{uuid.uuid4().hex[:8]}",
        "-v", f"{conf_dir}:/conf:ro", IMAGE, "unbound-checkconf", "-o", option, "/conf/unbound.conf",
    )  # fmt: skip


@pytest.mark.parametrize(("option", "text", "value", "taken"), CASES)
def test_unbound_takes_a_value_exactly_where_the_guard_models_it(
    tmp_path: Path, option: str, text: str, value: str, taken: bool
) -> None:
    (tmp_path / "included.conf").write_text(INCLUDED, encoding="utf-8")
    (tmp_path / "unbound.conf").write_text(BASE + text, encoding="utf-8")

    result = _checkconf(tmp_path, option)

    assert result.returncode == 0, f"unbound-checkconf rejected the configuration:\n{result.stdout}\n{result.stderr}"
    assert (value in result.stdout.split()) is taken, (
        f"unbound-checkconf -o {option} printed {result.stdout.split()!r}; expected {value!r} "
        f"{'to be taken' if taken else 'not to be taken'} for:\n{text}"
    )
