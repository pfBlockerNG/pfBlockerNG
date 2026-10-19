"""The Python proxy is the gateway's decision service and nothing else (issue #3517): its command line is the one the
rc script hands it, with the three mode flags the gateway adds, and the DNS listener flags are gone."""

from __future__ import annotations

import pfb_dns_proxy
import pytest

# What pfb_dns_proxy_service() puts after `--`, and what pfb_dns_gateway appends for the pfB-DNS mode.
RC_ARGV = ["--decision-fd", "3", "--module-dir", "/var/unbound", "--user", "unbound"]


def test_the_argv_the_rc_script_gives_the_decider_is_accepted_and_every_mode_flag_is_off_by_default() -> None:
    args = pfb_dns_proxy.parse_args(RC_ARGV)
    assert (args.decision_fd, args.module_dir, args.user) == (3, "/var/unbound", "unbound")
    assert (args.no_module, args.observer, args.reply_log) == (False, False, False)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (["--no-module"], (True, False, False)),
        (["--no-module", "--reply-log"], (True, False, True)),
        (["--observer"], (False, True, False)),
    ],
    ids=["dnsbl-off", "dnsbl-off-reply-log", "forwarding-observer"],
)
def test_each_mode_the_gateway_hands_on_is_accepted(mode: list[str], expected: tuple[bool, bool, bool]) -> None:
    args = pfb_dns_proxy.parse_args([*RC_ARGV, *mode])
    assert (args.no_module, args.observer, args.reply_log) == expected


@pytest.mark.parametrize(
    "mode",
    [["--no-module", "--observer"], ["--reply-log"]],
    ids=["observer-needs-the-module", "reply-log-needs-no-module"],
)
def test_a_mode_combination_the_gateway_never_makes_is_refused(
    mode: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as refused:
        pfb_dns_proxy.parse_args([*RC_ARGV, *mode])
    assert refused.value.code == 2
    assert "error:" in capsys.readouterr().err


LISTENER_FLAGS = [
    ["--listen", "127.0.0.1"],
    ["--port", "53"],
    ["--upstream", "127.0.0.1:5353"],
    ["--timeout", "5"],
    ["--dot"],
    ["--pfsense-config", "/cf/conf/config.xml"],
    ["--ready-file", "/var/unbound/pfb_dns_ready"],
]


@pytest.mark.parametrize("flag", LISTENER_FLAGS, ids=[flag[0] for flag in LISTENER_FLAGS])
def test_a_flag_that_only_a_dns_listener_took_is_an_unknown_argument(
    flag: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as refused:
        pfb_dns_proxy.parse_args([*RC_ARGV, *flag])
    assert refused.value.code == 2
    assert f"unrecognized arguments: {flag[0]}" in capsys.readouterr().err


def test_without_a_decision_socket_there_is_nothing_to_serve_and_the_process_refuses_to_start(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as refused:
        pfb_dns_proxy.parse_args(["--module-dir", "/var/unbound"])
    assert refused.value.code == 2
    assert "--decision-fd" in capsys.readouterr().err
