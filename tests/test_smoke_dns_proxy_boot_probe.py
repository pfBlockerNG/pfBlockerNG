"""Off-appliance tests of the verdict on the pfB-DNS reboot test's early-boot probe log (issue #3515).

The live test plants a probe in /etc/rc.custom_boot_early and judges its log with `_judge_boot_probe`; these cases feed
that judge logs a box could write, so a verdict that stops noticing a late answer, a bounced proxy or a dropped query
fails here without a VM.
"""

from __future__ import annotations

import pytest

from tests.smoke import test_smoke_dns_proxy as dns

BOOT = 1000
PACKAGES = 1035  # rc.start_packages' own log line
VIP = "10.10.10.1"
UPSTREAM = "192.0.2.9"
GOOD = f"listed=NOERROR:{VIP} answer=NOERROR:{UPSTREAM}"
NONE = "listed=NONE:- answer=NONE:-"
SERVING = "unbound=77 proxy=111 daemon=110 listening=1"


def _log(*rows: str) -> str:
    return "".join(f"@@ {row}\n" for row in rows)


# The proxy is launched, listens at 1015, answers at 1016; rc.start_packages begins at 1035; the probe stops at 1080.
GREEN = [
    f"1005 boot={BOOT} start pid=9 deadline=300",
    f"1012 boot={BOOT} state unbound= proxy=111 daemon=110 listening=0 pkg=0 unbound_age=",
    f"1013 boot={BOOT} query n=1 allowed=p-1.com {NONE}",
    f"1015 boot={BOOT} state {SERVING} pkg=0 unbound_age=2",
    f"1016 boot={BOOT} query n=2 allowed=p-2.com {GOOD}",
    f"1035 boot={BOOT} state {SERVING} pkg=1 unbound_age=2",
    f"1036 boot={BOOT} query n=3 allowed=p-3.com {GOOD}",
    f"1045 boot={BOOT} query n=4 allowed=p-4.com {GOOD}",
    f"1080 boot={BOOT} end reason=packages",
]


def _judge(rows: list[str], *, packages: int = PACKAGES) -> dns.BootProbe:
    return dns._judge_boot_probe(
        _log(*rows), boot=BOOT, packages=packages, listed_address=VIP, upstream_address=UPSTREAM
    )


def _swap(rows: list[str], index: int, row: str) -> list[str]:
    return [*rows[:index], row, *rows[index + 1 :]]


def test_answers_before_the_package_stage_and_an_undisturbed_proxy_pass() -> None:
    assert _judge(GREEN) == dns.BootProbe(
        ready=1016,
        ready_name="p-2.com",
        listening=1015,
        unbound_start=1013,
        pids=("111", "110"),
        packages_seen=1035,
    )


def test_an_unknown_unbound_age_leaves_its_start_unknown() -> None:
    rows = _swap(GREEN, 3, f"1015 boot={BOOT} state {SERVING} pkg=0 unbound_age=")
    assert _judge(rows).unbound_start is None


@pytest.mark.parametrize(
    ("rows", "packages", "message"),
    [
        # rc.start_packages begins in the second the first correct answers are logged: the answers must come before it
        (GREEN, 1016, "not before rc.start_packages"),
        # the listed name never got the VIP
        (
            [row.replace(GOOD, f"listed=NOERROR:{UPSTREAM} answer=NOERROR:{UPSTREAM}") for row in GREEN],
            PACKAGES,
            "none of",
        ),
        # the proxy answers but the fresh name never reached the upstream
        ([row.replace(GOOD, f"listed=NOERROR:{VIP} answer=SERVFAIL:-") for row in GREEN], PACKAGES, "none of"),
        # rc.start_packages starts the proxy again: new pids, the socket gone in between
        (
            [
                *GREEN[:7],
                f"1037 boot={BOOT} state unbound=77 proxy= daemon= listening=0 pkg=1 unbound_age=2",
                f"1039 boot={BOOT} state unbound=77 proxy=222 daemon=221 listening=1 pkg=1 unbound_age=2",
                *GREEN[7:],
            ],
            PACKAGES,
            "was listening, then",
        ),
        # same pids, but a query fails while the package stage runs
        (_swap(GREEN, 6, f"1036 boot={BOOT} query n=3 allowed=p-3.com {NONE}"), PACKAGES, "quer.* failed"),
        # the probe never saw rc.start_packages begin, so it cannot speak for the package stage
        ([row for i, row in enumerate(GREEN) if i != 5], PACKAGES, "never saw"),
        # the probe's deadline ended it before it had watched the package stage for GRACE seconds
        (_swap(GREEN, 8, f"1300 boot={BOOT} end reason=deadline"), PACKAGES, "deadline"),
        # a log left by another boot
        ([row.replace(f"boot={BOOT}", "boot=500") for row in GREEN], PACKAGES, "another boot"),
        # the probe was killed before it logged its end
        (GREEN[:-1], PACKAGES, "did not finish"),
        # the hook never started it
        ([], PACKAGES, "never started"),
    ],
    ids=[
        "answers-after-packages",
        "no-vip",
        "no-upstream-answer",
        "proxy-started-again",
        "query-fails-in-package-stage",
        "package-stage-unseen",
        "deadline-before-the-stage-was-watched",
        "other-boot",
        "no-end",
        "no-start",
    ],
)
def test_a_boot_that_misses_the_bar_is_refused(rows: list[str], packages: int, message: str) -> None:
    with pytest.raises(AssertionError, match=message):
        _judge(rows, packages=packages)
