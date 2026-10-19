"""Off-appliance tests of the verdict on the pfB-DNS reboot test's early-boot probe log (issue #3515).

The live test plants a probe in /etc/rc.custom_boot_early and judges its log with `_judge_boot_probe`; these cases feed
that judge logs a box could write, so a verdict that stops noticing a late answer, a bounced proxy or a dropped query
fails here without a VM.

The probe samples the proxy and the package stage after the answers of each query and logs a `state` row, when
something changed, before that query's row. The judge therefore reads every order from the position of rows in the
probe's own log: the first correct answers must come before the first `state` row that shows the package stage begun
(`pkg=1`; `pkg=2` is rc.start_packages returned and its rc scripts exited, which ends the probe). No epoch decides an
order, so a clock that steps while the probe runs cannot change the verdict (see
`test_a_clock_that_steps_backwards_does_not_change_an_order_read_from_the_log`).
"""

from __future__ import annotations

import pytest

from tests.smoke import test_smoke_dns_proxy as dns

BOOT = 1000
VIP = "10.10.10.1"
UPSTREAM = "192.0.2.9"
GOOD = f"listed=NOERROR:{VIP} answer=NOERROR:{UPSTREAM}"
NONE = "listed=NONE:- answer=NONE:-"
SERVING = "unbound=77 proxy=111 daemon=110 listening=1"


def _log(*rows: str) -> str:
    return "".join(f"@@ {row}\n" for row in rows)


# The proxy is launched, listens at 1015, answers at 1016; rc.start_packages begins at 1035 and is over at 1070.
GREEN = [
    f"1005 boot={BOOT} start pid=9 deadline=300",
    f"1012 boot={BOOT} state unbound= proxy=111 daemon=110 listening=0 pkg=0 unbound_age=",
    f"1013 boot={BOOT} query n=1 allowed=p-1.com {NONE}",
    f"1015 boot={BOOT} state {SERVING} pkg=0 unbound_age=2",
    f"1016 boot={BOOT} query n=2 allowed=p-2.com {GOOD}",
    f"1035 boot={BOOT} state {SERVING} pkg=1 unbound_age=2",
    f"1036 boot={BOOT} query n=3 allowed=p-3.com {GOOD}",
    f"1045 boot={BOOT} query n=4 allowed=p-4.com {GOOD}",
    f"1070 boot={BOOT} state {SERVING} pkg=2 unbound_age=2",
    f"1071 boot={BOOT} query n=5 allowed=p-5.com {GOOD}",
    f"1071 boot={BOOT} end reason=packages",
]


def _judge(rows: list[str]) -> dns.BootProbe:
    return dns._judge_boot_probe(_log(*rows), boot=BOOT, listed_address=VIP, upstream_address=UPSTREAM)


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


def test_a_clock_that_steps_backwards_does_not_change_an_order_read_from_the_log() -> None:
    """The guest clock steps back 200 s as rc.start_packages begins: every row after it carries a smaller epoch.

    A verdict that compared epochs would see the first correct answers (1016) after the package stage (835) and
    refuse a boot whose log is in the right order; the judge reads the order of the rows.
    """
    stepped = [
        row if i < 5 else row.replace(f"{row.split()[0]} ", f"{int(row.split()[0]) - 200} ", 1)
        for i, row in enumerate(GREEN)
    ]
    assert stepped[5].startswith("835 "), "the fixture must step the clock back at the first pkg=1 row"

    probe = _judge(stepped)

    assert (probe.ready, probe.packages_seen) == (1016, 835)


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        # the state row that first shows the package stage comes right before the first correct answers: they were
        # given while rc.start_packages may already have begun, so they are not "before" it
        (
            [
                *GREEN[:3],
                f"1035 boot={BOOT} state {SERVING} pkg=1 unbound_age=2",
                f"1036 boot={BOOT} query n=2 allowed=p-2.com {GOOD}",
                f"1070 boot={BOOT} state {SERVING} pkg=2 unbound_age=2",
                f"1071 boot={BOOT} end reason=packages",
            ],
            "not before rc.start_packages",
        ),
        # the listed name never got the VIP
        (
            [row.replace(GOOD, f"listed=NOERROR:{UPSTREAM} answer=NOERROR:{UPSTREAM}") for row in GREEN],
            "none of",
        ),
        # the proxy answers but the fresh name never reached the upstream
        ([row.replace(GOOD, f"listed=NOERROR:{VIP} answer=SERVFAIL:-") for row in GREEN], "none of"),
        # a correct answer was logged before any state row showed the proxy listening
        (
            [
                *GREEN[:2],
                f"1016 boot={BOOT} query n=1 allowed=p-1.com {GOOD}",
                *GREEN[3:],
            ],
            "never saw the proxy listening",
        ),
        # rc.start_packages starts the proxy again: new pids, the socket gone in between
        (
            [
                *GREEN[:6],
                f"1037 boot={BOOT} state unbound=77 proxy= daemon= listening=0 pkg=1 unbound_age=2",
                f"1039 boot={BOOT} state unbound=77 proxy=222 daemon=221 listening=1 pkg=1 unbound_age=2",
                *GREEN[6:],
            ],
            "was listening, then",
        ),
        # same pids, but a query fails while the package stage runs
        (_swap(GREEN, 6, f"1036 boot={BOOT} query n=3 allowed=p-3.com {NONE}"), "quer.* failed"),
        # the probe never saw rc.start_packages begin, so it cannot speak for the package stage
        ([row for row in GREEN if "pkg=1" not in row and "pkg=2" not in row], "never saw rc.start_packages begin"),
        # the package stage began but was not over when the probe's deadline ended it
        (
            [
                *GREEN[:8],
                f"1300 boot={BOOT} end reason=deadline",
            ],
            "STUCK/ENVIRONMENT: the probe hit its 300 s deadline",
        ),
        # a log left by another boot
        ([row.replace(f"boot={BOOT}", "boot=500") for row in GREEN], "another boot"),
        # the probe was killed before it logged its end
        (GREEN[:-1], "STUCK/ENVIRONMENT: the early-boot probe did not finish"),
        # the hook never started it
        ([], "never started"),
    ],
    ids=[
        "answers-in-the-iteration-that-first-saw-the-package-stage",
        "no-vip",
        "no-upstream-answer",
        "answers-before-the-listening-sample",
        "proxy-started-again",
        "query-fails-in-package-stage",
        "package-stage-unseen",
        "deadline-before-the-stage-was-over",
        "other-boot",
        "no-end",
        "no-start",
    ],
)
def test_a_boot_that_misses_the_bar_is_refused(rows: list[str], message: str) -> None:
    with pytest.raises(AssertionError, match=message):
        _judge(rows)
