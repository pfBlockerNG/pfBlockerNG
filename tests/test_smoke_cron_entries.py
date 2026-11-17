"""Hermetic rows for the "no pfBlockerNG cron entry of any kind" matcher (issue #3996)."""

from __future__ import annotations

import pytest

from tests.smoke import cron_entries as ce

LONG = "*/15 * * * * root " + "x" * 200_000 + " /usr/local/www/pfblockerng/pfblockerng.php cron-tick\n"


@pytest.mark.parametrize(
    "line",
    [
        "*/15 * * * * root /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> /x 2>&1",
        "* * * * * root /usr/bin/timeout -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics",
        "0 0 * * * root /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php clearip",
        "0 0 * * 0 root /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cleardnsbl",
        "* * * * * root /usr/local/pkg/pfblockerng/pfb_core_metrics.sh",
        "*/15\t*\t*\t*\t*\troot\t/usr/local/pkg/pfblockerng/pfb_core_maintenance.sh   ",
        "*/15  *   *  * *   root    php   /usr/local/www/pfblockerng/pfblockerng.php   cron-tick",
        LONG,
    ],
)
def test_pfblockerng_entries_are_found(line: str) -> None:
    assert ce.find_entries([line + "\n"]) == [line.strip()]


@pytest.mark.parametrize(
    "line",
    [
        "*/15 * * * * root /usr/local/bin/php /usr/local/www/otherpackage.php tick",
        "#*/15 * * * * root php /usr/local/www/pfblockerng/pfblockerng.php cron-tick",
        "   # * * * * * root /usr/local/pkg/pfblockerng/pfb_core_metrics.sh",
        "*/5 * * * * root /usr/libexec/atrun",
        "",
    ],
)
def test_unrelated_or_commented_lines_are_not_entries(line: str) -> None:
    assert ce.find_entries([line + "\n"]) == []


def test_config_commands_are_checked_verbatim() -> None:
    assert ce.find_entries([], ["/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics"])
    assert ce.find_entries([], ["/usr/local/bin/php /usr/local/www/otherpackage.php tick"]) == []


def test_non_utf8_bytes_do_not_hide_or_invent_an_entry() -> None:
    hit = b"* * * * * root \xff\xfe /usr/local/pkg/pfblockerng/pfb_core_metrics.sh\n"
    assert len(ce.find_entries([hit])) == 1
    assert ce.find_entries([b"* * * * * root \xff\xfe /bin/true\n"]) == []


def test_empty_output_is_empty() -> None:
    assert ce.find_entries(["", ""]) == []
    assert ce.root_crontab_text(0, "", "") == ""


def test_exact_no_crontab_for_root_is_benign_and_nothing_else_is() -> None:
    assert ce.root_crontab_text(1, "", "crontab: no crontab for root\n") == ""
    for rc, out, err in (
        (1, "", "crontab: no crontab for nobody\n"),
        (1, "", "crontab: no crontab for root"),
        (1, "x", "crontab: no crontab for root\n"),
        (2, "", "crontab: no crontab for root\n"),
        (1, "", "crontab: /var/cron/tabs/root: Permission denied\n"),
    ):
        with pytest.raises(RuntimeError, match="root crontab"):
            ce.root_crontab_text(rc, out, err)
