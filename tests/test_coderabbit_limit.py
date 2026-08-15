"""Unit tests for scripts/agent/coderabbit_limit.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.agent.coderabbit_limit import (
    build_report,
    classify_comment,
    decode_gh_pages,
    finished_review_times,
    hourly_allowance,
    next_slot_at,
    parse_quota_expiry,
    taper_band,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (ROOT / "tests/fixtures/coderabbit_quota_notice.md").read_text(encoding="utf-8")
AVAILABLE = (ROOT / "tests/fixtures/coderabbit_available_now.md").read_text(encoding="utf-8")
T0 = datetime(2026, 8, 15, 14, 57, 50, tzinfo=timezone.utc)
FINISHED = "No actionable comments were generated in the recent review."
FINISHED_WITH_STALE_QUOTA = "<!-- This is an auto-generated comment: rate limited by coderabbit.ai -->\n" + FINISHED


def _bot(created: str, body: str, updated: str | None = None, pr: int = 10) -> dict:
    return {
        "user": {"login": "coderabbitai[bot]"},
        "created_at": created,
        "updated_at": updated or created,
        "body": body,
        "issue_url": f"https://api.github.com/repos/pfBlockerNG/pfBlockerNG/issues/{pr}",
    }


def test_parse_production_quota_notice() -> None:
    expiry = parse_quota_expiry(FIXTURE, "2026-08-15T14:57:50Z")
    assert expiry == T0 + timedelta(minutes=6, seconds=30)


def test_classify() -> None:
    assert classify_comment(AVAILABLE) == "available"
    assert classify_comment(FINISHED_WITH_STALE_QUOTA) == "finished"
    assert parse_quota_expiry(FINISHED_WITH_STALE_QUOTA, "2026-08-15T14:57:50Z") is None
    assert parse_quota_expiry(FINISHED, "2026-08-15T15:00:00Z") is None


def test_created_at_not_updated_at() -> None:
    comments = [_bot("2026-08-15T09:00:00Z", FINISHED, updated="2026-08-15T15:55:00Z")]
    times = finished_review_times(comments)
    assert times[0][1] == datetime(2026, 8, 15, 9, 0, tzinfo=timezone.utc)
    report = build_report(comments, datetime(2026, 8, 15, 16, 0, tzinfo=timezone.utc), plan="pro+")
    assert report.used_hour == 0
    assert report.used_7d == 1
    assert report.recommend == "open"


def test_hourly_allowance_follows_published_proplus_taper() -> None:
    assert hourly_allowance(0, "pro+") == 10
    assert hourly_allowance(29, "pro+") == 10
    assert hourly_allowance(30, "pro+") == 8
    assert hourly_allowance(42, "pro+") == 6
    assert hourly_allowance(90, "pro+") == 1
    assert taper_band(42, "pro+") == ("40-49", 6)
    assert hourly_allowance(0, "pro") == 5
    assert hourly_allowance(60, "pro") == 1


def test_next_slot_is_when_oldest_blocking_review_ages_out() -> None:
    times = [T0 + timedelta(minutes=m) for m in (0, 10, 20, 30, 40, 50, 55, 56, 57, 58)]
    assert next_slot_at(times, 10) == T0 + timedelta(hours=1, seconds=30)


def test_report_wait_on_quota() -> None:
    comments = [_bot("2026-08-15T14:57:50Z", FIXTURE, pr=2430)]
    report = build_report(comments, T0 + timedelta(minutes=1), plan="pro+")
    assert report.recommend == "wait"
    assert report.reason == "quota"
    assert report.quota_live
    assert report.quota_pr == 2430
    assert "14:57" not in (report.last_review or "")


def test_report_wait_when_hour_is_full() -> None:
    minutes = (0, 5, 10, 15, 20, 25, 30, 35, 40, 45)
    comments = [_bot(f"2026-08-15T14:{m:02d}:00Z", FINISHED, pr=10 + i) for i, m in enumerate(minutes)]
    report = build_report(comments, T0, plan="pro+")
    assert report.used_hour == 10
    assert report.remaining_hour == 0
    assert report.recommend == "wait"
    assert report.reason == "budget"


def test_report_open_when_slots_remain() -> None:
    comments = [_bot("2026-08-15T14:50:00Z", FINISHED)]
    report = build_report(comments, T0, plan="pro+")
    assert report.recommend == "open"
    assert report.remaining_hour == 9
    assert report.channels["pr"] == 10
    assert report.channels["cli"] == 10


def test_available_now_is_not_a_review_or_quota() -> None:
    comments = [
        _bot("2026-08-15T14:50:00Z", FINISHED),
        _bot("2026-08-15T15:34:41Z", AVAILABLE, pr=2431),
    ]
    report = build_report(comments, T0, plan="pro+")
    assert report.used_hour == 1
    assert not report.quota_live
    assert report.recommend == "open"


def test_decode_gh_pages_joins_concatenated_arrays() -> None:
    raw = '[{"id":1}][{"id":2}]'
    assert decode_gh_pages(raw) == [{"id": 1}, {"id": 2}]


def test_format_contains_the_numbers_an_agent_needs() -> None:
    from scripts.agent.coderabbit_limit import format_report

    report = build_report([_bot("2026-08-15T14:50:00Z", FINISHED)], T0, plan="pro+")
    text = format_report(report)
    assert "10 PR / 10 CLI / 10 IDE" in text
    assert "remaining 9" in text
    assert "recommend: open" in text
    assert "Lower bound" in text
