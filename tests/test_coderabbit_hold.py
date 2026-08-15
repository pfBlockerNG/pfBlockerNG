"""Unit tests for scripts/agent/coderabbit_hold.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.agent.coderabbit_hold import (
    LimitStatus,
    build_limit_status,
    classify_comment,
    hourly_allowance,
    newest_quota_expiry,
    next_slot_at,
    parse_quota_expiry,
    poll_actions,
    prs_to_unhold,
    quota_is_live,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (ROOT / "tests/fixtures/coderabbit_quota_notice.md").read_text(encoding="utf-8")
AVAILABLE = (ROOT / "tests/fixtures/coderabbit_available_now.md").read_text(encoding="utf-8")
T0 = datetime(2026, 8, 15, 14, 57, 50, tzinfo=timezone.utc)
FINISHED = "No actionable comments were generated in the recent review."
FINISHED_WITH_STALE_QUOTA = "<!-- This is an auto-generated comment: rate limited by coderabbit.ai -->\n" + FINISHED


def _bot(created: str, body: str, updated: str | None = None) -> dict:
    return {
        "user": {"login": "coderabbitai[bot]"},
        "created_at": created,
        "updated_at": updated or created,
        "body": body,
    }


def test_parse_production_quota_notice() -> None:
    expiry = parse_quota_expiry(FIXTURE, "2026-08-15T14:57:50Z")
    assert expiry == T0 + timedelta(minutes=6, seconds=30)


def test_parse_ignores_non_quota() -> None:
    assert parse_quota_expiry("No actionable comments were generated", "2026-08-15T15:00:00Z") is None


def test_classify_available_now() -> None:
    assert classify_comment(AVAILABLE) == "available"
    assert parse_quota_expiry(AVAILABLE, "2026-08-15T15:34:41Z") is None


def test_classify_finished_wins_over_stale_quota_marker() -> None:
    assert classify_comment(FINISHED_WITH_STALE_QUOTA) == "finished"
    assert parse_quota_expiry(FINISHED_WITH_STALE_QUOTA, "2026-08-15T14:57:50Z") is None


def test_newest_quota_not_the_latest_non_quota_comment() -> None:
    comments = [
        _bot("2026-08-15T14:57:50Z", FIXTURE),
        _bot("2026-08-15T15:00:00Z", "I will review pull request #2430"),
    ]
    expiry = newest_quota_expiry(comments)
    assert expiry == T0 + timedelta(minutes=6, seconds=30)
    assert quota_is_live(comments, T0 + timedelta(minutes=3))
    assert not quota_is_live(comments, T0 + timedelta(minutes=7))


def test_unhold_none_while_any_quota_live() -> None:
    comments = {10: [_bot("2026-08-15T14:57:50Z", FIXTURE)], 11: []}
    assert prs_to_unhold([10, 11], comments, T0 + timedelta(minutes=1)) == []


def test_unhold_oldest_one_after_window() -> None:
    comments = {
        10: [_bot("2026-08-15T14:57:50Z", FIXTURE)],
        11: [],
        12: [],
    }
    later = T0 + timedelta(minutes=10)
    assert prs_to_unhold([12, 10, 11], comments, later, one=True) == [10]
    assert prs_to_unhold([12, 10, 11], comments, later, one=False) == [10, 11, 12]


def test_hourly_allowance_follows_published_proplus_taper() -> None:
    assert hourly_allowance(0, "pro+") == 10
    assert hourly_allowance(29, "pro+") == 10
    assert hourly_allowance(30, "pro+") == 8
    assert hourly_allowance(90, "pro+") == 1
    assert hourly_allowance(0, "pro") == 5
    assert hourly_allowance(60, "pro") == 1


def test_next_slot_is_when_oldest_blocking_review_ages_out() -> None:
    times = [T0 + timedelta(minutes=m) for m in (0, 10, 20, 30, 40, 50, 55, 56, 57)]
    assert next_slot_at(times, 9) == T0 + timedelta(hours=1, seconds=30)


def test_budget_hold_uses_last_review_times_not_quota_regex() -> None:
    comments = {
        10: [_bot("2026-08-15T14:00:00Z", FINISHED, updated="2026-08-15T14:10:00Z")],
        11: [_bot("2026-08-15T14:20:00Z", FINISHED)],
        12: [_bot("2026-08-15T14:40:00Z", FINISHED)],
        13: [_bot("2026-08-15T14:50:00Z", FINISHED)],
        14: [_bot("2026-08-15T14:55:00Z", FINISHED)],
    }
    now = T0  # 14:57:50 — five finished reviews inside the hour
    # spare=1, allowance=10 → threshold 9; 5 used → clear
    status = build_limit_status(comments, now, plan="pro+", spare=1)
    assert status.reason == "clear"
    assert status.used_hour == 5
    assert status.last_review == datetime(2026, 8, 15, 14, 55, tzinfo=timezone.utc)

    # Same five reviews on a tightened Pro taper (or a small test allowance)
    tight = build_limit_status(comments, now, plan="pro", spare=1)
    # Pro base 5, spare 1 → hold at 4
    assert tight.live
    assert tight.reason == "budget"
    plan = poll_actions(tight, [10, 11, 12, 13, 14, 15], [], one=True)
    assert plan.hold == [10, 11, 12, 13, 14, 15]
    assert plan.release == []


def test_quota_overrides_budget_and_skips_source_pr() -> None:
    comments = {
        10: [_bot("2026-08-15T14:57:50Z", FIXTURE)],
        11: [_bot("2026-08-15T14:50:00Z", FINISHED)],
    }
    status = build_limit_status(comments, T0 + timedelta(minutes=1), plan="pro+", spare=1)
    assert status.reason == "quota"
    assert status.source_pr == 10
    plan = poll_actions(status, [10, 11, 12], [11], one=True)
    assert plan.hold == [12]
    assert plan.release == []


def test_available_now_does_not_override_a_full_budget() -> None:
    comments = {
        10: [_bot("2026-08-15T14:10:00Z", FINISHED)],
        11: [_bot("2026-08-15T14:20:00Z", FINISHED)],
        12: [_bot("2026-08-15T14:30:00Z", FINISHED)],
        13: [_bot("2026-08-15T14:40:00Z", FINISHED)],
        14: [_bot("2026-08-15T14:50:00Z", FINISHED)],
        15: [_bot("2026-08-15T15:34:41Z", AVAILABLE)],
    }
    status = build_limit_status(comments, T0, plan="pro", spare=1)
    assert status.live
    assert status.reason == "budget"


def test_release_one_oldest_when_budget_clears() -> None:
    comments = {10: [_bot("2026-08-15T13:00:00Z", FINISHED)]}
    status = build_limit_status(comments, T0, plan="pro+", spare=1)
    assert not status.live
    plan = poll_actions(status, [10, 11], [11, 12], one=True)
    assert plan.hold == []
    assert plan.release == [11]


def test_owner_override_never_held_and_always_released() -> None:
    status = LimitStatus(
        live=True,
        reason="budget",
        source_pr=None,
        expiry=T0 + timedelta(hours=1),
        used_hour=5,
        used_7d=5,
        allowance=5,
        last_review=T0,
    )
    plan = poll_actions(status, [10, 11, 12], [11], one=True, overrides=[11, 12])
    assert 11 not in plan.hold
    assert 12 not in plan.hold
    assert plan.hold == [10]
    assert plan.release == [11]
