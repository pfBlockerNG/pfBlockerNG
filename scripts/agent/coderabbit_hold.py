#!/usr/bin/env python3
"""CodeRabbit Fair Usage hold helpers.

Used by .github/workflows/coderabbit-hold.yml. Labels only — never posts.

There is no public Fair Usage remaining-slots REST API (CodeRabbit OpenAPI
1.0.0, 2026-08-15). The Action reconstructs spend from finished-review
comments and applies the published rolling-hour + 7-day Fair Usage table.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

QUOTA_RE = re.compile(r"Review limit reached|rate limited by coderabbit", re.I)
# Production notice (PR #2430, 2026-08-15):
#   **Next review available in:** **6 minutes**
AVAIL_RE = re.compile(
    r"Next review available in:?\s*(?:\*+\s*)*(\d+)\s*(minutes?|hours?)",
    re.I,
)
AVAILABLE_NOW_RE = re.compile(r"Reviews are available now", re.I)
FINISHED_RE = re.compile(
    r"Actionable comments posted|No actionable comments were generated",
    re.I,
)
BOT = "coderabbitai[bot]"
HOLD_LABEL = "cr-hold"
OVERRIDE_LABEL = "cr-go"
HOUR = timedelta(hours=1)
WEEK = timedelta(days=7)
DEFAULT_WINDOW_MINUTES = 15

# https://docs.coderabbit.ai/management/plans#rate-limits
PLAN_RATES = {
    "free": 1,
    "oss": 1,
    "pro": 5,
    "pro+": 10,
    "proplus": 10,
    "enterprise": 12,
}

# https://docs.coderabbit.ai/management/plans#fair-usage-limits-policy
# (max 7-day reviews inclusive, hourly allowance). Enterprise has no published
# taper — use the flat plan rate.
FAIR_USAGE_7D: dict[str, tuple[tuple[int, int], ...]] = {
    "pro": ((29, 5), (39, 4), (49, 3), (59, 2), (10**9, 1)),
    "pro+": ((29, 10), (39, 8), (49, 6), (59, 5), (69, 4), (79, 3), (89, 2), (10**9, 1)),
    "proplus": ((29, 10), (39, 8), (49, 6), (59, 5), (69, 4), (79, 3), (89, 2), (10**9, 1)),
}


@dataclass(frozen=True)
class LimitStatus:
    live: bool
    reason: str
    source_pr: int | None
    expiry: datetime | None
    used_hour: int
    used_7d: int
    allowance: int
    last_review: datetime | None


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _bot_login(comment: Mapping[str, Any]) -> str:
    return (comment.get("user") or {}).get("login") or ""


def classify_comment(body: str) -> str:
    """Return quota, available, finished, or other.

    A summarize comment can keep a leftover ``rate limited`` HTML marker after
    it is edited into a real review — finished wins. ``Reviews are available
    now`` is a chat reply, not a review and not a quota notice.
    """
    text = body or ""
    if AVAILABLE_NOW_RE.search(text):
        return "available"
    if FINISHED_RE.search(text):
        return "finished"
    if QUOTA_RE.search(text):
        return "quota"
    return "other"


def parse_quota_expiry(body: str, created_at: str) -> datetime | None:
    """Return when a quota notice stops being live, or None if body is not one."""
    if classify_comment(body) != "quota":
        return None
    created = _parse_dt(created_at)
    match = AVAIL_RE.search(body or "")
    minutes = DEFAULT_WINDOW_MINUTES
    if match:
        minutes = int(match.group(1))
        if match.group(2).lower().startswith("hour"):
            minutes *= 60
    return created + timedelta(minutes=minutes, seconds=30)


def newest_quota_expiry(comments: Iterable[Mapping[str, Any]]) -> datetime | None:
    """Expiry of the newest *quota* comment, ignoring later non-quota CR posts."""
    _pr, expiry = newest_quota_across({0: list(comments)})
    return expiry


def newest_quota_across(
    comments_by_pr: Mapping[int, list[Mapping[str, Any]]],
) -> tuple[int | None, datetime | None]:
    best: datetime | None = None
    best_pr: int | None = None
    best_created = ""
    for number, comments in comments_by_pr.items():
        for comment in comments:
            if _bot_login(comment) != BOT:
                continue
            created = comment.get("created_at") or ""
            expiry = parse_quota_expiry(comment.get("body") or "", created)
            if expiry is None:
                continue
            if created >= best_created:
                best_created = created
                best = expiry
                best_pr = int(number)
    return best_pr, best


def quota_is_live(comments: Iterable[Mapping[str, Any]], now: datetime) -> bool:
    expiry = newest_quota_expiry(comments)
    return expiry is not None and expiry > now


def finished_review_times(
    comments_by_pr: Mapping[int, list[Mapping[str, Any]]],
) -> list[tuple[int, datetime]]:
    """(pr, completed_at) for each finished review. Uses updated_at (in-place edits)."""
    out: list[tuple[int, datetime]] = []
    for number, comments in comments_by_pr.items():
        for comment in comments:
            if _bot_login(comment) != BOT:
                continue
            if classify_comment(comment.get("body") or "") != "finished":
                continue
            stamp = comment.get("updated_at") or comment.get("created_at") or ""
            if not stamp:
                continue
            out.append((int(number), _parse_dt(stamp)))
    return out


def reviews_in_window(times: Iterable[datetime], now: datetime, window: timedelta) -> list[datetime]:
    start = now - window
    return sorted(stamp for stamp in times if start < stamp <= now)


def normalize_plan(plan: str) -> str:
    key = (plan or "pro+").strip().lower().replace(" ", "")
    if key in {"proplus", "pro_plus"}:
        return "pro+"
    return key or "pro+"


def hourly_allowance(reviews_7d: int, plan: str = "pro+") -> int:
    """Published rolling-hour rate after the 7-day Fair Usage taper."""
    key = normalize_plan(plan)
    table = FAIR_USAGE_7D.get(key)
    if table:
        for cap, rate in table:
            if reviews_7d <= cap:
                return rate
    return PLAN_RATES.get(key, PLAN_RATES["pro+"])


def hold_threshold(allowance: int, spare: int) -> int:
    return max(1, allowance - max(0, spare))


def next_slot_at(times_in_hour: list[datetime], threshold: int) -> datetime | None:
    """When the rolling hour drops below ``threshold`` spent slots."""
    if len(times_in_hour) < threshold:
        return None
    ordered = sorted(times_in_hour)
    pivot = ordered[len(ordered) - threshold]
    return pivot + timedelta(hours=1, seconds=30)


def build_limit_status(
    comments_by_pr: Mapping[int, list[Mapping[str, Any]]],
    now: datetime,
    *,
    plan: str = "pro+",
    spare: int = 1,
) -> LimitStatus:
    stamps = [stamp for _pr, stamp in finished_review_times(comments_by_pr)]
    used_7d = len(reviews_in_window(stamps, now, WEEK))
    hour = reviews_in_window(stamps, now, HOUR)
    allowance = hourly_allowance(used_7d, plan)
    threshold = hold_threshold(allowance, spare)
    last = max(stamps) if stamps else None
    quota_pr, quota_expiry = newest_quota_across(comments_by_pr)
    quota_live = quota_expiry is not None and quota_expiry > now
    if quota_live:
        return LimitStatus(
            live=True,
            reason="quota",
            source_pr=quota_pr,
            expiry=quota_expiry,
            used_hour=len(hour),
            used_7d=used_7d,
            allowance=allowance,
            last_review=last,
        )
    if len(hour) >= threshold:
        return LimitStatus(
            live=True,
            reason="budget",
            source_pr=None,
            expiry=next_slot_at(hour, threshold),
            used_hour=len(hour),
            used_7d=used_7d,
            allowance=allowance,
            last_review=last,
        )
    return LimitStatus(
        live=False,
        reason="clear",
        source_pr=None,
        expiry=next_slot_at(hour, threshold) if hour else None,
        used_hour=len(hour),
        used_7d=used_7d,
        allowance=allowance,
        last_review=last,
    )


@dataclass(frozen=True)
class PollPlan:
    hold: list[int]
    release: list[int]


def poll_actions(
    status: LimitStatus,
    open_prs: list[int],
    held: list[int],
    *,
    one: bool = True,
    overrides: Iterable[int] = (),
) -> PollPlan:
    """Compute label changes. Owner ``cr-go`` PRs are never held and always unheld."""
    override_set = {int(number) for number in overrides}
    held_set = set(held)
    release_override = sorted(number for number in held if number in override_set)
    if status.live:
        skip = {status.source_pr} if status.source_pr is not None else set()
        skip |= override_set
        hold = sorted(number for number in open_prs if number not in skip and number not in held_set)
        return PollPlan(hold=hold, release=release_override)
    remaining = [number for number in sorted(held) if number not in override_set]
    release = release_override + (remaining[:1] if one else remaining)
    return PollPlan(hold=[], release=release)


def prs_to_unhold(
    held: list[int],
    comments_by_pr: Mapping[int, list[Mapping[str, Any]]],
    now: datetime,
    *,
    one: bool = True,
    plan: str = "pro+",
    spare: int = 1,
) -> list[int]:
    """Held PR numbers that may lose cr-hold.

    Live quota or a full rolling-hour budget releases none. Otherwise release
    the lowest number (oldest PR) when ``one`` is true, else all held PRs.
    """
    status = build_limit_status(comments_by_pr, now, plan=plan, spare=spare)
    return poll_actions(status, [], held, one=one).release


def _gh_json(args: list[str]) -> Any:
    out = subprocess.check_output(["gh"] + args, text=True)
    return json.loads(out) if out.strip() else []


def _ensure_label(repo: str) -> None:
    for name, description, color in (
        (HOLD_LABEL, "Mute CodeRabbit auto-review while Fair Usage is live", "C4A000"),
        (OVERRIDE_LABEL, "Owner override: do not mute CodeRabbit on this PR", "1D76DB"),
    ):
        subprocess.run(
            [
                "gh",
                "label",
                "create",
                name,
                "--repo",
                repo,
                "--description",
                description,
                "--color",
                color,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _pr_has_label(pr: Mapping[str, Any], name: str) -> bool:
    return any(label.get("name") == name for label in pr.get("labels") or [])


def _load_comments(repo: str, numbers: Iterable[int]) -> dict[int, list[Mapping[str, Any]]]:
    comments_by_pr: dict[int, list[Mapping[str, Any]]] = {}
    for number in numbers:
        comments_by_pr[int(number)] = _gh_json(["api", f"repos/{repo}/issues/{number}/comments?per_page=100"])
    return comments_by_pr


def _recent_pr_numbers(repo: str, since: datetime) -> list[int]:
    day = since.date().isoformat()
    rows = _gh_json(
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "all",
            "--limit",
            "100",
            "--search",
            f"updated:>={day}",
            "--json",
            "number",
        ]
    )
    return [int(row["number"]) for row in rows]


def _format_status(status: LimitStatus) -> str:
    last = status.last_review.isoformat() if status.last_review else "-"
    expiry = status.expiry.isoformat() if status.expiry else "-"
    return (
        f"limit {status.reason} live={status.live} "
        f"used={status.used_hour}/{status.allowance} 7d={status.used_7d} "
        f"last={last} next={expiry}"
    )


def cmd_poll(repo: str, *, one: bool = True, plan: str = "pro+", spare: int = 1) -> int:
    """Recompute mute from the review ledger; hold or release labels."""
    _ensure_label(repo)
    now = datetime.now(timezone.utc)
    open_prs = _gh_json(["pr", "list", "--repo", repo, "--state", "open", "--limit", "100", "--json", "number,labels"])
    open_numbers = [int(pr["number"]) for pr in open_prs]
    held = [int(pr["number"]) for pr in open_prs if _pr_has_label(pr, HOLD_LABEL)]
    overrides = [int(pr["number"]) for pr in open_prs if _pr_has_label(pr, OVERRIDE_LABEL)]
    numbers = sorted(set(open_numbers) | set(_recent_pr_numbers(repo, now - WEEK)))
    comments_by_pr = _load_comments(repo, numbers)
    status = build_limit_status(comments_by_pr, now, plan=plan, spare=spare)
    print(_format_status(status))
    if overrides:
        print("owner override cr-go: " + ",".join(f"#{n}" for n in overrides))
    plan = poll_actions(status, open_numbers, held, one=one, overrides=overrides)
    changed = False
    for number in plan.release:
        subprocess.check_call(["gh", "pr", "edit", str(number), "--repo", repo, "--remove-label", HOLD_LABEL])
        print(f"removed cr-hold from #{number}")
        changed = True
    for number in plan.hold:
        subprocess.check_call(["gh", "pr", "edit", str(number), "--repo", repo, "--add-label", HOLD_LABEL])
        print(f"added cr-hold to #{number}")
        changed = True
    if not changed:
        print("no label change")
    return 0


def cmd_release(repo: str, *, one: bool = True, plan: str = "pro+", spare: int = 1) -> int:
    return cmd_poll(repo, one=one, plan=plan, spare=spare)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    common.add_argument(
        "--all",
        action="store_true",
        help="clear every hold when releasing (default: one oldest PR per run)",
    )
    common.add_argument(
        "--plan",
        default=os.environ.get("CODERABBIT_PLAN", "pro+"),
        help="CodeRabbit plan for the published hourly table (default: pro+)",
    )
    common.add_argument(
        "--spare",
        type=int,
        default=int(os.environ.get("CODERABBIT_SPARE_SLOTS", "1")),
        help="hold when used >= allowance - spare (default: 1)",
    )
    sub.add_parser("poll", parents=[common], help="hold or release from the reconstructed review ledger")
    sub.add_parser("release", parents=[common], help="same as poll (kept for older workflow pins)")
    args = parser.parse_args(argv)
    if args.cmd in {"poll", "release"}:
        if not args.repo:
            print("GITHUB_REPOSITORY / --repo required", file=sys.stderr)
            return 2
        return cmd_poll(args.repo, one=not args.all, plan=args.plan, spare=args.spare)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
