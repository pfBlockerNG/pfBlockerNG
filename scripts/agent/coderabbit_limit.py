#!/usr/bin/env python3
"""Advisory CodeRabbit PR-review limit status.

No labels, no comments, no mute. Reconstructs a *lower bound* on this
repo's PR-review spend from GitHub issue comments and prints the full
picture so an agent can decide whether to open a PR.

- There is no Fair Usage remaining-slots REST API (OpenAPI 1.0.0).
- Use ``created_at``: CodeRabbit edits the summarize comment in place,
  so ``updated_at`` moves a review into the wrong hour (32/32 last week).
- Incrementals collapse onto that one comment, so the hour count is a
  lower bound. Cross-repo spend is invisible (Fair Usage is per developer).
- Fetch: ``GET /repos/{o}/{r}/issues/comments?since=`` (paginated), not
  one request per PR.

Called from ``scripts/agent/before-pr-create.sh`` immediately before
``gh pr create``. Exit 0 = open is affordable; 3 = wait.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

QUOTA_RE = re.compile(r"Review limit reached|rate limited by coderabbit", re.I)
AVAIL_RE = re.compile(
    r"Next review available in:?\s*(?:\*+\s*)*(\d+)\s*(minutes?|hours?)",
    re.I,
)
AVAILABLE_NOW_RE = re.compile(r"Reviews are available now", re.I)
FINISHED_RE = re.compile(
    r"Actionable comments posted|No actionable comments were generated",
    re.I,
)
ISSUE_RE = re.compile(r"/issues/(\d+)(?:\b|$)")
BOT = "coderabbitai[bot]"
HOUR = timedelta(hours=1)
WEEK = timedelta(days=7)
DEFAULT_WINDOW_MINUTES = 15
NOTE = (
    "Lower bound: incrementals edit one summarize comment (created_at). "
    "Other repos are invisible. Fair Usage is per developer."
)

# https://docs.coderabbit.ai/management/plans#rate-limits
PLAN_CHANNELS = {
    "free": {"pr": 1, "ide": 3, "cli": 3},
    "oss": {"pr": 1, "ide": 1, "cli": 3},
    "pro": {"pr": 5, "ide": 5, "cli": 5},
    "pro+": {"pr": 10, "ide": 10, "cli": 10},
    "enterprise": {"pr": 12, "ide": 12, "cli": 12},
}

# https://docs.coderabbit.ai/management/plans#fair-usage-limits-policy
# (max 7-day *PR* reviews inclusive, hourly PR allowance).
FAIR_USAGE_7D: dict[str, tuple[tuple[int, int], ...]] = {
    "pro": ((29, 5), (39, 4), (49, 3), (59, 2), (10**9, 1)),
    "pro+": ((29, 10), (39, 8), (49, 6), (59, 5), (69, 4), (79, 3), (89, 2), (10**9, 1)),
}


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _bot_login(comment: Mapping[str, Any]) -> str:
    return (comment.get("user") or {}).get("login") or ""


def classify_comment(body: str) -> str:
    """Return quota, available, finished, or other."""
    text = body or ""
    if AVAILABLE_NOW_RE.search(text):
        return "available"
    if FINISHED_RE.search(text):
        return "finished"
    if QUOTA_RE.search(text):
        return "quota"
    return "other"


def parse_quota_expiry(body: str, created_at: str) -> datetime | None:
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


def comment_pr_number(comment: Mapping[str, Any]) -> int | None:
    for key in ("issue_url", "html_url"):
        match = ISSUE_RE.search(comment.get(key) or "")
        if match:
            return int(match.group(1))
    return None


def finished_review_times(comments: Iterable[Mapping[str, Any]]) -> list[tuple[int | None, datetime]]:
    """(pr, created_at) for each finished-review comment. Never updated_at."""
    out: list[tuple[int | None, datetime]] = []
    for comment in comments:
        if _bot_login(comment) != BOT:
            continue
        if classify_comment(comment.get("body") or "") != "finished":
            continue
        created = comment.get("created_at") or ""
        if not created:
            continue
        out.append((comment_pr_number(comment), _parse_dt(created)))
    return out


def newest_quota(comments: Iterable[Mapping[str, Any]]) -> tuple[int | None, datetime | None]:
    best: datetime | None = None
    best_pr: int | None = None
    best_created = ""
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
            best_pr = comment_pr_number(comment)
    return best_pr, best


def reviews_in_window(times: Iterable[datetime], now: datetime, window: timedelta) -> list[datetime]:
    start = now - window
    return sorted(stamp for stamp in times if start < stamp <= now)


def normalize_plan(plan: str) -> str:
    key = (plan or "pro+").strip().lower().replace(" ", "")
    if key in {"proplus", "pro_plus"}:
        return "pro+"
    return key or "pro+"


def taper_band(reviews_7d: int, plan: str = "pro+") -> tuple[str, int]:
    """Return (band label, hourly PR allowance) from the published 7-day table."""
    key = normalize_plan(plan)
    table = FAIR_USAGE_7D.get(key)
    if not table:
        rate = PLAN_CHANNELS.get(key, PLAN_CHANNELS["pro+"])["pr"]
        return "flat", rate
    prev = 0
    for cap, rate in table:
        if reviews_7d <= cap:
            if cap >= 10**8:
                return f"{prev}+", rate
            return f"{prev}-{cap}", rate
        prev = cap + 1
    return "90+", 1


def hourly_allowance(reviews_7d: int, plan: str = "pro+") -> int:
    return taper_band(reviews_7d, plan)[1]


def next_slot_at(times_in_hour: list[datetime], allowance: int) -> datetime | None:
    """When the rolling hour drops below ``allowance`` spent slots."""
    if allowance <= 0 or len(times_in_hour) < allowance:
        return None
    ordered = sorted(times_in_hour)
    pivot = ordered[len(ordered) - allowance]
    return pivot + timedelta(hours=1, seconds=30)


def decode_gh_pages(raw: str) -> list[Any]:
    """Parse ``gh api --paginate`` output (one array, or ``][``-joined pages)."""
    text = (raw or "").strip()
    if not text:
        return []
    if "][" in text:
        text = text.replace("][", ",")
    data = json.loads(text)
    if isinstance(data, list):
        return data
    return [data]


@dataclass(frozen=True)
class LimitReport:
    plan: str
    channels: dict[str, int]
    used_7d: int
    taper_band: str
    hourly_allowance: int
    used_hour: int
    remaining_hour: int
    last_review: str | None
    next_slot: str | None
    quota_live: bool
    quota_until: str | None
    quota_pr: int | None
    recommend: str
    reason: str
    note: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_report(
    comments: Iterable[Mapping[str, Any]],
    now: datetime,
    *,
    plan: str = "pro+",
) -> LimitReport:
    key = normalize_plan(plan)
    channels = dict(PLAN_CHANNELS.get(key, PLAN_CHANNELS["pro+"]))
    stamps = [stamp for _pr, stamp in finished_review_times(comments)]
    used_7d = len(reviews_in_window(stamps, now, WEEK))
    hour = reviews_in_window(stamps, now, HOUR)
    band, allowance = taper_band(used_7d, key)
    last = max(stamps) if stamps else None
    quota_pr, quota_expiry = newest_quota(comments)
    quota_live = quota_expiry is not None and quota_expiry > now
    remaining = max(0, allowance - len(hour))
    if quota_live:
        recommend, reason, wait_until = "wait", "quota", quota_expiry
    elif remaining <= 0:
        recommend, reason, wait_until = "wait", "budget", next_slot_at(hour, allowance)
    else:
        recommend, reason, wait_until = "open", "clear", next_slot_at(hour, allowance)
    return LimitReport(
        plan=key,
        channels=channels,
        used_7d=used_7d,
        taper_band=band,
        hourly_allowance=allowance,
        used_hour=len(hour),
        remaining_hour=remaining,
        last_review=_iso(last),
        next_slot=_iso(wait_until),
        quota_live=quota_live,
        quota_until=_iso(quota_expiry) if quota_live else None,
        quota_pr=quota_pr if quota_live else None,
        recommend=recommend,
        reason=reason,
        note=NOTE,
    )


def format_report(report: LimitReport) -> str:
    ch = report.channels
    lines = [
        "CodeRabbit PR-review limit (advisory, lower bound)",
        (
            f"plan: {report.plan}  |  published hourly: "
            f"{ch.get('pr', '?')} PR / {ch.get('cli', '?')} CLI / {ch.get('ide', '?')} IDE"
        ),
        (
            f"7-day PR reviews seen: {report.used_7d}  →  "
            f"Fair Usage band {report.taper_band}  →  {report.hourly_allowance}/hour"
        ),
        f"this hour: used {report.used_hour}  remaining {report.remaining_hour}",
        f"last review: {report.last_review or '-'}",
        f"next slot: {report.next_slot or '-'}",
    ]
    if report.quota_live:
        lines.append(f"quota notice: live until {report.quota_until} on #{report.quota_pr}")
    else:
        lines.append("quota notice: none")
    if report.recommend == "wait":
        when = report.next_slot or "unknown"
        lines.append(f"recommend: wait until {when} ({report.reason})")
    else:
        lines.append(f"recommend: open  ({report.remaining_hour} slot(s) left this hour)")
    lines.append(f"note: {report.note}")
    return "\n".join(lines) + "\n"


def fetch_comments_since(repo: str, since: datetime) -> list[Mapping[str, Any]]:
    iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = subprocess.check_output(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{repo}/issues/comments?since={iso}&per_page=100",
        ],
        text=True,
    )
    rows = decode_gh_pages(raw)
    return [row for row in rows if isinstance(row, dict)]


def cmd_status(repo: str, *, plan: str, as_json: bool) -> int:
    now = datetime.now(timezone.utc)
    comments = fetch_comments_since(repo, now - WEEK)
    report = build_report(comments, now, plan=plan)
    text = format_report(report)
    sys.stdout.write(json.dumps(report.as_dict(), indent=2) + "\n" if as_json else text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("```\n" + text + "```\n")
    return 3 if report.recommend == "wait" else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    status = sub.add_parser("status", help="print the advisory limit picture")
    status.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    status.add_argument("--plan", default=os.environ.get("CODERABBIT_PLAN", "pro+"))
    status.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    if args.cmd == "status":
        if not args.repo:
            print("GITHUB_REPOSITORY / --repo required", file=sys.stderr)
            return 2
        return cmd_status(args.repo, plan=args.plan, as_json=args.as_json)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
