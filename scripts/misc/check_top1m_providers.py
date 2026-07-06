#!/usr/bin/env python3
"""check_top1m_providers.py -- health-check the Top1M provider URLs we ship.

Issue #884: nothing caught the Alexa Top1M source rotting silently (its
hardcoded URL died years ago; cleaned up in #877). This script gives the
weekly top1m-healthcheck.yml workflow something to fail on the day the next
provider dies the same way.

We do NOT vendor the ~1M-row lists -- they're runtime-downloaded per box.
This is validate-only: fetch, check it's a real recent Top1M zip, report.

Two modes:
  --extract           Parse pfblockerng.php for every URL wired to the
                       top1m extras slot, print as a JSON list to stdout.
                       Feeds the workflow's matrix -- add/remove a provider
                       arm in the PHP and this picks it up with no edit here.
  --check-url <url>   Fetch + validate one URL. Prints an expected-vs-actual
                       report. Exit 0 = healthy, non-zero = unhealthy.

Dev-host tooling (scripts/): bare `python3` is fine here, this never runs on
the pfSense appliance (CLAUDE.md's appliance-python carve-out).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse

# A real Top1M list is ~1M rows; 100k is a generous floor that still rejects a
# truncated/error payload. Lists update ~daily; 30 days is generously frozen.
MIN_ROWS = 100_000
MAX_AGE_DAYS = 30

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PHP_FILE = REPO_ROOT / "src/usr/local/www/pfblockerng/pfblockerng.php"

# Matches "$pfb['extras'][N]['url'] = '...'" / "...['type'] = '...'" regardless
# of which if/elseif/else arm assigns it -- an extras index can be assigned
# more than once (each arm is a separate match tied to the same index N), so a
# new provider arm is picked up with no change to this script.
_URL_RE = re.compile(r"\$pfb\['extras'\]\[(\d+)\]\['url'\]\s*=\s*'([^']*)'")
_TYPE_RE = re.compile(r"\$pfb\['extras'\]\[(\d+)\]\['type'\]\s*=\s*'([^']*)'")


def extract_providers(php_text: str) -> list[dict[str, str]]:
    """Every URL wired to the top1m extras slot in pfblockerng.php.

    Groups by extras index so a URL assigned in an if/elseif/else arm is
    matched to its slot's type regardless of assignment order in the file.
    """
    types = dict(_TYPE_RE.findall(php_text))
    providers: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for idx, url in _URL_RE.findall(php_text):
        if not url or types.get(idx) != "top1m":
            continue
        if (idx, url) in seen:
            continue
        seen.add((idx, url))
        providers.append({"name": _name_from_url(url), "url": url})
    return providers


def _name_from_url(url: str) -> str:
    # Cosmetic only -- just needs to be distinct/readable per provider.
    return urlparse(url).netloc or url


def is_stale(last_modified: str | None, now: datetime, max_age_days: int) -> bool:
    """True iff a present, parseable Last-Modified is older than max_age_days.

    No header, or one we can't parse, means "unknown" -- not a staleness
    verdict we can make, so it reads as not-stale rather than a false alarm.
    """
    if not last_modified:
        return False
    try:
        modified = parsedate_to_datetime(last_modified)
    except (TypeError, ValueError):
        return False
    if modified.tzinfo is None:
        modified = modified.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - modified) > timedelta(days=max_age_days)


def _is_valid_row(row: list[str]) -> bool:
    """A plausible Top1M row: "<int rank>,<dotted domain>"."""
    if len(row) != 2:
        return False
    rank, domain = row[0].strip(), row[1].strip()
    return rank.isdigit() and "." in domain and not any(c.isspace() for c in domain)


def _scan_csv(body: bytes) -> tuple[str, int, int, tuple[int, list[str]] | None]:
    """Open `body` as a zip and scan its CSV member.

    Returns (member_name, total_rows, valid_rows, first_bad_row). Raises
    zipfile.BadZipFile / KeyError-free -- callers handle the zip-shape errors.
    """
    with zipfile.ZipFile(io.BytesIO(body)) as zf:
        names = zf.namelist()
        if not names:
            raise zipfile.BadZipFile("zip archive has no members")
        member = next((n for n in names if n.lower().endswith(".csv")), names[0])
        with zf.open(member) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")
            total = 0
            valid = 0
            first_bad: tuple[int, list[str]] | None = None
            for line_num, row in enumerate(csv.reader(text), start=1):
                if not row:
                    continue
                total += 1
                if _is_valid_row(row):
                    valid += 1
                elif first_bad is None:
                    first_bad = (line_num, row)
    return member, total, valid, first_bad


def validate_top1m(
    body: bytes,
    last_modified: str | None,
    now: datetime,
    min_rows: int = MIN_ROWS,
    max_age_days: int = MAX_AGE_DAYS,
) -> list[str]:
    """Validate a fetched Top1M payload. Empty return = healthy."""
    try:
        member, total, valid, first_bad = _scan_csv(body)
    except zipfile.BadZipFile as exc:
        return [f"expected a valid non-empty ZIP archive, got {len(body)} bytes that failed to parse ({exc})"]

    reasons = []
    if valid < min_rows:
        detail = f"; first bad row at {member}:{first_bad[0]}: {first_bad[1]!r}" if first_bad else ""
        reasons.append(
            f"expected >= {min_rows} valid 'rank,domain' rows in {member!r}, "
            f"found {valid} (of {total} total rows){detail}"
        )
    if is_stale(last_modified, now, max_age_days):
        age_days = (now - parsedate_to_datetime(last_modified)).days  # type: ignore[arg-type]
        reasons.append(
            f"expected Last-Modified within {max_age_days} days of {now.isoformat()}, "
            f"found {last_modified!r} ({age_days} days old)"
        )
    return reasons


def check_url(url: str, min_rows: int = MIN_ROWS, max_age_days: int = MAX_AGE_DAYS) -> list[str]:
    """Fetch `url` and validate it. Empty return = healthy."""
    now = datetime.now(timezone.utc)
    request = urllib.request.Request(url, headers={"User-Agent": "pfBlockerNG-top1m-healthcheck/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=120) as resp:
            body = resp.read()
            last_modified = resp.headers.get("Last-Modified")
            status = resp.status
    except urllib.error.HTTPError as exc:
        return [f"expected HTTP 2xx, got HTTP {exc.code} {exc.reason}"]
    except urllib.error.URLError as exc:
        return [f"expected a reachable URL, got a connection error: {exc.reason}"]

    if not (200 <= status < 300):
        return [f"expected HTTP 2xx, got HTTP {status}"]
    return validate_top1m(body, last_modified, now, min_rows, max_age_days)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--extract", action="store_true", help="print every top1m provider URL as JSON")
    group.add_argument("--check-url", metavar="URL", help="fetch + validate one provider URL")
    args = parser.parse_args(argv)

    if args.extract:
        providers = extract_providers(DEFAULT_PHP_FILE.read_text(encoding="utf-8"))
        print(json.dumps(providers))
        return 0

    reasons = check_url(args.check_url)
    if not reasons:
        print(f"OK  {args.check_url}: healthy (>= {MIN_ROWS} rows, not stale)")
        return 0
    print(f"FAIL {args.check_url}: unhealthy")
    for reason in reasons:
        print(f"  - {reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
