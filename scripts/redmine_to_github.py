#!/usr/bin/env python3
# redmine_to_github.py — migrate open pfBlockerNG issues from the pfSense
# Redmine instance (https://redmine.pfsense.org) to GitHub issues on this repo,
# preserving comment threads.
#
# Each Redmine journal note becomes its own GitHub comment, headed with the
# original author + date, in chronological order.
#
# Idempotency: a re-run skips already-migrated issues and fills in any missing
# comments, so a half-finished migration is safely completed.  Mechanism:
#   - Issue body carries  <!-- redmine-id: {ID} -->
#   - Each comment ends with  <!-- redmine-journal-id: {JID} -->
# Existing GH issues are discovered via the "redmine-imported" label; existing
# comments are discovered by parsing their journal-id markers.
#
# Run via the workflow:
#   .github/workflows/redmine-import.yml
# or locally (requires REDMINE_API_KEY + GITHUB_TOKEN in env):
#   python scripts/redmine_to_github.py [--dry-run] [--limit N] ...
"""
Migrate open pfBlockerNG Redmine issues to GitHub, preserving comment threads.

Each Redmine journal note becomes a separate GitHub comment with original author
and date.  Re-runs are idempotent: issues are not duplicated, and any missing
comments are posted.

Usage:
  REDMINE_API_KEY=... GITHUB_TOKEN=... python scripts/redmine_to_github.py
  python scripts/redmine_to_github.py --dry-run
  python scripts/redmine_to_github.py --issue 12345 --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from datetime import date, datetime
from typing import NamedTuple

# ── Constants ──────────────────────────────────────────────────────────────────

_REDMINE_BASE_URL = "https://redmine.pfsense.org"
_REDMINE_PROJECT = "pfsense-packages"
_REDMINE_CATEGORY_ID = 97  # pfBlockerNG

_GH_API_BASE = "https://api.github.com"
_GH_API_VERSION = "2022-11-28"

# Pause between HTTP requests (seconds).  Keeps us polite on both APIs.
_DEFAULT_SLEEP = 0.5

# Maximum retries on GitHub secondary-rate-limit (403/429).
_GH_RATE_RETRIES = 4

_UA = "pfBlockerNG-redmine-migrator/1.0 (https://github.com/pfBlockerNG/pfBlockerNG)"

# ── Label configuration (edit here to customise) ──────────────────────────────

# Tracker → GitHub label.
_TRACKER_LABELS: dict[str, str] = {
    "Bug": "bug",
    "Feature": "enhancement",
    "Feature request": "enhancement",
}

# Priority → GitHub label (Redmine priority name → label name).
_PRIORITY_LABELS: dict[str, str] = {
    "Low": "priority: low",
    "Normal": "priority: normal",
    "High": "priority: high",
    "Urgent": "priority: urgent",
    "Immediate": "priority: immediate",
}

# Keywords in subject/description → additional topic labels.
# Order is preserved in the output; keys are lowercased before comparison.
_KEYWORD_LABELS: dict[str, str] = {
    "unbound": "unbound",
    "dnsbl": "dnsbl",
    "cron": "cron",
    "performance": "performance",
    "sync": "sync",
    "geoip": "geoip",
    "python": "python",
    "ipv6": "ipv6",
    "blocklist": "blocklist",
    "whitelist": "whitelist",
    "allowlist": "allowlist",
    "safesearch": "safesearch",
}

# Label metadata for pre-creation (name → (hex_color, description)).
_LABEL_META: dict[str, tuple[str, str]] = {
    "redmine-imported": ("e4e669", "Migrated from Redmine (pfsense.org)"),
    "bug": ("d73a4a", "Something is not working"),
    "enhancement": ("a2eeef", "New feature or improvement request"),
    "priority: low": ("bfd4f2", "Redmine priority: low"),
    "priority: normal": ("bfd4f2", "Redmine priority: normal"),
    "priority: high": ("e11d48", "Redmine priority: high"),
    "priority: urgent": ("b91c1c", "Redmine priority: urgent"),
    "priority: immediate": ("7f1d1d", "Redmine priority: immediate"),
}

# ── Pure helpers ───────────────────────────────────────────────────────────────


def map_labels(issue: dict) -> list[str]:
    """Return GitHub labels for a Redmine issue dict.

    Always includes ``redmine-imported``.  Maps tracker → bug/enhancement;
    priority → ``priority: <name>``; and scans subject + description for
    keyword topics.  Result is deduped and in stable order.
    """
    labels: list[str] = ["redmine-imported"]

    tracker_name: str = (issue.get("tracker") or {}).get("name", "")
    if tracker_name in _TRACKER_LABELS:
        labels.append(_TRACKER_LABELS[tracker_name])

    priority_name: str = (issue.get("priority") or {}).get("name", "")
    if priority_name in _PRIORITY_LABELS:
        labels.append(_PRIORITY_LABELS[priority_name])

    # Keyword scan over subject + description.
    haystack = " ".join(
        [
            issue.get("subject", "") or "",
            issue.get("description", "") or "",
        ]
    ).lower()
    for keyword, label in _KEYWORD_LABELS.items():
        if keyword in haystack:
            labels.append(label)

    # Deduplicate while preserving order.
    seen: set[str] = set()
    result: list[str] = []
    for lbl in labels:
        if lbl not in seen:
            seen.add(lbl)
            result.append(lbl)
    return result


def render_issue_body(issue: dict, redmine_base_url: str) -> str:
    """Return a GitHub-Markdown body for a Redmine issue.

    Includes a metadata block, the original description verbatim, an optional
    Attachments section, a back-link to the Redmine issue, and the hidden
    idempotency marker ``<!-- redmine-id: {id} -->``.
    """
    issue_id: int = issue["id"]
    url = f"{redmine_base_url.rstrip('/')}/issues/{issue_id}"

    def _name(obj: object) -> str:
        if isinstance(obj, dict):
            return obj.get("name", "") or "—"
        return "—"

    def _field(obj: object, key: str = "name") -> str:
        if isinstance(obj, dict):
            v = obj.get(key, "")
            return str(v) if v else "—"
        return "—"

    tracker = _name(issue.get("tracker"))
    status = _name(issue.get("status"))
    priority = _name(issue.get("priority"))
    category = _name(issue.get("category"))
    author = _field(issue.get("author"))
    assignee = _field(issue.get("assigned_to"))
    created = _fmt_date(issue.get("created_on", ""))
    updated = _fmt_date(issue.get("updated_on", ""))

    description: str = (issue.get("description") or "").strip()

    lines: list[str] = [
        "| Field | Value |",
        "| --- | --- |",
        f"| Redmine ID | [{issue_id}]({url}) |",
        f"| Tracker | {tracker} |",
        f"| Status | {status} |",
        f"| Priority | {priority} |",
        f"| Category | {category} |",
        f"| Author | {author} |",
        f"| Assignee | {assignee} |",
        f"| Created | {created} |",
        f"| Updated | {updated} |",
        "",
        "---",
        "",
    ]

    if description:
        lines += [description, ""]

    # Attachments
    attachments: list[dict] = issue.get("attachments") or []
    if attachments:
        lines += ["**Attachments:**", ""]
        for att in attachments:
            fname: str = att.get("filename", "") or att.get("id", "attachment")
            content_url: str = att.get("content_url", "") or att.get("url", "")
            if content_url:
                lines.append(f"- [{fname}]({content_url})")
            else:
                lines.append(f"- {fname}")
        lines.append("")

    lines += [
        "---",
        "",
        f"*Migrated from [Redmine #{issue_id}]({url})*",
        "",
        f"<!-- redmine-id: {issue_id} -->",
    ]

    return "\n".join(lines)


def render_comment_body(journal: dict) -> str:
    """Return the GitHub comment body for a Redmine journal entry.

    Format: attribution header, the notes verbatim, and the hidden idempotency
    marker ``<!-- redmine-journal-id: {id} -->``.
    """
    journal_id: int = journal["id"]
    author: str = (journal.get("user") or {}).get("name", "") or "Unknown"
    created_on: str = _fmt_date(journal.get("created_on", ""))
    notes: str = (journal.get("notes") or "").strip()

    return "\n".join(
        [
            f"**{author}** commented on Redmine — {created_on}",
            "",
            notes,
            "",
            f"<!-- redmine-journal-id: {journal_id} -->",
        ]
    )


def parse_redmine_id(issue_body: str) -> int | None:
    """Extract the Redmine issue ID from a GH issue body marker.

    Returns the integer id, or None if the marker is absent or malformed.
    """
    m = re.search(r"<!--\s*redmine-id:\s*(\d+)\s*-->", issue_body)
    if m:
        return int(m.group(1))
    return None


def parse_posted_journal_ids(comment_bodies: Iterable[str]) -> set[int]:
    """Return the set of Redmine journal IDs already posted as GH comments.

    Scans each comment body for ``<!-- redmine-journal-id: N -->`` markers.
    """
    ids: set[int] = set()
    for body in comment_bodies:
        for m in re.finditer(r"<!--\s*redmine-journal-id:\s*(\d+)\s*-->", body):
            ids.add(int(m.group(1)))
    return ids


def parse_issue_ids(raw: str) -> list[int]:
    """Parse a comma/space-separated list of Redmine issue IDs into ints.

    Tolerates commas, spaces, and newlines as separators; ignores blank tokens;
    drops non-numeric tokens. Duplicates are removed while preserving first-seen
    order (so the migration processes them in the order given).
    """
    ids: list[int] = []
    seen: set[int] = set()
    for tok in re.split(r"[,\s]+", raw.strip()):
        if not tok or not tok.isdigit():
            continue
        n = int(tok)
        if n not in seen:
            seen.add(n)
            ids.append(n)
    return ids


def note_journals(journals: list[dict]) -> list[dict]:
    """Return journals that carry a non-empty note, in chronological order.

    Attribute-only journals (empty ``notes`` field) are dropped.
    """
    noted = [j for j in journals if (j.get("notes") or "").strip()]
    return sorted(noted, key=lambda j: (j.get("created_on") or "", j["id"]))


def missing_journals(journals: list[dict], posted_ids: set[int]) -> list[dict]:
    """Return note-journals whose id is not in ``posted_ids``, chronologically.

    This is the comment-level idempotency core: given all note-journals for a
    Redmine issue and the set of journal IDs already posted to GitHub, return
    only the ones that still need to be created.
    """
    noted = note_journals(journals)
    return [j for j in noted if j["id"] not in posted_ids]


def issue_updated_after(issue: dict, cutoff: date) -> bool:
    """Return True if the Redmine issue's ``updated_on`` is strictly after ``cutoff``."""
    raw: str = issue.get("updated_on", "") or ""
    if not raw:
        return False
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.date() > cutoff
    except ValueError:
        return False


def _fmt_date(raw: str) -> str:
    """Format a Redmine ISO datetime string to a short ``YYYY-MM-DD`` date.

    Returns the raw string unchanged if it cannot be parsed.
    """
    if not raw:
        return "—"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return raw


# ── HTTP layer ─────────────────────────────────────────────────────────────────


class _HTTPError(Exception):
    """Raised when an HTTP request returns an unexpected status code."""

    def __init__(self, status: int, url: str, body: str) -> None:
        super().__init__(f"HTTP {status} for {url}")
        self.status = status
        self.url = url
        self.body = body


def _http_json(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> dict:
    """Make a JSON HTTP request and return parsed response body.

    Retries on GitHub secondary-rate-limit (403/429 with Retry-After) up to
    ``_GH_RATE_RETRIES`` times.  Raises ``_HTTPError`` on non-2xx after retries.
    """
    all_headers = {
        "User-Agent": _UA,
        "Accept": "application/json",
        **headers,
    }
    if body is not None:
        all_headers["Content-Type"] = "application/json"

    last_exc: Exception | None = None
    for attempt in range(_GH_RATE_RETRIES + 1):
        req = urllib.request.Request(url, method=method, headers=all_headers, data=body)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_body = exc.read().decode("utf-8", errors="replace")
            # Retry ONLY on a genuine rate-limit signal: any 429, or a GitHub 403
            # that carries Retry-After (its secondary-rate-limit shape). A Redmine
            # auth/permission 403 has no Retry-After and must fail fast, not sleep.
            retry_after_hdr = exc.headers.get("Retry-After")
            is_github = url.startswith(_GH_API_BASE)
            rate_limited = status == 429 or (status == 403 and is_github and retry_after_hdr is not None)
            if rate_limited and attempt < _GH_RATE_RETRIES:
                retry_after = int(retry_after_hdr) if retry_after_hdr else 60
                logging.warning(
                    "Rate limit on %s (HTTP %s); waiting %s s (attempt %s/%s)",
                    url,
                    status,
                    retry_after,
                    attempt + 1,
                    _GH_RATE_RETRIES,
                )
                time.sleep(retry_after)
                last_exc = exc
                continue
            raise _HTTPError(status, url, resp_body) from exc
        except urllib.error.URLError as exc:
            raise _HTTPError(0, url, str(exc)) from exc
        finally:
            if attempt == 0 and sleep_seconds > 0:
                time.sleep(sleep_seconds)

    assert last_exc is not None
    raise _HTTPError(0, url, f"Exhausted retries: {last_exc}") from last_exc


# ── Redmine API ────────────────────────────────────────────────────────────────


def fetch_open_issue_ids(
    redmine_base_url: str,
    api_key: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> list[int]:
    """Return all open pfBlockerNG Redmine issue IDs (paginated)."""
    headers = {"X-Redmine-API-Key": api_key}
    ids: list[int] = []
    limit = 100
    offset = 0

    while True:
        url = (
            f"{redmine_base_url.rstrip('/')}/issues.json"
            f"?project_id={_REDMINE_PROJECT}"
            f"&category_id={_REDMINE_CATEGORY_ID}"
            f"&status_id=o"
            f"&limit={limit}"
            f"&offset={offset}"
        )
        data = _http_json("GET", url, headers, sleep_seconds=sleep_seconds)
        issues: list[dict] = data.get("issues") or []
        for iss in issues:
            ids.append(iss["id"])

        total_count: int = data.get("total_count", 0)
        offset += len(issues)
        if not issues or offset >= total_count:
            break

    return ids


def fetch_issue_detail(
    issue_id: int,
    redmine_base_url: str,
    api_key: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> dict:
    """Return the full Redmine issue dict including journals and attachments."""
    url = f"{redmine_base_url.rstrip('/')}/issues/{issue_id}.json?include=journals,attachments"
    data = _http_json("GET", url, {"X-Redmine-API-Key": api_key}, sleep_seconds=sleep_seconds)
    return data.get("issue") or {}


# ── GitHub REST API ────────────────────────────────────────────────────────────


def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _GH_API_VERSION,
    }


def ensure_label(
    name: str,
    color: str,
    description: str,
    owner_repo: str,
    token: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> None:
    """Create a GitHub label if it does not already exist.

    A 422 "already exists" response is silently accepted.
    """
    url = f"{_GH_API_BASE}/repos/{owner_repo}/labels"
    body = json.dumps({"name": name, "color": color, "description": description}).encode()
    try:
        _http_json("POST", url, _gh_headers(token), body=body, sleep_seconds=sleep_seconds)
        logging.debug("Created label %r", name)
    except _HTTPError as exc:
        if exc.status == 422:
            logging.debug("Label %r already exists", name)
        else:
            logging.warning("Could not create label %r: %s", name, exc)


def list_imported_issues(
    owner_repo: str,
    token: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> dict[int, int]:
    """Return a mapping of Redmine issue ID → GitHub issue number.

    Fetches all GH issues labelled ``redmine-imported`` (all states) and parses
    the ``<!-- redmine-id: N -->`` marker from each body.
    """
    mapping: dict[int, int] = {}
    page = 1
    while True:
        url = f"{_GH_API_BASE}/repos/{owner_repo}/issues?labels=redmine-imported&state=all&per_page=100&page={page}"
        issues: list[dict] = _http_json("GET", url, _gh_headers(token), sleep_seconds=sleep_seconds)  # type: ignore[assignment]
        if not isinstance(issues, list) or not issues:
            break
        for iss in issues:
            body: str = iss.get("body") or ""
            rid = parse_redmine_id(body)
            if rid is not None:
                mapping[rid] = iss["number"]
        page += 1

    return mapping


def create_issue(
    title: str,
    body: str,
    labels: list[str],
    owner_repo: str,
    token: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> int:
    """Create a GitHub issue and return its number."""
    url = f"{_GH_API_BASE}/repos/{owner_repo}/issues"
    payload = json.dumps({"title": title, "body": body, "labels": labels}).encode()
    result = _http_json("POST", url, _gh_headers(token), body=payload, sleep_seconds=sleep_seconds)
    return int(result["number"])


def list_issue_comments(
    issue_number: int,
    owner_repo: str,
    token: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
    author: str | None = None,
) -> list[str]:
    """Return comment bodies for a GitHub issue (all pages).

    When ``author`` is set, only comments written by that login are returned —
    so the journal-id markers are read solely from THIS tool's own comments. A
    marker forged in an unrelated user's comment can never make the migration
    skip a real Redmine journal.
    """
    bodies: list[str] = []
    page = 1
    while True:
        url = f"{_GH_API_BASE}/repos/{owner_repo}/issues/{issue_number}/comments?per_page=100&page={page}"
        comments: list[dict] = _http_json("GET", url, _gh_headers(token), sleep_seconds=sleep_seconds)  # type: ignore[assignment]
        if not isinstance(comments, list) or not comments:
            break
        for c in comments:
            if author is not None and (c.get("user") or {}).get("login") != author:
                continue
            bodies.append(c.get("body") or "")
        page += 1

    return bodies


def create_comment(
    issue_number: int,
    body: str,
    owner_repo: str,
    token: str,
    sleep_seconds: float = _DEFAULT_SLEEP,
) -> None:
    """Post a comment on a GitHub issue."""
    url = f"{_GH_API_BASE}/repos/{owner_repo}/issues/{issue_number}/comments"
    payload = json.dumps({"body": body}).encode()
    _http_json("POST", url, _gh_headers(token), body=payload, sleep_seconds=sleep_seconds)


# ── Main ───────────────────────────────────────────────────────────────────────


class _Stats(NamedTuple):
    created: int
    updated: int
    skipped: int
    failed: int


def _run_migration(
    *,
    redmine_base_url: str,
    redmine_api_key: str,
    github_token: str,
    owner_repo: str,
    dry_run: bool,
    limit: int | None,
    updated_after: date | None,
    single_issue_id: int | None,
    explicit_ids: list[int] | None,
    sleep_seconds: float,
    migration_author: str,
) -> _Stats:
    """Core migration loop.  Returns final counts."""
    created = updated = skipped = failed = 0

    # Pre-create known labels so they have nice metadata.
    if not dry_run:
        for label_name, (color, desc) in _LABEL_META.items():
            ensure_label(label_name, color, desc, owner_repo, github_token, sleep_seconds)

    # Discover which Redmine issues are already on GitHub.
    if dry_run:
        logging.info("[dry-run] Skipping GH issue scan (no writes)")
        redmine_to_gh: dict[int, int] = {}
    else:
        logging.info("Scanning existing imported issues on GitHub…")
        redmine_to_gh = list_imported_issues(owner_repo, github_token, sleep_seconds)
        logging.info("Found %d already-imported issues", len(redmine_to_gh))

    # Collect Redmine issue IDs to process. An explicit ID list (--issue-ids) takes
    # precedence and skips the open-issue fetch entirely; then a single --issue; else
    # the full open-issue list.
    if explicit_ids is not None:
        issue_ids: list[int] = list(explicit_ids)
        logging.info("Processing %d explicitly-listed Redmine issue(s)", len(issue_ids))
    elif single_issue_id is not None:
        issue_ids = [single_issue_id]
    else:
        logging.info("Fetching open Redmine issue list…")
        issue_ids = fetch_open_issue_ids(redmine_base_url, redmine_api_key, sleep_seconds)
        logging.info("Found %d open Redmine issues", len(issue_ids))

    if limit is not None:
        issue_ids = issue_ids[:limit]
        logging.info("Processing %d issues (limited)", len(issue_ids))

    for issue_id in issue_ids:
        try:
            outcome = _process_issue(
                issue_id=issue_id,
                redmine_base_url=redmine_base_url,
                redmine_api_key=redmine_api_key,
                github_token=github_token,
                owner_repo=owner_repo,
                dry_run=dry_run,
                updated_after=updated_after,
                redmine_to_gh=redmine_to_gh,
                sleep_seconds=sleep_seconds,
                migration_author=migration_author,
            )
        except Exception as exc:  # noqa: BLE001
            logging.error("Failed to process Redmine issue #%d: %s", issue_id, exc)
            failed += 1
            continue

        # Tally the per-issue outcome so the final summary is accurate.
        if outcome == "created":
            created += 1
        elif outcome == "updated":
            updated += 1
        else:
            skipped += 1

    return _Stats(created=created, updated=updated, skipped=skipped, failed=failed)


def _process_issue(
    *,
    issue_id: int,
    redmine_base_url: str,
    redmine_api_key: str,
    github_token: str,
    owner_repo: str,
    dry_run: bool,
    updated_after: date | None,
    redmine_to_gh: dict[int, int],
    sleep_seconds: float,
    migration_author: str,
) -> str:
    """Migrate one Redmine issue.  Returns 'created', 'updated', or 'skipped'."""
    logging.info("Fetching Redmine issue #%d…", issue_id)
    issue = fetch_issue_detail(issue_id, redmine_base_url, redmine_api_key, sleep_seconds)
    if not issue:
        logging.warning("Redmine issue #%d returned empty — skipping", issue_id)
        return "skipped"

    if updated_after is not None and not issue_updated_after(issue, updated_after):
        logging.info("Redmine #%d: not updated after %s — skipping", issue_id, updated_after)
        return "skipped"

    title = f"[Redmine #{issue_id}] {issue.get('subject', '(no subject)')}"
    body = render_issue_body(issue, redmine_base_url)
    labels = map_labels(issue)
    journals: list[dict] = issue.get("journals") or []

    # --- Ensure the GH issue exists ---
    if issue_id in redmine_to_gh:
        gh_number = redmine_to_gh[issue_id]
        outcome = "updated"
        logging.info("Redmine #%d → existing GH issue #%d", issue_id, gh_number)
    else:
        if dry_run:
            logging.info("[dry-run] WOULD create GH issue: %r  labels=%s", title, labels)
            # Simulate a gh number for comment dry-run logging.
            gh_number = 0
            outcome = "created"
        else:
            gh_number = create_issue(title, body, labels, owner_repo, github_token, sleep_seconds)
            redmine_to_gh[issue_id] = gh_number
            logging.info("Created GH issue #%d for Redmine #%d", gh_number, issue_id)
            outcome = "created"

    # --- Fill in missing comments ---
    if dry_run:
        pending = missing_journals(journals, set())
        if pending:
            logging.info(
                "[dry-run] WOULD post %d comment(s) on GH #%d for Redmine #%d",
                len(pending),
                gh_number,
                issue_id,
            )
        else:
            logging.info("[dry-run] No comments to post for Redmine #%d", issue_id)
        return outcome

    existing_bodies = list_issue_comments(gh_number, owner_repo, github_token, sleep_seconds, author=migration_author)
    posted_ids = parse_posted_journal_ids(existing_bodies)
    pending = missing_journals(journals, posted_ids)

    if not pending:
        logging.info("GH #%d: all comments up to date (Redmine #%d)", gh_number, issue_id)
    else:
        logging.info(
            "GH #%d: posting %d missing comment(s) for Redmine #%d",
            gh_number,
            len(pending),
            issue_id,
        )
        for journal in pending:
            comment_body = render_comment_body(journal)
            create_comment(gh_number, comment_body, owner_repo, github_token, sleep_seconds)
            logging.debug("Posted journal #%d on GH #%d", journal["id"], gh_number)

    return outcome


def main() -> None:
    """CLI entry point."""
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what WOULD happen but make no writes to GitHub or Redmine.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Cap the number of Redmine issues processed.",
    )
    ap.add_argument(
        "--updated-after",
        metavar="YYYY-MM-DD",
        help="Only process issues updated after this date (exclusive).",
    )
    ap.add_argument(
        "--issue",
        type=int,
        metavar="ID",
        dest="issue_id",
        help="Migrate a single Redmine issue by ID (for testing).",
    )
    ap.add_argument(
        "--issue-ids",
        default="",
        metavar="IDS",
        help=(
            "Process ONLY this explicit, comma/space-separated list of Redmine issue IDs "
            "(skips fetching the open-issue list). Useful after triage to import a curated set."
        ),
    )
    ap.add_argument(
        "--redmine-base-url",
        default=_REDMINE_BASE_URL,
        help=f"Redmine base URL (default: {_REDMINE_BASE_URL})",
    )
    ap.add_argument(
        "--sleep",
        type=float,
        default=_DEFAULT_SLEEP,
        metavar="SECONDS",
        help=f"Pause between HTTP requests in seconds (default: {_DEFAULT_SLEEP})",
    )
    ap.add_argument(
        "--migration-author",
        default="github-actions[bot]",
        metavar="LOGIN",
        help=(
            "GitHub login this tool posts comments as — only its own comments are trusted "
            "for the already-migrated journal markers (default: github-actions[bot], the "
            "built-in GITHUB_TOKEN identity; set to your login when using a PAT)."
        ),
    )
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stderr,
    )

    # Resolve credentials from env.
    redmine_api_key = os.environ.get("REDMINE_API_KEY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    owner_repo = os.environ.get("GITHUB_REPOSITORY", "pfBlockerNG/pfBlockerNG")

    if not redmine_api_key:
        logging.error("REDMINE_API_KEY env var is not set — aborting")
        sys.exit(1)
    if not github_token and not args.dry_run:
        logging.error("GITHUB_TOKEN env var is not set — aborting (pass --dry-run for read-only mode)")
        sys.exit(1)

    updated_after: date | None = None
    if args.updated_after:
        try:
            updated_after = date.fromisoformat(args.updated_after)
        except ValueError:
            logging.error("Invalid --updated-after date %r (expected YYYY-MM-DD)", args.updated_after)
            sys.exit(1)

    if args.dry_run:
        logging.info("=== DRY-RUN MODE — no writes will be made ===")

    # An explicit --issue-ids that parses to nothing (only junk/separators) must NOT
    # silently fall through to migrating every open issue — fail loudly instead.
    explicit_ids: list[int] | None = None
    if args.issue_ids.strip():
        explicit_ids = parse_issue_ids(args.issue_ids)
        if not explicit_ids:
            logging.error("Invalid --issue-ids %r (expected at least one numeric ID)", args.issue_ids)
            sys.exit(1)

    try:
        stats = _run_migration(
            redmine_base_url=args.redmine_base_url,
            redmine_api_key=redmine_api_key,
            github_token=github_token,
            owner_repo=owner_repo,
            dry_run=args.dry_run,
            limit=args.limit,
            updated_after=updated_after,
            single_issue_id=args.issue_id,
            explicit_ids=explicit_ids,
            sleep_seconds=args.sleep,
            migration_author=args.migration_author,
        )
    except Exception as exc:  # noqa: BLE001
        logging.error("Fatal error: %s", exc)
        sys.exit(1)

    logging.info(
        "Done — created=%d updated=%d skipped=%d failed=%d",
        stats.created,
        stats.updated,
        stats.skipped,
        stats.failed,
    )
    if stats.failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
