#!/usr/bin/env python3
"""Turn CodeRabbit CLI --agent JSONL into a PR comment.

CLI findings have fileName + comment, not a line range. This posts a
summary comment (advisory). It never calls the PR-review bot.

Used by .github/workflows/coderabbit-cli.yml (workflow_dispatch only).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

HEADER = "CodeRabbit CLI review (separate hourly CLI budget; not a PR-review slot)"


def parse_events(raw: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            events.append(obj)
    return events


def findings_of(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if event.get("type") == "finding"]


def complete_of(events: list[dict[str, Any]]) -> dict[str, Any]:
    for event in reversed(events):
        if event.get("type") == "complete":
            return event
    return {}


def format_report(events: list[dict[str, Any]]) -> str:
    complete = complete_of(events)
    findings = findings_of(events)
    status = complete.get("status") or "unknown"
    count = complete.get("findings")
    if count is None:
        count = len(findings)
    lines = [
        HEADER,
        "",
        f"status: `{status}`  findings: {count}",
        "",
        "Findings are **file-level** (CLI JSONL has `fileName`, no line range).",
        "This job is `workflow_dispatch` only so it cannot walk the PR Fair Usage band by itself.",
        "",
    ]
    if status == "review_skipped":
        lines.append(complete.get("message") or "No changes detected.")
        lines.append("")
        return "\n".join(lines)
    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)
    for event in findings:
        severity = event.get("severity") or "info"
        path = event.get("fileName") or "(no file)"
        body = (event.get("comment") or event.get("codegenInstructions") or "").strip()
        lines.append(f"### `{path}` ({severity})")
        lines.append("")
        lines.append(body or "_no comment text_")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", help="path to CLI --agent JSONL (use - for stdin)")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--pr", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    raw = sys.stdin.read() if args.jsonl == "-" else open(args.jsonl, encoding="utf-8").read()
    text = format_report(parse_events(raw))
    if args.dry_run or not args.pr:
        sys.stdout.write(text)
        return 0
    if not args.repo:
        print("GITHUB_REPOSITORY / --repo required to post", file=sys.stderr)
        return 2
    subprocess.check_call(["gh", "pr", "comment", str(args.pr), "--repo", args.repo, "--body", text])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
