#!/usr/bin/env python3
"""reconcile-plan.py — decide the daily image-reconcile actions for one channel
(issue #1823). Pure text-in/JSON-out: the box facts (gathered by
scripts/box-facts.sh from booted smoke images) and the supported-version matrix
go in; a list of actions comes out. The workflow executes them:

  republish       — switch (optionally) + pfSense-upgrade + republish the family
                    tag (image-refresh.yml direct leg, from == family)
  publish_new     — first publish of a merged-but-unbuilt matrix entry (direct
                    leg, from = newest published stable family, to = family)
  matrix_pr_add   — propose a matrix entry for a repo branch whose family the
                    matrix does not carry (the ONLY human gate)
  matrix_pr_ga_flip — propose flipping a beta entry to active (final build seen)
  warn            — a rule matched but the plan lacks data to act; message only
  error           — the booted /etc/version belongs to a DIFFERENT family than
                    the image tag claims (issue #1857): the image is mislabeled,
                    none of that boot's facts drive any rule, and the workflow
                    surfaces the fact as a ::error:: annotation

Sources of truth, in order (owner decisions, 2026-07-28):
  1. `pfSense-upgrade -c` on the booted image's own configured branch — the
     second-source safety net: an available update fires `republish` even when
     branch parsing sees nothing new.
  2. `pfSense-repoc -p` branch list — drives every branch move: patches, betas,
     GA finals are ALL separate branches (probed live; `-c` is branch-scoped and
     never surfaces them).
The Netgate versions page is not consulted (retired with #1823).

Usage:
  reconcile-plan.py --channel CE|Plus --matrix-json JSON --published-json JSON \
      --boot FAMILY:FACTS_DIR [--boot FAMILY:FACTS_DIR ...]

  --matrix-json     the channel's entries from supported-versions.json (array)
  --published-json  {"<family>": true|false} — does the GHCR tag exist?
  --boot            one per booted image: FACTS_DIR holds etc-version,
                    repoc.txt, upgrade-check.txt (box-facts.sh output)

Output (stdout): {"actions": [...]} — deduped, deterministic order.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Chokepoint: branch names feed printf'd JSON, git branch names, and PR titles
# downstream — same rule the retired page scraper enforced. Underscores and a
# leading letter are legitimate (probed live: '26_03_1'; historical
# 'pfSense-plus-v26.07-DEVTEST'); shell/JSON metacharacters are not.
_BRANCH_NAME_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]*")
# The parenthesized version in a repoc description column, e.g.
# "Beta Version (26.07)" / "Current Stable Version (26.03.1)".
_DESC_VERSION_RE = re.compile(r"\(([0-9][0-9A-Za-z.-]*)\)\s*$")
# Non-final build markers in /etc/version or a branch description.
_PRERELEASE_RE = re.compile(r"BETA|ALPHA|RC|DEVEL", re.IGNORECASE)
# The pfSense-upgrade -c "update available" line, e.g.
# "26.07.b.20260727.1443 version of pfSense is available" (probed live).
_UPGRADE_AVAILABLE_RE = re.compile(r"version of pfSense is available", re.IGNORECASE)


def family_of(version: str) -> str:
    """Major.Minor family key: '26.03.1' → '26.03', '2.8.1-RELEASE' → '2.8'."""
    parts = version.strip().split("-")[0].split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version.strip()


def version_key(version: str) -> tuple[int, ...]:
    """Numeric sort key; non-numeric components count as 0."""
    key: list[int] = []
    for part in version.strip().split("-")[0].split("."):
        m = re.match(r"(\d+)", part)
        key.append(int(m.group(1)) if m else 0)
    return tuple(key)


def parse_repoc(text: str) -> list[dict[str, str]]:
    """Parse `pfSense-repoc -p` rows into {name, version, family, kind}.

    Row shape (probed live on CE 2.8.1 + Plus 26.03.1):
      26.07\t\tBeta Version (26.07)
      26_03_1 (release) (default)\t\tCurrent Stable Version (26.03.1)
    name = first column minus trailing "(...)" annotations; version = the
    parenthesized token at the END of the description; kind = beta when the
    description carries a pre-release marker. Rows that do not yield a valid
    version token are dropped (chokepoint).
    """
    branches: list[dict[str, str]] = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        raw_name, _, desc = line.partition("\t")
        name = re.sub(r"\s*\([^)]*\)", "", raw_name).strip()
        desc = desc.strip()
        m = _DESC_VERSION_RE.search(desc)
        if not m or not name or not _BRANCH_NAME_RE.fullmatch(name):
            continue
        version = m.group(1)
        branches.append(
            {
                "name": name,
                "version": version,
                "family": family_of(version),
                "kind": "beta" if _PRERELEASE_RE.search(desc) else "stable",
            }
        )
    return branches


def plan(
    channel: str,
    matrix: list[dict[str, Any]],
    published: dict[str, bool],
    boots: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Compute the action list. boots: [{family, etc_version, repoc, upgrade_check}]."""
    entries = [
        e
        for e in matrix
        if e.get("channel") == channel
        and (e.get("role") or "build") != "route-only"
        and (e.get("arch") or "amd64") == "amd64"
    ]
    matrix_families = {e["pfsense_version"] for e in entries}
    beta_families = {e["pfsense_version"] for e in entries if e.get("status") == "beta"}

    # One action per (type, family). A later duplicate carrying a branch wins
    # over a branchless one (a -c hit and a parsed newer branch are the same
    # move; the explicit switch is the superset).
    by_key: dict[tuple[str, str], dict[str, str]] = {}

    def add(action: dict[str, str]) -> None:
        key = (action["type"], action.get("family", ""))
        held = by_key.get(key)
        if held is None or (not held.get("branch") and action.get("branch")):
            by_key[key] = action

    all_branches: list[dict[str, str]] = []
    for boot in boots:
        family = boot["family"]
        booted_version = boot.get("etc_version", "").strip()

        # Rule: the booted /etc/version must belong to the family its image tag
        # claims (issue #1857 — a 26.07-tagged image booted 26.03.1-RELEASE and
        # flipped the beta entry to GA). A mismatch means the published image is
        # mislabeled: surface it loudly and quarantine ALL of this boot's facts.
        # An EMPTY etc-version stays a degraded fact (issue #1848), not a mismatch.
        if booted_version and family_of(booted_version) != family:
            add(
                {
                    "type": "error",
                    "family": family,
                    "message": f"booted /etc/version {booted_version} is family "
                    f"{family_of(booted_version)}, not {family} — mislabeled image; "
                    "ignoring this boot's facts",
                }
            )
            continue

        branches = parse_repoc(boot.get("repoc", ""))
        all_branches.extend(branches)

        # Rule: -c second source — an update on the image's OWN branch always
        # fires a republish, independent of branch parsing.
        if _UPGRADE_AVAILABLE_RE.search(boot.get("upgrade_check", "")):
            add({"type": "republish", "family": family, "branch": "", "reason": "upgrade-check"})

        for br in branches:
            if (
                booted_version  # CR5: an unestablished box version compares as (0,) — never act on it
                and br["family"] == family
                and br["kind"] == "stable"
                and version_key(br["version"]) > version_key(booted_version)
            ):
                # Newer patch (or the GA final of this very family) on a new
                # pinned branch — probed live: patches are branch switches.
                add({"type": "republish", "family": family, "branch": br["name"], "reason": "newer-branch"})

        # Rule: a booted beta image reporting a FINAL build → GA status flip.
        if family in beta_families and booted_version and not _PRERELEASE_RE.search(booted_version):
            add({"type": "matrix_pr_ga_flip", "family": family})

    # Branch-driven rules over the union of everything any booted box reported.
    for br in all_branches:
        if br["family"] not in matrix_families:
            # New family (beta or an untracked GA) → the human gate.
            add(
                {
                    "type": "matrix_pr_add",
                    "family": br["family"],
                    "branch": br["name"],
                    "status": "beta" if br["kind"] == "beta" else "active",
                }
            )
        elif br["family"] in beta_families and br["kind"] == "stable":
            # GA final published as a stable branch while the matrix still says
            # beta: flip the status, and refresh the beta image ONLY when its
            # tag exists (an unpublished entry is publish_new's job — a
            # republish leg against a nonexistent tag is a dead dispatch).
            if published.get(br["family"], False):
                add({"type": "republish", "family": br["family"], "branch": br["name"], "reason": "ga-final"})
            add({"type": "matrix_pr_ga_flip", "family": br["family"]})

    # Rule: merged matrix entry with no published tag → first build.
    published_stable = [
        e["pfsense_version"]
        for e in entries
        if e.get("status") != "beta" and published.get(e["pfsense_version"], False)
    ]
    newest_published = max(published_stable, key=version_key, default="")
    for entry in entries:
        fam = entry["pfsense_version"]
        if published.get(fam, False):
            continue
        # Prefer the STABLE branch for the first build — after GA a leftover
        # beta branch may still be listed first (live repoc orders betas first).
        branch = next((b["name"] for b in all_branches if b["family"] == fam and b["kind"] == "stable"), "") or next(
            (b["name"] for b in all_branches if b["family"] == fam), ""
        )
        if not branch:
            add({"type": "warn", "family": fam, "message": "no repo branch found for unpublished matrix entry"})
            continue
        if not newest_published:
            add({"type": "warn", "family": fam, "message": "no published stable image to build from"})
            continue
        add({"type": "publish_new", "family": fam, "branch": branch, "from": newest_published})

    return list(by_key.values())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--channel", required=True)
    ap.add_argument("--matrix-json", required=True)
    ap.add_argument("--published-json", required=True)
    ap.add_argument("--boot", action="append", default=[], metavar="FAMILY:FACTS_DIR")
    args = ap.parse_args()

    boots: list[dict[str, str]] = []
    for spec in args.boot:
        fam, _, facts_dir = spec.partition(":")
        d = Path(facts_dir)
        boots.append(
            {
                "family": fam,
                "etc_version": (d / "etc-version").read_text(encoding="utf-8", errors="replace").strip()
                if (d / "etc-version").exists()
                else "",
                "repoc": (d / "repoc.txt").read_text(encoding="utf-8", errors="replace")
                if (d / "repoc.txt").exists()
                else "",
                "upgrade_check": (d / "upgrade-check.txt").read_text(encoding="utf-8", errors="replace")
                if (d / "upgrade-check.txt").exists()
                else "",
            }
        )

    try:
        matrix = json.loads(args.matrix_json)
        published = json.loads(args.published_json)
    except json.JSONDecodeError as exc:
        print(f"::error::reconcile-plan: bad JSON input: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps({"actions": plan(args.channel, matrix, published, boots)}))


if __name__ == "__main__":
    main()
