#!/usr/bin/env python3
"""update_artifact_action_majors.py -- refresh ``_KNOWN_ARTIFACT_MAJORS``.

``tests/test_issue2231_workflow_hygiene.py`` freezes the published major tags of
``actions/upload-artifact`` and ``actions/download-artifact``. The live-pin gate
requires every ``uses:`` to exist upstream and sit at the highest major both
actions publish (issue #2725 / #2726). This script refreshes that table from
GitHub's git matching-refs API so a future upload-artifact v8 (or the next
common major) can be adopted without hand-editing the two frozensets.

Data source
-----------
https://api.github.com/repos/actions/{upload,download}-artifact/git/matching-refs/tags
-- JSON array of ``{ref, object, ...}``. HTML is refused; this script never
scrapes tag pages.

Extraction
----------
A tag contributes its major only when the ref is ``refs/tags/vN`` or
``refs/tags/vN.N.N`` (optional patch). Unprefixed tags (``1.0.0``) and suffix
variants (``v3-node20``) are ignored — they are not pin-able ``@vN`` refs.

Highest common is ``max(upload & download)``. A major that exists on only one
action must not raise the pin and must not silently allow a mismatched pair
(issue #2385 / #2728). An empty intersection is refused.

Output
------
Rewrites the ``_KNOWN_ARTIFACT_MAJORS`` assignment (and its Frozen comment) in
the hygiene test. The derived ``_HIGHEST_COMMON_ARTIFACT_MAJOR = max(...)``
line is left untouched. Churn guard: the Frozen date is rewritten only when
the parsed majors actually change.

Usage
-----
    python scripts/misc/update_artifact_action_majors.py           # rewrite in place
    python scripts/misc/update_artifact_action_majors.py --check   # exit 1 if stale

Dev-host tooling: run from the repo root on a dev box (never the appliance).
Optional ``GH_TOKEN`` / ``GITHUB_TOKEN`` raises the unauthenticated rate limit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

API_URL = "https://api.github.com/repos/actions/{kind}-artifact/git/matching-refs/tags"
KINDS = ("upload", "download")
DEFAULT_HYGIENE_FILE = Path(__file__).resolve().parent.parent.parent / "tests/test_issue2231_workflow_hygiene.py"

_TAG_REF = re.compile(r"^refs/tags/v(?P<major>[0-9]+)(?:\.[0-9]+){0,2}$")
_TABLE_RE = re.compile(
    r"# Frozen [^\n]*(?:\n# [^\n]*)*\n"
    r"_KNOWN_ARTIFACT_MAJORS: dict\[str, frozenset\[int\]\] = \{.*?\n\}",
    re.DOTALL,
)
_EXISTING_RE = re.compile(
    r'"upload": frozenset\(\{(?P<upload>[0-9, ]+)\}\),\s*'
    r'"download": frozenset\(\{(?P<download>[0-9, ]+)\}\),'
)


def parse_tag_refs(payload: object) -> frozenset[int]:
    """Return published ``@vN`` majors from a matching-refs JSON payload.

    Accepts a decoded list or a JSON string. HTML, a non-list, or an entry
    without a string ``ref`` is refused — never treated as an empty tag set.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            raise SystemExit("Refusing to rewrite: tag payload is not a JSON list") from None
    if not isinstance(payload, list):
        raise SystemExit("Refusing to rewrite: tag payload is not a JSON list")
    majors: set[int] = set()
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
            raise SystemExit("Refusing to rewrite: tag payload entry missing string 'ref'")
        match = _TAG_REF.fullmatch(item["ref"])
        if match is not None:
            majors.add(int(match.group("major")))
    return frozenset(majors)


def highest_common(majors: Mapping[str, frozenset[int]]) -> int:
    """Highest major both actions publish. Union is never used."""
    shared = majors["upload"] & majors["download"]
    if not shared:
        raise SystemExit("Refusing to rewrite: upload and download majors have an empty intersection")
    return max(shared)


def require_plausible(majors: Mapping[str, frozenset[int]]) -> None:
    """Refuse an empty per-action set (truncated/HTML-as-JSON must not wipe the table)."""
    for kind, values in majors.items():
        if not values:
            raise SystemExit(f"Refusing to rewrite: {kind}-artifact has no published majors")
    highest_common(majors)


def _frozenset_literal(values: frozenset[int]) -> str:
    return "frozenset({" + ", ".join(str(v) for v in sorted(values)) + "})"


def render_table(majors: Mapping[str, frozenset[int]], synced: str, highest: int) -> str:
    """Render the Frozen comment plus the ``_KNOWN_ARTIFACT_MAJORS`` assignment."""
    return (
        f"# Frozen {synced} from the GitHub API (issue #2728). Highest common is v{highest}.\n"
        "_KNOWN_ARTIFACT_MAJORS: dict[str, frozenset[int]] = {\n"
        f'    "upload": {_frozenset_literal(majors["upload"])},\n'
        f'    "download": {_frozenset_literal(majors["download"])},\n'
        "}\n"
    )


def replace_table(source: str, table_block: str) -> str:
    """Replace the Frozen comment + table assignment; leave the max(...) derivation."""
    if _TABLE_RE.search(source) is None:
        raise SystemExit("Refusing to rewrite: _KNOWN_ARTIFACT_MAJORS table not found")
    return _TABLE_RE.sub(table_block.rstrip(), source, count=1)


def existing_majors(source: str) -> dict[str, frozenset[int]] | None:
    match = _EXISTING_RE.search(source)
    if match is None:
        return None

    def _parse(group: str) -> frozenset[int]:
        return frozenset(int(part.strip()) for part in group.split(",") if part.strip())

    return {"upload": _parse(match.group("upload")), "download": _parse(match.group("download"))}


def fetch_tag_payload(kind: str, timeout: float = 15) -> Any:
    """GET matching-refs for one artifact action. JSON only; HTML is a hard fail."""
    url = API_URL.format(kind=kind)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "pfBlockerNG-update-artifact-action-majors",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 (fixed https host)
            raw = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SystemExit(f"Refusing to rewrite: failed to fetch {url}: {exc}") from None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Refusing to rewrite: fetched body is not JSON: {exc}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if _KNOWN_ARTIFACT_MAJORS is out of date vs a fresh fetch; changes nothing",
    )
    args = parser.parse_args(argv)
    target = DEFAULT_HYGIENE_FILE

    majors = {kind: parse_tag_refs(fetch_tag_payload(kind)) for kind in KINDS}
    require_plausible(majors)
    highest = highest_common(majors)

    old = target.read_text(encoding="utf-8")
    current = existing_majors(old)
    if current == majors:
        print(f"_KNOWN_ARTIFACT_MAJORS is up to date (highest common v{highest}).")
        return 0
    if args.check:
        print(
            f"_KNOWN_ARTIFACT_MAJORS is OUT OF DATE "
            f"(upload {sorted(majors['upload'])} download {sorted(majors['download'])}; "
            f"highest common v{highest})."
        )
        return 1

    synced = datetime.now(timezone.utc).date().isoformat()
    target.write_text(replace_table(old, render_table(majors, synced, highest)), encoding="utf-8")
    print(f"_KNOWN_ARTIFACT_MAJORS regenerated; highest common is v{highest}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
