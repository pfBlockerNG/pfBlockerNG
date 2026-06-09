#!/usr/bin/env python3
"""
check-pfsense-versions.py — detect pfSense versions missing from the supported-
version matrix by scraping docs.netgate.com/pfsense/en/latest/releases/versions.html.

Usage:
  check-pfsense-versions.py [--html-file PATH] [--matrix-json JSON]
  printf '%s' "$BUILD_MATRIX" | check-pfsense-versions.py

Output (stdout): {"supported_missing": [...], "future": [...]}

  supported_missing — families that appear as still-supported on the Netgate page
                      but are absent from the BUILD matrix.
  future            — families whose only rows are TBD/unreleased.

Graceful: any fetch or parse failure → empty result + ::warning:: to stderr, exit 0.
Pure detection — no gh calls, no matrix writes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from collections import defaultdict
from html.parser import HTMLParser
from typing import NamedTuple

VERSIONS_URL = "https://docs.netgate.com/pfsense/en/latest/releases/versions.html"

_FETCH_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_EMPTY: dict[str, list[dict[str, str]]] = {"supported_missing": [], "future": []}


# ── Data types ─────────────────────────────────────────────────────────────────


class _Row(NamedTuple):
    version: str
    support: str  # "supported" | "eol" | "future"
    released: str
    freebsd_version: str
    freebsd_major: str
    channel: str  # "CE" | "Plus"
    normalized: str  # family key: "2.8.x" (CE) or "26.03" (Plus)


class _Family(NamedTuple):
    version: str
    channel: str
    status: str  # "supported" | "future" | "eol"
    freebsd_version: str
    freebsd_major: str
    released: str


# ── HTML parser ────────────────────────────────────────────────────────────────


class _TableParser(HTMLParser):
    """Extract all <table> elements as list-of-rows (each row = list of cell texts)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._depth = 0
        self._in_cell = False
        self._cur_table: list[list[str]] = []
        self._cur_row: list[str] = []
        self._cur_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "table":
            if self._depth == 0:
                self._cur_table = []
            self._depth += 1
        elif t == "tr" and self._depth == 1:
            self._cur_row = []
        elif t in ("td", "th") and self._depth == 1:
            self._in_cell = True
            self._cur_parts = []
        elif t == "img" and self._in_cell:
            alt = (dict(attrs).get("alt") or "").strip()
            if alt:
                self._cur_parts.append(alt)

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "table":
            self._depth -= 1
            if self._depth == 0:
                self.tables.append(self._cur_table)
                self._cur_table = []
        elif t == "tr" and self._depth == 1:
            if self._cur_row:
                self._cur_table.append(self._cur_row[:])
        elif t in ("td", "th") and self._depth == 1 and self._in_cell:
            self._cur_row.append(" ".join(self._cur_parts).strip())
            self._in_cell = False

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            s = data.strip()
            if s:
                self._cur_parts.append(s)


# ── Classification helpers ─────────────────────────────────────────────────────


def _support_from_cell(cell: str) -> str:
    """Map Support-column cell text to 'supported', 'eol', or 'future'.

    The cell text is the <img alt="…"> value from the Netgate docs table:
      fa-check → supported
      fa-times → eol
      fa-clock → future/TBD (unreleased)
    Anything else defaults to 'future' (conservative — don't report as missing).
    """
    low = cell.lower()
    if "fa-check" in low:
        return "supported"
    if "fa-times" in low:
        return "eol"
    return "future"


def _freebsd_major(raw: str) -> str:
    """'16.0-CURRENT@hash' or '15.0-RELEASE' → '16' / '15'."""
    m = re.match(r"(\d+)\.", raw.strip())
    return m.group(1) if m else ""


def _channel_from_branch(branch: str) -> str | None:
    """'plus-RELENG_*' → 'Plus', 'RELENG_*' → 'CE', else None."""
    bl = branch.strip().lower()
    if bl.startswith("plus-releng_"):
        return "Plus"
    if bl.startswith("releng_"):
        return "CE"
    return None


def _normalize(raw: str, channel: str) -> str:
    """Normalize a raw version string to its family key.

    CE  '2.8.1'    → '2.8.x'
    Plus '26.03.1' → '26.03'
    """
    parts = raw.strip().split(".")
    if channel == "CE" and len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}.x"
    if channel == "Plus" and len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return raw


# ── Table → _Row list ──────────────────────────────────────────────────────────


def parse_tables(tables: list[list[list[str]]]) -> list[_Row]:
    """Convert raw table data into typed _Row entries."""
    rows: list[_Row] = []
    for table in tables:
        if not table:
            continue
        header = table[0]
        col: dict[str, int] = {}
        for i, cell in enumerate(header):
            key = re.sub(r"\s+", " ", cell).strip().lower()
            if key == "version":
                col["version"] = i
            elif key == "support":
                col["support"] = i
            elif key == "released":
                col["released"] = i
            elif "freebsd" in key:
                col["freebsd"] = i
            elif key == "branch":
                col["branch"] = i

        if not {"version", "support", "freebsd", "branch"}.issubset(col):
            continue

        max_idx = max(col.values())
        for row in table[1:]:
            if len(row) <= max_idx:
                continue
            ver_raw = row[col["version"]].strip()
            branch_raw = row[col["branch"]].strip()
            if not ver_raw or not branch_raw:
                continue

            channel = _channel_from_branch(branch_raw)
            if channel is None:
                continue

            fbsd_raw = row[col["freebsd"]].strip()
            released = row[col["released"]].strip() if "released" in col else ""

            rows.append(
                _Row(
                    version=ver_raw,
                    support=_support_from_cell(row[col["support"]]),
                    released=released,
                    freebsd_version=fbsd_raw,
                    freebsd_major=_freebsd_major(fbsd_raw),
                    channel=channel,
                    normalized=_normalize(ver_raw, channel),
                )
            )
    return rows


# ── Family grouping ────────────────────────────────────────────────────────────


def group_families(rows: list[_Row]) -> list[_Family]:
    """Group rows by (normalized_version, channel) and classify each family."""
    groups: dict[tuple[str, str], list[_Row]] = defaultdict(list)
    for r in rows:
        groups[(r.normalized, r.channel)].append(r)

    result: list[_Family] = []
    for (normalized, channel), members in groups.items():
        supported = [r for r in members if r.support == "supported"]
        future = [r for r in members if r.support == "future"]

        if supported:
            status, ref = "supported", supported[0]
        elif future:
            status, ref = "future", future[0]
        else:
            status, ref = "eol", members[0]

        result.append(
            _Family(
                version=normalized,
                channel=channel,
                status=status,
                freebsd_version=ref.freebsd_version,
                freebsd_major=ref.freebsd_major,
                released=ref.released,
            )
        )
    return result


# ── Diff ──────────────────────────────────────────────────────────────────────


def diff(
    families: list[_Family],
    build_matrix: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    """Produce the output JSON dict from the families + matrix comparison."""
    in_matrix = {entry["pfsense_version"] for entry in build_matrix}

    supported_missing: list[dict[str, str]] = []
    future_list: list[dict[str, str]] = []

    for fam in sorted(families, key=lambda f: (f.channel, f.version)):
        if fam.status == "supported" and fam.version not in in_matrix:
            supported_missing.append(
                {
                    "version": fam.version,
                    "channel": fam.channel,
                    "freebsd_major": fam.freebsd_major,
                    "freebsd_version": fam.freebsd_version,
                }
            )
        elif fam.status == "future":
            future_list.append(
                {
                    "version": fam.version,
                    "channel": fam.channel,
                    "released": fam.released,
                    "freebsd_major": fam.freebsd_major,
                }
            )

    return {"supported_missing": supported_missing, "future": future_list}


# ── I/O helpers ───────────────────────────────────────────────────────────────


def _fetch(url: str) -> str | None:
    req = urllib.request.Request(url, headers=_FETCH_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::fetch {url} failed: {exc}", file=sys.stderr)
        return None


def _load_matrix(matrix_arg: str | None) -> list[dict[str, str]]:
    raw: str | None
    if matrix_arg is not None:
        raw = matrix_arg
    elif not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
        except Exception:
            return []
    else:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


# ── Entrypoint ────────────────────────────────────────────────────────────────


def run(html_src: str | None, matrix_arg: str | None) -> int:
    """Core logic; separated for testing. Returns exit code (always 0)."""
    if html_src is None:
        html_src = _fetch(VERSIONS_URL)
        if html_src is None:
            print(json.dumps(_EMPTY))
            return 0

    try:
        p = _TableParser()
        p.feed(html_src)
        rows = parse_tables(p.tables)
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::HTML parse error: {exc}", file=sys.stderr)
        print(json.dumps(_EMPTY))
        return 0

    if not rows:
        print(
            "::warning::no version rows extracted — page structure may have changed",
            file=sys.stderr,
        )
        print(json.dumps(_EMPTY))
        return 0

    families = group_families(rows)
    build_matrix = _load_matrix(matrix_arg)
    print(json.dumps(diff(families, build_matrix)))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--html-file", metavar="PATH", help="Read HTML from file instead of fetching URL")
    ap.add_argument("--matrix-json", metavar="JSON", help="BUILD matrix as a JSON string")
    args = ap.parse_args()

    html_src: str | None = None
    if args.html_file:
        try:
            with open(args.html_file) as fh:
                html_src = fh.read()
        except OSError as exc:
            print(f"::warning::cannot read {args.html_file}: {exc}", file=sys.stderr)
            print(json.dumps(_EMPTY))
            sys.exit(0)

    sys.exit(run(html_src, args.matrix_json))


if __name__ == "__main__":
    main()
