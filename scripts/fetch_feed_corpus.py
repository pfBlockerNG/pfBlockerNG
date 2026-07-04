#!/usr/bin/env python3
"""Fetch the ADR-49 survey corpus: the first bytes of every catalogue feed.

Walks ``src/usr/local/www/pfblockerng/pfblockerng_feeds.json`` (every ``url``
entry, primaries and alternates), fetches the first SAMPLE_BYTES of each
reachable feed ONCE, and commits the result as an offline, mockable corpus
under ``tests/fixtures/feed_corpus/``:

- ``samples/<header>.bin`` — the raw first bytes as served (no transcoding);
- ``manifest.json`` — one record per catalogue URL: header, section, url,
  fetch timestamp, HTTP status, Content-Type, sample size/sha256, an
  ``archive`` flag (magic-byte sniff — gzip/zip/bz2/7z samples are not text
  feeds and are excluded from the text-sanity survey), and the error for
  unreachable feeds.

The corpus exists so the ADR-49 false-positive survey (``pfb_text_sanity()``
must return NULL for every real text feed) runs OFFLINE in PHPUnit — the live
catalogue is fetched exactly once, here, politely (sequential, one small
ranged read per URL, a short pause between requests — several feed sites
rate-limit downloads, per the maintainer's #581 guidance).

Dev-host tooling: run from the repo root on a dev box (never the appliance).
Re-run to refresh the corpus when the catalogue changes; commit the diff.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

FEEDS_JSON = Path("src/usr/local/www/pfblockerng/pfblockerng_feeds.json")
CORPUS_DIR = Path("tests/fixtures/feed_corpus")
SAMPLE_BYTES = 8192
TIMEOUT_S = 20
PAUSE_S = 0.3
USER_AGENT = "pfBlockerNG-feed-corpus/1.0 (+https://github.com/pfBlockerNG/pfBlockerNG; one-time test-fixture fetch)"

_ARCHIVE_MAGICS = (b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"7z\xbc\xaf\x27\x1c")


def _slug(header: str, taken: set[str]) -> str:
    # Dedup case-INSENSITIVELY: a case-insensitive filesystem (macOS APFS) maps
    # "EasyPrivacy.bin" and "Easyprivacy.bin" to one file, so two headers differing
    # only in case would clobber each other's sample here yet stay two records in the
    # manifest -- coherent on macOS, broken on case-sensitive Linux CI. Keying `taken`
    # on the lowercased slug forces distinct on-disk names on every filesystem.
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", header).strip("_") or "feed"
    slug = base
    n = 2
    while slug.lower() in taken:
        slug = f"{base}_{n}"
        n += 1
    taken.add(slug.lower())
    return slug


def _walk(node: object, section: str, out: list[dict[str, str]]) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("url"), str):
            out.append(
                {
                    "section": section,
                    "header": str(node.get("header") or node.get("feed") or "feed"),
                    "url": node["url"],
                }
            )
        for key, value in node.items():
            if key != "url":
                _walk(value, section, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, section, out)


def _fetch_sample(url: str) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Range": f"bytes=0-{SAMPLE_BYTES - 1}"},
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ctx) as resp:  # noqa: S310 - catalogue URLs are the SUT
        body = resp.read(SAMPLE_BYTES)
        return resp.status, resp.headers.get("Content-Type", ""), body


def main() -> int:
    catalogue = json.loads(FEEDS_JSON.read_text())
    entries: list[dict[str, str]] = []
    for section in ("ipv4", "ipv6", "dnsbl"):
        _walk(catalogue.get(section, {}), section, entries)

    samples_dir = CORPUS_DIR / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    taken: set[str] = set()
    records = []
    ok = failed = 0
    for i, entry in enumerate(entries, 1):
        slug = _slug(entry["header"], taken)
        record: dict[str, object] = {
            "header": entry["header"],
            "section": entry["section"],
            "url": entry["url"],
            "fetched_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        try:
            status, ctype, body = _fetch_sample(entry["url"])
            (samples_dir / f"{slug}.bin").write_bytes(body)
            record.update(
                {
                    "http_status": status,
                    "content_type": ctype,
                    "sample_file": f"samples/{slug}.bin",
                    "sample_bytes": len(body),
                    "sample_sha256": hashlib.sha256(body).hexdigest(),
                    "archive": body.startswith(_ARCHIVE_MAGICS),
                }
            )
            ok += 1
            print(f"[{i:3}/{len(entries)}] OK   {entry['url']} ({len(body)}B, {ctype or '?'})")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            failed += 1
            print(f"[{i:3}/{len(entries)}] FAIL {entry['url']} — {record['error']}")
        records.append(record)
        time.sleep(PAUSE_S)  # politeness pause between hosts; NOT concurrency sync

    records.sort(key=lambda r: (str(r["section"]), str(r["header"]), str(r["url"])))
    manifest = {
        "description": "ADR-49 survey corpus: first bytes of every pfblockerng_feeds.json url entry",
        "sample_bytes_cap": SAMPLE_BYTES,
        "generated_by": "scripts/fetch_feed_corpus.py",
        "feeds": records,
    }
    (CORPUS_DIR / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    print(f"\ncorpus: {ok} fetched, {failed} unreachable, manifest at {CORPUS_DIR / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
