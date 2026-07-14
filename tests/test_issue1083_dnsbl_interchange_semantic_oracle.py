"""issue #1083 Phase 1 -- format-independent DNSBL interchange semantic oracle.

The DNSBL interchange files (per-feed staging ``.txt``, ``pfb_dnsbl.raw``,
``pfb_py_data.txt``, ``pfb_py_zone.txt``) move from positional CSV to NDJSON in a
later phase. This module pins WHAT the pipeline means -- membership + feed/group/
log attribution -- independent of HOW it is encoded, so it must stay green,
unchanged, across that flip (a behaviour-PRESERVING oracle, CLAUDE.md Test
coverage #1's exception: no red proof required).

One remaining scenario, against
``tests/fixtures/dnsbl_corpus/tld/golden_pfb_py_loader_expected.json`` (hand-
transcribed from the golden CSVs/``feeds.json`` -- never computed from the same
bytes fed to the code under test):

B. The REAL ``build()`` over the ADR-62 corpus, asserting feed/group/log
   attribution for one representative domain per corpus feed -- membership
   itself is already pinned by ``test_adr62_byte_identity_corpus.py``/
   ``test_adr62_parity_oracle.py``; neither file asserts attribution, so this
   complements rather than duplicates them.

(Scenario A -- the legacy ``_load_zone_db``/``_load_data_db`` loaders over the
golden CSV files -- is RETIRED: ADR-65 removes those loaders entirely.)
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from typing import Any

import pfb_unbound as P

_CORPUS_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "dnsbl_corpus")
_TLD_DIR = os.path.join(_CORPUS_DIR, "tld")

# Matches _NAME_253 in test_adr62_byte_identity_corpus.py / test_adr62_parity_oracle.py
# -- the 253-char wire-cap boundary domain; not spelled out in the fixture (see its
# manifest_attribution._doc).
_NAME_253 = ".".join(["b" * 61] * 4) + "." + "b" * 5


def _load_expected() -> dict[str, Any]:
    with open(os.path.join(_TLD_DIR, "golden_pfb_py_loader_expected.json"), encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Scenario B: build() over the ADR-62 corpus -- feed/group/log attribution.
# --------------------------------------------------------------------------- #


def _load_feeds() -> list[dict[str, Any]]:
    with open(os.path.join(_CORPUS_DIR, "feeds.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _corpus_manifest() -> dict[str, Any]:
    feeds = []
    for f in _load_feeds():
        row = {
            "raw": f"{f['header']}.raw",
            "feed": f["header"],
            "group": f["group"],
            "provenance": f["provenance"],
            "log_flag": f["log"],
        }
        if "mode" in f:
            row["mode"] = f["mode"]
        feeds.append(row)
    return {"feeds": feeds}


def _corpus_line_reader() -> Callable[[str], Iterable[str]]:
    def reader(raw: str) -> list[str]:
        with open(os.path.join(_CORPUS_DIR, "raw", raw), encoding="utf-8") as fh:
            return fh.read().splitlines()

    return reader


def _run_corpus_build() -> P.BuildResult:
    config: dict[str, Any] = {
        "tld_wildcard_master": [],
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": [],
        "top1m_list": [],
    }
    return P.build(_corpus_manifest(), config, line_reader=_corpus_line_reader())


def _entry(result: P.BuildResult, domain: str) -> dict[str, Any] | None:
    return result.zone_db.get(domain) or result.data_db.get(domain) or result.white_db.get(domain)


def test_manifest_build_attribution_matches_golden_fixture() -> None:
    result = _run_corpus_build()
    expected = _load_expected()["manifest_attribution"]
    for header, row in expected.items():
        if header == "_doc":
            continue
        domain = row["domain"] if row["domain"] is not None else _NAME_253
        entry = _entry(result, domain)
        assert entry is not None, f"{header}: expected domain {domain!r} missing from every db"
        feed_group = result.feed_group_index_db[entry["index"]]
        assert feed_group == {"feed": row["feed"], "group": row["group"]}, (header, feed_group, row)
        if "log" in row:
            assert entry.get("log") == row["log"], (header, entry)
        else:
            assert "log" not in entry, f"{header}: expected no log attribution, found {entry.get('log')!r}"


def test_oversized_feed_claims_no_attribution_index() -> None:
    """#752 (KNOWN divergence): every oversized_feed line is wire-cap-rejected
    before index_for() runs, so it must claim NO feed_group_index_db entry."""
    result = _run_corpus_build()
    claimed_feeds = {fg["feed"] for fg in result.feed_group_index_db.values()}
    assert "oversized_feed" not in claimed_feeds
