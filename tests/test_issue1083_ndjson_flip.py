"""issue #1083 Phase 3 -- the NDJSON interchange FLIP, Python-side loader behaviour.

``_load_zone_db``/``_load_data_db`` now read schema-v1 NDJSON (pfblockerng.inc's
pfb_dnsbl_ndjson_emit_domain_row()/emit_abp_row() are the sole writers), not the
retired positional CSV. Pins: a domain row loads with attribution exactly as the
legacy CSV loader did; an 'abp' row is a legitimate self-describing line on the
TLD-disabled rename path (pfb_dnsbl.raw renamed verbatim to pfb_py_data.txt) and is
silently skipped WITHOUT the undecodable-line stderr diagnostic; a genuinely
undecodable line still hits the existing Failed-to-parse stderr path.
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

import pfb_unbound as P


def _write(tmp_path: Any, name: str, content: str) -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_load_zone_db_domain_row_loads_with_attribution(tmp_path: Any) -> None:
    P.pfb["pfb_py_zone"] = _write(
        tmp_path,
        "pfb_py_zone.txt",
        '{"kind":"domain","domain":"blocked.example","log":"1","feed":"FeedA","group":"GroupA"}\n',
    )
    feed_group_db: defaultdict[str, Any] = defaultdict(str)

    next_index = P._load_zone_db(feed_group_db, 0)

    assert next_index == 1
    assert dict(P.zoneDB) == {"blocked.example": {"log": "1", "index": 0, "important": False}}
    assert dict(P.feedGroupIndexDB) == {0: {"feed": "FeedA", "group": "GroupA"}}


def test_load_data_db_domain_row_loads_with_attribution(tmp_path: Any) -> None:
    P.pfb["pfb_py_data"] = _write(
        tmp_path,
        "pfb_py_data.txt",
        '{"kind":"domain","domain":"sub.blocked.example","log":"0","feed":"FeedB","group":"GroupB"}\n',
    )
    feed_group_db: defaultdict[str, Any] = defaultdict(str)

    next_index = P._load_data_db(feed_group_db, 0)

    assert next_index == 1
    assert dict(P.dataDB) == {"sub.blocked.example": {"log": "0", "index": 0, "important": False}}
    assert dict(P.feedGroupIndexDB) == {0: {"feed": "FeedB", "group": "GroupB"}}


def test_abp_row_skipped_without_stderr(tmp_path: Any, capsys: Any) -> None:
    """The TLD-disabled rename path (pfb_dnsbl.raw -> pfb_py_data.txt verbatim) can hand
    _load_data_db a legitimate 'abp' row -- it must be skipped silently, not treated as
    an undecodable line (no stderr), and it must claim no dataDB/feedGroupIndexDB entry."""
    P.pfb["pfb_py_data"] = _write(
        tmp_path,
        "pfb_py_data.txt",
        '{"kind":"abp","raw":"||ads.example^"}\n',
    )
    feed_group_db: defaultdict[str, Any] = defaultdict(str)

    next_index = P._load_data_db(feed_group_db, 0)

    assert next_index == 0
    assert dict(P.dataDB) == {}
    assert dict(P.feedGroupIndexDB) == {}
    assert capsys.readouterr().err == ""


def test_garbage_line_hits_failed_to_parse_path(tmp_path: Any, capsys: Any) -> None:
    """A genuinely undecodable line (not valid NDJSON) is NOT an 'abp' row -- it still
    hits the existing Failed-to-parse stderr diagnostic, and claims no DB entry."""
    path = _write(tmp_path, "pfb_py_zone.txt", "not,valid,ndjson,at,all\n")
    P.pfb["pfb_py_zone"] = path
    feed_group_db: defaultdict[str, Any] = defaultdict(str)

    next_index = P._load_zone_db(feed_group_db, 0)

    assert next_index == 0
    assert dict(P.zoneDB) == {}
    err = capsys.readouterr().err
    assert "Failed to parse" in err
    assert path in err


def test_recursion_error_line_is_skipped_not_fatal_to_the_rest_of_the_file(tmp_path: Any) -> None:
    """issue #1083 review: _load_data_db()'s try/except wraps the WHOLE per-line
    for-loop -- an uncaught RecursionError from one hostile deeply-nested line
    would abort every line after it in the file, unlike PHP's fixed-depth-cap
    json_decode() (skips just the one bad line). The domain BEFORE and the domain
    AFTER the hostile line must both still load."""
    depth = 300_000
    hostile = '{"kind":"domain","domain":' + "[" * depth + "]" * depth + ',"log":"1","feed":"f","group":"g"}'
    content = (
        '{"kind":"domain","domain":"before.example","log":"1","feed":"FeedA","group":"GroupA"}\n'
        + hostile
        + "\n"
        + '{"kind":"domain","domain":"after.example","log":"1","feed":"FeedA","group":"GroupA"}\n'
    )
    P.pfb["pfb_py_data"] = _write(tmp_path, "pfb_py_data.txt", content)
    feed_group_db: defaultdict[str, Any] = defaultdict(str)

    P._load_data_db(feed_group_db, 0)

    assert "before.example" in P.dataDB
    assert "after.example" in P.dataDB
