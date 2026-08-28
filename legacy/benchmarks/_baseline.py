"""Frozen pre-ADR dict-walk matchers — the baseline for the benchmarks.

These are verbatim reproductions of the flat-dict matchers that drove
``operate()`` before ADR-01 (``find_zone_match`` / ``whitelist_check_domain`` /
``find_noaaaa_wildcard_parent`` and the inline data/hsts walks). They are kept
here, isolated, purely so the trie can be benchmarked against the structure it
replaced. Do not "improve" them — they must stay byte-for-byte equivalent to the
historical behavior to make the comparison meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def find_zone_match(q_name: str, zone_db: dict[str, Any]) -> tuple[str, Any] | tuple[None, None]:
    q = q_name
    for _ in range(q.count(".") + 1, 0, -1):
        entry = zone_db.get(q)
        if entry is not None:
            return q, entry
        q = q.split(".", 1)[-1]
    return None, None


def whitelist_check_domain(name: str, white_db: dict[str, Any], tld_seg: int) -> bool:
    if white_db.get(name) is not None:
        return True
    if name.startswith("www.") and white_db.get(name[4:]) is not None:
        return True
    q = name.split(".", 1)[-1]
    for x in range(q.count(".") + 1, 0, -1):
        if x >= tld_seg and white_db.get(q):
            return True
        q = q.split(".", 1)[-1]
    return False


def find_noaaaa_wildcard_parent(q_name: str, noaaaa_db: dict[str, Any]) -> str | None:
    q = q_name.split(".", 1)[-1]
    for _ in range(q.count("."), 0, -1):
        if noaaaa_db.get(q):
            return q
        q = q.split(".", 1)[-1]
    return None


def hsts_check_domain(name: str, hsts_db: dict[str, Any], hsts_tlds: tuple[str, ...], tld: str) -> tuple[bool, str]:
    if tld in hsts_tlds:
        return True, "HSTS_TLD"
    q = name
    for _ in range(q.count(".") + 1, 0, -2):
        if hsts_db.get(q) is not None:
            return True, "HSTS"
        q = q.split(".", 1)[-1]
    return False, "Python"


def evaluate_noaaaa_dict(q_name: str, noaaaa_db: dict[str, Any]) -> bool:
    if noaaaa_db.get(q_name) is not None:
        return True
    return find_noaaaa_wildcard_parent(q_name, noaaaa_db) is not None


@dataclass
class MatchResult:
    """The structural portion of operate()'s DNSBL decision (data/zone/white/hsts).

    Excludes tld-allow / idn / regex, which are not data-structure work and are
    identical on both sides.
    """

    is_found: bool
    b_type: str
    b_eval: str
    in_whitelist: bool
    in_hsts: bool


def decide_dict(
    q_name: str,
    tld: str,
    dbs: dict,
    tld_seg: int,
    hsts_tlds: tuple[str, ...],
) -> MatchResult:
    """Reproduce operate()'s dict-based match sequence for one query."""
    is_found = False
    b_type = "Python"
    b_eval = ""
    in_white = False
    in_hsts = False

    entry = dbs["dataDB"].get(q_name)
    if entry is not None:
        is_found = True
        b_type = "DNSBL"
        b_eval = q_name
    if not is_found:
        matched_q, zone_entry = find_zone_match(q_name, dbs["zoneDB"])
        if matched_q is not None:
            is_found = True
            b_type = "TLD"
            b_eval = matched_q

    if is_found:
        in_white = whitelist_check_domain(q_name, dbs["whiteDB"], tld_seg)
    if is_found and not in_white:
        in_hsts, _ = hsts_check_domain(q_name, dbs["hstsDB"], hsts_tlds, tld)

    return MatchResult(is_found, b_type, b_eval, in_white, in_hsts)
