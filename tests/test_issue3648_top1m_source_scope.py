"""Scoped TOP1M filtering leaves Category, regex, CNAME-target and numeric blocking intact.

R8–R10 intentionally restore per-source filtering rather than a global allow: a
popular original name is not permission to bypass another source or CNAME target.
R11's exact/www versus deeper-child behavior is covered in both resolution modes
by test_a_ticked_wildcard_spares_only_the_top1m_names_under_it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P

DOMAIN = "cdn.shared.example"


def _row(feed: str, group: str, lines: str, *, checked: bool = False, user: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {"feed": feed, "group": group, "log_flag": "1", "lines": lines}
    if checked:
        row["top1m"] = True
    if user:
        row["provenance"] = "user"
    return row


def _load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feeds: list[dict[str, Any]], *, numeric: bool = False
) -> P.Snapshot:
    if numeric:
        feeds = [*feeds, _row("UnrelatedAllow", "DNSBL_Other", "@@||unrelated.example^\n")]
    rows = []
    for index, feed in enumerate(feeds):
        row = dict(feed)
        row["raw"] = f"{index}.raw"
        (tmp_path / row["raw"]).write_text(row.pop("lines"), encoding="utf-8")
        rows.append(row)
    manifest = tmp_path / "pfb_py_sources.json"
    manifest.write_text(json.dumps({"version": 1, "config": {"top1m_enabled": True}, "feeds": rows}), encoding="utf-8")
    (tmp_path / "pfb_py_top1m.txt").write_text(DOMAIN + "\n", encoding="utf-8")
    P.pfb["pfb_py_sources"] = str(manifest)
    P.pfb["pfb_unbound.ini"] = str(tmp_path / "absent.ini")
    P.pfb["python_blocking"] = True
    snap = P._build_swap_snapshot()
    assert snap is not None, "DNSBL generation must build"
    monkeypatch.setattr(P, "_snapshot", snap)
    return snap


@pytest.mark.parametrize("numeric", [False, True], ids=["fast", "numeric"])
def test_a_category_feed_without_top1m_opt_in_still_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, numeric: bool
) -> None:
    """R8: a synthesized Category source has no TOP1M opt-in; popularity cannot undo its category."""
    snap = _load(tmp_path, monkeypatch, [_row("Shalla_adv", "DNSBL_Shalla", DOMAIN + "\n")], numeric=numeric)
    assert snap.important_rules is numeric, f"expected numeric={numeric}"
    reply = P.dnsbl_query_answer(DOMAIN, "A")
    assert reply["blocked"] and reply["group"] == "DNSBL_Shalla", f"Category must block {DOMAIN}, got {reply}"


@pytest.mark.parametrize("checked", [False, True], ids=["unchecked", "checked"])
def test_irreducible_regex_still_blocks_a_top1m_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checked: bool
) -> None:
    """R9: TOP1M filters domain entries, not irreducible regex, regardless of the Group's box."""
    snap = _load(
        tmp_path,
        monkeypatch,
        [_row("RegexFeed", "DNSBL_RegexGroup", r"/^(?:cdn|ads)\.shared\.example$/" + "\n", checked=checked)],
    )
    assert snap.regex_db and not snap.data_db and not snap.zone_db, "fixture must take the irreducible-regex path"
    reply = P.dnsbl_query_answer(DOMAIN, "A")
    assert reply["blocked"], f"irreducible regex must block {DOMAIN}, got {reply}"


@pytest.mark.parametrize("numeric", [False, True], ids=["fast", "numeric"])
def test_a_top1m_original_name_does_not_exempt_its_blocked_cname_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, numeric: bool
) -> None:
    """R10: filtering the popular original name does not remove a different blocked target entry."""
    target = "tracker.other.example"
    snap = _load(
        tmp_path,
        monkeypatch,
        [_row("PhishFeed", "DNSBL_Phish", DOMAIN + "\n" + target + "\n", checked=True)],
        numeric=numeric,
    )
    assert snap.important_rules is numeric, f"expected numeric={numeric}"
    original = P.dnsbl_query_answer(DOMAIN, "A")
    assert not original["blocked"], f"the listed original name should be filtered, got {original}"
    decision = P.evaluate_domain(target, DOMAIN, "example", True, P._evaluate_cfg(snap), snap.containers())
    assert decision.is_found and not decision.in_whitelist, f"CNAME target must stay blocked, got {decision}"
    assert decision.group == "DNSBL_Phish", f"target block attribution must stay with its Group, got {decision}"


@pytest.mark.parametrize("unchecked_user_zone", [False, True], ids=["checked-zone-skipped", "unchecked-fallback-wins"])
def test_numeric_scanning_uses_only_the_zone_source_that_still_blocks_top1m(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unchecked_user_zone: bool
) -> None:
    """Discovery finds an unchecked band-1 exact block before scanning competing wildcard bands.

    A checked band-5 wildcard must disappear for the TOP1M name so permit band 2
    wins. Conversely, the unchecked band-5 fallback of a checked band-1 wildcard
    must remain and beat that permit. This discriminates numeric scanning from
    discovery: using the unfiltered stored payload gives the wrong verdict.
    """
    feeds = [_row("ExactFeed", "DNSBL_Exact", DOMAIN + "\n")]
    if unchecked_user_zone:
        feeds.append(_row("Ads_custom", "DNSBL_Ads", "||shared.example^\n", user=True))
        feeds.append(_row("PhishFeed", "DNSBL_Phish", "||shared.example^\n", checked=True))
    else:
        feeds.append(_row("Phish_custom", "DNSBL_Phish", "||shared.example^\n", checked=True, user=True))
    permit = _row("PermitFeed", "DNSBL_Permit", DOMAIN + "\n")
    permit["mode"] = "permit"
    feeds.append(permit)
    snap = _load(tmp_path, monkeypatch, feeds)
    assert snap.important_rules, "permit must engage numeric resolution"

    reply = P.dnsbl_query_answer(DOMAIN, "A")
    assert reply["blocked"] is unchecked_user_zone, f"wrong numeric TOP1M zone precedence: {reply}"
    if unchecked_user_zone:
        assert reply["group"] == "DNSBL_Ads", f"unchecked band-5 fallback must own the block, got {reply}"
