"""The user's wildcard whitelist remains sovereign when TOP1M no longer masks feed allows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pfb_unbound as P


@pytest.mark.parametrize("allow_kind", ["permit", "abp"])
@pytest.mark.parametrize("name", ["cdn.shared.example", "www.cdn.shared.example"])
def test_a_lower_band_allow_cannot_hide_the_user_wildcard_whitelist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, allow_kind: str, name: str
) -> None:
    """R5 with competing allows: adding a feed allow must not weaken the user's whitelist.

    Given an unchecked Group's Custom List blocks a TOP1M domain, and the user
    whitelists its parent with a wildcard, it resolves. Adding a lower-band DNSWL
    permit or ABP allow for the domain must leave the user's wildcard in effect,
    on both the exact and www-fallback lookup paths.
    """
    (tmp_path / "custom.raw").write_text("cdn.shared.example\nwww.cdn.shared.example\n", encoding="utf-8")
    (tmp_path / "allow.raw").write_text(
        "cdn.shared.example\n" if allow_kind == "permit" else "@@||cdn.shared.example^\n", encoding="utf-8"
    )
    (tmp_path / "pfb_py_top1m.txt").write_text("cdn.shared.example\n", encoding="utf-8")
    custom = {"raw": "custom.raw", "feed": "Ads_custom", "group": "DNSBL_Ads", "log_flag": "1", "provenance": "user"}
    allow = {"raw": "allow.raw", "feed": "SafeFeed", "group": "DNSBL_Safe", "log_flag": "1"}
    if allow_kind == "permit":
        allow["mode"] = "permit"
    manifest = {
        "version": 1,
        "config": {"top1m_enabled": True, "user_whitelist": [".shared.example"]},
        "feeds": [custom],
    }
    path = tmp_path / "pfb_py_sources.json"
    P.pfb["pfb_py_sources"] = str(path)
    P.pfb["pfb_unbound.ini"] = str(tmp_path / "absent.ini")
    P.pfb["python_blocking"] = True

    for feeds in ([custom], [custom, allow]):
        manifest["feeds"] = feeds
        path.write_text(json.dumps(manifest), encoding="utf-8")
        snap = P._build_swap_snapshot()
        assert snap is not None, "DNSBL generation must build"
        monkeypatch.setattr(P, "_snapshot", snap)
        reply = P.dnsbl_query_answer(name, "A")
        assert not reply["blocked"], f"user wildcard must allow {name} with {feeds!r}, got {reply!r}"
