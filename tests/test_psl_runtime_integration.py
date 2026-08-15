"""Issue #1541 Step 2: runtime PSL authority, classification, and snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P

PSL = """// ===BEGIN ICANN DOMAINS===
com
io
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""


def _manifest(path: Path) -> Path:
    raw = path / "feed.raw"
    raw.write_text("example.com\n", encoding="utf-8")
    manifest = path / "pfb_py_sources.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "feeds": [{"raw": raw.name, "feed": "feed", "group": "group", "log_flag": "1"}],
                "config": {"tld_wildcard_blacklist": [], "tld_wildcard_exclusion": []},
            }
        ),
        encoding="utf-8",
    )
    return manifest


def test_psl_classifier_uses_arbitrary_depth_and_private_policy() -> None:
    rules = P.parse_psl_rules(PSL)

    assert P.tld_wildcard_classify("com", rules, set()) == (P.DNSBL_CLASS_DATA, "com")
    assert P.tld_wildcard_classify("example.com", rules, set()) == (P.DNSBL_CLASS_ZONE, "example.com")
    assert P.tld_wildcard_classify("a.b.example.com", rules, set()) == (P.DNSBL_CLASS_DATA, "a.b.example.com")
    assert P.tld_wildcard_classify("example.github.io", rules, set()) == (P.DNSBL_CLASS_ZONE, "example.github.io")
    assert P.tld_wildcard_classify("example.github.io", rules, set(), include_private=False) == (
        P.DNSBL_CLASS_DATA,
        "example.github.io",
    )
    assert P.tld_wildcard_classify("a.b.example.github.io", rules, set()) == (
        P.DNSBL_CLASS_DATA,
        "a.b.example.github.io",
    )
    assert P.tld_wildcard_classify("foo.ck", rules, set()) == (P.DNSBL_CLASS_DATA, "foo.ck")
    assert P.tld_wildcard_classify("www.ck", rules, set()) == (P.DNSBL_CLASS_ZONE, "www.ck")


@pytest.mark.parametrize(
    ("domain", "blacklist"),
    [("example.com", ".com"), ("example.com", "com."), ("example.github.io", ".github.io")],
)
def test_psl_classifier_normalizes_dotted_blacklist_entries(domain: str, blacklist: str) -> None:
    assert P.tld_wildcard_classify(domain, P.parse_psl_rules(PSL), set(), blacklist={blacklist}) == (
        P.DNSBL_CLASS_DATA,
        domain,
    )


@pytest.mark.parametrize("bad", ["", "not-a-psl", "xn--bad", "a..com", "a$[b].com"])
def test_psl_authority_loader_rejects_invalid_files(tmp_path: Path, bad: str) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_bytes(bad.encode("utf-8"))
    with pytest.raises(ValueError):
        P._load_psl_authority(str(authority), enabled=True)


def test_psl_authority_loader_off_is_exact_only_without_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority = tmp_path / "missing"
    monkeypatch.setattr(P, "open", lambda *_args, **_kwargs: pytest.fail("authority opened while OFF"), raising=False)
    assert P._load_psl_authority(str(authority), enabled=False) == P.PslRules()


def test_build_carries_psl_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_text(PSL, encoding="utf-8")
    manifest = _manifest(tmp_path)
    monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
    monkeypatch.setitem(P.pfb, "python_tld_wildcard", True)
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert result is not None
    assert result.psl_rules.private_exact == ("github.io",)


def test_tld_allow_also_requires_psl_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_text(PSL, encoding="utf-8")
    manifest = _manifest(tmp_path)
    monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
    monkeypatch.setitem(P.pfb, "python_tld_wildcard", False)
    monkeypatch.setitem(P.pfb, "tld_allow", True)
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert result is not None
    assert result.psl_rules.icann_exact == ("com", "io")


def test_tld_allow_authority_does_not_enable_wildcard_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_text(PSL, encoding="utf-8")
    manifest = _manifest(tmp_path)
    monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
    monkeypatch.setitem(P.pfb, "python_tld_wildcard", False)
    monkeypatch.setitem(P.pfb, "tld_allow", True)

    result = P.dnsbl_build_from_manifest(str(manifest))

    assert result is not None
    assert result.zone_db == {}
    assert "example.com" in result.data_db


def test_tld_allow_invalid_psl_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_bytes(b"\xff")
    manifest = _manifest(tmp_path)
    monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
    monkeypatch.setitem(P.pfb, "python_tld_wildcard", False)
    monkeypatch.setitem(P.pfb, "tld_allow", True)
    assert P.dnsbl_build_from_manifest(str(manifest)) is None


def test_reload_failure_retains_psl_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    old = P.Snapshot({}, {}, {}, {}, {}, {}, {}, psl_rules=P.parse_psl_rules(PSL))
    monkeypatch.setattr(P, "_snapshot", old)
    assert P.rebuild_and_swap(lambda: None, emit_counts=False) is False
    assert P._snapshot is old
    assert P._snapshot.psl_rules == old.psl_rules


def test_successful_reload_snapshot_carries_exact_psl_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rules = P.parse_psl_rules(PSL)
    result = P.BuildResult({}, {}, {}, {}, 0, psl_rules=rules)
    monkeypatch.setattr(P, "dnsbl_build_from_manifest", lambda _path: result)
    monkeypatch.setitem(P.pfb, "pfb_py_sources", str(tmp_path / "pfb_py_sources.json"))
    monkeypatch.setitem(P.pfb, "pfb_unbound.ini", str(tmp_path / "missing.ini"))
    monkeypatch.setitem(P.pfb, "python_hsts", False)

    snapshot = P._build_swap_snapshot()

    assert snapshot is not None
    assert snapshot.psl_rules is rules


def _allow_cfg(**overrides: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "python_blocking": False,
        "dataDB": False,
        "zoneDB": False,
        "whiteDB": False,
        "regexDB": False,
        "allowRegexDB": False,
        "hstsDB": False,
        "tld_allow": True,
        "tld_allow_list": ["com"],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "python_idn": False,
        "python_tld_seg": 2,
        "hsts_tlds": (),
        "psl_include_private": True,
        "psl_allow_private": False,
    }
    cfg.update(overrides)
    return cfg


def _allow_containers(rules: P.PslRules) -> dict[str, Any]:
    return {
        "dataDB": {},
        "zoneDB": {},
        "whiteDB": {},
        "regexDB": {},
        "allowRegexDB": {},
        "feedGroupIndexDB": {},
        "hstsDB": {},
        "psl_rules": rules,
        "tld_allow_roots": ("com",),
    }


def test_psl_tld_allow_selected_root_and_private_precision() -> None:
    rules = P.parse_psl_rules(PSL)
    containers = _allow_containers(rules)

    # Selected IANA root always wins, even when the query is under a PRIVATE suffix.
    selected = P.evaluate_domain(
        "x.github.io.", "x.github.io.", "io", False, _allow_cfg(tld_allow_list=["io"]), containers
    )
    assert selected.is_found is False

    # A non-selected ICANN root remains blocked.
    blocked = P.evaluate_domain("x.example.net", "x.example.net", "net", False, _allow_cfg(), containers)
    assert blocked.is_found is True
    assert blocked.feed == "TLD_Allow"

    # PRIVATE allowance is explicit and does not broaden ICANN roots.
    private = P.evaluate_domain(
        "x.github.io",
        "x.github.io",
        "io",
        False,
        _allow_cfg(psl_allow_private=True),
        {**containers, "tld_allow_roots": ("com",)},
    )
    assert private.is_found is False
    still_blocked = P.evaluate_domain(
        "x.example.net",
        "x.example.net",
        "net",
        False,
        _allow_cfg(psl_allow_private=True),
        containers,
    )
    assert still_blocked.is_found is True


def test_psl_tld_allow_private_exception_does_not_fallback_to_private_allow() -> None:
    rules = P.parse_psl_rules(PSL)
    containers = {**_allow_containers(rules), "tld_allow_roots": ()}
    # www.ck resolves through the ICANN exception (!www.ck): private_active is
    # False, so PRIVATE allowance must not open it -- while a genuine PRIVATE
    # boundary (github.io) under the same policy IS allowed. Roots stay
    # populated so the empty-selection no-op guard cannot mask either outcome.
    exception_name = P.evaluate_domain(
        "www.ck",
        "www.ck",
        "ck",
        False,
        _allow_cfg(tld_allow_list=["com"], psl_allow_private=True),
        containers,
    )
    assert exception_name.is_found is True
    assert exception_name.feed == "TLD_Allow"

    private_name = P.evaluate_domain(
        "x.github.io",
        "x.github.io",
        "io",
        False,
        _allow_cfg(tld_allow_list=["com"], psl_allow_private=True),
        containers,
    )
    assert private_name.is_found is False


def test_snapshot_containers_capture_psl_policy_without_global_reads() -> None:
    rules = P.parse_psl_rules(PSL)
    snapshot = P.Snapshot(
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        psl_rules=rules,
        tld_allow_roots=("io",),
        psl_include_private=False,
        psl_allow_private=True,
        # issue #2371: feed-at-suffix PSL policy fields (enforced in build()).
        psl_feed_private_policy="ignore",
        psl_feed_icann_policy="apex",
    )
    containers = snapshot.containers()
    assert containers["psl_rules"] is rules
    assert containers["tld_allow_roots"] == ("io",)
    assert containers["psl_include_private"] is False
    assert containers["psl_allow_private"] is True
    assert containers["psl_feed_private_policy"] == "ignore"
    assert containers["psl_feed_icann_policy"] == "apex"


def test_snapshot_feed_suffix_policy_defaults_honor_for_legacy_fixtures() -> None:
    """issue #2371: a Snapshot built the pre-#2371 way (no policy kwargs -- every legacy
    hand-built fixture in this suite) must default both new fields to "honor", never
    KeyError or silently pick a stricter state."""
    snapshot = P.Snapshot({}, {}, {}, {}, {}, {}, {})
    containers = snapshot.containers()
    assert containers["psl_feed_private_policy"] == "honor"
    assert containers["psl_feed_icann_policy"] == "honor"


def test_snapshot_empty_tld_allow_roots_ignore_later_global_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = P.Snapshot(
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        psl_rules=P.parse_psl_rules(PSL),
        tld_allow_roots=(),
    )
    monkeypatch.setattr(P, "_snapshot", snapshot)
    monkeypatch.setitem(P.pfb, "tld_allow", True)
    monkeypatch.setitem(P.pfb, "tld_allow_list", ["com"])

    cfg = P._evaluate_cfg(snapshot)

    assert cfg["tld_allow_list"] == ()
    decision = P.evaluate_domain("x.example.net", "x.example.net", "net", False, cfg, snapshot.containers())
    assert decision.is_found is False


def test_legacy_snapshot_default_roots_are_empty_for_allow_matcher() -> None:
    snapshot = P.Snapshot({}, {}, {}, {}, {}, {}, {}, psl_rules=P.parse_psl_rules(PSL))
    assert snapshot.tld_allow_roots is None
    containers = snapshot.containers()

    assert containers["tld_allow_roots"] == ()
    decision = P.evaluate_domain(
        "x.example.net",
        "x.example.net",
        "net",
        False,
        _allow_cfg(tld_allow_list=[]),
        containers,
    )
    assert decision.is_found is False


def test_tld_allow_permits_underscore_service_labels_under_selected_root() -> None:
    """Underscore service labels (DMARC/DKIM/SRV/ACME) are valid query names.

    TLD-Allow judges the SUFFIX: a selected root admits them and an unselected
    root blocks them, exactly like any other name -- strict rule-grammar
    validation must never sinkhole a service lookup under a selected root.
    """
    rules = P.parse_psl_rules(PSL)
    containers = _allow_containers(rules)
    for name in ("_dmarc.example.com", "_sip._tcp.example.com", "_acme-challenge.example.com"):
        allowed = P.evaluate_domain(name, name, "com", False, _allow_cfg(), containers)
        assert allowed.is_found is False, name
    blocked = P.evaluate_domain("_dmarc.example.net", "_dmarc.example.net", "net", False, _allow_cfg(), containers)
    assert blocked.is_found is True
    assert blocked.feed == "TLD_Allow"


def test_allow_private_precision_is_independent_of_include_private() -> None:
    """pfb_psl_allow_private stands alone: the Wildcard-Blocking PRIVATE
    recognition toggle gates classification only, never TLD-Allow precision."""
    rules = P.parse_psl_rules(PSL)
    containers = {
        **_allow_containers(rules),
        "psl_include_private": False,
        "psl_allow_private": True,
    }
    private = P.evaluate_domain(
        "x.github.io",
        "x.github.io",
        "io",
        False,
        _allow_cfg(psl_include_private=False, psl_allow_private=True),
        containers,
    )
    assert private.is_found is False
    # PRIVATE precision still never opens the parent TLD.
    unrelated = P.evaluate_domain(
        "x.io",
        "x.io",
        "io",
        False,
        _allow_cfg(psl_include_private=False, psl_allow_private=True),
        containers,
    )
    assert unrelated.is_found is True
    assert unrelated.feed == "TLD_Allow"


def test_allow_private_off_blocks_private_boundary_and_parent_alike() -> None:
    """With the allow toggle off, x.github.io and unrelated x.io both stay
    blocked when the io root is not selected (issue #1541 'Allow: PRIVATE off'
    matrix row, same-root negative)."""
    rules = P.parse_psl_rules(PSL)
    containers = _allow_containers(rules)
    for name in ("x.github.io", "x.io"):
        decision = P.evaluate_domain(name, name, "io", False, _allow_cfg(), containers)
        assert decision.is_found is True, name
        assert decision.feed == "TLD_Allow"
