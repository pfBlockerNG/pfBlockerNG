"""Issue #1541 Step 2: runtime PSL authority, classification, and snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest import mock

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
def test_psl_build_normalizes_dotted_blacklist_entries(domain: str, blacklist: str) -> None:
    """A dotted or trailing-dot user blacklist entry still blocks at its root: ``build()``
    normalizes the textarea shape, so the entry lands as an exact DATA block (#3050).
    """
    result = P.build(
        {"feeds": [{"feed": "FEED", "group": "GRP", "log_flag": "1", "raw": "feed.raw"}]},
        {
            "psl_rules": P.parse_psl_rules(PSL),
            "tld_wildcard_blacklist": [blacklist],
            "tld_wildcard_exclusion": [],
            "user_whitelist": [],
        },
        line_reader=lambda _raw: [domain],
    )
    assert domain in result.data_db, (
        f"expected an exact DATA block for {domain!r} with {blacklist!r} blacklisted, "
        f"data_db={sorted(result.data_db)!r} zone_db={sorted(result.zone_db)!r}"
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


def test_resolving_a_name_never_hashes_the_rule_set() -> None:
    """issue #3046: the membership index must not sit behind a cache keyed on
    ``PslRules``.

    Computing such a key hashes all six rule tuples, and CPython does not cache
    tuple hashes, so the key costs more than the scan the cache exists to avoid.
    Asserted on the hashing itself rather than on a timing, which would be flaky.
    """
    rules = P.parse_psl_rules(PSL)
    hashed: list[str] = []
    original_hash = P.PslRules.__hash__

    def counting_hash(self: P.PslRules) -> int:
        hashed.append("hashed")
        return original_hash(self)

    with mock.patch.object(P.PslRules, "__hash__", counting_hash):
        for name in ("example.com", "a.b.example.com", "example.github.io", "www.ck"):
            P.resolve_public_suffix(name, rules)

    assert hashed == [], f"resolution hashed the rule set {len(hashed)} time(s); issue #3046 has regressed"


def test_the_index_is_built_once_per_instance() -> None:
    """The sets are held on the instance, so repeated resolution reuses them.

    Identity, not equality: two equal-but-distinct builds would mean the index
    is being recomputed, which is the cost this change exists to remove.
    """
    rules = P.parse_psl_rules(PSL)

    first = rules.index()

    assert rules.index() is first
    assert rules.index() is first


def test_indexing_an_instance_leaves_value_equality_and_hash_untouched() -> None:
    """``_index`` carries ``compare=False``, so an indexed instance stays equal
    to an un-indexed one built from the same rules -- and keeps the same hash.

    Both halves matter. Equality is the dataclass contract other tests rely on
    (``_load_psl_authority(...) == PslRules()``); the hash must also hold,
    because PslRules remains hashable and any caller putting one in a set or
    dict key would otherwise see two distinct entries for the same rules
    depending on whether a lookup had happened to run first.
    """
    indexed = P.parse_psl_rules(PSL)
    fresh = P.parse_psl_rules(PSL)

    indexed.index()

    assert indexed == fresh
    assert hash(indexed) == hash(fresh)


def test_the_instance_index_matches_a_direct_build() -> None:
    """Moving the sets onto the instance changed where they live, not what they
    are: the memoised value equals what the builder returns for the same rules.
    """
    rules = P.parse_psl_rules(PSL)

    assert rules.index() == P._psl_build_index(rules)


def test_the_live_query_path_does_not_rebuild_the_index_per_query() -> None:
    """issue #3046: TLD-Allow resolves through the memoised index too.

    ``_tld_allow_blocks`` reaches the index on the live DNS query path. Builds are
    counted rather than hashes because un-memoising that call site rebuilds the
    sets per query while hashing nothing, which a hash count cannot see.
    """
    rules = P.parse_psl_rules(PSL)
    containers = _allow_containers(rules)
    cfg = _allow_cfg(tld_allow_list=["com"])
    rules.index()  # prime: every build counted below is one too many

    builds: list[str] = []
    original_build = P._psl_build_index

    def counting_build(r: P.PslRules) -> Any:
        builds.append("build")
        return original_build(r)

    with mock.patch.object(P, "_psl_build_index", counting_build):
        for name in ("x.example.com", "y.example.com", "x.github.io"):
            P.evaluate_domain(name, name, "com", False, cfg, containers)

    assert builds == [], f"the live query path rebuilt the index {len(builds)} time(s); issue #3046 has regressed"


def _counting_walk(walks: list[str]) -> Any:
    """Wrap the label walk so every call is recorded and still really resolves."""
    original = P._psl_prevailing

    def counting_prevailing(*args: Any) -> Any:
        walks.append("walk")
        return original(*args)

    return counting_prevailing


def test_one_resolution_walks_the_labels_once_for_both_sections() -> None:
    """issue #3061: the ICANN-only and ICANN+PRIVATE suffixes come from ONE walk.

    Both suffixes are always needed -- ``private_active`` is their comparison and
    TLD-Allow reads both -- so the walk is shared instead of run once per section.
    Walking twice rebuilt every label tail of the name a second time, 2.23M walks
    per 1.2M-entry build.

    Counted, never timed (issue #3051): a duration cannot see the second walk, and
    the resolution is asserted alongside the count so a broken matcher cannot pass.
    """
    rules = P.parse_psl_rules(PSL)
    rules.index()  # prime: the index build is not what is being counted
    walks: list[str] = []

    with mock.patch.object(P, "_psl_prevailing", _counting_walk(walks)):
        resolution = P.resolve_public_suffix("evil.github.io", rules)

    assert (resolution.icann_suffix, resolution.public_suffix, resolution.private_active) == (
        "io",
        "github.io",
        True,
    ), f"the shared walk changed the resolution: {resolution!r}"
    assert len(walks) == 1, (
        f"one resolution took {len(walks)} label walks; the two sections are still walked separately (issue #3061)"
    )


def test_the_live_query_path_walks_the_labels_once_per_query() -> None:
    """issue #3061: TLD-Allow needs both suffixes too, and shares the same walk.

    ``_tld_allow_blocks`` compares both suffixes against the selected roots on the
    live DNS query path, so the second caller must not reintroduce a second walk.

    The query is a PRIVATE boundary under an unselected root with PRIVATE allowance
    on, because that is the decision the two suffixes actually drive: it passes only
    while ``public_suffix`` (github.io) is longer than ``icann_suffix`` (io). A query
    that merely falls through to the unmatched TLD would be blocked either way and
    could not tell the two sections apart.
    """
    rules = P.parse_psl_rules(PSL)
    containers = {**_allow_containers(rules), "tld_allow_roots": ("com",)}
    cfg = _allow_cfg(psl_allow_private=True)
    rules.index()  # prime: the index build is not what is being counted
    walks: list[str] = []

    with mock.patch.object(P, "_psl_prevailing", _counting_walk(walks)):
        decision = P.evaluate_domain("x.github.io", "x.github.io", "io", False, cfg, containers)

    assert decision.is_found is False, f"the shared walk changed the TLD-Allow decision: {decision!r}"
    assert len(walks) == 1, (
        f"one query took {len(walks)} label walks; TLD-Allow still walks each section separately (issue #3061)"
    )


_EXCEPTION_TLD_PSL = """// ===BEGIN ICANN DOMAINS===
jp
co.jp
kobe.jp
*.kobe.jp
!city.kobe.jp
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// ===END PRIVATE DOMAINS===
"""


@pytest.mark.parametrize(
    ("name", "public_suffix", "registrable"),
    [
        # Exact rule wins below the TLD: co.jp is longer than the bare 'jp' the
        # no-match fallback would return, so this row fails if the exact exit goes.
        ("shop.example.co.jp", "co.jp", "example.co.jp"),
        # Same exit at the TLD itself, where no deeper rule applies.
        ("shop.example.jp", "jp", "example.jp"),
        # Wildcard base kobe.jp promotes the suffix one label to the left.
        ("a.kobe.jp", "a.kobe.jp", ""),
        # The exception carves city.kobe.jp back out of that wildcard, and beats the
        # longer wildcard match it overlaps.
        ("x.city.kobe.jp", "kobe.jp", "city.kobe.jp"),
    ],
)
def test_an_exception_tld_resolves_through_the_two_phase_section_walk(
    name: str, public_suffix: str, registrable: str
) -> None:
    """issue #3061: names under a TLD that carries an exception rule take the
    two-phase walk, and each of its three exits stays correct.

    The shared single pass cannot honour exceptions, because an exception beats an
    ordinary match at ANY depth, so ``_psl_prevailing`` routes a name whose TLD owns
    an exception rule to ``_psl_prevailing_section`` instead. That walk is a live
    production path, not a corner: the shipped list carries seven of its eight
    exception rules under jp, which also holds 1777 exact rules, so all three exits
    -- exact, wildcard and exception -- resolve real feed entries and each gets a
    row here. The exact row sits below the TLD on purpose, because at the TLD that
    exit and the no-match fallback return the same string and cannot be told apart.
    """
    rules = P.parse_psl_rules(_EXCEPTION_TLD_PSL)

    resolution = P.resolve_public_suffix(name, rules)

    # No PRIVATE rules in this authority, so both sections must agree.
    assert (resolution.icann_suffix, resolution.public_suffix, resolution.registrable_domain) == (
        public_suffix,
        public_suffix,
        registrable,
    ), f"the two-phase walk changed the resolution of {name!r}: {resolution!r}"
    assert resolution.private_active is False, f"no PRIVATE rule exists, yet {name!r} reported one: {resolution!r}"
