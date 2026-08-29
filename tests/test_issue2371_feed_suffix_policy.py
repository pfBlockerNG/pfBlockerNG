"""Issue #2371 Step 2 -- enforce the feed-at-suffix PSL policy.

Step 1 (commit 48130739 + 97b3a505) registered the two per-section policy fields
(``psl_feed_private_policy`` / ``psl_feed_icann_policy``, tokens
``ignore|apex|honor``) end to end from ini through ``Snapshot`` -- with no
consumer. This file pins the Step-2 consumer: a FEED-provenance entry whose
normalized name sits exactly at its winning public suffix is dropped
(``ignore``), demoted from a wildcard ZONE to an exact-apex DATA block
(``apex``), or left alone (``honor``), in BOTH emission paths (the plain
``tld_wildcard_classify()`` loop and the ABP reconcile-fold loop in
``build()``) -- FEED provenance only, USER (``Custom_List``/ABP) rules keep
full power in every state. Every drop/demotion is tallied into
``BuildResult.rejects`` under new ``'suffix_drop'`` / ``'suffix_demote'``
buckets. A policy other than ``honor`` is also a third authority load gate in
``_dnsbl_config_from_manifest()``, independent of Wildcard Blocking
(``python_tld_wildcard``) / TLD-Allow.

Pure pytest, stdlib only, no Unbound symbols (CI-runnable).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound as P

# A small, self-contained PSL fixture (not the shipped file) exercising every
# shape the coverage matrix needs: a PRIVATE exact suffix (github.io) whose
# ICANN parent (io) differs; an ICANN exact two-label suffix (co.uk); an ICANN
# wildcard family with a sibling exception (*.ck / !www.ck); and an IDNA
# punycode ICANN apex (xn--p1ai).
PSL = """// ===BEGIN ICANN DOMAINS===
com
io
co.uk
xn--p1ai
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""


def _rules() -> P.PslRules:
    return P.parse_psl_rules(PSL)


# --------------------------------------------------------------------------- #
# Helpers: drive build() over a synthetic single-feed manifest + in-memory
# line_reader (same idiom as tests/test_adr21_abp_per_line.py), with the PSL
# rules + the two new policy fields threaded through the config blob.
# --------------------------------------------------------------------------- #


def _run_build(
    lines: list[str],
    *,
    private_policy: str = "honor",
    icann_policy: str = "honor",
    provenance: str = "feed",
    feed: str = "FEED",
    group: str = "GRP",
    log_flag: str = "1",
    psl_wildcard_enabled: bool = True,
    include_private: bool = True,
) -> P.BuildResult:
    raw_key = "feed.raw"
    manifest = {
        "feeds": [
            {
                "feed": feed,
                "group": group,
                "log_flag": log_flag,
                "provenance": provenance,
                "raw": raw_key,
            }
        ]
    }
    config: dict[str, Any] = {
        "psl_rules": _rules(),
        "psl_wildcard_enabled": psl_wildcard_enabled,
        "psl_include_private": include_private,
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": [],
        "psl_feed_private_policy": private_policy,
        "psl_feed_icann_policy": icann_policy,
    }

    def reader(raw: str) -> list[str]:
        assert raw == raw_key
        return list(lines)

    return P.build(manifest, config, line_reader=reader)


def _block_payload(result: P.BuildResult, domain: str) -> dict[str, Any]:
    if domain in result.zone_db:
        return result.zone_db[domain]
    return result.data_db[domain]


def _reject_row(result: P.BuildResult, feed: str = "FEED", group: str = "GRP") -> dict[str, int]:
    return result.rejects.get((feed, group), {})


# --------------------------------------------------------------------------- #
# Unit tests for the suffix predicate itself, incl. hostile inputs.
# --------------------------------------------------------------------------- #


class TestSuffixFeedPolicyPredicate:
    def test_private_apex_returns_private_policy(self) -> None:
        assert P._dnsbl_suffix_feed_policy("github.io", _rules(), "ignore", "apex") == "ignore"

    def test_icann_apex_returns_icann_policy(self) -> None:
        assert P._dnsbl_suffix_feed_policy("co.uk", _rules(), "ignore", "apex") == "apex"

    def test_wildcard_derived_boundary_is_at_boundary(self) -> None:
        """Hostile input: foo.ck sits one label under the *.ck wildcard family --
        it IS the winning public suffix (at-boundary), even though 'ck' itself
        carries no explicit PSL rule."""
        assert P._dnsbl_suffix_feed_policy("foo.ck", _rules(), "x", "ignore") == "ignore"

    def test_exception_carved_name_is_not_at_boundary(self) -> None:
        """Hostile input: www.ck resolves via the !www.ck exception to public
        suffix 'ck' -- www.ck (2 labels) != 'ck' (1 label), so it is a
        registrable domain under the suffix, never the suffix itself."""
        assert P._dnsbl_suffix_feed_policy("www.ck", _rules(), "ignore", "ignore") is None

    def test_bare_tld_in_exception_bearing_family_resolves_icann_section(self) -> None:
        """The exception-carved family's own bare TLD ('ck') falls back to
        itself (no explicit rule) and resolves ICANN (private_active False),
        proving the exception sibling never leaks PRIVATE section on it."""
        assert P._dnsbl_suffix_feed_policy("ck", _rules(), "x", "ignore") == "ignore"

    def test_punycode_apex_is_at_boundary(self) -> None:
        assert P._dnsbl_suffix_feed_policy("xn--p1ai", _rules(), "x", "apex") == "apex"

    def test_invalid_name_is_not_at_boundary(self) -> None:
        """Hostile input: a name normalise() already accepted (underscore is a
        valid DNSBL label char, #723) but _psl_normalize_name() rejects (IDNA
        charset) -- ValueError is caught, never propagated, and treated as
        'not at a boundary' (normal handling)."""
        assert P._dnsbl_suffix_feed_policy("foo_bar.com", _rules(), "ignore", "ignore") is None

    def test_non_suffix_registrable_is_not_at_boundary(self) -> None:
        assert P._dnsbl_suffix_feed_policy("example.com", _rules(), "ignore", "ignore") is None

    def test_deep_subdomain_is_not_at_boundary(self) -> None:
        assert P._dnsbl_suffix_feed_policy("a.b.example.github.io", _rules(), "ignore", "ignore") is None


# --------------------------------------------------------------------------- #
# Row 1 / 3: plain feed entry AT a suffix, PRIVATE and ICANN sections.
# --------------------------------------------------------------------------- #


class TestPlainSuffixPolicy:
    def test_private_ignore_drops_and_tallies(self) -> None:
        result = _run_build(["github.io"], private_policy="ignore", icann_policy="honor")
        assert "github.io" not in result.data_db
        assert "github.io" not in result.zone_db
        assert _reject_row(result)["suffix_drop"] == 1

    def test_private_apex_is_exact_data(self) -> None:
        result = _run_build(["github.io"], private_policy="apex", icann_policy="honor")
        assert result.data_db["github.io"]["band"] == P.PRIO_FEED_BLOCK
        assert "github.io" not in result.zone_db
        assert _reject_row(result).get("suffix_demote", 0) == 0

    def test_private_honor_is_exact_data(self) -> None:
        result = _run_build(["github.io"], private_policy="honor", icann_policy="honor")
        assert "github.io" in result.data_db
        assert "github.io" not in result.zone_db

    def test_icann_ignore_drops_and_tallies(self) -> None:
        result = _run_build(["co.uk"], private_policy="honor", icann_policy="ignore")
        assert "co.uk" not in result.data_db
        assert "co.uk" not in result.zone_db
        assert _reject_row(result)["suffix_drop"] == 1

    def test_icann_apex_is_exact_data(self) -> None:
        result = _run_build(["co.uk"], private_policy="honor", icann_policy="apex")
        assert "co.uk" in result.data_db
        assert "co.uk" not in result.zone_db

    def test_icann_honor_is_exact_data(self) -> None:
        result = _run_build(["co.uk"], private_policy="honor", icann_policy="honor")
        assert "co.uk" in result.data_db
        assert "co.uk" not in result.zone_db


# --------------------------------------------------------------------------- #
# Row 2 / 4: ABP explicit wildcard anchor AT a suffix, PRIVATE and ICANN.
# --------------------------------------------------------------------------- #


class TestAbpSuffixPolicy:
    def test_private_ignore_drops_and_tallies(self) -> None:
        result = _run_build(["||github.io^"], private_policy="ignore", icann_policy="honor")
        assert "github.io" not in result.data_db
        assert "github.io" not in result.zone_db
        assert _reject_row(result)["suffix_drop"] == 1

    def test_private_apex_demotes_zone_to_data_and_tallies(self) -> None:
        result = _run_build(["||github.io^$important"], private_policy="apex", icann_policy="honor")
        assert "github.io" not in result.zone_db
        payload = result.data_db["github.io"]
        # band/important/log preserved across the demotion (only cls changes).
        assert payload["important"] is True
        assert payload["log"] == "1"
        assert _reject_row(result)["suffix_demote"] == 1

    def test_private_honor_stays_wildcard_zone(self) -> None:
        result = _run_build(["||github.io^"], private_policy="honor", icann_policy="honor")
        assert "github.io" in result.zone_db
        assert "github.io" not in result.data_db

    def test_icann_ignore_drops_and_tallies(self) -> None:
        result = _run_build(["||co.uk^"], private_policy="honor", icann_policy="ignore")
        assert "co.uk" not in result.data_db
        assert "co.uk" not in result.zone_db
        assert _reject_row(result)["suffix_drop"] == 1

    def test_icann_apex_demotes_zone_to_data_and_tallies(self) -> None:
        result = _run_build(["||co.uk^"], private_policy="honor", icann_policy="apex")
        assert "co.uk" not in result.zone_db
        assert "co.uk" in result.data_db
        assert _reject_row(result)["suffix_demote"] == 1

    def test_icann_honor_stays_wildcard_zone(self) -> None:
        result = _run_build(["||co.uk^"], private_policy="honor", icann_policy="honor")
        assert "co.uk" in result.zone_db
        assert "co.uk" not in result.data_db


# --------------------------------------------------------------------------- #
# Row 5: the WINNING rule's section governs, not a fixed per-domain guess.
# --------------------------------------------------------------------------- #


class TestWinningRuleSectionSelectsPolicy:
    def test_private_rule_beats_icann_parent(self) -> None:
        # github.io's PRIVATE rule wins over its ICANN parent 'io' -- the
        # PRIVATE policy governs, the ICANN policy must be irrelevant here.
        result = _run_build(["github.io"], private_policy="ignore", icann_policy="apex")
        assert "github.io" not in result.data_db
        assert "github.io" not in result.zone_db

    def test_exception_fallback_name_uses_icann_policy(self) -> None:
        # 'ck' resolves ICANN (private_active False) in a ruleset that carries
        # a sibling exception (!www.ck) -- the ICANN policy governs.
        result = _run_build(["ck"], private_policy="honor", icann_policy="ignore")
        assert "ck" not in result.data_db
        assert "ck" not in result.zone_db


# --------------------------------------------------------------------------- #
# Row 6: USER (Custom_List / sovereign ABP) provenance is exempt in EVERY state.
# --------------------------------------------------------------------------- #


class TestUserProvenanceSovereignty:
    def test_user_plain_entry_never_dropped_or_demoted(self) -> None:
        result = _run_build(["github.io"], private_policy="ignore", icann_policy="ignore", provenance="user")
        assert "github.io" in result.data_db
        assert _reject_row(result, feed="FEED", group="GRP").get("suffix_drop", 0) == 0

    def test_user_abp_wildcard_never_dropped_or_demoted(self) -> None:
        result = _run_build(["||github.io^"], private_policy="ignore", icann_policy="ignore", provenance="user")
        assert "github.io" in result.zone_db
        assert "github.io" not in result.data_db
        assert _reject_row(result).get("suffix_drop", 0) == 0
        assert _reject_row(result).get("suffix_demote", 0) == 0


# --------------------------------------------------------------------------- #
# Row 7: non-suffix names are classification-byte-identical under a
# restrictive policy vs. honor/honor -- the SAME corpus run twice.
# --------------------------------------------------------------------------- #


class TestNonSuffixNamesUnaffected:
    _CORPUS = [
        "example.com",  # registrable under a two-label-absent (fallback) suffix -> ZONE
        "a.b.example.github.io",  # deep subdomain under a PRIVATE suffix -> DATA
        "sub.co.uk",  # registrable under the ICANN suffix co.uk -> ZONE
    ]

    def test_plain_corpus_identical_under_restrictive_and_honor(self) -> None:
        honor = _run_build(list(self._CORPUS), private_policy="honor", icann_policy="honor")
        restrictive = _run_build(list(self._CORPUS), private_policy="ignore", icann_policy="ignore")
        assert restrictive.data_db == honor.data_db
        assert restrictive.zone_db == honor.zone_db
        assert restrictive.rejects == honor.rejects

    def test_abp_corpus_identical_under_restrictive_and_honor(self) -> None:
        lines = [f"||{d}^" for d in self._CORPUS]
        honor = _run_build(lines, private_policy="honor", icann_policy="honor")
        restrictive = _run_build(lines, private_policy="apex", icann_policy="apex")
        assert restrictive.data_db == honor.data_db
        assert restrictive.zone_db == honor.zone_db


# --------------------------------------------------------------------------- #
# Row 8: Wildcard Blocking OFF -- ABP zones exist independently (#1255);
# policy must still apply, using the (raw) loaded PSL rules regardless of the
# classifier's own psl_wildcard_enabled gate.
# --------------------------------------------------------------------------- #


class TestWildcardBlockingOffPolicyStillApplies:
    def test_apex_demotes_with_wildcard_blocking_off(self) -> None:
        result = _run_build(["||co.uk^"], private_policy="honor", icann_policy="apex", psl_wildcard_enabled=False)
        assert "co.uk" not in result.zone_db
        assert "co.uk" in result.data_db

    def test_ignore_drops_with_wildcard_blocking_off(self) -> None:
        result = _run_build(["||co.uk^"], private_policy="honor", icann_policy="ignore", psl_wildcard_enabled=False)
        assert "co.uk" not in result.zone_db
        assert "co.uk" not in result.data_db
        assert _reject_row(result)["suffix_drop"] == 1


# --------------------------------------------------------------------------- #
# Row 9 / 10: the third authority load gate.
# --------------------------------------------------------------------------- #


def _manifest(path: Path, *, authority_text: str | bytes) -> tuple[Path, Path]:
    authority = path / "dnsbl_psl"
    if isinstance(authority_text, bytes):
        authority.write_bytes(authority_text)
    else:
        authority.write_text(authority_text, encoding="utf-8")
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
    return manifest, authority


class TestLoadGate:
    def test_policy_alone_opens_the_authority(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        manifest, authority = _manifest(tmp_path, authority_text=PSL)
        monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
        monkeypatch.setitem(P.pfb, "python_tld_wildcard", False)
        monkeypatch.setitem(P.pfb, "tld_allow", False)
        monkeypatch.setitem(P.pfb, "psl_feed_private_policy", "apex")
        monkeypatch.setitem(P.pfb, "psl_feed_icann_policy", "honor")

        result = P.dnsbl_build_from_manifest(str(manifest))

        assert result is not None
        assert result.psl_rules.private_exact == ("github.io",)

    def test_policy_alone_fails_closed_on_corrupt_authority(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manifest, authority = _manifest(tmp_path, authority_text=b"\xff")
        monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
        monkeypatch.setitem(P.pfb, "python_tld_wildcard", False)
        monkeypatch.setitem(P.pfb, "tld_allow", False)
        monkeypatch.setitem(P.pfb, "psl_feed_private_policy", "ignore")
        monkeypatch.setitem(P.pfb, "psl_feed_icann_policy", "honor")

        assert P.dnsbl_build_from_manifest(str(manifest)) is None

    def test_both_honor_and_both_old_gates_off_never_opens_authority(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Extends the existing "not opened while OFF" idiom
        # (test_psl_authority_loader_off_is_exact_only_without_open) up through
        # the composed three-gate expression in _dnsbl_config_from_manifest(),
        # rather than the lower-level _load_psl_authority() call alone.
        manifest, authority = _manifest(tmp_path, authority_text=PSL)
        monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
        monkeypatch.setitem(P.pfb, "python_tld_wildcard", False)
        monkeypatch.setitem(P.pfb, "tld_allow", False)
        monkeypatch.setitem(P.pfb, "psl_feed_private_policy", "honor")
        monkeypatch.setitem(P.pfb, "psl_feed_icann_policy", "honor")

        def guarded_open(path: Any, *a: Any, **k: Any) -> Any:
            # Only the AUTHORITY path must stay unopened -- the manifest JSON
            # itself (and the feed raw it references) legitimately opens.
            if str(path) == str(authority):
                pytest.fail("authority opened with both gates off and honor/honor")
            return open(path, *a, **k)  # noqa: SIM115 -- delegating wrapper, not a leak

        monkeypatch.setattr(P, "open", guarded_open, raising=False)

        result = P.dnsbl_build_from_manifest(str(manifest))

        assert result is not None
        assert result.psl_rules == P.PslRules()


# --------------------------------------------------------------------------- #
# Row 11: tally -- ignore-drop and apex-demote counted under the right
# bucket + (feed, group); honor tallies nothing new.
# --------------------------------------------------------------------------- #


class TestRejectTally:
    def test_honor_tallies_nothing_new(self) -> None:
        result = _run_build(["github.io", "||co.uk^"], private_policy="honor", icann_policy="honor")
        assert result.rejects == {}

    def test_drop_and_demote_attributed_per_feed_group(self) -> None:
        result = _run_build(
            ["github.io", "||co.uk^"],
            private_policy="ignore",
            icann_policy="apex",
            feed="MyFeed",
            group="MyGroup",
        )
        row = result.rejects[("MyFeed", "MyGroup")]
        assert row["suffix_drop"] == 1
        assert row["suffix_demote"] == 1

    def test_reject_stats_writer_emits_new_buckets(self, tmp_path: Path) -> None:
        out = tmp_path / "pfb_py_reject_stats.json"
        tally = {("F", "G"): {"shape": 0, "wire_cap": 0, "suffix_drop": 2, "suffix_demote": 1}}
        assert P.dnsbl_emit_reject_stats(str(out), tally) is True
        written = json.loads(out.read_text())
        assert written == [{"feed": "F", "group": "G", "shape": 0, "wire_cap": 0, "suffix_drop": 2, "suffix_demote": 1}]

    def test_reject_stats_writer_row_shape_unchanged_for_legacy_buckets(self, tmp_path: Path) -> None:
        """The pre-#2371 2-key row shape must stay byte-identical when only
        shape/wire_cap ever fired for that (feed, group) -- no gratuitous
        suffix_drop:0 / suffix_demote:0 padding on every row."""
        out = tmp_path / "pfb_py_reject_stats.json"
        tally = {("RejFeed", "RejGroup"): {"shape": 3, "wire_cap": 5}}
        assert P.dnsbl_emit_reject_stats(str(out), tally) is True
        written = json.loads(out.read_text())
        assert written == [{"feed": "RejFeed", "group": "RejGroup", "shape": 3, "wire_cap": 5}]


# --------------------------------------------------------------------------- #
# Row 12: ABP allow/regex rules and allow_domains at suffix-shaped names are
# untouched -- policy governs BLOCK emission only.
# --------------------------------------------------------------------------- #


class TestAllowAndRegexUntouched:
    def test_allow_rule_at_suffix_survives_ignore(self) -> None:
        result = _run_build(["||github.io^", "@@||github.io^"], private_policy="ignore", icann_policy="ignore")
        # The BLOCK anchor was dropped by policy...
        assert "github.io" not in result.data_db
        assert "github.io" not in result.zone_db
        # ...but the ALLOW anchor at the exact same suffix name is untouched.
        assert "github.io" in result.white_db

    def test_irreducible_regex_at_suffix_shape_survives_ignore(self) -> None:
        # An irreducible pattern (alternation) never folds into block_domains,
        # so it never reaches the suffix-policy check at all.
        result = _run_build(["/(a|b)\\.github\\.io$/"], private_policy="ignore", icann_policy="ignore")
        assert len(result.regex_db) == 1


# --------------------------------------------------------------------------- #
# The #1541 apex/ABP-anchor invariants live in test_pfb_unbound.py's
# suffix-apex classes, test_adr21_abp_per_line.py, and
# test_adr31_precedence_oracle.py; this file adds only the policy axis.
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# PR #2378 review F1: PRIVATE recognition OFF must not let 'apex' leak a ZONE.
# --------------------------------------------------------------------------- #


class TestPlainSuffixPolicyWithPrivateRecognitionOff:
    """With PSL PRIVATE recognition OFF the classifier's ICANN-only view sees a
    PRIVATE apex as a registrable domain and would wildcard it. The policy's
    view is the FULL PSL, so 'apex' demotes that would-be ZONE to an exact apex
    block; 'ignore' still drops; 'honor' keeps the classifier's outcome."""

    def test_private_apex_demotes_classifier_zone_and_tallies(self) -> None:
        result = _run_build(["github.io"], private_policy="apex", icann_policy="honor", include_private=False)
        assert "github.io" not in result.zone_db
        assert result.data_db["github.io"]["band"] == P.PRIO_FEED_BLOCK
        assert _reject_row(result)["suffix_demote"] == 1

    def test_private_ignore_still_drops_and_tallies(self) -> None:
        result = _run_build(["github.io"], private_policy="ignore", icann_policy="honor", include_private=False)
        assert "github.io" not in result.data_db
        assert "github.io" not in result.zone_db
        assert _reject_row(result)["suffix_drop"] == 1

    def test_private_honor_keeps_classifier_zone(self) -> None:
        result = _run_build(["github.io"], private_policy="honor", icann_policy="honor", include_private=False)
        assert "github.io" in result.zone_db
        assert _reject_row(result).get("suffix_demote", 0) == 0

    def test_user_provenance_keeps_zone_even_under_apex(self) -> None:
        result = _run_build(
            ["github.io"],
            private_policy="apex",
            icann_policy="apex",
            include_private=False,
            provenance="user",
        )
        assert "github.io" in result.zone_db
        assert _reject_row(result, feed="FEED", group="GRP").get("suffix_demote", 0) == 0

    def test_private_honor_not_demoted_while_icann_policy_arms_the_gate(self) -> None:
        # Mixed-policy axis: the entry's OWN section policy is honor, the OTHER
        # section's non-honor value merely keeps the policy machinery active. A
        # demotion guard that fires on any active policy (not the entry's own
        # apex) would wrongly demote this classifier ZONE.
        result = _run_build(["github.io"], private_policy="honor", icann_policy="apex", include_private=False)
        assert "github.io" in result.zone_db
        assert "github.io" not in result.data_db
        assert _reject_row(result).get("suffix_demote", 0) == 0
