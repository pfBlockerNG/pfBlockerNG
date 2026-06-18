"""Literal-prefilter for the regex-rule scan in _scan_block_band / _scan_allow_regex_band.

Two test classes:

(1) TestRequiredLiteralExtractor -- soundness / fuzz for _required_literal:
      for every (pattern, query) pair, whenever re.search(pattern, query) matches,
      _required_literal(pattern) is either None OR its value is in query.lower().
      ZERO violations is the kill-test.

(2) TestScanOutputIdentity -- _scan_block_band and _scan_allow_regex_band return
      the SAME (band, meta) / allow-band whether the prefilter is active or the
      original unguarded loop is used.  Covers: matching rules with strong literals,
      no-literal rules (pure alternation), a rule whose literal is embedded mid-name,
      a rule that should be skipped by the prefilter (literal absent), and an evicted
      name (popped from regex_db mid-test -- must not crash, must be skipped).
"""

from __future__ import annotations

import re
import string
from typing import Any

import pfb_unbound
from pfb_unbound import (
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    PRIO_FEED_BLOCK_IMPORTANT,
    PRIO_USER_BLOCK,
    _build_regex_index,
    _required_literal,
    _scan_allow_regex_band,
    _scan_block_band,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_regex_db(*patterns_and_bands: tuple[str, int]) -> dict[str, Any]:
    """Build a regex_db dict from (pattern_str, band) pairs."""
    db: dict[str, Any] = {}
    for i, (pat, band) in enumerate(patterns_and_bands):
        name = f"rule_{i}_{pat[:20]}"
        db[name] = {"re": re.compile(pat), "important": False, "band": band}
    return db


def _unguarded_block_scan(
    q_name: str,
    cfg: dict[str, Any],
    data_db: dict[str, Any],
    zone_db: dict[str, Any],
    regex_db: dict[str, Any],
) -> tuple[int, dict[str, Any] | None]:
    """Reference implementation: iterate ALL regex_db entries (no prefilter)."""
    from pfb_unbound import (
        REGEX_EVICT_MS_DEFAULT,
        REGEX_WARN_MS_DEFAULT,
        _block_entry_band,
        _regex_evict_names,
        _regex_should_evict,
        _regex_timed_search,
    )

    best = 0
    best_meta: dict[str, Any] | None = None
    to_evict: list[str] = []
    warn_ms = cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT)
    evict_ms = cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT)
    for _k, r in list(regex_db.items()):
        pattern = r.get("re") if isinstance(r, dict) else r
        match, elapsed_ms = _regex_timed_search(pattern, q_name)
        if _regex_should_evict(_k, elapsed_ms, warn_ms, evict_ms, "DNSBL_Regex", _k):
            to_evict.append(_k)
            continue
        if match:
            band = _block_entry_band(r)
            if band > best:
                best, best_meta = band, {"kind": "regex", "key": _k}
    if to_evict:
        _regex_evict_names(regex_db, to_evict)
    return best, best_meta


def _unguarded_allow_scan(
    q_name: str,
    allow_regex_db: dict[str, Any],
) -> int:
    """Reference implementation: iterate ALL allow_regex_db entries (no prefilter)."""
    from pfb_unbound import (
        REGEX_EVICT_MS_DEFAULT,
        REGEX_WARN_MS_DEFAULT,
        _allow_priority,
        _regex_evict_names,
        _regex_should_evict,
        _regex_timed_search,
    )

    if not q_name:
        return 0
    best = 0
    to_evict: list[str] = []
    warn_ms = REGEX_WARN_MS_DEFAULT
    evict_ms = REGEX_EVICT_MS_DEFAULT
    for _k, r in list(allow_regex_db.items()):
        pattern = r.get("re") if isinstance(r, dict) else r
        match, elapsed_ms = _regex_timed_search(pattern, q_name)
        if _regex_should_evict(_k, elapsed_ms, warn_ms, evict_ms, "DNSBL_AllowRegex", _k):
            to_evict.append(_k)
            continue
        if match:
            important = bool(r.get("important", False)) if isinstance(r, dict) else False
            band = r.get("band") if isinstance(r, dict) else None
            if not isinstance(band, int):
                band = _allow_priority(important)
            best = max(best, band)
    if to_evict:
        _regex_evict_names(allow_regex_db, to_evict)
    return best


def _base_cfg(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "python_blocking": True,
        "dataDB": False,
        "zoneDB": False,
        "python_tld": False,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "python_idn": False,
        "regexDB": True,
        "whiteDB": False,
        "allowRegexDB": False,
        "important_rules": False,
        "regex_warn_ms": pfb_unbound.REGEX_WARN_MS_DEFAULT,
        "regex_evict_ms": pfb_unbound.REGEX_EVICT_MS_DEFAULT,
        "python_tld_seg": 2,
        "hstsDB": False,
        "hsts_tlds": ("app", "dev"),
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# (1) _required_literal soundness / fuzz
# --------------------------------------------------------------------------- #


class TestRequiredLiteralExtractor:
    """_required_literal must never produce a literal that is absent from a matching
    query.  Equivalently: if re.search(p, q) matches AND _required_literal(p) is not
    None, then required_literal(p) MUST be a substring of q.lower().  ZERO violations.
    """

    # Corpus of varied patterns covering the main AST node types.
    PATTERNS: list[str] = [
        # Host-anchored domain with mandatory literal 'brand.'
        r"^(?:[a-z0-9-]+\.)*brand\.[a-z]{2,}$",
        # Alternation at start + mandatory suffix: required literal = '.com'
        r"(ads|track)\.com",
        # Case-insensitive flag: required literal = 'doubleclick' (lowercased)
        r"(?i)DoubleClick",
        # Char-class repeat + literal suffix: required literal = '.xyz'
        r"[0-9]{8}\.xyz",
        # Pure alternation only -> None (no mandatory literal)
        r"(abc|defg|hij)x?",
        # Path with long literal run
        r"/banner_ad\.gif",
        # Subdomain TLD pattern: mandatory '.doubleclick.net'
        r"\.doubleclick\.net$",
        # Optional prefix + long mandatory body
        r"^(www\.)?ad-server\.example\.com$",
        # MIN_REPEAT (min>=1) contributes chars: [a-z]{2,} before 'suffix'
        r"[a-z]{2,}suffix\.com$",
        # Nested subpattern: still extracts the long literal outside the group
        r"(?:tracking)\.example\.org",
        # ANY (.) breaks the run
        r"ads.track\.example",
        # Anchors only (no literal): None
        r"^$",
        # Empty pattern: None
        r"",
        # Single-char literal: None (length < 2)
        r"x",
    ]

    # Query corpus: varying-length domain-like strings and edge cases.
    QUERIES: list[str] = [
        "brand.com",
        "sub.brand.co.uk",
        "ads.example.com",
        "track.com",
        "www.doubleclick.net",
        "site.doubleclick.net",
        "12345678.xyz",
        "abc",
        "defg",
        "hij",
        "/path/to/banner_ad.gif",
        "ad-server.example.com",
        "www.ad-server.example.com",
        "xysuffix.com",
        "aasuffix.com",
        "tracking.example.org",
        "ads.track.example",
        "DOUBLECLICK.net",
        "some-DoubleClick-domain.com",
        "x",
        "",
        "a" * 100 + ".brand.co",
        "1" * 8 + ".xyz",
        # Strings with all printable ASCII chars (stress test for literal extraction)
        string.ascii_lowercase,
        string.digits + "." + string.ascii_lowercase[:5],
    ]

    def test_soundness_no_violations(self) -> None:
        """Scenario: prefilter soundness across the full pattern x query matrix.

        Given: a corpus of varied patterns and queries.
        When: for each (pattern, query) pair we check whether the pattern matches
              the query and what literal _required_literal extracts.
        Then: whenever the pattern matches, the extracted literal (if not None)
              must appear in the query lowercased -- ZERO violations.

        This is the kill-test: a single violation means the prefilter could
        incorrectly skip a rule that would have matched.
        """
        violations: list[str] = []
        for pat in self.PATTERNS:
            if not pat:
                continue
            try:
                compiled = re.compile(pat)
            except re.error:
                continue
            lit = _required_literal(pat)
            for q in self.QUERIES:
                if compiled.search(q) and lit is not None and lit not in q.lower():
                    violations.append(f"pattern={pat!r} query={q!r} lit={lit!r}")
        assert violations == [], "Required-literal prefilter UNSOUND:\n" + "\n".join(violations)

    def test_literal_minimum_length_two(self) -> None:
        """Literals shorter than 2 chars are not worth a bucket -- must return None."""
        # Single-char pattern: the lone literal 'x' has length 1 -> None
        assert _required_literal(r"x") is None
        # Single escaped dot (length 1 literal): -> None
        assert _required_literal(r"\.") is None

    def test_pure_alternation_yields_none(self) -> None:
        """A pattern whose top-level structure is all-BRANCH yields None (no common literal)."""
        assert _required_literal(r"(abc|defg|hij)x?") is None

    def test_long_literal_run_extracted(self) -> None:
        """The longest contiguous mandatory literal run is returned."""
        lit = _required_literal(r"/banner_ad\.gif")
        assert lit == "/banner_ad.gif"

    def test_anchored_domain_extracts_brand(self) -> None:
        """'brand.' is mandatory in every match of the anchored pattern."""
        lit = _required_literal(r"^(?:[a-z0-9-]+\.)*brand\.[a-z]{2,}$")
        assert lit is not None
        assert "brand" in lit

    def test_case_insensitive_literal_lowercased(self) -> None:
        """(?i)DoubleClick -> required literal is 'doubleclick' (lowercased)."""
        lit = _required_literal(r"(?i)DoubleClick")
        assert lit == "doubleclick"

    def test_none_on_parser_absent(self, monkeypatch: Any) -> None:
        """When _sre_parse is None (non-CPython / missing module), return None safely."""
        monkeypatch.setattr(pfb_unbound, "_sre_parse", None)
        assert _required_literal(r"brand\.com") is None

    def test_none_on_parse_error(self, monkeypatch: Any) -> None:
        """A parse exception must be swallowed and return None (safe degradation)."""

        class _BrokenParser:
            @staticmethod
            def parse(p: str) -> None:
                raise ValueError("injected parse error")

        monkeypatch.setattr(pfb_unbound, "_sre_parse", _BrokenParser())
        assert _required_literal(r"brand\.com") is None


# --------------------------------------------------------------------------- #
# (2) scan output-identity
# --------------------------------------------------------------------------- #


class TestScanOutputIdentity:
    """The guarded scan (with prefilter) must return the SAME result as the
    unguarded reference scan across all query classes.

    Background:
      - regex_db contains: a strong-literal rule, a no-literal (pure-alternation)
        rule, and a rule whose literal is embedded mid-name.
      - allow_regex_db mirrors the same diversity.
    """

    def _block_db(self) -> dict[str, Any]:
        """
        Three block rules:
          'strong' -- pattern has 'ads.' as a required literal (band 3, important)
          'noliter'-- pure alternation (abc|xyz), no extractable literal (band 1)
          'embedded'-- '.tracking.' embedded mid-name (band 5, user-block)
        """
        db: dict[str, Any] = {
            "strong": {
                "re": re.compile(r"\.ads\.example\.com$"),
                "important": True,
                "band": PRIO_FEED_BLOCK_IMPORTANT,
            },
            "noliter": {"re": re.compile(r"(abc|xyz)\.net$"), "important": False, "band": PRIO_FEED_BLOCK},
            "embedded": {"re": re.compile(r"\.tracking\."), "important": False, "band": PRIO_USER_BLOCK},
        }
        return db

    def _allow_db(self) -> dict[str, Any]:
        """
        Two allow rules:
          'allow_strong'  -- '.allow.example.' mandatory literal (band 2)
          'allow_noliter' -- pure alternation (foo|bar), no literal (band 2)
        """
        return {
            "allow_strong": {
                "re": re.compile(r"\.allow\.example\.com$"),
                "important": False,
                "band": PRIO_FEED_ALLOW,
            },
            "allow_noliter": {"re": re.compile(r"(foo|bar)\.org$"), "important": False, "band": PRIO_FEED_ALLOW},
        }

    def _cfg(self) -> dict[str, Any]:
        return _base_cfg()

    # ---- block scan -------------------------------------------------------- #

    def test_block_scan_strong_literal_match(self) -> None:
        """
        Scenario: query matches the strong-literal rule.

        Given: regex_db with 'strong' rule (.ads.example.com), no-literal rule,
               embedded-literal rule; query = 'sub.ads.example.com'.
        When: _scan_block_band is called (prefiltered) and the reference unguarded
              scan is called on a COPY of the same db.
        Then: both return the same (band, meta) -- band 3, key='strong'.
        """
        db = self._block_db()
        db_copy = {k: dict(v) for k, v in db.items()}
        cfg = self._cfg()
        q = "sub.ads.example.com"

        # Given: prefiltered scan
        pfb_unbound._block_regex_index = None
        guarded_band, guarded_meta = _scan_block_band(q, cfg, {}, {}, db)

        # Reference: unguarded scan on a separate copy (no state sharing)
        ref_band, ref_meta = _unguarded_block_scan(q, cfg, {}, {}, db_copy)

        # Then: identical result
        assert guarded_band == ref_band
        assert guarded_band == PRIO_FEED_BLOCK_IMPORTANT
        assert guarded_meta is not None
        assert guarded_meta.get("key") == "strong"
        assert ref_meta is not None and ref_meta.get("key") == "strong"

    def test_block_scan_no_literal_rule_still_runs(self) -> None:
        """
        Scenario: query matches only the no-literal rule (pure alternation).

        Given: query = 'abc.net' (matches noliter, not strong or embedded).
        When: both scans run.
        Then: both return band=1, key='noliter'.
        The prefilter must not skip a rule simply because it has no literal.
        """
        db = self._block_db()
        db_copy = {k: dict(v) for k, v in db.items()}
        cfg = self._cfg()
        q = "abc.net"

        pfb_unbound._block_regex_index = None
        guarded_band, guarded_meta = _scan_block_band(q, cfg, {}, {}, db)
        ref_band, ref_meta = _unguarded_block_scan(q, cfg, {}, {}, db_copy)

        assert guarded_band == ref_band == PRIO_FEED_BLOCK
        assert guarded_meta is not None and guarded_meta.get("key") == "noliter"
        assert ref_meta is not None and ref_meta.get("key") == "noliter"

    def test_block_scan_embedded_literal_match(self) -> None:
        """
        Scenario: query matches the embedded-literal rule only.

        Given: query = 'host.tracking.internal' (only matches 'embedded').
        When: both scans run.
        Then: both return band=5, key='embedded'.
        """
        db = self._block_db()
        db_copy = {k: dict(v) for k, v in db.items()}
        cfg = self._cfg()
        q = "host.tracking.internal"

        pfb_unbound._block_regex_index = None
        guarded_band, guarded_meta = _scan_block_band(q, cfg, {}, {}, db)
        ref_band, ref_meta = _unguarded_block_scan(q, cfg, {}, {}, db_copy)

        assert guarded_band == ref_band == PRIO_USER_BLOCK
        assert guarded_meta is not None and guarded_meta.get("key") == "embedded"

    def test_block_scan_no_match_returns_zero(self) -> None:
        """
        Scenario: query matches nothing.

        Given: query = 'safe.example.org' (no rule matches).
        When: both scans run.
        Then: both return (0, None).

        Before: confirm 'safe.example.org' is not matched by any rule.
        After: both return 0.
        """
        db = self._block_db()
        q = "safe.example.org"

        # Before: confirm none of the patterns match
        for name, entry in db.items():
            assert entry["re"].search(q) is None, f"Rule {name!r} unexpectedly matches {q!r}"

        db_copy = {k: dict(v) for k, v in db.items()}
        cfg = self._cfg()

        pfb_unbound._block_regex_index = None
        guarded_band, guarded_meta = _scan_block_band(q, cfg, {}, {}, db)
        ref_band, ref_meta = _unguarded_block_scan(q, cfg, {}, {}, db_copy)

        # After: both return zero
        assert guarded_band == ref_band == 0
        assert guarded_meta is None
        assert ref_meta is None

    def test_block_scan_prefilter_skips_absent_literal(self) -> None:
        """
        Scenario: the prefilter skips 'strong' rule because its literal is absent.

        Given: query = 'abc.net' -- 'ads.example.com' literal '.ads.example.com'
               is NOT in 'abc.net'.lower().
        When: we inspect the candidate set built by the prefilter.
        Then: 'strong' is NOT in candidates; 'noliter' IS (no-literal -> always-run).
        This proves the skip happens (not just that the final result is correct).
        """
        db = self._block_db()
        pfb_unbound._block_regex_index = None

        # Build the index explicitly to inspect it
        buckets, always = _build_regex_index(db)

        q = "abc.net"
        q_lower = q.lower()

        # Collect candidates as the scan does
        cand: set[str] = set(always)
        for ch in set(q_lower):
            b = buckets.get(ch)
            if b:
                for name, lit in b:
                    if lit in q_lower:
                        cand.add(name)

        # 'noliter' has no required literal -> in 'always' -> in cand
        assert "noliter" in cand
        # 'strong' has literal '.ads.example.com' which is not in 'abc.net'
        assert "strong" not in cand
        # 'embedded' has literal '.tracking.' which is not in 'abc.net'
        assert "embedded" not in cand

    def test_block_scan_evicted_name_skipped_no_crash(self) -> None:
        """
        Scenario: a rule is evicted (popped from regex_db) after the index is built.

        Given: regex_db with 'strong' and 'noliter'; prefilter index is built.
        When: 'strong' is popped from regex_db (simulating eviction), then
              _scan_block_band is called with a query that would have matched 'strong'.
        Then: no crash; 'strong' is skipped; result = (0, None) since 'noliter'
              also does not match.
        """
        db: dict[str, Any] = {
            "strong": {
                "re": re.compile(r"\.ads\.example\.com$"),
                "important": True,
                "band": PRIO_FEED_BLOCK_IMPORTANT,
            },
            "noliter": {"re": re.compile(r"(zzz|qqq)\.net$"), "important": False, "band": PRIO_FEED_BLOCK},
        }
        cfg = self._cfg()
        q = "sub.ads.example.com"

        # Build the index
        pfb_unbound._block_regex_index = None
        buckets, always = _build_regex_index(db)
        pfb_unbound._block_regex_index = (db, buckets, always)

        # Simulate eviction: pop 'strong' from the live db AFTER index build
        db.pop("strong")

        # When: scan runs with 'strong' already evicted
        guarded_band, guarded_meta = _scan_block_band(q, cfg, {}, {}, db)

        # Then: no crash; 'strong' is skipped (evicted); 'noliter' doesn't match -> 0
        assert guarded_band == 0
        assert guarded_meta is None

    def test_block_scan_index_rebuilds_on_new_db(self) -> None:
        """
        Scenario: a snapshot swap (new regex_db object) triggers an index rebuild.

        Given: prefilter index is built for db_old; db_new is a different object.
        When: _scan_block_band is called with db_new.
        Then: the index is rebuilt for db_new (identity check detects the swap).

        Before: index refers to db_old.
        After: index refers to db_new.
        """
        db_old: dict[str, Any] = {
            "old_rule": {"re": re.compile(r"old\.com$"), "important": False, "band": PRIO_FEED_BLOCK},
        }
        db_new: dict[str, Any] = {
            "new_rule": {"re": re.compile(r"new\.com$"), "important": False, "band": PRIO_FEED_BLOCK_IMPORTANT},
        }
        cfg = self._cfg()

        # Given: index is built for db_old
        pfb_unbound._block_regex_index = None
        _ = _scan_block_band("old.com", cfg, {}, {}, db_old)

        assert pfb_unbound._block_regex_index is not None
        assert pfb_unbound._block_regex_index[0] is db_old  # Before: index is for db_old

        # When: called with db_new (different object)
        band, meta = _scan_block_band("new.com", cfg, {}, {}, db_new)

        # After: index is rebuilt for db_new
        assert pfb_unbound._block_regex_index[0] is db_new
        assert band == PRIO_FEED_BLOCK_IMPORTANT
        assert meta is not None and meta.get("key") == "new_rule"

    # ---- allow scan -------------------------------------------------------- #

    def test_allow_scan_strong_literal_match(self) -> None:
        """
        Scenario: query matches the strong-literal allow rule.

        Given: allow_regex_db with 'allow_strong' (.allow.example.com) and
               'allow_noliter' (foo|bar alternation); query = 'x.allow.example.com'.
        When: both guarded and reference scans run.
        Then: both return PRIO_FEED_ALLOW (band 2).
        """
        db = self._allow_db()
        db_copy = {k: dict(v) for k, v in db.items()}
        q = "x.allow.example.com"

        pfb_unbound._allow_regex_index = None
        guarded = _scan_allow_regex_band(q, db)
        ref = _unguarded_allow_scan(q, db_copy)

        assert guarded == ref == PRIO_FEED_ALLOW

    def test_allow_scan_no_literal_rule_fires(self) -> None:
        """
        Scenario: query matches only the no-literal allow rule.

        Given: query = 'foo.org' (matches allow_noliter, not allow_strong).
        When: both scans run.
        Then: both return PRIO_FEED_ALLOW.
        """
        db = self._allow_db()
        db_copy = {k: dict(v) for k, v in db.items()}
        q = "foo.org"

        pfb_unbound._allow_regex_index = None
        guarded = _scan_allow_regex_band(q, db)
        ref = _unguarded_allow_scan(q, db_copy)

        assert guarded == ref == PRIO_FEED_ALLOW

    def test_allow_scan_no_match_returns_zero(self) -> None:
        """
        Scenario: query matches no allow rule.

        Given: query = 'safe.net' (no allow rule matches).
        When: both scans run.
        Then: both return 0.

        Before: verify none of the patterns match 'safe.net'.
        """
        db = self._allow_db()
        q = "safe.net"

        # Before: confirm no match
        for name, entry in db.items():
            assert entry["re"].search(q) is None, f"Allow rule {name!r} unexpectedly matches {q!r}"

        db_copy = {k: dict(v) for k, v in db.items()}

        pfb_unbound._allow_regex_index = None
        guarded = _scan_allow_regex_band(q, db)
        ref = _unguarded_allow_scan(q, db_copy)

        # After: both zero
        assert guarded == 0
        assert ref == 0

    def test_allow_scan_evicted_name_no_crash(self) -> None:
        """
        Scenario: allow rule evicted after index build -- must not crash.

        Given: allow_regex_db with 'allow_strong'; index is built; 'allow_strong'
               is then popped (simulating eviction).
        When: scan runs on a matching query.
        Then: no crash; result = 0 (evicted rule is skipped).
        """
        db: dict[str, Any] = {
            "allow_strong": {"re": re.compile(r"\.allow\.example\.com$"), "important": False, "band": PRIO_FEED_ALLOW},
        }
        q = "x.allow.example.com"

        pfb_unbound._allow_regex_index = None
        buckets, always = _build_regex_index(db)
        pfb_unbound._allow_regex_index = (db, buckets, always)

        # Simulate eviction
        db.pop("allow_strong")

        result = _scan_allow_regex_band(q, db)
        assert result == 0

    def test_allow_scan_empty_query_returns_zero(self) -> None:
        """Empty q_name must always return 0 (guard at function entry)."""
        db = self._allow_db()
        pfb_unbound._allow_regex_index = None
        assert _scan_allow_regex_band("", db) == 0
