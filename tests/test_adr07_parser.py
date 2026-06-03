"""ADR-07 Phase 4 -- production Stage-A ABP parser (``pfb_unbound.parse_abp``).

WHAT THIS PINS
--------------
``parse_abp(line, *, provenance, feed, group, log) -> Rule | None`` is the full
DNS-only ABP line parser: one raw ABP line -> a typed ``Rule`` (or ``None`` to
skip). It is PURE + ADDITIVE this phase (NOT wired into ``build()`` / init); the
reconcile / reduce / emit stages are later phases. The canonical TARGET is the
Phase-2 oracle (``tests/test_adr07_decision_spec.py::parse_abp_line``); this suite
asserts production agrees with it on SCOPE (in / out) and core fields, and pins
every KEEP / SKIP class, ``$options`` keep/skip, ``$important`` / ``$badfilter``
flag-setting, provenance plumbing, IP-anchor skip, and the reducible-vs-
irreducible regex TAG (just the classification -- reduction itself is Phase 5).

Pure pytest, stdlib only, no Unbound symbols (CI-runnable; ADR.md fact 4).
"""

from __future__ import annotations

import importlib.util
import os

import pytest

import pfb_unbound as P
from tests import test_adr07_decision_spec as spec

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _spike():
    spike_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "spike_adr07_regex.py")
    s = importlib.util.spec_from_file_location("spike_adr07_regex", spike_path)
    assert s and s.loader
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _corpus_lines() -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    lines: list[str] = []
    for fn in ("abp_sample.txt", "regex_reducible.txt", "regex_irreducible.txt"):
        with open(os.path.join(base, fn), encoding="utf-8") as fh:
            lines += fh.read().splitlines()
    return lines


def _reducible_lines() -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    with open(os.path.join(base, "regex_reducible.txt"), encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("!")]


def _irreducible_lines() -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    with open(os.path.join(base, "regex_irreducible.txt"), encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("!")]


# Spike category -> is this line an in-scope DNS decision (parse_abp != None)?
# (Mirrors the Phase-2 oracle's table; $badfilter parses to a Rule but emits no
# decision after reconcile, so it is in-scope-as-a-Rule and checked separately.)
_IN_SCOPE = {"block", "block_important", "block_dns_opts", "allow", "hosts", "plain", "regex_block", "regex_allow"}
_OUT_OF_SCOPE = {
    "comment",
    "element_hiding",
    "path_url",
    "page_context_opts",
    "non_dns_modifier",
    "ip_anchored",
    "other",
}


# --------------------------------------------------------------------------- #
# 1. BLOCK domain: ||domain^ , hosts , plain
# --------------------------------------------------------------------------- #


class TestBlockDomain:
    def test_pipe_anchor(self) -> None:
        r = P.parse_abp("||ads.example.com^")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_BLOCK
        assert r.target == P.RULE_TARGET_DOMAIN
        assert r.key_or_pattern == "ads.example.com"
        assert r.wildcard is True
        assert r.important is False and r.badfilter is False
        assert r.signature == ("ads.example.com", ())

    def test_pipe_anchor_no_separator(self) -> None:
        # ||domain with no ^ and no path is still a host anchor in ABP.
        r = P.parse_abp("||no-sep.example")
        assert r is not None and r.key_or_pattern == "no-sep.example" and r.wildcard is True

    def test_pipe_anchor_uppercase_lowered(self) -> None:
        r = P.parse_abp("||ADS.Example.COM^")
        assert r is not None and r.key_or_pattern == "ads.example.com"

    def test_hosts_zero_sink(self) -> None:
        r = P.parse_abp("0.0.0.0 tracker.host.example")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_BLOCK and r.target == P.RULE_TARGET_DOMAIN
        assert r.key_or_pattern == "tracker.host.example" and r.wildcard is True

    def test_hosts_loopback_sink(self) -> None:
        r = P.parse_abp("127.0.0.1 metrics.host.example")
        assert r is not None and r.key_or_pattern == "metrics.host.example"

    def test_plain_bare_domain(self) -> None:
        r = P.parse_abp("plain.bad.example")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_BLOCK and r.target == P.RULE_TARGET_DOMAIN
        assert r.key_or_pattern == "plain.bad.example" and r.wildcard is True

    def test_plain_leading_dot_stripped(self) -> None:
        r = P.parse_abp(".wildcardish.org")
        assert r is not None and r.key_or_pattern == "wildcardish.org"


# --------------------------------------------------------------------------- #
# 2. ALLOW domain: @@||domain^
# --------------------------------------------------------------------------- #


class TestAllowDomain:
    def test_at_at_pipe_anchor(self) -> None:
        r = P.parse_abp("@@||cdn.example.com^")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_ALLOW
        assert r.target == P.RULE_TARGET_DOMAIN
        assert r.key_or_pattern == "cdn.example.com"
        assert r.wildcard is True
        assert r.signature == ("cdn.example.com", ())

    def test_at_at_with_important(self) -> None:
        r = P.parse_abp("@@||cdn.example.com^$important")
        assert r is not None and r.kind == P.DNSBL_KIND_ALLOW and r.important is True


# --------------------------------------------------------------------------- #
# 3. REGEX: /re/ (block) , @@/re/ (allow) -- stored raw, NOT compiled/reduced
# --------------------------------------------------------------------------- #


class TestRegex:
    def test_block_regex_raw_inner(self) -> None:
        r = P.parse_abp(r"/ad[0-9]\.example\.com$/")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_BLOCK
        assert r.target == P.RULE_TARGET_REGEX
        assert r.key_or_pattern == r"ad[0-9]\.example\.com$"  # raw, unparsed
        assert r.signature == (r"ad[0-9]\.example\.com$", ())

    def test_allow_regex_raw_inner(self) -> None:
        r = P.parse_abp(r"@@/whitelist-[a-z]+\.example$/")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_ALLOW
        assert r.target == P.RULE_TARGET_REGEX
        assert r.key_or_pattern == r"whitelist-[a-z]+\.example$"

    def test_reducible_regex_still_a_regex_target_this_phase(self) -> None:
        # Reduction to a domain/wildcard rule is Phase 5; Stage A keeps it a REGEX.
        r = P.parse_abp(r"/^(.+\.)?doubleclick\.net$/")
        assert r is not None
        assert r.target == P.RULE_TARGET_REGEX
        assert r.key_or_pattern == r"^(.+\.)?doubleclick\.net$"

    def test_regex_inner_not_compiled(self) -> None:
        # A syntactically-broken regex is still ACCEPTED as a raw Rule here (compile
        # / vet is a later phase); parse_abp must not execute or compile it.
        r = P.parse_abp(r"/ad(unbalanced/")
        assert r is not None and r.target == P.RULE_TARGET_REGEX

    def test_block_regex_important(self) -> None:
        r = P.parse_abp(r"/ad[0-9]\.example\.com$/$important")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_BLOCK
        assert r.target == P.RULE_TARGET_REGEX
        assert r.key_or_pattern == r"ad[0-9]\.example\.com$"  # raw, options stripped
        assert r.important is True and r.badfilter is False
        # $important participates in the signature; the pattern stays the key.
        assert r.signature == (r"ad[0-9]\.example\.com$", ("important",))

    def test_block_regex_badfilter(self) -> None:
        r = P.parse_abp(r"/ad[0-9]\.example\.com$/$badfilter")
        assert r is not None
        assert r.target == P.RULE_TARGET_REGEX
        assert r.badfilter is True and r.important is False
        # signature MINUS $badfilter -> the bare pattern, no opts (prunes the plain /re/).
        assert r.signature == (r"ad[0-9]\.example\.com$", ())

    def test_allow_regex_with_options(self) -> None:
        r = P.parse_abp(r"@@/whitelist-[a-z]+\.example$/$important")
        assert r is not None
        assert r.kind == P.DNSBL_KIND_ALLOW
        assert r.target == P.RULE_TARGET_REGEX
        assert r.key_or_pattern == r"whitelist-[a-z]+\.example$"
        assert r.important is True

    def test_block_regex_important_and_badfilter(self) -> None:
        r = P.parse_abp(r"/ad[0-9]\.example$/$important,badfilter")
        assert r is not None
        assert r.important is True and r.badfilter is True
        assert r.signature == (r"ad[0-9]\.example$", ("important",))

    @pytest.mark.parametrize(
        "line",
        [
            r"/track[0-9]\.example$/$third-party",
            r"/track[0-9]\.example$/$dnsrewrite=0.0.0.0",
            r"@@/safe[0-9]\.example$/$domain=foo.com",
            r"/track[0-9]\.example$/$some-future-option",
            r"/track[0-9]\.example$/$important,third-party",  # one bad opt poisons it
        ],
    )
    def test_regex_skip_non_dns_options(self, line: str) -> None:
        # A page-context / non-DNS / unrecognised option skips the WHOLE regex rule,
        # exactly like a domain rule.
        assert P.parse_abp(line) is None, line

    @pytest.mark.parametrize("line", _reducible_lines())
    def test_corpus_reducible_tagged_regex(self, line: str) -> None:
        # The reducible-vs-irreducible TAG: both corpora parse to REGEX targets in
        # Stage A (reduction is Phase 5). This pins the classification flag only.
        r = P.parse_abp(line)
        assert r is not None and r.target == P.RULE_TARGET_REGEX, line

    @pytest.mark.parametrize("line", _irreducible_lines())
    def test_corpus_irreducible_tagged_regex(self, line: str) -> None:
        r = P.parse_abp(line)
        assert r is not None and r.target == P.RULE_TARGET_REGEX, line


# --------------------------------------------------------------------------- #
# 4. $options KEEP vs SKIP
# --------------------------------------------------------------------------- #


class TestOptions:
    def test_keep_important(self) -> None:
        r = P.parse_abp("||promo.example.com^$important")
        assert r is not None
        assert r.important is True and r.badfilter is False
        # $important participates in the signature; $badfilter never does.
        assert r.signature == ("promo.example.com", ("important",))

    def test_keep_badfilter(self) -> None:
        r = P.parse_abp("||gone.example^$badfilter")
        assert r is not None
        assert r.badfilter is True and r.important is False
        # signature MINUS $badfilter -> the bare domain, no opts.
        assert r.signature == ("gone.example", ())

    def test_keep_important_and_badfilter_signature_excludes_badfilter(self) -> None:
        r = P.parse_abp("||x.example^$important,badfilter")
        assert r is not None
        assert r.important is True and r.badfilter is True
        assert r.signature == ("x.example", ("important",))

    @pytest.mark.parametrize(
        "line",
        [
            "||widget.example^$third-party",
            "||script.example^$script",
            "||img.example^$image,third-party",
            "||frame.example^$subdocument",
            "||csp.example^$csp=script-src",
            "||domspecific.example^$domain=foo.com",
            "||rewrite.example^$dnsrewrite=0.0.0.0",
            "||rew.example^$dnstype=AAAA",
            "||cl.example^$client=10.0.0.0/8",
            "||unknown.example^$some-future-option",
            "||mixed.example^$important,third-party",  # one bad opt poisons the rule
        ],
    )
    def test_skip_non_dns_options(self, line: str) -> None:
        assert P.parse_abp(line) is None, line


# --------------------------------------------------------------------------- #
# 5. SKIP-ALWAYS classes
# --------------------------------------------------------------------------- #


class TestSkip:
    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "! Title: comment",
            "[Adblock Plus 2.0]",
            "# plain comment",
            "example.com##.ad-banner",
            "##.global-ad",
            "example.net#@#.whitelisted-ad",
            "example.org#?#div:has(> .ad)",
            "example.com#%#//scriptlet('x')",
            "example.com#$#body { color: red; }",
            "||example.com/ads/*",
            "||cdn.example.net/track.js",
            "/banners/*.gif",
            "||shop.example^/affiliate?id=",
            "||wild.*^",
            "not a domain at all",
        ],
    )
    def test_skip_lines(self, line: str) -> None:
        assert P.parse_abp(line) is None, line

    @pytest.mark.parametrize(
        "line",
        ["||203.0.113.7^", "||198.51.100.42^", "0.0.0.0 203.0.113.99", "127.0.0.1 10.0.0.1"],
    )
    def test_skip_ip_valued_anchors(self, line: str) -> None:
        # IP-valued anchors -> PHP firewall path; Python returns None (no-leak).
        assert P.parse_abp(line) is None, line

    @pytest.mark.parametrize(
        "line",
        ["||-bad.example^", "||bad-.example^", "||no_dot^", "0.0.0.0 -invalid.example"],
    )
    def test_skip_invalid_domain(self, line: str) -> None:
        # normalise() shape gate rejects invalid domains -> None.
        assert P.parse_abp(line) is None, line


# --------------------------------------------------------------------------- #
# 6. PROVENANCE / metadata plumbing
# --------------------------------------------------------------------------- #


class TestProvenance:
    def test_default_provenance_is_feed(self) -> None:
        r = P.parse_abp("||a.example^")
        assert r is not None and r.provenance == P.RULE_PROV_FEED
        assert r.feed == "" and r.group == "" and r.log == ""

    def test_user_provenance_plumbed(self) -> None:
        r = P.parse_abp("||a.example^", provenance=P.RULE_PROV_USER)
        assert r is not None and r.provenance == P.RULE_PROV_USER

    def test_metadata_plumbed_through(self) -> None:
        r = P.parse_abp(
            "@@||b.example^$important",
            provenance=P.RULE_PROV_USER,
            feed="MyFeed",
            group="MyGroup",
            log="2",
        )
        assert r is not None
        assert r.provenance == P.RULE_PROV_USER
        assert r.feed == "MyFeed" and r.group == "MyGroup" and r.log == "2"

    def test_metadata_plumbed_on_regex(self) -> None:
        r = P.parse_abp(r"/irr[0-9]+\.example$/", feed="F", group="G", log="1")
        assert r is not None and r.feed == "F" and r.group == "G" and r.log == "1"


# --------------------------------------------------------------------------- #
# 7. PURITY: no Unbound symbol, no mutation, frozen Rule
# --------------------------------------------------------------------------- #


class TestPurity:
    def test_rule_is_frozen(self) -> None:
        import dataclasses

        r = P.parse_abp("||a.example^")
        assert r is not None
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.kind = P.DNSBL_KIND_ALLOW  # type: ignore[misc]

    def test_parse_does_not_touch_module_globals(self) -> None:
        # parse_abp is pure -- the matcher DBs are untouched (not wired into build).
        before = (dict(P.dataDB), dict(P.zoneDB))
        P.parse_abp("||pure.example^")
        P.parse_abp(r"/re[0-9]+\.example$/")
        assert (dict(P.dataDB), dict(P.zoneDB)) == before


# --------------------------------------------------------------------------- #
# 8. AGREEMENT with the Phase-2 oracle + the Phase-1 spike (anti-drift)
# --------------------------------------------------------------------------- #


class TestSpecAgreement:
    @pytest.mark.parametrize("line", _corpus_lines())
    def test_scope_agrees_with_spike(self, line: str) -> None:
        """Production parse_abp's in-scope verdict matches the Phase-1 spike's
        categoriser on every corpus line (RESULTS-P1 SS6). $badfilter lines DO
        parse to a Rule (badfilter=True) -- scope-exempt, checked separately."""
        spike = _spike()
        cat = spike.categorise(line)
        rule = P.parse_abp(line)
        if cat == "badfilter":
            assert rule is not None and rule.badfilter is True, line
            return
        if cat in _IN_SCOPE:
            assert rule is not None, f"{cat}: {line!r} should be in DNS scope"
        elif cat in _OUT_OF_SCOPE:
            assert rule is None, f"{cat}: {line!r} should be skipped"
        else:
            pytest.fail(f"unhandled spike category {cat!r} for {line!r}")

    @pytest.mark.parametrize("line", _corpus_lines())
    def test_scope_agrees_with_oracle(self, line: str) -> None:
        """Production parse_abp agrees with the Phase-2 oracle parse_abp_line on
        in-scope-vs-skip for every corpus line. (The oracle REDUCES reducible
        regex to a DOMAIN target at parse time; production defers that to Phase 5,
        so only the in/out verdict -- not the target -- is compared here.)"""
        oracle = spec.parse_abp_line(line, spec.Provenance.FEED)
        prod = P.parse_abp(line)
        assert (oracle is None) == (prod is None), line

    @pytest.mark.parametrize(
        "line,kind,important,badfilter",
        [
            ("||a.example^", "block", False, False),
            ("@@||a.example^", "allow", False, False),
            ("||a.example^$important", "block", True, False),
            ("@@||a.example^$important", "allow", True, False),
            ("||a.example^$badfilter", "block", False, True),
            ("0.0.0.0 a.example", "block", False, False),
            ("a.example", "block", False, False),
        ],
    )
    def test_core_fields_match_oracle(self, line: str, kind: str, important: bool, badfilter: bool) -> None:
        oracle = spec.parse_abp_line(line, spec.Provenance.FEED)
        prod = P.parse_abp(line)
        assert oracle is not None and prod is not None
        assert prod.kind == kind
        assert prod.important is important
        assert prod.badfilter is badfilter
        # domain key + wildcard + signature match the oracle for domain rules
        assert prod.key_or_pattern == oracle.key
        assert prod.wildcard == oracle.wildcard
        assert prod.signature == oracle.signature
