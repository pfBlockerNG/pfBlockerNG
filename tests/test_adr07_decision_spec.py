"""ADR-07 Phase 2 -- ABP DNS-only decision SPEC + golden oracle (the TARGET).

WHY THIS FILE EXISTS
--------------------
Unlike ADR-06, ADR-07 has **no existing-code oracle**. The thing we are replacing
-- the PHP ``$easylist`` lite parser (``pfblockerng.inc:7781-7833``) and its
Python mirror ``_dnsbl_parse_abp_line`` (``pfb_unbound.py:1768-1780``) -- is the
*buggy* artefact: it keeps only ``||domain^`` blocks and silently DROPS ``@@``
exceptions, regex (block + allow), ``$options`` and ABP precedence
(``$important`` / ``$badfilter``). That over-blocking is the bug ADR-07 fixes
(ADR.md SS1), so the old behaviour cannot define "correct".

This module therefore AUTHORS the target: the ABP DNS-only decision semantics as
a pure reference oracle + a committed decision table, derived from the ABP /
AdGuard references (ADR.md References) and Phase-1's inventory + corpus
(``RESULTS/01_Results.txt`` SS1c/SS1f, SS2). Every later phase (4 parser, 5
reconcile, 6 emit/matcher) diffs its PRODUCTION output against this table; here
the oracle asserts against its own expected table (self-consistent now).

WHAT THE ORACLE ENCODES (mirrors ADR.md SS2 + RESULTS SS1c/SS1f)
----------------------------------------------------------------
  * Parse: ``parse_abp_line(line, provenance) -> Rule | None`` -- the full
    DNS-only ABP grammar. In scope: ``||domain^``(+DNS-opts), ``@@||domain^``,
    plain ``domain``, hosts ``IP domain``, ``/re/`` (block), ``@@/re/`` (allow).
    Skipped (returns None): element-hiding (``##`` / ``#@#`` / ``#?#``),
    path / URL rules, page-context ``$options`` (``$third-party`` / ``$domain=``
    / ``$script`` / ``$image`` / ``$csp`` / ``$subdocument`` ...), non-DNS
    AdGuard modifiers whose ONLY effect is a rewrite (``$dnsrewrite`` /
    ``$dnstype`` / ``$client`` / ``$ctag``), and IP-valued anchors (those go to
    the PHP firewall pass -- Python returns None, the no-leak contract).
  * Reconcile: feed-only ``$badfilter`` prune (signature = pattern + sorted
    DNS-options, minus ``$badfilter``); anchored-regex REDUCTION to a
    domain/wildcard rule (so a reducible ``/re/`` decides IDENTICALLY to its
    dict form); priority bands (RESULTS SS1f).
  * Decide: ``decide(rules, query) -> Decision`` -- the 6-band numeric
    resolution. One scale, highest wins; blocked iff a block matches AND
    block_prio > allow_prio (no ties; block in {1,3,5}, allow in {2,4,6}).

PRECEDENCE BANDS (RESULTS SS1f; ADR.md SS2 "Precedence")
  6  user allow            (sovereign; $badfilter-immune)
  5  user block            (sovereign; $badfilter-immune)
  4  feed allow + $important
  3  feed block + $important
  2  feed allow (@@)
  1  feed block (||)
TOP1M (when enabled) behaves as a user allow (band 6).

CHOSEN INTERPRETATIONS (references are DNS-ambiguous; recorded here + in the
handoff so Phases 4-6 implement the same thing):
  * Plain bare ``domain`` (no ``||``/``^``) is a DOMAIN BLOCK covering the domain
    AND its subdomains (AdGuardHome hosts-blocklist adblock-style; matches the
    current plain/hosts path which classifies a registrable parent to a wildcard
    zone). ``hosts`` ``IP domain`` is identical (the IP is the sink, ignored).
  * ``||domain^`` covers the domain and all subdomains (ABP ``^`` separator +
    ``||`` host-anchor). ``@@||domain^`` un-blocks the domain and subdomains.
  * Reducible regex folds to the SAME shape as its literal form: ``^(.+\\.)?D$``
    / ``(^|\\.)D$`` -> wildcard (domain + subs); ``^D$`` / ``^(www\\.)?D$`` ->
    exact (domain only). Mirrors ``benchmarks/spike_adr07_regex.reduce_pattern``.
  * Irreducible regex matches the query string as written (``re.search`` over the
    full query name), block or ``@@`` allow.
  * ``$important`` raises a feed rule from band 1/2 to 3/4 (inverts allow-vs-block
    WITHIN the feed: a feed ``||x^$important`` (3) beats a feed ``@@x^`` (2)).
  * ``$badfilter`` is feed-only and removes the matching FEED rule by signature;
    the ``$badfilter`` rule itself never blocks. A user rule with the same
    signature is NOT pruned (sovereignty).

This is pure Python, stdlib only, no Unbound symbols -- CI-runnable with no live
Unbound (ADR.md fact 4). Decisions, not list contents, are the contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import ModuleType
from typing import Iterable

import pytest

# --------------------------------------------------------------------------- #
# Rule model (mirrors RESULTS SS1c / ADR.md SS2 "Intermediate Rule model").
#
# parse('abp', line) -> Rule | None in production (Phase 4). Here the pure
# reference parser produces the same shape so the decision table is authored
# against the real input model.
# --------------------------------------------------------------------------- #


class Kind(Enum):
    BLOCK = "block"
    ALLOW = "allow"


class Target(Enum):
    DOMAIN = "domain"  # exact-or-wildcard domain key
    REGEX = "regex"  # irreducible compiled pattern


class Provenance(Enum):
    USER = "user"
    FEED = "feed"


@dataclass(frozen=True)
class Rule:
    """A typed ABP rule (DNS-only). ``key`` is the domain literal for DOMAIN
    targets (with ``wildcard`` saying whether subdomains are covered) or the
    regex inner pattern for REGEX targets. ``signature`` is the $badfilter match
    key (pattern + sorted DNS-options, minus $badfilter)."""

    kind: Kind
    target: Target
    key: str
    provenance: Provenance
    wildcard: bool = False
    important: bool = False
    badfilter: bool = False
    options: tuple[str, ...] = ()
    signature: tuple[str, tuple[str, ...]] = ("", ())


# --------------------------------------------------------------------------- #
# DNS-scope option classification (ADR.md SS2 "Scope").
# --------------------------------------------------------------------------- #
# Options that DO modify a DNS block/allow decision (kept):
_DNS_RELEVANT_OPTS = frozenset({"important", "badfilter"})
# Options that imply a page/element context, never a DNS decision (-> SKIP rule):
_PAGE_CONTEXT_OPTS = frozenset(
    {
        "third-party",
        "~third-party",
        "domain",  # $domain=...
        "script",
        "image",
        "stylesheet",
        "object",
        "subdocument",
        "document",
        "xmlhttprequest",
        "websocket",
        "ping",
        "media",
        "font",
        "popup",
        "csp",
        "elemhide",
        "generichide",
        "genericblock",
        "rewrite",  # $rewrite= (response rewriting, not a DNS decision)
    }
)
# AdGuard DNS modifiers whose ONLY effect is a rewrite, not block/allow (-> SKIP):
_NON_DNS_MODIFIERS = frozenset({"dnsrewrite", "dnstype", "client", "ctag"})


def _opt_name(opt: str) -> str:
    """Bare option name (drop a '=value' tail and a leading '~')."""
    name = opt.split("=", 1)[0].strip()
    return name


def _is_ipv4(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255) or (len(p) > 1 and p[0] == "0"):
            return False
    return True


# Underscore allowed (#723): parity with production _DNSBL_LABEL_CHARS and PHP's
# PFB_FILTER_DOMAIN — DNS labels carry no protocol charset (RFC 2181 s11).
_DOMAIN_RE = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")


def _valid_domain(host: str) -> str | None:
    host = host.strip().strip(".").lower()
    if not _DOMAIN_RE.match(host):
        return None
    for label in host.split("."):
        if not label or label[0] == "-" or label[-1] == "-":
            return None
    return host


# --------------------------------------------------------------------------- #
# Regex reduction grammar (mirrors benchmarks/spike_adr07_regex.reduce_pattern).
# A reducible /re/ decides IDENTICALLY to a domain/wildcard rule (ADR.md SS2).
# --------------------------------------------------------------------------- #
_DOMAIN_LITERAL = re.compile(r"^[a-z0-9_-]+(?:\\\.[a-z0-9_-]+)+$")  # underscore per #723
_WILDCARD_PREFIXES = (r"^(.+\.)?", r"(^|\.)", r"^(?:.+\.)?")
_EXACT_PREFIXES = (r"^",)


def reduce_regex(inner: str) -> tuple[bool, str] | None:
    """Return ``(wildcard, domain)`` if the regex body folds, else None.

    ``wildcard`` True -> domain + subdomains (zone); False -> exact (data).
    """
    if not inner.endswith("$"):
        return None
    body = inner[:-1]
    for pre in _WILDCARD_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            if _DOMAIN_LITERAL.match(lit):
                return True, lit.replace("\\.", ".")
            return None
    for pre in _EXACT_PREFIXES:
        if body.startswith(pre):
            lit = body[len(pre) :]
            if lit.startswith(r"(www\.)?"):
                lit = lit[len(r"(www\.)?") :]
            if _DOMAIN_LITERAL.match(lit):
                return False, lit.replace("\\.", ".")
            return None
    return None


# --------------------------------------------------------------------------- #
# The reference parser: parse_abp_line(line, provenance) -> Rule | None.
#
# Pure, no Unbound symbols. Production Phase-4 parse('abp', line) must agree with
# this on every corpus line (RESULTS SS6). Returns None for any line that is not
# an in-scope DNS decision (comment, element-hiding, path/URL, page-context
# option, non-DNS modifier, IP-anchored).
# --------------------------------------------------------------------------- #


def _classify_options(opts_str: str) -> tuple[tuple[str, ...], bool, bool] | None:
    """Parse the ``$options`` tail. Return ``(sorted_dns_opts, important,
    badfilter)`` if EVERY option is DNS-relevant, else None (skip the rule).

    A page-context option or a non-DNS modifier makes the whole rule out of DNS
    scope (a path/element/rewrite being acted on does not imply a DNS decision).
    """
    important = False
    badfilter = False
    kept: list[str] = []
    for raw in opts_str.split(","):
        raw = raw.strip()
        if not raw:
            continue
        name = _opt_name(raw)
        if name in _PAGE_CONTEXT_OPTS or name in _NON_DNS_MODIFIERS:
            return None
        if name == "important":
            important = True
            continue
        if name == "badfilter":
            badfilter = True
            continue
        # An unrecognised option is treated as out-of-scope (conservative: do not
        # invent a DNS decision for a modifier we do not model).
        return None
    return tuple(sorted(kept)), important, badfilter


def _parse_regex_rule(s: str) -> tuple[Kind, str, str] | None:
    """Recognise ``/re/`` (block) / ``@@/re/`` (allow) with an OPTIONAL ``$options``
    suffix after the closing slash. Return ``(kind, inner, opts_str)`` else None.
    Mirrors prod ``pfb_unbound._dnsbl_parse_abp_regex``."""
    if s.startswith("@@/"):
        kind, body = Kind.ALLOW, s[2:]
    elif s.startswith("/"):
        kind, body = Kind.BLOCK, s
    else:
        return None
    if body.endswith("/"):
        inner, opts_str = body[1:-1], ""
    else:
        marker = body.rfind("/$")
        if marker <= 0:
            return None
        inner, opts_str = body[1:marker], body[marker + 2 :]
    if not inner:
        return None
    return kind, inner, opts_str


def parse_abp_line(line: str, provenance: Provenance) -> Rule | None:
    s = line.strip()
    if not s or s.startswith("!") or s.startswith("["):
        return None
    if s.startswith("#"):
        # plain-feed comment (not element-hiding, which needs a domain## prefix)
        return None
    # element-hiding / cosmetic -> SKIP
    if "##" in s or "#@#" in s or "#?#" in s:
        return None

    # ---- regex rules: /re/ (block) or @@/re/ (allow), optional $options ---- #
    regex_hit = _parse_regex_rule(s)
    if regex_hit is not None:
        kind, inner, opts_str = regex_hit
        if opts_str:
            classified = _classify_options(opts_str)
            if classified is None:
                return None  # page-context / non-DNS / unrecognised -> skip rule
            dns_opts, important, badfilter = classified
        else:
            dns_opts, important, badfilter = (), False, False
        reduced = reduce_regex(inner)
        if reduced is not None:
            wildcard, rdom = reduced
            sig_opts = tuple(o for o in dns_opts) + (("important",) if important else ())
            return Rule(
                kind=kind,
                target=Target.DOMAIN,
                key=rdom,
                provenance=provenance,
                wildcard=wildcard,
                important=important,
                badfilter=badfilter,
                options=dns_opts,
                # A reducible regex folds to a DOMAIN rule for MATCHING, but its
                # $badfilter signature must stay the original regex body (inner): a
                # literal ||domain^$badfilter must NOT prune a reducible regex, and
                # vice-versa. Mirrors production parse_abp (signature=(inner, ...)).
                signature=(inner, tuple(sorted(sig_opts))),
            )
        try:
            re.compile(inner)
        except re.error:
            return None
        sig_opts = tuple(o for o in dns_opts) + (("important",) if important else ())
        return Rule(
            kind=kind,
            target=Target.REGEX,
            key=inner,
            provenance=provenance,
            important=important,
            badfilter=badfilter,
            options=dns_opts,
            signature=(inner, tuple(sorted(sig_opts))),
        )

    # ---- network rules: @@||domain^ (allow) / ||domain^ (block) ---------- #
    is_allow = s.startswith("@@||")
    is_block = s.startswith("||")
    if is_allow or is_block:
        rest = s[4:] if is_allow else s[2:]
        anchor, _, opts_str = rest.partition("$")
        # a path inside the anchor (before/within ^) -> not a whole-domain rule
        host = anchor.split("^", 1)[0]
        tail = anchor.split("^", 1)[1] if "^" in anchor else ""
        if "/" in host or "/" in tail or tail.strip("^"):
            return None
        if "^" not in anchor:
            # ||domain with no ^ and no path -- still a domain anchor in ABP
            host = anchor
        if _is_ipv4(host):
            return None  # IP-anchored -> PHP firewall path; Python skips
        dom = _valid_domain(host)
        if dom is None:
            return None
        if opts_str:
            classified = _classify_options(opts_str)
            if classified is None:
                return None
            dns_opts, important, badfilter = classified
        else:
            dns_opts, important, badfilter = (), False, False
        sig_opts = tuple(o for o in dns_opts) + (("important",) if important else ())
        return Rule(
            kind=Kind.ALLOW if is_allow else Kind.BLOCK,
            target=Target.DOMAIN,
            key=dom,
            provenance=provenance,
            wildcard=True,  # ||domain^ / @@||domain^ cover subdomains
            important=important,
            badfilter=badfilter,
            options=dns_opts,
            signature=(dom, tuple(sorted(sig_opts))),
        )

    # ---- hosts: "<ip> <domain>" ----------------------------------------- #
    if " " in s:
        first, _, target = s.partition(" ")
        target = target.strip()
        if _is_ipv4(first):
            if _is_ipv4(target):
                return None  # 0.0.0.0 <ip> -> firewall path
            dom = _valid_domain(target)
            if dom is None:
                return None
            return Rule(
                kind=Kind.BLOCK,
                target=Target.DOMAIN,
                key=dom,
                provenance=provenance,
                wildcard=True,
                signature=(dom, ()),
            )
        return None

    # ---- bare plain domain ---------------------------------------------- #
    if "/" in s or "*" in s:
        return None
    dom = _valid_domain(s)
    if dom is None:
        return None
    return Rule(
        kind=Kind.BLOCK,
        target=Target.DOMAIN,
        key=dom,
        provenance=provenance,
        wildcard=True,
        signature=(dom, ()),
    )


# --------------------------------------------------------------------------- #
# Reconcile: feed-only $badfilter prune (RESULTS SS1c; ADR.md SS2 "$badfilter").
# --------------------------------------------------------------------------- #


def reconcile(rules: Iterable[Rule]) -> list[Rule]:
    """Drop every FEED rule whose signature matches a FEED ``$badfilter``; drop
    the badfilter rules themselves; keep all USER rules (sovereignty, fact 7)."""
    rules = list(rules)
    bad_sigs = {r.signature for r in rules if r.badfilter and r.provenance is Provenance.FEED}
    out: list[Rule] = []
    for r in rules:
        if r.badfilter:
            continue  # the $badfilter rule never emits a decision
        if r.provenance is Provenance.FEED and r.signature in bad_sigs:
            continue  # pruned by a feed $badfilter
        out.append(r)
    return out


# --------------------------------------------------------------------------- #
# Priority bands + the decision engine (RESULTS SS1f; ADR.md SS2 "Precedence").
# --------------------------------------------------------------------------- #


def priority(rule: Rule) -> int:
    if rule.provenance is Provenance.USER:
        return 6 if rule.kind is Kind.ALLOW else 5
    if rule.important:
        return 4 if rule.kind is Kind.ALLOW else 3
    return 2 if rule.kind is Kind.ALLOW else 1


def _domain_matches(rule: Rule, query: str) -> bool:
    """Does a DOMAIN-target rule match the query name?"""
    q = query.strip(".").lower()
    if q == rule.key:
        return True
    if rule.wildcard and q.endswith("." + rule.key):
        return True
    return False


def _regex_matches(rule: Rule, query: str) -> bool:
    return re.search(rule.key, query.strip(".").lower()) is not None


def _matches(rule: Rule, query: str) -> bool:
    if rule.target is Target.DOMAIN:
        return _domain_matches(rule, query)
    return _regex_matches(rule, query)


@dataclass
class Decision:
    outcome: str  # "block" | "resolve" | "pass"
    block_prio: int = 0
    allow_prio: int = 0
    winner: Rule | None = field(default=None)


def decide(rules: Iterable[Rule], query: str) -> Decision:
    """The 6-band resolution. Reconcile (badfilter) first, then for the query
    take the highest-priority matching block and the highest-priority matching
    allow; blocked iff a block matches AND block_prio > allow_prio.

    "pass" = nothing matched. "resolve" = something matched but an allow wins (or
    nothing blocks). "block" = a block wins.
    """
    rules = reconcile(rules)
    best_block: Rule | None = None
    best_allow: Rule | None = None
    bp = 0
    ap = 0
    for r in rules:
        if not _matches(r, query):
            continue
        p = priority(r)
        if r.kind is Kind.BLOCK:
            if p > bp:
                bp, best_block = p, r
        else:
            if p > ap:
                ap, best_allow = p, r
    if best_block is None and best_allow is None:
        return Decision("pass")
    if best_block is not None and bp > ap:
        return Decision("block", bp, ap, best_block)
    # an allow matched (and no block, or allow wins) -> resolves
    return Decision("resolve", bp, ap, best_allow or best_block)


# --------------------------------------------------------------------------- #
# Helper: build a rule set from raw lines + a provenance.
# --------------------------------------------------------------------------- #


def rules_from(lines: Iterable[str], provenance: Provenance = Provenance.FEED) -> list[Rule]:
    out: list[Rule] = []
    for ln in lines:
        r = parse_abp_line(ln, provenance)
        if r is not None:
            out.append(r)
    return out


# =========================================================================== #
# THE GOLDEN DECISION TABLE (committed, human-readable).
#
# Each case: (named rule-set, query) -> expected outcome [+ optional winner
# provenance/kind]. This IS the contract every later phase diffs against.
# =========================================================================== #


# --- 1. BLOCK shapes: ||domain^, hosts, plain ------------------------------ #
def test_block_pipe_anchor_domain_and_subdomain() -> None:
    rs = rules_from(["||ads.example.com^"])
    assert decide(rs, "ads.example.com").outcome == "block"
    assert decide(rs, "deep.ads.example.com").outcome == "block"  # ^ covers subs
    assert decide(rs, "notads.example.com").outcome == "pass"
    assert decide(rs, "example.com").outcome == "pass"


def test_block_hosts_line() -> None:
    rs = rules_from(["0.0.0.0 tracker.hostsfmt.example", "127.0.0.1 metrics.hostsfmt.example"])
    assert decide(rs, "tracker.hostsfmt.example").outcome == "block"
    assert decide(rs, "sub.metrics.hostsfmt.example").outcome == "block"
    assert decide(rs, "other.example").outcome == "pass"


def test_block_plain_domain() -> None:
    rs = rules_from(["plain.bad.example"])
    assert decide(rs, "plain.bad.example").outcome == "block"
    assert decide(rs, "x.plain.bad.example").outcome == "block"  # plain => +subs
    assert decide(rs, "good.example").outcome == "pass"


# --- 2. ALLOW: @@||domain^ globally un-blocks ------------------------------ #
def test_allow_exception_unblocks_global() -> None:
    rs = rules_from(["||example.com^", "@@||cdn.example.com^"])
    assert decide(rs, "example.com").outcome == "block"
    assert decide(rs, "www.example.com").outcome == "block"
    # the @@ carve-back resolves the exempted name + its subs (the bug ADR fixes)
    assert decide(rs, "cdn.example.com").outcome == "resolve"
    assert decide(rs, "img.cdn.example.com").outcome == "resolve"


def test_allow_beats_block_same_band() -> None:
    # feed allow (2) > feed block (1): today's "allow overrides block" semantics.
    rs = rules_from(["||x.example^", "@@||x.example^"])
    d = decide(rs, "x.example")
    assert d.outcome == "resolve"
    assert d.allow_prio == 2 and d.block_prio == 1


# --- 3. REGEX REDUCIBLE: identical decision to its dict/wildcard form ------ #
def test_regex_reducible_wildcard_equals_zone() -> None:
    rs_regex = rules_from([r"/^(.+\.)?doubleclick\.net$/"])
    rs_dict = rules_from(["||doubleclick.net^"])
    for q in ("doubleclick.net", "ad.doubleclick.net", "x.y.doubleclick.net", "notdoubleclick.net"):
        assert decide(rs_regex, q).outcome == decide(rs_dict, q).outcome
    # spot-check the absolute values
    assert decide(rs_regex, "ad.doubleclick.net").outcome == "block"
    assert decide(rs_regex, "notdoubleclick.net").outcome == "pass"


def test_regex_reducible_alt_anchor_is_wildcard() -> None:
    rs = rules_from([r"/(^|\.)adnxs\.com$/"])
    assert decide(rs, "adnxs.com").outcome == "block"
    assert decide(rs, "ib.adnxs.com").outcome == "block"
    assert decide(rs, "badnxs.com").outcome == "pass"  # not a label boundary


def test_regex_reducible_exact_equals_data() -> None:
    rs_regex = rules_from([r"/^pixel\.example\.com$/"])
    assert decide(rs_regex, "pixel.example.com").outcome == "block"
    # exact form does NOT cover subdomains (data, not zone)
    assert decide(rs_regex, "sub.pixel.example.com").outcome == "pass"
    # and it is byte-equal to the plain-anchored literal data rule's decision
    rs_dict = [
        Rule(Kind.BLOCK, Target.DOMAIN, "pixel.example.com", Provenance.FEED, wildcard=False),
    ]
    for q in ("pixel.example.com", "sub.pixel.example.com"):
        assert decide(rs_regex, q).outcome == decide(rs_dict, q).outcome


def test_regex_reducible_allow_folds_to_whitelist() -> None:
    rs = rules_from(["||example.com^", r"@@/^(.+\.)?cdn\.example\.com$/"])
    assert decide(rs, "example.com").outcome == "block"
    assert decide(rs, "cdn.example.com").outcome == "resolve"
    assert decide(rs, "a.cdn.example.com").outcome == "resolve"


# --- 4. REGEX IRREDUCIBLE: matches as written ------------------------------ #
def test_regex_irreducible_block_matches_as_written() -> None:
    rs = rules_from([r"/ad[0-9]\.example\.com$/"])
    assert any(r.target is Target.REGEX for r in rs)
    assert decide(rs, "ad7.example.com").outcome == "block"
    assert decide(rs, "ads.example.com").outcome == "pass"  # 's' is not [0-9]


def test_regex_irreducible_substring_unanchored() -> None:
    rs = rules_from([r"/\.doubleclick\./"])
    assert decide(rs, "ad.doubleclick.net").outcome == "block"  # substring search
    assert decide(rs, "doubleclick.net").outcome == "pass"  # no leading dot


def test_regex_irreducible_allow_matches_as_written() -> None:
    rs = rules_from(["||ads.test^", r"@@/whitelist-[a-z]+\.example$/"])
    assert decide(rs, "unrelated.example").outcome == "pass"  # neither rule matches
    # an irreducible @@ allow un-blocks a name another rule blocks
    rs2 = rules_from([r"/[a-z0-9]+\.example$/", r"@@/whitelist-[a-z]+\.example$/"])
    assert decide(rs2, "ads.example").outcome == "block"
    assert decide(rs2, "whitelist-foo.example").outcome == "resolve"


def test_regex_important_block_beats_allow_regex() -> None:
    # $options now apply to regex too: a block /re/$important (band 3) beats a plain
    # allow @@/re/ (band 2). Without $important the allow would win.
    rs = rules_from([r"/x[0-9]\.example$/$important", r"@@/x[0-9]\.example$/"])
    d = decide(rs, "x7.example")
    assert d.outcome == "block"
    assert d.block_prio == 3 and d.allow_prio == 2
    # sanity: drop $important and the allow wins
    rs_plain = rules_from([r"/x[0-9]\.example$/", r"@@/x[0-9]\.example$/"])
    assert decide(rs_plain, "x7.example").outcome == "resolve"


def test_regex_badfilter_prunes_matching_feed_regex() -> None:
    # A feed /re/$badfilter removes the matching feed /re/ (same signature) -> resolve.
    rs = rules_from([r"/x[0-9]\.example$/", r"/x[0-9]\.example$/$badfilter"])
    assert decide(rs, "x7.example").outcome == "pass"


# --- 5. $options KEEP vs SKIP ---------------------------------------------- #
def test_options_skip_page_context_and_non_dns() -> None:
    skipped = [
        "||widget.example^$third-party",
        "||script.example^$script",
        "||img.example^$image,third-party",
        "||frame.example^$subdocument",
        "||csp.example^$csp=script-src",
        "||domspecific.example^$domain=foo.com",
        "||rewrite.example^$dnsrewrite=0.0.0.0",
        "example.com##.ad-banner",
        "##.global-ad",
        "example.net#@#.whitelisted-ad",
        "example.org#?#div:has(> .ad)",
        "||example.com/ads/*",
        "||cdn.example.net/track.js",
        "/banners/*.gif",
        "||shop.example^/affiliate?id=",
    ]
    for line in skipped:
        assert parse_abp_line(line, Provenance.FEED) is None, line
    # none of them create a DNS decision
    rs = rules_from(skipped)
    assert rs == []


def test_options_keep_dns_relevant() -> None:
    # $important / $badfilter are DNS-relevant (modify precedence) -> KEEP.
    assert parse_abp_line("||promo.example.com^$important", Provenance.FEED) is not None
    assert parse_abp_line("||gone.example^$badfilter", Provenance.FEED) is not None


def test_ip_anchored_skipped_python_side() -> None:
    # IP-valued anchors go to the PHP firewall pass; Python returns None (no leak).
    for line in ("||203.0.113.7^", "||198.51.100.42^", "0.0.0.0 203.0.113.99"):
        assert parse_abp_line(line, Provenance.FEED) is None, line


# --- 6. $important inverts allow-vs-block WITHIN the feed band -------------- #
def test_important_block_beats_feed_allow() -> None:
    rs = rules_from(["@@||x.example^", "||x.example^$important"])
    d = decide(rs, "x.example")
    assert d.outcome == "block"  # block(3, important) > allow(2)
    assert d.block_prio == 3 and d.allow_prio == 2


def test_important_allow_beats_feed_block() -> None:
    rs = rules_from(["||y.example^", "@@||y.example^$important"])
    d = decide(rs, "y.example")
    assert d.outcome == "resolve"  # allow(4, important) > block(1)
    assert d.allow_prio == 4 and d.block_prio == 1


def test_important_allow_beats_important_block() -> None:
    rs = rules_from(["||z.example^$important", "@@||z.example^$important"])
    d = decide(rs, "z.example")
    # block(3) vs allow(4): allow wins (4>3) -- the higher band always wins.
    assert d.outcome == "resolve"
    assert d.allow_prio == 4 and d.block_prio == 3


# --- 7. $badfilter removes the matching FEED rule (feed-only) --------------- #
def test_badfilter_removes_feed_block() -> None:
    rs = rules_from(["||gone.example^", "||gone.example^$badfilter"])
    # the badfiltered block is pruned; nothing blocks -> the name resolves.
    assert decide(rs, "gone.example").outcome == "pass"
    # the $badfilter rule itself does not block
    assert all(not (r.badfilter) for r in reconcile(rs))


def test_badfilter_signature_is_pattern_plus_sorted_opts() -> None:
    # $badfilter only removes a rule with the SAME signature (pattern+opts minus
    # $badfilter). A different option -> different signature -> NOT pruned.
    rs = rules_from(["||keep.example^$important", "||keep.example^$badfilter"])
    # signatures differ (important vs none) -> the important block survives.
    assert decide(rs, "keep.example").outcome == "block"
    # matched signature DOES prune:
    rs2 = rules_from(["||keep.example^$important", "||keep.example^$important,badfilter"])
    assert decide(rs2, "keep.example").outcome == "pass"


def test_badfilter_does_not_remove_user_rule() -> None:
    user = rules_from(["||sovereign.example^"], Provenance.USER)
    feed_bad = rules_from(["||sovereign.example^$badfilter"], Provenance.FEED)
    assert decide(user + feed_bad, "sovereign.example").outcome == "block"


# --- 8. PROVENANCE / SOVEREIGNTY bands (fact 7) ---------------------------- #
def test_user_allow_beats_everything() -> None:
    rs = (
        rules_from(["||a.example^$important"], Provenance.FEED)
        + rules_from(["@@||a.example^"], Provenance.USER)  # user allow = band 6
    )
    d = decide(rs, "a.example")
    assert d.outcome == "resolve"
    assert d.allow_prio == 6


def test_user_block_beats_feed_important_allow() -> None:
    rs = (
        rules_from(["@@||b.example^$important"], Provenance.FEED)  # band 4
        + rules_from(["||b.example^"], Provenance.USER)  # user block = band 5
    )
    d = decide(rs, "b.example")
    assert d.outcome == "block"
    assert d.block_prio == 5 and d.allow_prio == 4


def test_full_band_ordering() -> None:
    # one query, one rule per band, assert the exact winner per priority scale.
    bands = {
        6: Rule(Kind.ALLOW, Target.DOMAIN, "q.example", Provenance.USER, wildcard=True),
        5: Rule(Kind.BLOCK, Target.DOMAIN, "q.example", Provenance.USER, wildcard=True),
        4: Rule(Kind.ALLOW, Target.DOMAIN, "q.example", Provenance.FEED, wildcard=True, important=True),
        3: Rule(Kind.BLOCK, Target.DOMAIN, "q.example", Provenance.FEED, wildcard=True, important=True),
        2: Rule(Kind.ALLOW, Target.DOMAIN, "q.example", Provenance.FEED, wildcard=True),
        1: Rule(Kind.BLOCK, Target.DOMAIN, "q.example", Provenance.FEED, wildcard=True),
    }
    for p, r in bands.items():
        assert priority(r) == p
    # full stack -> band 6 (user allow) wins -> resolve
    assert decide(list(bands.values()), "q.example").outcome == "resolve"
    # drop band 6 -> band 5 (user block) wins -> block
    assert decide([bands[b] for b in (5, 4, 3, 2, 1)], "q.example").outcome == "block"
    # feed-only important: 4 (allow) beats 3 (block) -> resolve
    assert decide([bands[b] for b in (4, 3, 2, 1)], "q.example").outcome == "resolve"
    # plain feed: 2 (allow) beats 1 (block) -> resolve
    assert decide([bands[b] for b in (2, 1)], "q.example").outcome == "resolve"
    # feed block alone -> block
    assert decide([bands[1]], "q.example").outcome == "block"


def test_top1m_behaves_as_user_allow() -> None:
    # TOP1M (enabled) entries are modelled as user allows (band 6).
    top1m = [Rule(Kind.ALLOW, Target.DOMAIN, "popular.example", Provenance.USER, wildcard=False)]
    feed = rules_from(["||popular.example^$important"], Provenance.FEED)
    assert decide(top1m + feed, "popular.example").outcome == "resolve"


# --- 9. NO-REGRESSION anchor: non-ABP set == ADR-06 decisions -------------- #
# A plain/hosts set with NO @@/regex/important/badfilter must decide exactly as
# the ADR-06 oracle's plain/hosts semantics: a block matches the name and its
# subdomains (registrable-parent wildcard); unrelated names pass; an allow only
# un-blocks. Here every block is band-1, no allow -> block-or-pass, never the
# new precedence machinery.
def test_no_regression_plain_hosts_only() -> None:
    rs = rules_from(
        [
            "||malware.com^",
            "0.0.0.0 tracker.org",
            "plain.bad.example",
        ]
    )
    assert all(r.provenance is Provenance.FEED and not r.important and not r.badfilter for r in rs)
    assert all(r.kind is Kind.BLOCK for r in rs)
    # blocked names (+ subdomains)
    for q in ("malware.com", "www.malware.com", "tracker.org", "x.tracker.org", "plain.bad.example"):
        d = decide(rs, q)
        assert d.outcome == "block" and d.block_prio == 1 and d.allow_prio == 0
    # pass-through
    for q in ("good.net", "cleandata.com", "totally-unrelated.com"):
        assert decide(rs, q).outcome == "pass"


def test_no_regression_no_important_rules_flag() -> None:
    # The build-time fast-path flag (ADR.md SS2 "Query-time matcher"): a set with
    # no @@/regex/important/badfilter carries important_rules == False, so the
    # production matcher keeps today's early-exit path. Modelled here as: no rule
    # lands above band 1.
    rs = rules_from(["||a.com^", "0.0.0.0 b.org", "c.plain.example"])
    assert max(priority(r) for r in rs) == 1
    assert not any(r.important or r.badfilter or r.kind is Kind.ALLOW for r in rs)


# --- 10. corpus agreement: the spec parser agrees with the Phase-1 spike ---- #
def _spike() -> ModuleType:
    import importlib.util
    import os

    spike_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "spike_adr07_regex.py")
    spec = importlib.util.spec_from_file_location("spike_adr07_regex", spike_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _corpus_lines() -> list[str]:
    import os

    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    lines: list[str] = []
    for fn in ("abp_sample.txt", "regex_reducible.txt", "regex_irreducible.txt"):
        with open(os.path.join(base, fn), encoding="utf-8") as fh:
            lines += fh.read().splitlines()
    return lines


# Spike category -> is this line an in-scope DNS decision (parse_abp_line != None)?
_IN_SCOPE = {"block", "block_important", "block_dns_opts", "allow", "hosts", "plain", "regex_block", "regex_allow"}
_OUT_OF_SCOPE = {
    "comment",
    "element_hiding",
    "path_url",
    "page_context_opts",
    "non_dns_modifier",
    "ip_anchored",
    "badfilter",  # parses to a Rule but reconcile drops it; see note below
    "other",
}


@pytest.mark.parametrize("line", _corpus_lines())
def test_spec_parser_agrees_with_spike_scope(line: str) -> None:
    """The reference parser's in-scope verdict agrees with the Phase-1 spike's
    categoriser (RESULTS SS6: Phase-2 spec must agree with the spike). $badfilter
    lines DO parse to a Rule (with badfilter=True) but emit no decision after
    reconcile -- so they are scope-agreement-exempt and checked separately."""
    spike = _spike()
    cat = spike.categorise(line)
    rule = parse_abp_line(line, Provenance.FEED)
    if cat == "badfilter":
        assert rule is not None and rule.badfilter is True
        return
    if cat in _IN_SCOPE:
        assert rule is not None, f"{cat}: {line!r} should be in DNS scope"
    elif cat in _OUT_OF_SCOPE:
        assert rule is None, f"{cat}: {line!r} should be skipped"
    else:
        pytest.fail(f"unhandled spike category {cat!r} for {line!r}")


def test_spec_reduction_agrees_with_spike() -> None:
    """A reducible regex folds in the spec exactly when the spike folds it, to the
    same domain (the reduction grammar is shared, RESULTS SS3a)."""
    spike = _spike()
    base = __import__("os").path.join(__import__("os").path.dirname(__file__), "fixtures", "adr07_corpus")
    with open(__import__("os").path.join(base, "regex_reducible.txt"), encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("!")]
    for ln in lines:
        spike_red = spike.reduce_pattern(ln)
        rule = parse_abp_line(ln, Provenance.FEED)
        assert rule is not None
        # every reducible line folds to a DOMAIN rule (never an irreducible regex)
        assert rule.target is Target.DOMAIN, ln
        assert spike_red is not None, ln
        kind, dom = spike_red
        assert rule.key == dom, ln
        assert rule.wildcard == (kind == "zone"), ln


def test_spec_irreducible_stays_regex() -> None:
    """An irreducible regex stays a REGEX-target rule in the spec (does not fold).
    $badfilter / IP-anchored / comments are not regex lines and are skipped."""
    import os

    base = os.path.join(os.path.dirname(__file__), "fixtures", "adr07_corpus")
    with open(os.path.join(base, "regex_irreducible.txt"), encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("!")]
    for ln in lines:
        rule = parse_abp_line(ln, Provenance.FEED)
        assert rule is not None, ln
        assert rule.target is Target.REGEX, ln


# --- 11. cross-feed global @@ (true ABP semantics, ADR.md SS3) -------------- #
def test_cross_feed_allow_unblocks_other_feed_block() -> None:
    # an @@ exception in one feed un-blocks what another feed blocks (band 2 > 1).
    feed_a = rules_from(["||shared.example^"], Provenance.FEED)
    feed_b = rules_from(["@@||shared.example^"], Provenance.FEED)
    assert decide(feed_a + feed_b, "shared.example").outcome == "resolve"
    # ...but a user block still wins over the cross-feed @@ (sovereignty).
    user = rules_from(["||shared.example^"], Provenance.USER)
    assert decide(feed_a + feed_b + user, "shared.example").outcome == "block"
