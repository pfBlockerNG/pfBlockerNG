"""ADR-07 Phase 8 -- the slimmed PHP/shell boundary hands Python RAW 'abp' lines.

WHY THIS FILE EXISTS
--------------------
Phase 8 redraws the shell<->Python boundary for ABP/EasyList feeds to the
aggressive ADR-06 target:

  * The PHP ``$easylist`` lite parser (keep-only ``||domain^`` + the ``$e_replace``
    token strip) is DELETED. PHP captures an ABP-shaped line VERBATIM per-line
    (``pfb_dnsbl_is_abp_rule_line()``, #1083 P4 -- no whole-feed tag) and passes
    it through to the per-feed raw the manifest references. The full DNS-only ABP
    parser is the one in Python (``parse_abp``: ``@@`` / regex / ``$important`` /
    ``$badfilter``), not the PHP lite pass that silently dropped them.
  * DNSBL-IP coexistence (ADR-06 fact 7): the firewall IP pass still runs over the
    (now raw) ABP feeds. PHP's ``pfb_dnsbl_abp_extract_ip`` pulls an ABP-anchored
    IP (``||1.2.3.4^``) or a hosts IP (``<ip> <ip>``) to ``DNSBLIP_v4`` / ``_v6``
    and does NOT pass it to Python; Python's ``parse_abp`` independently SKIPS
    IP-valued anchors (returns ``None``) -- so IP -> firewall only, domain/regex ->
    Python only (no double-handling, no leak).

This test reproduces EXACTLY what the slimmed PHP loop writes for an ABP feed (run
the reference ABP-IP extractor over each raw line; divert IP-anchored lines to the
firewall set; emit every surviving raw line VERBATIM as the per-feed 'abp' raw),
then builds an ``abp`` manifest, runs the PRODUCTION ``build`` + ``evaluate_domain``
over it, and asserts:

  1. every decision matches the Phase-2 oracle ``decide()`` (the ABP semantics the
     lite parser used to drop are now honoured end-to-end through the boundary),
  2. no firewall IP leaks into the domain/regex build, and the IP-anchored lines
     land in the firewall set instead, and
  3. the boundary is RAW: a ``$``/``@@``/``/re/`` line reaches Python intact (it
     would have been dropped by the old PHP lite pass).
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

import pfb_unbound as P
import tests.test_adr07_decision_spec as spec

# A minimal public-suffix oracle (matches the emit_wire test): com/net/org are
# public suffixes, so example.com is the registrable parent (zone classify groups
# subdomains there).
_TLD_MASTER = ["com", "net", "org"]


# ABP-anchored / hosts IP detection -- the Python mirror of the PHP
# pfb_dnsbl_abp_extract_ip() the download loop uses for DNSBL-IP coexistence.
# PHP uses is_ipaddrv4()/is_ipaddrv6(), so both families divert to the firewall.
def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _php_abp_extract_ip(line: str) -> str | None:
    """Reproduce PHP ``pfb_dnsbl_abp_extract_ip()``: return the IP a raw ABP line
    carries for the firewall pass (``||<ip>^`` or hosts ``<ip> <ip>``, IPv4 OR
    IPv6), else None. Mirrors the PHP whitespace gate (space OR tab).
    """
    s = line.strip()
    if not s:
        return None
    if s.startswith("||"):
        rest = s[2:]
        rest = rest.split("$", 1)[0]
        host = rest.split("^", 1)[0].strip()
        return host if _is_ip(host) else None
    parts = s.split()
    if len(parts) >= 2 and _is_ip(parts[0]) and _is_ip(parts[1]):
        return parts[1]
    return None


def _php_abp_boundary(raw_lines: Iterable[str]) -> tuple[list[str], set[str]]:
    """Model the slimmed PHP ABP branch: divert IP-anchored/hosts IPs to the
    firewall, drop comment/control lines, pass every other RAW line through verbatim.

    Returns (the per-feed 'abp' raw lines handed to Python, the firewall IPs).
    """
    out: list[str] = []
    firewall_ips: set[str] = set()
    for raw in raw_lines:
        line = raw.strip()
        ip = _php_abp_extract_ip(line)
        if ip is not None:
            firewall_ips.add(ip)
            continue  # IP -> firewall only; never passed to Python
        if line == "" or line.startswith("!") or line.startswith("["):
            continue  # comment/control: PHP drops them (Python would skip too)
        out.append(line)  # RAW passthrough -- no domain extraction
    return out, firewall_ips


def _build_abp(feeds: dict[str, list[str]], *, user_whitelist: Iterable[str] = ()) -> tuple[P.BuildResult, set[str]]:
    """Run the slimmed PHP boundary over each feed, then the PRODUCTION abp build."""
    raw_store: dict[str, list[str]] = {}
    all_firewall_ips: set[str] = set()
    for name, lines in feeds.items():
        raw, ips = _php_abp_boundary(lines)
        raw_store[name] = raw
        all_firewall_ips |= ips

    manifest = {
        "feeds": [{"raw": name, "feed": name, "group": name, "log_flag": "1"} for name in feeds],
    }
    config = {
        "tld_wildcard_master": _TLD_MASTER,
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": list(user_whitelist),
        "top1m_list": [],
    }

    def reader(raw: str) -> Iterable[str]:
        return list(raw_store.get(raw, []))

    result = P.build(manifest, config, line_reader=reader, top1m_enabled=False)
    return result, all_firewall_ips


def _cfg(result: P.BuildResult) -> dict[str, Any]:
    return {
        "python_blocking": True,
        "dataDB": bool(result.data_db),
        "zoneDB": bool(result.zone_db),
        "whiteDB": bool(result.white_db),
        "regexDB": bool(result.regex_db),
        "allowRegexDB": bool(result.allow_regex_db),
        "important_rules": result.important_rules,
        "hstsDB": False,
        "tld_allow": False,
        "python_idn": False,
        "python_tld_seg": 2,
        "tld_allow_list": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "hsts_tlds": (),
    }


def _containers(result: P.BuildResult) -> dict[str, Any]:
    return {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": result.regex_db,
        "allowRegexDB": result.allow_regex_db,
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {},
    }


def _live_label(result: P.BuildResult, q_name: str) -> str:
    cfg = _cfg(result)
    containers = _containers(result)
    tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
    dec = P.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
    if not dec.is_found:
        return "pass"
    if dec.in_whitelist:
        return "resolve"
    return "block"


def _oracle_label(feeds: dict[str, list[str]], user_lines: list[str], q_name: str) -> str:
    rules: list[spec.Rule] = []
    for lines in feeds.values():
        rules += spec.rules_from(lines, spec.Provenance.FEED)
    rules += spec.rules_from(user_lines, spec.Provenance.USER)
    return spec.decide(rules, q_name).outcome


# --------------------------------------------------------------------------- #
# 1. The raw ABP feed round-trips PHP-tag -> Python build == Phase-2 decisions.
# --------------------------------------------------------------------------- #
class TestRawAbpBoundaryDecisions:
    """A single raw ABP feed (block + @@ exception + regex + $important +
    $badfilter + skip lines) round-tripped through the PHP-tag boundary into the
    production build yields the SAME decisions as the Phase-2 oracle."""

    # Registrable-parent domains (com/net/org are the public suffixes in the test
    # TLD master), so ``||example.com^`` classifies to a wildcard ZONE covering its
    # subdomains -- matching the Phase-2 oracle's wildcard semantics. The ``@@``
    # exception carves a subdomain back out of an overarching block (the real
    # over-blocking fix; the old PHP lite parser dropped it). ``||ads.metrics.net^``
    # is a DEEPER anchor (its own registrable parent is metrics.net, one level up):
    # ABP semantics still cover ITS subdomains too, regardless of that extra depth.
    FEED = [
        "[Adblock Plus 2.0]",  # header (PHP drops; never reaches Python)
        "! Title: test",  # comment (dropped)
        "||example.com^",  # block example.com + subdomains
        "@@||safe.example.com^",  # allow exception -- lite parser DROPPED this
        "||tracker.net^$important",  # important block
        "||gone.net^",
        "||gone.net^$badfilter",  # prunes the feed block above (feed-only)
        r"/ad[0-9]\.example\.org$/",  # irreducible block regex -- lite parser DROPPED
        r"@@/white[0-9]\.example\.org$/",  # allow regex -- lite parser DROPPED
        "##.banner",  # element-hiding (skip)
        "||img.example.net/banner.gif",  # path/URL (skip)
        "||evil.example.net^$third-party",  # page-context option (skip)
        "||ads.metrics.net^",  # deep anchor -- blocks its subdomains too
    ]

    QUERIES = [
        "example.com",
        "other.example.com",  # subdomain -> blocked by the zone
        "safe.example.com",  # @@ exception -> resolves
        "tracker.net",
        "gone.net",  # $badfilter pruned the block -> not blocked
        "ad7.example.org",  # irreducible block regex -> blocked
        "white3.example.org",  # allow regex -> resolves
        "img.example.net",  # path/URL skipped -> not blocked
        "evil.example.net",  # page-context option skipped -> not blocked
        "nothing.example.org",
        "ads.metrics.net",  # deep anchor itself -> blocked
        "deep.ads.metrics.net",  # deep anchor's subdomain -> blocked too
        "metrics.net",  # unblocked parent -- must stay unblocked
    ]

    def test_decisions_match_oracle(self) -> None:
        feeds = {"abpfeed": self.FEED}
        result, _ = _build_abp(feeds)
        failures: list[str] = []
        for q in self.QUERIES:
            live = _live_label(result, q)
            oracle = _oracle_label(feeds, [], q)
            # The net DNS outcome is "blocked" (null-routed) vs "not blocked". The
            # production matcher reports "pass" (nothing matched) where the spec
            # reports "resolve" (an allow won with no covering block) -- both are the
            # SAME net "not null-routed" outcome (RESULTS/06 SS5). Compare the net
            # outcome so the resolve/pass mapping caveat does not mask a real bug.
            if (live == "block") != (oracle == "block"):
                failures.append(f"{q}: live={live!r} oracle={oracle!r}")
        assert not failures, "abp boundary decision mismatch:\n" + "\n".join(failures)

    def test_exact_block_decisions(self) -> None:
        # The names that MUST be blocked (zone, subdomain, important, irreducible
        # regex) and the names that MUST resolve via a covering-block carve-out.
        result, _ = _build_abp({"abpfeed": self.FEED})
        assert _live_label(result, "example.com") == "block"
        assert _live_label(result, "other.example.com") == "block"  # zone subdomain
        assert _live_label(result, "safe.example.com") == "resolve"  # @@ carve-out
        assert _live_label(result, "tracker.net") == "block"  # $important
        assert _live_label(result, "ad7.example.org") == "block"  # irreducible regex
        assert _live_label(result, "gone.net") != "block"  # $badfilter pruned

    def test_raw_passthrough_reaches_python(self) -> None:
        # The @@ exception, regex, and $important rules the OLD PHP lite parser
        # silently dropped now survive the boundary and shape decisions.
        result, _ = _build_abp({"abpfeed": self.FEED})
        assert "safe.example.com" in result.white_db  # @@ exception honoured
        assert result.regex_db  # /re/ block reached Python
        assert result.allow_regex_db  # @@/re/ allow reached Python
        assert result.important_rules is True  # $important / @@ / regex engaged

    def test_user_whitelist_sovereign_over_feed_important(self) -> None:
        # A user whitelist un-blocks even a feed $important block (fact 7), end to
        # end through the boundary.
        feeds = {"abpfeed": ["||tracker.net^$important"]}
        result, _ = _build_abp(feeds, user_whitelist=["tracker.net"])
        assert _live_label(result, "tracker.net") != "block"


# --------------------------------------------------------------------------- #
# 2. DNSBL-IP coexistence: IP anchors -> firewall, never into the domain build.
# --------------------------------------------------------------------------- #
class TestDnsblIpCoexistence:
    FEED = [
        "||ads.example.com^",  # domain -> Python
        "||203.0.113.7^",  # ABP-anchored IPv4 -> firewall
        "||2001:db8::7^",  # ABP-anchored IPv6 -> firewall
        "||198.51.100.42^$important",  # IP anchor w/ options -> firewall (options ignored)
        "0.0.0.0 203.0.113.99",  # hosts IPv4 -> firewall
        ":: 2001:db8::99",  # hosts IPv6 -> firewall
        "0.0.0.0\t198.51.100.50",  # TAB-delimited hosts IPv4 -> firewall (whitespace gate)
        "0.0.0.0 blocked.example.net",  # hosts domain -> Python
    ]

    def test_ip_anchors_routed_to_firewall(self) -> None:
        result, firewall_ips = _build_abp({"f": self.FEED})
        assert firewall_ips == {
            "203.0.113.7",
            "2001:db8::7",
            "198.51.100.42",
            "203.0.113.99",
            "2001:db8::99",
            "198.51.100.50",
        }

    def test_no_ip_leaks_into_domain_or_regex_build(self) -> None:
        result, firewall_ips = _build_abp({"f": self.FEED})
        keys = set(result.data_db) | set(result.zone_db)
        # No firewall IP became a domain key.
        assert not (firewall_ips & keys)
        # And no compiled regex pattern is an IP literal (no IP-anchor leaked there).
        for payload in list(result.regex_db.values()) + list(result.allow_regex_db.values()):
            pat = payload["re"].pattern if isinstance(payload, dict) else payload.pattern
            assert not any(ip in pat for ip in firewall_ips)

    def test_domains_alongside_ips_still_block(self) -> None:
        result, _ = _build_abp({"f": self.FEED})
        assert _live_label(result, "ads.example.com") == "block"
        assert _live_label(result, "blocked.example.net") == "block"
        # An IP-anchored host is NOT a DNS block (it went to the firewall path only).
        assert _live_label(result, "203.0.113.7") == "pass"
