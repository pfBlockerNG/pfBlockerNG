from __future__ import annotations

import pytest

import pfb_unbound

AUTHORITY = """# Public Suffix List authority
// ===BEGIN ICANN DOMAINS===
com
co.uk
act.edu.au
chtr.k12.ma.us
*.ck
!www.ck
io
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
*.nom.br
one.two.three.four.five.example
*.two.three.four.five.six.example
// ===END PRIVATE DOMAINS===
"""


def test_parser_preserves_sections_rules_and_markers() -> None:
    assert hasattr(pfb_unbound, "parse_psl_rules")
    assert hasattr(pfb_unbound, "resolve_public_suffix")
    rules = pfb_unbound.parse_psl_rules(AUTHORITY)
    assert rules.icann_exact == ("com", "co.uk", "act.edu.au", "chtr.k12.ma.us", "io")
    assert rules.icann_wildcard == ("ck",)
    assert rules.icann_exception == ("www.ck",)
    assert rules.private_exact == ("github.io", "one.two.three.four.five.example")
    assert rules.private_wildcard == ("nom.br", "two.three.four.five.six.example")


@pytest.mark.parametrize(
    ("name", "icann", "public", "registrable", "private"),
    [
        ("example.com", "com", "com", "example.com", False),
        ("example.co.uk", "co.uk", "co.uk", "example.co.uk", False),
        ("example.act.edu.au", "act.edu.au", "act.edu.au", "example.act.edu.au", False),
        ("example.chtr.k12.ma.us", "chtr.k12.ma.us", "chtr.k12.ma.us", "example.chtr.k12.ma.us", False),
        ("a.ck", "a.ck", "a.ck", "", False),
        ("www.ck", "ck", "ck", "www.ck", False),
        ("x.www.ck", "ck", "ck", "www.ck", False),
        ("evil.github.io", "io", "github.io", "evil.github.io", True),
        ("github.io", "io", "github.io", "", True),
        ("evil.nom.br", "br", "evil.nom.br", "", True),
        ("foo.unknown", "unknown", "unknown", "foo.unknown", False),
    ],
)
def test_resolver_precedence_and_private_boundary(
    name: str, icann: str, public: str, registrable: str, private: bool
) -> None:
    result = pfb_unbound.resolve_public_suffix(name, pfb_unbound.parse_psl_rules(AUTHORITY))
    assert isinstance(result, pfb_unbound.PslResolution)
    assert (result.icann_suffix, result.public_suffix, result.registrable_domain, result.private_active) == (
        icann,
        public,
        registrable,
        private,
    )


def test_idna_raw_and_punycode_names_are_equivalent() -> None:
    authority = AUTHORITY.replace("com\n", "com\nxn--p1ai\n")
    rules = pfb_unbound.parse_psl_rules(authority)
    assert pfb_unbound.resolve_public_suffix("пример.рф", rules) == pfb_unbound.resolve_public_suffix(
        "xn--e1afmkfd.xn--p1ai", rules
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        ".example.com",
        "example.com.",
        "a..example.com",
        "*",
        "bad name.example",
        "a\x00.example",
        "a." + "x" * 64 + ".com",
        "a." + "x" * 250 + ".com",
    ],
)
def test_resolver_rejects_malformed_names(bad: str) -> None:
    with pytest.raises(ValueError):
        pfb_unbound.resolve_public_suffix(bad, pfb_unbound.parse_psl_rules(AUTHORITY))


@pytest.mark.parametrize(
    "authority",
    [
        AUTHORITY.replace("// ===BEGIN ICANN DOMAINS===", "// ===BEGIN ICANN DOMAINS===\n// ===BEGIN ICANN DOMAINS==="),
        AUTHORITY.replace("// ===END ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===\n// ===END ICANN DOMAINS==="),
        AUTHORITY.replace(
            "// ===BEGIN PRIVATE DOMAINS===", "// ===END PRIVATE DOMAINS===\n// ===BEGIN PRIVATE DOMAINS==="
        ),
        AUTHORITY.replace("!www.ck\n", "!orphan.example\n"),
        AUTHORITY.replace("*.ck\n", ""),
    ],
)
def test_parser_refuses_bad_markers_or_orphan_exceptions(authority: str) -> None:
    with pytest.raises(ValueError):
        pfb_unbound.parse_psl_rules(authority)


@pytest.mark.parametrize("rule", ["a$[b].com", "a|b.com", "a;$(id).com"])
def test_parser_rejects_shell_and_regex_metacharacters(rule: str) -> None:
    with pytest.raises(ValueError):
        pfb_unbound.parse_psl_rules(AUTHORITY.replace("com\n", f"com\n{rule}\n", 1))


@pytest.mark.parametrize("label", ["xn--bad", "xn--abc"])
def test_parser_and_resolver_reject_invalid_ace_labels(label: str) -> None:
    with pytest.raises(ValueError):
        pfb_unbound.parse_psl_rules(AUTHORITY.replace("com\n", f"com\n{label}\n", 1))
    with pytest.raises(ValueError):
        pfb_unbound.resolve_public_suffix(f"{label}.com", pfb_unbound.parse_psl_rules(AUTHORITY))


def test_parser_accepts_duplicate_overlapping_rules_without_changing_precedence() -> None:
    authority = AUTHORITY.replace("com\n", "com\ncom\n").replace("*.ck\n", "*.ck\n*.ck\n")
    rules = pfb_unbound.parse_psl_rules(authority)
    assert pfb_unbound.resolve_public_suffix("example.com", rules).public_suffix == "com"
    assert pfb_unbound.resolve_public_suffix("a.ck", rules).public_suffix == "a.ck"


def test_resolver_throughput_is_indexed_not_linear_scan() -> None:
    """Resolution must be O(name labels), never a scan over all ~10k shipped rules.

    The DNSBL build classifies every feed entry and TLD-Allow resolves on the live
    DNS query path, so a per-lookup scan over the full rule set (measured ~3.6 ms
    per resolve, ~30 minutes for a 500k-entry build) is a defect. 2000 resolves
    against the SHIPPED authority must finish comfortably inside 2 seconds; the
    indexed matcher needs ~0.1 s, the linear scan needs ~7 s.
    """
    import pathlib
    import time

    shipped = pathlib.Path(__file__).resolve().parents[1] / "src/usr/local/pkg/pfblockerng/dnsbl_psl"
    rules = pfb_unbound.parse_psl_rules(shipped.read_text(encoding="utf-8"))
    names = [
        "example.com",
        "foo.bar.co.uk",
        "tenant.github.io",
        "deep.a.b.c.example.org",
        "evil.foo.ck",
        "host.one.two.three.example.nom.br",
        "no-rule.zz-unknown",
        "x.act.edu.au",
    ] * 250
    started = time.perf_counter()
    for name in names:
        pfb_unbound.resolve_public_suffix(name, rules)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"2000 resolves took {elapsed:.2f}s; matcher is scanning rules per lookup"
