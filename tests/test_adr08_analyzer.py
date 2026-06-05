"""ADR-08 Phase 4 -- the shipped pure TR39 IDN homoglyph analyzer.

WHY THIS FILE EXISTS
--------------------
Phase 4 ships the PRODUCTION analyzer (``pfb_idn_analyzer``) plus the shipped
Unicode Scripts / Script_Extensions range tables (``pfb_unicode_scripts``, emitted
by ``scripts/update-unicode-data.py`` from a pinned Unicode version). This suite
grades the analyzer against the Phase-2 oracle (``test_adr08_decision_spec.py``)
over the Phase-1 corpus (``corpus.json``) and the Phase-2 golden decision table
(``decision_table.json``).

The analyzer is NOT yet wired into the matcher (that is Phase 5) -- it is proven in
isolation here. Every public function AND ``classify_idn`` end-to-end is exercised
with real, failable assertions and full branch coverage:

  * CJK legit (Han+Katakana / Han+Hangul) = OK -- the load-bearing 0-FP guard;
  * Latin+Cyrillic, Latin+Greek, AND Cyrillic+Greek = MALICIOUS;
  * Latin+{Armenian/Cherokee/Coptic} = SUSPICIOUS (the recorded borderline call);
  * a whole-script (single-script) look-alike = OK (documented miss, pinned);
  * malformed / scriptless labels = FLAGGED (caught, never raised);
  * per-label IDN-ccTLD never unioned across the dot (example.рф / site.中国 stay OK).

A dedicated cross-check (``TestAnalyzerMatchesPhase2OracleAndCorpus``) diffs the
analyzer's verdicts against the SAME golden table + corpus the oracle is graded
on, so the shipped tables and the scoped oracle map cannot silently diverge.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types

# --------------------------------------------------------------------------- #
# Import the SHIPPED analyzer from the package dir (the same location Unbound
# loads it from at runtime; conftest already puts that dir on sys.path).
# --------------------------------------------------------------------------- #
import pfb_idn_analyzer as A  # noqa: E402
import pfb_unicode_scripts as U  # noqa: E402
import pytest

_HERE = os.path.dirname(__file__)
_SPEC = os.path.join(_HERE, "fixtures", "adr08_spec", "decision_table.json")
_CORPUS = os.path.join(_HERE, "fixtures", "adr08_corpus", "corpus.json")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


DECISION_TABLE = _load(_SPEC)
CORPUS = _load(_CORPUS)


def _import_oracle() -> types.ModuleType:
    """Import the Phase-2 oracle module as a plain importable reference.

    ``test_adr08_decision_spec`` is a pure module (no Unbound symbol); importing it
    here lets us diff the shipped analyzer against the SAME oracle that authored the
    golden table -- so a regression in either is caught at the seam.
    """
    spec = importlib.util.spec_from_file_location("adr08_oracle", os.path.join(_HERE, "test_adr08_decision_spec.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["adr08_oracle"] = module  # so its dataclasses resolve __module__.
    spec.loader.exec_module(module)
    return module


ORACLE = _import_oracle()


def _single_label_rows() -> list[dict]:
    return DECISION_TABLE["single_label"]


def _multi_label_rows() -> list[dict]:
    return DECISION_TABLE["multi_label"]


def _edge_rows() -> list[dict]:
    return DECISION_TABLE["edge_decode"]


# --------------------------------------------------------------------------- #
# decode_idn_label -- raw 'punycode', non-xn-- pass-through, NOT idna.
# --------------------------------------------------------------------------- #


class TestDecodeIdnLabel:
    """decode_idn_label decodes an xn-- label with the RAW 'punycode' codec, passes
    a non-xn-- label through unchanged, and (uncaught here) raises on malformed
    input -- the load-bearing distinction from the 'idna' codec."""

    def test_decodes_homograph_label(self) -> None:
        assert A.decode_idn_label("xn--pple-43d") == "аpple"

    def test_non_xn_label_passes_through(self) -> None:
        # A plain ASCII label is returned unchanged (the analyzer is invoked per
        # label; non-IDN labels must not be touched).
        assert A.decode_idn_label("example") == "example"
        assert A.decode_idn_label("com") == "com"

    def test_uses_raw_punycode_not_idna(self) -> None:
        # The RAW codec decodes the analysable edge labels 'idna' rejects.
        assert A.decode_idn_label("xn--a") == "\x80"
        assert A.decode_idn_label("xn--") == ""
        with pytest.raises(UnicodeError):
            "xn--a".encode("ascii").decode("idna")

    def test_malformed_label_raises_uncaught(self) -> None:
        # decode_idn_label itself MAY raise; classify_label is the decode-safe wrapper.
        with pytest.raises((UnicodeDecodeError, UnicodeError, ValueError)):
            A.decode_idn_label("xn--zz")


# --------------------------------------------------------------------------- #
# script_of / resolved_script_set -- the shipped range tables, Script_Extensions
# first, Common/Inherited/Unknown transparent.
# --------------------------------------------------------------------------- #


class TestScriptOf:
    """script_of resolves a code point via the shipped range tables: a letter ->
    its owning script; a transparent (Common/Inherited) or unassigned code point ->
    the empty tuple (contributes no script)."""

    @pytest.mark.parametrize(
        "ch,want",
        [
            ("a", "Latin"),
            ("ü", "Latin"),
            ("а", "Cyrillic"),  # U+0430
            ("α", "Greek"),  # U+03B1
            ("中", "Han"),
            ("テ", "Katakana"),
            ("한", "Hangul"),
            ("ا", "Arabic"),
        ],
    )
    def test_letter_resolves_to_its_script(self, ch: str, want: str) -> None:
        assert want in A.script_of(ord(ch))

    @pytest.mark.parametrize("cp", [0x2D, 0x31, 0x20, 0x80, 0x1F4A9])
    def test_transparent_or_scriptless_codepoint_is_empty(self, cp: int) -> None:
        # Hyphen/digit/space (Common), a control char (U+0080), an emoji (U+1F4A9):
        # all carry no letter-script -> the empty tuple (transparent).
        assert A.script_of(cp) == ()

    def test_script_extensions_take_precedence(self) -> None:
        # A code point present in the Script_Extensions table resolves to that tuple,
        # NOT its plain Script. Pick the first such range from the shipped table and
        # assert the lookup returns exactly the extensions tuple.
        cp = U.SCRIPTX_RANGE_STARTS[0]
        i = 0
        assert A.script_of(cp) == U.SCRIPTX_RANGE_NAMES[i]
        assert len(A.script_of(cp)) >= 1


class TestResolvedScriptSet:
    """resolved_script_set unions each code point's scripts for ONE label, with
    Common/Inherited transparent and a scriptless code point contributing nothing
    (so an all-scriptless label yields the empty set -- the FLAGGED trigger)."""

    def test_single_script_label(self) -> None:
        assert A.resolved_script_set("münchen") == {"Latin"}
        assert A.resolved_script_set("россия") == {"Cyrillic"}

    def test_digits_and_hyphen_are_transparent(self) -> None:
        # ASCII letters+digits+hyphen -> only Latin (Common digits/hyphen dropped).
        assert A.resolved_script_set("a1-b2") == {"Latin"}

    def test_multi_script_union(self) -> None:
        # Han + Katakana legit CJK mix; Latin + Cyrillic homograph mix.
        assert A.resolved_script_set("ドメイン名") == {"Han", "Katakana"}
        assert A.resolved_script_set("аpple") == {"Cyrillic", "Latin"}

    def test_scriptless_label_is_empty_set(self) -> None:
        # Empty, control char, emoji: no letter-script -> empty set (flagged later).
        assert A.resolved_script_set("") == set()
        assert A.resolved_script_set("\x80") == set()
        assert A.resolved_script_set("💩") == set()


# --------------------------------------------------------------------------- #
# restriction_level -- every documented UTS#39 level is a real branch.
# --------------------------------------------------------------------------- #


class TestRestrictionLevel:
    """restriction_level maps a resolved set to a UTS#39 level. Each documented
    level is asserted so a later phase cannot silently collapse them."""

    def test_ascii_only(self) -> None:
        assert A.restriction_level({"Latin"}, ascii_only=True) == A.LEVEL_ASCII

    def test_single_script(self) -> None:
        assert A.restriction_level({"Cyrillic"}) == A.LEVEL_SINGLE

    def test_highly_restrictive_latin_cjk(self) -> None:
        # Latin/Han + CJK companions -> Highly Restrictive (the legit multi allow-set).
        assert A.restriction_level({"Han", "Katakana"}) == A.LEVEL_HIGHLY_RESTRICTIVE
        assert A.restriction_level({"Han", "Hangul"}) == A.LEVEL_HIGHLY_RESTRICTIVE

    def test_non_restrictive_mix(self) -> None:
        # A non-allow-set multi-script mix -> Non Restrictive.
        assert A.restriction_level({"Cyrillic", "Latin"}) == A.LEVEL_NON_RESTRICTIVE
        assert A.restriction_level({"Armenian", "Latin"}) == A.LEVEL_NON_RESTRICTIVE


# --------------------------------------------------------------------------- #
# severity_of + classify_idn end-to-end -- the core decision (BDD).
#
# Scenario: a DNS query name reaches the matcher's IDN branch as punycode ASCII.
# The analyzer must decode each label, resolve its per-label script set, and assign
# a severity (legit / suspicious / malicious / flagged) by the TR39 mixed-script
# rule -- never unioning scripts across the dot. classify_idn returns the most-
# severe label's verdict for the whole name.
# --------------------------------------------------------------------------- #


class TestCjkLegitIsZeroFalsePositive:
    """Given a legitimate Latin+CJK domain, Then the analyzer classifies it LEGIT --
    the single most important non-block case. The before-state proves it IS genuinely
    multi-script (so a naive 'any mix -> block' WOULD false-positive), and the
    restriction-level rule is what rescues it."""

    def test_han_katakana_is_legit_not_malicious(self) -> None:
        # Given the Japanese 'domain name' label (Han + Katakana).
        decoded = A.decode_idn_label("xn--eckwd4c7c777u")
        scripts = A.resolved_script_set(decoded)
        # When we observe it IS multi-script (a naive any-mix rule would block it)...
        assert scripts == {"Han", "Katakana"} and len(scripts) >= 2
        # Then the restriction-level rule classifies it Highly Restrictive -> legit.
        assert A.restriction_level(scripts) == A.LEVEL_HIGHLY_RESTRICTIVE
        assert A.severity_of(decoded) == A.SEV_LEGIT
        assert A.classify_idn("xn--eckwd4c7c777u").severity == A.SEV_LEGIT

    def test_han_hangul_is_legit_not_malicious(self) -> None:
        decoded = A.decode_idn_label("xn--eqr704t9deq8o")
        scripts = A.resolved_script_set(decoded)
        assert scripts == {"Han", "Hangul"} and len(scripts) >= 2
        assert A.severity_of(decoded) == A.SEV_LEGIT


class TestMaliciousConfusablePairs:
    """Each of the three confusable PAIRS is MALICIOUS, INCLUDING the non-Latin-
    anchored Cyrillic+Greek. Branch coverage of the malicious tier; ``offending``
    carries exactly the trio scripts that co-occur."""

    def test_latin_cyrillic_is_malicious(self) -> None:
        v = A.classify_idn("xn--pple-43d")
        assert v.severity == A.SEV_MALICIOUS
        assert v.offending == frozenset({"Latin", "Cyrillic"})

    def test_latin_greek_is_malicious(self) -> None:
        v = A.classify_idn("xn--ggle-0nda")
        assert v.severity == A.SEV_MALICIOUS
        assert v.offending == frozenset({"Latin", "Greek"})

    def test_cyrillic_greek_no_latin_is_malicious(self) -> None:
        # Borderline call: the rule is >=2 of the trio, NOT Latin-anchored.
        decoded = A.decode_idn_label("xn--mxa00ab")
        scripts = A.resolved_script_set(decoded)
        assert "Latin" not in scripts, "precondition: this mix has NO Latin"
        assert scripts == {"Cyrillic", "Greek"}
        v = A.classify_idn("xn--mxa00ab")
        assert v.severity == A.SEV_MALICIOUS
        assert v.offending == frozenset({"Cyrillic", "Greek"})


class TestSuspiciousTierBorderlineCalls:
    """Latin + a confusable-with-Latin script OUTSIDE the trio (Armenian / Cherokee /
    Coptic) is SUSPICIOUS, NOT malicious -- the recorded borderline call. Asserts the
    explicit NOT-malicious before the suspicious verdict so green proves the boundary."""

    @pytest.mark.parametrize(
        "a_label,other",
        [
            ("xn--bnk-1ce", "Armenian"),
            ("xn--bnk-u8p", "Cherokee"),
            ("xn--bnk-q10b", "Coptic"),
        ],
    )
    def test_latin_plus_nontrio_is_suspicious_not_malicious(self, a_label: str, other: str) -> None:
        decoded = A.decode_idn_label(a_label)
        scripts = A.resolved_script_set(decoded)
        assert scripts == {"Latin", other}
        sev = A.severity_of(decoded)
        assert sev != A.SEV_MALICIOUS  # explicitly NOT a default block...
        assert sev == A.SEV_SUSPICIOUS  # ...it is the suspicious/alert tier.
        # offending surfaces the full multi-script set for the alert.
        assert A.classify_idn(a_label).offending == frozenset({"Latin", other})


class TestSingleScriptIsLegitEvenForTrioScripts:
    """A single-script label is LEGIT even when its script is in the confusable trio
    (the malicious rule needs >=2 of the trio). Pairs the 'on' (mix) branch above
    with the 'off' (single) branch so the rule is proven a real boundary."""

    @pytest.mark.parametrize(
        "a_label,script",
        [
            ("xn--h1alffa9f", "Cyrillic"),  # россия
            ("xn--hxakic4aa", "Greek"),  # ελλάδα
            ("xn--mnchen-3ya", "Latin"),  # münchen
        ],
    )
    def test_single_trio_script_is_legit(self, a_label: str, script: str) -> None:
        decoded = A.decode_idn_label(a_label)
        assert A.resolved_script_set(decoded) == {script}
        assert A.severity_of(decoded) == A.SEV_LEGIT


class TestWholeScriptConfusableNotCaught:
    """DOCUMENTED LIMITATION (ADR-08 section 7): a whole-script (single-script) look-
    alike is NOT caught. Pinned as a no-op so a future change that started catching it
    goes red and forces a deliberate decision."""

    def test_all_cyrillic_apple_lookalike_is_legit(self) -> None:
        decoded = A.decode_idn_label("xn--80ak6aa92e")  # аррӏе
        scripts = A.resolved_script_set(decoded)
        assert scripts == {"Cyrillic"}  # single-script: no mix to detect.
        assert A.severity_of(decoded) == A.SEV_LEGIT


class TestPerLabelNeverUnionsAcrossTheDot:
    """The load-bearing per-label rule. A legit Latin SLD under an IDN ccTLD stays
    OK (each label single-script) even though the WRONG whole-name union reads
    confusable; a malicious SUBDOMAIN label makes the whole name malicious."""

    def test_idn_cctld_latin_under_cyrillic_is_legit_per_label(self) -> None:
        v = A.classify_idn("example.xn--p1ai")  # example.рф
        assert [lv.severity for lv in v.labels] == [A.SEV_LEGIT, A.SEV_LEGIT]
        assert v.severity == A.SEV_LEGIT

    def test_idn_cctld_latin_under_han_is_legit_per_label(self) -> None:
        v = A.classify_idn("site.xn--fiqs8s")  # site.中国
        assert [lv.severity for lv in v.labels] == [A.SEV_LEGIT, A.SEV_LEGIT]
        assert v.severity == A.SEV_LEGIT

    def test_wrong_union_would_have_false_positived_the_cctld(self) -> None:
        # Prove the guard is real: the WRONG whole-name union of example.рф is
        # {Cyrillic, Latin} -- which the malicious rule WOULD flag -- yet per-label
        # analysis keeps it legit (no single label mixes the trio).
        union: set[str] = set()
        for lbl in "example.xn--p1ai".split("."):
            union |= A.resolved_script_set(A.decode_idn_label(lbl))
        assert len(union & A.CONFUSABLE_SET) >= 2, "the wrong union genuinely looks malicious"
        assert A.classify_idn("example.xn--p1ai").severity == A.SEV_LEGIT

    def test_malicious_subdomain_label_blocks_whole_name(self) -> None:
        # A homograph in the SUBDOMAIN label -> that label malicious -> whole name malicious.
        v = A.classify_idn("xn--ypal-43d9g.example.com")
        assert v.labels[0].severity == A.SEV_MALICIOUS
        assert [lv.severity for lv in v.labels[1:]] == [A.SEV_LEGIT, A.SEV_LEGIT]
        assert v.severity == A.SEV_MALICIOUS
        assert v.offending == frozenset({"Latin", "Cyrillic"})


class TestMalformedLabelsAreFlaggedNotRaised:
    """A malformed / contentless xn-- label must be FLAGGED, never raise -- the
    resolver must not crash (ADR-08 robustness contract). Branch coverage: a raising
    label, a decodable-but-scriptless label, and a decodable junk-CJK label (legit)."""

    @pytest.mark.parametrize("row", _edge_rows(), ids=lambda r: r["id"])
    def test_edge_label_matches_golden(self, row: dict) -> None:
        verdict = A.classify_label(row["a_label"])  # NEVER raises.
        assert verdict.severity == row["severity"], f"{row['id']}: severity {verdict.severity}"
        if not row["decode_ok"]:
            assert verdict.decode_error == row["raises"], f"{row['id']}: decode_error"
            assert verdict.decoded is None
            assert verdict.severity == A.SEV_FLAGGED
        else:
            assert verdict.decode_error is None, f"{row['id']}: unexpected decode error"
            assert verdict.decoded is not None

    def test_raw_decode_actually_raises_for_the_raising_rows(self) -> None:
        # Pin that the catch in classify_label is load-bearing (not dead code).
        for row in _edge_rows():
            if row["decode_ok"]:
                continue
            with pytest.raises((UnicodeDecodeError, UnicodeError, ValueError)):
                A.decode_idn_label(row["a_label"])

    def test_no_edge_label_is_ever_malicious(self) -> None:
        for row in _edge_rows():
            assert A.classify_label(row["a_label"]).severity != A.SEV_MALICIOUS

    def test_classify_idn_on_undecodable_name_is_flagged_not_raised(self) -> None:
        # End-to-end: a name containing an undecodable label is flagged, never raises.
        v = A.classify_idn("xn--zz.example.com")
        assert v.labels[0].severity == A.SEV_FLAGGED
        assert v.labels[0].decode_error == "UnicodeDecodeError"
        assert v.severity == A.SEV_FLAGGED


# --------------------------------------------------------------------------- #
# The cross-check: the SHIPPED analyzer agrees with the Phase-2 oracle, the golden
# decision table, and the Phase-1 corpus across EVERY row. This is the gate that
# the full range tables agree with the scoped oracle map.
# --------------------------------------------------------------------------- #


class TestAnalyzerMatchesPhase2OracleAndCorpus:
    """The shipped analyzer's decode / resolved-set / severity reproduce the Phase-2
    oracle EXACTLY over the golden table and the corpus -- so the shipped tables and
    the scoped oracle map cannot silently diverge (0 FP on legit / CJK / IDN-ccTLD)."""

    @pytest.mark.parametrize("row", _single_label_rows(), ids=lambda r: r["id"])
    def test_single_label_matches_oracle_and_golden(self, row: dict) -> None:
        a_label = row["a_label"]
        # The shipped analyzer reproduces the oracle's decode + resolved set + severity...
        o_decoded = ORACLE.decode_label(a_label)
        a_decoded = A.decode_idn_label(a_label)
        assert a_decoded == o_decoded, f"{row['id']}: decode"
        o_scripts = ORACLE.resolved_scripts(o_decoded) - {ORACLE.UNKNOWN_SCRIPT}
        a_scripts = A.resolved_script_set(a_decoded)
        assert a_scripts == o_scripts, f"{row['id']}: resolved scripts"
        assert A.severity_of(a_decoded) == ORACLE.severity(o_decoded), f"{row['id']}: severity"
        # ...and matches the committed golden row directly.
        assert sorted(a_scripts) == sorted(row["resolved_scripts"]), f"{row['id']}: golden scripts"
        assert A.severity_of(a_decoded) == row["severity"], f"{row['id']}: golden severity"

    @pytest.mark.parametrize("row", _multi_label_rows(), ids=lambda r: r["id"])
    def test_multi_label_matches_golden_per_label(self, row: dict) -> None:
        verdict = A.classify_idn(row["a_name"])
        got_scripts = [sorted(lv.scripts) for lv in verdict.labels]
        assert got_scripts == [sorted(s) for s in row["per_label_scripts"]], f"{row['id']}: per-label scripts"
        assert [lv.severity for lv in verdict.labels] == row["per_label_severity"], f"{row['id']}: per-label sev"
        assert verdict.severity == row["severity"], f"{row['id']}: name severity"

    def test_corpus_single_label_severities(self) -> None:
        failures: list[str] = []
        for section in (
            "legit_single_label",
            "homograph_single_label",
            "suspicious_single_label",
            "limitation_whole_script",
        ):
            for entry in CORPUS[section]:
                got = A.severity_of(entry["decoded"])
                want = entry["expected_severity"]
                if got != want:
                    failures.append(f"{section}/{entry.get('a_label', entry['decoded'])}: {got} != {want}")
        assert not failures, "analyzer disagrees with the Phase-1 corpus:\n" + "\n".join(failures)

    def test_corpus_multi_label_per_label_no_union(self) -> None:
        for section in ("legit_multi_label", "homograph_multi_label"):
            for entry in CORPUS[section]:
                verdict = A.classify_idn(entry["a_name"])
                assert verdict.severity == entry["expected_severity"], entry["a_name"]
                assert [lv.severity for lv in verdict.labels] == entry["per_label_severity"], entry["a_name"]

    def test_zero_false_positive_on_every_legit_entry(self) -> None:
        # The FP contract, stated directly: NO legit-tier corpus entry is malicious.
        for section in ("legit_single_label", "legit_multi_label"):
            for entry in CORPUS[section]:
                if "a_name" in entry:
                    sev = A.classify_idn(entry["a_name"]).severity
                else:
                    sev = A.severity_of(entry["decoded"])
                assert sev != A.SEV_MALICIOUS, f"FALSE POSITIVE on legit {entry.get('a_label', entry.get('a_name'))}"


def test_shipped_unicode_version_documented() -> None:
    """The shipped tables are pinned to a Unicode version; pin it so a refresh is a
    deliberate, visible change matching the corpus/spec ucd_version."""
    assert U.UNICODE_VERSION == "15.1.0"
    assert U.UNICODE_VERSION == DECISION_TABLE["_meta"]["ucd_version"]


def test_shipped_tables_are_sorted_and_parallel() -> None:
    """The range tables are parallel sorted arrays (the bisect contract). A broken
    emission (unsorted / length-mismatched) would silently corrupt lookups."""
    assert len(U.SCRIPT_RANGE_STARTS) == len(U.SCRIPT_RANGE_ENDS) == len(U.SCRIPT_RANGE_NAMES)
    assert len(U.SCRIPTX_RANGE_STARTS) == len(U.SCRIPTX_RANGE_ENDS) == len(U.SCRIPTX_RANGE_NAMES)
    assert list(U.SCRIPT_RANGE_STARTS) == sorted(U.SCRIPT_RANGE_STARTS)
    assert list(U.SCRIPTX_RANGE_STARTS) == sorted(U.SCRIPTX_RANGE_STARTS)
    # Every range is well-formed (start <= end).
    assert all(s <= e for s, e in zip(U.SCRIPT_RANGE_STARTS, U.SCRIPT_RANGE_ENDS))
    assert all(s <= e for s, e in zip(U.SCRIPTX_RANGE_STARTS, U.SCRIPTX_RANGE_ENDS))
