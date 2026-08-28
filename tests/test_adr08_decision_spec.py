"""ADR-08 Phase 2 -- TR39 IDN homoglyph DECISION SPEC + golden oracle.

WHY THIS FILE EXISTS
--------------------
ADR-08 turns the blunt "block ALL IDN" toggle into a TR39 mixed-script analyzer
(decode each ``xn--`` label -> resolved script set -> restriction level ->
severity -> action). Unlike ADR-06, there is **no existing-code oracle to diff
against**: today's feature blocks *every* IDN -- the exact bluntness this ADR
replaces. So this module AUTHORS the TARGET, *before* any analyzer code exists:
the ``(label -> resolved-script-set -> restriction-level -> severity -> action)``
decision table that every later phase is graded against.

  * Phase 4 ships the production analyzer (Scripts/Script_Extensions range tables
    + the decode/resolve/restriction-level/severity logic). It must reproduce the
    severities/actions this oracle encodes.
  * Phase 5 wires it into the matcher. The net DNS decision (malicious->block,
    suspicious->alert, legit->resolve) must match this same table.

This file is a PURE reference (stdlib only, **no Unbound symbol**, importable as a
plain module) so the analyzer and the matcher diff against ONE table. The codepoint
-> resolved-script map (``SCRIPT_MAP``) is scoped to exactly the corpus + spec
codepoints, generated from UCD 15.1.0 (Script_Extensions preferred, Common/Inherited
transparent) -- the same map the Phase-1 throwaway ``measure_fp_tp.py`` used; the
Phase-4 generator replaces it with the full range tables. The oracle only needs to
reproduce the resolved set for these labels so the graded severities are real.

THE FINALISED RULE (RESULTS/01_Results.txt section 3, carried verbatim)
-----------------------------------------------------------------------
  * CONFUSABLE SET = {Latin, Cyrillic, Greek} (the mutually-confusable trio).
  * MALICIOUS (default block): a single label whose resolved set contains >= 2 of
    the trio -- Latin+Cyrillic OR Latin+Greek OR Cyrillic+Greek (NOT Latin-anchored).
  * PER-LABEL granularity: analyse EACH dot-separated label with its OWN resolved
    set; a name is malicious iff SOME label is. NEVER union across the dot.
  * LEGIT (UTS#39 Highly Restrictive): single script, OR Latin + CJK companions
    {Han, Hiragana, Katakana, Hangul, Bopomofo}. Common/Inherited transparent.
  * SUSPICIOUS (alert; block opt-in): multi-script that fails Highly Restrictive
    but isn't the malicious pair -- e.g. Latin+Armenian / Latin+Cherokee / Latin+Coptic.
  * Whole-script confusables (single-script) are NOT caught -- documented limitation.

BORDERLINE CALLS RECORDED (consistent with RESULTS/01)
------------------------------------------------------
  * Cherokee / Armenian / Coptic + Latin -> SUSPICIOUS, not malicious (outside the
    high-confidence trio; legit single-script use; default-block would risk FP).
  * Cyrillic+Greek with no Latin -> MALICIOUS (the rule is >=2 of the trio, not
    Latin-anchored).
  * An undecodable label (malformed punycode), or a decoded label whose code points
    carry no letter-script (empty / control char / emoji), resolves to severity
    ``FLAGGED`` -- NOT malicious (no confusable mix) but NOT silently legit either;
    surfaced so it is never silently passed, and the decode never crashes.
  * EXCEPTION: a digits/hyphen-only label (the EURid Common-only exempt characters,
    section 2's "Legitimate (no action)" row) also carries no letter-script but
    resolves ``LEGIT``, not ``FLAGGED`` -- the ONLY scriptless case that does (#720).

DECISION-LABEL DRIVER API (imported by Phases 4/5)
--------------------------------------------------
Pure module-level functions, no Unbound symbols:

  * ``decode_label(a_label) -> str``                 raw 'punycode' decode (may raise).
  * ``resolved_scripts(text) -> set[str]``           per-label resolved script set.
  * ``restriction_level(scripts) -> str``            UTS#39 level (one of LEVEL_*).
  * ``severity(text) -> str``                        ONE label -> SEV_* (never union).
  * ``analyze_label(a_label) -> LabelVerdict``        decode-safe label analysis.
  * ``analyze_name(a_name) -> NameVerdict``           per-label, most-severe wins.
  * ``action(sev, *, block_malicious=True, escalate_suspicious=False) -> str``
                                                      severity -> ACT_* under the
                                                      two ADR-08 sub-toggles.

Constants: ``CONFUSABLE_SET``, ``CJK_COMPANIONS``, ``SEV_LEGIT/SUSPICIOUS/MALICIOUS/
FLAGGED``, ``ACT_NONE/ALERT/BLOCK``, ``LEVEL_ASCII/SINGLE/HIGHLY_RESTRICTIVE/
NON_RESTRICTIVE``, ``UNKNOWN_SCRIPT``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import pytest

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

_HERE = os.path.dirname(__file__)
_SPEC = os.path.join(_HERE, "fixtures", "adr08_spec", "decision_table.json")
_CORPUS = os.path.join(_HERE, "fixtures", "adr08_corpus", "corpus.json")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


DECISION_TABLE = _load(_SPEC)
CORPUS = _load(_CORPUS)


# --------------------------------------------------------------------------- #
# Severity / action / restriction-level vocabulary
# --------------------------------------------------------------------------- #

SEV_LEGIT = "legit"
SEV_SUSPICIOUS = "suspicious"
SEV_MALICIOUS = "malicious"
SEV_FLAGGED = "flagged"

ACT_NONE = "none"
ACT_ALERT = "alert"
ACT_BLOCK = "block"

LEVEL_ASCII = "ascii_only"
LEVEL_SINGLE = "single_script"
LEVEL_HIGHLY_RESTRICTIVE = "highly_restrictive"
LEVEL_NON_RESTRICTIVE = "non_restrictive"

# A code point with no resolvable letter-script (control char / emoji) maps here.
UNKNOWN_SCRIPT = "Unknown"

# The finalised rule (RESULTS/01 section 3 + ADR-08 section 2).
CONFUSABLE_SET = frozenset({"Latin", "Cyrillic", "Greek"})
# UTS#39 "Highly Restrictive" CJK companions to Han (Jpan / Kore / Hanb).
CJK_COMPANIONS = frozenset({"Hiragana", "Katakana", "Hangul", "Bopomofo"})
_HIGHLY_RESTRICTIVE_SET = frozenset({"Latin", "Han"}) | CJK_COMPANIONS
# ADR-08 section 2: digits/hyphen (Common-only mixes) are the EURid-exempt,
# letter-less carve-out -- legit, never touched in Confusable mode -- distinct from
# every OTHER scriptless label (empty/control-char/emoji), which stays flagged
# (#720). Kept here so this oracle stays in lockstep with the shipped analyzer's
# severity_of().
_DIGIT_HYPHEN_CHARS = frozenset("0123456789-")


# --------------------------------------------------------------------------- #
# Codepoint -> resolved script map (UCD 15.1.0; Script_Extensions preferred,
# Common/Inherited transparent). Scoped to the corpus + spec codepoints -- the
# SAME basis as the Phase-1 measure_fp_tp.py. [] means transparent (no script);
# the Phase-4 generator replaces this with the full range tables.
# --------------------------------------------------------------------------- #

SCRIPT_MAP: dict[int, list[str]] = {
    0x002D: [],  # HYPHEN-MINUS (Common -> transparent)
    0x0031: [],  # DIGIT ONE
    0x0032: [],  # DIGIT TWO
    0x0061: ["Latin"],
    0x0062: ["Latin"],
    0x0063: ["Latin"],
    0x0065: ["Latin"],
    0x0066: ["Latin"],
    0x0067: ["Latin"],
    0x0068: ["Latin"],
    0x0069: ["Latin"],
    0x006B: ["Latin"],
    0x006C: ["Latin"],
    0x006D: ["Latin"],
    0x006E: ["Latin"],
    0x006F: ["Latin"],
    0x0070: ["Latin"],
    0x0073: ["Latin"],
    0x0074: ["Latin"],
    0x0078: ["Latin"],
    0x0079: ["Latin"],
    0x00E9: ["Latin"],  # é
    0x00FC: ["Latin"],  # ü
    0x03AC: ["Greek"],  # ά
    0x03B1: ["Greek"],  # α
    0x03B4: ["Greek"],  # δ
    0x03B5: ["Greek"],  # ε
    0x03BB: ["Greek"],  # λ
    0x03BF: ["Greek"],  # ο
    0x0430: ["Cyrillic"],  # а
    0x0435: ["Cyrillic"],  # е
    0x0438: ["Cyrillic"],  # и
    0x043E: ["Cyrillic"],  # о
    0x0440: ["Cyrillic"],  # р
    0x0441: ["Cyrillic"],  # с
    0x0444: ["Cyrillic"],  # ф
    0x044F: ["Cyrillic"],  # я
    0x0455: ["Cyrillic"],  # ѕ
    0x04CF: ["Cyrillic"],  # ӏ palochka
    0x0561: ["Armenian"],  # ա
    0x05D1: ["Hebrew"],
    0x05D9: ["Hebrew"],
    0x05E2: ["Hebrew"],
    0x05E8: ["Hebrew"],
    0x05EA: ["Hebrew"],
    0x0639: ["Arabic"],
    0x0642: ["Arabic"],
    0x0645: ["Arabic"],
    0x0648: ["Arabic"],
    0x0924: ["Devanagari"],
    0x092D: ["Devanagari"],
    0x0930: ["Devanagari"],
    0x093E: ["Devanagari"],
    0x0E17: ["Thai"],
    0x0E22: ["Thai"],
    0x0E44: ["Thai"],
    0x13A0: ["Cherokee"],  # Ꭰ
    0x2C81: ["Coptic"],  # ⲁ
    0x304D: ["Hiragana"],  # き
    0x30A4: ["Katakana"],
    0x30B9: ["Katakana"],
    0x30C6: ["Katakana"],
    0x30C8: ["Katakana"],
    0x30C9: ["Katakana"],
    0x30E1: ["Katakana"],
    0x30E2: ["Katakana"],  # モ
    0x30F3: ["Katakana"],
    0x4E2D: ["Han"],
    0x456E: ["Han"],  # xn--google junk ideograph
    0x4571: ["Han"],
    0x4575: ["Han"],
    0x4576: ["Han"],
    0x540D: ["Han"],
    0x56FD: ["Han"],
    0x6587: ["Han"],
    0x65E5: ["Han"],
    0x66F8: ["Han"],  # 書
    0x672C: ["Han"],
    0x8A9E: ["Han"],
    0xAD6D: ["Hangul"],
    0xB3C4: ["Hangul"],
    0xBA54: ["Hangul"],
    0xC5B4: ["Hangul"],
    0xC778: ["Hangul"],
    0xD55C: ["Hangul"],
}


# --------------------------------------------------------------------------- #
# The pure oracle (importable by Phases 4/5).
# --------------------------------------------------------------------------- #


def decode_label(a_label: str) -> str:
    """Raw stdlib 'punycode' decode of one ``xn--`` label.

    Uses the RAW 'punycode' codec (NOT 'idna', which adds IDNA2003 validation that
    throws on analysable attack labels -- RESULTS/01 section 5). A non-xn-- label is
    returned unchanged. MAY raise (UnicodeDecodeError / UnicodeError / ValueError) on
    malformed input -- the caller (analyze_label) catches it; the resolver never
    propagates a decode error.
    """
    if not a_label.startswith("xn--"):
        return a_label
    return a_label[4:].encode("ascii").decode("punycode")


def resolved_scripts(text: str) -> set[str]:
    """Per-label resolved script set for already-decoded Unicode ``text``.

    Script_Extensions preferred, Common/Inherited transparent (dropped). A code point
    not in the scoped map and carrying no letter-script (control char / emoji) maps to
    the ``UNKNOWN_SCRIPT`` sentinel so it is never silently treated as a known script.
    """
    out: set[str] = set()
    for ch in text:
        scripts = SCRIPT_MAP.get(ord(ch))
        if scripts is None:
            # Outside the scoped map: a letter we forgot would be a test bug, but a
            # control/symbol/emoji legitimately has no script -> Unknown sentinel.
            out.add(UNKNOWN_SCRIPT)
        else:
            out.update(scripts)
    return out


def restriction_level(scripts: set[str], *, ascii_only: bool = False) -> str:
    """UTS#39 restriction level for a resolved script set.

    ``ascii_only`` is a property of the raw label (all code points ASCII), passed in
    by the caller. The returned level is the documented intermediate the severity
    mapping reads -- pinned so a later phase can't silently change the classification.
    """
    letters = scripts - {UNKNOWN_SCRIPT}
    if ascii_only:
        return LEVEL_ASCII
    if len(letters) == 1:
        return LEVEL_SINGLE
    if letters and letters <= _HIGHLY_RESTRICTIVE_SET and len(letters) >= 2:
        # Latin + CJK companions (Jpan/Kore/Hanb) -- the legit multi-script allow-set.
        return LEVEL_HIGHLY_RESTRICTIVE
    return LEVEL_NON_RESTRICTIVE


def severity(text: str) -> str:
    """legit | suspicious | malicious | flagged for ONE decoded label.

    Never unions across the dot (operates on a single label's text). The rule:
      * >= 2 of the confusable trio -> MALICIOUS;
      * single resolvable script (incl. all-Latin/-Cyrillic/-Greek) or Latin+CJK
        (Highly Restrictive) -> LEGIT;
      * a digits/hyphen-only label (Common-only mix, section 2) -> LEGIT;
      * a label with NO resolvable letter-script AND NOT digits/hyphen-only (empty /
        control / emoji) -> FLAGGED;
      * any other multi-script mix (fails Highly Restrictive, not the malicious pair)
        -> SUSPICIOUS.
    """
    scripts = resolved_scripts(text)
    letters = scripts - {UNKNOWN_SCRIPT}

    # >= 2 of the mutually-confusable trio co-occur -> malicious (not Latin-anchored).
    if len(letters & CONFUSABLE_SET) >= 2:
        return SEV_MALICIOUS

    # No resolvable letter-script at all. Digits/hyphen-only is the ADR-08 section 2
    # Common-only carve-out (legit); every OTHER scriptless label (empty, control
    # char, emoji) stays flagged.
    if not letters:
        return SEV_LEGIT if text and set(text) <= _DIGIT_HYPHEN_CHARS else SEV_FLAGGED

    level = restriction_level(scripts, ascii_only=False)
    if level in (LEVEL_SINGLE, LEVEL_HIGHLY_RESTRICTIVE):
        return SEV_LEGIT

    # Multi-script, fails Highly Restrictive, not the malicious pair -> suspicious.
    return SEV_SUSPICIOUS


def action(sev: str, *, block_malicious: bool = True, escalate_suspicious: bool = False) -> str:
    """Severity -> action under the two ADR-08 sub-toggles (ADR-08 section 2).

    Defaults encode the shipped policy: ``block_malicious`` is default-ON (a malicious
    homograph is blocked unless the operator disables it, downgrading to alert);
    ``escalate_suspicious`` is default-OFF (a suspicious mix only alerts unless the
    opt-in escalates it to block). A FLAGGED anomaly is treated like the suspicious
    tier for the action: alerted, escalatable, never silently passed.
    """
    if sev == SEV_LEGIT:
        return ACT_NONE
    if sev == SEV_MALICIOUS:
        return ACT_BLOCK if block_malicious else ACT_ALERT
    if sev in (SEV_SUSPICIOUS, SEV_FLAGGED):
        return ACT_BLOCK if escalate_suspicious else ACT_ALERT
    raise ValueError(f"unknown severity {sev!r}")


_SEV_ORDER = {SEV_LEGIT: 0, SEV_FLAGGED: 1, SEV_SUSPICIOUS: 2, SEV_MALICIOUS: 3}


@dataclass(frozen=True)
class LabelVerdict:
    """Decode-safe analysis of one label."""

    a_label: str
    decoded: str | None  # None when the label could not be decoded.
    scripts: frozenset[str]
    severity: str
    decode_error: str | None  # exception type name when decode raised, else None.


@dataclass(frozen=True)
class NameVerdict:
    """Per-label analysis of a whole dot-separated name; most-severe label wins."""

    a_name: str
    labels: tuple[LabelVerdict, ...]
    severity: str


def analyze_label(a_label: str) -> LabelVerdict:
    """Decode + classify ONE label, never raising.

    A punycode decode error is CAUGHT (the resolver must not crash on a malformed
    ``xn--`` label, ADR-08 / RESULTS/01 section 5) and the label is recorded as
    FLAGGED with ``decode_error`` set and ``decoded`` None.
    """
    try:
        decoded = decode_label(a_label)
    except (UnicodeDecodeError, UnicodeError, ValueError) as exc:
        return LabelVerdict(
            a_label=a_label,
            decoded=None,
            scripts=frozenset(),
            severity=SEV_FLAGGED,
            decode_error=type(exc).__name__,
        )
    scripts = resolved_scripts(decoded)
    return LabelVerdict(
        a_label=a_label,
        decoded=decoded,
        scripts=frozenset(scripts),
        severity=severity(decoded),
        decode_error=None,
    )


def analyze_name(a_name: str) -> NameVerdict:
    """Analyse a whole name PER-LABEL; the name severity is the most severe label.

    Never unions scripts across the dot -- the load-bearing FP guard (example.рф,
    site.中国 stay legit; a malicious subdomain label makes the whole name malicious).
    """
    verdicts = tuple(analyze_label(lbl) for lbl in a_name.split("."))
    worst = SEV_LEGIT
    for v in verdicts:
        if _SEV_ORDER[v.severity] > _SEV_ORDER[worst]:
            worst = v.severity
    return NameVerdict(a_name=a_name, labels=verdicts, severity=worst)


# --------------------------------------------------------------------------- #
# TESTS
#
# Scenario (BDD): a DNS query name reaches the matcher's IDN branch as punycode
# ASCII. The TR39 analyzer must decode each label, resolve its script set, derive
# the UTS#39 restriction level, and map it to a severity, then to an action under
# the two sub-toggles. This suite pins that TARGET table (no production analyzer
# exists yet -- it is graded against this).
# --------------------------------------------------------------------------- #

_SEVERITY_TO_DEFAULT_ACTION = {
    SEV_LEGIT: ACT_NONE,
    SEV_SUSPICIOUS: ACT_ALERT,
    SEV_MALICIOUS: ACT_BLOCK,
    SEV_FLAGGED: ACT_ALERT,
}


def _single_label_rows() -> list[dict]:
    return DECISION_TABLE["single_label"]


def _multi_label_rows() -> list[dict]:
    return DECISION_TABLE["multi_label"]


def _edge_rows() -> list[dict]:
    return DECISION_TABLE["edge_decode"]


class TestSingleLabelDecisionTable:
    """Given a single label, When analysed, Then its resolved script set,
    restriction level, severity and default action MATCH the committed golden row.

    This is the core branch-coverage table: every severity outcome (legit /
    suspicious / malicious / flagged) and every restriction level appears, each
    with its own failable assertion. A wrong mapping (e.g. a CJK mix slipping into
    'malicious', or Cyrillic+Greek dropping to 'suspicious') fails the exact row.
    """

    @pytest.mark.parametrize("row", _single_label_rows(), ids=lambda r: r["id"])
    def test_label_matches_golden(self, row: dict) -> None:
        # Given a label and its committed expected resolved scripts.
        a_label = row["a_label"]
        ascii_only = a_label == row["decoded"] and a_label.isascii() and not a_label.startswith("xn--")

        # When the oracle analyses it.
        verdict = analyze_label(a_label)
        decoded = decode_label(a_label)
        scripts = resolved_scripts(decoded)
        letters = scripts - {UNKNOWN_SCRIPT}
        level = restriction_level(scripts, ascii_only=ascii_only)

        # Then the decoded form, resolved scripts, restriction level, severity and
        # default action all equal the golden row.
        assert decoded == row["decoded"], f"{row['id']}: decoded {decoded!r} != {row['decoded']!r}"
        assert sorted(letters) == sorted(row["resolved_scripts"]), f"{row['id']}: scripts {sorted(letters)}"
        assert level == row["restriction_level"], f"{row['id']}: level {level}"
        assert verdict.severity == row["severity"], f"{row['id']}: severity {verdict.severity}"
        assert action(verdict.severity) == row["action"], f"{row['id']}: action"
        # The default action must be the documented severity->action mapping.
        assert _SEVERITY_TO_DEFAULT_ACTION[verdict.severity] == row["action"]


class TestRestrictionLevelIsADistinctBranch:
    """The restriction level is a real intermediate, not cosmetics: assert each
    documented level is REACHED by some row, so a later phase can't collapse them."""

    def test_every_documented_level_is_exercised(self) -> None:
        seen = set()
        for row in _single_label_rows():
            seen.add(row["restriction_level"])
        # ASCII (example), single-script (münchen/россия/…), highly-restrictive
        # (Han+Katakana / Han+Hangul), non-restrictive (the homographs/suspicious).
        assert seen == {LEVEL_ASCII, LEVEL_SINGLE, LEVEL_HIGHLY_RESTRICTIVE, LEVEL_NON_RESTRICTIVE}


class TestCjkLegitFalsePositiveGuard:
    """The single most important non-block case (ADR-08 negative-risk section):
    a legitimate Latin+CJK domain must NOT be flagged malicious by a naive
    'any multi-script -> block'. Pinned with the before/after of the rule."""

    def test_han_katakana_is_legit_not_malicious(self) -> None:
        # Given the Japanese 'domain name' label (Han + Katakana).
        decoded = decode_label("xn--eckwd4c7c777u")
        scripts = resolved_scripts(decoded) - {UNKNOWN_SCRIPT}
        # When we observe it IS multi-script (so a naive any-mix rule would block it)...
        assert len(scripts) >= 2, "precondition: Han+Katakana is genuinely multi-script"
        assert scripts == {"Han", "Katakana"}
        # Then the restriction-level rule classifies it Highly Restrictive -> legit.
        assert restriction_level(resolved_scripts(decoded)) == LEVEL_HIGHLY_RESTRICTIVE
        assert severity(decoded) == SEV_LEGIT
        assert action(severity(decoded)) == ACT_NONE

    def test_han_hangul_is_legit_not_malicious(self) -> None:
        # Given the Korean Han+Hangul label.
        decoded = decode_label("xn--eqr704t9deq8o")
        scripts = resolved_scripts(decoded) - {UNKNOWN_SCRIPT}
        assert scripts == {"Han", "Hangul"} and len(scripts) >= 2
        assert severity(decoded) == SEV_LEGIT
        assert action(severity(decoded)) == ACT_NONE


class TestMaliciousConfusablePairs:
    """Each of the three confusable PAIRS is malicious->block, INCLUDING the
    non-Latin-anchored Cyrillic+Greek. Branch coverage of the malicious tier."""

    def test_latin_cyrillic_is_malicious(self) -> None:
        assert severity(decode_label("xn--pple-43d")) == SEV_MALICIOUS

    def test_latin_greek_is_malicious(self) -> None:
        assert severity(decode_label("xn--ggle-0nda")) == SEV_MALICIOUS

    def test_cyrillic_greek_no_latin_is_malicious(self) -> None:
        # Borderline call (RESULTS/01): the rule is >=2 of the trio, NOT Latin-anchored.
        decoded = decode_label("xn--mxa00ab")
        scripts = resolved_scripts(decoded) - {UNKNOWN_SCRIPT}
        assert "Latin" not in scripts, "precondition: this mix has NO Latin"
        assert scripts == {"Cyrillic", "Greek"}
        assert severity(decoded) == SEV_MALICIOUS

    def test_malicious_action_respects_block_malicious_toggle(self) -> None:
        # Default-ON: malicious -> block. Operator disable -> downgrades to alert.
        assert action(SEV_MALICIOUS) == ACT_BLOCK
        assert action(SEV_MALICIOUS, block_malicious=True) == ACT_BLOCK
        assert action(SEV_MALICIOUS, block_malicious=False) == ACT_ALERT


class TestSuspiciousTierBorderlineCalls:
    """Latin + a confusable-with-Latin script OUTSIDE the trio (Armenian / Cherokee
    / Coptic) is SUSPICIOUS, not malicious -- the recorded borderline call. Default
    action alerts; the opt-in escalates to block. Branch coverage off + on."""

    @pytest.mark.parametrize(
        "a_label,other",
        [
            ("xn--bnk-1ce", "Armenian"),
            ("xn--bnk-u8p", "Cherokee"),
            ("xn--bnk-q10b", "Coptic"),
        ],
    )
    def test_latin_plus_nontrio_is_suspicious_not_malicious(self, a_label: str, other: str) -> None:
        # Given a Latin + non-trio confusable mix.
        decoded = decode_label(a_label)
        scripts = resolved_scripts(decoded) - {UNKNOWN_SCRIPT}
        assert scripts == {"Latin", other}
        # Then it is suspicious (alert), explicitly NOT malicious (would be a default block).
        assert severity(decoded) == SEV_SUSPICIOUS
        assert severity(decoded) != SEV_MALICIOUS

    def test_suspicious_action_escalation_toggle(self) -> None:
        # Default-OFF: suspicious -> alert. Opt-in ON -> block. Both sides asserted.
        assert action(SEV_SUSPICIOUS) == ACT_ALERT
        assert action(SEV_SUSPICIOUS, escalate_suspicious=False) == ACT_ALERT
        assert action(SEV_SUSPICIOUS, escalate_suspicious=True) == ACT_BLOCK


class TestWholeScriptConfusableNotCaught:
    """DOCUMENTED LIMITATION (ADR-08 section 7): a whole-script (single-script)
    look-alike is NOT caught. Asserted as a no-op so the limitation is pinned --
    if a future change started catching it, this test would notice and force a
    deliberate decision."""

    def test_all_cyrillic_apple_lookalike_is_a_noop(self) -> None:
        # Given the all-Cyrillic 'apple' look-alike (аррӏе).
        decoded = decode_label("xn--80ak6aa92e")
        scripts = resolved_scripts(decoded) - {UNKNOWN_SCRIPT}
        # When analysed: it is single-script Cyrillic (no mix to detect)...
        assert scripts == {"Cyrillic"}
        # Then mixed-script detection does NOT catch it -> legit -> no action.
        # (This is the documented out-of-scope limitation, NOT a bug.)
        assert severity(decoded) == SEV_LEGIT
        assert action(severity(decoded)) == ACT_NONE


class TestPerLabelNeverUnionsAcrossTheDot:
    """The load-bearing per-label rule. A legit ASCII/Latin SLD under an IDN ccTLD
    stays legit (each label single-script) EVEN THOUGH the wrong whole-name union
    would read malicious; a malicious SUBDOMAIN label makes the whole name malicious.
    Asserts the analyzer NEVER unions scripts across the dot."""

    @pytest.mark.parametrize("row", _multi_label_rows(), ids=lambda r: r["id"])
    def test_name_matches_golden_per_label(self, row: dict) -> None:
        # Given an IDN name and its committed per-label scripts/severities.
        verdict = analyze_name(row["a_name"])

        # Then each label's resolved scripts + severity match the golden row...
        got_label_scripts = [sorted(lv.scripts - {UNKNOWN_SCRIPT}) for lv in verdict.labels]
        want_label_scripts = [sorted(s) for s in row["per_label_scripts"]]
        assert got_label_scripts == want_label_scripts, f"{row['id']}: per-label scripts"
        assert [lv.severity for lv in verdict.labels] == row["per_label_severity"], f"{row['id']}: per-label sev"
        # ...and the whole-name verdict (most-severe label) + action match.
        assert verdict.severity == row["severity"], f"{row['id']}: name severity"
        assert action(verdict.severity) == row["action"], f"{row['id']}: name action"

    def test_wrong_union_would_have_false_positived_the_cctld(self) -> None:
        """Prove the guard is real: the WRONG whole-name union of example.рф is
        {Cyrillic, Latin} -- which the malicious rule WOULD flag -- yet per-label
        analysis keeps it legit. This is the FP the per-label rule eliminates."""
        # Given example.рф.
        name = "example.рф"  # example.рф
        # When we (wrongly) union all labels' scripts across the dot...
        union: set[str] = set()
        for lbl in name.split("."):
            union |= resolved_scripts(decode_label("xn--p1ai") if lbl == "рф" else lbl)
        union -= {UNKNOWN_SCRIPT}
        # Then the union WOULD be malicious (>=2 of the trio)...
        assert len(union & CONFUSABLE_SET) >= 2, "the wrong union genuinely looks malicious"
        # ...but the correct per-label analysis is legit (no single label mixes the trio).
        assert analyze_name("example.xn--p1ai").severity == SEV_LEGIT

    def test_malicious_subdomain_label_blocks_whole_name(self) -> None:
        """A homograph in the SUBDOMAIN label (registries can't validate subdomains)
        -> the offending label is malicious -> the whole name is malicious."""
        verdict = analyze_name("xn--ypal-43d9g.example.com")
        # The first label is the malicious one; the rest are legit Latin.
        assert verdict.labels[0].severity == SEV_MALICIOUS
        assert [lv.severity for lv in verdict.labels[1:]] == [SEV_LEGIT, SEV_LEGIT]
        assert verdict.severity == SEV_MALICIOUS
        assert action(verdict.severity) == ACT_BLOCK


class TestMalformedLabelsAreFlaggedNotRaised:
    """A malformed / undecodable xn-- label must be FLAGGED, never raise -- the
    resolver must not crash (ADR-08 robustness contract; RESULTS/01 section 5).
    Branch coverage: a raising label, a decodable-but-scriptless label, and a
    decodable junk-CJK label that is legit."""

    @pytest.mark.parametrize("row", _edge_rows(), ids=lambda r: r["id"])
    def test_edge_label_matches_golden(self, row: dict) -> None:
        a_label = row["a_label"]
        # When analysed via the decode-safe path: it NEVER raises.
        verdict = analyze_label(a_label)
        assert verdict.severity == row["severity"], f"{row['id']}: severity {verdict.severity}"

        if not row["decode_ok"]:
            # A raising decoder -> flagged with the caught exception type recorded.
            # The raw 'punycode' codec raises UnicodeDecodeError on Python 3.13+ but
            # the base UnicodeError on 3.11/3.12 for some malformed inputs, so accept
            # any of the caught family (row["raises"] documents the representative).
            assert verdict.decode_error in {"UnicodeDecodeError", "UnicodeError", "ValueError"}, (
                f"{row['id']}: decode_error {verdict.decode_error!r}"
            )
            assert verdict.decoded is None
            assert verdict.severity == SEV_FLAGGED
        else:
            # A clean decode -> no error recorded.
            assert verdict.decode_error is None, f"{row['id']}: unexpected decode error"
            assert verdict.decoded is not None

    def test_raw_decode_actually_raises_for_the_raising_rows(self) -> None:
        """Pin that the 'raises' rows are genuinely malformed: the RAW decoder DOES
        raise on them (so analyze_label's catch is load-bearing, not dead code)."""
        for row in _edge_rows():
            if row["decode_ok"]:
                continue
            with pytest.raises((UnicodeDecodeError, UnicodeError, ValueError)):
                decode_label(row["a_label"])

    def test_no_edge_label_is_ever_malicious(self) -> None:
        """A malformed/contentless label must never be mis-classified malicious
        (no confusable mix exists)."""
        for row in _edge_rows():
            assert analyze_label(row["a_label"]).severity != SEV_MALICIOUS


class TestSeverityToActionMappingTotality:
    """The severity->action mapping is total and matches the documented policy for
    EVERY severity under BOTH sub-toggle states. No severity is unhandled."""

    def test_every_severity_maps_under_default_toggles(self) -> None:
        assert action(SEV_LEGIT) == ACT_NONE
        assert action(SEV_SUSPICIOUS) == ACT_ALERT
        assert action(SEV_MALICIOUS) == ACT_BLOCK
        assert action(SEV_FLAGGED) == ACT_ALERT

    def test_toggle_matrix(self) -> None:
        # block_malicious x escalate_suspicious -- all four corners pinned.
        assert action(SEV_MALICIOUS, block_malicious=True, escalate_suspicious=False) == ACT_BLOCK
        assert action(SEV_MALICIOUS, block_malicious=False, escalate_suspicious=False) == ACT_ALERT
        assert action(SEV_SUSPICIOUS, block_malicious=True, escalate_suspicious=True) == ACT_BLOCK
        assert action(SEV_SUSPICIOUS, block_malicious=True, escalate_suspicious=False) == ACT_ALERT
        # Legit is never blocked regardless of toggles.
        assert action(SEV_LEGIT, block_malicious=True, escalate_suspicious=True) == ACT_NONE

    def test_unknown_severity_raises(self) -> None:
        with pytest.raises(ValueError):
            action("nonsense")


class TestOracleAgreesWithThePhase1Corpus:
    """Cross-check: the oracle reproduces the expected_severity labelled in the
    Phase-1 corpus (corpus.json) for every single-label entry -- so the Phase-2
    spec and the Phase-1 de-risk corpus cannot silently diverge."""

    def test_corpus_single_label_severities(self) -> None:
        failures: list[str] = []
        sections = (
            "legit_single_label",
            "homograph_single_label",
            "suspicious_single_label",
            "limitation_whole_script",
        )
        for section in sections:
            for entry in CORPUS[section]:
                got = severity(entry["decoded"])
                want = entry["expected_severity"]
                if got != want:
                    failures.append(f"{section}/{entry.get('a_label', entry['decoded'])}: got {got} want {want}")
        assert not failures, "oracle disagrees with the Phase-1 corpus:\n" + "\n".join(failures)

    def test_corpus_multi_label_per_label_no_union(self) -> None:
        """The corpus' per-label IDN-ccTLD + subdomain cases agree with analyze_name."""
        for section in ("legit_multi_label", "homograph_multi_label"):
            for entry in CORPUS[section]:
                verdict = analyze_name(entry["a_name"])
                assert verdict.severity == entry["expected_severity"], entry["a_name"]
                assert [lv.severity for lv in verdict.labels] == entry["per_label_severity"], entry["a_name"]


class TestPunycodeDecodeFidelity:
    """The raw 'punycode' decode reproduces each corpus label's decoded Unicode --
    confirming the oracle decodes (not prefix-matches) and the codec is correct."""

    def test_decodes_match_corpus(self) -> None:
        for entry in CORPUS["legit_single_label"] + CORPUS["homograph_single_label"]:
            if not entry["a_label"].startswith("xn--"):
                continue
            assert decode_label(entry["a_label"]) == entry["decoded"], entry["a_label"]

    def test_decode_is_not_idna_codec(self) -> None:
        """Pin the RESULTS/01 section-5 decision to use the RAW 'punycode' codec,
        not the higher-level 'idna' codec. The distinction is load-bearing on the
        ANALYSABLE EDGE labels: 'idna' adds IDNA2003 validation that REJECTS labels
        the raw codec decodes fine (so we could still analyse / flag them) -- e.g.
        an overlong-byte label (xn--a -> U+0080) and the empty payload (xn--).
        Using 'idna' would turn those analysable labels into decode errors."""
        # raw punycode decodes the overlong-byte edge label...
        assert decode_label("xn--a") == "\x80"
        assert decode_label("xn--") == ""
        # ...whereas the higher-level 'idna' codec REJECTS both.
        with pytest.raises(UnicodeError):
            "xn--a".encode("ascii").decode("idna")
        with pytest.raises(UnicodeError):
            "xn--".encode("ascii").decode("idna")


def test_unicodedata_version_documented() -> None:
    """Pin the UCD version the corpus/spec GOLDEN was authored against (15.1.0) so a
    refresh of the fixtures is a deliberate, visible change. No runtime-UCD assertion:
    the analyzer reads scripts from whatever stdlib UCD is present (Python 3.11 ships
    14.0.0, 3.12/3.13 ship 15.1.0, 3.14 ships 16.0.0) and the corpus cross-check proves
    it agrees with the golden across those versions for the established scripts in scope."""
    assert DECISION_TABLE["_meta"]["ucd_version"] == "15.1.0"
