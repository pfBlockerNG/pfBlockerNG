# pfb_idn_analyzer.py
# pfBlockerNG - pure TR39 cross-script IDN homoglyph analyzer (ADR-08).

# part of pfSense (https://www.pfsense.org)
# Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
# Copyright (c) 2015-2024 BBcan177@gmail.com
# All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pure, Unbound-symbol-free TR39 mixed-script IDN homoglyph analyzer (ADR-08).

A DNS query name reaches the matcher as punycode ASCII (``xn--…``). Script
analysis is impossible on the A-label, so each ``xn--`` label is decoded to
Unicode with the stdlib RAW ``'punycode'`` codec (NOT ``'idna'`` — its IDNA2003
validation throws on analysable attack labels), its resolved script set computed
from the shipped Scripts / Script_Extensions range tables (``pfb_unicode_scripts``,
Common/Inherited/Unknown transparent), and a severity assigned:

  * **MALICIOUS** — the label's resolved set contains >= 2 of the mutually-
    confusable trio {Latin, Cyrillic, Greek} (Latin+Cyrillic, Latin+Greek, OR
    Cyrillic+Greek — NOT Latin-anchored). No legit orthography mixes any pair.
  * **SUSPICIOUS** — multi-script that fails UTS#39 *Highly Restrictive* but is
    not the malicious pair (e.g. Latin+Armenian/Cherokee/Coptic).
  * **OK** (legit) — single-script (incl. all-Latin/-Cyrillic/-Greek) or Latin +
    CJK companions {Han, Hiragana, Katakana, Hangul, Bopomofo} (UTS#39 Highly
    Restrictive). Never touched in Confusable mode.
  * **FLAGGED** — an undecodable label (malformed punycode, caught) or a decoded
    label whose code points carry no letter-script (empty / control char / emoji).
    NOT malicious (no confusable mix) but NOT silently legit — surfaced so an
    anomaly is never silently passed and the decode NEVER crashes the resolver.

Analysis is **per label**: each dot-separated label is decoded and classified with
its OWN resolved set; a name's severity is the most severe label. Scripts are
NEVER unioned across the dot — else a legit ASCII/Latin SLD under an IDN ccTLD
(``example.рф``, ``site.中国``) would falsely read as a confusable mix.

This module is graded against the Phase-2 oracle (``tests/test_adr08_decision_spec.py``)
over the Phase-1 corpus; it references NO Unbound symbol and is stdlib-only, so the
matcher (Phase 5) can call it and it stays unit-testable off-appliance.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass

from pfb_unicode_scripts import (
    SCRIPT_RANGE_ENDS,
    SCRIPT_RANGE_NAMES,
    SCRIPT_RANGE_STARTS,
    SCRIPTX_RANGE_ENDS,
    SCRIPTX_RANGE_NAMES,
    SCRIPTX_RANGE_STARTS,
)

# --------------------------------------------------------------------------- #
# Severity / restriction-level vocabulary (mirrors the Phase-2 oracle).
# --------------------------------------------------------------------------- #

SEV_LEGIT = "legit"
SEV_SUSPICIOUS = "suspicious"
SEV_MALICIOUS = "malicious"
SEV_FLAGGED = "flagged"

LEVEL_ASCII = "ascii_only"
LEVEL_SINGLE = "single_script"
LEVEL_HIGHLY_RESTRICTIVE = "highly_restrictive"
LEVEL_NON_RESTRICTIVE = "non_restrictive"

# The mutually-confusable trio (RESULTS/01 section 3; ADR-08 section 2).
CONFUSABLE_SET = frozenset({"Latin", "Cyrillic", "Greek"})
# UTS#39 "Highly Restrictive" CJK companions to Han (Jpan / Kore / Hanb).
CJK_COMPANIONS = frozenset({"Hiragana", "Katakana", "Hangul", "Bopomofo"})
_HIGHLY_RESTRICTIVE_SET = frozenset({"Latin", "Han"}) | CJK_COMPANIONS

# Severity ordering for "most severe label wins" across a name.
_SEV_ORDER = {SEV_LEGIT: 0, SEV_FLAGGED: 1, SEV_SUSPICIOUS: 2, SEV_MALICIOUS: 3}

# Decode exceptions the raw 'punycode' codec can raise on malformed input
# (RESULTS/01 section 5). Caught -> the label is FLAGGED, never propagated.
_DECODE_ERRORS = (UnicodeDecodeError, UnicodeError, ValueError)


# --------------------------------------------------------------------------- #
# Punycode decode + per-code-point script lookup (shipped range tables).
# --------------------------------------------------------------------------- #


def decode_idn_label(label: str) -> str:
    """Raw stdlib ``'punycode'`` decode of one label; non-``xn--`` returned as-is.

    Uses the RAW ``'punycode'`` codec, NOT ``'idna'`` (whose IDNA2003 validation
    rejects analysable attack labels the raw codec decodes — e.g. ``xn--a`` ->
    U+0080, ``xn--`` -> ''). MAY raise (``UnicodeDecodeError`` / ``UnicodeError`` /
    ``ValueError``) on malformed input; ``classify_label`` catches it so the
    resolver never propagates a decode error.
    """
    if not label.startswith("xn--"):
        return label
    return label[4:].encode("ascii").decode("punycode")


def script_of(codepoint: int) -> tuple[str, ...]:
    """Resolved script(s) of one code point: Script_Extensions when present, else Script.

    Returns the tuple of script long-names a code point carries for confusable
    analysis. Script_Extensions takes precedence (a code point shared by several
    scripts narrows to that set); otherwise the plain Script applies. Common /
    Inherited / Unknown are NOT in the shipped tables (dropped at generation time),
    so a transparent or unassigned code point returns the empty tuple — it
    contributes no script to the resolved set.
    """
    # Script_Extensions first (binary search over sorted range starts).
    i = bisect.bisect_right(SCRIPTX_RANGE_STARTS, codepoint) - 1
    if i >= 0 and codepoint <= SCRIPTX_RANGE_ENDS[i]:
        return SCRIPTX_RANGE_NAMES[i]
    # Fall back to the plain Script property.
    j = bisect.bisect_right(SCRIPT_RANGE_STARTS, codepoint) - 1
    if j >= 0 and codepoint <= SCRIPT_RANGE_ENDS[j]:
        return (SCRIPT_RANGE_NAMES[j],)
    return ()


def resolved_script_set(text: str) -> set[str]:
    """Resolved script set for one already-decoded label's *text*.

    Union of each code point's resolved scripts (``script_of``), with Common /
    Inherited transparent (they are absent from the tables, so they add nothing).
    A code point with no letter-script (control / emoji / unassigned) contributes
    nothing too — an all-scriptless label therefore yields the EMPTY set, the
    FLAGGED trigger. Never unions across the dot (operates on one label).
    """
    out: set[str] = set()
    for ch in text:
        out.update(script_of(ord(ch)))
    return out


# --------------------------------------------------------------------------- #
# Restriction level + severity (per label; mirrors the Phase-2 oracle).
# --------------------------------------------------------------------------- #


def restriction_level(scripts: set[str], *, ascii_only: bool = False) -> str:
    """UTS#39 restriction level for a resolved script set (the documented intermediate)."""
    if ascii_only:
        return LEVEL_ASCII
    if len(scripts) == 1:
        return LEVEL_SINGLE
    if scripts and scripts <= _HIGHLY_RESTRICTIVE_SET and len(scripts) >= 2:
        # Latin + CJK companions (Jpan/Kore/Hanb) -- the legit multi-script allow-set.
        return LEVEL_HIGHLY_RESTRICTIVE
    return LEVEL_NON_RESTRICTIVE


def severity_of(text: str) -> str:
    """legit | suspicious | malicious | flagged for ONE decoded label.

    Never unions across the dot. The rule:
      * >= 2 of the confusable trio -> MALICIOUS (not Latin-anchored);
      * no resolvable letter-script (empty / control / emoji) -> FLAGGED;
      * single script or Latin+CJK (Highly Restrictive) -> LEGIT;
      * any other multi-script mix -> SUSPICIOUS.
    """
    scripts = resolved_script_set(text)

    if len(scripts & CONFUSABLE_SET) >= 2:
        return SEV_MALICIOUS
    if not scripts:
        return SEV_FLAGGED
    if restriction_level(scripts) in (LEVEL_SINGLE, LEVEL_HIGHLY_RESTRICTIVE):
        return SEV_LEGIT
    return SEV_SUSPICIOUS


# --------------------------------------------------------------------------- #
# Verdicts (decode-safe; the public classify_* surface for Phase 5).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LabelVerdict:
    """Decode-safe analysis of ONE label.

    ``offending``: the resolved scripts that drove a non-legit verdict (the >=2
    confusable scripts that co-occur for MALICIOUS, the full multi-script set for
    SUSPICIOUS, the empty set for FLAGGED/LEGIT) — surfaced for dual-form logging
    (decoded Unicode + offending script/char), mirroring the alerts page's
    existing ``idn_to_utf8`` display.
    """

    a_label: str
    decoded: str | None  # None when the label could not be decoded.
    scripts: frozenset[str]
    severity: str
    offending: frozenset[str]
    decode_error: str | None  # exception type name when decode raised, else None.


@dataclass(frozen=True)
class NameVerdict:
    """Per-label analysis of a whole dot-separated name; most-severe label wins."""

    a_name: str
    labels: tuple[LabelVerdict, ...]
    severity: str
    offending: frozenset[str]


def _offending_scripts(scripts: frozenset[str], severity: str) -> frozenset[str]:
    """The script(s) that explain a non-legit verdict (for logging)."""
    if severity == SEV_MALICIOUS:
        return frozenset(scripts & CONFUSABLE_SET)
    if severity == SEV_SUSPICIOUS:
        return scripts
    return frozenset()


def classify_label(a_label: str) -> LabelVerdict:
    """Decode + classify ONE label, NEVER raising.

    A punycode decode error is CAUGHT (the resolver must not crash on a malformed
    ``xn--`` label) and the label recorded as FLAGGED with ``decode_error`` set and
    ``decoded`` None.
    """
    try:
        decoded = decode_idn_label(a_label)
    except _DECODE_ERRORS as exc:
        return LabelVerdict(
            a_label=a_label,
            decoded=None,
            scripts=frozenset(),
            severity=SEV_FLAGGED,
            offending=frozenset(),
            decode_error=type(exc).__name__,
        )
    scripts = frozenset(resolved_script_set(decoded))
    sev = severity_of(decoded)
    return LabelVerdict(
        a_label=a_label,
        decoded=decoded,
        scripts=scripts,
        severity=sev,
        offending=_offending_scripts(scripts, sev),
        decode_error=None,
    )


def classify_idn(q_name: str) -> NameVerdict:
    """Classify a whole DNS name PER-LABEL; the name severity is the most severe label.

    The public entry point the Phase-5 matcher calls on ``xn--`` queries. Splits on
    ``'.'``, classifies EACH label independently (decode-safe), and returns the
    most-severe label's severity as the name verdict — NEVER unioning scripts across
    the dot (the load-bearing FP guard: ``example.рф`` / ``site.中国`` stay legit; a
    malicious subdomain label makes the whole name malicious). ``offending`` carries
    the offending scripts of the worst label for logging.
    """
    verdicts = tuple(classify_label(lbl) for lbl in q_name.split("."))
    worst = verdicts[0] if verdicts else None
    for v in verdicts[1:]:
        if _SEV_ORDER[v.severity] > _SEV_ORDER[worst.severity]:
            worst = v
    severity = worst.severity if worst is not None else SEV_LEGIT
    offending = worst.offending if worst is not None else frozenset()
    return NameVerdict(a_name=q_name, labels=verdicts, severity=severity, offending=offending)
