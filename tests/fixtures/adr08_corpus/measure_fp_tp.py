#!/usr/bin/env python3
"""ADR-08 Phase 1 — THROWAWAY FP/TP measurement over the frozen IDN corpus.

NOT a pytest test and NOT production code. This is the de-risk instrument the
phase prompt asks for: it applies the *finalised* confusable-script rule to
``corpus.json`` and prints the FP (false positives on the LEGIT set) and TP
(true positives on the HOMOGRAPH set), the per-label IDN-ccTLD outcome, the
suspicious tier, the documented whole-script limitation, the stdlib punycode
decode + edge handling, and a per-query cost sanity check.

It is self-contained / offline: the per-codepoint resolved-script map below is
generated ONCE from UCD 15.1.0 (Scripts.txt + ScriptExtensions.txt, Script_
Extensions preferred, Common/Inherited transparent) and scoped to exactly the
codepoints used by the corpus. The shipped Phase-4 generator/analyzer will
replace this embedded map with the full range tables; here it only needs to
reproduce the resolved set for the corpus labels so the numbers are real.

Run:  python tests/fixtures/adr08_corpus/measure_fp_tp.py

HISTORICAL MODEL (#723): this instrument is the Phase-1 GO-gate snapshot and
deliberately does NOT track the shipped analyzer. The production TR39 analyzer
(pfb_unbound.py) has a FLAGGED tier this script lacks (3 tiers here vs 4
shipped) and derives scripts via unicodedata.name(), while this script times
its own scoped-dict lookup -- so the ~0.70us cost figure and the tier model
cited by ADR-08 describe THIS simplified model, not production. Production
FP/TP behaviour is re-proven by tests/test_adr08_analyzer.py; do not re-run
this script expecting production numbers.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

# Resolved script set per codepoint (UCD 15.1.0; [] == transparent Common/Inherited).
# Scoped to the corpus codepoints (regenerate from UCD when the corpus changes).
SCRIPT_MAP: dict[int, list[str]] = {
    0x002D: [],
    0x0031: [],
    0x0032: [],
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
    0x00E9: ["Latin"],
    0x00FC: ["Latin"],
    0x03AC: ["Greek"],
    0x03B1: ["Greek"],
    0x03B4: ["Greek"],
    0x03B5: ["Greek"],
    0x03BB: ["Greek"],
    0x03BF: ["Greek"],
    0x0430: ["Cyrillic"],
    0x0435: ["Cyrillic"],
    0x0438: ["Cyrillic"],
    0x043E: ["Cyrillic"],
    0x0440: ["Cyrillic"],
    0x0441: ["Cyrillic"],
    0x0444: ["Cyrillic"],
    0x044F: ["Cyrillic"],
    0x0455: ["Cyrillic"],
    0x04CF: ["Cyrillic"],
    0x0561: ["Armenian"],
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
    0x13A0: ["Cherokee"],
    0x2C81: ["Coptic"],
    0x30A4: ["Katakana"],
    0x30B9: ["Katakana"],
    0x30C6: ["Katakana"],
    0x30C8: ["Katakana"],
    0x30C9: ["Katakana"],
    0x30E1: ["Katakana"],
    0x30F3: ["Katakana"],
    0x4E2D: ["Han"],
    0x540D: ["Han"],
    0x56FD: ["Han"],
    0x6587: ["Han"],
    0x65E5: ["Han"],
    0x672C: ["Han"],
    0x8A9E: ["Han"],
    0xAD6D: ["Hangul"],
    0xB3C4: ["Hangul"],
    0xBA54: ["Hangul"],
    0xC5B4: ["Hangul"],
    0xC778: ["Hangul"],
    0xD55C: ["Hangul"],
}

# The finalised rule (ADR-08 §2 + Phase-1 decision).
CONFUSABLE_SET = frozenset({"Latin", "Cyrillic", "Greek"})
# Restriction-Level "Highly Restrictive" legit CJK companions to Han.
CJK_COMPANIONS = frozenset({"Hiragana", "Katakana", "Hangul", "Bopomofo"})


def decode_label(a_label: str) -> str:
    """stdlib raw 'punycode' decode of one xn-- label (raises on malformed)."""
    if not a_label.startswith("xn--"):
        return a_label
    return a_label[4:].encode("ascii").decode("punycode")


def resolved_scripts(label_unicode: str) -> set[str]:
    """Per-label resolved script set (transparent Common/Inherited dropped)."""
    out: set[str] = set()
    for ch in label_unicode:
        out.update(SCRIPT_MAP.get(ord(ch), ["__UNKNOWN__"]))
    return out


def severity(label_unicode: str) -> str:
    """legit | suspicious | malicious for ONE label (never cross-label union)."""
    scripts = resolved_scripts(label_unicode)
    if not scripts:  # all-transparent (digits/hyphen)
        return "legit"
    # malicious: >=2 of the mutually-confusable trio co-occur.
    if len(scripts & CONFUSABLE_SET) >= 2:
        return "malicious"
    # legit: single script (incl. all-Latin/Cyrillic/Greek), or Latin+CJK /
    # CJK-internal (Highly Restrictive).
    if len(scripts) == 1:
        return "legit"
    if scripts <= ({"Latin", "Han"} | CJK_COMPANIONS):
        return "legit"
    # anything else multi-script -> suspicious (alert tier).
    return "suspicious"


def name_severity(label_unicodes: list[str]) -> str:
    """Whole-name verdict = the most severe of its labels (per-label, no union)."""
    order = {"legit": 0, "suspicious": 1, "malicious": 2}
    worst = "legit"
    for lab in label_unicodes:
        s = severity(lab)
        if order[s] > order[worst]:
            worst = s
    return worst


def main() -> None:
    corpus = json.loads((Path(__file__).parent / "corpus.json").read_text())

    print("=" * 78)
    print("ADR-08 Phase 1 — FP/TP measurement (rule: >=2 of {Latin,Cyrillic,Greek}/label)")
    print("=" * 78)

    fp = 0  # legit wrongly flagged malicious/suspicious-as-block
    fp_detail: list[str] = []
    tp = 0  # homographs correctly flagged malicious
    tp_total = 0

    # --- LEGIT single-label: malicious-tier FP must be 0 (CJK especially) ---
    print("\n[LEGIT single-label]  (must NOT be malicious)")
    for e in corpus["legit_single_label"]:
        got = severity(e["decoded"])
        flag = "" if got == "legit" else f"  <-- FP ({got})"
        if got == "malicious":
            fp += 1
            fp_detail.append(f"{e['a_label']} ({e['label_class']}) -> {got}")
        print(f"  {e['a_label']:20} {e['label_class']:24} got={got}{flag}")

    # --- LEGIT IDN-ccTLD multi-label: per-label keeps them legit ---
    print("\n[LEGIT IDN-ccTLD multi-label]  (per-label; union would FALSE-POSITIVE)")
    for e in corpus["legit_multi_label"]:
        labs = [lab["label"] for lab in e["labels"]]
        got = name_severity(labs)
        union = set().union(*(resolved_scripts(lbl) for lbl in labs))
        union_mal = len(union & CONFUSABLE_SET) >= 2
        if got == "malicious":
            fp += 1
            fp_detail.append(f"{e['a_name']} -> {got}")
        print(f"  {e['a_name']:28} per-label={got:10} WRONG-union={sorted(union)} union-malicious={union_mal}")

    # --- HOMOGRAPH single-label: TP ---
    print("\n[HOMOGRAPH single-label]  (must be malicious)")
    for e in corpus["homograph_single_label"]:
        tp_total += 1
        got = severity(e["decoded"])
        ok = got == "malicious"
        tp += ok
        print(f"  {e['a_label']:20} {e['mix']:16} got={got:10} {'TP' if ok else 'MISS'}")

    # --- HOMOGRAPH subdomain multi-label: TP (registry can't catch) ---
    print("\n[HOMOGRAPH subdomain multi-label]  (per-label catches subdomain)")
    for e in corpus["homograph_multi_label"]:
        tp_total += 1
        labs = [lab["label"] for lab in e["labels"]]
        got = name_severity(labs)
        ok = got == "malicious"
        tp += ok
        print(f"  {e['a_name']:34} got={got:10} {'TP' if ok else 'MISS'}")

    # --- SUSPICIOUS tier (alert, not block by default): not an FP, not malicious ---
    print("\n[SUSPICIOUS single-label]  (alert tier; NOT malicious -> no default block)")
    for e in corpus["suspicious_single_label"]:
        got = severity(e["decoded"])
        note = "" if got == "suspicious" else f"  <-- expected suspicious, got {got}"
        if got == "malicious":  # over-blocking a borderline = FP against the legit allow-set
            fp += 1
            fp_detail.append(f"{e['a_label']} ({e['mix']}) -> malicious (should be suspicious)")
        print(f"  {e['a_label']:20} {e['mix']:16} got={got}{note}")

    # --- LIMITATION: whole-script Cyrillic look-alike NOT caught (documented) ---
    print("\n[LIMITATION whole-script]  (single-script -> NOT caught, documented)")
    for e in corpus["limitation_whole_script"]:
        got = severity(e["decoded"])
        print(f"  {e['a_label']:20} got={got:10} (documented out-of-scope)")

    # --- EDGE: punycode decode robustness ---
    print("\n[EDGE punycode decode]  (every label: decode_ok OR caught, never propagates)")
    safe = True
    for e in corpus["edge_decode"]:
        try:
            u = decode_label(e["a_label"])
            outcome = f"decoded={u!r}"
        except (UnicodeDecodeError, UnicodeError, ValueError) as exc:
            outcome = f"CAUGHT {type(exc).__name__}"
        except Exception as exc:  # any other -> would crash the resolver: FAIL the gate
            outcome = f"UNCAUGHT {type(exc).__name__}: {exc}"
            safe = False
        print(f"  {e['a_label']:18} {outcome}")

    # --- COST: per-query analyzer cost on xn-- labels ---
    sample = [e["decoded"] for e in corpus["homograph_single_label"]] * 2000
    t0 = time.perf_counter()
    for s in sample:
        severity(s)
    dt = time.perf_counter() - t0
    per_us = dt / len(sample) * 1e6

    legit_n = (
        len(corpus["legit_single_label"]) + len(corpus["legit_multi_label"]) + len(corpus["suspicious_single_label"])
    )
    print("\n" + "=" * 78)
    print("RESULTS")
    print("=" * 78)
    print(f"  FP (legit/suspicious wrongly -> malicious): {fp} / {legit_n} legit-tier labels")
    if fp_detail:
        for d in fp_detail:
            print(f"      FP: {d}")
    print(f"  TP (homographs caught):                    {tp} / {tp_total}")
    print(f"  Punycode decode safe (no uncaught raise):  {safe}")
    print(f"  Analyzer cost per xn-- label:              ~{per_us:.2f} us")
    cjk = [
        e
        for e in corpus["legit_single_label"]
        if "japanese" in e["label_class"] or "korean" in e["label_class"] or "chinese" in e["label_class"]
    ]
    cjk_fp = sum(1 for e in cjk if severity(e["decoded"]) == "malicious")
    cctld_fp = sum(
        1 for e in corpus["legit_multi_label"] if name_severity([lab["label"] for lab in e["labels"]]) == "malicious"
    )
    print(f"  CJK FP (must be 0):                        {cjk_fp}")
    print(f"  IDN-ccTLD per-label FP (must be 0):        {cctld_fp}")
    gate = (fp == 0) and (tp == tp_total) and safe and cjk_fp == 0 and cctld_fp == 0
    print("\n  GATE:", "GO" if gate else "PIVOT/NARROW")


if __name__ == "__main__":
    main()
