#!/usr/bin/env python3
"""update_tld_lists.py — refresh the gTLD/ccTLD/iTLD picker arrays from IANA.

pfblockerng_dnsbl.php's TLD Allow feature ($tld_list['gTLD'/'ccTLD'/'iTLD']) is a
snapshot of IANA's root-zone TLD list, hand-curated with two markers: '*' (used by
at least one DNSBL feed) and '!' (Spamhaus "most abused" TLD) -- see the page's
own Legend text. This script refreshes those three arrays from the authoritative
IANA source while preserving that curation.

Data sources
------------
- REQUIRED: https://data.iana.org/TLD/tlds-alpha-by-domain.txt (the TLD set).
- OPTIONAL: https://data.iana.org/TLD/tlds.json (country-code refinement only).
  It can be unreachable or return an empty body (observed in some sandboxed
  environments) -- classification never depends on it; the heuristic below is
  correct on its own.

Classification heuristic
-------------------------
- starts with 'xn--'        -> iTLD (punycode / IDN)
- exactly two ASCII letters -> ccTLD
- else                      -> gTLD

$tld_list['bgTLD'] (hand-curated "branded" generic TLDs) is NOT an IANA
category and is never regenerated -- but its keys are subtracted from the
fresh gTLD set so a branded TLD isn't duplicated into both arrays. A brand-new
generic TLD not yet triaged into bgTLD lands in gTLD until a human moves it;
that is expected.

Labels for a RETAINED tld (already present in the existing array) keep the
existing label VERBATIM minus its trailing registration-count bracket (that
count is unreproducible once source-order counts are gone) -- so curation
like the '*'/'!' markers, region/sponsor prefixes, '(Country)' names, and
' - <native script>' segments survives untouched, e.g.
'de' => 'DE* (Germany) [15,083,400]' -> 'de' => 'DE* (Germany)'. A brand-NEW
tld (in IANA but not yet in the existing arrays) gets a plain uppercase label
(no country/region data available -- a human enriches later), e.g.
'zzz' => 'ZZZ'. Fresh entries are ordered alphabetically by key for a clean,
localized diff on each re-run.

Usage
-----
    python scripts/misc/update_tld_lists.py            # rewrite the file in place
    python scripts/misc/update_tld_lists.py --check     # exit 1 if out of date, no changes

Dev-host tooling: run from the repo root on a dev box (never the appliance).
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import urllib.request
from pathlib import Path

TLDS_ALPHA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
TLDS_JSON_URL = "https://data.iana.org/TLD/tlds.json"

# Plausibility floor: the IANA root zone holds ~1,400+ TLDs. A fetch that returns far
# fewer (an empty-but-200 body, a captive-portal/proxy interstitial, a truncated
# response) must NEVER overwrite the arrays -- a blanked $tld_list is valid PHP (passes
# php -l) and, once written, is unrecoverable (the next run sees empty existing arrays and
# discards every curated label). Refuse below this floor instead.
MIN_PLAUSIBLE_TLDS = 1000

# Plausibility floor for tlds.json's OPTIONAL type map (ccTLD refinement only, see
# fetch_tlds_json). Set well under the real population (~1,450 TLDs) but far above
# a garbage response that still happens to be valid JSON (a captive-portal/proxy
# page, a truncated body with a handful of records) -- below this floor the
# refinement is skipped exactly like a fetch failure, never partially applied.
MIN_PLAUSIBLE_TLD_TYPES = 500

DEFAULT_PHP_FILE = Path(__file__).resolve().parent.parent.parent / "src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php"

_TLD_KEYS = ("gTLD", "ccTLD", "iTLD")
_ENTRY_RE = re.compile(r"'([^']*)'\s*=>\s*'([^']*)'")


# ── Pure logic (unit-tested, no network) ───────────────────────────────────


def parse_tlds_alpha(text: str) -> set[str]:
    """Parse tlds-alpha-by-domain.txt into a lowercase TLD set.

    Drops the leading '# Version ...' comment line and blank lines.
    """
    return {line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")}


def require_plausible(iana_tlds: set[str]) -> None:
    """Refuse to proceed if the fetched TLD set is implausibly small.

    Guards every caller (cron, manual dispatch, a dev run) against a bad fetch silently
    blanking the arrays. Raises SystemExit below :data:`MIN_PLAUSIBLE_TLDS`.
    """
    if len(iana_tlds) < MIN_PLAUSIBLE_TLDS:
        raise SystemExit(
            f"Refusing to rewrite: IANA fetch yielded only {len(iana_tlds)} TLDs "
            f"(< {MIN_PLAUSIBLE_TLDS}); a truncated/empty response must not blank the arrays."
        )


def plausible_tld_types(iana_types: dict[str, str]) -> bool:
    """True iff tlds.json's OPTIONAL tld->type map is large enough to trust.

    Mirrors require_plausible's floor, but for the best-effort refinement source:
    unlike the required tlds-alpha fetch (which must hard-refuse below its floor),
    a too-small tlds.json is simply discarded by the caller -- proceeding exactly
    as on a fetch failure -- since classification never depends on it.
    """
    return len(iana_types) >= MIN_PLAUSIBLE_TLD_TYPES


def classify(tld: str, iana_types: dict[str, str] | None = None) -> str:
    """Classify a lowercase TLD into 'iTLD' / 'ccTLD' / 'gTLD'.

    The heuristic (punycode -> iTLD, two ASCII letters -> ccTLD, else gTLD) is
    correct standalone. When tlds.json's type map is available, a 'country-code'
    entry is honored as ccTLD too -- pure refinement, never required. For real
    IANA data the refinement is effectively a no-op: every real ccTLD is either
    exactly two ASCII letters or an xn-- A-label, and both forms are already
    classified without the type map. Kept as a defensive fallback for a
    hypothetical future TLD form, not because any current input needs it.

    xn-- is checked BEFORE the type map, unconditionally: the committed arrays
    keep every xn-- TLD (including IDN ccTLDs) in iTLD, curated with a '(cc)'
    marker in the label rather than a bucket move. Checking type first would make
    an IDN ccTLD's bucket flip with whatever tlds.json happens to report on a
    given run -- and since label retention is keyed by tld, not bucket, a flip
    also silently replaces the curated '(cc) ...' label with a bare uppercase one.
    """
    if tld.startswith("xn--"):
        return "iTLD"
    if iana_types and iana_types.get(tld) == "country-code":
        return "ccTLD"
    if len(tld) == 2 and tld.isalpha():
        return "ccTLD"
    return "gTLD"


_COUNT_BRACKET_RE = re.compile(r"\s*\[[^\]]*\]\s*$")


def strip_count(label: str) -> str:
    """Drop a trailing '[registration count]' bracket, keeping everything else
    in the existing label verbatim (markers, region/sponsor prefixes, country
    names, native-script segments -- all hand curation that must survive).
    """
    return _COUNT_BRACKET_RE.sub("", label).rstrip()


def parse_existing_arrays(php_text: str) -> dict[str, dict[str, str]]:
    """Extract {tld: label} for each of gTLD/ccTLD/iTLD/bgTLD from the PHP source."""
    result: dict[str, dict[str, str]] = {}
    for key in (*_TLD_KEYS, "bgTLD"):
        m = re.search(rf"\$tld_list\['{key}'\]\s*=\s*array\(\n(.*?)\n\);", php_text, re.DOTALL)
        if not m:
            raise ValueError(f"$tld_list['{key}'] block not found in the PHP source")
        result[key] = {tld.lower(): label for tld, label in _ENTRY_RE.findall(m.group(1))}
    return result


def build_fresh_arrays(
    iana_tlds: set[str],
    existing: dict[str, dict[str, str]],
    iana_types: dict[str, str] | None = None,
) -> dict[str, dict[str, str]]:
    """Build the fresh gTLD/ccTLD/iTLD {tld: label} dicts, alphabetical by key.

    gTLD = IANA's generic set MINUS the curated bgTLD keys (bgTLD is a hand-picked
    "branded" carve-out, not an IANA category -- see module docstring).
    """
    bgtld_keys = set(existing.get("bgTLD", {}))
    buckets: dict[str, set[str]] = {key: set() for key in _TLD_KEYS}
    for tld in iana_tlds:
        buckets[classify(tld, iana_types)].add(tld)
    buckets["gTLD"] -= bgtld_keys

    # Label lookup spans ALL regenerated buckets, not just the target one: a TLD
    # that legitimately moves bucket (e.g. IANA re-typing a plain gTLD as a ccTLD)
    # must still keep its curated label rather than falling back to a bare
    # uppercase one just because the label lived in its old bucket.
    existing_by_tld: dict[str, str] = {}
    for key in _TLD_KEYS:
        existing_by_tld.update(existing.get(key, {}))

    fresh: dict[str, dict[str, str]] = {}
    for key, tlds in buckets.items():
        fresh[key] = {
            tld: strip_count(existing_by_tld[tld]) if tld in existing_by_tld else tld.upper() for tld in sorted(tlds)
        }
    return fresh


def render_array_block(entries: dict[str, str]) -> str:
    """Render {tld: label} as PHP array body lines (no indentation, matching the
    file's existing style; no trailing comma on the last entry)."""
    return ",\n".join(f"'{tld}' => '{label}'" for tld, label in entries.items())


def rewrite_php(php_text: str, fresh: dict[str, dict[str, str]]) -> str:
    """Replace the gTLD/ccTLD/iTLD array bodies; bgTLD and everything else is
    left byte-identical."""
    out = php_text
    for key in _TLD_KEYS:
        pattern = re.compile(rf"(\$tld_list\['{key}'\]\s*=\s*array\(\n).*?(\n\);)", re.DOTALL)
        replacement = render_array_block(fresh[key])
        out, n = pattern.subn(lambda m, r=replacement: m.group(1) + r + m.group(2), out, count=1)
        if n != 1:
            raise ValueError(f"$tld_list['{key}'] block not found while rewriting")
    return out


# ── Network (excluded from unit tests) ─────────────────────────────────────


def fetch_tlds_alpha(timeout: float = 15) -> str:
    """Fetch the authoritative TLD list from IANA (uppercase, one per line)."""
    with urllib.request.urlopen(TLDS_ALPHA_URL, timeout=timeout) as resp:  # noqa: S310 (fixed https IANA host)
        return resp.read().decode("utf-8")


def fetch_tlds_json(timeout: float = 15) -> dict[str, str] | None:
    """Best-effort fetch of tlds.json's tld->type map (ccTLD refinement only).

    Returns None on ANY problem -- unreachable, empty body (observed in some
    sandboxed environments), an unexpected schema, or a body that parses fine but
    is implausibly small (below MIN_PLAUSIBLE_TLD_TYPES; logged as a warning and
    treated exactly like a fetch failure). Classification never depends on this
    succeeding.
    """
    try:
        with urllib.request.urlopen(TLDS_JSON_URL, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
        if not raw:
            return None
        data = json.loads(raw)
        records = data["tlds"] if isinstance(data, dict) else data
        result = {rec["tld"].lower(): rec.get("type", "") for rec in records}
    except Exception:
        return None
    if not plausible_tld_types(result):
        print(
            f"warning: tlds.json refinement skipped -- only {len(result)} entries "
            f"(< {MIN_PLAUSIBLE_TLD_TYPES}); proceeding as if the fetch had failed.",
            file=sys.stderr,
        )
        return None
    return result


# ── CLI ─────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the file is out of date vs a fresh IANA fetch; changes nothing",
    )
    args = parser.parse_args(argv)

    php_text = DEFAULT_PHP_FILE.read_text(encoding="utf-8")
    iana_tlds = parse_tlds_alpha(fetch_tlds_alpha())
    require_plausible(iana_tlds)
    iana_types = fetch_tlds_json()
    existing = parse_existing_arrays(php_text)
    fresh = build_fresh_arrays(iana_tlds, existing, iana_types)
    new_text = rewrite_php(php_text, fresh)

    if args.check:
        if new_text == php_text:
            print("pfblockerng_dnsbl.php TLD arrays are up to date.")
            return 0
        diff_lines = list(
            difflib.unified_diff(
                php_text.splitlines(),
                new_text.splitlines(),
                fromfile="pfblockerng_dnsbl.php",
                tofile="pfblockerng_dnsbl.php (fresh)",
                lineterm="",
                n=1,
            )
        )
        print(f"pfblockerng_dnsbl.php TLD arrays are OUT OF DATE ({len(diff_lines)} diff lines), showing first 40:")
        print("\n".join(diff_lines[:40]))
        return 1

    DEFAULT_PHP_FILE.write_text(new_text, encoding="utf-8")
    for key in _TLD_KEYS:
        print(f"{key}: {len(fresh[key])} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
