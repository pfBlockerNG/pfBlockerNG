# TLD Allow lists — maintenance (dev-only)

Scope: maintain TLD Allow picker arrays. Load when: refresh `$tld_list` arrays in `pfblockerng_dnsbl.php` from IANA root zone.

DNSBL **TLD Allow** (DNSBL Configuration page → *TLD Allow*) blocks domain whose TLD not in selected allow-set. Pickers populated from four hardcoded arrays in `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` (`$tld_list['gTLD']`, `['ccTLD']`, `['iTLD']`, `['bgTLD']`), sourced from IANA root zone. This note record how keep current. Sibling of issue #872 (Part A).

## Sources

- `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` — authoritative TLD set (required).
- `https://data.iana.org/TLD/tlds.json` — per-TLD `type` (optional refinement only).
- `https://www.iana.org/domains/root/db` — human-readable Root Zone Database.

## What is automated vs manual

- **gTLD / ccTLD / iTLD regenerated from IANA** by `scripts/misc/update_tld_lists.py`. Classifies each TLD (`XN--` → iTLD, two ASCII letters → ccTLD, else gTLD), subtracts curated `bgTLD` keys from fresh gTLD set (branded TLD never duplicated), rewrites three array bodies in place. `bgTLD` left byte-identical.
- **`bgTLD` (branded generic TLDs) hand-curated.** "Branded" not IANA category (`tlds.json` types are generic / country-code / sponsored / …; brand TLDs are ICANN Spec-13 designation), so no authoritative source to regenerate from. Newly delegated brand TLD lands in `gTLD` (from IANA) until maintainer move it into `bgTLD` by hand.

## Labels

Each entry is `'<tld>' => '<LABEL>'`. On refresh script keeps existing label **verbatim except trailing registration-count bracket**, which drops — IANA publish no registration counts, so unmaintainable and years stale. Everything else preserved: `*` marker (TLD used by at least one DNSBL feed), `!` marker (Spamhaus "most abused"), `(s)`/`(eu)`/`(cc)` region/sponsor prefixes, `(Country)` names, native-script suffix (e.g. `XN--P1AI - рф`). Brand-new TLD (not previously in arrays) gets plain uppercase label — maintainer can enrich later. Entries emitted alphabetically for clean, localized diff each refresh.

"(N TLDs available)" help text computed from arrays (`number_format($tld_total)`), so never stale.

## Refreshing

- **Automated (weekly):** `.github/workflows/tld-refresh.yml` runs script every Monday and, when root zone drifted, opens/updates PR against `devel` from bot-owned branch. Never pushes to `devel`/`main`. GitHub runs no automatic CI on GITHUB_TOKEN-created PR (and dispatched run's checks never attach to its Checks tab), so workflow dispatches real gates — unit suite (`test.yml`) and Tier-A `ui_render` (`ui-tests.yml`) — onto branch head and posts PR comment linking both runs (issue #902); merge once linked runs green. Auto-PR carries `ui-tests` label to mark UI-affecting.
- **Manual:** from repo root, `python3 scripts/misc/update_tld_lists.py` (rewrites file) or `python3 scripts/misc/update_tld_lists.py --check` (exit 1 + diff if out of date, no write). Manual refresh otherwise 6–12 month task, or whenever major new gTLD batch delegated. Review data diff, then land via normal PR flow.
- **Safety:** script refuses rewrite when IANA fetch yields fewer than `MIN_PLAUSIBLE_TLDS` (1000) TLDs, so empty or truncated response cannot silently blank arrays (blanked `$tld_list` is valid PHP and would drop all curation on next run).

## Out of scope

Fetching lists at runtime / on package update is possible future enhancement, explicitly deferred (issue #872). Arrays remain static, reviewed snapshot.

For separate `dnsbl_psl` Public Suffix List authority (DNSBL Wildcard Blocking), see sibling doc [`public-suffix-list.md`](public-suffix-list.md) (issue #1272; single-authority retirement issue #1541).
