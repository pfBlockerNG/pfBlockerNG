# TLD Allow lists — maintenance (dev-only)

The DNSBL **TLD Allow** feature (DNSBL Configuration page → *TLD Allow*) blocks any domain
whose top-level domain is not in a selected allow-set. The pickers are populated from four
hardcoded arrays in `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` (`$tld_list['gTLD']`,
`['ccTLD']`, `['iTLD']`, `['bgTLD']`), sourced from the IANA root zone. This note records how
to keep them current. It is the sibling of issue #872 (Part A).

## Sources

- `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` — authoritative TLD set (required).
- `https://data.iana.org/TLD/tlds.json` — per-TLD `type` (optional refinement only).
- `https://www.iana.org/domains/root/db` — human-readable Root Zone Database.

## What is automated vs manual

- **gTLD / ccTLD / iTLD are regenerated from IANA** by `scripts/misc/update_tld_lists.py`.
  It classifies each TLD (`XN--` → iTLD, two ASCII letters → ccTLD, else gTLD), subtracts the
  curated `bgTLD` keys from the fresh gTLD set (so a branded TLD is never duplicated), and
  rewrites the three array bodies in place. `bgTLD` is left byte-identical.
- **`bgTLD` (branded generic TLDs) is hand-curated.** "Branded" is not an IANA category
  (`tlds.json` types are generic / country-code / sponsored / …; brand TLDs are an ICANN
  Spec-13 designation), so there is no authoritative source to regenerate it from. A newly
  delegated brand TLD initially lands in `gTLD` (from IANA) until a maintainer moves it into
  `bgTLD` by hand.

## Labels

Each entry is `'<tld>' => '<LABEL>'`. On a refresh the script keeps the existing label
**verbatim except the trailing registration-count bracket**, which is dropped — IANA does not
publish registration counts, so they are unmaintainable and were years stale. Everything else
is preserved: the `*` marker (TLD used by at least one DNSBL feed), the `!` marker (Spamhaus
"most abused"), the `(s)`/`(eu)`/`(cc)` region/sponsor prefixes, the `(Country)` names, and the
native-script suffix (e.g. `XN--P1AI - рф`). A brand-new TLD (not previously in the arrays) gets a plain
uppercase label — a maintainer can enrich it later. Entries are emitted alphabetically for a
clean, localized diff on each refresh.

The "(N TLDs available)" help text is computed from the arrays (`number_format($tld_total)`),
so it never goes stale.

## Refreshing

- **Automated (weekly):** `.github/workflows/tld-refresh.yml` runs the script every Monday and,
  when the root zone has drifted, opens/updates a PR against `devel` from a bot-owned branch.
  It never pushes to `devel`/`main`. GitHub runs no automatic CI on a GITHUB_TOKEN-created PR
  (and a dispatched run's checks never attach to its Checks tab), so the workflow dispatches
  the real gates — the unit suite (`test.yml`) and Tier-A `ui_render` (`ui-tests.yml`) — onto
  the branch head and posts a PR comment linking both runs (issue #902); merge once the linked
  runs are green. The auto-PR carries the `ui-tests` label to mark it as UI-affecting.
- **Manual:** from the repo root, `python3 scripts/misc/update_tld_lists.py` (rewrites the file)
  or `python3 scripts/misc/update_tld_lists.py --check` (exit 1 + a diff if out of date, no
  write). A manual refresh is otherwise a 6–12 month task, or whenever a major new gTLD batch
  is delegated. Review the data diff, then land it via the normal PR flow.
- **Safety:** the script refuses to rewrite when the IANA fetch yields fewer than
  `MIN_PLAUSIBLE_TLDS` (1000) TLDs, so an empty or truncated response cannot silently blank the
  arrays (a blanked `$tld_list` is valid PHP and would drop all curation on the next run).

## Out of scope

Fetching the lists at runtime / on package update is a possible future enhancement, explicitly
deferred (issue #872). The arrays remain a static, reviewed snapshot.

For the separate `dnsbl_tld` public-suffix master list (DNSBL Wildcard Blocking), see the
sibling doc [`public-suffix-list.md`](public-suffix-list.md) (issue #1272).
