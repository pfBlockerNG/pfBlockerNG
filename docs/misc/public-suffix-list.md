# Public Suffix List — maintenance (dev-only)

`src/usr/local/pkg/pfblockerng/dnsbl_tld` is the flat, one-suffix-per-line public-suffix
master list that `tld_analysis()` (PHP) and `_dnsbl_load_tld_wildcard_master()` (Python) use to derive
each domain's registrable parent for DNSBL Wildcard Blocking (TLD). This note records how to
keep it current. It is the sibling of [`tld-lists.md`](tld-lists.md) (issue #1272).

## Sources

- `https://publicsuffix.org/list/public_suffix_list.dat` — authoritative suffix set, ICANN
  section only (between the `// ===BEGIN ICANN DOMAINS===` / `// ===END ICANN DOMAINS===`
  markers).
- **License:** MPL 2.0 — <https://mozilla.org/MPL/2.0/>.

## What is automated vs manual

- **`dnsbl_tld` is regenerated from the Public Suffix List** by
  `scripts/misc/update_public_suffix_list.py`. It punycode-encodes any non-ASCII label,
  lowercases defensively, and rewrites the file in place (header + one suffix per line, in
  PSL source order).
- **A churn guard skips a header-only refresh:** the upstream `VERSION`/`COMMIT` header moves
  on every PSL commit even when no suffix actually changed, so a run compares the generated
  body against the shipped file's body and leaves the file untouched when they match — no
  weekly no-op diff.

## Out of scope (owner decision, issue #1272)

- **PRIVATE-section suffixes** (`blogspot.*`, `github.io`, …) are excluded — the DNSBL
  oracle wants a plain public-suffix contract, not private-registry entries.
- **PSL wildcard (`*.`) and exception (`!`) rules** are excluded — `dnsbl_tld` is a flat
  exact-match list with no format extension for either. Skipping a wildcard rule only
  narrows the suffix depth matched under that label; it never causes an over-block.

## Refreshing

- **Automated (weekly):** `.github/workflows/psl-refresh.yml` runs the script every Monday
  and, when the list has drifted, opens/updates a PR against `devel` from a bot-owned branch.
  It never pushes to `devel`/`main`. GitHub runs no automatic CI on a GITHUB_TOKEN-created PR
  (and a dispatched run's checks never attach to its Checks tab), so the workflow dispatches
  the unit suite (`test.yml`) onto the branch head and posts a PR comment linking the run
  (issue #902's fix, reused here); merge once the linked run is green. The diff touches only
  a data file, so — unlike `tld-refresh.yml` — no Tier-A `ui_render` gate is dispatched.
- **Manual:** from the repo root, `python3 scripts/misc/update_public_suffix_list.py`
  (rewrites the file) or `python3 scripts/misc/update_public_suffix_list.py --check` (exit 1
  and a status line if out of date, no write).
- **Safety:** the script refuses to rewrite when the fetched ICANN section yields fewer than
  `MIN_PLAUSIBLE_SUFFIXES` (5000) suffixes, or when the ICANN BEGIN/END markers are missing,
  so an empty/truncated/captive-portal response can never silently blank the master list.
