# Public Suffix List — maintenance (dev-only)

Scope: maintain vendored `dnsbl_psl` Public Suffix List authority. Load when:
refresh or audit `dnsbl_psl` against publicsuffix.org.

`src/usr/local/pkg/pfblockerng/dnsbl_psl` = the SOLE shipped PSL artifact (issue #1541):
a self-describing authority carrying both ICANN and PRIVATE sections, exact/wildcard
(`*.`)/exception (`!`) rule syntax preserved. Consumed by the pure PSL resolver
(`pfb_unbound.py`'s `parse_psl_rules`) to derive each domain's registrable parent for
DNSBL Wildcard Blocking. This note record how to keep current. Sibling of
[`tld-lists.md`](tld-lists.md) (issue #1272; single-authority retirement issue #1541).

## Sources

- `https://publicsuffix.org/list/public_suffix_list.dat` — authoritative suffix set, both
  ICANN section (between `// ===BEGIN ICANN DOMAINS===` / `// ===END ICANN DOMAINS===`
  markers) and PRIVATE section (matching PRIVATE markers).
- **License:** MPL 2.0 — <https://mozilla.org/MPL/2.0/>.

## What is automated vs manual

- **`dnsbl_psl` regenerated from Public Suffix List** by
  `scripts/misc/update_public_suffix_list.py`. Punycode-encode any non-ASCII label,
  lowercase defensively, preserve exact/wildcard/exception rule syntax, rewrite file in
  place (header + both sections between their own BEGIN/END markers).
- **Churn guard skip header-only refresh:** upstream `VERSION`/`COMMIT` header move
  on every PSL commit even when no rule changed, so run compare generated
  body against shipped file's body and leave file untouched when match — no
  weekly no-op diff.

## Contract preserved (unlike the retired dnsbl_tld flat list)

- **Both ICANN and PRIVATE sections shipped** — `blogspot.*`, `github.io`, … land in
  the PRIVATE section, distinct from ICANN.
- **PSL wildcard (`*.`) and exception (`!`) rules preserved**, not dropped — the
  authority format keeps their prefix syntax intact so the resolver can distinguish
  exact/wildcard/exception semantics per public-suffix rule.

## Refreshing

- **Automated (weekly):** `.github/workflows/psl-refresh.yml` run script every Monday
  and, when list drifted, open/update PR against `devel` from bot-owned branch.
  Never push to `devel`/`main`. GitHub run no automatic CI on GITHUB_TOKEN-created PR
  (and dispatched run's checks never attach to its Checks tab), so workflow dispatch
  unit suite (`test.yml`) onto branch head and post PR comment linking run
  (issue #902's fix, reused here); merge once linked run green. Diff touch only
  data file, so — unlike `tld-refresh.yml` — no Tier-A `ui_render` gate dispatched.
- **Manual:** from repo root, `python3 scripts/misc/update_public_suffix_list.py`
  (rewrite file) or `python3 scripts/misc/update_public_suffix_list.py --check` (exit 1
  and status line if out of date, no write).
- **Safety:** script refuse to rewrite when fetched ICANN section yield fewer than
  `MIN_PLAUSIBLE_SUFFIXES` (5000) rules, fetched PRIVATE section yield fewer than
  `MIN_PLAUSIBLE_PRIVATE_SUFFIXES` (1000) rules, or when any of the four BEGIN/END
  markers missing/duplicated/out of order, so empty/truncated/captive-portal response
  never silently blank the authority.
