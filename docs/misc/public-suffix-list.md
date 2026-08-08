# Public Suffix List — maintenance (dev-only)

Scope: maintain vendored `dnsbl_tld` public-suffix master list. Load when:
refresh or audit `dnsbl_tld` / `pfb_py_tld.txt` against publicsuffix.org.

`src/usr/local/pkg/pfblockerng/dnsbl_tld` = flat one-suffix-per-line public-suffix
master list. `_dnsbl_load_tld_wildcard_master()` (`pfb_unbound.py`) use it — staged into
Unbound chroot as `pfb_py_tld.txt` by `pfblockerng.sh` — to derive each domain's registrable
parent for DNSBL Wildcard Blocking (TLD). (Legacy PHP consumer replaced by
manifest/Python classification plus in-memory PHP stats finalizer.) This note record how to
keep current. Sibling of [`tld-lists.md`](tld-lists.md) (issue #1272).

## Sources

- `https://publicsuffix.org/list/public_suffix_list.dat` — authoritative suffix set, ICANN
  section only (between `// ===BEGIN ICANN DOMAINS===` / `// ===END ICANN DOMAINS===`
  markers).
- **License:** MPL 2.0 — <https://mozilla.org/MPL/2.0/>.

## What is automated vs manual

- **`dnsbl_tld` regenerated from Public Suffix List** by
  `scripts/misc/update_public_suffix_list.py`. Punycode-encode any non-ASCII label,
  lowercase defensively, rewrite file in place (header + one suffix per line, PSL
  source order).
- **Churn guard skip header-only refresh:** upstream `VERSION`/`COMMIT` header move
  on every PSL commit even when no suffix changed, so run compare generated
  body against shipped file's body and leave file untouched when match — no
  weekly no-op diff.

## Out of scope (owner decision, issue #1272)

- **PRIVATE-section suffixes** (`blogspot.*`, `github.io`, …) excluded — DNSBL
  oracle want plain public-suffix contract, not private-registry entries.
- **PSL wildcard (`*.`) and exception (`!`) rules** excluded — `dnsbl_tld` = flat
  exact-match list, no format extension for either. Skip wildcard rule only
  narrow suffix depth matched under that label; never cause over-block.

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
  `MIN_PLAUSIBLE_SUFFIXES` (5000) suffixes, or when ICANN BEGIN/END markers missing,
  so empty/truncated/captive-portal response never silently blank master list.
