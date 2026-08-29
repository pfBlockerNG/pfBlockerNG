# HSTS preload list — maintenance (dev-only)

Scope: maintain vendored `pfb_py_hsts.txt` HSTS exclusion list. Load when: refreshing or auditing HSTS preload snapshot.

`src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt` = flat one-name-per-line HSTS exclusion oracle. `_load_hsts_db()` (pfb_unbound.py) keys resolved domains against it: blocked domain on list resolves real (HSTS bypass) instead of null-blocked. Parent-suffix walk over loaded set means listing domain also covers subdomains, so `include_subdomains` moot for this consumer. This note = how to keep current. Sibling of [`public-suffix-list.md`](public-suffix-list.md) (issue #1303).

## Sources

- `https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json`
  — Chromium HSTS preload source (gitiles serves base64-encoded via `?format=TEXT`); keep only entries with `mode == "force-https"` (pinning-only rows with no `mode` skipped).
- **License:** BSD-style, The Chromium Authors —
  <https://chromium.googlesource.com/chromium/src/+/main/LICENSE> (redistribution with attribution permitted; both URLs carried in generated file header).

## What is automated vs manual

- **`pfb_py_hsts.txt` is regenerated from the Chromium HSTS preload list** by `scripts/misc/update_hsts_preload_list.py`. Punycode-encodes non-ASCII labels, lowercases defensively, rewrites file in place (header + one name per line, sorted, deduped).
- **A churn guard skips a header-only refresh:** upstream has no retrievable revision marker, so run compares generated body against shipped file body and leaves file untouched when match — no weekly no-op diff.
- **Automated (weekly):** `.github/workflows/hsts-refresh.yml` runs script every Monday, and on drift opens/updates PR against `devel` from bot-owned branch. Never pushes to `devel`/`main`. GitHub runs no automatic CI on GITHUB_TOKEN-created PR (and dispatched run checks never attach to its Checks tab), so workflow dispatches unit suite (`test.yml`) onto branch head and posts PR comment linking run; merge once linked run green. Diff touches data file only, so no Tier-A `ui_render` gate dispatched.
- **Manual:** from repo root, `python3 scripts/misc/update_hsts_preload_list.py` (rewrites file) or `python3 scripts/misc/update_hsts_preload_list.py --check` (exit 1 + status line if out of date, no write).
- **Safety:** script refuses to rewrite when fetched body isn't valid base64/JSON, has no `entries`, or yields fewer than `MIN_PLAUSIBLE_ENTRIES` (50000) force-https names. Truncated/malformed upstream response can never silently blank exclusion list.

## Out of scope (issue #1303)

- **Pinning-only entries** (rows with no `mode` field) excluded — oracle needs force-https set only.
- **`include_subdomains` expansion** not applied — consumer parent-suffix walk already matches subdomains of every listed name, so expanding list only adds redundant rows.
