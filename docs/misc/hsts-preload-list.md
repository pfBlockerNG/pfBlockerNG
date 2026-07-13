# HSTS preload list — maintenance (dev-only)

`src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt` is the flat, one-name-per-line HSTS
exclusion oracle `_load_hsts_db()` (pfb_unbound.py) keys resolved domains against: a
blocked domain on this list resolves real (HSTS bypass) instead of being null-blocked —
the parent-suffix walk over the loaded set means listing a domain also covers its
subdomains, so `include_subdomains` is moot for this consumer. This note records how to
keep it current. It is the sibling of [`public-suffix-list.md`](public-suffix-list.md)
(issue #1303).

## Sources

- `https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json`
  — Chromium's own HSTS preload source (gitiles serves it base64-encoded via
  `?format=TEXT`); only entries with `mode == "force-https"` are kept (pinning-only rows
  with no `mode` are skipped).
- **License:** BSD-style, The Chromium Authors —
  <https://chromium.googlesource.com/chromium/src/+/main/LICENSE> (redistribution with
  attribution permitted; both URLs are carried in the generated file's header).

## What is automated vs manual

- **`pfb_py_hsts.txt` is regenerated from the Chromium HSTS preload list** by
  `scripts/misc/update_hsts_preload_list.py`. It punycode-encodes any non-ASCII label,
  lowercases defensively, and rewrites the file in place (header + one name per line,
  sorted and deduplicated).
- **A churn guard skips a header-only refresh:** upstream carries no retrievable revision
  marker, so a run compares the generated body against the shipped file's body and leaves
  the file untouched when they match — no weekly no-op diff.
- **Automated (weekly):** `.github/workflows/hsts-refresh.yml` runs the script every
  Monday and, when the list has drifted, opens/updates a PR against `devel` from a
  bot-owned branch. It never pushes to `devel`/`main`. GitHub runs no automatic CI on a
  GITHUB_TOKEN-created PR (and a dispatched run's checks never attach to its Checks tab),
  so the workflow dispatches the unit suite (`test.yml`) onto the branch head and posts a
  PR comment linking the run; merge once the linked run is green. The diff touches only a
  data file, so no Tier-A `ui_render` gate is dispatched.
- **Manual:** from the repo root, `python3 scripts/misc/update_hsts_preload_list.py`
  (rewrites the file) or `python3 scripts/misc/update_hsts_preload_list.py --check` (exit
  1 and a status line if out of date, no write).
- **Safety:** the script refuses to rewrite when the fetched body isn't valid
  base64/JSON, has no `entries`, or yields fewer than `MIN_PLAUSIBLE_ENTRIES` (50000)
  force-https names, so a truncated/malformed upstream response can never silently blank
  the exclusion list.

## Out of scope (issue #1303)

- **Pinning-only entries** (rows with no `mode` field) are excluded — this oracle only
  needs the force-https set.
- **`include_subdomains` expansion** is not applied — the consumer's parent-suffix walk
  already matches subdomains of every listed name, so expanding the list would only add
  redundant rows.
