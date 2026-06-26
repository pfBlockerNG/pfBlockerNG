# ADR-44 Manual Smoke Checklist

Owner: maintainer (requires a live pfSense box with pfBlockerNG installed).
Branch: `adr/44-mime-normalisation`.

ADR-44 adds `pfb_mime_normalise()` in `pfb_filter()`: before the MIME allow-list
gate (constant `PFB_FILTER_FILE_MIME`, 17), known ZIP variant strings from
`file(1)` (`application/x-zip-compressed`, `application/x-zip`, and other
`zip`-bearing variants) are canonicalised to `application/zip`, and
`application/x-gzip` to `application/gzip`. `application/gzip`, `application/x-bzip2`,
`application/octet-stream`, and any non-archive string pass through unchanged.

## Pre-conditions

- [ ] Branch `adr/44-mime-normalisation` is installed on the test box.
- [ ] pfBlockerNG is enabled with at least one IP or DNSBL feed configured.

## Test cases

- [ ] TC-1: Download a blocklist feed served as a ZIP created by Python `zipfile`
  (or 7-Zip / Windows Explorer). Confirm it passes the MIME gate and the feed is
  processed normally (entries imported, no MIME-rejection line in the pfBlockerNG
  log).
- [ ] TC-2: If a feed previously triggered an `application/x-zip-compressed`
  rejection, re-run it. Confirm it now succeeds.
- [ ] TC-3: Download a feed served as `application/gzip` (and, if available, one
  served as `application/x-bzip2`). Confirm both still pass and are processed —
  no regression from normalisation (these must NOT be rewritten to
  `application/zip`).
- [ ] TC-4: Inspect the debug sink `/tmp/pfb_debug` after TC-1/TC-2. Confirm a
  normalisation event is logged when a variant string is encountered, e.g.:

  ```text
  MIME normalised: raw="application/x-zip-compressed" -> canonical="application/zip"
  ```

- [ ] TC-5: Download a feed that returns a genuine HTML error page (or simulate
  with a test URL whose body is HTML). `text/html` is allow-listed, so the MIME
  gate accepts it; confirm the downstream parser still rejects it because no valid
  entries are extracted.
- [ ] TC-5b: Download a non-archive body (e.g. `application/octet-stream`). Confirm
  it is rejected at the MIME gate and never promoted through normalisation.

## Reject criteria (if any occur, do NOT mark ADR-44 Accepted)

- Any feed that previously succeeded now fails after this change.
- `application/octet-stream` (or any non-archive string) is ever promoted through
  the normalisation path.
- `application/x-bzip2` or `application/gzip` is rewritten to `application/zip`
  (misrouted into the ZIP handler).
- `PFB_FILTER_FILE_MIME_COMPARE` (constant 16) behaviour changes in any way.

## Sign-off

- Tester: _______________
- Date: _______________
- Result: PASS / FAIL
- Notes: _______________
