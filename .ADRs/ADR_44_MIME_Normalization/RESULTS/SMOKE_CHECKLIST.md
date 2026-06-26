# ADR-44 — Coverage and acceptance

ADR-44 adds `pfb_mime_in_allowlist()` and `pfb_mime_normalise()` and wires the
normaliser into the `PFB_FILTER_FILE_MIME` (constant 17) gate in `pfb_filter()`.
The reproducible behaviour is covered by automated tests; the variant-string
normalisation cannot be exercised on FreeBSD and is documented below as defensive.

## Automated coverage

### Unit (`vendor/bin/phpunit`, in-CI)

- `tests/php/PfbMimeAllowlistTest.php` — the shipped allow-list membership oracle.
- `tests/php/PfbMimeNormaliseTest.php` — `pfb_mime_normalise()` for every variant,
  including the `gzip`/`bzip2` guard (`x-bzip2`, `gzip`, `x-gzip` pass through
  unchanged) and the `x-zip-compressed` → `application/zip` rewrite, plus a
  before→after integration assertion.

### Live-VM smoke (`tests/smoke/test_smoke_feeds.py`, ADR-04, CE + Plus fan-out)

- `test_zip_feed_imports` — an `application/zip` feed downloads, `bsdtar`-extracts,
  and its entries land in the pf alias table. Confirms ADR-44's wiring into the
  constant-17 gate did not break the normal ZIP path (`pfb_mime_normalise()` leaves
  `application/zip` unchanged).
- `test_gzip_feed_imports` — an `application/gzip` feed `gunzip`s and imports.
  **Regression guard:** if `pfb_mime_normalise()` rewrote `application/gzip` to
  `application/zip`, the gzip bytes would be routed to `bsdtar`, zero entries would
  load, and the membership assertion fails.
- `test_bzip2_feed_imports` — an `application/x-bzip2` feed `bzip2 -dkc`s and
  imports. **Regression guard** for the `bzip` exclusion in the normaliser.

## Not reproducible on FreeBSD (defensive code)

`pfb_mime_normalise()` also maps `application/x-zip-compressed` / `application/x-zip`
→ `application/zip`. On a stock pfSense box these inputs **cannot occur**: pfBlockerNG
detects the type with `/usr/bin/file -b --mime-type` on the downloaded **bytes** (not
the HTTP `Content-Type`), and FreeBSD libmagic returns `application/zip` for ordinary
ZIPs. `application/x-zip-compressed` is absent from libmagic's magic database (a
Windows / HTTP-header MIME); `application/x-zip` maps only to Mozilla `omni.ja`. So
the variant→canonical rewrite is **defensive** — it protects the gate should a future
libmagic, a custom magic file, or a third-party `file` build ever emit those strings.
It is covered at the unit level only; there is no live path that can exercise it.
This is a documented out-of-CI limitation, not an acceptance blocker.

## Acceptance

Per CLAUDE.md "ADR acceptance — automated tests, not a manual sign-off", ADR-44 flips
to **Accepted** on a green CE + Plus live-VM fan-out of the three smoke cases above
(plus the green unit suite) — no manual maintainer step required.
