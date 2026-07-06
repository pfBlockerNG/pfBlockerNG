# TOP1M providers — reference (ADR-59)

The DNSBL **TOP1M Whitelist** feature (DNSBL Configuration page → *TOP1M Whitelist*) downloads a
"most popular domains" list and whitelists it, to cut false positives on feeds that block full
URLs (PhishTank, OpenPhish, MalwarePatrol, …). ADR-59 turned the single hardcoded Tranco/Cisco
pair into a provider framework — a new source is a descriptor row, not a code fork. This note
records the framework, the per-provider shapes, the licence obligations, and how a user supplies
Cloudflare's token. Sibling of `docs/misc/tld-lists.md` (a similarly maintained, non-vendored
external list).

## The descriptor table

`pfb_top1m_providers()` in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` is the single
source of truth — every provider is one row:

- **`url`** — the download URL (a stable literal; no per-request parameterization is needed for
  the default "latest" behaviour any provider ships today).
- **`container`** — `'zip'` or `'plain'` (uncompressed). Read by `pfb_download()`'s extractor.
- **`parse`** — `'rank_domain'` (Tranco/Cisco's original 2-column shape) or `'csv'` (a general
  `str_getcsv()` read using `domain_col`). Read by `pfblockerng_top1m()` (`pfblockerng.inc`).
- **`header`** — whether the file's first row is a header to skip.
- **`domain_col`** — the 0-indexed `str_getcsv()` column holding the domain.
- **`auth`** — `'none'` (keyless) or `array('header' => ..., 'scheme' => ...)` for a
  token-authenticated provider. Consumed by `pfb_top1m_auth_headers()`, which builds the header
  `pfb_download()` sends — never a query-string token.
- **`label`** / **`licence`** — the UI's option text and licence note.

`pfblockerng.php` selects the active row via `$pfb['dnsbl_top1m_type']`/`PfbTop1mSource` and wires
its `url`/`headers` into the `extras[2]` download slot; no per-provider `if`/`elseif` remains.

## Providers

| Provider | Format | Container | Auth | Licence |
| -------- | ------ | --------- | ---- | ------- |
| Tranco | rank,domain CSV | zip | none | — |
| Cisco Umbrella | rank,domain CSV | zip | none | — |
| DomCop (top 10M) | `"Rank","Domain","Open Page Rank"` CSV, header | zip | none | — |
| Majestic Million | `GlobalRank,TldRank,Domain,TLD,...` CSV, header | plain | none | CC BY 3.0 — attribution required |
| Cloudflare Radar (top 1M bucket) | single `domain` column CSV, header | plain | `Authorization: Bearer <token>` | CC BY-NC 4.0 — non-commercial use, attribution required |

## Licence obligations

**Majestic Million** is distributed under **CC BY 3.0** — attribution to Majestic is required.
**Cloudflare Radar** is distributed under **CC BY-NC 4.0** — non-commercial use only, attribution
to Cloudflare required. Both notes render on the DNSBL Configuration page next to the source
picker (`$top1m_text` in `pfblockerng_dnsbl.php`) so a user selecting either sees the obligation
before enabling it; pfBlockerNG does not enforce non-commercial use, the user is on their own.

## Supplying the Cloudflare token

Cloudflare Radar needs a Cloudflare API token (a free account, Radar read scope — see the
in-page link to Cloudflare's own token-creation docs). It is entered in the masked `top1m_token`
field, shown only when *Cloudflare Radar* is the selected TOP1M source (JS
`enable_top1m_token()`, driven by which descriptor rows have a non-`'none'` `auth`). The field is
write-only — never echoed back on a page load — and round-trips through the registered
`PfbConfig` field of the same name (see `docs/misc/config-gateway.md`'s inventory). A blank save
preserves the existing stored token rather than clearing it, since the field always renders
blank.

## CI health-check

`scripts/misc/check_top1m_providers.py` (`.github/workflows/top1m-healthcheck.yml`, weekly) reads
the descriptor table via `--extract` and validates each provider via `--check-url` — a real
recent list, not just a 200. It classifies by `auth`:

- **Keyless** providers are always fetched and validated.
- A **token** provider is validated only when its CI secret is configured, else the leg **prints
  a visible `SKIP … needs token, no secret configured` line and exits 0** — it never fails the
  run merely for lacking a secret, and it never fails silently either.

The secret's env-var name is **derived from the provider's `label`**, not hand-mapped —
`_secret_env_from_label()` turns `"Cloudflare Radar"` into `CLOUDFLARE_RADAR_TOKEN` (the
convention the ADR itself names). Wiring a new token provider's secret is: add the repo secret
under that derived name, then add one `NAME: ${{ secrets.NAME }}` line to the `check` (and
`alert`) jobs' `env:` in the workflow — no other script or workflow change.

## Adding a provider

1. Add a row to `pfb_top1m_providers()` (url/container/parse/header/domain_col/auth/label/licence).
2. Add its option to `$options_alexa_type` in `pfblockerng_dnsbl.php`; extend `$top1m_text` with
   its licence note if it carries one.
3. If it needs a token, no code changes are required beyond the descriptor's `auth` field — the
   masked field, its JS toggle, and the CI health-check's classification are all derived from it.
4. Add Tier-A UI coverage (the new option + any licence text renders); extend the relevant
   PHPUnit descriptor/parsing tests.

## Out of scope

Vendoring/embedding any of these lists; Chrome CrUX (BigQuery-only, not a bulk downloadable
list) and OpenPageRank (a per-domain API, not a bulk list); per-provider tokens (one shared
`top1m_token` field suffices — only one source is active at a time).
