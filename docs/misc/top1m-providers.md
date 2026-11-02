# TOP1M providers — reference (ADR-59)

Scope: TOP1M Whitelist provider framework (ADR-59). Load when: adding/updating TOP1M provider descriptor, or auditing provider licences.

DNSBL **TOP1M Whitelist** feature (DNSBL Configuration page → *TOP1M Whitelist*) downloads a "most popular domains" list to filter opted-in Groups. It reduces false positives on feeds blocking full URLs (PhishTank, OpenPhish, MalwarePatrol, …). ADR-59 turned the single hardcoded Tranco/Cisco pair into a provider framework — a new source is a descriptor row, not a code fork. This note records the framework, per-provider shapes, licence obligations, and how users supply a Cloudflare token. Sibling of `docs/misc/tld-lists.md` (similarly maintained, non-vendored external list).

## Per-Group filtering (#3648)

The global switch loads the popularity list; a Group's **TOP1M Whitelist** checkbox
opts its domain entries into filtering. The listed name and its `www.` form resolve
unless another, unchecked Group blocks them. Deeper subdomains remain blocked by
wildcards unless separately listed in TOP1M. The Group's Custom List follows its box.
The user's DNSBL Whitelist and temporary unlocks remain unconditional user allows.

New Groups default to unchecked. The wizard's advertising Group remains unchecked.
The existing `filter_alexa` → `filter_top1m` migration preserves 3.3 checkbox states.
Category feeds have no checkbox and remain unfiltered: popularity must not undo a
chosen content category. Built-in blocks and irreducible regex are not Group domain
entries and remain unfiltered.

The manifest carries optional per-feed `top1m: true`. Python drops an opted-in
Group's exact TOP1M entries before merging them. Filtered wildcard entries share
one immutable TOP1M name set and retain the last unchecked writer as their fallback.
Both zone discovery and numeric block-band scanning consult that set and fallback. This keeps
the six-band allow/block model unchanged and preserves wildcard subdomain blocking,
which deleting whole zone entries would lose. TOP1M no longer enters `whiteDB` at
the sovereign user-allow band. Old manifests without the flag filter no Groups;
the next DNSBL update republishes each Group's saved checkbox state.

## The descriptor table

`pfb_top1m_providers()` in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` = single source of truth. Every provider one row:

- **`url`** — download URL (stable literal; no per-request parameterization needed for default "latest" behaviour any provider ships today).
- **`container`** — `'zip'` or `'plain'` (uncompressed). Read by `pfb_download()` extractor.
- **`parse`** — `'rank_domain'` (Tranco/Cisco original 2-column shape) or `'csv'` (general `str_getcsv()` read using `domain_col`). Read by `pfblockerng_top1m()` (`pfblockerng.inc`).
- **`header`** — whether file first row is header to skip.
- **`domain_col`** — 0-indexed `str_getcsv()` column holding domain.
- **`auth`** — `'none'` (keyless) or `array('header' => ..., 'scheme' => ...)` for token-authenticated provider. Consumed by `pfb_top1m_auth_headers()`, which builds header `pfb_download()` sends — never query-string token.
- **`label`** / **`licence`** — UI option text and licence note.

`pfblockerng.php` select active row via `$pfb['dnsbl_top1m_type']`/`PfbTop1mSource`, wire its `url`/`headers` into `extras[2]` download slot. No per-provider `if`/`elseif` remain.

## Providers

| Provider | Format | Container | Auth | Licence |
| -------- | ------ | --------- | ---- | ------- |
| Tranco | rank,domain CSV | zip | none | — |
| Cisco Umbrella | rank,domain CSV | zip | none | — |
| OpenPageRank (top 10M) | `Rank,Domain,Extension,Open Page Rank,Referring Domains` CSV, header | zip | none | — |
| Majestic Million | `GlobalRank,TldRank,Domain,TLD,...` CSV, header | plain | none | CC BY 3.0 — attribution required |
| Cloudflare Radar (top 1M bucket) | single `domain` column CSV, header | plain | `Authorization: Bearer <token>` | CC BY-NC 4.0 — non-commercial use, attribution required |

## Licence obligations

**Majestic Million** under **CC BY 3.0** — attribution to Majestic required. **Cloudflare Radar** under **CC BY-NC 4.0** — non-commercial use only, attribution to Cloudflare required. Both notes render on DNSBL Configuration page next to source picker (`$top1m_text` in `pfblockerng_dnsbl.php`) so user selecting either see obligation before enabling. pfBlockerNG do not enforce non-commercial use — user on own.

## Supplying the Cloudflare token

Cloudflare Radar need Cloudflare API token (free account, Radar read scope — see in-page link to Cloudflare token-creation docs). Entered in masked `top1m_token` field, shown only when *Cloudflare Radar* is selected TOP1M source (JS `enable_top1m_token()`, driven by which descriptor rows have non-`'none'` `auth`). Field write-only — never echoed back on page load — and round-trips through registered `PfbConfig` field of same name (see `docs/misc/config-gateway.md` inventory). Blank save preserve existing stored token instead of clearing it, since field always render blank.

## CI health-check

`scripts/misc/check_top1m_providers.py` (`.github/workflows/top1m-healthcheck.yml`, weekly) read descriptor table via `--extract`, validate each provider via `--check-url` — real recent list, not just 200. Classify by `auth`:

- **Keyless** providers always fetched and validated.
- **Token** provider validated only when its CI secret configured, else leg **print visible `SKIP … needs token, no secret configured` line and exit 0** — never fail run merely for lacking secret, never fail silently either.

Secret env-var name **derived from provider `label`**, not hand-mapped — `_secret_env_from_label()` turn `"Cloudflare Radar"` into `CLOUDFLARE_RADAR_TOKEN` (convention ADR itself name). Wiring new token provider secret: add repo secret under that derived name, then add one `NAME: ${{ secrets.NAME }}` line to `check` (and `alert`) jobs' `env:` in workflow. No other script or workflow change.

## Adding a provider

1. Add row to `pfb_top1m_providers()` (url/container/parse/header/domain_col/auth/label/licence).
2. Add its option to `$options_top1m_source` in `pfblockerng_dnsbl.php`; extend `$top1m_text` with its licence note if it carry one.
3. If needs token, no code change beyond descriptor `auth` field — masked field, JS toggle, CI health-check classification all derived from it.
4. Add Tier-A UI coverage (new option + any licence text renders); extend relevant PHPUnit descriptor/parsing tests.

## Out of scope

Vendoring/embedding any of these lists; Chrome CrUX (BigQuery-only, not bulk downloadable list); per-provider tokens (one shared `top1m_token` field suffice — only one source active at a time).

Note (#928): bulk top-10M list moved hosting from DomCop to OpenPageRank in 2026 (DomCop URL froze 2026-03-29) — descriptor above track that bulk CSV download, not OpenPageRank separate **per-domain API** (rank lookup one domain at a time), which stay out of scope for same reason as Chrome CrUX: this feature only download bulk lists.
