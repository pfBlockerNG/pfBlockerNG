# ADR-59: A provider framework for the DNSBL TOP1M whitelist — add sources, incl. token-authenticated ones

- **Status:** **Implemented (pending smoke test)** (2026-07-06) — all 6 phases landed on `devel` via PR #892 (review findings incl. the csv-mode #886 wipe fixed). Flips to **Accepted** once the §7 manual smoke passes on a real box.
- **Date:** 2026-07-06
- **Branch:** `adr/59-top1m-provider-framework` (off **`devel`**); `{slug}` per CLAUDE.md "Branch naming".
- **Component(s):**
  - `src/usr/local/www/pfblockerng/pfblockerng.php` — the `$pfb['extras'][2]` TOP1M slot + the provider URL if/else.
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — `pfblockerng_top1m()` (the CSV→whitelist builder), `pfb_download()` (the fetcher), the extract/decompress post-processor, `PfbConfig`/registry.
  - `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` — `Top1mSource` enum + `pfb_cfg_registry()`.
  - `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` — the "TOP1M Whitelist" UI (source select, new token field).
  - `scripts/misc/check_top1m_providers.py` + `.github/workflows/top1m-healthcheck.yml` — the CI health-check.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the package; POSIX sh / dev-host `python3` for the CI tooling. No Python on the appliance.
- **Test suite:** `tests/php/` (PHPUnit), `tests/smoke/ui/` (Tier-A `ui_render`), `tests/test_check_top1m_providers.py`.

---

## 1. Context (today)

The DNSBL **TOP1M Whitelist** un-blocks the most-popular domains to cut false positives. It is a runtime, per-box feature: when enabled, the package downloads a "top 1 million" list on cron and writes `pfbalexawhitelist.txt`, applied as a band-6 user-allow at query time. It is **not** the TLD Allow feature (that is IANA-sourced and refreshed by `tld-refresh.yml`, ADR-unrelated) — the two are independent.

Load-bearing facts (verified):

- **Two hardcoded providers.** `pfblockerng.php:162` selects the download URL by `if/else` on `$pfb['dnsbl_top1m_type']` (a `Top1mSource` enum, `tranco`/`cisco`, ADR from #877). Both ship `top-1m.csv.zip` = a `rank,domain` CSV with no header.
- **One parser, one shape.** `pfblockerng_top1m()` (`pfblockerng.inc` ~8250) reads `top-1m.csv` line-by-line, requires each line to contain a `.` and a `,`, requires a **numeric rank** in column 0 (#886 review), and takes the **domain from column index 1**. It writes `.d,,` / `,d,,` / `,www.d,,` triplets to `pfbalexawhitelist.txt`. It cannot handle a header row, a different domain column, a non-CSV (JSON) body, or a non-`.zip` container.
- **The extractor is `.zip`-only for `top1m`.** The download post-processor (`pfblockerng.inc` ~10196) untars a `.zip` straight to `top-1m.csv` **only** for `type=='geoip'||'top1m'`; a `.gz`/plain body would land elsewhere and the parser would find nothing.
- **The downloader has no caller header support.** `pfb_download()` (`pfblockerng.inc:9626`) offers **HTTP Basic** (`CURLOPT_USERPWD`, used by MaxMind) and plain/query-param URLs. `CURLOPT_HTTPHEADER` is used **internally only** for the ADR-42 conditional-GET (`If-None-Match`) and **replaces** the whole header list.
- **Token precedent = a query-param, and it leaks.** The IPinfo ASN feed appends its token as `?token=<asn_token>` (`pfblockerng.php:670`, `rawurlencode`). The field is a **plain-text** (unmasked) input validated by `PFB_FILTER_WORD` = `[A-Za-z0-9_]` only. On a failed download the **full URL (token included) is logged** to `extras.log` (`pfblockerng.inc:9919`), which ships in support bundles — a pre-existing info-disclosure (handled separately, see §2.6 / #890). MaxMind's key does **not** leak (Basic-auth, never in the URL).
- **The CI health-check (#884) is keyless-only.** `check_top1m_providers.py` extracts every URL wired to the `top1m` extras slot and GET-validates it; it has no way to supply a token.

## 2. Decision

Replace the two-way hardcoded provider `if/else` + single-shape parser with a **per-provider descriptor** that drives URL, container, parse, and auth — then add three sources under it. Land the security prerequisite first.

### 2.0 Prerequisite (NOT an ADR phase) — redact credential-bearing URLs in the download logger

Issue **#890** adds `pfb_redact_url()` and applies it at every download-URL log site, so a token/userinfo never lands in `extras.log`. **This must land before any token feature.** Also fixes the pre-existing `asn_token` leak (private advisory). ADR-59 phases assume it is merged.

### 2.1 A provider descriptor table (per-area decision)

| Aspect | Today | ADR-59 |
| --- | --- | --- |
| Provider set | `if/else` in `pfblockerng.php` | a descriptor table (one entry per provider) keyed by the `Top1mSource` value |
| URL | literal per arm | `url` (literal) or a `url_builder` (Cloudflare's bucket endpoint) in the descriptor |
| Container | `.zip` assumed | `container` ∈ `zip` \| `gz` \| `plain`, driving the decompress path |
| Parse | domain @ col 1, CSV | `parse` ∈ `rank_domain` \| `{csv, domain_col:N, header:bool}` \| `{json, field}` |
| Auth | none / query-param (`asn`) / Basic (`geoip`) | `auth` ∈ `none` \| `basic` \| `{header:'<Name>', scheme:'Bearer'\|''}` |
| Licence | — | `licence` note surfaced in the UI (attribution / non-commercial) |

Descriptor lives in PHP (a `pfb_top1m_providers()` function returning the table) so `pfblockerng.php` (URL + auth), `pfblockerng_top1m()` (parse), and the extractor (container) all read one source of truth.

### 2.2 The providers

| id | Source | Container | Parse | Auth | Licence note |
| --- | --- | --- | --- | --- | --- |
| `tranco` | tranco-list.eu top-1m | zip | rank_domain | none | (kept) |
| `cisco` | umbrella-static top-1m | zip | rank_domain | none | (kept) |
| `domcop` | domcop top-10M | zip | csv, domain_col 2, header | none | — |
| `majestic` | majestic_million.csv | **plain** | csv, domain_col 3, header | none | **CC BY 3.0 — attribution required** |
| `cloudflare` | Radar ranking bucket | (csv) | csv, domain_col 1, header | **header `Authorization: Bearer <token>`** | **CC BY-NC — non-commercial** |

DomCop is a top-**10M** (registered-domain granularity); good breadth for a whitelist. CrUX (BigQuery-only) and OpenPageRank's per-domain API are **out of scope** (§2.7).

### 2.3 Generalize `pfblockerng_top1m()` — parse per descriptor

The builder takes the active descriptor's `parse`: skip a header row when `header`; take the domain from `domain_col` (default 1); keep the numeric-rank guard only for `rank_domain`; for `json`, parse the body and read `field`. Output (`pfbalexawhitelist.txt` triplets) is **unchanged** — a pure input-normalization change. The extract post-processor honours `container` (`gz`/`plain` write straight to `top-1m.csv`; `zip` as today).

### 2.4 A single masked token field

- One registered `PfbConfig` field **`top1m_token`** (section = dnsbl), rendered as a **masked `password`** `Form_Input` (like `varsyncpassword`, not the unmasked `asn_token`), **write-only** (never echoed back on GET). Shown by JS **only when** the selected provider's `auth` needs a token; the provider's `licence` note renders beside it.
- **Validator** widened from `PFB_FILTER_WORD` to a token charset (base64url / JWT: `[A-Za-z0-9._~+/=-]`, bounded length) via a new `PFB_FILTER_TOKEN` or a dedicated sanitiser — `PFB_FILTER_WORD` would reject a real Cloudflare token.
- Only the **active** provider consumes it; `auth:none` providers ignore it. Round-trip-pinned per the config-gateway contract.

### 2.5 Header auth in `pfb_download()`

Add an `$extra_headers = array()` param + a per-feed `$feed['headers']` field. When set, **merge** into `CURLOPT_HTTPHEADER` alongside the conditional-GET header (do not clobber `If-None-Match`). Cloudflare's descriptor sets `headers = ['Authorization: Bearer ' . $token]`. Header creds never enter the logged URL — structurally safe (unlike a query-param token).

### 2.6 Security

- **Header, not query-param, for the new token** (§2.5) — so even without #890 it wouldn't hit the URL log; with #890 the class is closed.
- **Masked, write-only field** (§2.4). Accept plaintext-at-rest in `config.xml` — every existing pfBlockerNG secret (`asn_token`, `maxmind_key`, `varsyncpassword`) already is; pfSense has no per-field backup redaction and HA sync must transmit it. No bespoke crypto layer.
- The concrete pre-existing `asn_token` leak is disclosed via a **GitHub Private Security Advisory**; the public fix (#890) stays neutral.

### 2.7 CI health-check for token-gated providers

`check_top1m_providers.py` classifies each descriptor by `auth`: **keyless** providers are GET-validated as today; a **token** provider is checked **only if** a repo/CI secret is present (e.g. `CLOUDFLARE_RADAR_TOKEN`), else **explicitly skipped with a logged reason** (never silently — a skipped provider must be visible, matching #884's ethos). The health-check never fails merely because a token provider can't be reached without a secret.

### 2.8 Explicitly kept / out of scope

- **Kept:** the runtime-download-per-box model (no vendoring); the `pfbalexawhitelist.txt` output shape + its query-time application; TLD Allow (separate feature).
- **Out of scope:** vendoring/embedding lists; Chrome CrUX (BigQuery-only) + OpenPageRank API (per-domain, not a bulk list); encrypting secrets at rest; a per-provider token (one shared field suffices — one source is active at a time).

## 3. Consequences

**Positive**

- Source diversity (5 providers incl. a 10M list) + the first token-authenticated source, behind a clean descriptor the UI/parser/downloader all read.
- The provider abstraction makes the *next* provider a table row, not a code fork.
- The token path is header-based + masked + post-#890 — safer than the existing `asn_token`.

**Negative / risks**

- **Parser complexity grows** — header skip, variable domain column, `gz`/`plain` containers, and a **JSON** path (Cloudflare) inside a function that was line-oriented CSV. Risk of regressing the Tranco/Cisco path; mitigated by front-loaded oracle tests (§6 P1–P2).
- **Cloudflare's JSON + bucket endpoint** is the most divergent (auth + format + a two-call dataset API). If it proves disproportionately complex, it is the **first drop** (§7 reject).
- **A user secret** now lives in config (backups/HA) — accepted as consistent with existing secrets, but a real surface.
- **Licensing burden** — Majestic (CC BY 3.0 attribution) and Cloudflare (CC BY-NC) obligations must be surfaced; a user who ignores them is on their own, but we must show the note.
- **Token providers are not fully CI-covered** without a secret (§2.7).

## 4. Requirements (acceptance)

1. Tranco/Cisco behave **byte-identically** to today (same `pfbalexawhitelist.txt`).
2. DomCop + Majestic produce a correct whitelist from their real formats (domain col 2 / col 3, header skipped).
3. Cloudflare Radar downloads with a `Authorization: Bearer` header and parses to the same output; with no/invalid token it fails **safely** (preserve prior whitelist + warn, per #886) and **never logs the token**.
4. The token field is masked, write-only, accepts a real token charset, and round-trips per the config-gateway contract.
5. A `www/` change carries Tier-A UI coverage; the licence notes render.
6. The CI health-check validates keyless providers and visibly skips (or secret-checks) token ones.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`, no `die()/exit()`; PFBL-01 `RequirePfbFilter` + `RequireConfigGateway` + `UppercaseBooleanLiteral` sniffs stay green.
- A registered field ⇒ registry entry + `since` + round-trip test + sniff `$registeredPaths` + inventory (config-gateway.md).
- Test-coverage mandate: every behaviour-changing phase fails-before/passes-after; behaviour-preserving phases pin an oracle; `www/` ⇒ Tier-A. No coverage theater.
- CI tooling under `scripts/` may use `python3`; the appliance may not.

## 6. Action plan (phases — early ones are behaviour-preserving prep)

### Phase 1 — Extract the provider table (behaviour-preserving)

- Prompt: `01_Provider_Descriptor.txt`
- Introduce `pfb_top1m_providers()` returning the descriptor table for **tranco + cisco only** (container `zip`, parse `rank_domain`, auth `none`). Rewire `pfblockerng.php`'s URL `if/else` to read it. No new provider, no behaviour change.
- Tests: an off-appliance oracle pinning that the resolved URL for `tranco`/`cisco` is unchanged; existing TOP1M tests stay green.

### Phase 2 — Generalize the parser to the descriptor (behaviour-preserving)

- Prompt: `02_Parser_Generalize.txt`
- `pfblockerng_top1m()` reads `parse`/`container` from the active descriptor; for `rank_domain`/`zip` the output is byte-identical. The `pfblockerng_top1m()` `Top1mPreserveOnEmptyFeedTest` oracle stays green.
- Tests: extend `Top1mPreserveOnEmptyFeedTest` — same input, same output; add a header-skip + domain-col unit case against a synthetic descriptor (proves the new knobs work) with no live provider yet.

### Phase 3 — Header auth in `pfb_download()` (behaviour-preserving)

- Prompt: `03_Download_Header_Auth.txt`
- Add `$extra_headers` + `$feed['headers']`; merge into `CURLOPT_HTTPHEADER` without clobbering the conditional-GET header. No caller sets it yet.
- Tests: a unit/pinning test that the header list is merged (both `If-None-Match` and a supplied header present); existing downloads unchanged.

### Phase 4 — Add the keyless providers (DomCop, Majestic)

- Prompt: `04_Keyless_Providers.txt`
- Descriptor rows (DomCop: zip/col-2/header; Majestic: plain/col-3/header); UI options; Majestic **CC BY 3.0 attribution** note; Tier-A render assertion (both options present + attribution shown).
- Tests: fail-before/pass-after — a DomCop/Majestic sample parses to the expected whitelist (domain from the right column, header skipped) where today's parser would mis-read it; Tier-A UI.

### Phase 5 — Add the token field + Cloudflare Radar (token via header)

- Prompt: `05_Token_And_Cloudflare.txt`
- Registered masked `top1m_token` field + `PFB_FILTER_TOKEN` validator + round-trip test + sniff/inventory; Cloudflare descriptor (header auth, JSON/CSV parse, bucket URL); UI (JS-toggled token field + **CC BY-NC** note); safe-on-missing-token behaviour (preserve+warn, no token in logs). Tier-A + a Tier-B save→reload persistence check for the token field.
- Tests: token round-trip; a Cloudflare-format sample parses; a missing/invalid-token run preserves the prior whitelist + warns + logs no token (assert the redacted log).

### Phase 6 — Health-check + docs

- Prompt: `06_Healthcheck_And_Docs.txt`
- `check_top1m_providers.py`: classify by `auth`; keyless validated, token providers secret-checked-or-visibly-skipped. Docs: config-gateway inventory (`top1m_token`), a TOP1M-providers note (sources, formats, licences, token setup).
- Tests: unit — a token-auth descriptor is skipped-with-reason when no secret, validated when a (mock) secret is present; keyless unchanged.

## 7. Definition of done

- All six phases merged; §4 requirements met; every phase's tests green; PFBL sniffs + PHPStan + PHPUnit + Tier-A green.
- **Manual smoke (owner: maintainer)** — CI cannot exercise a live token download or a live-VM DNSBL resolve for every provider: on a real box, for each of DomCop / Majestic / Cloudflare (with a real token), run an Update and confirm `Building TOP1M Whitelist … Found N` with N>0, a blocked-then-whitelisted popular domain resolves, and — for Cloudflare — `extras.log` after a forced failure shows **no** token.
- Licence notes visible in the UI for Majestic + Cloudflare.

**Reject / revisit criteria**

- If **Phase 2's** generalization can't keep Tranco/Cisco byte-identical without disproportionate complexity → stop; reconsider a separate builder per shape instead of one generalized function.
- If **Cloudflare** (Phase 5) proves disproportionately complex (its two-call dataset API / JSON) relative to its value → **ship Phases 1–4 + the token plumbing dormant**, drop Cloudflare from the provider set, and record it here — the keyless providers (DomCop, Majestic) stand alone.
- If a token cannot be kept out of every log post-#890 → do not ship the token feature.

## 8. Test plan (summary)

- **Oracle (P1–P3):** Tranco/Cisco URL + `pfblockerng_top1m()` output pinned unchanged across the refactor; the header merge pinned.
- **Fail-before/pass-after (P4–P5):** each new format parses correctly where the old parser would not; the token round-trips; a missing-token run preserves+warns+logs-no-token.
- **Tier-A (P4–P5):** the DNSBL page renders the new options + licence notes + the masked token field; **Tier-B** for the token save→reload persistence.
- **CI health-check (P6):** keyless validated; token skipped-with-reason / secret-checked.
- **Manual smoke (§7):** the live per-provider download + resolve + no-token-in-log, on a real box.

## Amendment — 2026-07-20: inherited rollback-suite references superseded (issue #1593)

TOP1M provider behaviour, credential handling, current canonical round trips, and supported
forward-upgrade legacy reads remain unchanged. Completed phase references to
`RollbackContractTest` are historical; that downgrade-only suite is retired.
