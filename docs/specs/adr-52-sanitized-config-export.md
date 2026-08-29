# Spec: sanitized configuration export (Diagnostics page)

Migrated from `legacy/ADRs/ADR_52_Sanitized_Config_Export/` (Proposed, never implemented) under
wayfinder map [#1383](https://github.com/pfBlockerNG/pfBlockerNG/issues/1383), spec ticket
[#1441](https://github.com/pfBlockerNG/pfBlockerNG/issues/1441). Requirements and rationale
migrate; the ADR's phase plan and phase-prompt files are obsolete under the fresh-session
workflow and do not. All of the ADR's open forks were resolved with the owner in #1441.

## Goal

Give users a one-click, read-only **"Export sanitized configuration"** action on a new
top-level **Diagnostics** page. The export emits only the pfBlockerNG-owned configuration
(`installedpackages/pfblockerng*`) with secrets and private data removed, as a downloadable
`.xml` file safe to attach to a bug report. Today the bug-report template asks users to
redact `config.xml` by hand — error-prone, and the direct cause of thin bug reports.

## Fixed constraints

- PHP 8.3 (pfSense CE 2.8). No Python, no shell on the appliance.
- **Read-only**: the export reads `/conf/config.xml`, mutates nothing, writes nothing,
  triggers no reload.
- **Scope**: only `pfblockerng*` sections under `installedpackages` are ever emitted —
  nothing else from `config.xml` (interfaces, VPN, certs, users, other packages).
- **Under-redaction is the reject criterion**: if a known secret class cannot be reliably
  removed (neither pattern-redacted nor safely dropped wholesale) without gutting the
  export's usefulness, the button does not ship — a leaky "sanitized" export is worse than
  none. Fall back to the issue-template manual-redaction guidance.
- Config access: the whole-section structural read of `installedpackages` is a
  section-level read, not a registered `pfblockerng*` scalar — no registered scalar may be
  touched through a raw `config_*_path` (see `docs/misc/config-gateway.md`).
- Engine code (`.inc`) returns/throws — no `die()`/`exit()`; the page may `exit` after
  streaming, as the log page does.
- New shipped files require FreeBSD-ports wiring (`pkg-plist` + `do-install` in all three
  ports on the `pfBlockerNG/FreeBSD-ports` fork), landed in lockstep with the package
  change; `scripts/build-pkg-portable.py --dry-run` must pass.
- Front-end change ⇒ Tier A UI coverage; the download+content assertion is observable only
  in Tier B ⇒ Tier B required for it.
- Cite symbols, not line numbers, in derived work — line drift in `pfblockerng.inc` is
  universal.

## Decisions

### Engine

- New pure-function engine `pfblockerng_diagnostics.inc` (under
  `src/usr/local/pkg/pfblockerng/`): keeps the logic out of the 14k-line core and is the
  shared home the ADR-34 triangulator later joins.
  - `pfb_diag_extract_pfb_xml(string $config_xml): string` — DOM/XPath selection of
    `//installedpackages/*` nodes whose name starts with `pfblockerng`, operating on the
    **stored XML text** (preserves the on-disk form; no config-array round-trip); applies
    the wholesale drops; returns the nodes wrapped in a single
    `<pfblockerng_sanitized_export>` root (valid standalone XML).
  - `pfb_diag_redact(string $xml): string` — the redaction passes below.
  - `pfb_diag_export_sanitized_config(string $path = '/conf/config.xml'): string` —
    extract, then redact.

### Redaction model (hybrid)

- **Wholesale drops** (before redaction): the entire `pfblockerngsync` node (sync
  password + peer firewall addresses) and the `hooks` subtree under
  `pfblockerng/config` (free-text
  shell that can embed arbitrary credentials).
- **Tag-name pass — DOM-walk, never regex-over-serialized-text**: traverse the built
  `DOMDocument`; for any element whose tag name ends in one of the sensitive words
  (case-insensitive, optional trailing plural `s`), replace its **text AND CDATA** children
  with `REDACTED`. The regex form is **rejected**: pfSense's `$cdata_fields` serialization
  (`<password><![CDATA[…]]></password>`) survives `(<tag>)[^<]*` patterns. Over-redaction
  is safe; under-redaction is not.
- **Word set**: a superset of the proven harness scrubber's `_SENSITIVE_TAG_WORDS`
  (`tests/smoke/helpers.py` — `password`/`passwd`/`secret`/`token`/`apikey`/`authkey`/
  `privatekey`/`passphrase`/`psk`/`credential`/`key`). The harness scrubber is the
  reference floor, not a shippable library (it is Python `sed`-program code).
- **Explicit rule**: `maxmind_account` → `REDACTED` (not caught by the suffix set).
  Premise fix carried from #1441: `maxmind_account` lives in `pfblockerng.inc`
  (`pfb_maxmind_credential_notice()`, and the global-load assignment near
  `asn_token`) — not in `pfblockerng_install.inc` as the ADR cited.
- **Feed URLs** (fork resolved in #1441): in `<url>` values, strip the **entire query
  string** (`?…` → `?REDACTED`) and any userinfo (`://user:pass@` → `://REDACTED@`).
  Host and path survive. Fail-closed by construction: no per-parameter denylist to drift,
  and bare-token query strings (`?ABCDEF`, no `=`) cannot leak.

### Fail-closed inventory test (fork resolved in #1441: adopted)

A CI test walks `pfb_cfg_registry()` (`pfblockerng_extra.inc`) plus the known
`installedpackages/pfblockerng*` section keys and **fails when any field is neither on an
explicit known-non-secret allowlist nor provably redacted** by the engine. Adding a config
field forces a secret-or-not classification at add time; an innocuously-named secret (the
`maxmind_account` class) can no longer leak silently. The allowlist is the maintenance
cost, one line per new field, named by the failing test.

### Page, tab, ACL, download

- **Top-level Diagnostics tab** (fork resolved in #1441: confirmed): new page
  `pfblockerng_diagnostics.php` (under `src/usr/local/www/pfblockerng/`); the tab is added
  to every page's `$tab_array` (the bar is per-page — no shared tab list). The export is
  the page's first card; the ADR-34 triangulator and the #364 rule-lookup later add cards
  to this page and reconcile to this location (ADR-34's "under Reports" draft is
  superseded).
- **Download**: POST handler streams the string using the existing `pfblockerng_log.php`
  attachment pattern (`Content-Type: application/octet-stream` + `Content-Length` +
  `Content-Disposition: attachment`); filename `pfblockerng-config-sanitized.xml`.
- **ACL**: no new priv — the page path is added to the existing
  `page-firewall-pfblockerng` `match[]` list in `pfblockerng.priv.inc`.

## Acceptance criteria

1. The Diagnostics page renders: Tier A 200, page marker present, no new `php_error.log`
   line; the Diagnostics tab is present on the pages that render the bar.
2. The Export action returns a downloadable XML file
   (`Content-Disposition: attachment`, filename `pfblockerng-config-sanitized.xml`).
3. **Adversarial fixture (PHPUnit, red→green, branch-covered)**: against a config fixture
   seeding every known secret — `maxmind_key`, `maxmind_account`, `asn_token`, a feed
   `<url>` with `?token=…`, a basic-auth feed `<url>`, `varsyncpassword`, an update-hook
   with an `Authorization` header, and generic `<password>`/`<secret>`/`<apikey>`/
   `<…token>` tags — each seeded in **both** plain entity-escaped text AND the pfSense
   `$cdata_fields` CDATA form, **no secret value appears in the output**. Every expected
   non-secret field is present (feed alias names, formats, actions, list/mode settings,
   `maxmind_locale`, feed-URL host+path). Each redaction rule has a positive case AND a
   kept near-miss (`maxmind_locale` kept vs `maxmind_account` redacted; a clean `<url>`
   intact vs a `?token=` URL stripped). The wholesale-dropped sections are wholly absent.
4. **Parity test**: the shipped word-set is a superset of the harness
   `_SENSITIVE_TAG_WORDS` (Python test parsing the `.inc`), so the product never redacts
   less than the smoke diagnostics already do.
5. **Inventory test**: the fail-closed `pfb_cfg_registry()`-walk test is green, and
   demonstrably red when a field is neither allowlisted nor redacted.
6. The export reads `/conf/config.xml` only and emits only `pfblockerng*` sections.
7. Access is governed by the existing `page-firewall-pfblockerng` priv.
8. Green CE+Plus Tier A fan-out; Tier B POSTs the export and asserts the attachment header,
   a seeded non-secret present, and a seeded secret absent from the downloaded body.
9. `scripts/build-pkg-portable.py --dry-run` passes with both new files wired into all
   three ports (lockstep landing).

Out-of-CI confirmation (documented, not an acceptance gate): on a real box with a MaxMind
key, a token-bearing feed URL, a configured sync peer, and an update hook — export, open
the file, confirm all secrets gone and the feed lists/settings present and useful.

## Out of scope

- The Block Triangulator (#294 / ADR-34) and the rule-lookup (#364) — the page is shaped
  to host them later, not built here.
- Centralizing the per-page tab bar (future tools add cards, not tabs — the tab sweep is
  paid exactly once, here).
- A whole-system sanitized export (pfSense core already scrubs+dumps the whole config;
  this stays pfBlockerNG-scoped).
- `config.xml` schema changes or migrations.
- Import/restore of a sanitized export (lossy by design).

## Open forks

None. The three forks recorded in the migration matrix (feed-URL strip granularity,
registry-walk inventory test, Diagnostics tab placement) were resolved with the owner in
[#1441](https://github.com/pfBlockerNG/pfBlockerNG/issues/1441).
