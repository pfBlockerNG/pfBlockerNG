# ADR-52: Export a sanitized pfBlockerNG configuration from a new Diagnostics page

- **Status:** **Proposed** (2026-06-29). Not yet implemented.
- **Date:** 2026-06-29
- **Branch:** `adr/52-sanitized-config-export` (off **`devel`**; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming"). / **Component(s):** a new diagnostics engine
  `src/usr/local/pkg/pfblockerng/pfblockerng_diagnostics.inc`, a new GUI page
  `src/usr/local/www/pfblockerng/pfblockerng_diagnostics.php`, the per-page tab bar (each
  `src/usr/local/www/pfblockerng/*.php` that renders `$tab_array`), the package ACL
  `src/etc/inc/priv/pfblockerng.priv.inc`, and the FreeBSD-ports packaging (`pkg-plist` +
  `do-install`) on the `pfBlockerNG/FreeBSD-ports` fork.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). No Python, no shell.
- **Test suite:** `tests/php/` (PHPUnit — the pure extraction + redaction engine, off-appliance),
  `tests/smoke/ui/` (ADR-14 Tier A render + Tier B download), and a Python parity test under
  `tests/` (the shipped redaction word-set must not under-redact relative to the proven smoke
  scrubber).

## 1. Context

### 1.1 The problem

Bug reports rarely include enough of the user's pfBlockerNG configuration to reproduce a problem,
because pasting the raw config means pasting secrets. The config carries, at minimum:

- the **MaxMind license key** and **account ID** (`installedpackages/pfblockerngipsettings/config/0`
  — `maxmind_key`, `maxmind_account`; see `pfblockerng_install.inc:683`);
- **feed-URL credentials** — many feeds authenticate via a **token in the URL query string**
  (`<url>https://host/list.txt?token=…</url>`) or HTTP basic-auth userinfo
  (`https://user:pass@host/…`). Feed URLs are stored per row under the `pfblockerng*` list sections
  (`<url>`, e.g. `pfblockerng.inc:265`/`:290`);
- the **cluster sync password** and the addresses of the user's other firewalls
  (`installedpackages/pfblockerngsync`);
- **update-hook commands** (ADR-12) — free-text shell stored under
  `installedpackages/pfblockerng/config/0/hooks/row`, which can embed arbitrary credentials
  (`curl -H "Authorization: Bearer …"`).

There is no in-product way to hand a maintainer a safe, scoped copy of just the pfBlockerNG
configuration. The companion bug-report issue template
(`.github/ISSUE_TEMPLATE/bug_report.yml`) currently asks the user to redact by hand — error-prone,
and the exact thing this ADR removes the need for.

### 1.2 Today (load-bearing facts, verified)

- **A file-download pattern already exists in the GUI.** `pfblockerng_log.php:331-333` streams a
  file with `Content-Type: application/octet-stream` + `Content-Length` +
  `Content-Disposition: attachment; filename="…"`. The export reuses this exact pattern — no new
  download machinery.
- **A proven config-secret scrubber already exists, but only in the test harness.**
  `tests/smoke/helpers.py` defines `_config_xml_scrub_sed_program()` (used by `snap_state()` and
  `collect_host_diagnostics()`), which combines explicit credential substitutions
  (`bcrypt-hash`/`prv`/`authorizedkeys`/`tls_certificate`) with an Actuator-style **tag-name** pass
  (`sensitive_tag_sed_program()`) built from `_SENSITIVE_TAG_WORDS`
  (`password`/`passwd`/`secret`/`token`/`apikey`/`authkey`/`privatekey`/`passphrase`/`psk`/
  `credential`/`key`). This is Python `sed`-program code — **not shippable** to the appliance GUI
  (PHP). It is the **reference**, not a reusable library, for the shipped redactor; its word-set is
  the floor the shipped redactor must meet or exceed.
  Pinned off-appliance by `tests/test_smoke_diag_redaction.py`.
- **The tab bar is per-page.** Each main `www/` page builds its own `$tab_array` inline (General /
  IP / DNSBL / Update / Reports / Feeds / Logs / Sync) and calls `pfb_software_add_tab()`
  (`pfblockerng.inc:3152`) then `display_top_tabs()`. There is **no** shared tab list — adding a
  tab edits each page that renders the bar.
- **The ACL is a per-page match list, not a wildcard.** `pfblockerng.priv.inc` defines one priv,
  `page-firewall-pfblockerng`, with an explicit `match[]` entry per page. A new page is reachable
  only if its path is added to that list.
- **A new shipped file needs FreeBSD-ports wiring.** Release archives contain only `src/`; a new
  file under `src/usr/local/...` must be added to `pkg-plist` **and** the `do-install`
  (`MKDIR`/`INSTALL_DATA`) of **all three** ports on the `pfBlockerNG/FreeBSD-ports` fork.
  `scripts/build-pkg-portable.py --dry-run` **hard-fails** on plist↔staged drift; PR CI does not
  build the `.pkg`, so this is caught only by the smoke/release build — land package + ports in
  lockstep.

### 1.3 Why a new Diagnostics page (not an existing tab)

The export could live on the Logs/Update/General tab with no new file. We deliberately accept the
new-page cost because two roadmap items want the same home:

- **#364** ("Check what rule is triggered by a Domain or IP").
- **#294 / ADR-34** (the read-only Block **Triangulator** / Why-Blocked tool; ADR-34 already
  proposes "a new Diagnostics page").

ADR-52 **establishes** the Diagnostics page and ships **Export sanitized configuration** as its
first card. #364 and ADR-34 later add their tools as **additional cards on the same page** — no new
tabs. (ADR-34's draft says "under Reports"; this ADR makes it a top-level **Diagnostics** tab.
ADR-34/#364 should reconcile to that when implemented — noted here, ADR-34's own text is left
untouched.)

### 1.4 Scope boundary

ADR-52 builds **only** the Diagnostics page shell + the Export tool. It does **not** build the
triangulator (#294/ADR-34) or the rule-lookup (#364) — it only leaves a page they can extend.

## 2. Decision

Add a **read-only "Export sanitized configuration"** action on a new **Diagnostics** page. The
export emits only the pfBlockerNG-owned config (`installedpackages/pfblockerng*`), with secrets and
private data removed by a **hybrid** model, as a downloadable `.xml` file the user can attach to a
bug report.

### 2.1 Per-area decision

| Area | Decision |
| --- | --- |
| Engine location | new `pfblockerng_diagnostics.inc` (pure functions; keeps logic out of the 14k-line core and is the shared home ADR-34 also targets) |
| Extraction | `pfb_diag_extract_pfb_xml($config_xml)` → `DOMDocument`/`DOMXPath` select `//installedpackages/*` whose node name starts with `pfblockerng`; serialize those nodes. Operates on the **stored XML text** (preserves the on-disk form), not a config-array round-trip |
| Wholesale drops (hybrid) | before redaction, **remove entire** `pfblockerngsync` node(s) (sync password + peer addresses) and the `hooks` subtree under `pfblockerng/config` (free-text shell that can embed credentials) |
| Redaction — tag-name pass | `preg_replace` the inner text of any element whose tag ends in one of the sensitive words (the `_SENSITIVE_TAG_WORDS` set, **case-insensitive**, optional trailing plural `s`) → `REDACTED`. Catches `maxmind_key`, `varsyncpassword` (if ever kept), etc. Over-redaction is safe; under-redaction is not |
| Redaction — explicit | `maxmind_account` → `REDACTED` (not caught by the word set) |
| Redaction — feed URLs | in `<url>` values, strip the **entire query string** (`?…` → `?REDACTED`) and any `user:pass@` userinfo (`://…@` → `://REDACTED@`). Conservative default — a secret query param can't be reliably distinguished from a benign one. **Exact granularity is a TBD for implementation** (see §6 Phase 1) |
| Output | `pfb_diag_export_sanitized_config($path='/conf/config.xml')` → the extracted-then-redacted XML string. Wrapped in a single `<pfblockerng_sanitized_export>` root for valid standalone XML |
| Download | `pfblockerng_diagnostics.php` POST handler streams the string via the `pfblockerng_log.php:331-333` `Content-Disposition` pattern; filename `pfblockerng-config-sanitized.xml` |
| Page / tab | new top-level **Diagnostics** tab added to each page's `$tab_array`; the new page renders the bar with Diagnostics active |
| ACL | **no new priv** — add `pfblockerng/pfblockerng_diagnostics.php` to the existing `page-firewall-pfblockerng` `match[]` list. Pfb GUI managers get the export (and, later, the triangulator) |

### 2.2 Semantics that MUST be preserved / guaranteed (pin with tests before shipping)

- **No known secret class survives the export.** For a config fixture seeded with every known
  secret — `maxmind_key`, `maxmind_account`, a feed `<url>` with `?token=…`, a basic-auth feed
  `<url>`, `varsyncpassword`, an update-hook with an `Authorization` header, and generic
  `<password>`/`<secret>`/`<apikey>`/`<…token>` tags — **none** appears in the output. This is the
  acceptance core and the reject criterion.
- **Useful non-secret data is preserved.** Feed alias names, formats, actions, list/mode settings,
  `maxmind_locale`, and the feed-URL **host+path** survive (only the query/userinfo is stripped) —
  otherwise the export does not help reproduce anything.
- **The export is read-only.** It reads `/conf/config.xml`, mutates nothing, writes nothing,
  triggers no reload.
- **Only pfBlockerNG sections leave the box.** No `installedpackages/*` outside `pfblockerng*`, and
  nothing from the rest of `config.xml` (interfaces, VPN, certs, users), is ever emitted.
- **Shipped redaction ⊇ proven scrubber.** The shipped word-set is a **superset** of the harness
  `_SENSITIVE_TAG_WORDS`, so the product never redacts *less* than the smoke diagnostics already do.

### 2.3 Explicitly kept / out of scope

- **The triangulator (#294/ADR-34) and rule-lookup (#364)** — not built here; the page is shaped to
  host them later.
- **Centralizing the per-page tab bar** — out of scope (YAGNI: future Diagnostics tools add *cards*
  to this page, not new *tabs*, so the tab is added exactly once, here).
- **A whole-system sanitized export** — pfSense core's System Status already scrubs+dumps the whole
  config; ADR-52 is deliberately pfBlockerNG-scoped (less exposure, more relevance).
- **`config.xml` schema / migration** — none; this is a read-only export.
- **Import / restore of a sanitized config** — nonsensical (it's lossy by design).

## 3. Consequences

**Positive**

- Users can attach a safe, scoped pfBlockerNG config to a bug report in one click — better reports,
  no hand-redaction, no accidental key leak.
- The security-critical part (extraction + redaction) is **pure PHP string/XML work → fully
  off-appliance PHPUnit-testable**, including adversarial "secret must not survive" tests. No live
  VM needed to prove the core.
- Establishes the Diagnostics page that #364 and ADR-34 plug into — one page, paid once.

**Negative / risks**

- **Under-redaction is the cardinal risk.** A "sanitized" export that leaks a secret is worse than
  no button (false confidence). Mitigated by the wholesale drops for un-scrubable sections (sync,
  hooks) and the adversarial test set as the acceptance gate.
- **Denylist drift.** A future secret field with an unmatched name could leak until added to the
  list. Mitigated by the broad suffix match (`*key`/`*token`/`*secret`/`*password`/…), the
  superset-of-harness parity test, and the wholesale section drops for the known free-text risks.
- **New shipped files → cross-repo lockstep.** Two new `src/` files must be wired into three ports'
  `pkg-plist`/`do-install`; the package PR and the ports PR must land together or the smoke/release
  build fails.
- **Per-page tab edit.** Adding the tab touches every page that renders the bar — mechanical, but a
  wide diff; pinned by the Tier A render oracle (same tab set on every page, plus the new one).

## 4. Requirements (acceptance)

1. The Diagnostics page renders (Tier A: 200, page marker present, no new `php_error.log` line).
2. The Export action returns a downloadable XML file (`Content-Disposition: attachment`).
3. Against the seeded all-secrets fixture, the exported file contains **none** of the secret values
   and **does** contain the expected non-secret fields (PHPUnit, red→green; branch-covered).
4. The shipped redaction word-set is a superset of the harness `_SENSITIVE_TAG_WORDS` (parity test).
5. The export reads `/conf/config.xml` only and emits only `pfblockerng*` sections.
6. Access is governed by the existing `page-firewall-pfblockerng` priv.
7. Green CE+Plus Tier A fan-out (+ Tier B download check).

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; uppercase `TRUE`/`FALSE`; tabs; no `die()`/`exit()` in library code (the `.inc` engine
  returns/throws; the `.php` page may `exit` after streaming, as the log page does).
- Config reads: the whole-section structural read of `installedpackages` is a section-level read,
  not a registered `pfblockerng*` scalar — use `config_get_path('installedpackages')` /
  text read of `/conf/config.xml`; the `RequireConfigGateway` sniff does not flag it. Touch no
  registered scalar through a raw `config_*_path`.
- Web-UI help text: brief, matching neighbouring help wording.
- Front-end change ⇒ Tier A required; the multi-step download+content assertion is observable only
  in **Tier B** ⇒ Tier B required for it.
- New shipped file ⇒ FreeBSD-ports `pkg-plist` + `do-install` in all three ports, landed in
  lockstep; verify with `build-pkg-portable.py --dry-run`.
- Plan-with-higher-model / implement-with-Sonnet for the multi-step `src/`/`www/`/ports work.

## 6. Action plan (phases)

### Phase 1 — Diagnostics engine + redaction (pure PHP, TDD, off-appliance)

Prompt: `01_Engine_Redaction.txt`

- New `src/usr/local/pkg/pfblockerng/pfblockerng_diagnostics.inc` with pure functions:
  - `pfb_diag_extract_pfb_xml(string $config_xml): string` — DOM/XPath select `pfblockerng*`
    nodes; apply the wholesale drops (`pfblockerngsync`, `hooks` subtree); return the concatenated
    node XML wrapped in `<pfblockerng_sanitized_export>`.
  - `pfb_diag_redact(string $xml): string` — the tag-name pass + explicit `maxmind_account` +
    feed-`<url>` query/userinfo stripping. **Settle the URL-stripping granularity here** (default:
    strip the whole query string + userinfo) and pin it with tests.
  - `pfb_diag_export_sanitized_config(string $path = '/conf/config.xml'): string` — extract→redact.
- Wire the new `.inc` into the PHPUnit bootstrap (`tests/php/bootstrap.php`) so the engine loads
  off-appliance.
- **Tests FIRST (red→green):**
  - `tests/php/DiagnosticsExportTest.php` — an all-secrets config fixture; assert every seeded
    secret value is absent from the output AND every expected non-secret field is present; branch
    coverage (each redaction rule has a positive case that is redacted AND a near-miss that is
    kept, e.g. `<maxmind_locale>` kept vs `<maxmind_account>` redacted; a clean `<url>` intact vs a
    `?token=` URL stripped); the wholesale-dropped sections are wholly absent.
  - A Python parity test under `tests/` asserting the PHP word-set (parsed from the `.inc`) ⊇
    `tests.smoke.helpers._SENSITIVE_TAG_WORDS`.
- Verify: `vendor/bin/phpunit` green; `php -l`; `python -m pytest` green.

### Phase 2 — Diagnostics page, Export download, tab + ACL (www)

Prompt: `02_Diagnostics_Page.txt`

- New `src/usr/local/www/pfblockerng/pfblockerng_diagnostics.php`: renders the tab bar with a new
  **Diagnostics** tab active; an "Export sanitized configuration" card (brief help text + a button
  / POST form). On POST, call `pfb_diag_export_sanitized_config()` and stream it with the
  `pfblockerng_log.php:331-333` `Content-Disposition` pattern (filename
  `pfblockerng-config-sanitized.xml`), then `exit`.
- Add the **Diagnostics** entry to every page's `$tab_array` (the pages that render the bar).
- Add `pfblockerng/pfblockerng_diagnostics.php` to the `page-firewall-pfblockerng` `match[]` list in
  `pfblockerng.priv.inc`.
- **Tests:** Tier A (`tests/smoke/ui/`) — Diagnostics page 200, marker, no new `php_error.log`;
  the new tab present on a sample of pages. **Tier B** — POST the export, assert
  `Content-Disposition` + that a seeded non-secret field is present and a seeded secret is **absent**
  from the downloaded body.
- Verify: `php -l`; Tier A locally (`SMOKE_ADMIN_PASSWORD` set) or via dispatch.

### Phase 3 — FreeBSD-ports lockstep wiring

Prompt: `03_Ports_Lockstep.txt`

- On the `pfBlockerNG/FreeBSD-ports` fork (`pfblockerng/use-github` build-input branch), add both new
  files (`pfblockerng_diagnostics.inc`, `pfblockerng_diagnostics.php`) to `pkg-plist` and the
  `do-install` (`MKDIR`/`INSTALL_DATA`) of **all three** ports.
- Verify `scripts/build-pkg-portable.py --dry-run` passes (no plist↔staged drift).
- Land in lockstep with the package PR.

### Phase 4 — Docs + Definition-of-done / live-VM

Prompt: `04_Docs_DoD.txt`

- `docs/misc/architecture-notes.md`: a short "Diagnostics page / sanitized config export" section
  (the hybrid redaction model + the wholesale drops + the ADR-34/#364 coordination note).
- Run the CE+Plus Tier A fan-out (+ Tier B download); record results.

## 7. Definition of done

- Phases 1–4 landed on `adr/52-…` (package) with the ports change landed in lockstep; off-appliance
  `vendor/bin/phpunit` + `python -m pytest` green.
- The adversarial export test proves no known secret class survives, with non-secret data preserved.
- Tier A render green on the CE+Plus fan-out; Tier B proves the downloaded body is secret-free.
- **Manual smoke checklist (owner: maintainer)** — on a real box with a MaxMind key, a token-bearing
  feed URL, a configured sync peer, and an update hook: click Export, open the file, confirm the key,
  account, feed token, sync password/peers, and hook command are all gone and the feed lists / settings
  are present and useful.
- Flips to **Accepted** on the green CE+Plus Tier A/B fan-out + the maintainer manual check (the
  redaction completeness is the one thing a render test cannot fully assert — the manual check is the
  documented out-of-CI confirmation).
- **Reject/revisit criteria:** if Phase 1 shows a known secret class cannot be reliably removed
  (neither pattern-redacted nor safely dropped wholesale) without gutting the export's usefulness,
  **do not ship** the button — a leaky "sanitized" export is worse than none. Fall back to the
  issue-template manual-redaction guidance and mark this ADR Rejected with the evidence.
