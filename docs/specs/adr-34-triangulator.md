# Spec: Block Triangulator (Why-Blocked diagnostics)

Migrated from `legacy/ADRs/ADR_34_Triangulator_Tool/` (Proposed, never implemented; folds in
issue #294) under wayfinder map
[#1383](https://github.com/pfBlockerNG/pfBlockerNG/issues/1383), map ticket
[#1484](https://github.com/pfBlockerNG/pfBlockerNG/issues/1484). Requirements and
rationale migrate; the ADR's phase plan and phase-prompt files are obsolete under the
fresh-session workflow and do not. The ADR's §2.0 open fork and the per-entry-path
verdict scoping were resolved with the owner in #1484.

## Goal

Answer the canonical support question — "why is this domain/IP blocked, and where do I
whitelist it?" — with a **read-only** diagnostics tool that attributes the correct layer
(DNSBL at the resolver vs IP firewall post-resolution), names the responsible feed/rule,
and explains the remedy in plain English. Whitelisting the wrong layer has no effect;
today users burn support rounds discovering that. v1 is read-only with contextual links
to the existing whitelist/config pages; in-place whitelisting is deferred.

## Fixed constraints

- PHP 8.3 on the appliance; Python only inside `pfb_unbound.py` (the standing exception).
- **Strictly read-only**: the engine performs no `config_set_path`/`write_config` and no
  DNSBL cache writes; asserted across a triangulate run.
- **Input is validated before any shell/DNS use** (PFBL-01): `pfb_filter()` domain
  filtering / `is_ipaddr()` / URL parsing; no unfiltered value reaches `drill`, `pfctl`,
  or the control channel; new input-handling functions join the PHPCS `scopeFunctions`
  allow-list.
- **Bounded**: CNAME chains depth-limited (~10) with timeouts and a loop guard; process
  waits follow `docs/misc/external-process-waits.md`.
- **Existing Alerts behaviour unchanged**: the per-row entry point is additive;
  `convert_dnsbl_log()` / `dnsbl_log_details()` are reused read-only, never modified.
- Unbound is chrooted at `/var/unbound`: resolver-side data is reached via existing
  helpers and the control channel, never re-derived host-absolute paths.
- Any new shipped file needs FreeBSD-ports lockstep (`pkg-plist` + `do-install`, all
  three ports; `scripts/build-pkg-portable.py --dry-run` clean).
- Front-end: Tier A `ui_render` for the page surface; the multi-step form/pre-fill flows
  are Tier B `ui_e2e`; the end-to-end block-and-triangulate proof is live-VM smoke (no
  Unbound in CI).
- Cite symbols, not line numbers, in derived work.
- **Reduce/reject criteria**: if read-only on-demand lookups for arbitrary input cannot
  be bounded safely, or correct layer attribution cannot be validated, reduce to
  Alerts-context-only (no free-text) or reject, recording the evidence.

## Decisions

### Matcher truth (fork resolved in #1484: ask the Python module)

- The DNSBL verdict comes from a new **`explain` op on the `python_control` channel**:
  the live `pfb_unbound.py` module runs the name through its own matcher (manifest-built
  structures, ABP, feed regex, TLD/wildcard, the allow layer — user whitelist, ADR-31
  permit feeds, allow-regex) and returns the verdict plus the matched layer/feed/rule
  band. Correct by construction; a second matcher never exists.
- A **PHP parity matcher is rejected**: its data anchors are dead (`pfb_dnsbl_parse()`
  deleted; the legacy `unbound_py_data`/`unbound_py_zone` CSVs are ADR-65 retired writer
  targets) and a co-maintained re-implementation would drift — the worst failure mode
  for a diagnostic that must not lie.
- The channel today is one-way (JSON record, seq-advance, applied-seq marker; ops
  `disable`/`enable`/`addbypass`/`removebypass`). `explain` adds a **response path**
  mirroring the applied-marker pattern: request record with seq → the module writes a
  response document keyed to that seq → PHP polls with a bounded timeout.
- Unbound not running ⇒ the page reports "resolver not running"; the DNSBL section is
  unavailable (IP-side checks still run). Acceptable for a diagnostics page.

### Verdict scoping (fork resolved in #1484: optional context)

- `explain` accepts **optional query context** (client IP, query type). The Alerts-row
  entry pre-fills it from the logged query — full-fidelity attribution. The free-text
  form omits it — the module answers for the global/default view, and the report labels
  context-dependent verdicts (SafeSearch, DoH-DoT-DoQ, IDN, TLD-Allow, future per-client
  policy) as evaluated without client context.

### Engine

- Lives in `pfblockerng_diagnostics.inc` — the shared Diagnostics engine established by
  the ADR-52 spec (`docs/specs/adr-52-sanitized-config-export.md`).
  - `pfb_diag_resolve($domain)` — A/AAAA + full CNAME chain via the existing
    `pfb_ss_resolve_target()`/`drill`/`extdns` pattern; input validated first; depth
    limit + timeout.
  - `pfb_diag_dnsbl($domain, $cname_chain)` — the `explain` op over the domain and every
    CNAME in the chain; classifies exact / parent-wildcard / TLD / CNAME / allowed.
  - `pfb_diag_ip($ips)` — `pfctl -t <table> -T test` over the active `pfB_*` urltable
    aliases; identifies the matching feed/alias.
  - `pfb_triangulate($input)` — auto-detects IP / domain / URL, runs the relevant
    checks, returns a structured report.
- The Alerts-row path may reuse `dnsbl_log_details()` log-field parsing (a genuine
  behaviour oracle); matching logic itself is never re-implemented in PHP.

### Classification and explanation

- Verdict vocabulary: pure-DNSBL / pure-IP / hybrid / via-CNAME / via-TLD /
  allowed-whitelisted / SafeSearch / DoH-DoT-DoQ / IDN / TLD-Allow.
- Each classification carries a plain-English explanation with layer-correct guidance
  (e.g. "DNSBL block — whitelisting the IP has no effect; whitelist at the DNSBL
  level"), plus contextual links to the existing whitelist/config pages, pre-filled
  where possible.

### UI

- Supersedes the ADR's "under Reports" placement: the Triangulator is a **card on the
  top-level Diagnostics page** established by the ADR-52 spec (fork verdict in #1441) —
  free-text IP/domain/URL form with a structured, colour-coded results panel and a
  copy-report affordance.
- A per-row "Triangulate" icon on the Alerts page pre-fills the domain plus the logged
  query context.
- ACL: the Diagnostics page is already covered by the existing
  `page-firewall-pfblockerng` priv entry added when the page lands (ADR-52 spec); no new
  priv.

## Acceptance criteria

1. **`explain` op**: request/response protocol with seq correlation and bounded timeout;
   returns verdict + matched layer/feed for every band — exact, wildcard, TLD, ABP,
   feed regex, user whitelist, permit feed, allow-regex; Python tests cover each band,
   malformed/unknown requests, stale-seq handling, and optional-context presence and
   absence. Existing control ops are byte-identically unaffected.
2. **Read-only**: no config or DNSBL-cache mutation across a triangulate run (asserted).
3. **Validation**: malformed input never reaches `drill`/`pfctl`/the control channel
   (tests prove rejection short of the shell).
4. **Bounded resolution**: fixture-driven `drill` parsing covers chain assembly, the
   depth limit, timeout handling, and a CNAME loop guard.
5. **IP attribution**: `pfctl -T test` results map to the correct `pfB_*` alias and feed.
6. **Classification branches**: each vocabulary verdict is produced from a fixtured
   combination of resolve/dnsbl/ip results, including the allowed-whitelisted near-miss
   (a domain present in a block feed but whitelisted reports allowed, not blocked).
7. **Scoping**: free-text reports label context-dependent verdicts; the Alerts-row path
   passes the logged context and gets full attribution (Tier B asserts both).
8. **UI**: Tier A render for the Diagnostics page with the card; Tier B — submit the
   form → report renders; Alerts icon → pre-filled run; Alerts page behaviour unchanged.
9. **Live-VM smoke (CE + Plus fan-out)**: a real DNSBL-blocked domain triangulates
   naming the feed with the IP-whitelist-has-no-effect guidance; an IP-side case; a
   CNAME-chain case; an allowed/whitelisted case; a resolver-down case reports honestly.
10. **Ports**: any new shipped file wired in all three ports in lockstep; dry-run clean.

## Out of scope

- In-place whitelisting (type-aware write-backs) — v2; v1 links to the existing pages.
- A menu entry or tab separate from the Diagnostics page.
- Modifying `convert_dnsbl_log()`/`dnsbl_log_details()` beyond read-only reuse.
- Caching diagnostic results.
- Any PHP fallback matcher (partial or otherwise) — rejected with the parity fork.

## Open forks

None. The §2.0 matcher fork (Python `explain` op confirmed), the per-entry-path verdict
scoping (optional context), and the map shape (one spec + a blocked chain of
implementation tickets) were resolved with the owner in
[#1484](https://github.com/pfBlockerNG/pfBlockerNG/issues/1484).
