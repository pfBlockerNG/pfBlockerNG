# ADR-56: Per-Client-Group DNSBL axes (SafeSearch, DoH/DoT blocking)

- **Status:** **Proposed — deferred** (2026-07-04; committed follow-up of the ADR-54/55/25
  trilogy; do not start before ADR-25's decision layer is Accepted)
- **Date:** 2026-07-04
- **Depends on:** ADR-54 + ADR-55 + ADR-25 (revised) **complete** — consumes the Client
  Group entity, the client-mask machinery (`gpClientGroups`), and the divergence-gated
  caching scheme (or whatever the ADR-25 Phase-1 spike selected).
- **Branch (when started):** `adr/56-per-client-group-dnsbl-axes`

## Execution order

```text
ADR-54 → ADR-55 → ADR-25 P2..P7 → ADR-56 (this) → ADR-57
```

## 1. Context

SafeSearch is a global per-engine override axis (`safesearch_enable`/`safesearch_youtube`/
`safesearch_doh` registered scalars → CSV → `safeSearchDB` in `pfb_unbound.py`, A/AAAA
rewrite + NXDOMAIN shapes); DoH/DoT blocking likewise applies to every client. The natural
request after per-client DNSBL policy is "enforce SafeSearch (and DoH blocking) for the
kids' devices only". ADR-25 §2.4 explicitly deferred these axes here.

## 2. Decision (sketch — to be developed when picked up)

- **Client Groups gain axis toggles** (CG-level fields, NOT per-binding): `ss_enforce`
  (SafeSearch), `doh_enforce` (DoH/DoT list). Global settings stay as the default for
  clients outside any axis-enforcing CG (absent ⇒ today's behaviour).
- Enforcement rides the existing machinery: `gpClientGroups` membership check before
  applying the `safeSearchDB` / DoH override in `operate()`.
- **The same C-cache divergence hazard applies** — a rewritten SafeSearch answer cached
  once serves every client. Names covered by a per-CG-enforced axis join the divergent set
  (ADR-25 §2.2 (a′)); no new cache mechanism.
- UI: a "DNSBL Axes" section in `pfblockerng_group_policy_edit.php` (stock components), the
  SafeSearch page notes the per-CG override.

## 3. Out of scope

Per-CG TLD/IDN/noAAAA axes (assess separately); MAC/hostname identity; IP-side axes.

## 4. Action plan

Authored when picked up (after ADR-25 acceptance). Expected shape: (1) config + manifest
emission (axis flags per CG, divergent-set extension), (2) python enforcement + tests per
axis/branch, (3) UI + Tier A/B, (4) smoke reusing `client_source(ip)`.

## Migration note — 2026-07-23

Retired before implementation by [issue #1629](https://github.com/pfBlockerNG/pfBlockerNG/issues/1629).
ADR-55's unified DNS Policy Layer contract now owns SafeSearch, DoH-hostname NXDOMAIN,
No-AAAA, TLD/TOP1M/IDN, CNAME, domain/regex decisions, native Schedules, recipient
selection, provenance, UI, and forward migration. ADR-25's
[recipient-safe enforcement specification](../../docs/specs/adr-25-recipient-safe-dnsbl-enforcement.md)
owns policy-scoped compilation/publication, actual-recipient enforcement, cache safety,
generation invalidation, and CE/Plus acceptance. The per-Client-Group toggles and direct
`gpClientGroups` checks sketched above are superseded by complete ordered DNS Policy Layers
and deterministic recipient policy classes. No residual requirement, replacement spec,
implementation graph, or Wayfinder map remains.
