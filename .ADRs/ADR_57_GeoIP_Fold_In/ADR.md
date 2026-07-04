# ADR-57: GeoIP fold-in (continents become Feed Groups)

- **Status:** **Proposed — deferred** (2026-07-04; committed follow-up of the ADR-54/55/25
  trilogy; last in the sequence)
- **Date:** 2026-07-04
- **Depends on:** ADR-54 + ADR-55 **complete** (Feed Group entity + policy bindings);
  independent of ADR-25's DNSBL layer but sequenced after ADR-56 to keep one migration in
  flight at a time.
- **Branch (when started):** `adr/57-geoip-fold-in`

## Execution order

```text
ADR-54 → ADR-55 → ADR-25 P2..P7 → ADR-56 → ADR-57 (this)
```

## 1. Context

GeoIP lives outside the normalized model: one config section per continent
(`installedpackages/pfblockerng<continent>/config/0`), a separate editor path on the
Category page (`?type=geoip`, no `cron` column, per-continent action), its own build path
(`pfblockerng.inc` GeoIP loops feeding `pfb_firewall_rule()` per continent), and ADR-11
aggregation folds continents in by action class. ADR-54 §2.4 explicitly left it untouched;
ADR-55 CG bindings do not apply to GeoIP.

## 2. Decision (sketch — to be developed when picked up)

- Each continent becomes a **Feed Group** whose members are per-country **feed entities**
  (`managed_by = geoip`, local MaxMind/IPinfo-derived artifacts — the ADR-54 §2.5 Blacklist
  pattern reused verbatim: the GeoIP settings page stays the source manager; the entities
  join the normal pipeline).
- Continent groups then get M:N membership (a custom "Sanctioned countries" group mixing
  countries across continents becomes possible) and **CG policy bindings** like any other
  group — per-client GeoIP enforcement.
- Migration: per-continent sections → groups + country feeds, one-time, mirrored (the
  ADR-54 §2.4 downgrade posture), Category-page GeoIP special case retired.

## 3. Risks flagged now

- Country-set size × M:N duplication vs `system/maximumtableentries` — needs the same
  rule-count/table-size surfacing ADR-55 added.
- Reputation/dedup interactions with GeoIP folding (ADR-40 §cross-list rules) must be
  re-pinned.

## 4. Action plan

Authored when picked up. Expected shape: (1) country-feed emission + provider page rework,
(2) migration + oracles (zero-change for existing continent configs), (3) Category/Feeds
page GeoIP unification + Tier A/B, (4) smoke.
