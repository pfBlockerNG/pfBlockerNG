# .Plans — single-step plan ADRs

Lightweight, single-step ADRs for discrete pieces of work — the design, the findings
made while implementing, and the result. Unlike `.ADRs/` (multi-phase architecture
records with `/adr-phase` prompt files), each entry here is **one** plan → one PR.

Dev-only: like `.ADRs/` and `.claude/skills/`, this directory is **not** shipped
(release archives contain only `src/`).

## Index

This batch records the DNSBL Python **decision-cache** line of work (June 2026):
making the per-domain *decision* the single cached structure, then bounding it.

| # | Plan | PR | Status |
| - | ---- | -- | ------ |
| 01 | [DNSBL block replies: stop caching them](01_DNSBL_Block_No_Cache_Store/README.md) | #64 | Merged |
| 02 | [Unified DNSBL decision cache (Stage 1)](02_Unified_DNSBL_Decision_Cache/README.md) | #67 | Merged |
| 03 | [DNSBL attribution bug fixes (casing + CNAME TLD)](03_DNSBL_Attribution_Bugfixes/README.md) | #68 | Merged |
| 04 | [Unify all query-time caches (Stage 2)](04_Unify_All_Query_Caches/README.md) | #70 | Merged |
| 05 | [Bound decisionDB with an LRU cache](05_DecisionDB_LRU_Cap/README.md) | #72 | Merged |
