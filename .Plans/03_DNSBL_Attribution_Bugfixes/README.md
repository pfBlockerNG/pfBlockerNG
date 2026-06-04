# Plan 03 — DNSBL attribution bug fixes: casing + CNAME TLD (#68)

- **Status:** Implemented — PR #68 merged (`devel` `279bbcc`, 2026-06-04)
- **Component:** `src/usr/local/pkg/pfblockerng/pfb_unbound.py`, `tests/`

## Context / problem

Two **pre-existing** latent bugs surfaced during the #67 review (deferred from there,
verified identical on `b7a371c`, the pre-#67 tip):

1. **Mixed-case attribution miss.** `operate()` stores `decisionDB` keys lowercased
   (`q_name_original = ...lower()`; CNAME targets `convert_other(...).lower()`), but
   `get_details_dnsbl` looked them up with the **raw** query casing (`get_q_name_qstate`
   doesn't lowercase). A mixed-case query was blocked but its block was silently dropped
   from `dnsbl.log` + the per-group counter → per-feed under-count.
2. **CNAME target evaluated against the wrong TLD.** In the validate loop,
   `tld = get_tld(qstate)` is the **original** query's second-level label, but
   `evaluate_domain` uses `tld` for the TLD-Allow and HSTS checks on the name being
   evaluated. A CNAME target with a different TLD was checked against the original's, so a
   target whose TLD is not in the allowlist could slip past TLD-Allow.

## Decision

1. Normalise the lookup key (`q_name.lower()`) in `get_details_dnsbl`; keep the log line's
   original casing.
2. Add `get_tld_from_name()` (the same second-level label, from a name string) and use it
   for CNAME targets; the original-query path is unchanged (still `get_tld(qstate)`).

## Findings

- `get_q_name_qstate` does **not** lowercase; `get_tld` returns
  `qstate.qinfo.qname_list[-2]` (always the original query) — confirmed both real and
  pre-existing.
- Each fix is pinned by a test **proven** to fail without it (production change stashed,
  re-run): `test_mixed_case_query_is_attributed`,
  `test_cname_target_uses_target_tld_not_original`, plus `get_tld_from_name` units.

## Result

PR #68 merged. One commit; clean review.
