# Phase 3 Results — Oracle/property tests + fixture insulation

## Summary

Phase 3 adds **631 lines** of test-only code to `tests/test_pfb_unbound.py`.
No production code was changed.

---

## Insert helpers

All helpers live at **module level** in `tests/test_pfb_unbound.py` (not in conftest).
Each writes into the matching module-level container AND sets the enabling `pfb[...]` flag.
Phase 4+ can change only the helper bodies when the container type changes.

| Helper | Container written | Flag set |
|--------|-------------------|----------|
| `add_data(domain, log="1", index=0)` | `pfb_unbound.dataDB[domain]` | `pfb["dataDB"] = True` |
| `add_zone(domain, log="1", index=0)` | `pfb_unbound.zoneDB[domain]` | `pfb["zoneDB"] = True` |
| `add_white(domain, wildcard=False)` | `pfb_unbound.whiteDB[domain]` | `pfb["whiteDB"] = True` |
| `add_noaaaa(domain, wildcard=False)` | `pfb_unbound.noAAAADB[domain]` | `pfb["noAAAADB"] = True` |
| `add_hsts(domain)` | `pfb_unbound.hstsDB[domain] = 0` | `pfb["hstsDB"] = True` |
| `set_feed_group(index, feed, group)` | `pfb_unbound.feedGroupIndexDB[index]` | (no flag — index lookup only) |

`TestOperateDnsbl` and `TestOperateNoAAAA` were converted to use these helpers. Behavior unchanged; all pre-existing tests still pass.

---

## New test classes

### `TestIterDomainSuffixes`
Pins the suffix-generator: single label, two labels, three labels, empty string.

### `TestFindZoneMatch`
Pins zone (wildcard-incl-self) semantics:
- Self-match.
- Subdomain match; deep subdomain match.
- No match → `(None, None)`.
- Most-specific entry wins (iter_domain_suffixes walks most-specific first).
- `b_eval` is the matched zone key, not the query name.

### `TestWhitelistCheckDomain`
Pins the three whitelist branches and the `tld_seg` gate:
- Exact match.
- `www.`-strip (only strips for `www.` prefix, not arbitrary subdomains).
- Suffix walk: match at `x >= tld_seg`; no match when `x < tld_seg`.
- High `tld_seg` value blocks intermediate entries below the gate.

### `TestFindNoaaaaWildcardParent`
Pins parent-only wildcard semantics:
- Self is never matched (function starts from `q_name.split(".", 1)[-1]`).
- Direct parent matched; grandparent matched via walk.
- `wildcard=False` value (falsy) is not matched (truthy check).
- Single-label parent not checked (loop range is empty).

### `TestEvaluateNoaaaa`
Pins the composite exact-OR-wildcard-parent logic:
- Exact with `wildcard=False` still matches (presence check, not truthy).
- Wildcard parent matches child only when value is truthy.
- No match returns False.

### `TestHstsCheckDomain`
Pins HSTS matching including the **step-2 stride quirk**:
- TLD in `hsts_tlds` → `("HSTS_TLD", ...)`.
- Exact domain in `hstsDB` → `("HSTS", ...)`.
- Suffix walk hits parent at two-label depth.
- **Stride-2 locks**: for `a.b.c.d`, positions checked are `a.b.c.d` and `b.c.d`; `c.d` is skipped. Test confirms `"c.d"` alone is NOT found, `"b.c.d"` alone IS found.

### `TestResolveFeedGroup`
Pins index → (feed, group) lookup: hit, miss, None index → `("Unknown", "Unknown")`.

### `TestPureMatcherProperties`
Three randomized property tests, all seeded at `random.Random(42)` / `+1` / `+2`:
- `find_zone_match` vs brute-force suffix scan (30 entries, 60 queries).
- `whitelist_check_domain` vs brute-force three-branch check.
- `evaluate_noaaaa` vs brute-force that mirrors `find_noaaaa_wildcard_parent` semantics exactly (truthy check for wildcard branch; limited depth — stops before single-label suffix).

### `TestEvaluateDomainGolden`
Calls `evaluate_domain` directly (pure, no qstate) across 14 scenarios; asserts full `DnsblDecision` field values:

| Test | What it pins |
|------|-------------|
| `test_data_hit` | `b_type="DNSBL"`, `b_eval=q_name`, `null_blocking=False` when `log="1"` |
| `test_data_exact_does_not_match_subdomain` | dataDB = exact only |
| `test_zone_hit_wildcard_incl_self` | self + subdomain both match; `b_type="TLD"` |
| `test_zone_b_eval_is_parent_not_query` | `b_eval` = matched zone key |
| `test_tld_allow` | `feed="TLD_Allow"`, `group="DNSBL_TLD_Allow"` |
| `test_tld_allow_passthrough_when_tld_allowed` | no block when TLD in allowed list |
| `test_idn_block` | `feed="IDN"`, `group="DNSBL_IDN"` |
| `test_regex_block` | `group="DNSBL_Regex"`, `feed=pattern_name` |
| `test_whitelist_override` | `in_whitelist=True`, `null_blocking=True` (no flip) |
| `test_hsts_null_blocking` | `in_hsts=True`, `p_type="HSTS"`, `null_blocking=True` |
| `test_hsts_tld_null_blocking` | `p_type="HSTS_TLD"`, `null_blocking=True` |
| `test_cname_b_type_suffix` | `b_type="DNSBL_CNAME"` when `is_cname=True` |
| `test_not_found_returns_default_decision` | all default field values |
| `test_python_blocking_false_skips_data_zone` | gate respected |
| `test_log_type_2_does_not_change_null_blocking` | only `log="1"` flips `null_blocking` |

### `TestEvaluateNoaaaGolden`
Calls `evaluate_noaaaa` directly across 6 scenarios covering exact, wildcard-parent, no-match, and the self/parent branching distinction.

---

## Linter output

```
ruff check .       → All checks passed.
ruff format . --check → 7 files already formatted.
python -m pytest   → 162 passed in 0.12s
```

Old test count: 97. New test count: 162. All 65 new tests green against the current dict-based implementation.

---

## Key behavioral quirks pinned (contract for Phase 6 trie swap)

1. **dataDB = exact only.** `evil.com` does not match `sub.evil.com`.
2. **zoneDB = wildcard incl. self.** `example.com` matches `example.com` and any subdomain. `b_eval` = matched zone key (not the query).
3. **whiteDB `tld_seg` gate.** Suffix walk only matches when `x >= tld_seg`. Default `tld_seg=2` means `example.com` in whiteDB catches `sub.example.com` but `com` alone does not catch `example.com`.
4. **noAAAADB wildcard-parent = truthy + limited depth.** `wildcard=False` (falsy) does not match children. Walk stops before single-label suffix (no TLD-only matches). Self is handled by exact branch (`is not None`), not the wildcard branch.
5. **HSTS walk stride = −2.** For `a.b.c.d`, positions checked are `a.b.c.d` → `b.c.d` (skips `c.d` and `d`).
