# Phase 1 Results — Extract pure domain-match helpers and unify signatures

**Commit:** `c34fee7`
**Branch:** `devel`
**Status:** Complete — 97/97 tests pass, `ruff check .` clean, `ruff format --check .` clean.

---

## Functions added

### `iter_domain_suffixes(name: str) -> Iterator[str]`
Canonical suffix generator. Yields `name`, then `name` with the leftmost label
stripped, down to the last label (the TLD). Example: `sub.example.com` yields
`sub.example.com`, `example.com`, `com`.

### `resolve_feed_group(index: Any) -> tuple[Any, Any]`
Deduplicates the `feedGroupIndexDB` lookup that was duplicated in the `data` and
`zone` branches of `operate()`. Returns `(feed, group)` on hit, or
`('Unknown', 'Unknown')` on miss — matching the pre-existing default behaviour.
Reads `feedGroupIndexDB` as a module-level global (consistent with other helpers).

### `hsts_check_domain(name: str, hsts_db: dict[str, Any], hsts_tlds: tuple[str, ...] | list[str], tld: str) -> tuple[bool, str]`
Extracts the inline HSTS suffix walk from `operate()`. Returns `(True, 'HSTS_TLD')`
when `tld in hsts_tlds`, `(True, 'HSTS')` on a suffix-membership hit, or
`(False, 'Python')` when no match. The step-−2 stride
(`range(q.count('.') + 1, 0, -2)`) is preserved exactly.

---

## Refactored functions

### `find_zone_match(q_name, zone_db)`
Now uses `iter_domain_suffixes` internally. Semantics unchanged.

### `find_noaaaa_wildcard_parent` / `whitelist_check_domain`
Loops left as-is — their start offsets and gates do not map cleanly onto the
generator (parent-only start, tld_seg gate, stride-1 vs stride-2).

---

## Call sites updated in `operate()`

| Before | After |
|---|---|
| Inline `feedGroupIndexDB.get(isDomainInData['index'])` + 3-line conditional | `feed, group = resolve_feed_group(isDomainInData['index'])` |
| Inline `feedGroupIndexDB.get(zone_entry['index'])` + 3-line conditional | `feed, group = resolve_feed_group(zone_entry['index'])` |
| 21-line inline HSTS block (`if pfb['hstsDB']:` … loop) | `isInHsts, p_type = hsts_check_domain(q_name, hstsDB, pfb['hsts_tlds'], tld)` |

`feedGroupIndexDB` removed from `operate()`'s `global` declaration (now accessed
only through `resolve_feed_group`).

---

## Signature convention (for Phase 2)

All domain matchers use `(name, container, *opts)` — **name first**:

| Function | Signature |
|---|---|
| `find_zone_match` | `(q_name, zone_db)` |
| `find_noaaaa_wildcard_parent` | `(q_name, noaaaa_db)` |
| `whitelist_check_domain` | `(name, white_db, tld_seg)` |
| `hsts_check_domain` | `(name, hsts_db, hsts_tlds, tld)` |

No call-site signature changes were required — the existing helpers were already
name-first. New helpers follow the same convention.

---

## Additional cleanup (pre-existing)

`ruff format .` was applied to all files in the repo (pre-existing quote/style
drift across 6 files). 11 pre-existing E501 violations in `pfb_unbound.py` were
fixed to make `ruff check .` pass cleanly.
