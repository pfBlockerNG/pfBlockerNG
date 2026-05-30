# Phase 6 Results — Swap readers to the trie

Runtime DNSBL/noAAAA matching now flows through `domainTrie`. The per-category
dicts (`dataDB`, `zoneDB`, `whiteDB`, `hstsDB`, `noAAAADB`) stay populated
(Phase 5 dual-write) but are no longer read by `operate()`. No observable
behavior change — guaranteed by the Phase 3 golden tests and the Phase 4
equivalence tests, both still green.

All edits in `src/usr/local/pkg/pfblockerng/pfb_unbound.py` and
`tests/test_pfb_unbound.py`.

---

## How `domainTrie` is threaded into the pure functions

`evaluate_domain` / `evaluate_noaaaa` stay pure — the trie is passed in, never
read as a global.

- **`evaluate_domain(q_name, q_name_original, tld, is_cname, cfg, containers)`**
  — signature unchanged. The trie arrives via the existing `containers` arg as a
  new `"domainTrie"` key. `operate()` builds `containers` with just the three
  things `evaluate_domain` still needs from a container:

  ```python
  containers = {
      "domainTrie": domainTrie,
      "regexDB": regexDB,
      "feedGroupIndexDB": feedGroupIndexDB,
  }
  ```

  (`regexDB` stays a linear scan, `feedGroupIndexDB` stays index dedup — neither
  is a domain-suffix structure.) `dataDB`/`zoneDB`/`whiteDB`/`hstsDB` were
  dropped from `containers`.

- **`evaluate_noaaaa(domain_trie, q_name) -> bool`** — signature CHANGED (was
  `(q_name, noaaaa_db)`). Trie is now the first positional arg.

`operate()` reads the module global `domainTrie` (added to its `global`
statement) and passes it down — this is the call site, not a pure function, so
reading the global there is fine.

---

## Swapped call sites (before → after)

### data — `evaluate_domain()` (was line ~1822)
```python
# before
data_entry = data_db.get(q_name)
# after
data_entry = trie_lookup_exact(domain_trie, q_name)
```

### zone — `evaluate_domain()` (was line ~1831)
```python
# before
matched_q, zone_entry = find_zone_match(q_name, zone_db)
# after
matched_q, zone_entry = trie_lookup_zone(domain_trie, q_name)
```
`matched_q` (the matched-parent string) still flows into `b_eval` unchanged —
`test_zone_b_eval_is_parent_not_query` confirms.

### white — `evaluate_domain()` (was line ~1869)
```python
# before
in_whitelist = any(whitelist_check_domain(n, white_db, cfg["python_tld_seg"]) for n in names)
# after
in_whitelist = any(trie_lookup_white(domain_trie, n, cfg["python_tld_seg"]) for n in names)
```
`tld_seg` gate preserved (passed through to `trie_lookup_white`).

### hsts — `evaluate_domain()` (was line ~1873)
```python
# before
in_hsts, p_type = hsts_check_domain(q_name, hsts_db, cfg["hsts_tlds"], tld)
# after
in_hsts, p_type = trie_lookup_hsts(domain_trie, q_name, cfg["hsts_tlds"], tld)
```
Step −2 stride lives inside `trie_lookup_hsts` (Phase 4) — unchanged.

### noaaaa — `evaluate_noaaaa()` (whole body)
```python
# before
def evaluate_noaaaa(q_name, noaaaa_db):
    if noaaaa_db.get(q_name) is not None:
        return True
    return find_noaaaa_wildcard_parent(q_name, noaaaa_db) is not None
# after
def evaluate_noaaaa(domain_trie, q_name):
    return trie_lookup_noaaaa(domain_trie, q_name)
```

The `pfb[...]` enable gates (`pfb['dataDB']`, `pfb['zoneDB']`, `pfb['whiteDB']`,
`pfb['hstsDB']`, `pfb['noAAAADB']`) are untouched — the trie lookup is only
called when the corresponding feature is enabled, same as before.

---

## noAAAA memo decision: option (b) — memo lives in the trie

The Phase 2 behavior was: on any noAAAA hit, if the queried name had no existing
exact entry, write `noAAAADB[q_name] = True` so a later identical query
short-circuits on the exact branch. Since `noAAAADB` is now unread at runtime,
keeping the memo there (option a) would make it dead. Chose **option (b)**: the
memo now writes into the trie.

`operate()` (noAAAA block):
```python
# before
if noAAAADB.get(q_name_original) is None:
    noAAAADB[q_name_original] = True
# after
_memo_node = _trie_walk(domainTrie, trie_split_labels(q_name_original))
if _memo_node is None or _memo_node.noaaaa is None:
    trie_insert_noaaaa(domainTrie, q_name_original, False)
```

Rationale:
- The old guard was `noAAAADB.get(q) is None` (absent only — a stored `False`
  counts as present). The trie equivalent is "terminal node missing OR its
  `.noaaaa is None`" — `_trie_walk` + `node.noaaaa is None`.
- Inserting with `wildcard=False` sets `node.noaaaa = False` (presence) and does
  NOT touch `noaaaa_wild`, so it creates only an exact memo — never a new
  wildcard parent. Identical semantics to the old `= True` exact memo (the
  exact branch is a presence check, so `False` vs `True` payload is
  indistinguishable).

**Confirming test:** `TestOperateNoAAAA::test_wildcard_blocks_subdomain_and_caches`
(updated) — a wildcard-parent hit on `sub.example.com` now:
1. creates an exact trie memo (`trie_lookup_exact` for the name is still `None`
   because the memo is a noAAAA flag, not a `data` payload — asserted),
2. `evaluate_noaaaa(domainTrie, "sub.example.com")` returns `True`,
3. a second identical query still returns `MODULE_FINISHED` (fast path
   unchanged — asserted by running `operate()` twice).

---

## Test updates (outcomes unchanged, assertions not weakened)

- `add_data` / `add_zone` / `add_white` / `add_noaaaa` / `add_hsts` helpers now
  dual-write the trie (mirrors `init_standard`), so `TestOperateDnsbl` /
  `TestOperateNoAAAA` end-to-end tests exercise the trie read path.
- `_make_containers()` projects the `dataDB`/`zoneDB`/`whiteDB`/`hstsDB` dict
  overrides callers still pass into a fresh trie and supplies it as
  `containers["domainTrie"]`. The `TestEvaluateDomainGolden` call sites are
  unchanged; their assertions are identical.
- `TestEvaluateNoaaaa` / `TestEvaluateNoaaaGolden` rebuilt via a `_noaaaa_trie`
  helper and call `evaluate_noaaaa(root, name)`. Same golden outcomes.
- `test_evaluate_noaaaa_vs_brute_force` builds a trie alongside the dict and
  calls `evaluate_noaaaa(root, q)`; the independent `brute_noaaaa` dict oracle is
  retained — still a real cross-check.
- `test_noaaaa_equivalence` and `TestDomainTrieConsistency::test_noaaaa_trie_matches_dict`
  previously used `evaluate_noaaaa` (dict-based) as the oracle; that is now
  trie-backed, so the oracle was inlined as the dict walk
  (`db.get(q) is not None or find_noaaaa_wildcard_parent(q, db) is not None`) to
  keep them meaningful cross-checks rather than tautologies.

Old helpers (`find_zone_match`, `whitelist_check_domain`, `hsts_check_domain`,
`find_noaaaa_wildcard_parent`) and all five dicts remain — safety net + oracle.
Phase 8 deletes them.

---

## Verification

```
python -m pytest
199 passed in 0.16s
```

High-risk cases re-confirmed (`-k "tld_seg or stride2 or whitelist"`): 17 passed.

```
ruff check .
All checks passed!

ruff format . --check
7 files already formatted
```

---

## Surprises / observations

1. **`trie_lookup_exact` vs noAAAA memo.** The memo is a noAAAA flag, not a
   `data` payload, so `trie_lookup_exact` on a memoized name still returns
   `None` — the two categories live on the same node but in different slots.
   The updated cache test asserts exactly this to avoid a misleading assertion.
2. **No new global purity leak.** `evaluate_domain` keeps its exact signature;
   threading the trie through the existing `containers` dict means zero churn at
   the `evaluate_domain` golden call sites — only `_make_containers` changed.
3. **Oracle inversion.** Two tests that used `evaluate_noaaaa` as the dict oracle
   had to switch to an inlined dict walk once `evaluate_noaaaa` became
   trie-backed; otherwise they would have compared the trie to itself.
