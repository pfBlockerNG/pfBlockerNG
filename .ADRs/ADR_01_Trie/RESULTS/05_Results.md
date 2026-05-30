# Phase 5 Results — Dual-populate domainTrie at load time

## domainTrie declaration and initialization

**Module-level annotation** (PEP 526, type-checker only — no runtime object created):

```python
# pfb_unbound.py, after excludeSS: list[str] and maxmindReader: Any
domainTrie: TrieNode
```

**global statement** in `init_standard()`:

```python
global \
    ...
    pfb_task_queue, \
    pfb_worker_thread, \
    domainTrie
```

**Container init block** (same scope as `dataDB = defaultdict(...)` etc.):

```python
# Trie rebuilt from scratch on each (re)load; populated in parallel with
# the dicts below. Readers remain on the dicts until Phase 6.
domainTrie = TrieNode()
```

Placing the init here guarantees a clean rebuild on every `init_standard()` call (i.e. on pfBlockerNG reload), consistent with all other containers.

**conftest.py** also resets `domainTrie` between tests:

```python
pfb_unbound.domainTrie = pfb_unbound.TrieNode()
```

---

## Loaders that now dual-write

All inserts live inside the same `try` block as their corresponding dict writes, so a malformed feed cannot half-populate one structure without the other.

### Zone CSV loader (`pfb_py_zone.txt`)

```python
zoneDB[row[1]] = {"log": row[3], "index": final_index}
trie_insert_zone(domainTrie, row[1], {"log": row[3], "index": final_index})
```

Payload shape matches dict exactly. Both writes are inside the `if row and len(row) == 6:` guard.

### Data CSV loader (`pfb_py_data.txt`)

```python
dataDB[row[1]] = {"log": row[3], "index": final_index}
trie_insert_data(domainTrie, row[1], {"log": row[3], "index": final_index})
```

Same guard (`len(row) == 6`). `feedGroupIndexDB` is unchanged; trie stores the same `index` integer.

### Whitelist CSV loader (`pfb_py_whitelist.txt`)

```python
whiteDB[row[0]] = wildcard
trie_insert_white(domainTrie, row[0], wildcard)
```

Inside `if row and len(row) == 2:` guard.

### HSTS loader (`pfb_py_hsts.txt`)

Before this phase the HSTS loader used the loop variable `line` directly, which included the trailing `\r\n` in the strip but assigned the stripped value to `hstsDB` implicitly. Phase 5 extracts the stripped value into a local `domain` variable so both structures receive the same string:

```python
for line in hsts:
    domain = line.rstrip("\r\n")
    hstsDB[domain] = 0
    trie_insert_hsts(domainTrie, domain)
```

This is a no-behavior-change refactor: the dict key was already the stripped value.

### noAAAA ini loader (`[noAAAA]` section in `pfb_unbound.ini`)

```python
noAAAADB[data[0]] = wildcard
trie_insert_noaaaa(domainTrie, data[0], wildcard)
```

Inside the `if data and len(data) == 2:` guard. Wildcard flag is set identically.

---

## Consistency test added

`TestDomainTrieConsistency` in `tests/test_pfb_unbound.py` — 7 test methods.

**What it covers:**

| Test | Assertion |
|------|-----------|
| `test_data_trie_matches_dict` | `trie_lookup_exact` == `dataDB.get` for all loaded data keys |
| `test_data_trie_no_false_positives` | non-inserted domains return `None` from both |
| `test_zone_trie_matches_dict` | `trie_lookup_zone` == `find_zone_match` for all zone keys + their subdomains (key and payload) |
| `test_zone_trie_no_false_positives` | unblocked domains return `(None, None)` from both |
| `test_white_trie_matches_dict` | `trie_lookup_white` == `whitelist_check_domain` for all whitelist keys + edge cases (www-strip, suffix walk, non-whitelisted) |
| `test_hsts_trie_matches_dict` | `trie_lookup_hsts` == `hsts_check_domain` for all hsts keys + subdomains + HSTS TLD + non-match |
| `test_noaaaa_trie_matches_dict` | `trie_lookup_noaaaa` == `evaluate_noaaaa` for all noAAAA keys + exact/wildcard subdomains + non-match |

The `_load()` helper populates both dicts and `pfb_unbound.domainTrie` in tandem using the same insert pattern as `init_standard()`.

---

## Verification

```
python -m pytest
199 passed in 0.16s
```

(192 existing + 7 new consistency tests)

```
ruff check .
All checks passed!

ruff format . --check
7 files already formatted
```

---

## Surprises / observations

1. **HSTS loop variable refactor**: The existing HSTS loader wrote `hstsDB[line.rstrip("\r\n")] = 0` inline without a named variable. Introduced `domain = line.rstrip("\r\n")` to avoid calling `rstrip` twice and to pass the identical string to both structures. Semantics unchanged.

2. **`domainTrie` forward reference at module level**: The annotation `domainTrie: TrieNode` appears before `class TrieNode:` in the file. This works because `from __future__ import annotations` is at the top of the file, making all annotations strings evaluated lazily. No runtime error.

3. **conftest reset**: `domainTrie` must be reset to a fresh `TrieNode()` in `reset_pfb_globals` so each test starts with an empty trie, matching the empty-dict state of all other containers. Without this, test isolation would be broken for tests that call `_load()` or manipulate the trie directly.

4. **operate() unchanged**: All read paths still use the dicts (`dataDB`, `zoneDB`, etc.). The trie is populated but its lookup functions are not called from `operate()` or any other runtime path in this phase.
