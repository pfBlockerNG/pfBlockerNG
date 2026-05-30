# Phase 4 Results — Domain trie structure and lookup API

## Summary

Phase 4 adds **318 lines** to `src/usr/local/pkg/pfblockerng/pfb_unbound.py` and
**327 lines** to `tests/test_pfb_unbound.py`.  No production runtime paths were
changed; `operate()` and `init_standard()` are untouched.  The dict matchers
remain the oracle.

---

## TrieNode shape

```python
class TrieNode:
    __slots__ = ('children', 'data', 'zone', 'white', 'white_wild',
                 'noaaaa', 'noaaaa_wild', 'hsts')
```

| Slot | Type | Semantics |
|------|------|-----------|
| `children` | `dict[str, TrieNode] \| None` | Lazy; allocated on first insert child. |
| `data` | `dict[str, Any] \| None` | Exact-match payload `{log, index}`. |
| `zone` | `dict[str, Any] \| None` | Wildcard-incl-self zone payload. |
| `white` | `bool` | Entry exists with `wildcard=False` (exact-only whitelist). |
| `white_wild` | `bool` | Entry exists with `wildcard=True` (suffix-wildcard whitelist). |
| `noaaaa` | `bool \| None` | `None` = absent; `False` = exact-only; `True` = wildcard-parent. |
| `noaaaa_wild` | `bool` | True when `wildcard=True`; used by truthy check in parent walk. |
| `hsts` | `bool` | Domain is in HSTS list. |

All slots initialize to `None` or `False` in `__init__`.

---

## Insert API

```python
def trie_split_labels(name: str) -> list[str]
    # 'ads.example.com' -> ['com', 'example', 'ads']

def trie_insert_data(root: TrieNode, domain: str, payload: dict[str, Any]) -> None
    # Exact-match. Sets .data on terminal node.

def trie_insert_zone(root: TrieNode, domain: str, payload: dict[str, Any]) -> None
    # Wildcard-incl-self. Sets .zone on terminal node.

def trie_insert_white(root: TrieNode, domain: str, wildcard: bool) -> None
    # wildcard=True -> .white_wild; wildcard=False -> .white.

def trie_insert_noaaaa(root: TrieNode, domain: str, wildcard: bool) -> None
    # Sets .noaaaa = wildcard (bool); .noaaaa_wild = True when wildcard=True.

def trie_insert_hsts(root: TrieNode, domain: str) -> None
    # Sets .hsts = True on terminal node.
```

Two private helpers support inserts and lookups:

```python
def _trie_walk_or_create(root, labels) -> TrieNode   # creates missing nodes
def _trie_walk(root, labels) -> TrieNode | None       # read-only walk
```

---

## Lookup API

```python
def trie_lookup_exact(root: TrieNode, name: str) -> dict[str, Any] | None

def trie_lookup_zone(root: TrieNode, name: str) -> tuple[str, dict] | tuple[None, None]

def trie_lookup_white(root: TrieNode, name: str, tld_seg: int) -> bool

def trie_lookup_noaaaa(root: TrieNode, name: str) -> bool

def trie_lookup_hsts(
    root: TrieNode,
    name: str,
    hsts_tlds: tuple[str, ...] | list[str],
    tld: str,
) -> tuple[bool, str]
```

---

## Equivalence test class

`TestTrieEquivalence` in `tests/test_pfb_unbound.py` (30 new tests):

- Randomized corpus (seed=100) of 30 entries x 80 queries for each matcher type.
- Five randomized equivalence property tests (one per matcher).
- Hand-pinned edge cases that re-verify Phase 3 oracle contracts via trie.

### tld_seg boundary cases

| Query | Inserted | wildcard | tld_seg | Expected | Trie |
|-------|----------|----------|---------|----------|------|
| `sub.evil.com` | `evil.com` | True | 2 | True (x=2 >= 2) | True |
| `evil.com` | `com` | True | 2 | False (x=1 < 2) | False |
| `a.b.example.com` | `example.com` | True | 3 | False (x=2 < 3) | False |
| `a.b.example.com` | `b.example.com` | True | 3 | True (x=3 >= 3) | True |

All four match dict oracle. `test_white_high_tld_seg_blocks_intermediate` and
`test_white_high_tld_seg_allows_at_gate` pin these explicitly.

### HSTS -2 stride cases

`range(dot_count+1, 0, -2)` controls how many domain positions are checked
(ceil(n/2)), not the step between positions.  Each loop iteration advances the
domain by exactly one label.

For `a.b.c.d` (dot_count=3, full_depth=4):
- `range(4, 0, -2)` -> 2 iterations -> checks `a.b.c.d` then `b.c.d`.
- `c.d` is **never checked**. Confirmed by `test_hsts_stride2_skips_cd`.
- `b.c.d` IS checked. Confirmed by `test_hsts_stride2_hits_second_position`.

Trie implementation: `n_iters = (full_depth+1)//2`; for each `i in range(n_iters)`, checks `path_nodes[full_depth-1-i]` (depths count from TLD=1 upward).

---

## Quirks discovered while mapping dict semantics onto the trie

### 1. White exact branch: presence not value
`whitelist_check_domain` branch 1 uses `white_db.get(name) is not None` — a **presence** check. Both `wildcard=True` and `wildcard=False` entries match. The trie stores these as separate flags (`.white` and `.white_wild`). The exact branch must check `node.white or node.white_wild`.

Initial implementation only checked `node.white` -> missed `wildcard=True` entries at exact depth. Fixed: exact and www-strip branches now check `node.white or node.white_wild`.

### 2. White suffix walk: truthy only
Branch 3 uses `white_db.get(q)` (truthy check). `wildcard=False` -> value=`False` -> falsy -> no match. Only `wildcard=True` entries match. The suffix walk correctly checks only `.white_wild`.

### 3. HSTS stride: loop count vs domain step
The `-2` in `range(dot_count+1, 0, -2)` halves the **iteration count**, not the **domain advancement**. Each iteration still strips one label. Initial (wrong) implementation decremented path index by 2, skipping a depth. Fixed: decrement by 1 per iteration, run `ceil(full_depth/2)` times.

### 4. noAAAA: self handled by exact branch
`find_noaaaa_wildcard_parent` starts from the direct parent (drops leftmost label), so self is never checked by the wildcard branch. The exact branch (`noaaaa_db.get(q_name) is not None`) handles self. Trie reproduces this: exact branch checks `.noaaaa is not None`; parent walk starts from `name.split(".",1)[1]`.

### 5. Zone: deepest match wins
`find_zone_match` returns the first match in `iter_domain_suffixes` (most-specific first). In the reverse-label trie, descending further means MORE specific. The trie keeps a running `best_key/best_payload` and overwrites on each `.zone` hit -> last hit = deepest = most specific. Correct.

---

## Linter and test output

```
python -m pytest   -> 192 passed in 0.14s  (162 pre-existing + 30 new)
ruff check .       -> All checks passed.
ruff format . --check -> 7 files already formatted.
```

---

## Files changed

- `src/usr/local/pkg/pfblockerng/pfb_unbound.py` -- +318 lines (TrieNode class, 5 insert fns, 2 private helpers, 5 lookup fns, delimiter comments)
- `tests/test_pfb_unbound.py` -- +327 lines (TestTrieEquivalence with 30 tests; updated imports)

Commit: `pfb_unbound: add domain trie structure and lookup API (unused, tested vs dicts)`
