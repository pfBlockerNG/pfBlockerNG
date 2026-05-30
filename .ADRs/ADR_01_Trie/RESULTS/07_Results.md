# Phase 7 — Single-walk fusion: Results

## Summary

Added a fused single-descent trie lookup, `trie_lookup_all()`, that splits a
query name into reverse labels **once**, descends the trie **once**, and derives
**every** category result (data, zone, white, noaaaa, hsts) from that single
shared path. It is proven equivalent, per-category, to the five Phase 4 wrappers
(`trie_lookup_exact/_zone/_white/_noaaaa/_hsts`), which are themselves the proven
oracle against the original dict matchers.

`evaluate_domain()` is now wired to consult this fused result for the q_name
data/zone/white/hsts categories, replacing its four separate per-category trie
walks (Phase 6) with one descent. Zero behavior change — golden + equivalence
tests pass **unchanged**.

## Note on the implementation base

The first implementation pass was done on a worktree that branched from a stale
`devel` tip (`8766b5c`), which predated the Phase 6 reader-swap commit
(`52fa92b`). On that stale base `evaluate_domain` still read the dicts, so the
fused walker was delivered as a ready-to-wire primitive and the wiring was
deferred. The branch was subsequently **rebased onto the real `devel`** (which
contains Phase 6: `evaluate_domain`/`evaluate_noaaaa` already read the trie via
the per-category wrappers), the rebase was clean (the fused primitive is purely
additive), and the wiring (step 2) was then completed against the correct base.

## What was implemented

### Fused descent signature

```python
def trie_lookup_all(
    root: TrieNode,
    name: str,
    tld_seg: int,
    hsts_tlds: tuple[str, ...] | list[str],
    tld: str,
) -> TrieLookupResult
```

Pure: trie + name + static config in, result out. No feature gating, no Unbound
symbols, no I/O.

### Result struct shape

```python
@dataclass
class TrieLookupResult:
    data:   dict[str, Any] | None                                   # exact-match payload (== trie_lookup_exact)
    zone:   tuple[str, dict[str, Any]] | tuple[None, None]          # (matched_parent, payload) (== trie_lookup_zone)
    white:  bool                                                    # tld_seg-gated whitelist hit (== trie_lookup_white)
    noaaaa: bool                                                    # exact-or-wildcard-parent (== trie_lookup_noaaaa)
    hsts:   tuple[bool, str]                                        # (hit, p_type), -2 stride (== trie_lookup_hsts)
```

`zone` carries the **matched-parent domain string** so it can feed `b_eval`,
exactly as `find_zone_match()`/`trie_lookup_zone()` require.

### How a single descent reproduces all categories

One loop collects `path_nodes` (index `i` = node at depth `i+1`, depth 1 = TLD).
Each category result is then computed from that one list using the **same
depth-indexing math** as its per-category wrapper:

- data: terminal node reached at full depth -> `.data`.
- zone: deepest path node with `.zone` set; matched-parent rebuilt from
  `reversed(labels[:depth])`.
- white: branch 1 exact (`.white`/`.white_wild`), branch 2 `www.`-strip, branch
  3 `tld_seg`-gated suffix walk on `.white_wild`.
- noaaaa: exact `.noaaaa is not None`, else wildcard-parent `.noaaaa_wild` from
  depth `full_depth-1` down to 2 (stops before TLD).
- hsts: `tld in hsts_tlds` shortcut, else `-2` stride (`ceil(full_depth/2)`
  iterations over `.hsts`).

## Which call sites consult the fused result vs the old per-category wrappers

In `evaluate_domain()`, immediately after extracting the trie from `containers`,
a single call resolves all categories for `q_name`:

```python
trie_hits = trie_lookup_all(domain_trie, q_name, cfg["python_tld_seg"], cfg["hsts_tlds"], tld)
```

The four previously-separate trie walks are now field reads off `trie_hits`,
behind their existing `pfb[...]` gates (unchanged precedence and field-setting):

| Category | Before (Phase 6)                                  | After (Phase 7)        |
| -------- | ------------------------------------------------- | ---------------------- |
| data     | `trie_lookup_exact(domain_trie, q_name)`          | `trie_hits.data`       |
| zone     | `trie_lookup_zone(domain_trie, q_name)`           | `trie_hits.zone`       |
| white    | `trie_lookup_white(domain_trie, q_name, tld_seg)` | `trie_hits.white`      |
| hsts     | `trie_lookup_hsts(domain_trie, q_name, ...)`      | `trie_hits.hsts`       |

The CNAME-original whitelist check is a **different name**, so it still needs its
own walk — the `any([q_name] + ([q_name_original] if is_cname else []))`
semantics are preserved as an OR:

```python
in_whitelist = trie_hits.white
if not in_whitelist and is_cname:
    in_whitelist = trie_lookup_white(domain_trie, q_name_original, cfg["python_tld_seg"])
```

`evaluate_noaaaa()` is unchanged — it lives on a separate (AAAA) path that reads
only the noaaaa category, so its single `trie_lookup_noaaaa` call already is a
single descent; fusing nothing there.

Per-category wrappers (`trie_lookup_*`) are **retained**: the Phase 4 equivalence
tests use them as the oracle, the fused test uses them as the comparison, the
CNAME-original whitelist check and `evaluate_noaaaa` still call them.

## How feature gates are honored

`trie_lookup_all()` always collects every category off the already-resolved path
(a few attribute reads — free). Feature gating remains a **caller** concern:
`evaluate_domain` acts on `trie_hits.data` only inside `if cfg["dataDB"]`, on
`trie_hits.zone` only inside `if cfg["zoneDB"]`, on `trie_hits.white` only inside
`if cfg["whiteDB"]`, on `trie_hits.hsts` only inside `if cfg["hstsDB"]` —
identical gating to the Phase 6 per-category call sites. The walker never
inspects `pfb[...]`, keeping it pure.

## Before/after traversal-count evidence

For a query with N labels and C enabled categories:

- Per-category wrappers: C independent descents -> ~N*C node-steps.
- `trie_lookup_all`: 1 descent -> ~N node-steps (then O(N) cheap re-reads of the
  collected path, no further trie traversal).

Worked example — `a.b.c.example.com` (6 labels), data+zone+white+hsts read:

| Approach              | Descents | Node-steps |
| --------------------- | -------- | ---------- |
| Per-category wrappers | 4        | ~24        |
| `trie_lookup_all`     | 1        | ~6         |

## Test + linter results

Golden + equivalence tests pass **unchanged**; 4 new fused-equivalence tests added.

```
============================= 203 passed in 0.08s ==============================
```
(199 pre-existing, all unchanged + green; 4 new in `TestTrieLookupAllEquivalence`.)

```
ruff check .          -> All checks passed!
ruff format . --check -> 7 files already formatted
```

## Surprises / observations

- The fused walker is purely additive to the trie API, so it rebased cleanly onto
  the Phase 6 reader-swap with no conflicts and the equivalence test passed
  immediately on the integrated tree.
- Because `TestTrieLookupAllEquivalence` already proves `trie_lookup_all` ==
  the five per-category wrappers over a random corpus, and Phase 6 proved the
  wrappers == the dict oracle, wiring `evaluate_domain` to the fused result is
  transitively guaranteed behavior-identical — the Phase 3 golden tests confirmed
  it with no test changes.
- The CNAME-original whitelist name is the one input not covered by the q_name
  fused descent; it is intentionally kept as a second `trie_lookup_white` walk to
  preserve the exact `any(...)` short-circuit semantics.
