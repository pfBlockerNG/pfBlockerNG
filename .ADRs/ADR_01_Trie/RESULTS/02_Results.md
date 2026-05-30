# Phase 2 Results — Split decision from side-effects

## DnsblDecision shape

```python
@dataclass
class DnsblDecision:
    is_found: bool
    in_whitelist: bool
    in_hsts: bool
    null_blocking: bool
    log_type: Any        # False | "1" | log value from data/zone entry
    b_type: str          # "Python" | "DNSBL" | "TLD" | any of the above + "_CNAME"
    p_type: str          # "Python" | "HSTS" | "HSTS_TLD"
    feed: Any            # "Unknown" | feed name string
    group: Any           # "Unknown" | group name string
    b_eval: str          # "" | q_name | matched zone parent
```

## evaluate_domain signature

```python
def evaluate_domain(
    q_name: str,
    q_name_original: str,
    tld: str,
    is_cname: bool,
    cfg: dict[str, Any],
    containers: dict[str, Any],
) -> DnsblDecision
```

### cfg keys threaded from pfb

| key | source |
|-----|--------|
| `python_blocking` | `pfb["python_blocking"]` |
| `dataDB` | `pfb["dataDB"]` (enable bit) |
| `zoneDB` | `pfb["zoneDB"]` (enable bit) |
| `python_tld` | `pfb["python_tld"]` |
| `python_tlds` | `pfb["python_tlds"]` |
| `dnsbl_ipv4` | `pfb["dnsbl_ipv4"]` |
| `dnsbl_ipv6` | `pfb["dnsbl_ipv6"]` |
| `python_idn` | `pfb["python_idn"]` |
| `regexDB` | `pfb["regexDB"]` (enable bit) |
| `whiteDB` | `pfb["whiteDB"]` (enable bit) |
| `python_tld_seg` | `pfb["python_tld_seg"]` |
| `hstsDB` | `pfb["hstsDB"]` (enable bit) |
| `hsts_tlds` | `pfb["hsts_tlds"]` |

### containers keys threaded as module globals

| key | module global |
|-----|---------------|
| `dataDB` | `dataDB` |
| `zoneDB` | `zoneDB` |
| `whiteDB` | `whiteDB` |
| `regexDB` | `regexDB` |
| `feedGroupIndexDB` | `feedGroupIndexDB` |
| `hstsDB` | `hstsDB` |

Notes on evaluate_domain internals:

- **`resolve_feed_group`** was updated (post-Phase-2 correction) to accept
  `feed_group_index_db` as a second parameter rather than reading the module
  global. It is called for both the data and zone hit branches.
  Final signature: `resolve_feed_group(index, feed_group_index_db) -> tuple[Any, Any]`
  (pure; no global reads).

- **`regexDB` matching** is performed inline (`for k, r in regex_db.items()`)
  rather than calling `pfb_regex_match()`, which still reads the module global
  and is therefore not callable from a pure function.

## resolve_feed_group signature (updated in Phase 2)

```python
def resolve_feed_group(index: Any, feed_group_index_db: dict[int, Any]) -> tuple[Any, Any]
```

Pure. Returns `(feed, group)` on hit, `("Unknown", "Unknown")` on miss.
Called by `evaluate_domain` for data and zone hits.

## Pure vs global-reading helpers (for Phase 3 test authoring)

| Helper | Pure? | Notes |
|--------|-------|-------|
| `iter_domain_suffixes` | yes | |
| `find_zone_match` | yes | takes `zone_db` arg |
| `find_noaaaa_wildcard_parent` | yes | takes `noaaaa_db` arg |
| `whitelist_check_domain` | yes | takes `white_db`, `tld_seg` args |
| `hsts_check_domain` | yes | takes `hsts_db`, `hsts_tlds`, `tld` args |
| `resolve_feed_group` | yes | takes `feed_group_index_db` arg |
| `evaluate_domain` | yes | all inputs via `cfg` / `containers` |
| `evaluate_noaaaa` | yes | takes `noaaaa_db` arg |
| `pfb_regex_match` | **no** | reads global `regexDB` |

Phase 3 oracle tests for pure helpers can pass containers directly without
setting up module globals. Tests for `pfb_regex_match` must assign
`pfb_unbound.regexDB` (as the existing tests already do).

## evaluate_noaaaa signature

```python
def evaluate_noaaaa(q_name: str, noaaaa_db: dict[str, Any]) -> bool
```

Returns `True` on exact hit OR wildcard-parent hit; `False` otherwise.

## noAAAA memo write location

Memo write (`noAAAADB[q_name] = True`) stays in `operate()`. After
`evaluate_noaaaa` returns `True`, operate() checks whether an exact entry already
exists (`noAAAADB.get(q_name_original) is None`). If no exact entry exists, the
hit was a wildcard-parent hit and the memo is written — preserving the original
behaviour exactly.

## Verification

- `python -m pytest`: 97/97 passed
- `ruff check .`: clean
- `ruff format . --check`: clean
- operate() side-effect order unchanged; decision now sourced from evaluate_domain /
  evaluate_noaaaa
