# ADR-62 Phase 1 — DNSBL byte-identity corpus

A committed corpus pinning DNSBL feed-parsing output across the
`ADR_62_DNSBL_Unified_Line_Parsing` coverage matrix, byte-identical to `origin/devel` modulo
the ADR's enumerated delta table (D1-D5) — a row whose delta has already landed (e.g.
`mixed_plain`/`permit_feed`'s D2/D4, broadened-capture) carries its NEW outcome instead.

## Layout

- `feeds.json` — one record per synthetic feed: `header`/`group`/`log`/`format`/`provenance`/
  `mode` (the exact shape `pfb_unbound_python_sources()` and `pfb_unbound.py`'s `build()`
  consume) plus a `row` note naming the coverage-matrix row it represents.
- `txt/<header>.txt` — the **documented per-feed `.txt` staging output** for that row: the
  6-col plain dialect (`,domain,,log,feed,group`) or the verbatim ABP/ADR-21-anchor dialect,
  hand-derived from reading `sync_package_pfblockerng()`'s DNSBL parse loop (the download
  loop itself has no off-appliance driver — ADR.md §6 Phase 1 — so this is the loop's
  documented OUTPUT, not independently re-executed; its own raw-feed-to-`.txt` correctness is
  a DEFERRED smoke row, see the Phase-1 handoff coverage matrix).
- `raw/<header>.raw` — the **golden** per-feed `.raw` that `pfb_unbound_python_sources()`
  produces from the matching `txt/<header>.txt`, captured by actually running the real
  function once (not hand-derived) so the PHPUnit oracle (re-running the function) and the
  pytest oracle (reading these bytes straight into `build()`) share one ground truth.

## Regenerating `raw/`

Never hand-edit `raw/*.raw`. Change `txt/*.txt` or `feeds.json`, then regenerate by running
`pfb_unbound_python_sources()` over the corpus (see
`tests/php/Adr62DnsblCorpusManifestTest.php`::`GENERATE.md` note, or simply run the PHPUnit
suite — a byte mismatch fails loudly with a diff) and copy the freshly written
`<rawdir>/pfb_py_raw/*.raw` back over `raw/*.raw`. Commit the diff.

## What the corpus is NOT

- **Not a loop-level oracle.** The DNSBL download loop
  (`sync_package_pfblockerng()`) has no off-appliance driver; this corpus pins the
  **manifest-writer** (`pfb_unbound_python_sources()`) and **Python build** (`build()`/
  `parse()`/`parse_abp()`) surfaces downstream of it, plus the **TLD-analysis** pass
  (`tld_analysis()`, fixtures under `tld/`). The loop's own raw-feed -> `.txt` transform is
  verified live (deferred smoke rows, listed in the Phase-1 handoff).
- **Not shipped.** `tests/` is dev-only; release archives contain `src/` only.

Consumed by `tests/php/Adr62DnsblCorpusManifestTest.php`, `tests/php/Adr62TldAnalysisCorpusTest.php`,
and `tests/test_adr62_byte_identity_corpus.py`.
