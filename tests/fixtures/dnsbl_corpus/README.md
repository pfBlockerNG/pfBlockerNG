# ADR-62 Phase 1 — DNSBL byte-identity corpus

A committed corpus pinning DNSBL feed-parsing output across the
`ADR_62_DNSBL_Unified_Line_Parsing` coverage matrix, byte-identical to `origin/devel` modulo
the ADR's enumerated delta table (D1-D5) — a row whose delta has already landed (e.g.
`mixed_plain`/`permit_feed`'s D2/D4, broadened-capture) carries its NEW outcome instead.

## Layout

- `feeds.json` — one record per synthetic feed: `header`/`group`/`log`/`format`/`provenance`/
  `mode` (the exact shape `pfb_unbound_python_sources()` and `pfb_unbound.py`'s `build()`
  consume) plus a `row` note naming the coverage-matrix row it represents.
- `txt/<header>.txt` — accepted legacy NDJSON object rows from issue #1083: domains use
  `{"kind":"domain","domain":...,"log":...,"feed":...,"group":...}` and ABP/ADR-21 anchors
  use `{"kind":"abp","raw":...}`. Issue #1177 changed current writers to compact tagged arrays,
  but the reader deliberately retains these fixtures as its shipped-object compatibility corpus.
  The loop's per-line body is `pfb_dnsbl_parse_line()`, pinned line by line by
  `go/pfb_core/feedparse/testdata/dnsbl.json`; live smoke rows pin the whole raw-feed-to-`.txt` output.
- `raw/<header>.raw` — the **golden** per-feed `.raw` that `pfb_unbound_python_sources()`
  produces from the matching `txt/<header>.txt`, captured by actually running the real
  function once (not hand-derived) so the PHPUnit oracle (re-running the function) and the
  pytest oracle (reading these bytes straight into `build()`) share one ground truth.

## Regenerating `raw/`

Never hand-edit `raw/*.raw`. Change `txt/*.txt` or `feeds.json`, then regenerate by running
`pfb_unbound_python_sources()` over the corpus (see
`tests/php/Adr62DnsblCorpusManifestTest.php`::`GENERATE.md` note, or simply run the PHPUnit
suite — a byte mismatch fails loudly with a diff) and copy the freshly written
files named by the manifest's `feeds[].raw` rows from
`<rawdir>/pfb_py_raw.<xxh128>/` back over `raw/*.raw`. Commit the diff.

## What the corpus is NOT

- **Not a loop-level oracle.** The raw-feed -> row transform is pinned by
  `go/pfb_core/feedparse/testdata/dnsbl.json` (`pfb_dnsbl_parse_line()`); this corpus pins the
  **manifest-writer** (`pfb_unbound_python_sources()`) and **Go build** (`dnsblBuildFromManifest`
  with `parseEntry`/`parseAbp` in `go/pfb_dns_gateway/decider`) surfaces downstream of
  it, plus the **TLD-Wildcard classification** pass (`tld/tld_master.txt`, read by the Go
  oracle generator -- ADR-65 moved classification out of PHP's `tld_analysis()` entirely).
- **Not shipped.** `tests/` is dev-only; release archives contain `src/` only.

Consumed by `tests/php/Adr62DnsblCorpusManifestTest.php` and by the Go build tests in
`go/pfb_dns_gateway/decider` (`bldStageCorpus`, `TestFixtureManifestV1BuildsAndConfigAffectsResult`).
