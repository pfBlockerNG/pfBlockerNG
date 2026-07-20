# ADR-42: Hash-based feed change detection + conditional GET — replace mtime with content hashing

- **Status:** **Implemented (pending live-VM smoke)** (2026-06-25) — all five phases landed on
  `adr/42-hash-based-change-detection`; off-appliance coverage (PHPUnit + the smoke matrix
  collection) is green. Flips to **Accepted** once the ADR-04 live-VM fan-out (CE + Plus) for the
  feed cases is green (maintainer-dispatched per §7 / CLAUDE.md "ADR acceptance").
- **Date:** 2026-06-25
- **Branch:** `adr/42-hash-based-change-detection` (off **`devel`**; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming"). / **Component(s):** the feed download + change-detection
  path — `src/usr/local/www/pfblockerng/pfblockerng.php` (`pfb_update_check`, the detector) and
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (`pfb_download` + the `curl_defaults`), with the
  shared file-comparison primitives applied in `src/usr/local/pkg/pfblockerng/pfblockerng.sh`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the detector/download; POSIX `sh` for the shell
  primitives; `xxh128sum` (base CLI) for shell hashing. Python 3.11+ inside Unbound's pythonmod is
  **policy-only** here (md5 via `hashlib`); its implementing code lands with its first consumer in
  the follow-up DNSBL-reuse ADR.
- **Test suite:** `tests/php/` (PHPUnit — off-appliance pure helpers of `pfblockerng.inc`),
  `tests/smoke/` (live-VM ADR-04; the mock-feed HTTP server can simulate ETag/`304`), and the
  existing cron-detector cases in `tests/smoke/test_smoke_feeds.py` (#538/#540), which this ADR
  migrates from mtime to hash.

## 1. Context

### 1.1 Today

Feed change detection is **mtime-based**, with a whole-feed-redownload md5 fallback, and there is
**no HTTP conditional GET at all**:

- **Local feeds** (`pfb_update_check`, `pfblockerng.php`): a feed is "changed" iff
  `pfb_file_mtime(source)` ≠ `pfb_file_mtime({pforig}/{header}.orig)` — both reads route through the
  stat-cache-fresh `pfb_file_mtime()` helper (ADR/#537, `pfblockerng.inc:9284`), compared at
  `pfblockerng.php:562`. #540 added an `md5_file(source)` vs `md5_file(.orig)` *confirmation* when
  the mtimes differ (`php:572`), so a touch/cp that bumps mtime without changing bytes no longer
  re-ingests. The `.orig` baseline is a **byte-identical** rename of the downloaded source
  (`pfb_download` writes `.raw` then `@rename(.raw, .orig)` with no transform, `inc:7862`).
- **Remote feeds**: the detector does a **HEAD** (`CURLOPT_NOBODY => TRUE`, `php:480`) to read the
  server's `Last-Modified` (`CURLINFO_FILETIME`, `php:502`; `CURLOPT_FILETIME => TRUE` in
  `curl_defaults`, `inc:183`) and compares it **client-side** to the local `.orig` mtime. When the
  server returns no usable `Last-Modified`, the fallback **re-downloads the entire feed** to
  `{header}.md5.raw` and `md5_file`s it locally (`php:526`–`:531`) — a *post*-download detector.
- **No conditional request is ever sent.** There is no `If-Modified-Since`, no `If-None-Match`, no
  `ETag` anywhere in `src/` (verified). `pfb_download` has a `304 Not Modified` handler
  (`inc:7694`) but nothing arms it, so it is **dead code**.
- **Shell** already uses the lightest file-vs-file primitive where it has one: `cmp -s` at
  `pfblockerng.sh:621` (the aggregate member-list mtime-gate).

### 1.2 The problem

1. **Second-granularity mtime is fragile.** pfSense mtime is whole-second. A content change *within
   the same second* as the last ingest leaves mtime unchanged → the equal-mtime branch trusts
   "unchanged" and **misses it** (the blind spot #540 explicitly left open). The reverse —
   mtime bumped without a content change — is only patched by #540's md5-confirm, i.e. an extra
   read layered on a fundamentally weak signal. Detection should be **content-addressed**, with
   mtime at most a cheap pre-filter, not the source of truth.
2. **md5 is slow and the remote fallback wastes a full download.** `md5_file` runs ~0.6 GB/s; the
   remote md5 path pays the entire transfer just to decide *whether* to ingest. The cheap,
   universal "did it change without downloading it" primitive — the **HTTP conditional GET**
   (`If-None-Match`/`If-Modified-Since` → `304`, empty body) — is unused, despite a dead handler
   already sitting in the code.
3. **No shared, self-describing hash convention.** Persisted digests (today only the transient
   `.md5.raw`) carry no algorithm tag, and md5 is the only algorithm — so there is no clean path to
   a faster hash, and no cross-language story for the future DNSBL/IP work.

### 1.3 Load-bearing facts (verified this session, not assumed)

- **`xxh128` is native in PHP and matches the base CLI byte-for-byte.** `hash('xxh128', $data)` ≡
  `xxh128sum` (only the unrelated `xxh3sum` prepends an `XXH3_` label; `xxh128sum` does not). Both
  are canonical/version-stable (XXH128 frozen since xxHash 0.8.0). `xxh128sum` ships on the pfSense
  box (confirmed present). Throughput: **~11× md5** on arm64 (PHP 6846 vs 633 MB/s) and dominant on
  amd64 via SIMD — clears the "faster on both amd64 and arm64" gate decisively.
- **Python has no native xxhash.** `hashlib` offers md5/sha/blake2, not xxhash; `pfb_unbound.py` is
  stdlib-only and chrooted at `/var/unbound` (a host-absolute symlink to `xxh128sum` resolves
  against the chroot root → broken; running the binary needs it + its libs copied into the jail).
  **blake2b is not worth it** (≈md5 on arm64, build-dependently slower; `hash('blake2b', …)` is not
  even a valid PHP algo — sodium-only). So **Python's side is md5** (`hashlib.md5`), used only for
  its own self-comparisons — no cross-language digest is ever needed.
- **md5 and xxh128 are both 128-bit → both 32 hex chars**, so a persisted digest's algorithm
  **cannot be inferred from its length** — the format must be **self-describing** (a filename
  extension / tag), or a legacy md5 and a new xxh128 are indistinguishable.
- **The `.orig` mirror is byte-identical to the source** for a plain feed (`inc:7862`), so
  `xxh128(source) == xxh128(.orig)` exactly when the source is unchanged — the gate is sound.
- **`cmp -s` is the lightest file-vs-file primitive** (early-exit on first differing byte, zero
  hashing) and is already in-tree (`pfblockerng.sh:621`).
- **pf/Unbound are not real in CI.** The HTTP/`304`/ETag behaviour and end-to-end detection are
  only fully exercised on the ADR-04 live VM (the mock-feed server can emit ETag/`Last-Modified`
  and answer `304`); PHPUnit pins the pure decision/format helpers off-appliance.

### 1.4 Relationship to ADR-40 and the deferred DNSBL-reuse ADR

- **ADR-40 (Content-Addressed Alias Updates)** gates IP **pf-table** reloads on **set membership**
  (radix-tree sets — it deliberately *avoids* file hashing) and keeps the feed-fetch 304/md5 skip
  as a network optimisation. It is a **sibling**, not a parent or child: different data (sets vs
  byte files), different mechanism (membership diff vs content hash). This ADR provides the
  **file-content-hash convention** ADR-40's member-file comparisons *may* adopt, but does not touch
  ADR-40's table gate. Cross-reference, no overlap.
- **Deferred — DNSBL structure-reuse ADR (follow-up).** The motivating payoff ("persist each loaded
  file's hash; on a swap, reuse the in-memory structure for an unchanged file instead of rebuilding
  it") is real — `dnsbl_build_from_manifest` → `build()` rebuilds **all** structures from raw on
  every swap (`pfb_unbound.py:4870`/`:4929`), no per-file reuse. **But** it is premise-gated (the
  rebuild is off the hot path; its cost is unmeasured) and **coupling-heavy** (ADR-07 cross-feed
  `@@`/`$badfilter`, banding, dedup make the structures *not* cleanly per-feed-separable). It needs
  its own baseline + decomposition study and is **out of scope here**; ADR-42 lays the hash
  convention it will build on.

## 2. Decision

Make change detection **content-addressed** via a fast, self-describing hash, and add a real
**conditional GET** so unchanged remote feeds are not re-downloaded. Two algorithms, each native on
its side, each used only for self-comparison (no cross-language digest):

| Area | Decision |
| --- | --- |
| **Hash algorithm** | **`xxh128`** for PHP (`hash('xxh128')`) / shell + CLI (`xxh128sum`); **`md5`** for Python (`hashlib.md5`, policy-only here — code lands with its consumer). Each side compares its own digests; no cross-language comparison exists. |
| **Local-feed gate** | Replace the mtime compare (+ #540 md5-confirm) with **`xxh128(source)` vs the persisted source hash**. mtime is dropped as the gate (kept, if at all, only as a cheap *pre-filter* that a hash always confirms). This closes the same-second blind spot (§1.2.1). |
| **Persisted hash format** | **Self-describing by filename extension**: `{header}.xxhash128` (new), `{header}.md5` (legacy). A **bare/untagged** legacy digest reads as **md5**. Required because md5 and xxh128 are length-indistinguishable (§1.3). |
| **Migration** | **Read legacy md5, write `xxhash128`** (mirrors bzip2→zstd / the ADR-28 read-boundary adapter): on read, an `.md5`/untagged value compares with md5; any newly written content computes `xxh128`, writes `.xxhash128`, and **deletes the superseded `.md5`**. No config/schema migration. |
| **Downgrade tolerance** | An older release meeting an unknown `.xxhash128` it cannot read must **fail safe → treat as changed → re-ingest**, never crash and never falsely "unchanged". |
| **Pre-download check** | **Conditional GET first:** send `If-None-Match` (persisted **ETag**, primary) and `If-Modified-Since` (persisted `Last-Modified`, fallback); a **`304`** skips the body (revives the dead handler, `inc:7694`) and means "unchanged → no re-ingest". Replaces the HEAD-then-client-compare. **download-then-hash** (xxh128 of the fetched bytes vs persisted) is the **last resort** when the server validates with neither. The two layers compose: `304` ⇒ skip download *and* re-ingest; `200` ⇒ download, then hash decides re-ingest. |
| **File comparison primitives (the four scenarios)** | (1) **file-vs-file → `cmp -s`** (shell `cmp -s`; Python `filecmp.cmp(a,b,shallow=False)`; PHP streamed compare or `cmp -s` shell-out) — lighter than hashing both. (2) **memory-vs-file → streamed byte compare, early-return** where the language supports it; else hash both. (3) **hash-vs-file → hash the file.** (4) **memory-vs-hash → hash the memory.** |
| **Shell** | Apply the convention where shell does file detection; keep the existing `cmp -s` (`sh:621`); use `xxh128sum` where a persisted/portable digest is wanted, written with the `.xxhash128` extension. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **Change detection is at least as correct as today.** A genuinely changed local feed is detected
   (incl. the same-second case today's mtime misses — red→green); an unchanged feed is not
   re-ingested.
2. **`.orig`-equals-source soundness.** `xxh128(source) == xxh128(.orig)` exactly when the source is
   byte-unchanged (the `.orig` is a byte-identical mirror).
3. **Legacy md5 still reads.** An install carrying a legacy `.md5`/untagged digest compares
   correctly with md5 on the first post-upgrade pass; the next write emits `.xxhash128` and removes
   the `.md5`.
4. **Round-trip + tag fidelity.** A written `.xxhash128` reads back to the same value and compares
   equal to a re-hash of unchanged content; the extension unambiguously selects the algorithm.
5. **Conditional-GET fidelity.** A `304` ⇒ the feed is treated as unchanged (no re-ingest); a `200`
   ⇒ the fetched bytes are hashed and re-ingested **iff** the hash differs from the persisted one —
   a spurious `200` (server ignored the validator) does **not** force a needless rebuild.
6. **No false skip.** Detection never concludes "unchanged" on changed content via any path
   (conditional GET, hash, or legacy md5); when in doubt it re-ingests (fail-safe).
7. **No new `filter_configure()` / `pkg` / network work** beyond the feed fetch itself; the detector
   stays a read-only decision.
8. **Determinism / idempotence.** Identical content ⇒ identical hash ⇒ no re-ingest; pinned by a
   same-input-twice test.

### Explicitly kept / out of scope

- **DNSBL in-memory structure reuse + manifest split** — the follow-up ADR (§1.4); ADR-42 only
  establishes the hash convention it will use.
- **ADR-40's IP pf-table set-membership gating** — untouched; sibling ADR.
- **Python implementing code** — the convention records Python = md5; the helper code lands with
  its first real consumer (the DNSBL-reuse ADR). No speculative unused Python helper here (YAGNI).
- **The dedup/aggregation/reputation/parse algorithms** — unchanged; this changes *how change is
  detected*, not how feeds are processed.
- **`config.xml` schema** — no migration; the persisted hash is a sidecar file next to `.orig`.

## 3. Consequences

**Positive**

- **Correct detection:** the same-second mtime blind spot is closed; detection is content-addressed,
  not timestamp-guessed.
- **Cheaper:** `xxh128` is ~11× md5; a conditional `304` skips the entire body download for an
  unchanged remote feed (and removes today's wasted HEAD round-trip + the whole-feed md5 redownload).
- **A real convention:** one self-describing, tagged, per-side-native hashing primitive the rest of
  the codebase (ADR-40 member files, the future DNSBL-reuse ADR) can adopt.
- **ETag > Last-Modified:** byte-level validator, immune to mtime granularity and same-mtime
  republishes.

**Negative / risks**

- **Behaviour change on the network path.** A buggy/misconfigured server ETag could in principle
  cause a false `304`. **Mitigation:** ETag is the server's own validator (byte-level); and the hash
  is the final arbiter on any `200`, so the worst a flaky validator causes is an occasional extra
  download (harmless), never a missed change — the fail-safe contract (#5/#6) holds.
- **Migration surface.** The tagged read-md5/write-xxh128 path must be exactly right or an upgrade
  could re-ingest once spuriously (harmless) or, if wrong, miss a change (not acceptable).
  **Mitigation:** round-trip + legacy-read + downgrade tests pinned in Phase 1 before any swap.
- **`xxh128sum` presence assumption (shell side).** Confirmed on the box, but if it is incidental
  (not base) a future image could drop it. **Mitigation:** Phase 4 verifies provenance (`pkg which`)
  and, if it is package-owned, declares the dependency; PHP `hash('xxh128')` needs no binary.
- **Low perf-premise risk (unlike ADR-01).** The speed claim is already measured (§1.3); the
  conditional-GET saving is structural (skip the body). No benchmark kill-gate needed — but the
  live-VM smoke must confirm the `304` path and both detection branches actually fire.

## 4. Requirements (acceptance)

- A local feed changed **within the same second** as the prior ingest is detected and re-ingested
  (red→green vs today's mtime miss); an unchanged feed is not re-ingested.
- A persisted `.xxhash128` round-trips; a legacy `.md5`/untagged digest reads as md5 and the next
  write replaces it with `.xxhash128` (the `.md5` removed).
- A remote feed unchanged since last fetch returns **`304`** (via `If-None-Match`/`If-Modified-Since`)
  and is **not** re-downloaded or re-ingested; a changed feed returns `200`, is hashed, and
  re-ingested.
- No path ever concludes "unchanged" on changed content; ambiguity ⇒ re-ingest.
- `python -m pytest`, `ruff`, `php -l`, PHPUnit, PHPStan, PHPCS, ShellCheck all green; the migrated
  #538/#540 smoke cases assert hash-based (not mtime) detection.
- Live-VM smoke (CE + Plus) green: `304` skip, hash detect (both branches), legacy-md5 read.

## 5. Constraints (from CLAUDE.md)

- **PHP:** tabs, PHP 8.3; uppercase `TRUE`/`FALSE` (PHPCS sniff); no `die()`/`exit()` in library
  code; registered config via `PfbConfig` (ADR-29) if any new field is added (none expected — the
  hash/validators are sidecar files, not config); PFBL-01 `RequirePfbFilter` stays green for any new
  `exec`/path build; pfSense funcs via `stubs/` + `pfsense_doubles.php`.
- **Shell:** POSIX `sh`; quote expansions; absolute `path*` var for `xxh128sum` if it is an add-on
  binary, bare if base (per the shell standard); `LC_ALL=C` inline on any `sort`/set op (ADR-26).
- **Python:** stdlib-only inside the loader — but no Python code lands here (policy-only).
- **Test coverage (five non-negotiables):** behaviour-changing phases pin **fail-before/pass-after**
  tests; the prep phase pins today's behaviour as an **oracle**; every branch (changed/unchanged,
  legacy-md5/new-xxh128, `304`/`200`/no-validator) gets its own assertion; no phase without tests;
  intent-named.
- **No live Unbound/pf/real HTTP servers in CI** → the `304`/ETag + end-to-end detection are
  live-VM (ADR-04, mock-feed server) / maintainer-smoke; PHPUnit pins the pure helpers.
- **ADR text + phase prompts land directly on the branch** (docs carve-out, no PR); every
  `src/`/`tests/` phase uses the full worktree + rebase-only-PR flow.

## 6. Action plan

Front-loaded with behaviour-preserving prep (extract the decision + lay down the hash/format helpers
with oracle tests) before any live swap. Phases 2 and 3 are the two independently-valuable
behaviour changes; Phase 4 generalises the convention to shell + docs; Phase 5 is live-VM proof.

### Phase 1 — Extract + oracle-pin the detector; add the hash + tagged-format helpers (prep, behaviour-preserving)

- **Prompt:** `01_Extract_And_Helpers.txt`
- Extract `pfb_update_check`'s local + remote decision into a named, off-appliance-testable helper
  in `pfblockerng.inc` (loadable via `tests/php/bootstrap.php`). Add: a **hash helper** (`xxh128`
  via `hash_file`/`hash`), and a **tagged read/write helper** — read `{header}.xxhash128` else
  legacy `{header}.md5`/untagged (→ md5), write `.xxhash128` + delete `.md5`. Add a **`cmp -s`**
  file-vs-file helper (or confirm the shell one). **Wire nothing into the live path yet.**
- **Tests (oracle, stay green + new unit):** PHPUnit pins today's decision on fixtures; round-trip
  (`write→read` equal), legacy-md5 read, tag selects algorithm, the PHP↔`xxh128sum` equality pinned
  as a known-answer vector; downgrade (unknown tag → "changed").

### Phase 2 — Content-hash local-feed detection (mtime → hash; behaviour-changing)

- **Prompt:** `02_Local_Hash_Detection.txt`
- Replace the mtime compare + #540 md5-confirm with `xxh128(source)` vs the persisted source hash
  (tagged read/write from Phase 1). Drop mtime as the gate (or keep purely as a confirmed
  pre-filter). Migrate the #538/#540 `tests/smoke/test_smoke_feeds.py` cron cases to hash-based.
- **Tests (red→green):** same-second content change now detected (failed before); content-identical
  re-touch → no re-ingest; legacy `.md5` read then replaced by `.xxhash128`; idempotence no-op.

### Phase 3 — Conditional GET (ETag / If-Modified-Since → 304; behaviour-changing)

- **Prompt:** `03_Conditional_Get.txt`
- Send `If-None-Match` (persisted ETag) + `If-Modified-Since` (persisted `Last-Modified`); persist
  both validators per feed on each `200`; honour `304` (revive `inc:7694`); remove the
  HEAD-then-client-compare. download-then-`xxh128` fallback when no validator is offered; on a `200`
  the body hash still decides re-ingest (contract #5).
- **Tests (red→green + live):** smoke via the mock-feed server — unchanged feed → `304` → no
  re-download/re-ingest; changed → `200` → hashed → re-ingest; no-validator server → download +
  hash decides; a spurious `200` with identical bytes → no re-ingest.

### Phase 4 — Shell convention + documentation (+ Python policy recorded)

- **Prompt:** `04_Shell_And_Docs.txt`
- Apply the convention in `pfblockerng.sh` (keep `cmp -s` at `:621`; use `xxh128sum` + `.xxhash128`
  where a persisted digest is wanted; verify `xxh128sum` provenance and declare the dep if
  package-owned). Document the convention — the four scenarios, per-side algos (`xxh128` PHP/shell,
  `md5` Python), the tagged-extension format + read-md5/write-xxh128 migration, the
  conditional-GET-first rule — in `docs/misc/architecture-notes.md` and the CLAUDE.md feed-update
  mechanics. Record Python = md5 as policy; no Python code (deferred).
- **Tests:** ShellCheck + any shellspec for new shell helpers; `xxh128sum`↔`hash('xxh128')`
  equality re-confirmed in a smoke/known-answer check; markdownlint for docs.

### Phase 5 — Live-VM smoke + DoD

- **Prompt:** `05_Smoke_Docs_DoD.txt`
- Live-VM (CE + Plus) matrix: the `304` skip path, hash detection (changed + same-second + unchanged),
  legacy-md5 read → `.xxhash128` write, the no-validator download+hash path. Confirm no false skip.
  Finalise docs and the DoD.

## 7. Definition of done

- All §4 requirements met; the migrated #538/#540 cron cases + the new `304`/ETag and
  same-second cases green on the live-VM fan-out (CE + Plus).
- The detector is content-addressed (mtime no longer the gate); persisted hashes are tagged
  `.xxhash128` with legacy `.md5` read + replace; conditional GET (ETag/IMS → `304`) is live and the
  HEAD-then-client-compare is gone.
- Round-trip / legacy-read / downgrade-safe / idempotence tests green; PHP↔`xxh128sum` equality
  pinned; no false-skip on any path.
- `xxh128sum` provenance settled (dep declared if package-owned); no new config/schema; no new
  `filter_configure()`/`pkg` on the detector path.
- Docs updated (architecture-notes + CLAUDE.md); the convention recorded for all three languages.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- Against a **real feed host that emits ETag**, confirm an unchanged feed returns `304` and is not
  re-downloaded (observe traffic / logs), and a changed feed returns `200` and re-ingests.
- Confirm an **upgrade** from a build carrying legacy `.md5` sidecars reads them correctly on the
  first pass and replaces them with `.xxhash128` on the next.

**REJECT / re-scope criteria (what would kill or narrow this ADR):**

- If `xxh128sum` proves **absent or unreliable** on a supported pfSense build and cannot be declared
  as a dependency → the shell side falls back to base `/sbin/md5` (PHP keeps `hash('xxh128')`), and
  the "one shell algorithm" goal is narrowed — the rest of the ADR stands.
- If conditional GET cannot be made **fail-safe** in practice (servers whose ETag/Last-Modified lie
  in a way the body-hash arbiter cannot catch) → drop the `304` arm, keep download-then-xxh128; the
  hashing convention (Phases 1–2, 4) still stands alone.
- If the tagged-format migration cannot be shown **downgrade-safe** (an old release crashing on a
  `.xxhash128`) → revert to md5-on-disk with xxh128 used only in-memory; convention narrows, no data
  risk.

## Amendment — 2026-07-20: fail-safe state is not downgrade support (issue #1593)

Tagged hashes, legacy-md5 reads by current code, and changed-on-unknown fail-safe behaviour remain
unchanged. Requirements and reject gates whose sole purpose is proving an older package can consume
new sidecars are superseded. Package downgrade is unsupported.
