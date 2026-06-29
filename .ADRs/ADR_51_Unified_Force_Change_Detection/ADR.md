# ADR-51: Unify the Force modes on sidecar-driven change detection (drop the reuse flag)

- **Status:** **Proposed** (2026-06-29). Builds directly on the contained Force-mode work
  shipped in PR #624 (Update-page `pfb_force_mode` = None/Parse/Download/Both) and on the
  ADR-42 change-detector. Not yet implemented.
- **Date:** 2026-06-29
- **Branch:** `adr/51-unified-force-change-detection` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming"). / **Component(s):** the change-detector and the
  ingest reuse path — `src/usr/local/www/pfblockerng/pfblockerng.php`
  (`pfb_update_check()`, the per-feed detector, ~`:401`), `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
  (the ingest re-download-vs-reuse gate in `sync_package_pfblockerng()`, ~`:13344`/`:13392`; the
  ADR-42 sidecar helpers `pfb_hash_read`/`pfb_hash_write`, ~`:10006`/`:10045`; the force-dispatch
  block, ~`:12177`–`:12204`), and the Update page (`pfblockerng_update.php` — the `Parse` dispatch).
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). No Python (the Python side hashes only its own
  state, ADR-42 policy — untouched here).
- **Test suite:** `tests/php/` (PHPUnit — the detector's pure decision helpers + the sidecar
  lifecycle), `tests/smoke/` and `tests/smoke/ui/` (ADR-04/ADR-14 live-VM — the actual
  reparse-from-cache-on-304, self-heal, and the Update-page Force modes).

> **Prerequisite — gated on ADR-42 (the change-detector) being _implemented_, not merely
> Proposed.** This ADR changes one branch of `pfb_update_check`'s decision contract, so it can
> only be designed against the real detector. ADR-42 is on `devel`; PR #624 (the Force-mode UI +
> on-demand detector invocation) is the immediate base.

## 1. Context

### 1.1 Today (after PR #624)

The Update page exposes a four-mode **Force** control (`pfb_force_mode`), wired by **two different
mechanisms**:

- **None** → `pfb_runnow($scope, FALSE)` — a plain detector-respecting pass.
- **Parse** → `pfb_runnow($scope, TRUE)` — `force=true` ⇒ `$pfb['reuse']='on'`: reparse the cached
  `.orig` files, **no re-download**. This is the legacy "Force Reload" / reuse mechanism.
- **Download** → clear the scoped `.etag`/`.lastmod` validator sidecars, then run the detector
  on-demand. With the validators gone the probe gets `200`; the kept `.xxhash128` baseline makes
  the existing per-feed compare re-ingest **only changed** feeds.
- **Both** → also clear the `.xxhash128`/`.md5` baseline → no baseline → re-ingest **all** feeds.

So Download/Both are expressed purely by **removing sidecars + letting the detector decide**, while
Parse rides a **separate internal flag** (`reuse=on`). The deprecated force verbs
(`updateip`/`updatednsbl`/`update`-force) also map to that same reuse flag.

### 1.2 The problem

The control is conceptually two systems bolted together. "Force" is a special-case flag for one
of the four modes; the other two are sidecar-driven. A reader (and the deprecated-verb adapters)
must hold both models. The goal of this ADR: make **every** Force mode "remove some sidecars, then
run the detector (tick)", so the `force`/`reuse=on` flag disappears from the codebase entirely and
there is **one** change-detection story.

### 1.3 Load-bearing facts (verified, not assumed)

- A feed is re-ingested by `sync_package_pfblockerng()` iff (`pfblockerng.inc:13344`): `reuse=='on'`
  (reparse cached `.orig`, **no download**), OR a `{header}.update`/`.fail` marker exists
  (re-ingest **with** `pfb_download`), OR the parsed `.txt` is missing.
- `{header}.update` markers are written **only** by the detector `pfb_update_check()`
  (`pfblockerng.php:401`), and on the scheduled path that runs **only** inside the hour-gated
  `pfblockerng_sync_cron()`. PR #624 added an on-demand, non-hour-gated invocation (`forcecheck`).
- **The detector's 304 branch returns "Update not required" before it ever reads the hash sidecar**
  (`pfblockerng.php:551`). So removing the `.xxhash128` baseline while the `.etag`/`.lastmod`
  validators are still present is **inert** for an unchanged remote feed: the server answers `304`
  and the detector bails. **This is exactly why Parse cannot be expressed as "remove the hash"
  today** — and why Parse still needs `reuse=on`.
- `reuse=on` is the **only** lever that reparses cached lists **without** a (re)download. There is
  no sidecar state that means "reparse the cached `.orig`, do not re-fetch".
- The hash sidecar is (re)written at **ingest** time inside `pfb_download` (`pfblockerng.inc:8526`),
  not at detect time — a deliberate anti-staleness choice (ADR-42). The reuse-cached path **skips**
  `pfb_download`, so it does **not** currently re-write the hash.
- The downstream apply is already change-gated independently of all this: ADR-40 reloads a pf table
  iff its final set changed; ADR-10 swaps DNSBL iff its data changed. "Reload all regardless" in the
  Force help text therefore means **re-ingest/reparse** all lists; the firewall/Unbound apply stays
  correctly set-change-gated.

### 1.4 Relationship to ADR-42, ADR-43, ADR-40/10

- **ADR-42** owns the detector + the sidecar lifecycle (validators + content hash, conditional GET).
  This ADR changes exactly **one** branch of its decision (the `304` branch) and adds a self-heal
  write on the reuse path. Everything else in ADR-42 is unchanged.
- **ADR-43** owns the trigger API (`{scope, force, trigger}`) and scheduling. The `force` **bool**
  in that request is the thing this ADR removes; `trigger` and `scope` are unaffected.
- **ADR-40/10** own apply. Untouched — they keep gating the actual firewall/DNSBL reload on set/data
  change.

## 2. Decision

**Teach the detector that a missing hash sidecar forces a reparse-from-cache, even on a 304** —
then express every Force mode as sidecar removal and delete the reuse flag.

1. **`pfb_update_check` 304 branch (the one contract change):** on `304`, before returning
   "not required", read the hash sidecar for the feed's `.orig`. If it is **missing** (the
   `pfb_hash_read` "changed" sentinel — no `.xxhash128`/`.md5`), treat the feed as **needing a
   reparse from cache**: set `update_cron` + `touch {header}.update`, and signal the ingest to
   **reuse the cached `.orig`** (no re-download — the `304` already proved the remote is unchanged).
   If the hash sidecar **is** present, behaviour is exactly as today (304 → not required).
2. **Ingest reuse-on-missing-hash + self-heal:** for a feed the detector flagged as
   reparse-from-cache, `sync_package_pfblockerng()` reuses the cached `.orig` (the existing reuse
   code path, but triggered per-feed by the detector's signal rather than the global `reuse` flag),
   and **writes the hash sidecar from the cached `.orig` at ingest** so the next tick sees a present
   hash + 304 → "not required". This self-heal is what stops a missing-hash feed from reparsing on
   every tick.
3. **Force modes become uniform (no flag):**
   - **None** → plain pass.
   - **Parse** → remove the **hash** sidecars (scoped), keep the validators → detector 304 +
     missing-hash → reparse cached, no re-download. (Replaces `reuse=on`.)
   - **Download** → remove the **validator** sidecars (scoped), keep the hash → 200 → reload iff
     changed. (Unchanged from #624.)
   - **Both** → remove validators **and** hash (scoped) → 200 + no baseline → reload all.
     (Unchanged from #624.)
4. **Remove the `reuse`/`force` flag:** drop the `force` bool from the ADR-43 trigger request and
   the `$pfb['reuse']='on'` force-dispatch block; the deprecated force verbs
   (`updateip`/`updatednsbl`/`update`-force) become thin adapters that **remove the scoped hash
   sidecars + dispatch a tick** (Parse semantics — behaviour-preserving for their "reparse cached,
   no re-download" contract). The global **Reuse** setting (`pfb_reuse`, the user-facing "reload
   without downloading" toggle), if it survives as a setting, is re-expressed the same way.

### Semantics that MUST be preserved (pin with tests before changing)

- **Parse** still reparses cached lists with **no re-download** (a 304 is a header-only request;
  no feed body is fetched).
- **Download** still re-fetches all yet reloads **only changed** feeds; **Both** reloads **all**.
- The scheduled **`cron`** path (hour-gated detector, no force) is **byte-identical** — the
  missing-hash branch only fires when a hash sidecar was deliberately removed, which the scheduled
  path never does.
- **Downgrade-safe:** an older release that lacks the new branch simply treats a missing hash as it
  does today (re-ingest with download on the next change) — no novel on-disk state is introduced;
  the only artefact is the _absence_ of a sidecar, which older code already tolerates.
- **Self-heal is mandatory:** the reuse-cached path re-writes the hash, so a forced reparse is a
  one-shot, never a perpetual every-tick reparse.

### Explicitly kept / out of scope

- **ADR-40/10 apply gating** — kept. "Reload all" is re-ingest, not a forced pf/Unbound reload.
- **The detector's 200 branch** — unchanged (body-hash vs persisted-hash compare).
- **The Python-side hashing** (ADR-42 policy: `md5`, self-comparison only) — untouched.
- **`config.xml` schema** — no migration; this is sidecar + code behaviour only.

## 3. Consequences

**Positive**

- One change-detection model: every Force mode is "remove sidecars + tick". No `reuse`/`force`
  flag to thread through the trigger API, the verb adapters, or the ingest.
- The detector becomes the single authority for "does this feed need reparsing", including the
  forced case — fewer code paths, easier to reason about and test.
- Parse, Download, Both differ only in **which sidecars** they remove — a small, inspectable table.

**Negative / risks**

- **A new branch in a flagged surface (the ADR-42 detector).** The `304 + missing-hash → reparse
  cached` rule must be precise and well-tested; a mistake reparses unnecessarily or (worse) skips a
  real change.
- **The reparse-cached mechanism is not eliminated, only relocated.** Something must still tell the
  ingest "reuse the cached `.orig`, do not re-fetch" — this ADR moves that signal from an explicit
  flag to "the detector flagged this feed as missing-hash". The complexity is conserved; the win is
  one consistent expression, not less machinery.
- **Self-heal is load-bearing.** If the reuse-cached path fails to re-write the hash, the feed
  reparses on every tick (a performance regression, not a correctness one). Must be pinned by a test
  that asserts a second tick is a no-op.
- **Live-VM-only for the integration behaviour.** The detector + ingest interaction (304 → reparse
  cached → self-heal) can only be fully proven on a live VM (ADR-04); the pure decision pieces are
  off-appliance unit-tested.

## 4. Requirements (acceptance)

1. With the hash sidecar removed and validators present, a feed reparses from the **cached** `.orig`
   on the next detector run with **no body re-fetch** (304), and writes a fresh hash sidecar.
2. A subsequent tick (hash now present) is a **no-op** for that feed (self-heal proven).
3. Parse / Download / Both produce their #624 user-facing semantics with **no `reuse`/`force` flag**
   anywhere in the code.
4. The scheduled `cron` path is unchanged (regression-pinned).
5. Downgrade-safe (no novel on-disk state).
6. Green CE+Plus live-VM fan-out of the ADR-51 cases.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; uppercase `TRUE`/`FALSE`; config-gateway rules for any registered field touched.
- Change detection is a **flagged surface** — investigate the live state, do not assume; pin the
  preserved semantics as an oracle **before** changing the 304 branch.
- Test-coverage mandate: every behaviour change red→green; branch coverage of the detector's
  decision (304 present-hash vs missing-hash; 200 changed vs unchanged); Tier A + Tier B for the
  `www/` Parse rewire; self-heal pinned.
- Plan-with-higher-model / implement-with-Sonnet for the multi-step `src/` work.

## 6. Action plan (phases — each one behaviour-preserving or with red→green tests)

1. **Prep — pin the detector contract as an oracle.** Off-appliance tests that fix today's
   decision matrix (304 → not required; 200 changed/unchanged) so the change is provably scoped to
   the new missing-hash sub-branch. Behaviour-preserving.
2. **Detector — 304 + missing-hash → reparse-cached signal.** Add the branch + the per-feed
   reuse-cached signal the ingest consumes. Red→green: with validators present + hash absent, the
   detector now flags the feed (was: not required).
3. **Ingest — reuse-cached on the signal + self-heal hash write.** Reparse from `.orig` without a
   re-fetch; write the hash at ingest. Red→green: forced reparse happens once; the next tick is a
   no-op.
4. **Rewire Parse → remove hash sidecars (scoped); delete the `reuse`/`force` flag.** Update the
   trigger request, the force-dispatch block, the deprecated verb adapters, and the Update page's
   Parse dispatch. Tier A + Tier B (`www/`). Pin: Parse reparses cached with no re-download.
5. **Docs + live-VM DoD.** Update `docs/misc/architecture-notes.md` (the change-detection section)
   and the ADR-43 migration notes; run the CE+Plus fan-out.

## 7. Definition of done

- Phases 1–5 landed on `adr/51-…`; off-appliance suites green; the `reuse`/`force` flag gone from
  `src/`.
- Live-VM (ADR-04) proves: forced reparse-from-cache on 304+missing-hash with no body re-fetch;
  self-heal (second tick no-op); Parse/Download/Both end-to-end; the scheduled `cron` path unchanged.
- Flips to **Accepted** on the green CE+Plus live-VM fan-out (no separate manual sign-off — the
  smoke/UI cases are the acceptance, per CLAUDE.md "ADR acceptance").
- **Reject/revisit criteria:** if pinning the detector contract (Phase 1) shows the 304 branch
  cannot be sub-divided without disturbing the scheduled path, or self-heal cannot be made reliable
  (perpetual-reparse risk), keep the #624 contained model (Parse on `reuse=on`) and mark this ADR
  Rejected with the evidence.
