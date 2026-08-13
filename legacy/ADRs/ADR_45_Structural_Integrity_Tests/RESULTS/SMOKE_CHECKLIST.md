# ADR-45 Smoke Checklist — Maintainer Fan-out + Accept

## Dispatch command (CE + Plus, full ADR-45 coverage)

Run after this branch is merged to `devel`:

```sh
# Full fan-out — both CE and Plus legs, all ADR-45 cases
gh workflow run smoke.yml \
  -f scope=full \
  -f pytest_filter="test_corrupt_zip_rejected or test_corrupt_gzip_rejected or test_corrupt_bzip2_rejected or test_octet_stream_zip_recovered or test_junk_octet_stream_rejected or test_zip_feed_imports or test_gzip_feed_imports or test_bzip2_feed_imports"
```

This runs both the new ADR-45 cases AND the healthy-archive pairs (ADR-44) so a
single fan-out covers the full paired-branch proof.

Alternatively, run the entire smoke suite (includes the above and all other cases):

```sh
gh workflow run smoke.yml -f scope=full
```

## Pass criteria

All of the following must be green on **both CE and Plus** legs:

| Case | Expected outcome |
| ---- | ---------------- |
| `test_corrupt_zip_rejected` | Alias absent before AND after Force Update |
| `test_corrupt_gzip_rejected` | Alias absent before AND after Force Update |
| `test_corrupt_bzip2_rejected` | Alias absent before AND after Force Update |
| `test_octet_stream_zip_recovered` | Member `203.0.113.11` present after Force Update; rule references alias. On-box guard: if file(1) reports octet-stream → recovery exercised; if not → normal zip branch, still imported. Either way: member present. |
| `test_junk_octet_stream_rejected` | Alias absent before AND after Force Update. Skipped (not failed) if the box's file(1) does not report octet-stream for the junk blob. |
| `test_zip_feed_imports` (existing) | Member present, rule references alias — healthy zip still imports |
| `test_gzip_feed_imports` (existing) | Member present, rule references alias — healthy gzip still imports |
| `test_bzip2_feed_imports` (existing) | Member present, rule references alias — healthy bzip2 still imports |

## Reject criteria (any of these = NOT accepted)

Per ADR-45 §7:

- Any **healthy-archive feed** (`test_zip_feed_imports`, `test_gzip_feed_imports`,
  `test_bzip2_feed_imports`) now **fails** — the structural probe is rejecting valid input.
- `test_octet_stream_zip_recovered` **fails** with member absent — a valid archive that
  file(1) reports as octet-stream is still rejected after the ADR-45 fix.
- `test_junk_octet_stream_rejected` **fails** with alias present — a junk/HTML blob was
  accepted (ADR §7 violation: octet-stream must never be blanket-accepted).
- Any corrupt-archive case (`test_corrupt_*_rejected`) **fails** with alias present —
  the structural probe did not reject a corrupt archive.
- A probe was introduced on a **plain-text** path (text/plain feed rows) — verify the diff
  shows no such addition; the probe only applies to the archive and MIME-gate branches.

## 7z — out-of-CI limitation

`/usr/local/bin/7z` is not present on the smoke image. The 7z branch is only reachable
via the octet-stream recovery path (Phase-3 probe order: zip → gzip → bzip2 → 7z-compressed).
A corrupt-7z test would require 7z on the image; adding it is deferred. Documented in
`04_Results.txt`.

## Status flip instruction

On **green on both CE and Plus legs** (all pass criteria met, no reject criteria hit):

Open `.ADRs/ADR_45_Structural_Integrity_Tests/ADR.md` and change:

```text
Status: Proposed
```

to:

```text
Status: Accepted (YYYY-MM-DD)
```

where `YYYY-MM-DD` is the date of the green fan-out run. Commit directly to `devel`
(ADR-doc-only change, no PR needed per CLAUDE.md worktrees exception).
