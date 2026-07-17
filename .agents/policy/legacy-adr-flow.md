# Legacy ADR flow — acceptance and amendments

Scope: the existing `.ADRs/` corpus only. New implementation-plan ADRs stopped (wayfinder
map #1383); this file governs the historical records that remain. Load when: touching an
Accepted/Implemented ADR's text or flipping a legacy ADR's status.

## ADR acceptance — automated tests, not a manual sign-off

An ADR flips to **Accepted** on **green automated coverage alone** — provided its smoke/UI
tests genuinely prove the behaviour (every branch, before-and-after, no coverage theater) on
the live-VM **CE + Plus fan-out**. A §7 item that **cannot** run in CI (HA/CARP sync, a real
HAProxy reload, load profiles, smallest-box RAM, true *visual* correctness) is a **documented
out-of-CI limitation**, not an acceptance blocker. Supersedes any older per-ADR "manual smoke
required" gate.

## ADR amendments after merge

An Accepted/Implemented ADR is still the spec its future readers plan against — stale text
seeds repeat defects (the #1008 scrub removal overturned ADR-60 §2.1/§2.4; the un-amended
ADR text then seeded #1047).

- **When a post-merge fix overturns a piece of an Accepted/Implemented ADR** — a review
  finding, an issue fix, anything that invalidates a decision, contract, or stated fact —
  the ADR gains (or extends) a dated **"Post-merge amendments" / "Post-acceptance
  addendum" section in the same change** as the fix. The correction never lives only in
  the issue/PR.
- The accepted ADR body stays byte-identical as the historical record. The same
  immutability applies to that ADR's phase documents and Results artifacts: later work
  appends a dated correction/addendum and never edits their existing content. Direct
  edits are allowed only while authoring, implementing, or testing the ADR before
  acceptance.
- The dated amendment/addendum is the authoritative correction: one item per overturned
  piece, each naming the issue/commit that overturned it and the corrected decision.
- Exemplars: `.ADRs/ADR_60_Age_Based_Log_Retention/ADR.md` §8 and
  `.ADRs/ADR_61_Sync_Status_Ledger/ADR.md` §8.
- ADR text is the dev-only no-PR class, so the amendment commits directly to `devel`
  alongside (or immediately after) the fix landing.
