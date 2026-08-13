# Legacy ADR flow — acceptance and amendments

Scope: existing `legacy/ADRs/` corpus only. New implementation-plan ADRs stopped (wayfinder map #1383); this file govern historical records that remain. Load when: touching Accepted/Implemented ADR text or flipping legacy ADR status.

## ADR acceptance — automated tests, not a manual sign-off

ADR flips to **Accepted** on **green automated coverage alone** — if smoke/UI tests truly prove behaviour (every branch, before-and-after, no coverage theater) on live-VM **CE + Plus fan-out**. §7 item that **cannot** run in CI (HA/CARP sync, real HAProxy reload, load profiles, smallest-box RAM, true *visual* correctness) is **documented out-of-CI limitation**, not acceptance blocker. Supersedes older per-ADR "manual smoke required" gate.

## ADR amendments after merge

Accepted/Implemented ADR still spec future readers plan against — stale text seed repeat defects (#1008 scrub removal overturned ADR-60 §2.1/§2.4; un-amended ADR text then seeded #1047).

- **When post-merge fix overturns piece of Accepted/Implemented ADR** — review finding, issue fix, anything invalidating decision, contract, or stated fact — ADR gains (or extends) dated **"Post-merge amendments" / "Post-acceptance addendum" section in same change** as fix. Correction never live only in issue/PR.
- Accepted ADR body stay byte-identical as historical record. Same immutability apply to that ADR's phase documents and Results artifacts: later work append dated correction/addendum, never edit existing content. Direct edits allowed only while authoring, implementing, or testing ADR before acceptance.
- Dated amendment/addendum is authoritative correction: one item per overturned piece, each naming issue/commit that overturned it and corrected decision.
- Exemplars: `legacy/ADRs/ADR_60_Age_Based_Log_Retention/ADR.md` §8 and `legacy/ADRs/ADR_61_Sync_Status_Ledger/ADR.md` §8.
- ADR text is dev-only no-PR class, so amendment commits directly to `devel` alongside (or right after) fix landing.
