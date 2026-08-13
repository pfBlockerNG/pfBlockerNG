# ADR-40 benchmark — consolidated summary + shortcomings

Canonical summary of the ADR-40 data-plane benchmark work: what was measured, what it
concluded, and — importantly — where the measurement falls short. This is the reference for a
future standardized torture/stress + benchmark suite (see the linked GitHub issue).

## TL;DR

- A pf table update (`-T replace` or chunked `-T add`/`-T delete`) is **bimodal** on the data
  plane: the large majority of in-flight connections are unaffected (~1–3 ms), and a **small
  fraction (~4–5%) are "caught" mid-swap and fail hard (≥5 s)**. That caught fraction is roughly
  **table-size-independent**.
- **Forward delta does NOT reduce the per-connection stall or the caught fraction.** What it
  reduces is the **exposure window** (op wall-time): at ~1% churn the window is ~1.7–1.9× shorter,
  so fewer connections are caught in absolute terms. **Above ~5% churn the relationship inverts** —
  delta is slower and slightly more disruptive than a single `-T replace`.
- Shipped defaults follow the data: **`PFB_DELTA_CHURN_THRESHOLD = 0.05`** (auto-mode falls back to
  replace above ~5% churn) and **`pfb_alias_delta_batch` default `512`**. Real feed updates are
  typically <1% churn/cron, where delta gives its modest window reduction.
- **The disruption-reduction justification for delta is modest, not dramatic.** Delta is justified
  primarily by cheap incremental apply + cross-list correctness (ADR-40 Phase 3), with a *secondary*
  small-churn window-reduction benefit — not by a large stall cut. Earlier "huge reduction" numbers
  were measurement artifacts (see Shortcomings).

## Datasets (all under this RESULTS/ directory)

| File | What it measured | Status |
| ---- | ---------------- | ------ |
| `02_Results.txt` | Delta knee sweep + wall-time; first reject-loop run (ICMP probe) | Kept; wall-time valid, stall numbers window-diluted/censored |
| `02b_Replace_Disruption_Baseline.txt` | Replace-only disruption, ICMP, 0.5 s probe | **Superseded** — right-censored at 0.5 s; one cell starved (n=4) |
| `02c_Disruption_Magnitude_Uncensored.txt` | **Definitive**: TCP-RST reject loop, 5 s timeout, high-concurrency probe, op-aligned windows; replace size-sweep + delta cells | **Authoritative** for disruption magnitude |

Harness: `scripts/bench_pfctl_tables.sh` (on-guest pfctl timing) + `tests/smoke/test_bench_pfctl.py`
(two-VM orchestration, probe, stats), pytest marker `pfctl_bench`, **dispatch-only** (excluded from
the PR gate via `--ignore=tests/smoke`). Bench environment: the Debian/KVM smoke box, running a
pfSense guest and a civm client (3 vCPUs each, 6 GiB pfSense); floating reject ruleset (LAN
`block return` on the bench table, WAN `block return out`), TCP-SYN→RST probe to in-table
(11.0.0.0/8) and out-of-table
(13.0.0.0/8) IPs.

## Headline numbers (from `02c`, uncensored)

`-T replace` service disruption vs table size (op-aligned, 20 reps, pooled):

| table | op wall | p50 | p95 | p99 | caught (≥2 s) |
| ----- | ------- | --- | --- | --- | ------------- |
| 10k | 21 ms | 2.4 ms | 179 ms | 5001 ms | ~1–5% |
| 100k | 98 ms | 1.9 ms | 31 ms | 5001 ms | ~4.9% |
| 462k | 350 ms | 1.1 ms | 67 ms | 5001 ms | ~4.8% |
| 1M | 679 ms | 1.1 ms | 64 ms | 5001 ms | ~4.3% |

Delta vs replace (batch 512): a caught connection stalls the same ~5 s either way; delta only
shortens the exposure window. At 1% churn delta's window is ~1.7–1.9× shorter (e.g. 100k: 52 ms vs
98 ms); at 5% churn delta is ~2.2–2.6× slower and marginally more disruptive → replace wins. This is
exactly the crossover the 5% threshold encodes.

## Shortcomings (read before trusting any of this, and before building the next suite)

These are the reasons the benchmark is *directional*, not definitive — and the requirements list for
a proper torture/stress suite.

1. **Probe only exercises BLOCKED traffic.** The probe hits IPs that are rejected (in-table → LAN
   reject; out-of-table → WAN reject). So the measured "caught/failed" connections are to
   destinations that are blocked anyway — a degraded *block* experience (5 s hang instead of fast
   RST), **not** disruption to *legitimate pass-through traffic*. The question that actually matters
   for an operator — *does a feed update disrupt normal, allowed traffic?* — is **not answered** by
   this benchmark. (This is the gap the planned small-server test targets: civm reaches a real
   server whose IP is sometimes in the block table and sometimes not, measuring both paths.)
2. **The ≥5 s "no-recovery" failure is unexplained.** Caught connections hit the probe ceiling
   (5 s) rather than recovering via TCP SYN retransmit (~1 s). Either real pf behavior (a SYN
   dropped during the atomic swap leaves no state and isn't re-evaluated) or a probe-side artifact
   (400-way concurrency, reject-RST under load). Until understood, the dominant disruption signal is
   not trustworthy in magnitude.
3. **Still right-censored — just at a higher ceiling.** The probe timeout was raised 0.5 s → 5 s,
   but caught connections still pin at ~5 s (max 5002–5011 ms), so the *true* stall duration of a
   failed connection is unknown (≥5 s). A definitive run needs a timeout well above any plausible
   stall, or a probe that records the real completion/failure time.
4. **SYN→RST is not a full connection lifecycle.** The probe measures time-to-RST on a rejected
   SYN. A real connection is SYN/SYN-ACK/ACK + data; the reject short-circuits it. Disruption to an
   *established* or *legitimately-completing* connection (and to long-lived flows) is not measured.
5. **Cross-VM timing fragility.** Op-aligned windows (the CR#12 fix) slice probe samples to the op
   bracket using civm's clock on both ends to avoid pfSense/civm clock skew. Correct, but fragile —
   a future suite should make the alignment robust (or co-locate the timestamp source).
6. **The "spike" metric was degenerate.** The original spike threshold (3× baseline p99) never
   fired because the quiescent baseline itself had a ~500 ms p99 (occasional SYN retransmit), so
   "spikes" = 0 everywhere. Replaced with explicit disruption buckets (>50/100/250/500 ms/1 s/2 s).
   A real spike metric must derive its threshold from the quiescent *typical* latency (p50/p95), not
   the retransmit-polluted tail.
7. **Resolution / contention.** Runs used 3 vCPUs per VM on a 6-core host (no oversubscription) —
   chosen because 6-each (2× oversubscription) injects scheduling jitter into the very latency tail
   being measured. Even so, a latency benchmark on shared virtual hardware has inherent noise; tail
   percentiles need large pooled n (the final run used hundreds–thousands of samples/cell).
8. **Synthetic churn ≠ real churn.** Tables and deltas are generated from contiguous IP ranges
   (baseline 11.0.0.0/8, disjoint adds 13.0.0.0/8). Real feed updates have different size/locality
   distributions; the disruption profile may differ.
9. **CE only for the bench.** The disruption benchmark ran on CE 2.8.1. The ADR-40 *correctness*
   smoke is green on CE + Plus, but the disruption numbers are CE-only.
10. **Wall-time was a red herring.** Early framing optimized for apply wall-time; the metric that
    matters is data-plane disruption. Documented here so the next suite measures disruption first.

## Earlier measurement bugs (fixed; listed so they aren't reintroduced)

- **Window dilution (CR#12):** the "during-op" probe window included idle traffic before/after the
  op → flattened stall stats. Fixed by op-aligned slicing to `[t0, t1]`.
- **No-op delta adds:** the delta `-T add` set was sourced from the already-loaded table, so adds
  were duplicates (no-ops) → under-measured the add path. Fixed by sourcing adds from a disjoint
  range (13.0.0.0/8) vs the baseline (11.0.0.0/8).
- **Probe starvation:** low concurrency + a long timeout captured almost nothing in short op
  windows (one cell got n=4). Fixed by a high-concurrency (~400 in-flight) probe.

## What the planned next test should add

A standardized torture/stress + benchmark suite (tracked in the linked issue) that, at minimum:

- Runs a **small server** civm actually connects to, with the server's IP **sometimes in the block
  table and sometimes not**, so it measures disruption to **legitimate (passed) traffic** as well as
  to blocked traffic — the gap in #1 above.
- Measures the **full connection lifecycle** (connect + request/response), not just SYN→RST.
- Uses a timeout high enough (or a completion-time probe) to **uncensor** the failure tail (#3) and
  to characterize the **≥5 s no-recovery** behavior (#2).
- Derives a **meaningful spike/disruption metric** from quiescent typical latency (#6).
- Is **reproducible and standardized** (fixed topology, vCPU/RAM, churn profiles, rep counts),
  CE + Plus, and dispatch-only so it never gates PRs.

## References

- ADR: `.ADRs/ADR_40_Content_Addressed_Alias_Updates/ADR.md`
- Datasets: `02_Results.txt`, `02b_Replace_Disruption_Baseline.txt`,
  `02c_Disruption_Magnitude_Uncensored.txt` (this directory)
- PRs: #560 (ADR-40 implementation), #583 (review fixes + data-backed defaults 5%/512 + this work)
