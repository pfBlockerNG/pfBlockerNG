---
name: debug
description: >
  Structured hypothesis-ledger debugging (CLAUDE.md "Evidence rules"): reproduce
  first, list competing hypotheses, run the discriminating probe for each, and
  only fix a CONFIRMED cause — never "try a fix and see". Args: <symptom, error
  message, or failing command>. Use when the user says "debug this", "why is X
  failing", "investigate this error", or invokes /debug.
---
You debugging under CLAUDE.md hypothesis-ledger rule: **no fix edit before a CONFIRMED
hypothesis**. Committing to path without discriminating evidence is failure mode this skill
kills — plausible story not diagnosis.

Args: `{{ args }}`

## Step 1 — Reproduce (or gather the artifacts)

Run failing thing yourself. Capture exact output — error line, wrong value, diff between
expected and actual. Not reproducible off-appliance? Collect real artifacts instead (logs,
smoke-diagnostics snapshot, `config.xml` section, pasted user report) and say precisely what
could not reproduce and why. **No reproduction and no artifacts ⇒ stop and ask for them** — no
theorize from symptom description alone.

## Step 2 — The ledger

Keep this table in working notes. Carry into final report:

```text
OBSERVATIONS (pasted output only, no interpretation)
  O1: <command> → <exact output line(s)>
HYPOTHESES (≥2, each with a mechanism)
  H1: <cause> — would explain O1 because <mechanism>; predicts <observable>
  H2: <cause> — …
PROBES (one per live hypothesis — the cheapest command whose output separates them)
  P1 (tests H1 vs H2): <command> → EXPECTED-if-H1: <x> / EXPECTED-if-H2: <y>
  P1 ACTUAL: <pasted output> → verdict: H1 CONFIRMED / REFUTED / …
```

Rules:

- **≥2 hypotheses before first probe.** One hypothesis is conclusion wearing lab coat. Cannot
  form second? Write down why — that reasoning itself checkable.
- **Probes discriminate; they don't confirm.** Probe whose output look same under both
  hypotheses not probe. Prefer reading effective live state (CLAUDE.md "Investigate, don't
  assume": tool's own CLI, included files, chroot-relative path) over re-reading code you
  already believe you understand.
- **Every environmental claim gets probed**, not remembered — default shells, tool exit-code
  semantics, platform behaviour (false-"pipefail" and #902 class).
- All hypotheses refuted? Evidence told you something: write new hypotheses FROM probe
  outputs, continue ledger. Never fall through to "just try changing X".

## Step 3 — Fix only after CONFIRMED

- State confirmed root cause in one sentence, cite probe that proved it.
- Root cause, not symptom (ponytail): grep every caller/sibling of faulty path — #858→#900
  chain was five symptom-fixes of one cause. Enumerate sibling axes before choosing where fix
  goes.
- Fix follows test mandate: pin with test that **fails on broken code** (executed, output
  recorded) and passes after. Land per normal flow (worktree; PR per `.agents/policy/landing.md`
  for code, direct `devel` for dev-only classes) — or hand confirmed diagnosis to delegated
  implementer if user only asked for investigation.

## Step 4 — Report

Final report = verdict (root cause + confirming probe), full ledger, fix (or recommended next
step), any ASSUMED facts still unverified.
