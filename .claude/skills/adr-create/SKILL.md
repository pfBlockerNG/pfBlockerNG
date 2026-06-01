---
name: adr-create
description: >
  Interactively design and author a NEW ADR (Architecture Decision Record) for
  this repository, then write it to .ADRs/ADR_NN_Name/ as ADR.md plus ordered
  phase-prompt .txt files ready for /adr-phase. Args: [optional one-line topic].
  Use when the user says "create an ADR", "start a new ADR", "let's design
  ADR-N", or invokes /adr-create. You act as a skeptical design partner, not a
  transcriber.
---

You are helping the user author a **new ADR** in this repository. ADRs here are
not just decision records — each one is a **step-by-step implementation plan
whose phases are picked up by AI agents** (via `/adr-phase`). Your output is a
complete `ADR.md` plus one plain-text prompt file per phase.

Your job during the conversation is to **scrutinise the idea, not stenograph
it.** Push back. Surface hidden coupling and risk. Demand a falsifiable
validation plan. Treat "this idea should be **rejected**" as a legitimate, even
valuable, outcome — ADR-01 was fully implemented (8 phases, correct,
oracle-tested) and then **REJECTED** because benchmarks showed its core premise
("a trie is faster/smaller") did not hold in CPython. Do not let the user walk
into that trap; make them prove the premise *before* committing to phases.

## Step 0 — Ground yourself in the conventions (do this first, every time)

Read these so the new ADR matches the **current** house style (conventions have
evolved across ADRs — always mirror the most recent one rather than this file's
embedded snippets if they diverge):

- `CLAUDE.md` — code standards, branch/release model, commit style, the exact
  test/lint commands, and the "no live Unbound in CI" reality.
- **The most recent ADR as the template of record.** Find the highest-numbered
  `.ADRs/ADR_NN_*/` and read its `ADR.md`, one of its `NN_*.txt` phase prompts,
  and one `RESULTS/NN_Results.txt` handoff. ADRs live on different branches; if
  the latest isn't on the current branch, read it with
  `git show <branch>:<path>` (discover with `git for-each-ref`).
- `.ADRs/ADR_01_Trie/ADR.md` **§8 (Rejection)** — the worked example of an ADR
  killed on evidence. Internalise it.

## Step 1 — Determine the ADR number

ADRs are scattered across branches, so a plain `ls .ADRs/` undercounts. Compute
the next number across **all refs**:

```sh
git for-each-ref --format='%(refname)' \
  | while read r; do git ls-tree -r --name-only "$r" -- .ADRs/ 2>/dev/null; done \
  | grep -oE 'ADR_[0-9]{2,}' | sort -u
```

Next number = `max + 1`, zero-padded to two digits (`NN`). Agree a short
`Snake_Case` name with the user. The ADR directory is
`.ADRs/ADR_{NN}_{Name}/`. Confirm both before writing anything.

## Step 2 — Interactive elicitation (the core; expect many turns)

The user feeds you the idea incrementally ("here's what I have so far"). For
each piece, interrogate it. **Do not advance to writing files until the picture
is coherent, the contract is explicit, and the validation plan is falsifiable.**
Drive these dimensions — ask, don't assume; read the actual code to confirm
claims and cite real symbols + `file:line`:

1. **Context / "Today."** What does the code do now, exactly, and where? Capture
   the *load-bearing* facts (threading/concurrency model, concurrent writers,
   inode/file-lifecycle behaviour, platform limits, existing knobs) — the kind
   ADR-03 §1 enumerates. If the user asserts current behaviour, verify it.
2. **Problem.** What hurts, and how would you *measure* it? If the justification
   is performance or memory, there must be a **baseline** — without it you
   cannot know the change helps (ADR-01's failure mode).
3. **Prior art, tooling & libraries.** Before designing anything, check what
   already solves this. **In-repo:** is there an existing knob/helper/flag you'd
   otherwise reinvent? (ADR-03 found the `log_max_*` line-cap already existed — so
   no new knob was added.) **Out-of-repo:** how do the platform and sibling
   packages handle the same need — e.g. read `../FreeBSD-ports/` for how other
   pfSense packages do internal sqlite queries/connections and file logging.
   Prefer **proven, well-tested tools** (stdlib `logging`, sqlite
   WAL/`busy_timeout`) over bespoke code, and respect the hard constraints
   (stdlib-only inside Unbound's loader; POSIX sh). Settle the tooling/library
   choice here, with its justification.
4. **Decision / approach.** The proposed change. A per-area decision table
   (ADR-03 §2) is the target shape when the change spans components. Note any
   **opportunistic improvements** you might fold in, and decide explicitly whether
   each is in scope or belongs under "Explicitly kept / out of scope."
5. **Scrutiny — your value-add. Be skeptical out loud.** Flag: hidden coupling,
   concurrent access (e.g. PHP writing the same sqlite files), failure &
   recovery scope, platform constraints (stdlib-only inside Unbound's loader; no
   live Unbound in CI; POSIX-sh shell), and **simpler alternatives**. Ask
   whether the premise even holds and how you'd **falsify** it cheaply *before*
   building phases. If it looks unjustified, say so plainly and propose the
   experiment that would settle it.
6. **The contract.** Enumerate the semantics that MUST be preserved, each one
   pinned by a test *before* any swap. These are the things a silent regression
   would break.
7. **Validation strategy.** Concrete and falsifiable: golden/property tests with
   the current implementation as the oracle; a benchmark *with methodology and a
   kill-threshold* if the claim is perf/memory; and a **manual smoke checklist**
   for whatever CI cannot cover (no live Unbound). Define the **Definition of
   Done** and, explicitly, **what evidence would cause the ADR to be REJECTED.**
8. **Preparatory de-risking & simplification (the "pre-ADR" pass).** Before the
   core change, deliberately hunt for **behaviour-preserving** prep that makes the
   implementation **safer, simpler, faster, or leaner** — the more axes at once,
   the better:
   - *Safer:* extract the stable / side-effect-free pieces the ADR will touch (or
     whose callers it will touch) into named functions and pin them with
     **regression tests**, so the later change cannot silently break them. (ADR-01's
     Phases 1–3 did exactly this — and being behaviour-preserving with their own
     tests, they were **retained even after the trie was rejected**: prep has
     standalone value.)
   - *Simpler:* refactors that cut steps, collapse branches, remove corner cases,
     or lower cyclomatic complexity in the area being changed — so the ADR applies
     to a smaller, cleaner surface.
   - *Faster / leaner:* cheap, independent wins in the touched code (drop dead
     code, hoist invariants, remove redundant work).
   Each prep item must be **independently valuable and behaviour-preserving**, and
   becomes one of the **first phases** of the plan.
9. **Phase plan.** Ordered phases. Each is **one commit**, leaves
   `python -m pytest` green, and is behaviour-preserving where possible.
   **Front-load the preparatory phases from (8)** — extract pure functions + lay
   down oracle/regression tests, and do the simplifying refactors — *before* any
   risky swap of data structures or I/O. Each phase becomes one `NN_Name.txt`
   prompt.

Use `AskUserQuestion` only for genuine forks. Periodically reflect the evolving
ADR back to the user in prose so they can correct course.

## Step 3 — Write the ADR document

Create `.ADRs/ADR_{NN}_{Name}/ADR.md` (**markdown**). Mirror the latest ADR's
section set; the canonical skeleton is:

```text
# ADR-NN: <imperative title>

- **Status:** **Proposed** (<today's date>)
- **Date:** <today's date>
- **Branch:** `adr/{NN}` (off <base, e.g. devel>) / **Component(s):** <files>
- **Target runtime:** <e.g. Python 3.11+ in Unbound pythonmod, stdlib only; PHP 8.3>
- **Test suite:** <paths>

## 1. Context        (Today / current state w/ file:line; load-bearing constraints)
## 2. Decision       (per-area decision table; "Semantics that MUST be preserved
                      (the contract — pin with tests before swapping)";
                      "Explicitly kept / out of scope")
## 3. Consequences   (Positive ; Negative / risks)
## 4. Requirements (acceptance)
## 5. Constraints (from CLAUDE.md)
## 6. Action plan    (### Phase N — <title> / Prompt: NN_Name.txt / bullets +
                      that phase's own tests; the EARLY phases are the
                      behaviour-preserving preparatory de-risking/simplification
                      pass, before the core change)
## 7. Definition of done   (incl. the manual smoke checklist — owner: maintainer —
                            and the explicit reject criteria)
```

Status starts **Proposed**. Use today's date. Number every phase in §6 and name
its prompt file.

## Step 4 — Write the phase prompts

For each phase create `.ADRs/ADR_{NN}_{Name}/{NN}_{Name}.txt` (**plain text**),
using the banner template:

```text
================================================================================
PHASE N PROMPT — <title>
Target model: <e.g. Claude Sonnet 4.6>
ADR: .ADRs/ADR_NN_Name/ADR.md   (read <relevant section> first)
================================================================================

ROLE
<which branch; which phase; behaviour-preserving? ; "inline on <branch>, one
 commit, push directly">

WHY THIS PHASE EXISTS
<motivation + the load-bearing facts this phase depends on>

REQUIRED READING
- FIRST, read the prior phase's handoff:
  .ADRs/ADR_NN_Name/RESULTS/<N-1>_Results.txt — <what it must confirm>. If it is
  missing, the previous phase is not complete; STOP and report.   <-- omit for Phase 1
- .ADRs/ADR_NN_Name/ADR.md
- <source files with function names + ~line refs>
- tests/..., CLAUDE.md

ACTION PLAN (ordered — golden/oracle tests FIRST when behaviour-preserving)
1. ...
2. ...

CONSTRAINTS
<language rules; an explicit do-NOT-touch list>

VERIFICATION (must all pass before the phase is done)
- python -m pytest        → green (+ the new tests this phase adds)
- ruff check . / ruff format .   → clean
- php -l / shellcheck     → as relevant to files touched
- diff-read <what to eyeball>

EXPECTED RESULT
<the observable end state>

COMMIT (single)
    <scope>: <imperative summary> (ADR-NN PN)
Push directly to <branch>; open a PR only if the direct push is rejected.

HANDOFF — write `.ADRs/ADR_NN_Name/RESULTS/<NN>_Results.txt` (plain .txt)
<what the next phase needs: state after this phase; decisions/values chosen;
 watch-outs; verification numbers; and the go-ahead>
```

Rules:

- Phase 1 has **no** prior-handoff line; **every later phase** opens REQUIRED
  READING with the "FIRST, read RESULTS/(N-1)_Results.txt … else STOP" gate.
- Each phase ends with the HANDOFF block naming `RESULTS/{NN}_Results.txt`.
- Reflect the CLAUDE.md workflow actually in force (commit style, inline-on-
  branch, push-direct-PR-only-if-rejected).

## Step 5 — Do NOT pre-write handoffs

`RESULTS/NN_Results.txt` files are produced by `/adr-phase` at implementation
time. Do not stub them. Creating an empty `RESULTS/` dir is optional (adr-phase
will create it).

## Step 6 — Report back

Tell the user: the assigned number, the directory, the `ADR.md`, the ordered
list of phase-prompt files, and how to implement it — `/adr-phase {NN} 1` for a
single phase, or `/adr-phase {NN} all` to build the whole ADR end-to-end on a
clean branch off the base (each phase reviewed against its objectives before its
handoff), landing as a PR (default) or a rebase onto the base when complete.
Restate that Status is **Proposed** until they accept the plan, and that
acceptance ultimately depends on the validation evidence / manual smoke defined
in §7.
