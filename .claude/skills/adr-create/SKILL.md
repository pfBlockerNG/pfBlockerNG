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

- **Sync FIRST — `git fetch origin` before anything else, every invocation**: ground on the
  current `origin/devel` and the latest ADRs across refs, never a stale local branch or an
  earlier in-session snapshot (CLAUDE.md "Rebase onto the latest base"). The
  `adr/{NN}-{slug}` branch that `/adr-phase` later cuts inherits this base.
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

**Set up the worktree now, before Step 3 writes any file** — CLAUDE.md "Worktrees" has no
carve-out for ADR *authoring*: dev-only (no PR — commits/push straight to `devel`) but
still **never the primary checkout**. `{slug}` = the sanitised `{Name}` per CLAUDE.md
"Branch naming"; reuse per CLAUDE.md "Worktrees" (`git worktree list` first — only your own
from this run; foreign ⇒ fresh `-{epoch}`), else
`git worktree add <abs path> -b adr/{NN}-{slug} origin/devel` (fetch first). `/adr-phase`
later reuses this branch for the phase work — creating it now is reuse, not a collision. Do
all Step 3/4 file-writing inside `<path>`.

## Step 2 — Interactive elicitation (the core; expect many turns)

The user feeds you the idea incrementally ("here's what I have so far"). For
each piece, interrogate it. **Do not advance to writing files until the picture
is coherent, the contract is explicit, and the validation plan is falsifiable.**

**Big ADRs (spanning more than ~2 components): fan the investigation out.** When the
Workflow tool is available, run `Workflow({name: 'adr-investigate', args: {topic: '<one-line
ADR topic>', repoRoot: '<worktree/checkout path>', areas: [{key, focus, hints}...]}})` — one
read-only reader per area (pass no extra parameter — `run_in_background` is not a Workflow
parameter and fails validation; it is harness-tracked, so end the turn and answer its
completion notification rather than polling it), returning **evidence-tagged** facts (`verified` with the command/
`file:line` that proved it; `assumed` with the probe that would). Use only `verified` facts as
§1 load-bearing facts; every `assumed` fact is either probed by you now or carried into the
plan as an explicit verification step. The design judgment — scrutiny, contract, phases —
stays yours; the fan-out only grounds it.
Drive these dimensions — ask, don't assume; read the actual code to confirm
claims and cite real symbols + `file:line`:

1. **Context / "Today."** What does the code do now, exactly, and where? Capture
   the *load-bearing* facts (threading/concurrency model, concurrent writers,
   inode/file-lifecycle behaviour, platform limits, existing knobs) — the kind
   ADR-03 §1 enumerates. If the user asserts current behaviour, verify it.
   **Every load-bearing fact carries its evidence** — the command + output, the
   `file:line`, or the doc fetched this session — or is explicitly tagged
   **ASSUMED** with a verification step in the phase that first relies on it
   (CLAUDE.md "Evidence rules"). This applies doubly to **external formats and
   third-party behaviour** (feed layouts, column indexes, API/token semantics,
   CI-platform behaviour): fetch the live artifact or official doc **before** the
   value enters a decision table — ADR-59 shipped wrong `domain_col` values for
   feeds nobody had fetched, and only implementer initiative caught them.
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
6. **The contract.** Enumerate the semantics that MUST be preserved as a
   **numbered** "Semantics that MUST be preserved" list in §2, each one pinned by
   a test *before* any swap — phase prompts cite the item **numbers** their tests
   pin, turning acceptance into a per-phase checklist the orchestrator ticks.
   These are the things a silent regression would break.
   **Plus the coverage matrix:** every sibling axis the change touches (v4/v6,
   address/port, CE/Plus versions, parse modes, providers, all callers of touched
   symbols) enumerated **from the source** (grep output, the version-matrix file),
   each row mapped to a phase/test or an explicit out-of-scope entry — "all X"
   without the list is not a spec (CLAUDE.md "THE BRIEF" §3).
7. **Validation strategy.** Concrete and falsifiable, and bound by CLAUDE.md **Test
   coverage** — the five non-negotiables. Encode them into the plan: every
   **behaviour-changing** phase pins a test that **fails before / passes after** the change;
   every **behaviour-preserving** phase pins the current behaviour as an **oracle** that stays
   green; **no phase without tests**; intent-named, never coverage theater. Front-end (`www/`)
   phases include **Tier A** UI coverage (Tier B only when the change is observable *only*
   there). Use golden/property tests with the current implementation as the oracle; a benchmark
   *with methodology and a kill-threshold* if the claim is perf/memory; and a **manual smoke
   checklist** for whatever CI cannot cover (no live Unbound). Define the **Definition of Done**
   and, explicitly, **what evidence would cause the ADR to be REJECTED.**
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
   prompt. **Per-phase safety rails (each was a cause of ADR-62's
   pre-implementation re-split — build them in from the start):**
   - **Phase size budget (owner feedback 2026-07-14 — ADR-65's phases ran
     60–90 min of implementer time each; that is under-splitting).** A phase
     is ONE mechanism in ONE place. Mechanical caps — exceeding ANY of them
     means split BEFORE writing the prompt: more than 2 production files
     edited; more than 1 production language (a Python change and its PHP
     notice surface are TWO phases); more than 5 ACTION-PLAN items; a
     coverage matrix over ~10 rows; an expected diff over ~300 changed
     lines. Target: an implementer sitting of ~15–30 minutes. Splitting is
     cheap at authoring time and unpayable mid-implementation — when in
     doubt, split (smaller phases also make `WEIGHT: light` applicable more
     often).
   - **Delta budget.** Number the accepted behaviour deltas in §2 (D1, D2, …);
     every behaviour-changing phase declares the exact subset it may flip, and
     the oracle stays byte-identical outside it. A phase whose budget spans
     deltas carried by **independent mechanisms** (e.g. a broadened capture vs
     a deletable classifier) is TWO phases — one mechanism per phase; ADR-62's
     original Phase 4 bundled five interacting concerns and had to be re-split.
   - **Pinned test surfaces.** For every golden/oracle/capture target the
     PLANNER names the driving harness + entry symbol (which pytest path, which
     PHPUnit test drives which function — mirror an existing sibling test),
     enumerated from source — never "implementer picks a way to test it". A
     target with **no off-appliance driver** becomes an explicit DEFERRED smoke
     row carrying its exact live-VM dispatch command; never instruct
     re-implementing production logic as its own oracle (an oracle of a copy is
     coverage theater).
   - **Blast radius.** Every phase states what production behaviour can change
     when it lands alone ("NONE" / "PRODUCTION-DORMANT until Phase N" must be
     stated, never implied) — checker-enforced from ADR-62 on.
   - **Latent bug found while planning.** File the tracking issue immediately;
     its fix lands as its **own red→green commit** at the start of the earliest
     phase that depends on it (the ADR-62 / issue #1060 pattern).

**Design-completeness checks (the ADR-60/61 post-merge classes — issues
1047–1057).** Before writing files, answer each of these **with evidence
written into the ADR** — an enumeration, a grep output, a stated decision —
never a platitude; where one is genuinely not applicable, say so explicitly:

- **Transformer × hostile-input completeness.** Enumerate EVERY new/changed
  parser, regex, scrub, or formatter the ADR introduces (grep your own decision
  table for them) and give EACH its hostile-input row set. Rows for only some
  transformers is an incomplete spec (ADR-60 covered its age-cutoff parser but
  not its NOW scrub, which shipped content-corrupting — #1047).
- **Data-shape axis.** A contract pinned over call sites ("all X get Y") gets a
  shape axis enumerated FROM GREP of the actual call sites, never from the
  contract's mental model (ADR-60's "fixed line-start prefix" assumed every
  write is a line; 23 sub-line fragment sites existed — #1054).
- **Key granularity.** A new keyed store (ledger, cache, map) states its key's
  granularity explicitly AND compares it against the granularity of the events
  that write it; a key coarser than the event needs an explicit aggregation
  decision (ADR-61's `item` spanned three granularities and the ambiguity
  guaranteed a masking bug — #1048).
- **The third transition.** Any lifecycle the ADR introduces (open/close,
  set/clear, start/stop) enumerates what happens when the owning code path is
  SKIPPED — path not taken, feature off, input absent — not just when it
  succeeds or fails (ADR-61's symmetric open/close stranded state on skipped
  paths — #1049).
- **Scenario propagation.** A scenario named anywhere in the ADR is checked
  against EVERY row of the consumer axis, not just the component it was written
  for (ADR-60's mixed legacy+ISO upgrade scenario reached the trim but never
  the format's consumers — #1057).
- **Cost claims per matrix row.** A performance/cost claim is checked against
  every row of the coverage matrix; a claim that only holds for some rows is
  stated per-row (ADR-60's "cheap — one extra pass" was false for its own
  nolimit row — #1052).
- **Cross-ADR interaction.** Which other Proposed/in-flight ADRs touch the same
  files or resources? Grep `.ADRs/` for status + component overlap and add an
  interaction row for each hit (ADR-61's whole-log read met ADR-60's unbounded
  nolimit logs the same day; each locally coherent, nobody owned the product —
  #1052).
- **Security surface.** Any phase touching a `www/` page or endpoint states
  that page's auth/CSRF posture in the ADR (one line), so a weakened surface is
  a decision, not an accident (ADR-61 rewrote a mutating POST handler on a
  `$nocsrf` page without flagging it — #1050).

**Interaction contract (owner feedback 2026-07-14 — the observed failure mode:
ask one question, read the short answer as blanket approval, then produce pages
of enthusiastic prose that drift off the ADR's objective):**

- Ask at EVERY genuine fork, as it arises — scope boundary, mechanism choice,
  accepted-delta wording, phase granularity, naming. One `AskUserQuestion` per
  fork; never silently resolve a fork you could ask about, and never fold
  several forks into one question.
- An answer authorizes EXACTLY the asked question — nothing more. It is not
  approval of the surrounding design, not enthusiasm, not "keep going". After
  each answer: restate the updated decision in ≤2 lines, then surface the NEXT
  open fork.
- Keep a running OPEN FORKS list from turn one; elicitation is complete only
  when that list is empty. Reflect the evolving ADR back as the list + the
  decision table — compact and factual, never celebratory (the tone target is
  a technical record, not a pitch).
- Before Step 3 writes any file: present the decision summary (numbered
  decisions, deltas D1..Dn, phase list with each phase's size-budget check)
  and get an explicit go-ahead via `AskUserQuestion`. A conversation that
  "feels" settled is never the trigger to start writing.
- Drift guard: before any long reply, re-read the draft's objective line; if
  the reply is not resolving an open fork of THAT objective, stop and say so
  instead of writing it.

## Step 3 — Write the ADR document

Create `.ADRs/ADR_{NN}_{Name}/ADR.md` (**markdown**). Mirror the latest ADR's
section set; the canonical skeleton is:

```text
# ADR-NN: <imperative title>

- **Status:** **Proposed** (<today's date>)
- **Date:** <today's date>
- **Branch:** `adr/{NN}-{slug}` (off <base, e.g. devel>; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming") / **Component(s):** <files>
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
Target model: <e.g. Claude Sonnet 5>
ADR: .ADRs/ADR_NN_Name/ADR.md   (read <relevant section> first)
================================================================================

ROLE
<which branch; which phase; behaviour-preserving? ; "inline on <branch>, one
 commit, push directly">
WEIGHT: light   <-- OPTIONAL (owner directive 2026-07-14). Only for a
 behaviour-preserving MECHANICAL phase (pure renames/moves/retirement sweeps
 executing an already-enumerated plan) whose correctness is pinned by an oracle
 an EARLIER phase froze. /adr-phase then skips the fresh-context Brief stage
 (~1/3 of the phase's cost): the implementer executes this prompt directly and
 re-derives its site lists from source. NEVER on an oracle-building phase, the
 first phase, or anything touching a parser/regex/guard or new behaviour.
Blast-radius note for the gate: <what production behaviour can change when this
 phase lands alone — "NONE" / "PRODUCTION-DORMANT until Phase N" stated, never
 implied; a behaviour-changing phase names its delta budget here>

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

VERIFICATION (must all pass before the phase is done; only gates RUNNABLE in the
implementer's environment — anything else goes under DEFERRED with its exact
dispatch command, never as "must pass")
- <the canonical gates for the touched languages — CLAUDE.md "Canonical gates">
- red-run (behaviour-changing phase): AUTHOR <named new test> FIRST, before any
  production edit, at full suite quality; execute → FAILS for the defect's
  reason (paste command + failure line into HANDOFF; record `git hash-object`);
  freeze it byte-identical, implement, re-run the SAME test with zero edits →
  PASSES; only then add the remaining tests — executed runs, never "reasoned
  through". (Waived for brand-new code whose only possible red is a missing
  symbol — an existence test is coverage theater; its tests still ship.)
- <the per-item acceptance checks: WHEN <command/input> THEN <observable>>
- diff-read <what to eyeball>

EXPECTED RESULT
<the observable end state>

COMMIT (single)
    <scope>: <imperative summary> (ADR-NN PN)
Push directly to <branch>; open a PR only if the direct push is rejected.

HANDOFF — write `.ADRs/ADR_NN_Name/RESULTS/<NN>_Results.txt` (plain .txt) with
the fixed fields (CLAUDE.md "THE HANDOFF"): verdict; what changed + commit;
gates with pasted output; red→green proof; coverage-matrix ticks; deviations /
judgment calls (or "none"); carry-forward for the next phase.
```

Rules:

- Phase 1 has **no** prior-handoff line; **every later phase** opens REQUIRED
  READING with the "FIRST, read RESULTS/(N-1)_Results.txt … else STOP" gate.
- Each phase ends with the HANDOFF block naming `RESULTS/{NN}_Results.txt`.
- Reflect the CLAUDE.md workflow actually in force (commit style, inline-on-
  branch, push-direct-PR-only-if-rejected).
- **Every prompt carries the reality-override line:** "Line numbers and
  code-state claims in this prompt were written before earlier phases ran; the
  prior RESULTS files and the live tree override this prompt on any conflict —
  verify each claim before acting on it, and flag contradictions loudly in the
  handoff." Planner briefs contain errors in every era; the durable defence is
  an implementer instructed to disprove the brief, not obey it.
- A phase adding/changing a **parser, regex, scrub, formatter, or input guard**
  carries its **hostile-input rows** (punycode/IDN, empty, header/no-header,
  metacharacters, tabs/consecutive spaces, oversized, wrong encoding) with
  expected outcomes as REQUIRED test data — the implementer fills in results,
  it never invents the input classes (CLAUDE.md "THE BRIEF" §4; the full
  transformer list comes from Step 2's design-completeness enumeration).
- **Every prompt carries a blast-radius line** (Step 2 item 9's safety rails;
  `blast-radius` check in the prompt checker): what production behaviour can
  change when the phase lands alone, with a behaviour-changing prompt naming
  its exact delta budget and the pinned surfaces its oracle rides.
- **Size check per prompt:** a prompt whose ACTION PLAN exceeds 5 items, spans
  two production languages, or needs more than ~90 lines to state violates the
  Step 2 phase-size budget — go back and split the phase; never write a bigger
  prompt.
- **Template drift is bounded:** mirror the latest ADR's section set and prose
  style, but the VERIFICATION and HANDOFF gate content above comes from THIS
  skill's template — one weak ADR must not become the convention every later
  ADR copies.
- §7 Definition of Done always carries the **CE+Plus live-VM fan-out** line (the
  org-default validation matrix); an ADR wanting to skip it states the exemption
  explicitly.
- **After writing all prompts, lint them:**
  `python3 scripts/check_phase_prompts.py .ADRs/ADR_{NN}_{Name}/[0-9]*.txt`
  (the `/spec-lint` checker — also a pre-commit gate). Fix any missing block
  before reporting the ADR done; never weaken the checker to make a prompt
  pass.

## Step 5 — Do NOT pre-write handoffs

`RESULTS/NN_Results.txt` files are produced by `/adr-phase` at implementation
time. Do not stub them. Creating an empty `RESULTS/` dir is optional (adr-phase
will create it).

## Step 6 — Land the ADR text, then report back

**Land it before reporting done** — an ADR only the local worktree can see is not "created".
From `<path>`: `git add .ADRs/ADR_{NN}_{Name}/`, commit
(`adr: propose ADR-{NN} {title}`), `git fetch origin devel` + rebase if it moved (dev-only
class — CLAUDE.md "Worktrees" exception: commit/push **directly to `devel`**, no PR), then
`git push origin HEAD:devel`. Confirm the push landed (`git log origin/devel -1 --
.ADRs/ADR_{NN}_{Name}/ADR.md`) — do not just trust a non-erroring push. Leave the worktree in
place (`/adr-phase` reuses its branch for the phase-implementation work); do not delete it.

Tell the user: the assigned number, the directory, the `ADR.md`, the ordered
list of phase-prompt files, confirmation it landed on `devel` (commit hash), and how to
implement it — `/adr-phase {NN} 1` for a single phase, or `/adr-phase {NN} all` to build the
whole ADR end-to-end (each phase reviewed against its objectives before its handoff), landing
as a PR (default) or a rebase onto the base when complete. Restate that Status is **Proposed**
until they accept the plan, and that acceptance ultimately depends on the validation evidence /
manual smoke defined in §7.
