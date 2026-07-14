export const meta = {
  name: 'phase-step',
  description: 'One delegated step under the delegation contract: optional fresh higher-model Reconcile stage (validates the prior phase, patches the phase prompt on disk, derives the enumerations) -> Sonnet implementer -> independent Sonnet verifier, all schema-forced',
  whenToUse: 'Called by /adr-phase (per phase) and /gh-issue --fix (per step) instead of hand-spawning the implementer/verifier stages yourself. Args: {worktree, brief | briefSpec: {adrDir, phase, notes?, weight?: "full" (default) | "light"}, gates: [cmd...], redProof: {srcPaths: [...], testCmd} | null, planItems: [...], ponytailLevel: "full" | null, briefModel?: "<model id>" (Reconcile stage ONLY — default inherits the session model; owner directive 2026-07-14: pass claude-opus-4-8 while the Fable budget is constrained; Implement/Verify stay pinned to Sonnet regardless)}. Unknown top-level args are REJECTED (a stale script once dropped briefModel silently and burned the wrong model, 2026-07-14). The Verify stage always runs on Sonnet — a fresh set of model-eyes distinct from the higher-model reconciler (owner directive 2026-07-14). With briefSpec (ADR phases — issue #1089 fresh-context principle; 2026-07-14 overhead redesign) the Reconcile stage validates the previous phase\'s landed diff (scoped drift check), patches the phase prompt on disk to match the live tree (committed, spec-lint-clean), and derives gates/redProof/planItems + the coverage matrix and hostile rows from source; the implementer then executes the reconciled prompt directly with those enumerations rendered mechanically — no separate brief document exists. weight "light" (owner directive 2026-07-14; ONLY when the phase prompt itself carries a WEIGHT: light line — behaviour-preserving mechanical execution pinned by an earlier gate-passed oracle) skips the Reconcile stage: the implementer executes the phase prompt directly and re-derives its enumerations from source; the Verify stage is unchanged. The caller keeps ALL judgment: it validates the returned records, commits the RESULTS/Gate files, and decides HALT/continue/landing.',
  phases: [
    { title: 'Reconcile', detail: 'fresh higher-model planner validates the prior phase (scoped drift), patches the phase prompt against the live tree, and derives the matrix + hostile rows (briefSpec callers only; skipped for weight: light)' },
    { title: 'Implement', detail: 'one Sonnet implementer executes the reconciled prompt + rendered enumerations', model: 'claude-sonnet-5' },
    { title: 'Verify', detail: 'fresh Sonnet verifier (never the reconciler\'s model) re-derives every gate item', model: 'claude-sonnet-5' },
  ],
}

// The mechanical core of CLAUDE.md "The delegation contract": the implementer
// never grades its own work; the verifier re-derives (re-runs gates, re-executes
// the red proof, reads the full diff) and returns a fixed-field gate record. The
// Reconcile stage keeps planning in a fresh higher-model context (issue #1089) but
// treats the phase prompt as the brief: it patches the prompt against the live tree
// and returns only structured enumerations — the per-phase Brief that re-authored
// the prompt as a 30KB document was a fixed ~16-min toll (measured 2026-07-14) that
// dominated the new smaller phases. The calling skill owns HALT/resume/landing — a
// workflow cannot ask the user anything.

// Callers sometimes deliver args JSON-string-encoded (killed review-fanout on PR #937,
// issue #942) — normalize before destructuring instead of trusting caller discipline.
const input = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
const KNOWN_ARGS = ['worktree', 'brief', 'briefSpec', 'gates', 'redProof', 'planItems', 'ponytailLevel', 'briefModel']
const unknownArgs = Object.keys(input).filter(k => !KNOWN_ARGS.includes(k))
if (unknownArgs.length) throw new Error(`unknown args: ${unknownArgs.join(', ')} — refusing to drop them silently (a stale resumed script once discarded briefModel and ran the Brief stage on the wrong model, 2026-07-14); update KNOWN_ARGS when adding an arg`)
let { worktree, brief = null, briefSpec = null, gates = [], redProof = null, planItems = [], ponytailLevel = null, briefModel = null } = input
if (!worktree || (!brief && !briefSpec) || (brief && briefSpec)) throw new Error('args must include {worktree} and exactly ONE of {brief, briefSpec}; see meta.whenToUse')

const RECONCILE_RECORD = {
  type: 'object',
  required: ['verdict', 'prompt_status', 'corrections', 'coverage_matrix', 'hostile_rows', 'gates', 'red_proof', 'plan_items', 'drift_flags', 'implementer_notes'],
  properties: {
    verdict: { type: 'string', enum: ['OK', 'BLOCKED'] },
    prompt_status: { type: 'string', enum: ['unchanged', 'patched'], description: 'patched = the phase prompt file was edited against the live tree and committed' },
    corrections: { type: 'array', items: { type: 'object', required: ['claim', 'correction', 'evidence'], properties: { claim: { type: 'string', description: 'the stale prompt claim/ref' }, correction: { type: 'string' }, evidence: { type: 'string', description: 'the executed probe that proved the correction' } } }, description: 'one entry per fixed claim; empty when prompt_status is unchanged' },
    coverage_matrix: { type: 'array', minItems: 1, items: { type: 'object', required: ['row', 'source', 'mapping'], properties: { row: { type: 'string' }, source: { type: 'string', description: 'the executed grep command / file:line this row was enumerated from — never memory' }, mapping: { type: 'string', description: 'the test that covers it, or the explicit justified deferral' } } }, description: 'phase touches no sibling axes at all -> exactly one row stating that, with the source evidence proving it' },
    hostile_rows: { type: 'array', minItems: 1, items: { type: 'object', required: ['input', 'expected'], properties: { input: { type: 'string' }, expected: { type: 'string' } } }, description: 'phase touches no parser/regex/guard -> exactly one row stating that, with the evidence' },
    gates: { type: 'array', minItems: 1, items: { type: 'string' }, description: 'canonical gate commands for the languages the phase touches (CLAUDE.md table) plus cross-language consumers' },
    red_proof: { type: ['object', 'null'], required: ['srcPaths', 'testCmd'], properties: { srcPaths: { type: 'array', items: { type: 'string' } }, testCmd: { type: 'string' } }, description: 'null ONLY for a behaviour-preserving phase — and the prompt must say so and name the oracle tests' },
    plan_items: { type: 'array', minItems: 1, items: { type: 'string' }, description: 'the phase prompt ACTION-PLAN items the verifier ticks against the diff' },
    drift_flags: { type: 'array', items: { type: 'string' }, description: 'soft contradictions between prior RESULTS/Gate records, the previous landed diff, and this phase plan, for the caller to judge; empty = none. A hard contradiction is verdict BLOCKED instead' },
    implementer_notes: { type: 'string', description: 'transient session facts the implementer needs that do not belong in the committed prompt (verified branch/base state, environment gotchas from prior handoffs); "" if none. NEVER a restatement of the matrix/hostile rows/gates/plan items' },
    blocker: { type: 'string', description: 'BLOCKED only: which claim reality contradicted, with the probe evidence' },
  },
}

const HANDOFF = {
  type: 'object',
  required: ['verdict', 'what_changed', 'base_sha', 'commit', 'gates', 'red_green', 'coverage_matrix', 'deviations', 'carry_forward'],
  properties: {
    verdict: { type: 'string', enum: ['DONE', 'DONE-WITH-DEVIATION', 'BLOCKED'] },
    what_changed: { type: 'array', items: { type: 'object', required: ['file', 'why'], properties: { file: { type: 'string' }, why: { type: 'string' } } } },
    base_sha: { type: 'string', description: 'git rev-parse HEAD captured BEFORE the first edit of this step — the true pre-fix baseline the verifier reverts src to, or "" if BLOCKED before you ran it. NOT HEAD~1: a step that lands a follow-up commit (doc/ADR reconciliation, a review fix) makes HEAD~1 the wrong baseline (issue #1249).' },
    commit: { type: 'string', description: 'the commit hash, or "" when BLOCKED' },
    gates: { type: 'array', items: { type: 'object', required: ['cmd', 'output_tail'], properties: { cmd: { type: 'string' }, output_tail: { type: 'string', description: 'pasted output tail with pass/fail counts — never a bare claim' } } } },
    red_green: { type: 'array', minItems: 1, description: 'MANDATORY, one entry per behaviour-changing item: PASTED executed red output (run BEFORE any production edit), pasted green output, and git hash-object of each test file at red time. An item with no red run carries carve_out naming the CLAUDE.md exception (brand-new code / behaviour-preserving oracle) instead — never an empty entry. Implementers reliably drop this when optional; it is schema-required for that reason.', items: { type: 'object', required: ['item'], properties: { item: { type: 'string', description: 'which plan item this proves' }, red_output: { type: 'string' }, green_output: { type: 'string' }, red_test_hashes: { type: 'array', items: { type: 'object', required: ['file', 'hash'], properties: { file: { type: 'string' }, hash: { type: 'string', description: 'git hash-object at red-run time — must equal the committed file' } } } }, carve_out: { type: 'string', description: 'the named CLAUDE.md exception, ONLY when no red run applies to this item' } } } },
    coverage_matrix: { type: 'array', items: { type: 'object', required: ['row', 'status'], properties: { row: { type: 'string' }, status: { type: 'string', description: 'test name covering it, or the stated deferral' } } } },
    deviations: { type: 'string', description: '"none" or the judgment calls made' },
    carry_forward: { type: 'string' },
    blocker: { type: 'string', description: 'BLOCKED only: the structured blocker (which brief claim reality contradicted)' },
  },
}

const GATE_RECORD = {
  type: 'object',
  required: ['verdict', 'items', 'skipped'],
  properties: {
    verdict: { type: 'string', enum: ['PASS', 'FAIL'] },
    items: {
      type: 'array',
      items: {
        type: 'object',
        required: ['check', 'status', 'evidence'],
        properties: {
          check: { type: 'string', description: 'gate-rerun | red-proof | diff-vs-plan:<item> | matrix:<row> | test-honesty | conventions | handoff-fields' },
          status: { type: 'string', enum: ['pass', 'fail', 'skipped'] },
          evidence: { type: 'string', description: 'the executed command + output tail, or the diff observation — never "looks fine"' },
        },
      },
    },
    skipped: { type: 'array', items: { type: 'string' }, description: 'every skipped check with its reason — an unrun check must be visible' },
    blocking_reasons: { type: 'array', items: { type: 'string' } },
  },
}

// Both briefSpec routes hand the implementer a POINTER brief: the constraints
// (do-NOT-touch) and acceptance checks live in the phase prompt on disk, so the
// verifier must read that file too or it gates against half a contract.
let reconcileRecord = null
let promptRef = null
if (briefSpec) {
  const { adrDir, phase: phaseNum, notes = '', weight = 'full' } = briefSpec
  if (!adrDir || !phaseNum) throw new Error('briefSpec must include {adrDir, phase}')
  if (weight !== 'full' && weight !== 'light') throw new Error(`briefSpec.weight must be "full" or "light"; got "${weight}"`)

  if (weight === 'light') {
    // Owner directive (2026-07-14): mechanical phases skip the Reconcile stage — the
    // phase prompt on disk IS the brief; the implementer re-derives its enumerations from
    // source (there is no planner enumeration to trust). Verify stage unchanged. In-workflow
    // guards below make a mis-tagged light call fail BLOCKED instead of running under-briefed.
    if (redProof) throw new Error('weight "light" is for behaviour-preserving phases only — redProof must be null (a behaviour-changing phase is full-weight)')
    log('light-weight phase: Reconcile stage skipped — the phase prompt on disk is the brief')
    const mm = String(phaseNum).padStart(2, '0')
    promptRef = `${adrDir}/${mm}_*.txt`
    brief = `LIGHT-WEIGHT ADR PHASE (weight: light — mechanical execution of an already-enumerated, oracle-pinned plan). Your brief lives ON DISK, not in this message. Worktree: ${worktree}; ADR directory: ${adrDir} (relative to the worktree); phase ${phaseNum}.

MANDATORY READING (in order): the phase prompt ${adrDir}/${mm}_*.txt — it IS the brief: its ACTION PLAN is your plan, its VERIFICATION section your acceptance checks, its CONSTRAINTS/stays lists your do-NOT-touch list; the previous phase's Results + Gate files in ${adrDir}/RESULTS/ plus the carry_forward line of every earlier Results file; the ADR.md sections the prompt names.

LIGHT-WEIGHT GUARDS (each is a BLOCKED trigger, not a judgment call):
1. The phase prompt must contain a line starting "WEIGHT: light". Absent -> verdict BLOCKED (the caller mis-tagged a full-weight phase).
2. Light weight covers ONLY behaviour-preserving mechanical work pinned by an existing oracle from an earlier phase. If the prompt demands new behaviour, a new parser/regex/input guard, or a red->green proof -> verdict BLOCKED.
3. There is no planner enumeration to trust here: re-derive the prompt's identifier/site lists FROM SOURCE (git -C ${worktree} grep) before editing — prompt line refs may be stale (reality-override). A prompt claim the source refutes -> verdict BLOCKED with the probe evidence.${notes ? `\n\nSESSION NOTES from the caller: ${notes}` : ''}

Write ${adrDir}/RESULTS/${mm}_Results.txt with the fixed HANDOFF fields, make ONE focused commit (code + handoff, repo commit style), and push it (git -C ${worktree} push -u origin HEAD).`
  } else {
  phase('Reconcile')
  const mm = String(phaseNum).padStart(2, '0')
  promptRef = `${adrDir}/${mm}_*.txt`

  reconcileRecord = await agent(`You are the RECONCILER for ONE ADR phase (CLAUDE.md "The delegation contract" — you produce THE BRIEF's content, split between the phase prompt on disk and your structured fields), with a fresh context: read everything just-in-time from disk; trust nothing from memory. You plan only — you implement nothing and spawn no agents. The phase prompt IS the implementer's brief: your job is to bring it up to date with the live tree and derive the enumerations, NOT to re-author it as a new document.

Worktree: ${worktree}. ADR directory: ${adrDir} (relative to the worktree). Phase: ${phaseNum}.

READ (all inside the worktree): the phase prompt ${adrDir}/${mm}_*.txt; the ADR.md sections that prompt names (not the whole ADR); the PREVIOUS phase's Results + Gate files in ${adrDir}/RESULTS/; the carry_forward line of every earlier Results file (grep it out — do not re-read the full records: cross-phase state is chained through carry_forward precisely so each phase needn't re-read O(phases) history; read a FULL earlier record only when the prompt, the ADR, or the previous records explicitly reference that phase); CLAUDE.md "The delegation contract" (THE BRIEF sections 3-4) and the "Canonical gates" table.${notes ? `\nSESSION NOTES from the caller: ${notes}` : ''}

DRIFT CHECK — scoped, not a re-review: evaluate the PREVIOUS phase's LANDED DIFF (git -C ${worktree} show of its commit) ONLY against (a) the ADR invariants it touches and (b) this phase's premises. The previous Verify stage already re-derived that phase's gate mechanically and the whole-PR review re-reads every diff — do not re-review the diff generally. Soft findings go in drift_flags (this phase would undo a pinned invariant; the previous diff strains an ADR invariant; a carry_forward contradicts the ADR). A HARD contradiction — the phase prompt or ADR refuted by the code or a prior record — is verdict BLOCKED with the blocker field filled; stop there. Phase 1 of a run has no previous diff: skip the diff read, still reconcile the prompt below (this also covers an ADR authored long before the run).

RECONCILE THE PROMPT (edit the file in place — smallest diff, never a rewrite): verify every file:line ref and code-state claim in the prompt against the live tree (git -C ${worktree} grep / read the named sites); fix what is stale; fold in any prior carry_forward fact the implementer must see; add a load-bearing fact you discovered ONLY if acting without it would ship a defect. Keep the prompt's structure and contract blocks intact and run python3 ${worktree}/scripts/check_phase_prompts.py <the prompt's absolute path> after editing — it must stay clean (it takes explicit paths from any cwd). Do NOT restate what is already correct, and do NOT write the coverage matrix / hostile rows / gates into the prompt (they live in your structured fields; the workflow renders them for the implementer). If you changed the file, commit ONLY that file (message style: docs: ADR-NN phase ${phaseNum} prompt reconciled), do not push; report prompt_status accordingly with one corrections[] entry per fixed claim {claim, correction, evidence}.

DERIVE, never copy: run the enumeration greps YOURSELF (git -C ${worktree} grep ...) for every sibling axis the phase touches (v4/v6, address/port, CE/Plus versions, parse modes, every caller of a touched symbol, every branch of a touched conditional) — each coverage_matrix row cites the executed command or file:line it came from. Supply hostile_rows with expected outcomes for any parser/regex/guard the phase touches (CLAUDE.md THE BRIEF section 4 input classes). Derive gates from the languages the phase touches (CLAUDE.md "Canonical gates" table, plus cross-language consumers of artifacts it changes), red_proof {srcPaths, testCmd} (null ONLY if the phase is behaviour-preserving — the prompt must say so and name the oracle tests), and plan_items from the prompt's ACTION PLAN. implementer_notes carries transient session facts only (verified branch/base state, environment gotchas from prior handoffs) — never a restatement of the structured fields.`,
    { label: 'reconcile', phase: 'Reconcile', effort: 'xhigh', schema: RECONCILE_RECORD, ...(briefModel ? { model: briefModel } : {}) })

  if (!reconcileRecord) throw new Error('reconcile agent returned nothing (skipped or terminal error)')
  if (reconcileRecord.verdict === 'BLOCKED') {
    log('reconcile stage BLOCKED — returning without implementing')
    return { reconcileRecord, handoff: null, gateRecord: null }
  }
  if (reconcileRecord.drift_flags.length) log(`drift flags for the caller: ${reconcileRecord.drift_flags.join(' | ')}`)
  if (reconcileRecord.prompt_status === 'patched') log(`phase prompt patched: ${reconcileRecord.corrections.length} correction(s) committed`)
  gates = reconcileRecord.gates
  redProof = reconcileRecord.red_proof
  planItems = reconcileRecord.plan_items

  const renderMatrix = rows => rows.map(r => `- ${r.row}\n    source: ${r.source}\n    maps to: ${r.mapping}`).join('\n')
  const renderHostile = rows => rows.map(r => `- input: ${r.input}\n    expected: ${r.expected}`).join('\n')
  brief = `ADR PHASE ${phaseNum} (${adrDir}). Your brief is ON DISK plus the planner enumerations below. Worktree: ${worktree}.

THE BRIEF: the phase prompt ${adrDir}/${mm}_*.txt, reconciled against the live tree this run — its refs and code-state claims were verified/corrected by the planner; trust them. Its ACTION PLAN is your plan, its CONSTRAINTS your do-NOT-touch list, its VERIFICATION your acceptance checks, its HANDOFF section your handoff spec (write ${adrDir}/RESULTS/${mm}_Results.txt with the fixed HANDOFF fields).

MANDATORY READING (in order, just-in-time — nothing else): the phase prompt; the previous phase's Results file in ${adrDir}/RESULTS/ (especially its carry_forward); the refs the prompt names.

PLANNER ENUMERATIONS (derived from source by the planner, each row citing its evidence — execute them, do not re-derive them):
COVERAGE MATRIX (every row maps to a test or an explicit justified deferral in your handoff):
${renderMatrix(reconcileRecord.coverage_matrix)}
HOSTILE-INPUT ROWS (each becomes a test for the parser/regex/guard this phase touches):
${renderHostile(reconcileRecord.hostile_rows)}${reconcileRecord.implementer_notes ? `\nSESSION NOTES from the planner: ${reconcileRecord.implementer_notes}` : ''}

Make ONE focused commit (code + handoff; the message the prompt's COMMIT section names) and push it (git -C ${worktree} push -u origin HEAD).`
  }
}

phase('Implement')

// The SubagentStart hook injects the mode capsule at the repo default (full);
// a brief line is needed only to OVERRIDE it with a non-default level.
const ponytailLine = ponytailLevel && ponytailLevel !== 'full' ? `Run /ponytail:ponytail ${ponytailLevel} (or /ponytail ${ponytailLevel} if unnamespaced) before anything else.\n` : ''
const handoff = await agent(`${ponytailLine}${brief}

STANDING CONTRACT (CLAUDE.md "The delegation contract" — these override nothing above, they restate the law):
- Work ENTIRELY inside the worktree at ${worktree} (git -C ${worktree} ...); never the main checkout. You may spawn subagents for a subtask that genuinely splits (the platform caps nesting depth) — but nested work is YOUR work: verify it yourself before it enters the handoff, whose every field stays yours to fill, and never hand the whole brief downward unexamined.
- Run the gates and do not proceed red: ${gates.length ? gates.join(' · ') : 'the canonical gates for every language you touch (CLAUDE.md "Canonical gates")'}.
- Red->green is TEST-FIRST and EXECUTED (CLAUDE.md Test coverage #1): author the reproduction test(s) BEFORE any production edit, run them -> FAIL for the defect's reason (paste output; record git hash-object of each test file in red_test_hashes), freeze them byte-identical (a temporary skip while developing is fine, but the committed file must match the red-run content exactly), implement, re-run the SAME tests with zero edits -> PASS (paste output). Only then add further tests. Never "reasoned through". Waived only for brand-new code whose sole possible red is a missing symbol (an existence test is coverage theater) — its tests still ship.
- TRUST THE BRIEF — do NOT re-investigate it. The brief's facts were verified by the planner and carry their evidence; an independent verifier re-derives every gate item after you, and an adversarial review re-checks the PR. Your reading scope is: the brief itself, its named required-reading refs, and the code you are about to edit. Do NOT re-fetch the issue/ADR/PR from GitHub, do NOT re-run the brief's enumeration greps, do NOT re-derive its coverage matrix — that spends the step's budget re-doing the planner's work.
- ESCALATE is REACTIVE, not an audit mandate: when code you are editing (or a probe you needed anyway) contradicts a brief claim, STOP and return verdict BLOCKED with the blocker field filled — never silently patch the plan. Encountering a contradiction triggers it; going looking for one does not.
- FIRST, before any edit: run git -C ${worktree} rev-parse HEAD and report it verbatim as base_sha. That is the pre-fix baseline the verifier reverts to; it stays correct even if you land a follow-up commit on top of the fix, which HEAD~1 would not.
- Commit as the brief instructs (single focused commit, repo commit style), then fill the structured handoff COMPLETELY — an empty field is a gate failure.`,
  { label: 'implement', phase: 'Implement', model: 'claude-sonnet-5', effort: 'xhigh', schema: HANDOFF })

if (!handoff) throw new Error('implementer returned nothing (skipped or terminal error)')
if (handoff.verdict === 'BLOCKED') {
  log('implementer BLOCKED — returning without verification')
  return { reconcileRecord, handoff, gateRecord: null }
}

phase('Verify')

// The handoff is agent-authored text that ends up inside a shell command the verifier runs.
// Identifier-shaped fields are shape-checked at the boundary or the step dies; testCmd is a
// free-form command (spaces, quotes, $(...) are legitimate) so it gets quoted, not restricted.
const safe = (value, pattern, field) => {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new Error(`unsafe ${field} in handoff: ${JSON.stringify(value)}`)
  }
  return value
}
const shq = s => `'${String(s).replace(/'/g, "'\\''")}'`
const baseSha = redProof ? safe(handoff.base_sha, /^[0-9a-f]{40}$/, 'base_sha') : ''
const redHashArgs = (handoff.red_green || [])
  .flatMap(e => e.red_test_hashes || [])
  .map(h => `--hash ${safe(h.file, /^[A-Za-z0-9._/-]+$/, 'red_test_hashes.file')}=${safe(h.hash, /^[0-9a-f]{40}$/, 'red_test_hashes.hash')}`)
  .join(' ')

const redProofText = redProof
  ? `RED PROOF (re-execute yourself, never accept the handoff's claim).

FIRST, BASELINE SANITY — the script trusts whatever ref you hand it, so earn that trust before you run it: the handoff's base_sha (${baseSha}) must be a real commit, an ANCESTOR of HEAD, and NOT equal to HEAD — else the implementer captured it after editing and the red run would prove nothing. Check: git -C ${shq(worktree)} merge-base --is-ancestor ${baseSha} HEAD && [ "$(git -C ${shq(worktree)} rev-parse ${baseSha})" != "$(git -C ${shq(worktree)} rev-parse HEAD)" ]. Either check failing = FAIL this item; do not substitute HEAD~1 to make it pass.

THEN run the single implementation — do NOT hand-roll the checkout dance:

  sh scripts/agent/verify-red-proof.sh --worktree ${shq(worktree)} --test-cmd ${shq(redProof.testCmd)} ${redProof.srcPaths.map(p => `--src ${safe(p, /^[A-Za-z0-9._/-]+$/, 'redProof.srcPaths')}`).join(' ')} ${redHashArgs} --base-ref ${baseSha}

It reverts the src paths to --base-ref (tests stay) and requires FAIL, restores HEAD and requires PASS, and enforces the freeze (git hash-object of each committed reproduction test == the handoff's red-time hash — a test edited between red and green, or with no red-time hash, proves nothing). Record its FREEZE-OK / RED-OK / GREEN-OK / VERDICT lines as evidence; a non-PASS verdict fails this item.`
  : 'This step is declared behaviour-preserving: confirm the oracle/pinned tests exist and stayed green; record which.'

const gateRecord = await agent(`You are an independent VERIFIER (CLAUDE.md "THE GATE") for one delegated step. You did not write this code; re-derive, never merely re-read. READ-ONLY except the red-proof checkout dance below (which you must fully restore). Worktree: ${worktree}.

THE IMPLEMENTER'S HANDOFF (verify it, don't trust it):
${JSON.stringify(handoff, null, 2)}

THE BRIEF IT EXECUTED (check the diff against every plan item):
${brief}
${promptRef ? `\nThat brief is a POINTER: READ the phase prompt ${promptRef} in the worktree before you gate. Its CONSTRAINTS section is the do-NOT-touch list you check the diff against, and its VERIFICATION section the acceptance checks you tick — they exist nowhere else in this message.\n` : ''}
MANDATORY CHECKS — one items[] entry each, with executed evidence; a skipped check goes in skipped[] with its reason:
1. handoff-fields: every required field non-empty and internally consistent (commit exists: git -C ${worktree} log -1).
2. gate-rerun: re-run ${gates.length ? gates.join(' · ') : 'the canonical gates for every language the diff touches, plus cross-language consumers'} yourself; paste output tails.
3. red-proof: ${redProofText}
4. diff-vs-plan: read the FULL diff of the step's commit (git -C ${worktree} show — never --stat alone) and tick EVERY plan item${planItems.length ? ` — the items: ${planItems.map((x, i) => `(${i + 1}) ${x}`).join(' ')}` : ' from the brief\'s ACTION PLAN'} and every coverage-matrix row against what the diff actually does. Hardcoded values, stubbed branches, dropped items live below --stat.
5. test-honesty: no weakened/removed assertions; every negative assertion has a fixture that could fail it; no red manufactured via a fault production cannot produce; www/ touched => Tier-A coverage present.
6. conventions: each new public symbol beside 3 sibling symbols proving the name matches; stale comments/docs about touched symbols reconciled.

Verdict FAIL iff any item fails; list blocking_reasons. Your structured output IS the gate record.`,
  // Owner directive (2026-07-14): the verifier never runs on the reconciler's (higher)
  // model — Sonnet re-derives the gate; the top tier's cross-referencing is reserved for
  // the whole-PR review (review-single).
  { label: 'verify', phase: 'Verify', model: 'claude-sonnet-5', effort: 'xhigh', schema: GATE_RECORD })

return { reconcileRecord, handoff, gateRecord }
