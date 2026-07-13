export const meta = {
  name: 'phase-step',
  description: 'One delegated step under the delegation contract: optional fresh higher-model Brief stage -> Sonnet implementer -> independent higher-model verifier, all schema-forced',
  whenToUse: 'Called by /adr-phase (per phase) and /gh-issue --fix (per step) instead of hand-spawning the implementer/verifier stages yourself. Args: {worktree, brief | briefSpec: {adrDir, phase, notes?}, gates: [cmd...], redProof: {srcPaths: [...], testCmd} | null, planItems: [...], ponytailLevel: "full" | null}. With briefSpec (ADR phases — issue #1089) the Brief stage derives brief/gates/redProof/planItems itself from disk, so the caller passes only pointers. The caller keeps ALL judgment: it validates the returned records, commits the RESULTS/Gate files, and decides HALT/continue/landing.',
  phases: [
    { title: 'Brief', detail: 'fresh higher-model planner enumerates the matrix + hostile rows and composes the brief (briefSpec callers only)' },
    { title: 'Implement', detail: 'one Sonnet implementer executes the brief', model: 'sonnet' },
    { title: 'Verify', detail: 'fresh higher-model verifier re-derives every gate item' },
  ],
}

// The mechanical core of CLAUDE.md "The delegation contract": the implementer
// never grades its own work; the verifier re-derives (re-runs gates, re-executes
// the red proof, reads the full diff) and returns a fixed-field gate record. The
// Brief stage (issue #1089) moves brief-writing into a fresh higher-model context
// too — the calling session passes pointers, not a composed brief, so its context
// stays flat across a long run. The calling skill owns HALT/resume/landing — a
// workflow cannot ask the user anything.

// Callers sometimes deliver args JSON-string-encoded (killed review-fanout on PR #937,
// issue #942) — normalize before destructuring instead of trusting caller discipline.
const input = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
let { worktree, brief = null, briefSpec = null, gates = [], redProof = null, planItems = [], ponytailLevel = null } = input
if (!worktree || (!brief && !briefSpec) || (brief && briefSpec)) throw new Error('args must include {worktree} and exactly ONE of {brief, briefSpec}; see meta.whenToUse')

const BRIEF_RECORD = {
  type: 'object',
  required: ['verdict', 'brief_text', 'coverage_matrix', 'hostile_rows', 'gates', 'red_proof', 'plan_items', 'drift_flags'],
  properties: {
    verdict: { type: 'string', enum: ['OK', 'BLOCKED'] },
    brief_text: { type: 'string', description: 'the complete self-contained implementer brief — all seven CLAUDE.md THE-BRIEF sections' },
    coverage_matrix: { type: 'array', minItems: 1, items: { type: 'object', required: ['row', 'source', 'mapping'], properties: { row: { type: 'string' }, source: { type: 'string', description: 'the executed grep command / file:line this row was enumerated from — never memory' }, mapping: { type: 'string', description: 'the test that covers it, or the explicit justified deferral' } } }, description: 'phase touches no sibling axes at all -> exactly one row stating that, with the source evidence proving it' },
    hostile_rows: { type: 'array', minItems: 1, items: { type: 'object', required: ['input', 'expected'], properties: { input: { type: 'string' }, expected: { type: 'string' } } }, description: 'phase touches no parser/regex/guard -> exactly one row stating that, with the evidence' },
    gates: { type: 'array', minItems: 1, items: { type: 'string' }, description: 'canonical gate commands for the languages the phase touches (CLAUDE.md table) plus cross-language consumers' },
    red_proof: { type: ['object', 'null'], required: ['srcPaths', 'testCmd'], properties: { srcPaths: { type: 'array', items: { type: 'string' } }, testCmd: { type: 'string' } }, description: 'null ONLY for a behaviour-preserving phase — and brief_text must say so' },
    plan_items: { type: 'array', minItems: 1, items: { type: 'string' }, description: 'the phase prompt ACTION-PLAN items the verifier ticks against the diff' },
    drift_flags: { type: 'array', items: { type: 'string' }, description: 'soft contradictions between prior RESULTS/Gate records and this phase plan, for the caller to judge; empty = none. A hard contradiction is verdict BLOCKED instead' },
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

let briefRecord = null
if (briefSpec) {
  phase('Brief')
  const { adrDir, phase: phaseNum, notes = '' } = briefSpec
  if (!adrDir || !phaseNum) throw new Error('briefSpec must include {adrDir, phase}')

  briefRecord = await agent(`You are the PLANNER writing THE BRIEF (CLAUDE.md "The delegation contract" — all seven mandatory sections) for ONE ADR phase, with a fresh context: read everything just-in-time from disk; trust nothing from memory. You write the brief only — you implement nothing and spawn no agents.

Worktree: ${worktree}. ADR directory: ${adrDir} (relative to the worktree). Phase: ${phaseNum}.

READ (all inside the worktree): CLAUDE.md ("The delegation contract", "Test coverage", "Code standards", "Canonical gates"); ${adrDir}/ADR.md; the phase prompt ${adrDir}/<MM>_*.txt for phase ${phaseNum} (MM = zero-padded phase number); the PREVIOUS phase's Results + Gate files in ${adrDir}/RESULTS/; and the carry_forward line of every earlier Results file (grep it out — do not re-read the full records: cross-phase state is chained through carry_forward precisely so each brief needn't re-read O(phases) history). Read a FULL earlier record only when the phase prompt, the ADR, or the previous records explicitly reference that phase.${notes ? `\nSESSION NOTES from the caller: ${notes}` : ''}

DERIVE, never copy: run the enumeration greps YOURSELF (git -C ${worktree} grep ...) for every sibling axis the phase touches (v4/v6, address/port, CE/Plus versions, parse modes, every caller of a touched symbol, every branch of a touched conditional) — each coverage_matrix row cites the executed command or file:line it came from. Supply hostile_rows with expected outcomes for any parser/regex/guard the phase touches (CLAUDE.md THE BRIEF section 4 input classes). Derive gates from the languages the phase touches (CLAUDE.md "Canonical gates" table, plus cross-language consumers of artifacts it changes), red_proof {srcPaths, testCmd} (null ONLY if the phase is behaviour-preserving — then brief_text says so and names the oracle tests), and plan_items from the prompt's ACTION PLAN.

DRIFT CHECK — deliberately broader than record-vs-plan: evaluate the PREVIOUS phase's LANDED DIFF (git -C ${worktree} show of its commit) against the ADR's invariants and the broader architecture, not just contradictions between the records and this phase's plan. You are the fresh set of eyes between phases: an architectural screw-up the previous phase landed must surface HERE, not at the final PR review after later phases build on it. Soft findings go in drift_flags (this phase would undo a pinned invariant; the previous diff strains an ADR invariant; a carry_forward contradicts the ADR). A HARD contradiction — the phase prompt or ADR refuted by the code or a prior record — is verdict BLOCKED with the blocker field filled, not a brief.

brief_text must be fully self-contained for a Sonnet implementer that has this worktree but no other context — and SELF-SUFFICIENT: embed the evidence for every factual claim (the grep/command output that proved it) so the implementer never needs to re-derive or re-fetch anything, and state explicitly that its reading scope is the brief + named refs + the code it edits (no re-reading the ADR/issue, no re-running the enumeration greps — the verifier and the PR review carry the skepticism): name the phase prompt file and the prior handoff as mandatory required reading (reference paths, do not paste bodies); carry the coverage matrix, hostile rows, constraints (do-NOT-touch list), verification commands with expected observables, and the ESCALATE contract; never weaken a CLAUDE.md mandate (red->green is TEST-FIRST and EXECUTED, output pasted); and instruct the implementer to write ${adrDir}/RESULTS/<MM>_Results.txt with the fixed HANDOFF fields, make ONE focused commit (code + handoff, repo commit style), and push it (git -C ${worktree} push -u origin HEAD).`,
    { label: 'brief', phase: 'Brief', effort: 'xhigh', schema: BRIEF_RECORD })

  if (!briefRecord) throw new Error('brief agent returned nothing (skipped or terminal error)')
  if (briefRecord.verdict === 'BLOCKED') {
    log('brief stage BLOCKED — returning without implementing')
    return { briefRecord, handoff: null, gateRecord: null }
  }
  if (briefRecord.drift_flags.length) log(`drift flags for the caller: ${briefRecord.drift_flags.join(' | ')}`)
  brief = briefRecord.brief_text
  gates = briefRecord.gates
  redProof = briefRecord.red_proof
  planItems = briefRecord.plan_items
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
  { label: 'implement', phase: 'Implement', model: 'sonnet', effort: 'xhigh', schema: HANDOFF })

if (!handoff) throw new Error('implementer returned nothing (skipped or terminal error)')
if (handoff.verdict === 'BLOCKED') {
  log('implementer BLOCKED — returning without verification')
  return { briefRecord, handoff, gateRecord: null }
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

MANDATORY CHECKS — one items[] entry each, with executed evidence; a skipped check goes in skipped[] with its reason:
1. handoff-fields: every required field non-empty and internally consistent (commit exists: git -C ${worktree} log -1).
2. gate-rerun: re-run ${gates.length ? gates.join(' · ') : 'the canonical gates for every language the diff touches, plus cross-language consumers'} yourself; paste output tails.
3. red-proof: ${redProofText}
4. diff-vs-plan: read the FULL diff of the step's commit (git -C ${worktree} show — never --stat alone) and tick EVERY plan item${planItems.length ? ` — the items: ${planItems.map((x, i) => `(${i + 1}) ${x}`).join(' ')}` : ' from the brief\'s ACTION PLAN'} and every coverage-matrix row against what the diff actually does. Hardcoded values, stubbed branches, dropped items live below --stat.
5. test-honesty: no weakened/removed assertions; every negative assertion has a fixture that could fail it; no red manufactured via a fault production cannot produce; www/ touched => Tier-A coverage present.
6. conventions: each new public symbol beside 3 sibling symbols proving the name matches; stale comments/docs about touched symbols reconciled.

Verdict FAIL iff any item fails; list blocking_reasons. Your structured output IS the gate record.`,
  { label: 'verify', phase: 'Verify', effort: 'xhigh', schema: GATE_RECORD })

return { briefRecord, handoff, gateRecord }
