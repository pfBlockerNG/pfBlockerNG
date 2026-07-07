export const meta = {
  name: 'phase-step',
  description: 'One delegated step under the delegation contract: Sonnet implementer -> independent Sonnet verifier, schema-forced handoff + gate record',
  whenToUse: 'Called by /adr-phase (per phase) and /gh-issue --fix (per step) instead of hand-spawning 6a/6b or 7a/7b. Args: {worktree, brief, gates: [cmd...], redProof: {srcPaths: [...], testCmd} | null, planItems: [...], ponytailLevel: "full" | null}. The caller keeps ALL judgment: it validates the returned gate record, commits the RESULTS/Gate files, and decides HALT/continue/landing.',
  phases: [
    { title: 'Implement', detail: 'one Sonnet implementer executes the brief' },
    { title: 'Verify', detail: 'fresh Sonnet verifier re-derives every gate item' },
  ],
}

// The mechanical core of CLAUDE.md "The delegation contract": the implementer
// never grades its own work; the verifier re-derives (re-runs gates, re-executes
// the red proof, reads the full diff) and returns a fixed-field gate record. The
// calling skill owns HALT/resume/landing — a workflow cannot ask the user anything.

const { worktree, brief, gates = [], redProof = null, planItems = [], ponytailLevel = null } = args ?? {}
if (!worktree || !brief) throw new Error('args must include {worktree, brief}; see meta.whenToUse')

const HANDOFF = {
  type: 'object',
  required: ['verdict', 'what_changed', 'commit', 'gates', 'coverage_matrix', 'deviations', 'carry_forward'],
  properties: {
    verdict: { type: 'string', enum: ['DONE', 'DONE-WITH-DEVIATION', 'BLOCKED'] },
    what_changed: { type: 'array', items: { type: 'object', required: ['file', 'why'], properties: { file: { type: 'string' }, why: { type: 'string' } } } },
    commit: { type: 'string', description: 'the commit hash, or "" when BLOCKED' },
    gates: { type: 'array', items: { type: 'object', required: ['cmd', 'output_tail'], properties: { cmd: { type: 'string' }, output_tail: { type: 'string', description: 'pasted output tail with pass/fail counts — never a bare claim' } } } },
    red_green: { type: 'object', description: 'behaviour-changing steps only; null otherwise', properties: { red_output: { type: 'string' }, green_output: { type: 'string' } } },
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

phase('Implement')

// The SubagentStart hook injects the mode capsule at the repo default (full);
// a brief line is needed only to OVERRIDE it with a non-default level.
const ponytailLine = ponytailLevel && ponytailLevel !== 'full' ? `Run /ponytail:ponytail ${ponytailLevel} (or /ponytail ${ponytailLevel} if unnamespaced) before anything else.\n` : ''
const handoff = await agent(`${ponytailLine}${brief}

STANDING CONTRACT (CLAUDE.md "The delegation contract" — these override nothing above, they restate the law):
- Work ENTIRELY inside the worktree at ${worktree} (git -C ${worktree} ...); never the main checkout. You implement yourself with Read/Edit/Write/Bash and NEVER spawn further agents.
- Run the gates and do not proceed red: ${gates.length ? gates.join(' · ') : 'the canonical gates for every language you touch (CLAUDE.md "Canonical gates")'}.
- Red->green is an EXECUTED run with output pasted into your handoff, never "reasoned through".
- ESCALATE: if any factual claim in the brief is contradicted by the code or a live probe, STOP and return verdict BLOCKED with the blocker field filled — never silently patch the plan.
- Commit as the brief instructs (single focused commit, repo commit style), then fill the structured handoff COMPLETELY — an empty field is a gate failure.`,
  { label: 'implement', phase: 'Implement', model: 'sonnet', effort: 'xhigh', schema: HANDOFF })

if (!handoff) throw new Error('implementer returned nothing (skipped or terminal error)')
if (handoff.verdict === 'BLOCKED') {
  log('implementer BLOCKED — returning without verification')
  return { handoff, gateRecord: null }
}

phase('Verify')

const redProofText = redProof
  ? `RED PROOF (re-execute yourself, never accept the handoff's claim): git -C ${worktree} checkout HEAD~1 -- ${redProof.srcPaths.join(' ')} (tests stay), run ${redProof.testCmd} -> expect FAIL; git -C ${worktree} checkout HEAD -- . , re-run -> expect PASS. Record both outputs as evidence.`
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
  { label: 'verify', phase: 'Verify', model: 'sonnet', effort: 'xhigh', schema: GATE_RECORD })

return { handoff, gateRecord }
