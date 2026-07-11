export const meta = {
  name: 'review-fanout',
  description: 'Deterministic multi-agent adversarial PR review: 3 lenses -> dedup -> execution-grounded verify per finding',
  whenToUse: 'ONLY on explicit user request for a multi-agent review — retired as pr-merge-flow\'s default (2026-07-11): the flow now runs ONE reviewer sub-agent (latest Sonnet, or latest Fable for a large/complex PR) at xhigh. Args: {pr: <number>, base: <branch>, worktree: <path>, spec: <intent/acceptance text>}.',
  phases: [
    { title: 'Find', detail: 'three independent lenses over the diff' },
    { title: 'Verify', detail: 'adversarial, execution-grounded check of every finding' },
  ],
}

// Multi-agent review shape, run only on explicit user request (pr-merge-flow's default
// is a single reviewer sub-agent since 2026-07-11). Every agent is Sonnet at xhigh (this
// workflow's floor and ceiling); no ponytail (reviewers build nothing). Findings must be
// execution-grounded; the verify stage tries to REFUTE each finding, so
// plausible-but-wrong ones die here instead of in triage.

// Callers sometimes deliver args JSON-string-encoded (killed this workflow on PR #937,
// issue #942) — normalize before destructuring instead of trusting caller discipline.
const input = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
const { pr, base = 'devel', worktree, spec = '(no spec provided — flag that as a finding)' } = input
if (!pr || !worktree) throw new Error('args must be {pr, worktree, base?, spec?}')

const FINDINGS = {
  type: 'object',
  required: ['findings', 'per_file'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['severity', 'location', 'explanation', 'reproduce', 'suggested_fix'],
        properties: {
          severity: { type: 'string', enum: ['blocking', 'nitpick', 'outside-diff'] },
          location: { type: 'string' },
          explanation: { type: 'string' },
          reproduce: { type: 'string', description: 'executed command + output for blocking claims' },
          suggested_fix: { type: 'string' },
        },
      },
    },
    per_file: {
      type: 'array',
      items: {
        type: 'object',
        required: ['file', 'verdict'],
        properties: { file: { type: 'string' }, verdict: { type: 'string' } },
      },
    },
  },
}

const VERDICT = {
  type: 'object',
  required: ['holds', 'evidence'],
  properties: {
    holds: { type: 'boolean', description: 'true iff the finding survives an attempt to refute it' },
    evidence: { type: 'string', description: 'the executed probe (command + output) that settles it' },
    revised_severity: { type: 'string', enum: ['blocking', 'nitpick', 'outside-diff'] },
  },
}

const COMMON = `You are an independent ADVERSARIAL reviewer of PR #${pr} (base ${base}) in a READ-ONLY checkout at ${worktree}. Diff: git -C ${worktree} diff origin/${base}...HEAD. Read surrounding code, not just hunks; you may run commands/gates but never edit, commit, or push. Ground every blocking correctness claim in an EXECUTED probe (command + output) where executable off-appliance — create scratch fixtures under /tmp, never inside the checkout. Files under .claude/skills/ponytail/ and .claude/skills/caveman/ are VENDORED byte-identical third-party trees (see their UPSTREAM provenance files) — do NOT review their content or style; only byte-identity with the pinned upstream ref and the UPSTREAM provenance are reviewable. Return structured findings; your output is the review. THE SPEC (review the diff AGAINST this; silently narrowed scope is a blocking finding): ${spec}`

phase('Find')

const LENSES = [
  { key: 'contract', prompt: `${COMMON}\nLENS: CONTRACT CONFORMANCE. Map every spec claim/acceptance criterion to where the diff satisfies it; flag unimplemented or narrowed items. Enumerate sibling axes the change touches (v4/v6, ports, CE/Plus, parse modes, every caller of touched symbols — from grep, not memory) and flag uncovered rows. Flag hardcoded env-derived literals. Give a per-file verdict for EVERY changed file.` },
  { key: 'correctness', prompt: `${COMMON}\nLENS: CORRECTNESS + HOSTILE INPUTS. Hunt logic errors, unreachable/dead branches, error paths (every filesystem/subprocess/network result checked or deliberately best-effort), races, and — for any parser/regex/guard — attack it with the CLAUDE.md hostile-input classes (punycode/IDN, empty, header/no-header, metacharacters, tabs/consecutive spaces, oversized, wrong encoding), EXECUTING probes. Per-file verdict for every changed file.` },
  { key: 'tests', prompt: `${COMMON}\nLENS: TEST HONESTY. For each new/changed test: does it carry an assertion that fails on regression; does every negative assertion have a fixture that could fail it (vacuity); is any red-run manufactured via a fault production cannot produce; are failure modes exercised through the production surface; is red->green evidence real (re-execute it: check out the pre-change tree for the src paths, run the named tests, restore). Also: does anything touch www/ without Tier-A coverage. Per-file verdict for every changed test file.` },
]

const found = await parallel(LENSES.map(l => () =>
  agent(l.prompt, { label: `find:${l.key}`, phase: 'Find', model: 'sonnet', effort: 'xhigh', schema: FINDINGS })))

// Barrier is deliberate: dedup across all lenses before paying for verification.
const clean = found.filter(Boolean)
const seen = new Set()
const merged = []
for (const r of clean) {
  for (const f of r.findings ?? []) {
    const key = `${f.location}|${f.explanation.slice(0, 80)}`
    if (!seen.has(key)) { seen.add(key); merged.push(f) }
  }
}
log(`${merged.length} unique findings from ${clean.length}/${LENSES.length} lenses`)

phase('Verify')

const verified = await parallel(merged.map(f => () =>
  agent(`${COMMON}\nVERIFY ONE FINDING — try to REFUTE it. Finding: [${f.severity}] ${f.location}: ${f.explanation}\nClaimed reproduction: ${f.reproduce}\nRe-derive it yourself: run the probe (or construct one), read the surrounding code, and decide whether it truly holds against the CURRENT branch tip. Default to holds=false if you cannot reproduce or ground it.`,
    { label: `verify:${f.location.slice(0, 40)}`, phase: 'Verify', model: 'sonnet', effort: 'xhigh', schema: VERDICT })
    .then(v => ({ ...f, verified: v }))))

const confirmed = verified.filter(Boolean).filter(f => f.verified?.holds)
  .map(f => ({ ...f, severity: f.verified.revised_severity ?? f.severity }))

return {
  confirmed,
  refuted: verified.filter(Boolean).filter(f => !f.verified?.holds).map(f => ({ location: f.location, explanation: f.explanation, evidence: f.verified?.evidence })),
  per_file: clean.flatMap(r => r.per_file ?? []),
  lenses_returned: clean.length,
}
