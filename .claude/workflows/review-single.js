export const meta = {
  name: 'review-single',
  description: 'Single-agent adversarial PR review: ONE reviewer covers contract, correctness/hostile-inputs, and test-honesty; schema-forced findings',
  whenToUse: 'pr-merge-flow Step 1d\'s default review shape. Args: {pr: <number>, base: <branch>, worktree: <path>, spec: <intent/acceptance text>, model?: "sonnet" | "fable" (default sonnet; fable for a large/complex PR — >300 lines, >6 files, or src/ parsing/guard/scheduling behaviour)}.',
  phases: [
    { title: 'Review', detail: 'one adversarial reviewer over the whole diff' },
  ],
}

// Single-agent variant of review-fanout (pr-merge-flow's default since 2026-07-11):
// same schema-forced findings contract, no fan-out and no separate verify stage — the
// one reviewer must ground its own blocking claims in executed probes. Model is the
// bare family alias (resolves to the latest generation); Opus is rejected, effort is
// pinned xhigh (the flow's floor and ceiling); no ponytail (reviewers build nothing).

// Callers sometimes deliver args JSON-string-encoded (killed review-fanout on PR #937,
// issue #942) — normalize before destructuring instead of trusting caller discipline.
const input = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
const { pr, base = 'devel', worktree, spec = '(no spec provided — flag that as a finding)', model = 'sonnet' } = input
if (!pr || !worktree) throw new Error('args must be {pr, worktree, base?, spec?, model?}')
if (model !== 'sonnet' && model !== 'fable') throw new Error(`model must be "sonnet" or "fable" (never Opus, never a dated ID); got "${model}"`)

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

const PROMPT = `You are an independent ADVERSARIAL reviewer of PR #${pr} (base ${base}) in a READ-ONLY checkout at ${worktree}. Diff: git -C ${worktree} diff origin/${base}...HEAD. Read surrounding code, not just hunks; you may run commands/gates but never edit, commit, or push. Ground every blocking correctness claim in an EXECUTED probe (command + output) where executable off-appliance — create scratch fixtures under /tmp, never inside the checkout. Files under .claude/skills/ponytail/ and .claude/skills/caveman/ are VENDORED byte-identical third-party trees (see their UPSTREAM provenance files) — do NOT review their content or style; only byte-identity with the pinned upstream ref and the UPSTREAM provenance are reviewable. Return structured findings; your output is the review. THE SPEC (review the diff AGAINST this; silently narrowed scope is a blocking finding): ${spec}

You alone cover ALL of the following lenses — none may be skipped:

1. CONTRACT CONFORMANCE. Map every spec claim/acceptance criterion to where the diff satisfies it; flag unimplemented or narrowed items. Enumerate sibling axes the change touches (v4/v6, ports, CE/Plus, parse modes, every caller of touched symbols — from grep, not memory) and flag uncovered rows. Flag hardcoded env-derived literals.

2. CORRECTNESS + HOSTILE INPUTS. Hunt logic errors, unreachable/dead branches, error paths (every filesystem/subprocess/network result checked or deliberately best-effort), races, and — for any parser/regex/guard — attack it with the CLAUDE.md hostile-input classes (punycode/IDN, empty, header/no-header, metacharacters, tabs/consecutive spaces, oversized, wrong encoding), EXECUTING probes.

3. TEST HONESTY. For each new/changed test: does it carry an assertion that fails on regression; does every negative assertion have a fixture that could fail it (vacuity); is any red-run manufactured via a fault production cannot produce; are failure modes exercised through the production surface; is red->green evidence real (re-execute it: check out the pre-change tree for the src paths, run the named tests, restore). Also: does anything touch www/ without Tier-A coverage.

Before returning, try to REFUTE each of your own blocking findings — re-derive the probe against the current branch tip and drop (or downgrade) anything you cannot reproduce or ground. Give a per-file verdict for EVERY changed file (findings / considered-and-fine / not-examined-because).`

phase('Review')

const review = await agent(PROMPT, { label: `review:pr-${pr}`, phase: 'Review', model, effort: 'xhigh', schema: FINDINGS })
if (!review) throw new Error('reviewer agent returned no result')

log(`${(review.findings ?? []).length} findings across ${(review.per_file ?? []).length} files (model: ${model})`)

return { ...review, model }
