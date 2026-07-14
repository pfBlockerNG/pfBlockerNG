export const meta = {
  name: 'review-single',
  description: 'Single-agent adversarial PR review: ONE reviewer covers contract, correctness/hostile-inputs, and test-honesty; schema-forced findings',
  whenToUse: 'pr-merge-flow Step 1d\'s default review shape. Args: {pr: <number>, base: <branch, or a bare pre-fix SHA to review ONLY the fix delta — mandatory scoping for feedback-fix re-reviews>, worktree: <path>, spec: <intent/acceptance text>, model?: "sonnet" (default; also the model for every delta re-review) | "fable" (large/complex PR: >300 lines, >6 files, or src/ parsing/guard/scheduling behaviour — whole-PR cross-referencing) | "opus" (ONLY as the second pass of the dual fallback: top tier unavailable on a fable-grade PR -> run once with sonnet and once with opus, union the findings), profile?: "full" (default) | "verify" (mechanically-trivial data/pin/config diffs ONLY — the caller applies pr-merge-flow\'s objective no-new-control-flow gate before choosing it)}.',
  phases: [
    { title: 'Review', detail: 'one adversarial reviewer over the whole diff' },
  ],
}

// Single-agent variant of review-fanout (pr-merge-flow's default since 2026-07-11):
// same schema-forced findings contract, no fan-out and no separate verify stage — the
// one reviewer must ground its own blocking claims in executed probes. Model is the
// bare family alias (resolves to the latest generation). Effort: xhigh for the full
// profile (the flow's floor and ceiling); the verify profile runs at high — owner
// authorization 2026-07-14: "do all 6" (item 6 of the review-speed batch). No ponytail
// (reviewers build nothing; the SubagentStart capsule's review carve-out applies).

// Callers sometimes deliver args JSON-string-encoded (killed review-fanout on PR #937,
// issue #942) — normalize before destructuring instead of trusting caller discipline.
const input = typeof args === 'string' ? JSON.parse(args) : (args ?? {})
const { pr, base = 'devel', worktree, spec = '(no spec provided — flag that as a finding)', model = 'sonnet', profile = 'full' } = input
// A bare SHA base reviews a fix delta (pr-merge-flow 1d.4); a branch name gets origin/.
const baseRef = /^[0-9a-f]{7,40}$/.test(base) ? base : `origin/${base}`
if (!pr || !worktree) throw new Error('args must be {pr, worktree, base?, spec?, model?, profile?}')
// Owner directive (2026-07-14): fable (the highest tier) reviews large/complex PRs —
// whole-PR cross-referencing; sonnet is the default AND the model for every delta
// re-review. opus is valid ONLY as the second pass of the dual fallback (top tier
// unavailable on a fable-grade PR: one sonnet + one opus run, findings unioned by the
// caller) — never a sole reviewer.
if (model !== 'sonnet' && model !== 'fable' && model !== 'opus') throw new Error(`model must be "sonnet", "fable", or "opus" (opus only as the dual-fallback second pass; never a dated ID); got "${model}"`)
if (profile !== 'full' && profile !== 'verify') throw new Error(`profile must be "full" or "verify"; got "${profile}"`)

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

// Shared tooling + output discipline (both profiles). TS covers this repo's PHP/inc/sh
// since the fork pin; rtk proxies compact common command output (a PreToolUse hook also
// auto-rewrites bare git/gh, but the read/diff/test forms need explicit use).
const TOOLING = `TOOLING: to locate symbols or read a single function/class body, prefer the token-savior-recall MCP tools (load via ToolSearch: search_codebase, find_symbol, get_function_source, get_call_chain) over Reading whole files; fall back to Read/Grep only for files the index does not cover. For shell output, prefer rtk proxy forms (rtk read <file>, rtk diff, rtk git ..., rtk gh ..., rtk test -- <cmd>) — compact output, same exit codes. OUTPUT DISCIPLINE: per_file verdicts and finding explanations are TERSE — defect, evidence pointer, done; no essays. Quoted command output, error strings, and code stay byte-exact and complete; compress only your connective prose.`

const FULL_PROMPT = `You are an independent ADVERSARIAL reviewer of PR #${pr} (base ${baseRef}) in a READ-ONLY checkout at ${worktree}. Diff: git -C ${worktree} diff ${baseRef}...HEAD. Read surrounding code, not just hunks; you may run commands/gates but never edit, commit, or push. Ground every blocking correctness claim in an EXECUTED probe (command + output) where executable off-appliance — create scratch fixtures under /tmp, never inside the checkout. Probes are TARGETED: never re-run whole test suites for their own sake (CI and the delegation gate already run them); a suite run is justified only when a specific finding needs exactly that evidence. Files under .claude/skills/ponytail/ and .claude/skills/caveman/ are VENDORED byte-identical third-party trees (see their UPSTREAM provenance files) — do NOT review their content or style; only byte-identity with the pinned upstream ref and the UPSTREAM provenance are reviewable. ${TOOLING} Return structured findings; your output is the review. THE SPEC (review the diff AGAINST this; silently narrowed scope is a blocking finding): ${spec}

You alone cover ALL of the following lenses — none may be skipped:

1. CONTRACT CONFORMANCE. Map every spec claim/acceptance criterion to where the diff satisfies it; flag unimplemented or narrowed items. Enumerate sibling axes the change touches (v4/v6, ports, CE/Plus, parse modes, every caller of touched symbols — from grep, not memory) and flag uncovered rows. Flag hardcoded env-derived literals.

2. CORRECTNESS + HOSTILE INPUTS. Hunt logic errors, unreachable/dead branches, error paths (every filesystem/subprocess/network result checked or deliberately best-effort), races, security holes, CLAUDE.md/code-standard violations, stale comments/docs about touched symbols, and — for any parser/regex/guard — attack it with the CLAUDE.md hostile-input classes (punycode/IDN, empty, header/no-header, metacharacters, tabs/consecutive spaces, oversized, wrong encoding), EXECUTING probes.

3. TEST HONESTY. For each new/changed test: does it carry an assertion that fails on regression; does every negative assertion have a fixture that could fail it (vacuity); is any red-run manufactured via a fault production cannot produce; are failure modes exercised through the production surface; is red->green evidence real (re-execute it: check out the pre-change tree for the src paths, run the named tests, restore). Also: does anything touch www/ without Tier-A coverage.

Before returning, try to REFUTE each of your own blocking findings — re-derive the probe against the current branch tip and drop (or downgrade) anything you cannot reproduce or ground. Give a per-file verdict for EVERY changed file (findings / considered-and-fine / not-examined-because).`

// verify profile: claims-verification for diffs the caller's mechanical gate certified
// as adding NO control flow (data/pin/config-only). Every spec claim still gets an
// executed probe; duty 1 below is the accuracy backstop — a misclassified diff comes
// back as a blocking escalation finding, never a silently lighter review.
const VERIFY_PROMPT = `You are an independent ADVERSARIAL claims-verifier of PR #${pr} (base ${baseRef}) in a READ-ONLY checkout at ${worktree}. Diff: git -C ${worktree} diff ${baseRef}...HEAD. The caller classified this diff as mechanically trivial: data/pin/config-only, NO new control flow. You may run commands but never edit, commit, or push; scratch fixtures under /tmp only. ${TOOLING} THE SPEC (every claim below must be PROBED, not read): ${spec}

Your duties:

1. GATE CHECK FIRST. Scan the diff's added lines yourself. If ANY added line introduces control flow or executable logic (a branch, loop, function definition, pipeline, subshell, or command substitution beyond a literal value), STOP probing and return ONE blocking finding: "profile escalation required — diff is not mechanically trivial", citing the offending lines. The caller must re-run the full profile.

2. PROBE EVERY SPEC CLAIM with an executed command: pinned refs/SHAs exist where claimed and have the claimed lineage (e.g. gh api compare); changed values match the sources they cite; each touched file is byte-identical to base outside the claimed hunks; new/changed ignore or config entries hit their intended targets and nothing tracked (git check-ignore, git ls-files probes); replaced literals leave no stale copies tree-wide (git grep old AND new values).

3. EXISTING TESTS. Run only the suites the spec names as pinning the touched contracts; confirm green unmodified.

Give a per-file verdict for EVERY changed file. Blocking claims need executed evidence, same as the full profile.`

phase('Review')

const effort = profile === 'verify' ? 'high' : 'xhigh'
const review = await agent(profile === 'verify' ? VERIFY_PROMPT : FULL_PROMPT, { label: `review:pr-${pr}:${profile}`, phase: 'Review', model, effort, schema: FINDINGS })
if (!review) throw new Error('reviewer agent returned no result')

log(`${(review.findings ?? []).length} findings across ${(review.per_file ?? []).length} files (model: ${model}, profile: ${profile})`)

return { ...review, model, profile }
