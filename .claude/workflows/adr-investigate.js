export const meta = {
  name: 'adr-investigate',
  description: 'Investigation fan-out for a big ADR: parallel per-area readers return evidence-tagged load-bearing facts, risks, prior art, and open questions',
  whenToUse: 'Called by /adr-create Step 2 when the ADR spans more than ~2 components. Args: {topic, repoRoot, areas: [{key, focus, hints?}]}. Every returned fact is tagged verified (with its command/file:line evidence) or assumed — assumed facts must be probed before a phase relies on them (CLAUDE.md "Evidence rules"). The CALLER does the design; this only gathers grounded facts.',
  phases: [{ title: 'Investigate', detail: 'one reader per area, evidence-tagged facts' }],
}

// ADR quality lives and dies on §1's load-bearing facts: ADR-59 shipped wrong
// column indexes for feeds nobody had fetched; ADR-53's strength was facts
// "verified live this session". This fan-out makes the evidence-per-fact rule
// the output SCHEMA, so an unverified fact cannot masquerade as a verified one.

const { topic, repoRoot, areas } = args ?? {}
if (!topic || !repoRoot || !Array.isArray(areas) || areas.length === 0) {
  throw new Error('args must include {topic, repoRoot, areas: [{key, focus}]}; see meta.whenToUse')
}

const AREA_REPORT = {
  type: 'object',
  required: ['area', 'facts', 'risks', 'prior_art', 'open_questions'],
  properties: {
    area: { type: 'string' },
    facts: {
      type: 'array',
      items: {
        type: 'object',
        required: ['fact', 'confidence', 'evidence'],
        properties: {
          fact: { type: 'string', description: 'one load-bearing fact, stated precisely' },
          confidence: { type: 'string', enum: ['verified', 'assumed'] },
          evidence: { type: 'string', description: 'verified: the command + output tail, or file:line quoted. assumed: what probe would verify it' },
        },
      },
    },
    risks: { type: 'array', items: { type: 'string' }, description: 'hidden coupling, concurrency, chroot/platform limits, failure/recovery scope' },
    prior_art: { type: 'array', items: { type: 'string' }, description: 'in-repo helpers/knobs that already solve part of this (grep evidence), and platform/stdlib options' },
    open_questions: { type: 'array', items: { type: 'string' }, description: 'genuine forks the ADR author must settle with the user' },
  },
}

phase('Investigate')

const reports = await parallel(areas.map(a => () =>
  agent(`You are a READ-ONLY investigator grounding a future ADR. Repo checkout: ${repoRoot}. Never edit/commit; read code, grep, run read-only probes (php -r one-liners, python3 -c, git log/blame) freely — an executed probe beats a code reading.

ADR TOPIC: ${topic}
YOUR AREA: ${a.key} — ${a.focus}
${a.hints ? `STARTING POINTS: ${a.hints}` : ''}

Produce the area report per the schema. Rules (CLAUDE.md "Evidence rules" + /adr-create Step 2):
- Every fact is tagged: "verified" carries the command + output tail or the exact file:line you read; "assumed" carries the probe that WOULD verify it. Never launder an assumption as verified.
- Hunt prior art before anything else: an existing knob/helper the design would otherwise reinvent (in-repo grep) and how the platform/stdlib already solves it.
- Third-party/external formats and platform behaviours are verified by fetching/probing, never from memory (the ADR-59 domain_col lesson).
- Risks: hidden coupling, concurrent writers, chroot path rules, no-live-Unbound-in-CI, POSIX-sh-only — whatever your area actually touches.
- Open questions are genuine user forks only, not things another grep would settle (settle those yourself, now).`,
    { label: `investigate:${a.key}`, phase: 'Investigate', model: 'sonnet', effort: 'xhigh', schema: AREA_REPORT })))

const clean = reports.filter(Boolean)
log(`${clean.length}/${areas.length} areas returned; ${clean.flatMap(r => r.facts).filter(f => f.confidence === 'assumed').length} facts still ASSUMED`)
return {
  reports: clean,
  missing_areas: areas.filter((a, i) => !reports[i]).map(a => a.key),
}
