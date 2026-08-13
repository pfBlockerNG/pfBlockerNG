# ADR archive — historical records

Everything under `.ADRs/` — ADR bodies, phase-prompt `.txt` files, and per-phase
`RESULTS/` artifacts — is an **immutable historical record** (CLAUDE.md "Applying
review findings"): later changes append dated amendments, never rewrites.

**Dated note (2026-07-17, issue #1431):** these records reference orchestration
surfaces retired by the wayfinder cutover (map #1383) — the `/adr-phase`,
`/adr-create`, `/adr-all`, `/adr-list`, `/gh-issue`, `/delegate`, `/pr-merge-flow`,
`/pr-merge`, `/pr-comments`, `/spec-lint` skills, the `.claude/workflows/*.js`
programs (`adr-investigate`, `issue-triage`, `phase-step`, `review-single`,
`review-fanout`, `triage-findings`), and `scripts/check_phase_prompts.py`. Those
references are kept as-is here; the current flow lives in
`.agents/policy/workflow.md` and `.agents/policy/landing.md`. New
implementation-plan ADRs are no longer created.
