# pfBlockerNG session invariants

Never assume: read the source of truth and investigate live state. Claims require run artifacts. Before a bug fix, list at least two hypotheses and run a discriminating probe. Every behavior change requires an unchanged test executed red before the production edit and green afterward. Every change ships with tests that fail on regression. Read an entire GitHub issue, including comments, before working it. Substantial delegated implementation follows `.agents/policy/delegation.md`.
