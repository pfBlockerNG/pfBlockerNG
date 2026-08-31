# OMP adapter — pfBlockerNG

Scope: OMP-specific surfaces plus canonical-noun translation. Canonical policy is
`AGENTS.md` plus the routed `.agents/policy/` and `.agents/context/` files.

OMP loads `.omp/AGENTS.md` as the native project bootstrap and `.omp/RULES.md` as
sticky per-turn invariants. User configuration lives under the active OMP agent
directory (normally `~/.omp/agent`), not legacy `~/.pi`.

- Skills come from OMP marketplace plugins, native `skills/`, and the shared
  `.agents/skills/` provider. Prefer managed marketplace plugins for third-party
  bundles that ship hooks; never vendor them into this repository.
- Repository discovery uses CodeGraph first, then Serena or native LSP for exact
  language semantics, per `.agents/context/repository-intelligence.md`.
- The user-level OMP hook `~/.omp/agent/hooks/pre/pfblockerng-policy.ts`
  bridges the existing branch-freshness and Bash-guard scripts into OMP's
  `session_start` and `tool_call` events. Repository sticky rules replace the
  Claude `UserPromptSubmit` discipline hook for OMP.
- Set `OMP_CLI=1` in the active OMP agent `.env`; OMP mirrors it to `PI_CLI=1`.
  Both markers are inherited by child shells and recognized by
  `.githooks/prepare-commit-msg` and `.githooks/pre-push`.
- OMP adds no attribution to commits or public bodies. Commit identity and public content
  follow `git.md` and `landing.md`.
- Reviews use the repository role contracts in `.agents/policy/agent-roles.md`.
  When an exact custom role is unavailable, dispatch OMP's `reviewer` with that
  contract in the task brief rather than weakening the review.
