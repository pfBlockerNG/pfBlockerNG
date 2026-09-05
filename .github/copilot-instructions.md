# Copilot instructions — pfBlockerNG

[`AGENTS.md`](../AGENTS.md) is the canonical vendor-neutral agent policy bootstrap; this file is the GitHub Copilot adapter and pull-request review instructions. Copilot noun translation lives in [`.agents/context/copilot-adapter.md`](../.agents/context/copilot-adapter.md).

Hard invariants in `AGENTS.md` never-list, not restated here: work in a dedicated worktree, rebase onto live base before each push, land fully gated PRs by squash or fast-forward, keep linear history, ship tests with every change and red-to-green proof, route every config field through `PfbConfig`, never invoke Python directly on the appliance, and use POSIX shell only.

## Copilot Code Review Instructions

When performing a pull request code review on GitHub, strictly enforce the following scoping boundaries:

### 1. Explicitly Excluded Paths (DO NOT REVIEW)

Do NOT review, inspect, or comment on any of the following paths or patterns. Treat them as excluded content:

- **Generated code graphs and metadata:**
  - `graphify-out/**` (JSON/HTML graph rebuilds, summaries, and graph reports)
  - `.codegraph/**` (internal code intelligence indices and SQLite databases)
- **Documentation and archives:**
  - `docs/**` (design documents, runbooks, historical records, and incidents)
  - `legacy/**` (historical ADR corpus, benchmarks, and legacy tools)
  - `**/*.md` (all Markdown files across the repository, including `.agents/`, `.claude/`, `.github/`, and root `.md` files, unless the pull request is explicitly scoped to documentation or policy changes)
- **Agent configuration and runtime definitions:**
  - `.agents/**` (agent policies, context notes, and model configurations)
  - `.claude/**`, `.codex/**`, `.github/agents/**`, `.github/instructions/**`
- **Vendored and dependency assets:**
  - `vendor/**`, `node_modules/**`, `**/node_modules/**`

### 2. On-Demand Documentation Access

Do NOT crawl or read repository documentation, policy files, or architectural notes upfront.

- Only open and read specific reference documentation when strictly necessary to understand a domain rule in the exact code lines being changed.
- For language guidelines: consult `.agents/policy/coding.md` or `.agents/context/lang-<php|python|shell>.md` only if evaluating non-obvious language conventions for touched production code.
- For test conventions: consult `.agents/policy/testing.md` only when reviewing test assertions or coverage rules.
- Do not cite or comment on documentation files that are not part of the active code diff.

### 3. Review Focus & Priorities

Focus exclusively on production code (`src/**`) and test files (`tests/**`):

- **Correctness & Logic:** Unhandled edge cases, null/type errors, off-by-one errors, race conditions, memory leaks, resource cleanup failures, and broken control flow.
- **Security & Validation:** Hostile inputs, unescaped shell execution, command injection, path traversal, and authorization/privilege boundary crossings.
- **Test Integrity:** Ensure tests assert observable behavior and fail on regression; flag coverage theater or vacuous assertions.
- **Noise Suppression:** Do NOT flag formatting, whitespace, import ordering, or stylistic preferences that automated linters/formatters (Ruff, PHPCS, markdownlint) enforce.

## Copilot-only surfaces

- Skills discovered from `.agents/skills/` (canonical) and `.claude/skills/` symlinks onto it — no Copilot-specific copy exists or should be created.
- Custom agents live in `.github/agents/*.agent.md`, tiered per `.agents/model-tiers.conf`.
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect session through `COPILOT_CLI`, which CLI exports into every shell it spawns. Never unset to dodge guard it trips.
- Copilot adds no commit or public-body attribution. Configured user identity remains authoritative.
