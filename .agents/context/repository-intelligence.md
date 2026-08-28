# Repository intelligence

Scope: cross-client repository discovery, exact code semantics, and persistent graphs.
Load when: every agent session, from `AGENTS.md`.

- Bootstrap or refresh a macOS/Debian agent host with
  `sh scripts/agent/setup-agent-tools.sh <checkout>`. It installs or updates uv,
  Serena, CodeGraph, Graphify, and Worktrunk; configures only detected clients;
  disables Serena's web dashboard; and keeps Worktrunk worktrees outside the
  repository root.
- Initialize a checkout with `sh scripts/agent/init-worktree-tools.sh .`.
  `work-branch.sh --worktree` runs the same initializer after creating a worktree and
  removes the new worktree and branch if initialization fails; it uses Git directly
  and does not require Worktrunk. For `wt --yes switch --create <branch>`, the tracked
  `.config/wt.toml` runs the initializer as its `pre-start` hook and prunes worktree metadata after
  Worktrunk merge and remove operations.
- CodeGraph and Graphify are mandatory. The initializer runs
  `scripts/agent/ensure-codegraph.sh` for the exact-root CodeGraph index first,
  then runs `graphify update <root>` when the root graph already exists. When the
  root graph is absent the initializer prints a notice and builds nothing: the
  first build's scope is a judgement call, so create it with a `/graphify` run in
  an AI assistant. Install or refresh Graphify in one command with
  `uv tool install --upgrade 'graphifyy>=0.9.51'` — a floor, never an exact pin, so a
  fresh host and an outdated one both land on the current release.
- Every worktree owns its ignored and untracked `graphify-out/` graph. Refresh it
  directly with `graphify update <root>`; there is no shared repository graph.
- For indexed code discovery, understanding, cross-file architecture, call paths,
  flows, structural exploration, and impact analysis, use CodeGraph through
  `codegraph_explore` or `codegraph explore`. Every client uses the same standard
  stdio MCP command: `codegraph serve --mcp`; CodeGraph is never an edge feed into
  Graphify and has no Graphify schema role.
- Use the authoritative code-only root graph at `graphify-out/graph.json` for
  Graphify query/path/explain/affected and test-impact work. Source ownership is
  inferred only from each node's `source_file`: `src/` is production, `tests/` is
  harness/test, and `stubs/` is shim/support; communities describe topology only.
  The root graph excludes `src/**/vendor/**`, documents/media, and `legacy/`.
- Use `rg`, globbing, and file reads for literals, configuration, non-code files,
  and details CodeGraph did not cover. Use the client's LSP surface—Serena where
  available—for exact symbols, definitions, references, implementations,
  call/type hierarchy, diagnostics, and diagnostic-aware refactoring. The initializer
  runs `serena project index <root>` when Serena is available. Under OMP (`OMP_CLI`
  or `PI_CLI`), it skips Serena because OMP provides native LSP tooling.
- Compiler, static analysis, tests, CI, and live smoke remain final.
