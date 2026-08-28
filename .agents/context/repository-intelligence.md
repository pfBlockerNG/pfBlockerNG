# Repository intelligence

Scope: cross-client repository discovery, exact code semantics, and persistent graphs.
Load when: every agent session, from `AGENTS.md`.

- Bootstrap or refresh a macOS/Debian agent host with
  `sh scripts/agent/setup-agent-tools.sh <checkout>`. It installs or updates uv,
  Serena, CodeGraph, Graphify, and Worktrunk; configures only detected clients;
  disables Serena's web dashboard; and keeps Worktrunk worktrees outside the
  repository root.
- Every agent tool installs through one command that both installs on a fresh host
  and upgrades an outdated one — `uv tool install --upgrade <tool>`, `codegraph upgrade`,
  or the tool's own installer. A `>=` floor rides along only when a minimum release is
  required; an exact `==` pin is never the answer, because it makes every upstream
  release wait on a repository commit and downgrades a host that is already ahead.
  When a setup script fails because a dependency is absent, that missing dependency is
  installed the same way, never pinned to whatever version the failure happened to name.
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
- Every worktree owns its `.codegraph/` index: run `codegraph init` when it is absent,
  and never borrow a parent or sibling tree's index. Before Serena symbolic edits,
  verify that its active project root equals `git rev-parse --show-toplevel`; after a
  mid-session worktree switch Serena is forbidden until a fresh top-level session starts
  there. Claude Agent Teams teammates use built-ins.
- `graphify-out/graph.json` is tracked; everything else under `graphify-out/` is ignored
  and regenerated locally from it. Refresh the graph with `graphify update <root>` and
  commit it alongside the change that moved it. Every clone needs the union merge driver
  that `.gitattributes` assigns to the graph — `scripts/agent/ensure-graphify-merge-driver.sh`
  installs Graphify, runs `graphify hook install`, and verifies the registration. Without
  it a merge leaves conflict markers in the graph instead of union-merging it.
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
- Prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, and
  `graphify explain "<concept>"` over raw grep and file reads for codebase questions:
  they return a scoped subgraph. Read `graphify-out/GRAPH_REPORT.md` only for broad
  architecture review, and `graphify-out/wiki/index.md`, when present, for navigation.
  A dirty `graphify-out/` after a hook or incremental update is expected and is not a
  reason to skip Graphify; skip it only when the task is about stale or incorrect graph
  output. Run `graphify update .` after modifying code (AST only, no API cost).
- Use `rg`, globbing, and file reads for literals, configuration, non-code files,
  and details CodeGraph did not cover. Use the client's LSP surface—Serena where
  available—for exact symbols, definitions, references, implementations,
  call/type hierarchy, diagnostics, and diagnostic-aware refactoring. The initializer
  runs `serena project index <root>` when Serena is available. Under OMP (`OMP_CLI`
  or `PI_CLI`), it skips Serena because OMP provides native LSP tooling.
- PHP include files carry the `.inc` extension, and every tool that infers language
  from the extension has to be told so, or it reports zero matches with exit status 0 —
  indistinguishable from a genuine "no matches" (issue #2807). `phpcs.xml.dist`,
  `phpstan.neon`, `.editorconfig`, `.vscode/settings.json`, and the tracked
  `sgconfig.yml` (ast-grep) already carry the association. Semgrep exposes no
  configuration-file or environment-variable equivalent, so always pass
  `semgrep --scan-unknown-extensions` when a scan may reach a `.inc` file.
- Compiler, static analysis, tests, CI, and live smoke remain final.
