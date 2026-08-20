# Repository intelligence

Scope: cross-client repository discovery, exact code semantics, and persistent graphs.
Load when: every agent session, from `AGENTS.md`.

- Run `sh scripts/agent/ensure-codegraph.sh` at session start. It is exact-root and
  idempotent; `work-branch.sh --worktree` also runs it for every worktree it creates.
- For indexed code discovery, understanding, cross-file architecture, call paths,
  flows, structural exploration, and impact analysis, use CodeGraph first through
  `codegraph_explore` or `codegraph explore`. Every client uses the same standard
  stdio MCP command: `codegraph serve --mcp`.
- Use `rg`, globbing, and file reads for literals, configuration, non-code files, and
  details CodeGraph did not cover.
- Use the client's LSP surface—Serena where available—for exact symbols,
  definitions, references, implementations, call/type hierarchy, diagnostics, and
  diagnostic-aware refactoring.
- `work-branch.sh --worktree` restores an exact source-SHA snapshot from the local
  branch-mirrored Graphify store. `GRAPHIFY-REFRESH-REQUIRED` means delegate a
  top-tier/high Graphify coordinator: hold `.git/graphify-store.lock` in one
  harness-tracked `lockf`/`flock` session; create a temporary detached builder at
  the reported source SHA; run `graphify-store.py seed`, the full Graphify update
  skill, then `graphify-store.py publish`; release/remove the builder and retry
  `work-branch.sh`. Each agent worktree receives its own snapshot copy.
- After relevant classified-source changes, run `update_graphify_views.py` in that
  worktree. Query `graphify-out/current/graph.json` (investigation) by default;
  use `current/runtime/graph.json` for ownership and `current/agent-context/graph.json`
  for process improvement; follow `target_view`/`source_file` references.
- LSP/Serena language-semantic relationships override structurally inferred
  CodeGraph edges. Compiler, static analysis, tests, CI, and live smoke remain final.
