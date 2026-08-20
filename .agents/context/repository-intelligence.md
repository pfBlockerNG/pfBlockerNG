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
- After relevant classified-source changes, run
  `scripts/agent/update_graphify_views.py`. Query the worktree-local
  `graphify-out/graph.json` (investigation) by default; use
  `graphify-out/runtime/graph.json` for ownership questions, then follow each
  reference edge's `target_view` and `source_file`. Outputs stay worktree-local
  and are never shared between worktrees.
- LSP/Serena language-semantic relationships override structurally inferred
  CodeGraph edges. Compiler, static analysis, tests, CI, and live smoke remain final.
