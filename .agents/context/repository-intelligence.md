# Repository intelligence

Scope: cross-client repository discovery, exact code semantics, and persistent graphs.
Load when: every agent session, from `AGENTS.md`.

- Run `sh scripts/agent/ensure-codegraph.sh` at session start. It is exact-root and
  idempotent; `work-branch.sh --worktree` also runs it for worktrees created by
  Codex, Claude, Copilot, or Grok.
- For indexed code discovery, understanding, cross-file architecture, call paths,
  flows, structural exploration, and impact analysis, use CodeGraph first through
  `codegraph_explore` or `codegraph explore`. Every client uses the same standard
  stdio MCP command: `codegraph serve --mcp`.
- Use `rg`, globbing, and file reads for literals, configuration, non-code files, and
  details CodeGraph did not cover.
- Use the client's LSP surface—Serena where available—for exact symbols,
  definitions, references, implementations, call/type hierarchy, diagnostics, and
  diagnostic-aware refactoring.
- Use Graphify for semantic, rationale, cross-document, and test-contract exploration
  only when the worktree-local `graphify-out/graph.json` exists or the task justifies
  seeding it from the primary checkout. Update only affected `src`, `scripts`,
  `.github`, or `tests` subgraphs, merge the first three into the root production
  graph, and never share live Graphify output between worktrees.
- LSP/Serena language-semantic relationships override structurally inferred
  CodeGraph edges. Compiler, static analysis, tests, CI, and live smoke remain final.
