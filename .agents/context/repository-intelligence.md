# Repository intelligence

Scope: cross-client repository discovery, exact code semantics, and persistent graphs.
Load when: every agent session, from `AGENTS.md`.

- Run `sh scripts/agent/ensure-codegraph.sh` at session start. It is exact-root and
  idempotent; `work-branch.sh --worktree` also runs it for every worktree it creates.
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
- Use `rg`, globbing, and file reads for literals, configuration, non-code files, and
  details CodeGraph did not cover. Use the client's LSP surface—Serena where
  available—for exact symbols, definitions, references, implementations,
  call/type hierarchy, diagnostics, and diagnostic-aware refactoring.
- `work-branch.sh --worktree` restores an exact source-SHA snapshot from the local
  Graphify store. `GRAPHIFY-REFRESH-REQUIRED` means hold `.git/graphify-store.lock`
  in one harness-tracked `lockf`/`flock` session; create a temporary detached builder
  at the reported source SHA; run `graphify-store.py seed`, refresh with Graphify
  0.9.48 in the foreground using `PYTHONHASHSEED=0` and `--code-only` with
  `GRAPHIFY_VIZ_NODE_LIMIT=0` (the default `--no-viz` policy), then run
  `graphify-store.py publish`; release/remove the builder and retry. The store
  archives exactly `graph.json` and `GRAPH_REPORT.md` and rejects a refresh when
  `graphify-out/memory` or other non-canonical roots are present.
- Canonical refreshes use `PYTHONHASHSEED=0 GRAPHIFY_VIZ_NODE_LIMIT=0 graphify
  extract . --code-only --force`; no semantic agents, HTML, hooks, merge drivers,
  views, or generated artifacts are repository contracts. The exact-SHA store
  stores/restores only the root `graphify-out/graph.json` and
  `graphify-out/GRAPH_REPORT.md`; both remain ignored and untracked locally.
  Compiler, static analysis, tests, CI, and live smoke remain final.
