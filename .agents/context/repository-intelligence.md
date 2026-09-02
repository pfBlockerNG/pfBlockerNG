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
- CodeGraph and Graphify are mandatory. Canonical post-clone setup is
  `sh scripts/setup-hooks.sh`: it calls `scripts/agent/ensure-graphify.sh`, which
  installs or upgrades `graphifyy>=0.9.51` with `uv` and runs
  `scripts/agent/patch-graphify.sh`, before activating `.githooks`.
  `scripts/agent/resolve-graphify.sh` prefers the launcher selected by `PATH`,
  physically absolutizes a relative selection before returning it, and only when none
  exists resolves `uv tool dir --bin/graphify`; an arbitrary PATH wrapper remains
  authoritative and fails closed. A Python shebang is used directly. Only the
  exact uv-owned launcher may use uv's `/bin/sh` trampoline, in which case the resolver
  validates and uses the `graphifyy` tool environment's Python. Missing `uv` or a
  launcher/interpreter that cannot import its selected Graphify package fails closed.
  `setup-agent-tools.sh` runs this canonical setup at Graphify's install-order slot,
  before ast-grep and semgrep.
- Initialize a checkout with `sh scripts/agent/init-worktree-tools.sh .`. It runs
  `scripts/agent/ensure-codegraph.sh` for the exact-root CodeGraph index, reapplies
  the Graphify patch, then runs `graphify update <root>` when the root graph exists.
  When the graph is absent it prints a notice and builds nothing; first-build scope
  is a judgement call handled by a `/graphify` run. `wt --yes switch --create <branch>`
  runs it from `.config/wt.toml`'s `pre-start` hook. `work-branch.sh --worktree` cuts
  through `wt`, so that hook normally does the initializing; it calls the initializer
  itself only when the worktree came back without a CodeGraph index (the `git worktree`
  fallback, or a pre-start that did not run), and rolls back a failed cut either way.
- Graphify's suffix map parses `.inc` as Pascal, collapsing this repository's PHP
  includes from roughly 767 nodes to roughly 30 while extraction still succeeds.
  Until a release includes Graphify-Labs/graphify#3075, the fix rides as
  `.agents/patches/graphify-3075-language-overrides.patch`. The tracked
  `.graphifyrc` (`language.inc=php`) activates it. `ensure-graphify.sh` emits the
  validated absolute executable launcher path; `ensure-graphify-merge-driver.sh`
  captures and quotes that path for target-rooted `hook install`;
  `init-worktree-tools.sh` resolves the same launcher for update; and
  `.githooks/pre-commit` resolves and patches again
  before its no-staged-files exit, repairing a bare Graphify upgrade in a fresh process
  before the post-commit rebuild. The include-node floor in
  `tests/test_cross_agent_tooling.py`
  remains the final graph guard. Delete this machinery once the upstream change ships.
- Every worktree owns its `.codegraph/` index: run `codegraph init` when it is absent,
  and never borrow a parent or sibling tree's index. Before Serena symbolic edits,
  verify that its active project root equals `git rev-parse --show-toplevel`; after a
  mid-session worktree switch Serena is forbidden until a fresh top-level session starts
  there. Claude Agent Teams teammates use built-ins.
- `graphify-out/graph.json` is tracked, and records under `graphify-out/memory/` are tracked
  with the work that produced them; everything else under `graphify-out/` is ignored and
  regenerated locally.
  Refresh the graph with `graphify update <root>` and commit it alongside the change that
  moved it. Every clone needs the union merge driver that `.gitattributes` assigns to the
  graph — `scripts/agent/ensure-graphify-merge-driver.sh` installs Graphify, runs
  `graphify hook install`, and verifies the registration. Without it a merge leaves
  conflict markers in the graph instead of union-merging it.
- **CodeGraph owns purely code-related questions**, and is the first call for them:
  indexed code discovery, a named symbol's verbatim source, call paths, flows,
  cross-file structure, and blast radius. Use `codegraph_explore` or
  `codegraph explore`. Every client uses the same standard stdio MCP command:
  `codegraph serve --mcp`; CodeGraph is never an edge feed into Graphify and has no
  Graphify schema role.
- Use the authoritative code-only root graph at `graphify-out/graph.json` for
  Graphify query/path/explain/affected and test-impact work. Source ownership is
  inferred only from each node's `source_file`: `src/` is production, `tests/` is
  harness/test, and `stubs/` is shim/support; communities describe topology only.
  The root graph excludes `src/**/vendor/**`, documents/media, and `legacy/`.
- **Graphify owns what a code graph alone cannot answer**: semantics, meaning, and how
  people interact with the solution — product and documentation context, broad
  architecture review, community topology, and affected/test-impact work. Use
  `graphify query "<question>"`, `graphify path "<A>" "<B>"`, and
  `graphify explain "<concept>"`; they return a scoped subgraph. When a question is
  purely about code structure, CodeGraph answers it — reach for Graphify when the
  answer needs more than the code graph carries. Go to grep first
  for the three classes the graph does not model, because it indexes code structure and
  nothing else: configuration surfaces and tool wiring (which extensions a linter claims,
  where a tool is installed, what a hook runs), reference counts and other text-frequency
  questions, and a third-party tool's own feature set, which lives in its `--help`.
  Read `graphify-out/GRAPH_REPORT.md` only for broad architecture
  review, and `graphify-out/wiki/index.md`, when present, for navigation. A dirty
  `graphify-out/` after a hook or incremental update is expected and is not a reason to
  skip Graphify; skip it only when the task is about stale or incorrect graph output. Run
  `graphify update .` after modifying code (AST only, no API cost).
- Close the loop on every query: record it with `graphify save-result --question … --answer …
  --outcome useful|dead_end|corrected`. The boundary is where the answer came from:
  `useful` when the returned subgraph answered or narrowed the question,
  `dead_end` when another surface answered it,
  `corrected` when the graph answered and was wrong.
  A dead end MUST carry `--correction` naming the surface that actually answered it —
  an unexplained dead end is what makes the next session re-derive it. Records
  land in `graphify-out/memory/` and are committed with the work. `graphify reflect`
  aggregates them deterministically into `graphify-out/reflections/LESSONS.md`; that file
  is derivable, so it stays untracked — rebuild it, and read it for orientation before
  querying.
- Use `rg`, globbing, and file reads for literals, configuration, non-code files,
  and details CodeGraph did not cover. Use the client's LSP surface—Serena where
  available—for exact symbols, definitions, references, implementations,
  call/type hierarchy, diagnostics, and diagnostic-aware refactoring. The initializer
  runs `serena project index <root>` when Serena is available. Under OMP (`OMP_CLI`
  or `PI_CLI`), it skips Serena because OMP provides native LSP tooling.
- PHP includes are named `.inc`, and a tool that infers language from the extension
  silently skips them — indistinguishable from a clean no-match (issue #2807). The
  tracked `sgconfig.yml` fixes ast-grep; semgrep has no configuration equivalent, so
  always pass `semgrep --scan-unknown-extensions`.
- Compiler, static analysis, tests, CI, and live smoke remain final.
