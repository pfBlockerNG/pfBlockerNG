# Repository intelligence

Scope: cross-client repository discovery and exact code semantics.
Load when: every agent session, from `AGENTS.md`.

Which tool: CodeGraph (`codegraph explore`) first, for questions inside code (symbols,
call paths, blast radius); the harness's native LSP, otherwise Serena, for definitions,
references, and refactors (renames, moves, symbol edits); Grep/Read for anything outside
code (docs, specs, policy, decisions) and for exact lines those tools already located.
The tools' hook nudges are requirements, not hints.

- Bootstrap or refresh a macOS/Debian agent host with
  `sh scripts/agent/setup-agent-tools.sh <checkout>`. It installs uv when absent and
  never updates an installed one (#3106); installs or updates Serena, CodeGraph, and
  Worktrunk; configures only detected clients; disables Serena's web
  dashboard; and keeps Worktrunk worktrees outside the repository root.
- Every agent tool installs through one command that both installs on a fresh host
  and upgrades an outdated one — `uv tool install --upgrade <tool>`, `codegraph upgrade`,
  or the tool's own installer. A `>=` floor rides along only when a minimum release is
  required; an exact `==` pin is never the answer, because it makes every upstream
  release wait on a repository commit and downgrades a host that is already ahead.
  When a setup script fails because a dependency is absent, that missing dependency is
  installed the same way, never pinned to whatever version the failure happened to name.
- CodeGraph is mandatory. Canonical post-clone setup is `sh scripts/setup-hooks.sh`: it
  activates `.githooks` and, when CodeGraph is installed, creates the checkout's
  exact-root index.
- Initialize a checkout with `sh scripts/agent/init-worktree-tools.sh .`. It runs
  `scripts/agent/ensure-codegraph.sh` for the exact-root CodeGraph index.
  `wt --yes switch --create <branch>` runs it from `.config/wt.toml`'s `pre-start`
  hook. `work-branch.sh --worktree` cuts through `wt`, skips the initializer when
  pre-start already left a CodeGraph index, and rolls back a failed cut -- reclaiming
  a tree `wt` left behind when its hook failed.
- Every worktree owns its `.codegraph/` index: run `codegraph init` when it is absent,
  and never borrow a parent or sibling tree's index. Before Serena symbolic edits,
  verify that its active project root equals `git rev-parse --show-toplevel`; after a
  mid-session worktree switch Serena is forbidden until a fresh top-level session starts
  there. Claude Agent Teams teammates use built-ins.
- Each index runs its own CodeGraph daemon, registered in `~/.codegraph/daemons/*.json`
  (`root`, `pid`). Stop it before `wt remove` — the entry whose `root` is the worktree
  path, `kill -TERM <pid>` (interactive: `codegraph daemon`) — otherwise the removed
  `codegraph.db` stays pinned on disk until the daemon exits on its own.
- **CodeGraph owns purely code-related questions**, and is the first call for them:
  indexed code discovery, a named symbol's verbatim source, call paths, flows,
  cross-file structure, and blast radius. Use `codegraph_explore` or
  `codegraph explore`. Every client uses the same standard stdio MCP command:
  `codegraph serve --mcp`. Go to grep first for the three classes it does not model,
  because it indexes code structure and nothing else: configuration surfaces and tool
  wiring (which extensions a linter claims, where a tool is installed, what a hook
  runs), reference counts and other text-frequency questions, and a third-party tool's
  own feature set, which lives in its `--help`.
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
