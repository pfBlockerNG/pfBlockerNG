# Repository intelligence

Scope: cross-client repository discovery and exact code semantics.
Load when: every agent session, from `AGENTS.md`.

Which tool: the harness's native LSP, where it has one, for definitions, references, and
refactors (renames, moves, symbol edits); `rg`, globbing, and file reads for everything
else. Work in the task's worktree, never the primary checkout, and check edits with
`git -C <worktree> diff`.

- Bootstrap or refresh a macOS/Debian agent host with
  `sh scripts/agent/setup-agent-tools.sh <checkout>`. It installs uv when absent and
  never updates an installed one (#3106); installs or updates ast-grep, semgrep, and
  Worktrunk; and sets Worktrunk's `worktree-path` to `<repo>/.worktrees/`. That setting
  is host-wide: this repository ignores the folder (`.gitignore`, `init-worktree-tools.sh`), and
  any other repository needs its own ignore of it.
- Every agent tool installs through one command that both installs on a fresh host
  and upgrades an outdated one — `uv tool install --upgrade <tool>` or the tool's own
  installer. A `>=` floor rides along only when a minimum release is
  required; an exact `==` pin is never the answer, because it makes every upstream
  release wait on a repository commit and downgrades a host that is already ahead.
  When a setup script fails because a dependency is absent, that missing dependency is
  installed the same way, never pinned to whatever version the failure happened to name.
- Canonical post-clone setup is `sh scripts/setup-hooks.sh`: it activates `.githooks`.
- `wt --yes switch --create <branch>` runs `sh scripts/agent/init-worktree-tools.sh .`
  from `.config/wt.toml`'s `pre-start` hook; it makes the primary's `.worktrees/`
  ignore itself. `work-branch.sh --worktree` cuts through `wt`, runs the same
  initializer, and rolls back a failed cut -- reclaiming a tree `wt` left behind when
  its hook failed.
- PHP includes are named `.inc`, and a tool that infers language from the extension
  silently skips them — indistinguishable from a clean no-match (issue #2807). The
  tracked `sgconfig.yml` fixes ast-grep; semgrep has no configuration equivalent, so
  always pass `semgrep --scan-unknown-extensions`.
- Compiler, static analysis, tests, CI, and live smoke remain final.
