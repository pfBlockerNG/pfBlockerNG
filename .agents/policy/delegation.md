# Canonical gates and agent-ops scripts

Scope: canonical gates every change runs, and the `scripts/agent/` procedures. Load when:
running or changing gates, or touching `scripts/agent/`.

- **New implementation-plan ADRs stopped** (wayfinder map #1383): big work charted as map of
  tickets with committed specs ([`workflow.md`](workflow.md)); unimplemented ADRs migrate to
  specs and tickets (#1389); implemented ADRs stay immutable historical records. Retired
  ADR-phase orchestration (`/adr-phase`, `phase-step`) live on only in those records.

## Canonical gates (single source of truth)

Runner: `scripts/agent/run-gates.sh --diff <base>`; keep this table and the runner aligned.
"Touched" is computed from the diff's file types **plus cross-language consumers** — a
suite that parses an artifact the diff changes runs regardless of its language.

| Touched | Gates (all must pass) |
| ------- | --------------------- |
| Any diff (always-on) | `sh scripts/agent/check-graph-fresh.sh` — rebuilds `graphify-out/graph.json` (`PYTHONHASHSEED=0`, resolved Graphify launcher) and FAILS when the committed file differs: the commit that moves code moves the graph. Missing Graphify ⇒ FAIL, never SKIP. Fix: `PYTHONHASHSEED=0 graphify update .` + commit |
| Python (`*.py`) | `python3 -m pytest` · `ruff check .` · `ruff format --check .` · `mypy tests/` |
| PHP (`*.php`/`*.inc`) | `php -l` per touched file · `vendor/bin/phpunit` · `composer phpstan` · `composer phpcs -- --standard=phpcs.xml.dist src/` |
| Shell (`*.sh`) | `sh -n` · `shellcheck` (only `src/`, `scripts/`, `.claude/hooks/` — the scope `.githooks/pre-commit` + CI use; `tests/` shellspec specs trip SC2034 false-positives) · ShellSpec (next row) |
| Any path but Markdown and `docs/` (CI's shell-tests trigger), or Markdown a ShellSpec guard reads (set in `gates_for()`, #3425) | `shellspec --shell "$(command -v dash)"` (dash = strict-POSIX ash sibling of FreeBSD sh — bash-as-sh masks appliance divergences. Dash missing ⇒ the hand-run substitution goes empty and the runner falls back to `sh`: INSTALL dash (`brew`/`apt install dash`), never drop the pin; plain `shellspec` is a last resort, named in the PR evidence) |
| `go/**` | Go gate in `gates_for()` |
| Markdown (`*.md`) | `npx markdownlint-cli2` |
| `tests/skip-allowlist.txt` / `tests/fixtures/skip-allowlist-canary.xml` | `python3 -m pytest` — the skip-set checker, its red canary, and the tests parsing both files ride the pytest gate (issues #3166, #3174) |
| `www/` | Reachable UI coverage exists for the change per test mandate #4 |

## Agent-ops scripts (`scripts/agent/`)

Mechanical procedures the skills used to restate in prose live once, tested, in
`scripts/agent/`: `wait-reviewer.sh` (reviewer-wait state machine), `wait-checks.sh`
(CI wait), `run-gates.sh` (canonical-gates runner), `work-branch.sh` (branch sanitiser +
worktree cutter). Shared contract in `scripts/agent/agent_env.sh`; behaviour pinned by
`tests/shell/agent_*_spec.sh`.

- **Portability contract.** All network access ride `gh`/`git` CLIs — managed cloud
  environments route git/ssh/https through localhost proxy that only those CLIs inherit;
  never call raw endpoints. `gh` absent → script exit **3** with `GH-UNAVAILABLE` message:
  agent fall back to `mcp__github__*` tools with wakeup-paced checks (waits.md rule #4) — MCP
  tools are harness tools, unreachable from inside shell, so fallback cannot live in script.
  Any other missing tool → exit **4** (`TOOL-MISSING`). Exit **2** = usage/precondition,
  **1** = check itself failed, **0** = verdict reached.
- **Agent-maintained.** These scripts encode environment mechanics that drift. When
  environment change break one, agent fix script **in same session** and land it via normal
  flow (scripts are code-bearing: worktree + PR) — never work around it silently in transcript.
- **Hook-context safety.** Git-touching scripts (and any spec whose fixtures run git) scrub
  hook-exported `GIT_DIR`/`GIT_INDEX_FILE`/… via `scripts/lib/git-env-scrub.sh` (ADR-47) —
  inherited hook env otherwise aim fixture git ops at live repository.
- **Gate re-runs vs pre-commit hook (recorded-skip carve-out).** A `run-gates.sh` re-run
  may be recorded as SKIPPED for gate the pre-commit hook **provably just executed
  identically**: session watched that gate's `[pre-commit]` step line pass on exact
  commits being gated, same session, no `--no-verify`. Two hook properties keep this
  narrow: hook **skips missing tools instead of failing** (green commit is not proof gate ran
  — only its step line is), and its shellspec run is **impacted-scoped**, not full suite, so
  it never satisfy canonical full-suite shellspec gate. In practice carve-out cover whole-tree
  `markdownlint`, per-file `sh -n`/`shellcheck`/`php -l` lint gates, and phpstan/phpcs
  analyses (hook run both, memory-capped, off same configs); unit suites (`pytest`,
  `phpunit`) and full shellspec run exist only in `run-gates.sh` and never satisfied by
  pre-commit.
