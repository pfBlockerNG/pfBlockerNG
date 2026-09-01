# Git — worktrees, hooks, branches, commits

Scope: worktree mechanics, git hooks, branch naming, rebase/diff hygiene, commit style and
attribution. Load when: committing, branching, pushing, or cutting a worktree.

## Worktrees (mandatory for AI agents)

**Every AI agent MUST do all repository work in its own dedicated git worktree** — never
primary checkout, never shared with another agent (concurrent agents race on filesystem,
index, `HEAD`, refs). Session layouts (primary checkout vs harness-made session worktrees):
[`sessions.md`](sessions.md).

**Exception — dev-only classes need no PR.** Classes never shipped to users skip PR
stage: **ADR text** (`legacy/ADRs/`), **skills** (`.claude/skills/`, `.agents/skills/`), **agent
workflows/configuration** (`.claude/workflows/`, `.codex/`), **documentation-only**
changes (`**/*.md`, `docs/`, `AGENTS.md`, `CLAUDE.md`). Each still uses a worktree and
lands directly on `devel` only as a clean fast-forward of locally signed commits after
fetch + rebase. Anything touching `src/`, `tests/`, or CI — ADR *implementation*
included — requires the full PR flow. The reviewed signed local fast-forward allowed by
`landing.md` happens only after every PR gate; it is never a shortcut around the PR.

```sh
git worktree add -b <branch> <path> origin/devel   # branch off the latest base
sh scripts/agent/init-worktree-tools.sh <path>      # mandatory per-worktree indexes
# … work, commit, push, open the PR from inside <path> …
git worktree remove <path>            # run from any directory OUTSIDE <path>
```

`work-branch.sh … --worktree` fetches, adds below
`<repo-parent>/.<repo-name>_worktrees/<sanitized-branch>`, and initializes tools.
Relative paths stay below that root; absolute paths stay exact; initialization failure
rolls back the worktree and branch. It uses Git directly. Manual adds must run
`init-worktree-tools.sh`; CodeGraph and Graphify are mandatory, while Serena is skipped
when absent or under OMP.

For matching Worktrunk placement, set:

```toml
# ~/.config/worktrunk/config.toml
worktree-path = "{{ repo_path }}/../.{{ repo }}_worktrees/{{ branch | sanitize }}"
```

The tracked `.config/wt.toml` initializes tools during `wt --yes switch --create <branch>`
and prunes metadata after merge/removal. `wt remove` deletes only branches it verifies
as integrated; landing observes the foreground result.

- Branch off **current** base (`git fetch` first); stale-tip worktree needs rebase
  before it can land.
- **Rebase needs visible merge base.** In shallow checkout, normal fetch can move
  `origin/devel` beyond retained history while older worktree still points behind
  shallow boundary; plain `git rebase origin/devel` then mistakes base commits for work and
  replays them. If `git merge-base HEAD origin/devel` produces no commit, deepen/unshallow
  fetch first and retry ancestry check. Never start rebase without it.
- **Reuse only YOUR OWN worktree — never adopt one you merely found.** Worktree at
  conventional path you did not create this run may belong to live parallel session:
  `git -C <path> status` — foreign uncommitted changes ⇒ not yours; never `--force`-remove
  it; cut fresh uniquely-named worktree (suffix `-{epoch}`).
- **Reuse a branch for follow-up ONLY when no other session owns its PR** (foreign
  commits/pushes, running CI, review replies, assignee/open-`Fixes #N`-PR you didn't set,
  or legacy `WIP`/`Waiting PR` labels ⇒ another session owns it: wait, cooperate, or start
  NEW branch after merge). **Never force-push over another session's in-flight PR.**
- Name branch for its work item — `adr/{NN}-{slug}` / `issue/{NN}-{slug}`.
- Gotchas: `git worktree remove` fails from inside tree — run from any directory
  outside tree being removed (primary checkout works; session worktree too).
  `gh pr merge --delete-branch` can't check out base another worktree holds — verify
  merge landed, then `git push origin --delete <branch>`.
- Each worktree owns its Composer `vendor/` tree; never share or symlink `vendor/` between
  worktrees. Run `composer install --no-interaction` in current worktree.

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath`). If
`git config core.hooksPath` not `.githooks`, agent runs it at session start
(idempotent). When CodeGraph is installed, the same setup creates the checkout's
exact-root index. Any GitHub Actions workflow that commits code runs it after checkout too.

- **`pre-commit`** — fast lint, style, and policy checks, path-scoped to staged file types
  (Python → ruff; Markdown → markdownlint; shell → shebang gate + `sh -n` +
  shellcheck; PHP → `php -l` + PHPCS; URL-encoding check when
  `*.sh`/`*.md` staged). NOT unit suites — run `python3 -m pytest` yourself while
  iterating; tests and static analysis run in CI only. Missing tool = reported + skipped.
  `--no-verify` bypass is for humans, not agents. Release-line trees lacking the
  checker corpus opt out per gate via a committed root `.githooks-exempt`
  manifest (issue #2633) instead of bypassing.
- **`prepare-commit-msg`** — first aborts agent commit (`CLAUDECODE=1`,
  `CODEX_THREAD_ID`, Copilot, Grok, or OMP marker set) in **primary checkout**
  (agents commit only in linked worktrees — issue #1262; state-checked via
  `--git-dir` vs `--git-common-dir`, never command text; agent-dedicated checkouts opt out via `CLAUDE_CODE_USER_EMAIL`
  (managed-remote) or
  `git config pfblockerng.allowprimarycommit true`), then rejects every
  `Co-authored-by:` trailer and any agent author/committer identity that differs
  from configured `user.name` / `user.email`; runs even under `--no-verify`.
- **`commit-msg`** — rejects any `Co-authored-by:` trailer after Git's message
  editor runs, closing the post-`prepare-commit-msg` insertion window.
- **`pre-push`** — enforces release tag scheme via `scripts/release-version.sh`; denies
  agent branch rewrites over unfetched remote history (issue #1307); validates the final
  message of every outgoing commit; and validates each outgoing agent commit's configured
  author/committer identity and good signature from the configured user email.

## Rebase and diff hygiene

**Rebase onto latest base before every push, PR, or CI/smoke dispatch.** `devel` advances
out of band: `git fetch origin` + `git rebase origin/devel` (or `origin/<pr-base>`),
`--force-with-lease` if rewritten; never reconcile with merge commit. Stale base re-runs
bugs the base already fixed and sends you chasing phantom regression (bit ADR-29);
freshly-rebased branch that still fails is genuinely your bug.

**Clean diff before you push/PR.** `git diff origin/devel...HEAD` and reduce it to only
what change requires — strip debug logging, dead/commented-out experiments,
churned-then-reverted code, introduced-then-unused symbols, gratuitous reformatting, scratch
files. Cheapest before PR exists.

**Push as soon as commit is green and final.** Commit that exists only on this
workstation is invisible and unbacked-up work; never let commits pile up locally waiting
for later batch push. Dev-only commits fast-forward directly to `devel` only when locally
signed. Code branches push to their own remote through the full PR flow; only its final
landing gate may choose GitHub squash or the reviewed signed local fast-forward
([`landing.md`](landing.md)).

## Branch naming (ADRs and issues)

**ADR** `adr/{NN}-{slug}`, **issue** `issue/{NN}-{slug}`; `{slug}` derives from title
(ADR `{Name}`/`ADR.md` H1; issue title) by this **mandatory** sanitiser:

1. Lowercase.
2. Strip emojis + every non-ASCII char; drop anything not `[a-z0-9]`.
3. Collapse each removed/non-alphanumeric run to single `-`; trim leading/trailing `-`.
4. Truncate ≤30 chars at `-` boundary (never trailing `-`).
5. Empty slug → omit it (bare `adr/{NN}` / `issue/{NN}`).

Output is `[a-z0-9-]` only. **Never hand-derive it**: `scripts/agent/work-branch.sh
<issue|adr> <NN> [title...]` implements sanitiser (pinned by
`tests/shell/agent_work_branch_spec.sh`); `--worktree` also cuts worktree at
absolute path. **On collision** with *unrelated* branch, append `-{epoch}`
(epoch seconds). ADR reusing its own `adr/{NN}-*` branch across phases is reuse, not
collision. Examples: `ADR_10_Zero_Downtime_DNSBL` → `adr/10-zero-downtime-dnsbl`; issue #43
"TLD-Allow KeyError on …" → `issue/43-tld-allow-keyerror-on`.

## Commit style

`<scope>: <imperative summary>` (follow existing log — e.g. `ci: simplify pytest
invocation`, `pfblockerng: fix IPv6 subnet match`). No trailing period; body optional for
non-obvious changes.

**Commit identity:** agent-created commits are indistinguishable from the configured user
committing alone. `user.name` and `user.email` must be both author and committer, and the
user's normal signing configuration produces the signature. Commit messages carry no
`Co-authored-by:` trailers. Provider-specific and legacy `coauthor.*` configuration is
ignored.

`.githooks/prepare-commit-msg` enforces configured identity and rejects early
`Co-authored-by:` trailers; `.githooks/commit-msg` repeats the trailer check after Git's
message editor runs. Identity enforcement applies when a client marker is present:
`CLAUDECODE=1`, `CODEX_THREAD_ID`, `COPILOT_CLI` (plus `COPILOT_AGENT_PROMPT` for
Copilot's cloud agent), `GROK_SESSION_ID` / `GROK_AGENT`, and `OMP_CLI` / `PI_CLI`.

## Author, committer, and signing (full text)

- **Author = committer = configured user identity.** Never override either with an agent,
  model, service, or harness identity.
- **Sign with the user's configured key.** Valid signature + matching user email preserves
  GitHub's normal **Verified** result.
- **Message = ordinary project commit message.** No generated-by line, attribution footer,
  or co-author trailer.
- **Unavailable user identity or signing key = no commit.** A managed/remote environment
  that cannot produce the same commit the user would produce returns the patch to the user
  instead of committing under a substitute identity.
