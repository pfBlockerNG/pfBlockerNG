# Git — worktrees, hooks, branches, commits

Scope: worktree mechanics, git hooks, branch naming, rebase/diff hygiene, commit style and
attribution. Load when: committing, branching, pushing, or cutting a worktree.

## Worktrees (mandatory for AI agents)

**Every AI agent MUST do all repository work in its own dedicated git worktree** — never the
primary checkout, never shared with another agent (concurrent agents race on the filesystem,
index, `HEAD`, refs). Session layouts (primary checkout vs harness-made session worktrees):
[`sessions.md`](sessions.md).

**Exception — dev-only classes need no PR.** Classes never shipped to users skip the PR
stage: **ADR text** (`.ADRs/`), **skills** (`.claude/skills/`, `.agents/skills/`), **agent
workflows/configuration** (`.claude/workflows/`, `.codex/`), and **documentation-only**
changes (`**/*.md`, `docs/`, `AGENTS.md`, `CLAUDE.md`). Each still uses a worktree but
commits/pushes **directly to `devel`** (fetch + rebase first). Anything touching `src/`,
`tests/`, or CI — ADR *implementation* included — uses the full worktree + rebase-only-PR
flow.

```sh
git worktree add -b <branch> <path> origin/devel   # branch off the latest base
# … work, commit, push, open the PR from inside <path> …
git worktree remove <path>            # run from any directory OUTSIDE <path>
```

- Branch off the **current** base (`git fetch` first); a stale-tip worktree needs a rebase
  before it can land.
- **A rebase needs a visible merge base.** In a shallow checkout, a normal fetch can move
  `origin/devel` beyond the retained history while an older worktree still points behind the
  shallow boundary; plain `git rebase origin/devel` then mistakes base commits for work and
  replays them. If `git merge-base HEAD origin/devel` produces no commit, deepen/unshallow
  the fetch first and retry the ancestry check. Never start the rebase without it.
- **Reuse only YOUR OWN worktree — never adopt one you merely found.** A worktree at the
  conventional path that you did not create this run may belong to a live parallel session:
  `git -C <path> status` — foreign uncommitted changes ⇒ not yours; never `--force`-remove
  it; cut a fresh uniquely-named worktree (suffix `-{epoch}`).
- **Reuse a branch for a follow-up ONLY when no other session owns its PR** (foreign
  commits/pushes, running CI, review replies, an assignee/open-`Fixes #N`-PR you didn't set,
  or legacy `WIP`/`Waiting PR` labels ⇒ another session owns it: wait, cooperate, or start a
  NEW branch after the merge). **Never force-push over another session's in-flight PR.**
- Name the branch for its work item — `adr/{NN}-{slug}` / `issue/{NN}-{slug}`.
- Gotchas: `git worktree remove` fails from inside the tree — run it from any directory
  outside the tree being removed (the primary checkout works; so does a session worktree).
  `gh pr merge --delete-branch` can't check out a base another worktree holds — verify the
  merge landed, then `git push origin --delete <branch>`.

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath`). If
`git config core.hooksPath` is not `.githooks`, an agent runs it at session start
(idempotent). Any GitHub Actions workflow that commits code runs it after checkout too.

- **`pre-commit`** — the fast linters/static-analysis, path-scoped to staged file types
  (Python → ruff + `mypy tests/`; Markdown → markdownlint; shell → shebang gate + `sh -n` +
  shellcheck + shellspec; PHP → `php -l` + PHPStan + PHPCS; the URL-encoding check when
  `*.sh`/`*.md` staged). NOT the unit suites — run `python3 -m pytest` yourself while
  iterating; CI is the hard gate. Missing tool = reported + skipped. The `--no-verify` bypass
  is for humans, not agents.
- **`prepare-commit-msg`** — first aborts an agent commit (`CLAUDECODE=1` or
  `CODEX_THREAD_ID` set) in the **primary checkout** (agents commit only in linked
  worktrees — issue #1262; state-checked via `--git-dir` vs `--git-common-dir`, never
  command text; agent-dedicated checkouts opt out via `CLAUDE_CODE_USER_EMAIL`
  (managed-remote) or
  `git config pfblockerng.allowprimarycommit true`), then appends the owner's
  `Co-authored-by:` trailer (see Commit style); runs even under `--no-verify`.
- **`pre-push`** — enforces the release tag scheme via `scripts/release-version.sh`; also
  denies an agent (`CLAUDECODE=1` or `CODEX_THREAD_ID` set) branch push that would rewrite
  remote history the agent never fetched (advertised remote oid must equal the
  remote-tracking ref — issue #1307, `--force-with-lease`'s check enforced by effect).

## Rebase and diff hygiene

**Rebase onto the latest base before every push, PR, or CI/smoke dispatch.** `devel` advances
out of band: `git fetch origin` + `git rebase origin/devel` (or `origin/<pr-base>`),
`--force-with-lease` if rewritten; never reconcile with a merge commit. A stale base re-runs
bugs the base already fixed and sends you chasing a phantom regression (bit ADR-29); a
freshly-rebased branch that still fails is genuinely your bug.

**Clean the diff before you push/PR.** `git diff origin/devel...HEAD` and reduce it to only
what the change requires — strip debug logging, dead/commented-out experiments,
churned-then-reverted code, introduced-then-unused symbols, gratuitous reformatting, scratch
files. Cheapest before the PR exists.

## Branch naming (ADRs and issues)

**ADR** `adr/{NN}-{slug}`, **issue** `issue/{NN}-{slug}`; `{slug}` derives from the title
(ADR `{Name}`/`ADR.md` H1; the issue title) by this **mandatory** sanitiser:

1. Lowercase.
2. Strip emojis + every non-ASCII char; drop anything not `[a-z0-9]`.
3. Collapse each removed/non-alphanumeric run to a single `-`; trim leading/trailing `-`.
4. Truncate ≤30 chars at a `-` boundary (never trailing `-`).
5. Empty slug → omit it (bare `adr/{NN}` / `issue/{NN}`).

Output is `[a-z0-9-]` only. **Never hand-derive it**: `scripts/agent/work-branch.sh
<issue|adr> <NN> [title...]` implements the sanitiser (pinned by
`tests/shell/agent_work_branch_spec.sh`); `--worktree` also cuts the worktree at an
absolute path. **On collision** with an *unrelated* branch, append `-{epoch}`
(epoch seconds). An ADR reusing its own `adr/{NN}-*` branch across phases is reuse, not a
collision. Examples: `ADR_10_Zero_Downtime_DNSBL` → `adr/10-zero-downtime-dnsbl`; issue #43
"TLD-Allow KeyError on …" → `issue/43-tld-allow-keyerror-on`.

## Commit style

`<scope>: <imperative summary>` (follow the existing log — e.g. `ci: simplify pytest
invocation`, `pfblockerng: fix IPv6 subnet match`). No trailing period; body optional for
non-obvious changes.

**Attribution:** both environments keep the human owner visible and earn a GitHub
**Verified** badge. On a box with the **user's own signing key**, the user
authors/commits/signs as themselves. Credit the active AI client with a
`Co-authored-by:` trailer only when its provider adapter defines a verified,
GitHub-recognized identity; otherwise disclose it in the PR audit/footer and never
fabricate or borrow another provider's identity. Claude's adapter uses
`Claude <noreply@anthropic.com>`; Codex's current mapping in `AGENTS.md` has no
verified coauthor identity. In **agent/managed-remote** environments, the active
agent is committer+signer, the human is author (`--author=`), and the
`prepare-commit-msg` hook injects the owner's `Co-authored-by:` trailer automatically.
Full two-model spec + badge preconditions: below.

## Author, committer, and signing (full text)

Two environments, two attribution shapes — both keep the human owner visible and earn a GitHub
**Verified** badge. Pick by whether the box has the user's own signing key.

**Default — agent / managed-remote environment (no user signing key on the box):**

- **Committer = signer = Claude's GitHub identity** (the account whose verified email owns the
  registered signing key). GitHub binds the Verified badge — and the commit credit — to the
  committer, so the committer must be Claude for the signature to verify.
- **Author = the human owner** (`Andre Brait <andrebrait@gmail.com>`), set explicitly
  (`--author=` / `GIT_AUTHOR_*`).
- **Credit the human with a `Co-authored-by:` trailer for the owner** — mandatory; with Claude
  as committer GitHub credits only Claude otherwise. Injected automatically by
  `.githooks/prepare-commit-msg`, which resolves the owner generically (`coauthor.email`/
  `coauthor.name` git config, else `$CLAUDE_CODE_USER_EMAIL`, else the commit author) and is a
  no-op when the human is already the committer or already credited. (A `Co-authored-by:` for
  *Claude* is redundant there — Claude is already the committer.)
- **Sign every commit** (`-S`; SSH or GPG). Valid signature + key on Claude's account +
  matching committer email ⇒ Verified, attributed to Claude.

**User's personal environment, signing with the user's own key** (`commit.gpgsign = true`, or
a configured `user.signingkey`): do **not** override the local identity — the user authors,
commits, and signs as themselves (Verified as the user). Claude is then not the committer, so
credit it via the trailer: **add `Co-authored-by: Claude <…>` as the final line(s)**, using
Claude's GitHub-recognized identity (an unrecognized email credits no one). Mandatory: never
let a user-signed commit ship with no mention of Claude. Leave the user's `-S` in place; do
not add `--author=`.

**Badge precondition** (one-time infrastructure): the default model needs Claude's committer
email verified on its GitHub account and that account holding the registered signing key. In
the Claude Code managed-remote environment this is platform-provided (every commit signed by
the platform key under the `claude` committer identity, human as author). Only a bare /
self-hosted agent setup must provision the key + email itself (until then commits land
correctly attributed but read *Unverified*).
