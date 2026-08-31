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
changes (`**/*.md`, `docs/`, `AGENTS.md`, `CLAUDE.md`). Each still uses worktree but
commits/pushes **directly to `devel`** (fetch + rebase first). Anything touching `src/`,
`tests/`, or CI — ADR *implementation* included — uses full worktree + PR flow.

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
  `git config pfblockerng.allowprimarycommit true`), then appends owner's
  `Co-authored-by:` trailer (see Commit style); runs even under `--no-verify`.
- **`pre-push`** — enforces release tag scheme via `scripts/release-version.sh`; also
  denies agent (Claude, Codex, Copilot, Grok, or OMP marker set) branch push
  that would rewrite remote history the agent never fetched (advertised remote oid must equal
  remote-tracking ref — issue #1307, `--force-with-lease`'s check enforced by effect).

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
workstation is invisible and unbacked-up work; never let commits pile up locally waiting for
later batch push. Dev-only commits push straight to `devel`; code branches push to
own remote branch and carry on into PR flow ([`landing.md`](landing.md)).

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

**Attribution:** every environment keeps human owner visible and earns GitHub
**Verified** badge. On box with **user's own signing key**, user
authors/commits/signs as themselves. Credit AI client with `Co-authored-by:`
trailer only when its provider adapter defines verified, GitHub-recognized
identity; otherwise disclose it in PR audit/footer and never fabricate or
borrow another provider's identity. Claude's adapter uses
`Claude <noreply@anthropic.com>`; Codex and OMP have no verified coauthor
identity by default; Copilot's is whatever `coauthor.copilot.*` names locally;
Grok's is whatever `coauthor.grok.*` names locally.
**Every client whose marker is present gets its own trailer** — agent launched
from inside another agent's session inherits outer marker while setting its
own, and both worked on the commit. Each identity comes only from that client's
own `coauthor.<client>.*` keys; legacy `coauthor.*` key holds Claude's (and
human session's) identity and is read only when no client marker present at
all, so an unconfigured non-Claude client is never credited to Claude.
Client markers: `CLAUDECODE=1`, `CODEX_THREAD_ID`, `COPILOT_CLI` (plus
`COPILOT_AGENT_PROMPT` for Copilot's cloud agent), `GROK_SESSION_ID` /
`GROK_AGENT`, and `OMP_CLI` / `PI_CLI`. In **agent/managed-remote**
environments, active
agent is committer+signer, human is author (`--author=`), and
`prepare-commit-msg` hook injects owner's `Co-authored-by:` trailer automatically.
Full two-model spec + badge preconditions: below.

## Author, committer, and signing (full text)

Two environments, two attribution shapes — both keep human owner visible and earn GitHub
**Verified** badge. Pick by whether box has user's own signing key.

**Default — agent / managed-remote environment (no user signing key on the box):**

- **Committer = signer = Claude's GitHub identity** (account whose verified email owns the
  registered signing key). GitHub binds Verified badge — and commit credit — to
  committer, so committer must be Claude for signature to verify.
- **Author = human owner** (`Andre Brait <andrebrait@gmail.com>`), set explicitly
  (`--author=` / `GIT_AUTHOR_*`).
- **Credit human with `Co-authored-by:` trailer for owner** — mandatory; with Claude
  as committer GitHub credits only Claude otherwise. Injected automatically by
  `.githooks/prepare-commit-msg`, which resolves owner generically (`coauthor.email`/
  `coauthor.name` git config, else `$CLAUDE_CODE_USER_EMAIL`, else commit author) and is
  no-op when human already committer or already credited. (`Co-authored-by:` for
  *Claude* is redundant there — Claude already committer.)
- **Sign every commit** (`-S`; SSH or GPG). Valid signature + key on Claude's account +
  matching committer email ⇒ Verified, attributed to Claude.

**User's personal environment, signing with the user's own key** (`commit.gpgsign = true`, or
configured `user.signingkey`): do **not** override local identity — user authors,
commits, and signs as themselves (Verified as user). Claude then not committer, so
credit it via trailer: **add `Co-authored-by: Claude <…>` as final line(s)**, using
Claude's GitHub-recognized identity (unrecognized email credits no one). Mandatory: never
let user-signed commit ship with no mention of Claude. Leave user's `-S` in place; do
not add `--author=`.

**Badge precondition** (one-time infrastructure): default model needs Claude's committer
email verified on its GitHub account and that account holding registered signing key. In
Claude Code managed-remote environment this is platform-provided (every commit signed by
platform key under `claude` committer identity, human as author). Only bare /
self-hosted agent setup must provision key + email itself (until then commits land
correctly attributed but read *Unverified*).
