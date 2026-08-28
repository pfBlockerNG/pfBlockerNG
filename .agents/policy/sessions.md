# Session layouts and managed-remote sessions

Scope: where session runs, where work-item worktrees go, cross-session resume.
Load when: starting work in unfamiliar environment, or resuming another session's item.

## Session layouts (three environments, one rule)

Session may start in primary checkout (CLI, one per terminal) or inside **harness-made session worktree** — rc-mode cuts `<primary>/.claude/worktrees/bridge-<session-id>` (branch `worktree-bridge-*`, locked); managed environments cut one worktree per session, named after first-prompt issue. Detect mechanically, never from memory: `git rev-parse --git-dir --git-common-dir` differing ⇒ you are in linked worktree. Session worktree is harness's **orchestration home, not work-item worktree**: cut per-item worktree from wherever you sit (`scripts/agent/work-branch.sh --worktree` anchors at primary root — never derive placement from `--show-toplevel`, which names session tree and nests worktrees inside harness-lifecycle tree). Sole exception: environment hard-pins pushes to session branch — then that branch replaces convention per managed-remote policy below.

## Managed-remote sessions: branch policy + cross-session resume

Managed remote (web/app) session mints own branch — `claude/<slug>-<rand>`. Where you may push set by environment's branch-push policy (configured in environment/trigger, not this repo — see <https://code.claude.com/docs/en/claude-code-on-the-web>). Two configurations, in order of preference:

**Session-worktree environments (probe before assuming).** Some environments also cut **one linked worktree per session** and start session inside it: rc-mode (mobile Devices view) at `<primary>/.claude/worktrees/bridge-<session-id>` on branch `worktree-bridge-<session-id>` (pushes NOT pinned — probed 2026-07-14: skills mint canonical branches as usual), managed environments one worktree per session named after first-prompt issue. Session worktree is orchestration home, never work-item worktree (see "Session layouts" above). In unfamiliar environment, probe at task start instead of assuming: `git rev-parse --git-dir --git-common-dir` (differing ⇒ linked worktree) and push policy; unverified "pushes are pinned here" is ASSUMED — probe before it shapes branch choice.

**Preferred — allow pushing to canonical work-item branch.** Configure push policy to permit repo's own `adr/{NN}-{slug}` and `issue/{NN}-{slug}` branches (keep `devel`/`main` PR-only). Then managed-remote session works item on canonical branch exactly as off-appliance, and resume is native — recompute slug (`scripts/agent/work-branch.sh`), find existing branch, no archaeology. Hard "never push anywhere but session branch" pin is wrong default for this repo — always carve out this exception.

**One branch per work item.** Whichever model in force, branch belongs to single issue/ADR it was opened for. Asked to handle different item than branch was minted for ⇒ cut new branch named for new item off latest `origin/devel`, push there. Reuse acceptable only when environment hard-pins pushes to that one stale branch — and then flag name/item mismatch to user before proceeding.

**Fallback — push hard-pinned to minted `claude/*` branch.** Pinned branch replaces convention for session. Each session gets fresh branch, so work spans sessions only if resuming session finds prior one:

- **Record override loudly + machine-readably** in first handoff: prose override plus greppable sentinel `ADR-RESUME: branch=<actual-branch> next-phase=<N>` (or `ISSUE-RESUME:` for issue).
- **Before starting ADR/issue fresh, DISCOVER prior work:** `git fetch origin`; scan remote branches for that item's committed handoffs (`RESULTS/{NN}_*`) and `*-RESUME:` sentinel; select candidate with highest contiguous completed phase.
- **Resume by fast-forward onto your own branch** (push pinned): replay/cherry-pick discovered commits onto current session branch (shared base `devel` ⇒ clean linear replay), continue remaining phases, push to *your* branch, carry sentinel forward with updated `next-phase`.
- **Auto-resume WITHOUT asking iff unambiguous:** exactly one viable candidate, valid sentinel, no sign of concurrent live session. `AskUserQuestion` only on genuine ambiguity.
