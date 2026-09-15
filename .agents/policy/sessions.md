# Session layouts and managed-remote sessions

Scope: session and worktree layouts, maintenance-branch policy delivery, cross-session resume.
Load when: starting work in an unfamiliar environment, targeting a maintenance branch, or resuming another session's item.

## Session layouts (three environments, one rule)

Session may start in primary checkout (CLI, one per terminal) or inside **harness-made session worktree** — rc-mode cuts `<primary>/.claude/worktrees/bridge-<session-id>` (branch `worktree-bridge-*`, locked); managed environments cut one worktree per session, named after first-prompt issue. Detect mechanically, never from memory: `git rev-parse --git-dir --git-common-dir` differing ⇒ you are in linked worktree. Session worktree is harness's **orchestration home, not work-item worktree**: cut per-item worktree from wherever you sit (`scripts/agent/work-branch.sh --worktree` anchors at primary root — never derive placement from `--show-toplevel`, which names session tree and nests worktrees inside harness-lifecycle tree). Sole exception: environment hard-pins pushes to session branch — then that branch replaces convention per managed-remote policy below.

## Maintenance-branch policy delivery

For maintenance work in `pfBlockerNG/pfBlockerNG` (including `release/*` and backports
to `main`), load current process policy before editing or dispatching. A maintenance
checkout may contain an older `CLAUDE.md` and no `.agents/` or `.omp/`; that is branch
content, not permission to fall back to older process rules.

1. Resolve the canonical repository from the task and verified remote URLs. Fetch its
   `devel` branch and record the resulting commit as the **policy SHA**; an arbitrary
   fork's `origin/devel` is not automatically canonical. A worker may reuse the
   snapshot its parent already resolved for this task.
2. Read that commit's `AGENTS.md`, the active vendor adapter, and the task-relevant
   routed policy. Use an existing checkout whose relevant files match the policy SHA,
   or read `git show <policy-sha>:<path>` / the repository API at that SHA. When workers
   cannot access those sources, supply a session-artifact bundle preserving the
   repository-relative paths. Resolve further policy references from the same snapshot.
3. Keep the **code worktree, target branch, and base SHA** separate. Process policy
   governs evidence, delegation, worktrees, review, and landing. The target branch
   supplies the actual code, compatibility requirements, and adopted test/tooling
   surface. Verify any existing gate exemptions there; missing tooling is not a new
   exemption. A policy lookup never authorizes transplanting `devel` code or test
   infrastructure into the maintenance branch.
4. Before dispatch, include the following block and resolved required-reading paths
   in the task packet. The worker reads them and confirms both roots before editing;
   parent chat, skill state, and branch-local discovery are not substitutes.

   ```text
   Policy source: <canonical repository>@<policy SHA>
   Policy access: <verified checkout, pinned file URLs, or readable artifact bundle>
   Code target: <absolute worktree>, <target branch>@<base SHA>
   Required reading: <bootstrap, vendor adapter, and task-relevant policy paths>
   ```

If the policy source cannot be established or read, report the precise blocker before
editing or dispatching. A standalone maintenance session performs the same resolution
itself. Retain the policy SHA and access references in handoffs and resume records.
Policy material belongs in its canonical repository or session artifacts, not copied
into the maintenance branch merely to make discovery work.

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

## Leftover worktrees

A session that ends before its cleanup step leaves a finished worktree no later step
owns. Whoever finds one reaps it on sight under `landing.md`'s conditions, never on
mtime: clean tree (`git status --porcelain` empty, untracked included), no live process
under it (`/proc/*/cwd`, `/proc/*/fd`), and either a PR `MERGED` whose head equals or
descends from the local head with no open PR at that head, or `wt list` reporting the
branch integrated into `devel`. Stop its CodeGraph daemon
(`repository-intelligence.md`), run the `landing.md` removal command, observe
`branch_outcome`; anything else stays and is reported.
