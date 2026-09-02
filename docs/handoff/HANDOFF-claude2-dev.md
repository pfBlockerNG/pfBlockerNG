# Handoff — claude2-dev, session of 2026-09-01/02

Written before a deliberate context clear. Everything here is either measured in
this session or cited to the seat that measured it.

## Landed

| PR | Issue | What |
| --- | --- | --- |
| #3064 | #3010 | `setup-agent-tools.sh` owns uv by its install directory, not by `command -v` |
| #3084 | #3075 | `check_noopener.py` scans `src/usr/local/pkg` as well as `src/usr/local/www` |

Both by maintainer-local fast-forward. `devel` is **unprotected**, so `landing.md`
rules out the GitHub-hosted squash (it requires an atomic strict-base gate) and
directs the local path. Repo merge methods are squash-only.

**#3010's issue is deliberately still OPEN.** The PR did not do its steps 2-4 —
removing the root-owned `/usr/local/bin/uv`, and the `uvx` the issue does not
mention — which need root. Closing it would have lost that.

## Blocked, complete, waiting only on `php8.5-intl`

Two finished changes sit uncommitted in worktrees. Do not redo them.

- `.pfBlockerNG_worktrees/issue-3060-hide-top1m-token-field` — 3 files.
  Fully proven by claude-smoke on the LXC pool: RED and GREEN on both tiers plus
  a third arm. Full evidence and the patch are on **issue #3060**.
- `.pfBlockerNG_worktrees/issue-3085-detect-escaped-quote-target` — 8 files.
  Detector widened to backslash-escaped quotes; 11 live sites fixed. Unit
  red→green done (`3 failed, 145 passed` → `148 passed`). Patch on **issue #3085**.
  Tiers are with claude-smoke.

**The blocker, verified:** pfb-dev has `php-zip` but not `php-intl`. No intl →
`composer install` crashes in Symfony String → `vendor/` never exists →
`check_composer_vendor.py` fails → commit refused. `.githooks/pre-commit` has
**no exemption path**: `exempted()` excuses a checker only when that checker is
not shipped, and on `devel` it is. `--no-verify` is reserved for humans
(`AGENTS.md`). So **no `.php`/`.inc` change can be committed from this seat.**

## Open decisions the owner has not made

- **`php8.5-intl` on pfb-dev.** claude-smoke's view (asked for, and it argued
  against my own position): install it, *and* write the routing rule down
  separately — "enforcement by accident is indistinguishable from breakage, and
  it fails open the moment anyone fixes the box."
- **#3087 shape.** My issue claimed widening is frictionless; that was measured on
  two files only. Widening the real scan set surfaces **4 genuine violations** in
  `pfblockerng.inc`. Corrected on the issue. Fix-vs-exempt is undecided.
- **#3091 shape.** The tracked `graphify-out/graph.json` is **230 commits stale**,
  which inverts the issue's framing — the refresh on worktree cut is what makes it
  useful. Recommendation: untrack it. Undecided.
- **#3057 and #3088** — explicitly held by the owner.
- **#3070** — PR #3098 closed as not planned; the issue is open and unaddressed.

## Worktrees — leave them alone

33 worktrees, 2.8G, plus 4.7G in `.pfb-scratch`. The owner has said to leave
everything for now. Two carry commits that exist **nowhere else** — no remote, no
PR, subjects absent from `devel`:

- `issue/3018-phpunit-fixtures-leak-temp` — 1 commit across 11 PHPUnit files
- `issue/2952-escaped-quote-vocab-v2-work` — 4 commits on `ThemeSafetyUiTest.php`

The owner declined to push them and said to start fresh. Recorded so a future
session does not mistake them for recoverable work, and does not delete them
believing they are backed up.

## Corrections I published and had to retract — read before trusting my notes

Four wrong artifacts left where people read them, all caught by other seats:

1. **Send counts.** I reported `grok-smoke 0` as a liveness finding. It is **534**.
   My probe globbed `new/` and `cur/`, but the maildirs are `new/` and `read/`, so
   I counted unread mail and called it sends. Correct probe:
   `grep -rl "^From: <seat>$" /srv/Smoke/handoff/inbox/ | wc -l`
2. **A cross-branch claim.** I told a reviewer #3064's composer gate failed for
   environmental reasons. `run-gates.sh:87` only selects that gate for `.php`/`.inc`
   diffs, so it never ran — the symptom belonged to #3060, a different worktree.
3. **An inverted decision rule.** I said that if #3060's CLEAR assertion failed,
   `hideInput()` must already clear and my guard was redundant. Backwards. Variant C
   proved the guard is load-bearing; applying my rule would have deleted it.
4. **An empty patch.** Sent a 0-byte patch to another seat: `git add -A` had run
   before a failed commit, so the changes were staged and plain `git diff` showed
   nothing. Use `git diff HEAD` after a failed commit.

The durable lesson, and it is in this seat's memory: re-derive evidence from a run
on the artifact under discussion, and correct a published claim **where it was
published**.

## Cross-seat state

- **claude-smoke** — live, fresh session, ~558 sends. Runs the pool. Has #3085's
  tiers. Declined to carry commits for me, correctly: "smoke-1's gate passes where
  yours cannot" would route around a block rather than divide labour.
- **claude-dev** — was at 86% with its own handoff committed; #3067 and #3072
  merged, #3099 open. **Its handoff recommends #3055 as the best unclaimed piece —
  that is stale, #3055 is CLOSED.**
- **claude2-smoke** — DEAD since 2026-08-30 (8 sends, all that day). Not a routing
  target. Unread count and `serve` uptime prove a mailbox and a process; only
  **sends** prove a reader.

## Traps this session paid for

- `landing.md` in an older worktree still says "never squash"; #3038 inverted that
  the same day. Read policy from `origin/devel`, not your checkout.
- `/var/tmp/agents` is owned by `claude` mode 775 — unwritable by other seats. Use
  a per-seat path.
- `uv sync --extra smoke` errors; the working form is `uv sync --group smoke`.
- `graphify update` dirties tracked `graph.json` on every worktree cut — restore it
  before every diff or it lands 400k lines of noise (that is #3091).
- Local `shellspec` is `0.29.0-dev`; CI pins `0.28.1`.
