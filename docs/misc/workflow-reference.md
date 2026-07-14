# Workflow reference (CLAUDE.md annex)

Detail displaced from `CLAUDE.md` in the 2026-07 trim: everything here is **still policy**,
just not front-loaded into every session's context. `CLAUDE.md` keeps the rule in 1–3 lines
and points here; read the relevant section when the task actually touches it.

---

## Live-system investigation gotchas (pfSense/FreeBSD)

Expansion of CLAUDE.md "Investigate, don't assume". Each of these cost a real misdiagnosis:

- **Follow file inclusions.** *NIX config splits across `include:` directives and `*.d/`
  drop-ins — grep the whole tree, then follow the chain. Unbound's DNS-Resolver ACLs live not
  in `/var/unbound/unbound.conf` but in the included `/var/unbound/access_lists.conf` (with
  `host_entries.conf`, `domainoverrides.conf`, `remotecontrol.conf`).
- **Some pfSense services run CHROOTED** — a chrooted process resolves absolute paths against
  its chroot root. **Unbound** → `/var/unbound` (`pfb_unbound.py` runs there: host-absolute
  `/var/unbound/pfb_py_raw/x` becomes `/var/unbound/var/unbound/pfb_py_raw/x` inside and 404s —
  use in-chroot paths; files like `/usr/local/pkg/...` are unreachable). **HAProxy** →
  `/tmp/haproxy`. A host file can be unreadable purely from the chroot — caused a real DNSBL
  feed-loading bug (manifest stored host-absolute paths the chrooted module couldn't open).
- **Ask the tool for its effective state via its own CLI** (resolves includes, shows what's
  loaded): **pf** → `pfctl` (`-sr`/`-sn`/`-sTables`/`-t <t> -T show`/`-ss`); **Unbound** →
  `unbound-control` (`get_option <opt>`, `list_local_zones`, `status`), `unbound-checkconf`
  validates. In general prefer the CLI/`pfSsh.php` over generated files.
- **Turn on debug/verbose when unsure what a tool does** (URLs/files hit, cache/304). E.g.
  `pkg -d update` traces the underlying `curl` (catalogue `meta.conf`/`data.pkg`, the
  `If-Modified-Since` → "Simulate an HTTP 304" → "repository is up to date" path; local DB
  under `/var/db/pkg/repos/<repo>/db`); `curl -v` for raw HTTP. Gotcha: pfSense pkg uses the
  **`pkg+https`** scheme (mirror indirection) — `pkg.pfsense.org` doesn't resolve directly (a
  plain `dig` looks "broken") but pkg resolves it to a Netgate mirror (e.g.
  `pkg00-atx.netgate.com`). The smoke harness keeps egress OPEN during the `deploy()`/reload
  phase for the **resolver + feed-update path** (the DNSBL update needs a working resolver);
  `pkg add` itself is **OFFLINE** — pfBlockerNG's RUN_DEPENDS are baked into the smoke image
  (`scripts/misc/install_deps_CE_2.8.sh`), so it resolves them from the local pkg db with no
  mirror round-trip.
- **Confirm what's installed with `pkg`.** `pkg info` / `pkg info <pkg>` / `pkg info -l <pkg>`
  (files) / `pkg which <path>` (owner); available: `pkg search` / `pkg rquery`. The smoke
  image ships `ldns` (→ `drill`), `bind-tools` (→ `dig`/`host`/`nslookup`), `python311`,
  `unbound`, `php83`, `qemu-guest-agent` — check before adding a dep or coding a fallback.
- **`/conf/config.xml` is the source of truth** for pfSense settings; `/var/…` is generated
  from it. To check a setting, open the relevant `config.xml` section (e.g. `<unbound><acls>`)
  — don't assume.
- **"Everything is files" cuts both ways:** read the actual files (diff before/after) and
  confirm a set/empty value on the box, not from recollection.

## Resolving pfSense-provided PHP functions from upstream

When a pfSense-provided PHP function is missing, ambiguous, or possibly implicated in a bug
and isn't stubbed yet, do NOT guess a workaround. It's open source:
<https://github.com/pfsense/pfSense>. Behaviour differs across releases, so check it in the
full source tree at each relevant ref:

1. **Minimum supported CE** — youngest commit ≤ our min CE launch date (currently **2.8.0**).
2. **Each CE release** since the oldest supported — youngest commit ≤ its launch date.
3. **Each pfSense Plus release** since our oldest supported CE — youngest commit ≤ its date.
4. **`master`** — current tip.

Resolve refs at investigation time (don't hardcode hashes): take the youngest commit
at/before the release date (`git log --before="<date>" -1 <branch>`, or the dated GitHub
commits view). The public mirror may lack release branches/tags (no `RELENG_2_8_0`), so dated
commits are the reliable handle. **Prefer stubbing the real function over an exception** (a
`phpstan-baseline.neon` suppression, an `undefinedFunctions` entry, or a code workaround) —
stubs encode reality and keep PHPStan/Intelephense honest. By-hand counterpart to the bulk
generator in `scripts/update-pfsense-stubs.py`.

## Bounded waits — the full ladder

Expansion of CLAUDE.md "Bounded waits". Two independent guards, **both required** — but
only once §0 says a wait is warranted at all:

### 0 — First: is the awaited thing harness-tracked? Then do not wait on it

`Workflow`, `Agent`, and Bash with `run_in_background: true` are **tracked**: their
completion re-invokes you. Arm **nothing** for them — no background `sleep`, no poll, no
`ScheduleWakeup`. Launch, end the turn, answer the notification.

Only **untracked** state gets a wait, and it is always a wait on something the harness has
no visibility into:

| Awaited thing | Tracked? | Correct move |
| ------------- | -------- | ------------ |
| A `Workflow` you launched (`issue-triage`, `phase-step`, `review-single`, …) | yes | end the turn; the completion notification wakes you |
| An `Agent` / subagent you spawned | yes | same |
| `wait-checks.sh` / `wait-reviewer.sh` run with `run_in_background: true` | yes | same — the script self-exits and notifies; do not also poll it |
| CodeRabbit / Copilot posting a review; a CI run; a remote queue | **no** | a bounded wait: the script above, or the ladder in §1 |

The ladder's self-invalidating discipline applies to **every** timer you arm, not just
`ScheduleWakeup`: on firing, CHECK the concrete state first; if resolved, no-op and do NOT
re-arm. A chain of re-armed sleeps with no resolution check is an unbounded ladder wearing a
cap — the cap is per-rung, and the loop never ends.

### 1 — Never trust the event trigger alone: arm a self-check heartbeat ladder

A trigger can be mis-wired (wrong PR/run id, a webhook that never arrives) — then the
event-driven wake never fires. So **always** also arm a *self*-check-in, independent of the
event:

- **First self-check: 10 minutes** after arming the wait — wake and **check the real state
  yourself** (poll the PR / CI run / job directly via its CLI or API).
- **If still unresolved, re-arm on the ladder: 10, 10, 15, 15, 30, 30 minutes** — six further
  self-checks. Total budget ≈ **120 min (2 h)** across the seven checks.
- **After the final 30-minute rung with the awaited thing still not done → give up and die:**
  `unsubscribe` / `CronDelete` the check-in (and any subscription), then report that the wait
  was **abandoned because the event never fired** and that the trigger may have been
  mis-configured. **Never re-arm past the ladder.**
- **Any check where the awaited thing HAS happened ends the ladder early.** Genuine in-flight
  progress (CI still legitimately running) does not reset the ladder; the 2 h cap is hard —
  extending it is the user's call, never a silent re-arm.
- **Cancel on resolution — leave no orphaned trigger.** The instant the task reaches a
  terminal state by any path — a self-check or the event finds it done (good or bad), the
  give-up rung is hit, or the user interrupts to ask you to check — cancel **every**
  still-pending trigger tied to it (`CronDelete`, drop the `ScheduleWakeup`, `unsubscribe`).
  A user-driven check supersedes the scheduled ones. If the task moved on, its future
  triggers are dead.

### 2 — Event-deadline on the happy path

When waiting on a normal event (CI green, a PR merge, a queued job), the event-driven wait
still carries its own **explicit deadline** — never an open-ended re-arm. Default cap: the
same 2 h / seven-check budget unless the user sets a longer one.

### 3 — The cancel-on-resolution sweep, per trigger class

Background waits have been found alive **20+ hours** after their task ended. The sweep runs
the moment the awaited item reaches ANY terminal state, and again at work-item pickup/finish
(`TaskList` once; stop stale waits you own):

| Trigger class | Kill mechanism | Notes |
| ------------- | -------------- | ----- |
| Background Bash poll (`run_in_background`) | `TaskStop <task-id>` | Also self-terminating by construction: a hard iteration cap + wall-clock deadline INSIDE the loop. A poll without both is a defect — never launch it. |
| Cron check-in | `CronDelete` | The heartbeat ladder's rungs are crons — delete every remaining rung on resolution, not just the next. |
| PR/event subscription | unsubscribe | A user-driven check supersedes the subscription — kill it then and there. |
| `ScheduleWakeup` | **none — cannot be cancelled** | Fires regardless. Therefore: (a) FALLBACK only — harness completion notifications are the primary wake; (b) **short rung + minimal check + re-arm**, never one long wakeup at a speculative future time: arm the shortest sensible delay, and on firing do a minimal state check and re-arm the next ladder rung only if still unresolved (pick the rung by how fast the watched state actually changes; slow externals take 10 min+ rungs); (c) fixed self-invalidating prompt template: `CHECK <concrete state/command>; IF RESOLVED: no-op, do NOT re-arm; ELSE <next action> + re-arm <n> min` — a stale firing then costs one cheap turn. |

The sweep is an explicit terminal step in every wait-spawning skill (`/pr-merge`,
`/pr-merge-flow`, `/pr-comments`, `/gh-issue`, `/adr-phase`) — mechanical, not remembered.
It cannot be a workflow: `TaskStop`/`CronDelete` are orchestrator tools, invisible to
workflow agents.

### 4 — Managed environments (no `gh`): wakeup-paced MCP checks

Background bash polls presume `gh`; managed (web/app) environments may not ship it, and MCP
tools cannot be called from inside a shell loop. The portable wait:

1. **Detect once** at Step 0/1 of the skill: `command -v gh && gh auth status`. Present →
   the bash-poll snippets as written. Absent → the adaptation below; never mix per-call.
2. **Reads/writes** go through the session's GitHub MCP server (`mcp__github__*` — discover
   the exact tools via ToolSearch; names vary by server). Same data, same verdict logic.
3. **Waits become wakeup-paced checks:** do one minimal MCP state check NOW; if unresolved,
   `ScheduleWakeup` the next ladder rung with the self-invalidating template, and on firing
   check again + re-arm. The rung ladder IS the poll cadence — same escalation, same 2 h
   hard cap, same give-up-and-report rung. The sweep simplifies: there is no bash task to
   `TaskStop`; the wakeups self-invalidate by template.
4. **Workflows and scripts are unaffected:** the named workflows use only `git` + local
   commands (both present in managed environments), and workflow agents reach MCP tools via
   ToolSearch when they genuinely need GitHub state. Caveat: interactively-authenticated MCP
   servers may be absent in headless/cron runs — a skill that finds NEITHER `gh` nor a
   GitHub MCP server stops and reports rather than improvising.

## Config storage adapter rule (ADR-28 §2.2) — full text

Expansion of CLAUDE.md "Code-quality conventions (ADR-28)":

- **Storage is NOT frozen — consistent for back-compat where practical, not byte-for-byte.**
  No versioned migration routine. New options add new stored strings; read-boundary adapters
  absorb legacy tokens and writes emit a canonical token (which may differ from the legacy one
  when behaviour-equivalent). The goal is to preserve *behaviour* on upgrade, not bytes.
- **Forward-compat (upgrade) has two cases:** an existing config with the key absent reads to
  a value that **preserves that user's prior behaviour**; a brand-new config gets the new
  default. When those differ, a one-time grandfather seed sets the key for existing installs
  at upgrade (e.g. `pfb_rdns_seed_value`, `pfb_feed_filter_install_default`) so the
  absent-default never silently changes an existing user's behaviour.
- **Downgrade-tolerant.** Older releases string-compared these values, so an unknown token
  falls through to that release's safe default. Reusing a legacy token as the canonical value
  (see `pfb_idn`) keeps downgrade behaviour intact; a genuinely new token simply reads as off
  on an old release — acceptable, the feature didn't exist there.
- Enums/booleans are the **internal runtime representation**; conversion at the boundary:
  stored string → enum on read; enum → canonical stored string on write.
- **The enum owns its stored-value semantics** via the `PfbStoredEnum` interface +
  `PfbStoredEnumAdapter` trait: `EnumClass::fromStored($raw)` (read) and `$enum->toStored()`
  (write). The per-field **absent default** is the registry's `$entry['default']` (applied by
  `PfbConfig::read()` *before* the adapter); the enum's `default()` is only the
  **parse-fallback** for unknown/non-scalar tokens, never the absent-default. A field's `''`
  vs `'off'` off-value is handled by its own enum.
- **Round-trip pinned by tests** (`CfgAdaptersTest`, `RollbackContractTest`): every canonical
  token round-trips (`write(read(v)) == v`); a legacy token reads to the right runtime value
  and writes to its behaviour-equivalent canonical token (itself legacy-valid, so no novel
  on-disk value reaches an older release).
- **Explicitly out of scope (ADR-28 §2.4):** `config.xml` versioned schema/migrations;
  `py_unbound.ini` and any manifest/serialized/wire value read by Python or shell; ADR-26
  locale prefixes; genuine boolean predicates (return `bool`, not an enum); mass realignment
  of untouched lines; `stubs/`, generated artifacts, vendored code.
- Per-field adapter inventory, field-vocabulary table, since-version convention, rollback
  invariants, and the sniff's foreign-key exclusions:
  [`docs/misc/config-gateway.md`](config-gateway.md).

## Release notes pipeline

Body precedence: a **committed `docs/release-notes/TAG.md` wins** (curated, or persisted from
a prior run) — when present the Models step is skipped; else **GitHub Models**
(`actions/ai-inference`, model `openai/gpt-4.1` — no secret, the built-in token +
`permissions: models:read`, free tier) drafts it; else a placeholder (the release never blocks
on the generator). When Models runs, a shell step gathers the commits since the previous
same-channel release (`prev_tag` classifies each tag's channel via `release-version.sh`) and
feeds them with the static system prompt in `scripts/release-notes-prompt.txt`; the model
returns a `SUMMARY:` line (→ the Release title suffix; the title is
`YYYY-MM-DD - VER — 3-word summary`, ISO date prefixed so GitHub's alphabetical release sort
stays chronological) plus a Markdown block grouping user-facing changes under
**Features / Improvements / Bug Fixes** with PR/issue links (CI/test/tooling/ADR noise
filtered), ending with the compare link. A committed file carries the same notes; its title
summary rides in an optional first-line `<!-- SUMMARY: … -->` marker (stripped from the
rendered body). Generated notes are **persisted** to `docs/release-notes/TAG.md` by the
`persist-notes` job (committed to the channel branch; docs-only ⇒ CI-skipped); a pre-committed
file is left untouched. To author notes by hand, commit `docs/release-notes/TAG.md` — same
format. To swap models, change the `model:` input; to use Claude Haiku on a Max plan, flip the
step to the Claude CLI with `CLAUDE_CODE_OAUTH_TOKEN` (prompt file + parser reused).
**Nightly builds get no GitHub Release.**

**Dry-run.** `release.yml`'s `workflow_dispatch` is a no-publish harness: pass the `tag` to
simulate with `dry_run=true` (default) to validate the scheme, build the `.pkg` artifacts, and
render the body (the Models draft runs; the real body shows in the run summary) — publishing
nothing. Dispatchable only from the default branch once merged.

## Self-hosted `pkg` repository (ADR-17) — mechanics

Beyond the Netgate ports channel we publish a self-hosted FreeBSD `pkg` repository on GitHub
Pages (`pfblockerng.github.io/pkg`; NONE-signed, TLS-anchored; a derived index rebuilt from
**all** Releases each deploy). Cross-repo selection is keyed on repo **`priority:`** — it
dominates version — so our `priority: 100` (set by `add-repo.sh`) makes `pkg install`/`upgrade`
and the stock GUI Install pull our build over Netgate's. GUI discovery + the update badge stay
Netgate-bound; a GUI "Updates/Channel" panel is deferred (ADR-19; would touch `src/`).

Full varver/ABI rationale + live proof + upgrade-lag, the boot-time `rc.d` conf regenerator
(ADR-39), the publish pipeline (the separate `pfBlockerNG/pkg` repo + its OIDC deploy), the
generators + `add-repo.sh` bootstrap, and the `repo`-marker smoke flow:
[`docs/misc/architecture-notes.md`](architecture-notes.md) ("Self-hosted pkg distribution").

## ADR amendments after merge

An Accepted/Implemented ADR is still the spec its future readers plan against — stale text
seeds repeat defects (the #1008 scrub removal overturned ADR-60 §2.1/§2.4; the un-amended
ADR text then seeded #1047).

- **When a post-merge fix overturns a piece of an Accepted/Implemented ADR** — a review
  finding, an issue fix, anything that invalidates a decision, contract, or stated fact —
  the ADR gains (or extends) a **§8 "Post-merge amendments" section in the same change**
  as the fix. The correction never lives only in the issue/PR.
- Earlier sections stay as written (the historical record); §8 is the authoritative
  correction: one numbered item per overturned piece, each naming the issue/commit that
  overturned it and the corrected decision.
- Exemplars: `.ADRs/ADR_60_Age_Based_Log_Retention/ADR.md` §8 and
  `.ADRs/ADR_61_Sync_Status_Ledger/ADR.md` §8.
- ADR text is the dev-only no-PR class, so the amendment commits directly to `devel`
  alongside (or immediately after) the fix landing.

## Managed-remote sessions: branch policy + cross-session resume (full text)

A managed remote (web/app) session mints its own branch — `claude/<slug>-<rand>`. Where you
may push is set by the environment's branch-push policy (configured in the environment/
trigger, not this repo — see <https://code.claude.com/docs/en/claude-code-on-the-web>). Two
configurations, in order of preference:

**Session-worktree environments (probe before assuming).** Some environments also cut **one
linked worktree per session** and start the session inside it: rc-mode (mobile Devices view)
at `<primary>/.claude/worktrees/bridge-<session-id>` on branch `worktree-bridge-<session-id>`
(pushes NOT pinned — probed 2026-07-14: skills mint canonical branches as usual), managed
environments one worktree per session named after the first-prompt issue. The session
worktree is the orchestration home, never the work-item worktree (CLAUDE.md "Worktrees" —
"Session layouts"). In an unfamiliar environment, probe at task start instead of assuming:
`git rev-parse --git-dir --git-common-dir` (differing ⇒ linked worktree) and the push policy;
an unverified "pushes are pinned here" is ASSUMED and must be probed before it shapes branch
choice.

**Preferred — allow pushing to the canonical work-item branch.** Configure the push policy to
permit the repo's own `adr/{NN}-{slug}` and `issue/{NN}-{slug}` branches (keep `devel`/`main`
PR-only). Then a managed-remote session works the item on its canonical branch exactly as
off-appliance, and resume is native — `/adr-phase` / `/gh-issue` recompute the slug and find
the existing branch with no archaeology. The hard "never push anywhere but the session branch"
pin is the wrong default for this repo — always carve out this exception.

**One branch per work item.** Whichever model is in force, a branch belongs to the single
issue/ADR it was opened for. Asked to handle a different item than the branch was minted for
⇒ cut a new branch named for the new item off the latest `origin/devel` and push there. Only
when the environment hard-pins pushes to that one stale branch is reuse acceptable — and then
flag the name/item mismatch to the user before proceeding.

**Fallback — push hard-pinned to the minted `claude/*` branch.** The pinned branch replaces
the convention for the session. Each session gets a fresh branch, so work spans sessions only
if a resuming session finds the prior one:

- **Record the override loudly + machine-readably** in the first handoff: the prose override
  plus a greppable sentinel `ADR-RESUME: branch=<actual-branch> next-phase=<N>` (or
  `ISSUE-RESUME:` for an issue).
- **Before starting an ADR/issue fresh, DISCOVER prior work:** `git fetch origin`; scan remote
  branches for that item's committed handoffs (`RESULTS/{NN}_*`) and the `*-RESUME:` sentinel;
  select the candidate with the highest contiguous completed phase.
- **Resume by fast-forward onto your own branch** (push is pinned): replay/cherry-pick the
  discovered commits onto the current session branch (shared base `devel` ⇒ clean linear
  replay), continue the remaining phases, push to *your* branch, carry the sentinel forward
  with an updated `next-phase`.
- **Auto-resume WITHOUT asking iff unambiguous:** exactly one viable candidate, a valid
  sentinel, no sign of a concurrent live session. `AskUserQuestion` only on genuine ambiguity.

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

## Validating workflow records

What the calling session does with the schema-forced records a delegation workflow returns
(`phase-step`'s `{reconcileRecord, handoff, gateRecord}` — `/adr-phase`, `/gh-issue --fix`, and
`/delegate` all point here). **Validate, don't re-derive**: the workflow's independent
verifier just re-ran the gates, re-executed the red proof, and read the full diff, with
pasted evidence — a third derivation is redundant spend.

- Every fixed field non-empty and internally consistent — a missing/empty field rejects
  the record, never a judgment call.
- Every evidence entry is an executed command + pasted output, not prose.
- Spot-read the load-bearing diff hunks the verdicts rest on.
- Do NOT re-run the gates, re-execute the red proof, or re-read the whole diff the
  verifier just processed.
- Reject a record with any failed or missing item; rejection means HALT (or one corrected
  re-run) — never patch the record yourself.

## Agent-ops scripts (`scripts/agent/`)

The mechanical procedures the skills used to restate in prose live once, tested, in
`scripts/agent/`: `wait-reviewer.sh` (reviewer-wait state machine), `wait-checks.sh`
(CI wait), `verify-red-proof.sh` (red→green re-execution + freeze hash),
`run-gates.sh` (canonical-gates runner), `work-branch.sh` (branch sanitiser +
worktree cutter). Shared contract in `scripts/agent/agent_env.sh`; behaviour pinned
by `tests/shell/agent_*_spec.sh`.

- **Portability contract.** All network access rides the `gh`/`git` CLIs — managed
  cloud environments route git/ssh/https through a localhost proxy that only those
  CLIs inherit; never call raw endpoints. `gh` absent → the script exits **3** with a
  `GH-UNAVAILABLE` message: the agent falls back to `mcp__github__*` tools with
  wakeup-paced checks (CLAUDE.md "No orphaned waits" #4) — MCP tools are harness
  tools, unreachable from inside a shell, so the fallback cannot live in the script.
  Any other missing tool → exit **4** (`TOOL-MISSING`). Exit **2** = usage/precondition,
  **1** = the check itself failed, **0** = verdict reached.
- **Agent-maintained.** These scripts encode environment mechanics that drift. When an
  environment change breaks one, the agent fixes the script **in the same session** and
  lands it via the normal flow (scripts are code-bearing: worktree + PR) — never works
  around it silently in a transcript.
- **Hook-context safety.** Git-touching scripts (and any spec whose fixtures run git)
  scrub the hook-exported `GIT_DIR`/`GIT_INDEX_FILE`/… via
  `scripts/lib/git-env-scrub.sh` (ADR-47) — inherited hook env otherwise aims fixture
  git ops at the live repository.
- **Gate re-runs vs the pre-commit hook (recorded-skip carve-out).** THE GATE item 1's
  `run-gates.sh` re-run may be recorded as SKIPPED for a gate the pre-commit hook
  **provably just executed identically**: the gater watched that gate's `[pre-commit]`
  step line pass on the exact commits being gated, same session, no `--no-verify`. Two
  hook properties keep this narrow: the hook **skips missing tools instead of failing**
  (a green commit is not proof a gate ran — only its step line is), and its shellspec
  run is **impacted-scoped**, not the full suite, so it never satisfies the canonical
  full-suite shellspec gate. In practice the carve-out covers whole-tree
  `markdownlint`, the per-file `sh -n`/`shellcheck`/`php -l` lint gates, and the
  phpstan/phpcs analyses (the hook runs both, memory-capped, off the same configs);
  the unit suites (`pytest`, `phpunit`) and the full shellspec run exist only in
  `run-gates.sh` and are never satisfied by pre-commit.
