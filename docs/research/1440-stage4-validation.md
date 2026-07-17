# Stage 4 — selective-loading validation on both clients (#1440, map #1383)

Executed 2026-07-17. Ticket: [#1440](https://github.com/pfBlockerNG/pfBlockerNG/issues/1440).
Validates the #1386 findings §7 walkthroughs against the live post-Stage-3 tree and confirms
the §8.4 byte budgets held.

## Environment

- Tree under test: detached worktree at `origin/devel` `ee127bdb` (post-#1439).
- Claude Code 2.1.212, headless `claude -p --model sonnet --allowedTools "Read,Grep,Glob"
  --max-turns 40 --verbose --output-format stream-json` (read-only tool set; no Bash, so no
  side effects possible).
- Codex CLI 0.144.5, headless `codex exec --sandbox read-only --json`, default model
  (`gpt-5.6-sol` family per the #1438 probe environment).
- One probe per §7 role row: 3 task shapes × 7 role rows × 2 clients = 14 runs, all
  completed exit 0 (runner logs preserved the per-probe timestamps; Claude leg 20:02–20:16,
  Codex leg 20:02–20:30 local).

## Method

Each probe was a fresh headless session in the probe worktree, prompted with role + task
only — document names were never mentioned. The prompt forbade performing the task and asked
the agent to read exactly what the repository's bootstrap routing directs that role to load,
then self-report `LOADED:` and `MISSING:`. The authoritative loaded set was parsed from the
transcript, not the self-report: Claude `Read` tool-use `file_path`s from the stream-json
events; Codex file paths named in executed commands (read-only sandbox). Self-reports were
cross-checked against the transcript sets and agreed in all 14 probes.

Task shapes (verbatim premise, hypothetical):

- **A — PHP UI bug fix**: `www/pfblockerng/pfblockerng_alerts.php` prints
  `Undefined array key "geoip"`; no configuration field added or changed.
  Roles probed: explorer (triage), implementer, reviewer.
- **B — Python DNSBL pipeline change**: duplicate manifest entry when a feed ABP source
  lists the same domain twice; `pfb_unbound.py` + manifest handling.
  Roles probed: planner, implementer, reviewer.
- **C — Release cut**: cut `v4.0.0.alpha.9` from devel. Role probed: publisher.

§7 predictions were adapted to the post-Stage-1/3 tree before judging: triager→explorer and
operator→publisher (role registry names), `review.md`→`landing.md` (folded in Stage 1,
recorded on the map), predicted sets = role-contract floors ∪ fired routing rows.

Pass rule per probe: every required document loaded, AND no §7-forbidden load (walkthrough C
reads zero smoke/DNSBL/delegation text; walkthrough A's implementer reads zero
release/waits/sessions text). Meta/orientation docs (`AGENTS.md`, `CLAUDE.md`, `RTK.md`,
`workflow.md`, `agent-roles.md`, `.claude/rules/*`) tolerated everywhere — the bootstrap and
role registry are how a fresh session finds its floor.

## Verdicts — 14/14 PASS

| Probe | Required set loaded | Forbidden loads | Noted extras |
| ----- | ------------------- | --------------- | ------------ |
| Claude A-explorer | `issues.md` + arch-notes "Web UI test tiers" ✓ | none | `lang-php.md` (touched subsystem) |
| Claude A-implementer | `coding.md` `testing.md` `lang-php.md` + web-UI row ✓ | none | `smoke.md` (Tier-A `ui_render` duty), `git.md`, `issues.md`; `pfsense-live.md` read-to-rule-out; `config-gateway.md` correctly skipped |
| Claude A-reviewer | `testing.md` `landing.md` `lang-php.md` + web-UI row ✓ | none | `coding.md` |
| Claude B-planner | `delegation.md` + arch-notes "DNSBL/ABP pipeline" ✓ | none | `testing.md` `coding.md` `lang-python.md` (coverage-matrix relevant) |
| Claude B-implementer | `coding.md` `testing.md` `lang-python.md` + DNSBL row ✓ | none | `delegation.md`, `git.md` |
| Claude B-reviewer | `testing.md` `landing.md` `lang-python.md` + DNSBL row ✓ | none | `coding.md` |
| Claude C-publisher | `release.md` `git.md` `landing.md` ✓ | none | `waits.md` (bounded CI-wait duty) |
| Codex A-explorer | ✓ | none | — |
| Codex A-implementer | ✓ | none | `delegation.md` `issues.md` `git.md` `smoke.md` `pfsense-live.md` |
| Codex A-reviewer | ✓ | none | `delegation.md` `issues.md` `alerts-reports-pipeline.md` |
| Codex B-planner | ✓ | none | `pfsense-live.md`, `docs/history/incidents.md` |
| Codex B-implementer | ✓ (exactly the floor + rows — tightest probe of the set) | none | — |
| Codex B-reviewer | ✓ | none | `delegation.md` |
| Codex C-publisher | ✓ | none | arch-notes read was a *targeted* heading-grep → `sed -n '795,925p'` = "Self-hosted pkg distribution (ADR-17/20)" + publish pipeline — release-relevant, zero DNSBL/smoke text; `sessions.md` |

`MISSING` was **"no routed document missing"** in all 14 probes — nothing critical was
squeezed out by the extraction or the budgets. Every probe that faced the
`config-gateway.md` iff-condition (task states no field touched) excluded it correctly.

## Budget confirmation (§8.4)

`python3 scripts/check_context_budget.py --all` exit 0 on `ee127bdb`. Measured:

| File | Bytes | Budget |
| ---- | ----- | ------ |
| `AGENTS.md` (bootstrap) | 10,041 | 10,240 |
| `CLAUDE.md` (adapter) | 6,498 | 8,192 |
| `landing.md` | 25,819 | 26,000 (ratchet) |
| `agent-roles.md` | 18,906 | 19,000 (ratchet) |
| `delegation.md` | 17,774 | 18,000 (ratchet) |
| every other policy/context file | ≤ 9,959 | 12,288 |

## Observations (non-blocking)

1. **Release dispatch mechanics live only in the `/release` skill.** Both publishers flagged
   that no routed policy/context doc gives the `release.yml` dispatch procedure, and that
   `landing.md` is PR-shaped (no reconciliation against a tag-only `workflow_dispatch` cut).
   This matches the design — skills carry operator procedure, policy carries law — but the
   probes could not know the skill exists from the routing table alone.
2. **`docs/misc/alerts-reports-pipeline.md` has no routing-table row.** Claude's A-explorer
   flagged it as the closer fit for the alerts-page task; Codex's A-reviewer found and read
   it anyway. Candidate one-line routing row (AGENTS.md has 199 spare bytes).
3. **Codex leans on more meta/orientation docs** (`delegation.md` in 4 of 7 probes,
   `issues.md`, `sessions.md`) — same required sets, slightly larger halos. Behavioral
   equivalence holds; byte-for-byte parity was never the goal (map: "Behavioral equivalence,
   not surface parity").
4. Probe realism limits: orientation-shaped prompts (no real issue/PR/brief attached), one
   run per cell, Sonnet/GPT-5.6 tiers. The probes measure routing discovery, not full-task
   behavior — full-task evidence is the #1429/#1430 pilots.

## Deletion

`docs/misc/workflow-reference.md` (dissolved routing shell) deleted on devel — its stated
removal condition ("deleted once the Stage 4 pilots pass") was met by this validation.
Tree-wide basename sweep found only two era-history mentions (`docs/misc/ai-lessons-2026-07.md`,
`docs/history/incidents.md`), both accurate as written. No quarantined duplicates existed
(`grep -rni "quarantin"` over the tree: zero hits outside `.git`). Budget checker green
after removal.
