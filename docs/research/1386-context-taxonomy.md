# Research #1386 — Selective policy and domain-context loading

Wayfinder RESEARCH ticket #1386 (map #1383). Design only; no content moved.

Buckets used throughout (ticket's six): **UI** universal invariant · **RS** role-specific
standard · **DC** domain/language context · **WP** workflow protocol · **HR** historical
rationale / incident archaeology · **OD** obsolete or duplicated.

---

## 1. Measured hot-context cost (executed, not guessed)

```text
$ wc -c CLAUDE.md docs/misc/workflow-reference.md AGENTS.md .agents/model-tiers.conf
   68630 CLAUDE.md
   28028 docs/misc/workflow-reference.md
    4585 AGENTS.md
     318 .agents/model-tiers.conf
  101561 total
```

Hook capsules extracted from `.claude/settings.json` (`additionalContext` payload length):

```text
SessionStart 1157 bytes capsule
UserPromptSubmit 1103 bytes capsule
SubagentStart 1761 bytes capsule
```

At the usual ~4 bytes/token approximation:

| Surface | Bytes | ~Tokens | When paid |
| ------- | ----- | ------- | --------- |
| `CLAUDE.md` | 68,630 | ~17,200 | Every main session AND injected verbatim into every subagent's system prompt (observed in this session's own system-reminder) |
| SessionStart capsule | 1,157 | ~290 | Once per session |
| UserPromptSubmit capsule | 1,103 | ~275 | **Every turn** |
| SubagentStart capsule | 1,761 | ~440 | Every subagent |
| `AGENTS.md` (Codex adapter) | 4,585 | ~1,150 | Every Codex session (plus CLAUDE.md, which it mandates reading) |

Already selectively loaded (annex layer works today — the defect is only the hot file):

| Annex | Bytes | ~Tokens |
| ----- | ----- | ------- |
| `docs/misc/workflow-reference.md` | 28,028 | ~7,000 |
| `docs/misc/architecture-notes.md` | 111,729 | ~27,900 |
| `docs/misc/config-gateway.md` | 17,771 | ~4,400 |
| other `docs/misc/*.md` (13 files) | ~103,000 | ~25,800 |

So the hot surface is ~17.5k tokens per agent (main or sub), dominated by CLAUDE.md, of
which — per the matrix below — only ~15–20% is universal invariant; the rest is
role-/task-conditional detail every agent pays for regardless of relevance. A ticket premise
check: the premise holds; nothing in the tree contradicts it.

---

## 2. Classification inventory

### 2.1 CLAUDE.md — every section (42 headings, no "etc.")

Line refs are current `CLAUDE.md` on `origin/devel` (64cf3769).

| # | Section (line) | Bucket | Notes / intended home |
| - | -------------- | ------ | --------------------- |
| 1 | H1 `Shared agent policy` (1) | UI | Bootstrap: identity + canonical-source statement |
| 2 | `Scope — the pfBlockerNG-org default` (9) | UI | Bootstrap (compressed: 3 lines) |
| 3 | `Working principles — don't guess` (28) | UI | Bootstrap (the one-line top rule) |
| 4 | `Ambiguity — confirm before you build` (34) | UI | Bootstrap (compressed) |
| 5 | `Investigate, don't assume` bullets (44) | DC | pfSense/live-system context — the seven bullets are pfSense-specific; already expanded in workflow-reference "Live-system investigation gotchas" ⇒ CLAUDE.md copy is **OD** (summary duplicating the annex); keep one line + route |
| 6 | `Resolve pfSense-provided PHP functions` (63) | DC | PHP/pfSense context; **OD** duplicate of workflow-reference §"Resolving pfSense-provided PHP functions" — keep only the annex |
| 7 | `Evidence rules` (72) | UI (rule) + HR (inline #902/#933/#935/ADR-59 archaeology) | Bootstrap keeps 4 one-liners; archaeology → history refs |
| 8 | `Plan top-tier, implement small-tier` (94) | WP + RS (planner) | Delegation/workflow doc. ADR-phase paragraphs (Reconcile stage, light phases, issue #1089 redesign) are **WP-legacy**: map #1383 stops new implementation-plan ADRs — route to a legacy-flow doc slated for retirement after pilots |
| 9 | `The delegation contract` intro (158) | WP | Delegation doc; HR inline (#900–#909) → history |
| 10 | `THE BRIEF` (168) | RS (planner) | Delegation doc; heavy inline HR (#858, #901, #904, #881, #937, #941, #943) → history |
| 11 | `THE HANDOFF` (217) | RS (implementer) | Delegation doc |
| 12 | `THE GATE` (230) | RS (planner/verifier) | Delegation doc; HR inline (#900, #905, #937, #941, #943) |
| 13 | `Canonical gates` table (271) | UI (the table is load-bearing for everyone who commits) | Standards: verification doc. Keep a 2-line pointer + `run-gates.sh` name in bootstrap |
| 14 | `Test coverage (mandatory)` — 5 principles + how-to (286) | UI (the 5 principles) + RS (the how-to bullets: implementer/reviewer) | Principles: 5 one-liners in bootstrap or testing standard's header; how-to (branch coverage, before-state, isolation, BDD, expected-vs-actual, red canary) → testing standard. HR inline (#933, #937, #943, tick bug) |
| 15 | `ADR acceptance` (356) | WP-legacy | ADR-era; retires with ADR flow per map #1383 |
| 16 | `Communication` (367) | WP (vendor-leaning: hooks are Claude mechanics) | Bootstrap keeps the two style exceptions (1 line); mode activation stays in hooks (already mechanical) |
| 17 | `Work-context marker` (379) | WP | Communication/protocol doc; not needed by subagents at all |
| 18 | `Code standards` H2 (402) | — | Container heading |
| 19 | `Naming — follow the established pattern` (404) | UI | Coding standard (universal but only relevant when writing code ⇒ implementer-routed) |
| 20 | `Comments — constraint, not narration` (412) | RS (implementer/reviewer) | Coding standard; enforced by `check_comment_narration.py` anyway (mechanical backstop exists) |
| 21 | `PHP` (434) | DC | `lang-php` context |
| 22 | `Python` (442) | DC | `lang-python` context; "No Python on appliance" is UI-grade but mechanically enforced (`check_appliance_python.py`) ⇒ one bootstrap never-list line + detail routed |
| 23 | `Shell` (466) | DC | `lang-shell` context |
| 24 | `External processes` (482) | DC | Pointer stub; full text already in `docs/misc/external-process-waits.md` — **OD** summary, keep 1 line |
| 25 | `Code-quality conventions (ADR-28)` table (492) | RS (implementer) | Coding standard |
| 26 | `Config gateway — PfbConfig (ADR-29)` (502) | DC | pfSense-config context; detail already in `docs/misc/config-gateway.md` — CLAUDE.md copy partially **OD** |
| 27 | `Linting` (520) | RS (implementer) | Verification standard; the per-checker detail (URL-encoding, version-literal, narration, retired-token) is enforced by pre-commit + CI ⇒ agents only need "hooks + `run-gates.sh` are authoritative" |
| 28 | `Worktrees (mandatory for AI agents)` (560) | UI (the mandate) + WP (session layouts, reuse rules) | Mandate: 1 bootstrap line + `work-branch.sh`; mechanics → git/session protocol doc |
| 29 | `Git hooks` (600) | WP | Git protocol doc (hooks are self-enforcing; agents need only "activate once" + bypass prohibition) |
| 30 | `Running tests` (620) | DC | Verification/testing context (env gotchas: zstd, root-skip) |
| 31 | `Smoke tests (ADR-04)` (650) | DC | DNS/smoke domain context — the largest purely-domain block in the hot file (~6.5 KB) |
| 32 | `Branches and releases` (700) | DC + WP | Release context; landing-flow paragraph is WP (review protocol) |
| 33 | `Branch naming` (760) | WP | Git protocol; mechanically implemented by `work-branch.sh` — agents need the script name, not the 5-step sanitiser |
| 34 | `Managed-remote sessions` (785) | WP | Session protocol; **OD** summary of workflow-reference full text |
| 35 | `GitHub issues` (800) | WP | Issue protocol doc |
| 36 | `Scanner/audit finding gate` (807) | RS (triager) | Security-triage standard |
| 37 | `TypeError-class tracker (#1143)` (830) | RS (triager) + HR | Security-triage standard; heavily archaeological |
| 38 | `Labels (lifecycle)` (838) | WP | Issue protocol (map #1383 adds needs-info/needs-triage/ready-for-* — this section changes anyway) |
| 39 | `Commit style` (848) | WP | Git protocol; attribution detail **OD** vs workflow-reference "Author, committer, and signing" |
| 40 | `No orphaned waits` (868) | WP | Waits protocol; **OD** summary of workflow-reference "Bounded waits" — keep 2 lines + route |
| 41 | `Repository structure` (900) | DC | Bootstrap candidate (small, universally useful — 15 lines) or repo-context doc |
| 42 | `Updating documentation` (915) | WP | Docs protocol + `version-bump-runbook` pointer |

### 2.2 workflow-reference.md — every section (11 H2s)

| # | Section | Bucket | Intended home |
| - | ------- | ------ | ------------- |
| 1 | Live-system investigation gotchas | DC | pfSense/live-system context (as-is) |
| 2 | Resolving pfSense-provided PHP functions | DC | lang-php / pfSense context (as-is) |
| 3 | Bounded waits — the full ladder (§0–§4) | WP | Waits protocol (as-is) |
| 4 | Config storage adapter rule (ADR-28 §2.2) | DC | Config-gateway context (merge candidate into `config-gateway.md` — same topic, two files today) |
| 5 | Release notes pipeline | DC | Release context |
| 6 | Self-hosted pkg repository (ADR-17) mechanics | DC | Release/packaging context |
| 7 | ADR amendments after merge | WP-legacy + HR | Legacy ADR-flow doc; stays as history-maintenance rule while ADR corpus exists |
| 8 | Managed-remote sessions (full text) | WP | Session protocol |
| 9 | Author, committer, and signing (full text) | WP | Git protocol |
| 10 | Validating workflow records | WP-legacy | Tied to `phase-step` workflow; retires with ADR-era orchestration after pilots (map #1383) |
| 11 | Agent-ops scripts (`scripts/agent/`) | WP | Delegation/verification doc (scripts are the mechanical layer both vendors share) |

### 2.3 Other always-or-sometimes policy carriers

| Carrier | Bucket | Verdict |
| ------- | ------ | ------- |
| `AGENTS.md` (4,585 B) | WP (vendor adapter) | Correct shape already: pure surface-mapping, no duplicated policy. Under the new model it grows into the canonical bootstrap (see §3) |
| SessionStart capsule (1,157 B) | WP | Keep; shrink — half of it restates "read CLAUDE.md and the annex", which the bootstrap makes redundant |
| UserPromptSubmit capsule (1,103 B/turn) | UI (discipline reminders) | Keep — it is the per-turn floor and is cheap; its 8 items must match the bootstrap invariant list 1:1 (today it paraphrases) |
| SubagentStart capsule (1,761 B) | WP + RS | Keep; this is the natural place for the ROLE ROUTING line (see §4) |
| `.agents/skills/*` (~60 skills) | WP | Already selective by construction (load on invocation). No change; several restate CLAUDE.md mandates — dedupe opportunity, out of scope here |
| `.claude/workflows/*.js` prompts | RS | Already selective; role briefs are where role-routed reading lists live |
| `docs/misc/architecture-notes.md` (111,729 B, ~28 domain sections) | DC | Already selective; needs `Load-when:` headers per section index, not restructuring |
| `docs/misc/config-gateway.md`, `external-process-waits.md`, `local-smoke-debian.md`, `version-bump-runbook.md`, `pfSense_versions.md` | DC | Already selective; keep, add headers |
| `docs/misc/ai-lessons-2026-07.md`, `adr-7day-review-2026-06-26.md` | HR | History layer (as-is) |
| `docs/misc/codex-migration.md` | WP + HR | Partially superseded by `.agents/` layout; fold live parts into the adapter docs, mark the rest historical |
| `docs/misc/hsts-preload-list.md`, `public-suffix-list.md`, `tld-lists.md`, `top1m-providers.md`, `alerts-reports-pipeline.md`, `haproxy-*`, `logo-vectorization.md` | DC / HR | Data-source and one-off notes; already cold |
| `.agents/model-tiers.conf` (318 B) | UI | Stays; referenced from bootstrap |

Classification totals for the hot file: of CLAUDE.md's ~68.6 KB, the UI-bucket content
compresses to roughly 4–6 KB; DC ≈ 24 KB (PHP/Python/Shell/smoke/release/config/arch
pointers); WP ≈ 28 KB (delegation, waits, git, sessions, issues); the rest is inline HR
(issue-number archaeology woven into rules — at least 40 distinct issue/PR citations) and OD
(summaries duplicating workflow-reference/annex full texts).

---

## 3. Proposed document tree

Design constraints honoured: vendor-neutral (`.agents/` is already the neutral home — skills
and `model-tiers.conf` live there); reuse the existing annex layer (`docs/misc/` domain docs
stay put — the defect is the hot file, not the cold ones); NOT Matt Pocock's literal layout
(this repo's context is dominated by appliance/domain gotchas and a delegation protocol, not
API-shaped "context maps"; the ticket's warning is confirmed — a per-entity context-map tree
has nothing to attach to here).

```text
AGENTS.md                     # THE bootstrap (canonical, vendor-neutral) — target ≤8 KB
CLAUDE.md                     # thin Claude adapter: "AGENTS.md is canonical" + Claude-only
                              # surface notes (~1 KB) — inverts today's naming asymmetry
.agents/policy/
  invariants.md               # the full never-list, one line each + enforcement pointer
  delegation.md               # tiers, brief/handoff/gate, agent-ops scripts, record validation
  waits.md                    # no-orphaned-waits + full ladder (absorbs wf-ref §3 + CLAUDE §40)
  git.md                      # worktrees mechanics, hooks, branch naming, commit style,
                              # attribution/signing (absorbs CLAUDE §28-29/33/39 + wf-ref §9)
  sessions.md                 # session layouts, managed-remote, resume (CLAUDE §34 + wf-ref §8)
  issues.md                   # whole-issue reading, labels (new intake labels per #1383),
                              # security/scanner triage gate, #1143 tracker (CLAUDE §35-38)
  review.md                   # landing flow, reviewer contract pointer, applying findings
                              # coverage-discipline (CLAUDE §32's WP half)
  testing.md                  # the 5 principles + the how-to bullets + red canary +
                              # "Running tests" env gotchas (CLAUDE §14/30)
  coding.md                   # naming, comments budget, ADR-28 table, linting-is-mechanical
                              # (CLAUDE §19-20/25/27)
  legacy-adr-flow.md          # ADR acceptance, amendments, phase/Reconcile machinery,
                              # workflow-record validation — quarantined for retirement
                              # after #1383 pilots
.agents/context/              # domain/language contexts (small, new) — language files are
  lang-php.md                 # CLAUDE §21 + wf-ref §2 (upstream-resolution ladder)
  lang-python.md              # CLAUDE §22
  lang-shell.md               # CLAUDE §23 + locale pointer
  pfsense-live.md             # wf-ref §1 gotchas + CLAUDE §5 (single copy)
  smoke.md                    # CLAUDE §31 (smoke truths, PFB_BOXES, UI tiers pointer)
  release.md                  # CLAUDE §32 (channels/tags) + wf-ref §5-6
docs/misc/                    # UNCHANGED home for big domain references:
  architecture-notes.md       #   + per-section Load-when index at top
  config-gateway.md           #   + absorbs wf-ref §4 (storage adapter rule)
  external-process-waits.md, local-smoke-debian.md, version-bump-runbook.md, ...
docs/history/                 # HR layer (rename-in-place candidates, or stay in docs/misc/)
  incidents.md                # NEW: the issue-number archaeology extracted from rules —
                              # one line per incident: what shipped, which rule it pinned
  ai-lessons-2026-07.md, adr-7day-review-2026-06-26.md   (moved or linked as-is)
```

`docs/misc/workflow-reference.md` dissolves: §1→pfsense-live, §2→lang-php, §3→waits,
§4→config-gateway, §5–6→release, §7/§10→legacy-adr-flow, §8→sessions, §9→git,
§11→delegation. Nothing is deleted; every displaced paragraph moves verbatim (history
preserved by git and by `docs/history/incidents.md` links).

### Bootstrap content (AGENTS.md, target ≤8 KB / ~2k tokens)

1. Identity + scope (org default, mechanics-vs-how-we-work split) — ~15 lines.
2. Working principles: don't guess; ambiguity fork rule; 4 evidence one-liners — ~20 lines.
3. The never-list (hard invariants, one line each): worktrees mandatory; rebase-only merges;
   test-first red proof; every change ships with tests; no coverage theater; no Python on
   appliance; POSIX sh only; config via PfbConfig; no orphaned waits; `--no-verify` is not
   for agents; never weaken a mandate without quoted authorization — ~15 lines.
4. Mechanical enforcement note: pre-commit/CI/`run-gates.sh` are authoritative; hooks carry
   the mode capsules — ~5 lines.
5. **The routing table** (see §4) — ~30 lines.
6. Repository structure block (current §41) — ~15 lines.
7. Communication: two style exceptions; tier vocabulary + `model-tiers.conf` pointer — ~8 lines.

---

## 4. Loading rules (routing)

### 4.1 Mechanisms, vendor-neutral first

1. **Bootstrap routing table** (primary, fully vendor-neutral — both clients read the
   bootstrap). Shape:

   | Task touches | Read first |
   | ------------ | ---------- |
   | delegating any step | `.agents/policy/delegation.md` |
   | waiting on anything external | `.agents/policy/waits.md` |
   | committing / branching / landing | `.agents/policy/git.md`, `.agents/policy/review.md` |
   | a GitHub issue | `.agents/policy/issues.md` |
   | writing/changing tests | `.agents/policy/testing.md` |
   | writing code (any) | `.agents/policy/coding.md` + the `lang-*.md` for each touched language |
   | `pfb_unbound.py`, manifest, swap/watcher | arch-notes "DNSBL/ABP pipeline" |
   | `tests/smoke/**` | `.agents/context/smoke.md` (+ `local-smoke-debian.md` to run) |
   | config fields / `PfbConfig` | `docs/misc/config-gateway.md` |
   | live pfSense box | `.agents/context/pfsense-live.md` |
   | release / tags / pkg repo | `.agents/context/release.md` |
   | `www/` UI | arch-notes "Web UI test tiers" + `.agents/context/lang-php.md` |
   | process spawn/timeout/daemon | `docs/misc/external-process-waits.md` |
   | ADR corpus (legacy) | `.agents/policy/legacy-adr-flow.md` |

2. **Per-directory instruction stubs** (vendor-neutral: Claude Code loads nested `CLAUDE.md`
   on directory access; Codex reads nearer `AGENTS.md`). One ≤400-byte stub pair in
   `tests/smoke/`, `src/usr/local/www/`, `src/usr/local/pkg/pfblockerng/`, `scripts/agent/`
   pointing at the matching context doc. Backstop for agents that skip the routing table.

3. **Role briefs name required reading** (already the delegation contract's "Required
   reading" section — reuse, don't invent). The planner's brief lists the exact `lang-*`/
   domain docs for the step; role definitions (`.claude/workflows/*.js`, `.codex/agents/*.toml`)
   carry the per-role floor.

4. **Hooks** (vendor-specific, already mapped via `.codex/hooks.json`): capsules only. The
   SubagentStart capsule gains one line: "ROLE ROUTING: load only the bootstrap's routing-table
   rows your task touches; do not read policy docs outside your rows."

### 4.2 Per-role floors

| Role | Always (beyond bootstrap) | Conditional |
| ---- | ------------------------- | ----------- |
| planner / coordinator | `delegation.md` | `issues.md` (issue work), `review.md` (landing), `waits.md` (armed a wait) |
| implementer | `coding.md`, `testing.md`, touched `lang-*.md` | domain rows for touched paths (per routing table / dir stubs) |
| reviewer / verifier | `testing.md`, `review.md` | touched `lang-*.md` + domain rows of the diff |
| triager | `issues.md` | `pfsense-live.md` (live repro), domain row of the suspect subsystem |
| release operator | `context/release.md` | `git.md` (tag/push mechanics) |

### 4.3 Anti-monolith rules (what stops re-accretion)

1. **Byte budgets, CI-enforced** (a tiny checker in the existing pre-commit/CI checker family,
   e.g. `scripts/check_context_budget.py`): bootstrap ≤8,192 B; each hook capsule ≤1,200 B;
   each dir stub ≤400 B; each `.agents/policy/*.md` ≤12 KB. Over budget = red CI. Adding to
   the bootstrap forces removing equal bytes — the budget is the intake gate.
2. **No unconditional references.** The bootstrap may not say "read X before any work" for
   anything except itself; every routing row must carry a trigger condition. CI check: grep
   the bootstrap for reference lines lacking a "when/touches" clause is a review rule, the
   byte cap is the mechanical floor.
3. **One-hop mandatory depth.** A routed doc must be self-sufficient for its trigger; it may
   point onward for detail but may not make a second document mandatory (exception: a
   language doc pointing at arch-notes for a named subsystem section). Prevents the
   reference graph from becoming a load-everything chain.
4. **New-rule intake protocol.** A new rule lands in its bucket's standard/context doc, never
   the bootstrap, unless it is a genuine never-list invariant — and then it costs a line
   elsewhere (budget). Incident citations land in `docs/history/incidents.md` with a
   back-link, never inline in the rule (the rule keeps at most `(incident I-NN)`).
5. **Ownership/freshness headers.** Every routed doc starts with a fixed header block:
   `Scope:` (one line), `Load-when:` (the routing trigger, verbatim from the table),
   `Owner:` (default: repo owner), `Last-verified:` (date). The budget checker also asserts
   header presence for any file referenced from the routing table — a doc without a
   `Load-when:` header cannot be routed. Freshness sweep: re-verify headers at each min-CE
   version bump (already a runbook) and whenever a doc's subject code changes (reviewer
   checklist line in `review.md`).
6. **Capsule/bootstrap parity.** The UserPromptSubmit discipline capsule must be a strict
   subset of bootstrap invariant lines (today it paraphrases — drift risk). One parity check
   in the same CI checker.

---

## 5. Content-movement matrix summary

Full per-section mapping is §2.1/§2.2 (the "intended home" column). Aggregate movement:

| Destination | Sources (sections) | Est. size |
| ----------- | ------------------ | --------- |
| `AGENTS.md` bootstrap | C1–4, C7 (rules only), C13 (pointer), C14 (5 principles), C16 (exceptions), C41; never-list distilled from C22/C23/C26/C28/C32/C40 | ≤8 KB |
| `CLAUDE.md` adapter | inversion of today's AGENTS.md role | ~1 KB |
| `policy/delegation.md` | C8–C12, W11, parts of C13 | ~14 KB → split if over budget (contract vs tiers) |
| `policy/waits.md` | C40 + W3 | ~7 KB |
| `policy/git.md` | C28 (mechanics), C29, C33, C39 + W9 | ~9 KB |
| `policy/sessions.md` | C34 + W8 | ~5 KB |
| `policy/issues.md` | C35–C38 | ~4 KB |
| `policy/review.md` | C32 (landing/review half) | ~4 KB |
| `policy/testing.md` | C14 (how-to), C15→legacy, C30 | ~8 KB |
| `policy/coding.md` | C19, C20, C25, C27 | ~7 KB |
| `policy/legacy-adr-flow.md` | C8 (ADR paragraphs), C15, W7, W10 | ~6 KB |
| `context/lang-php.md` | C21 + W2 | ~3 KB |
| `context/lang-python.md` | C22 | ~2 KB |
| `context/lang-shell.md` | C23 | ~2 KB |
| `context/pfsense-live.md` | C5 + W1 (single copy) | ~4 KB |
| `context/smoke.md` | C31 | ~7 KB |
| `context/release.md` | C32 (channel/tag/pkg half) + W5 + W6 | ~6 KB |
| `docs/misc/config-gateway.md` (existing) | + C26 detail + W4 | +4 KB |
| `docs/history/incidents.md` (new) | inline issue/PR archaeology extracted from C7, C9–C14, C20, C27, C32, C37 (~40 citations) | ~4 KB |
| deleted as OD (content survives at its single home) | C5/C6/C24/C34/C40 summaries duplicating annex full texts; `workflow-reference.md` shell after dissolution | −(dup bytes) |

(C = CLAUDE.md §2.1 row; W = workflow-reference §2.2 row.)

---

## 6. Staged migration plan (strangler, matching map #1383's cutover)

1. **Stage 0 — this document.** Owner approval of the taxonomy + budgets; no content moves.
2. **Stage 1 — extract, don't rewrite.** Create `.agents/policy/` + `.agents/context/` by
   verbatim moves of CLAUDE.md/workflow-reference sections (per the matrix); each moved
   section leaves a one-line pointer in CLAUDE.md. CLAUDE.md stays canonical; measure shrink
   (`wc -c`). Reversible per-file. Incident citations sweep to `docs/history/incidents.md`
   in the same pass.
3. **Stage 2 — flip the bootstrap.** Rewrite AGENTS.md as the canonical ≤8 KB bootstrap with
   the routing table; CLAUDE.md becomes the thin Claude adapter. Land the budget/header CI
   checker in the same change (a new gate proves its red path in-session — CLAUDE.md "red
   canary" corollary).
4. **Stage 3 — routing backstops.** Dir stubs (`tests/smoke/`, `www/`, `pkg/pfblockerng/`,
   `scripts/agent/`); role-floor lines in role definitions; SubagentStart capsule gains the
   ROLE ROUTING line; UserPromptSubmit capsule reduced to the bootstrap-parity subset.
5. **Stage 4 — pilot validation** (belongs to the map's pilot tickets, not this one): run the
   three walkthrough task shapes below on both clients; verify each agent's loaded set matches
   the predicted set; then delete the dissolved `workflow-reference.md` shell and quarantined
   duplicates. `legacy-adr-flow.md` retires only after the pilots prove the replacement
   (map #1383 "Retire superseded workflows only after both pilots pass").

Each stage is a docs/skills-class change (dev-only, direct-to-devel per current policy) except
the CI checker (Stage 2), which takes the full PR flow.

---

## 7. Validation walkthroughs (which documents each role loads)

Costs use bytes/4. Today's baseline for EVERY agent below: 68,630 B ≈ 17,200 tokens of
CLAUDE.md regardless of task.

### A. PHP UI bug fix (issue names a `www/` page warning)

| Role | Loads | ~Tokens |
| ---- | ----- | ------- |
| triager | bootstrap (2k) + `issues.md` (1k) + `pfsense-live.md` (1k) | ~4k |
| implementer | bootstrap + `coding.md` (1.8k) + `testing.md` (2k) + `lang-php.md` (0.8k) + arch-notes "Web UI test tiers" section (~2k) + `config-gateway.md` iff a field is touched | ~8.6k |
| reviewer | bootstrap + `testing.md` + `review.md` (1k) + `lang-php.md` | ~5.8k |

### B. Python DNSBL pipeline change (`pfb_unbound.py` + manifest)

| Role | Loads | ~Tokens |
| ---- | ----- | ------- |
| planner | bootstrap + `delegation.md` (3.5k) + arch-notes "DNSBL/ABP pipeline" (~5k) | ~10.5k |
| implementer | bootstrap + `coding.md` + `testing.md` + `lang-python.md` (0.5k) + arch-notes DNSBL section | ~11.3k |
| reviewer | bootstrap + `testing.md` + `review.md` + `lang-python.md` + arch-notes DNSBL section | ~10.5k |

### C. Release cut (`/release v4.0.0.alpha.N`)

| Role | Loads | ~Tokens |
| ---- | ----- | ------- |
| operator | bootstrap + `context/release.md` (1.5k) + `git.md` (2.3k) | ~5.8k |

Every cell beats today's 17.2k floor, and — more importantly — every loaded byte is
task-relevant: walkthrough C reads zero smoke/DNSBL/delegation text; walkthrough A's
implementer reads zero release/waits/session text.

---

## 8. Open questions (for the map's follow-on tickets)

1. **Bootstrap naming direction.** Proposal inverts today's layout (AGENTS.md canonical,
   CLAUDE.md adapter) to make the neutral name the semantic source per map #1383's "no one
   client's tree is the source of truth". Alternative: keep CLAUDE.md canonical and accept
   the asymmetry. Owner call.
2. **`.agents/policy/` vs `docs/policy/`.** `.agents/` keeps policy beside skills/tiers
   (agent-facing); `docs/` keeps it human-discoverable. Proposal picks `.agents/` for
   consistency with the existing neutral home.
3. **Does Claude Code load nested CLAUDE.md stubs in linked worktrees reliably?** Marked
   ASSUMED — dir-stub mechanics must be probed in a pilot before Stage 3 relies on them
   (both vendors document nested instruction files, but behaviour in `.claude/worktrees/`
   session layouts is unverified).
4. **Budget numbers.** 8 KB bootstrap / 12 KB per policy doc are proposals sized from the
   matrix estimates, not measured optima; pilots should confirm nothing critical gets
   squeezed out.
5. **How much of `delegation.md` survives #1383's new workflow?** The brief/handoff/gate
   fields likely map onto the new "task packet" contract; write `delegation.md` once the
   packet schema ticket lands, to avoid moving the same text twice.
