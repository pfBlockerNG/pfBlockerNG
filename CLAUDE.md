# CLAUDE.md — pfBlockerNG

## Scope — the pfBlockerNG-org default

These rules, **plus** the project + user `.claude/settings.json` (the `SessionStart`/
`UserPromptSubmit` hooks), are the **default way of working for every repository in the
`pfBlockerNG` GitHub organization** — not only `pfBlockerNG/pfBlockerNG`. A repo-local
`CLAUDE.md` rule wins for that repo, and only there.

**Carries over (how we work):** communication, Working principles, the delegation contract,
worktrees + the rebase-only landing flow + `/pr-merge-flow`, branch naming, the test-coverage
mandate, linting discipline, GitHub-issue handling + labels, commit style. **Does not carry
over (this package's mechanics):** the DNSBL/ABP pipeline, smoke/UI suites, the pkg repo,
ports/release plumbing, and the language/runtime specifics tied to this package. When in
doubt: a rule about *mechanics* is local; a rule about *how we work* is org-wide.

Displaced detail (still policy, read when the task touches it):
[`docs/misc/workflow-reference.md`](docs/misc/workflow-reference.md).

---

## Working principles — don't guess

The top rule: **never assume — read the source of truth, investigate the live state, and
confirm a genuine fork before building.** A clean grep of one file is not proof; a plausible
memory is not a fact.

### Ambiguity — confirm before you build

**Pick the obvious option and proceed when there is one; pause and ask (`AskUserQuestion`)
when the choice is genuinely the user's to make**: unclear requirement/intent, more than one
defensible approach diverging in ways the user would care about, or an architecturally
significant change (the DNSBL/ABP pipeline, the manifest boundary, the zero-downtime
swap/watcher, a `config.xml` schema/migration, a privilege/security surface, public
behaviour). Don't guess through that fork — but don't ask what the code, the request, or a
sensible default already answers. Applies to autonomous flows too.

### Investigate, don't assume — read sources, not proxies (the live system)

Verify against the source of truth and the effective live state; never infer presence/absence
from one generated artifact. The one-liners (each cost a real misdiagnosis; expansions in
[`workflow-reference.md`](docs/misc/workflow-reference.md) "Live-system investigation
gotchas"):

- Follow file inclusions (`include:` + `*.d/` drop-ins) — Unbound's ACLs live in included
  files, not `unbound.conf`.
- Some services run **chrooted** (Unbound → `/var/unbound`, HAProxy → `/tmp/haproxy`) —
  host-absolute paths silently fail inside.
- Ask the tool for its effective state via its own CLI (`pfctl`, `unbound-control`,
  `pfSsh.php`) rather than generated files.
- Turn on debug/verbose (`pkg -d`, `curl -v`) when unsure what a tool does; pfSense pkg uses
  the `pkg+https` mirror-indirection scheme.
- Confirm installed software with `pkg info`/`pkg which` before adding a dep or a fallback.
- `/conf/config.xml` is the source of truth for pfSense settings; `/var/…` is generated.
- Read the actual files (diff before/after); confirm values on the box, not from recollection.

### Resolve pfSense-provided PHP functions from upstream

A missing/ambiguous pfSense-provided PHP function is resolved from the real source
(<https://github.com/pfsense/pfSense>) at **every supported ref** — min CE, each CE since,
each Plus release, `master` — resolved by release **date** (the mirror lacks release
branches). **Prefer stubbing the real function over an exception/workaround.** Full ladder +
ref-resolution recipe: [`workflow-reference.md`](docs/misc/workflow-reference.md) "Resolving
pfSense-provided PHP functions".

### Evidence rules (planner and implementer alike)

- **A claim without a run artifact is ASSUMED.** Every load-bearing fact in an ADR, brief, or
  triage verdict carries the command + output (or a doc citation fetched this session) that
  proved it. Facts marked ASSUMED must be verified before any step relies on them.
- **Environmental/platform claims written INTO artifacts** (code comments, workflows, docs —
  default shells, token semantics, external-service behaviour, third-party feed formats) must
  be probed or doc-verified **in-session, before being written**. A plausible memory is not a
  fact (a false "pipefail" comment shipped from memory; #902 shipped a CI contract that
  `GITHUB_TOKEN` event suppression made unfulfillable; ADR-59 shipped wrong `domain_col`
  values for feeds nobody had fetched). **Briefs are artifacts too**: an environmental claim
  a brief embeds in its build instructions (YAML, comments, commands) carries its probe
  evidence inline or is tagged ASSUMED — PR #933's pipefail no-op gate was seeded by the
  planner's own brief and caught only at the independent gate (#935).
- **No self-exemption.** Deviating from any MUST rule requires quoting the authorizing user
  message verbatim in the report. "Per session config" or "acceptable here" without a citation
  is fabricated authorization — a real observed failure, not a hypothetical.
- **Debugging = hypothesis ledger.** Before any fix edit: list ≥2 candidate hypotheses, the
  discriminating probe for each (what output confirms/refutes), run the probe, record the
  actual output. Only a CONFIRMED hypothesis gets a fix; the ledger rides the handoff so the
  gate can audit the causal chain instead of trusting the patch.

### Plan with a higher model, implement with Sonnet 5

Substantial coding work is **planned and gated by a higher model** (Opus / Fable) and
**implemented by Sonnet 5** sub-agents: the planner splits the task into steps, a Sonnet 5
implementer executes each, and the planner **independently checks every step** before the next
— that per-step gating is what makes a cheaper implementer safe. The skills already wire this
(`/adr-phase` and `/gh-issue --fix`); for ad-hoc coding, follow the same shape. The higher
model may implement a fix **directly** when it is relatively small and doable in one step —
and always handles **docs / config / settings / skills** directly. Delegation is for
non-trivial, multi-step `src/`/`tests/`/CI work.

- **An implementer may re-delegate when a subtask genuinely splits** (parallel siblings, a
  verifier per finding) — the platform enforces its own nesting-depth cap, so we add no depth
  rule of our own. **Accountability never splits**: the spawning agent verifies nested work
  itself before it enters its handoff, every handoff/gate field stays the spawner's to fill,
  and a nested delegate's defect is the spawner's defect at the gate above. Delegating the
  whole brief downward unexamined is still a defect — split work, not responsibility.
- **The planner's brief to Sonnet 5 follows the delegation contract below** — a vague or wrong
  brief is a planner bug, and a handful of real shipped defects trace directly to brief bugs
  (a half-enumerated axis, a vacuous test spec, an unverified "fact" stated as truth).
- **ADR phases: the brief itself is written fresh-context (issue #1089).** The default
  `/adr-phase` route passes `briefSpec` (pointers: ADR dir + phase number) to the
  `phase-step` workflow, whose **Brief stage** — a fresh higher-model agent — reads the ADR,
  phase prompt, and prior `RESULTS/`/Gate records just-in-time, runs the enumeration greps
  itself, and returns a schema-forced brief (matrix rows citing their grep source, hostile
  rows, gates, red proof, plan items, cross-phase drift flags); the workflow's verifier also
  runs at the higher model. The main session validates the records non-vacuously, commits the
  Gate file, and keeps HALT/continue/landing — its context stays flat across a long `all`
  run. Composing an ADR-phase brief in the main session is a recorded deviation, exactly like
  hand-spawning 6a/6b.
- **Mode propagation to delegates is mechanical** — the `SubagentStart` hook
  (`.claude/settings.json`) injects the ponytail + caveman capsule into every spawned
  sub-agent; the capsule itself carries the rules (reviewer carve-out; "terse prose,
  verbatim evidence"). Briefs add a mode line only for a non-default level (e.g. `ultra`).
- **Sonnet 5 follows every directive in this file.** The implementer is cheaper, not exempt.
- **Run at effort xhigh or better** — the session default in `.claude/settings.json`
  (`effortLevel: xhigh`), and stated explicitly in every spawn (never rely on inheritance).

### The delegation contract (brief → handoff → gate)

Three fixed artifacts govern **every** delegated step — `/adr-phase` phases, `/gh-issue --fix`
steps, and ad-hoc delegation alike. The design principle: **cheap models reliably fill
required fields and reliably drop optional virtues**, so every check is a named field in an
artifact, and **an empty or missing field is a gate failure** — never a judgment call. This
contract exists because prose-only gates demonstrably failed: a one-day post-hoc audit
(issues #900–#909) found ten reproducible defects in work that had passed every prose gate
and review.

#### THE BRIEF (planner → implementer) — mandatory sections

1. **Objective** — the one outcome, tied to the work item.
2. **Required reading** — `file:line` refs (identifiers, not pasted bodies — the implementer
   reads just-in-time in its own fresh context); the prior step's handoff.
3. **Coverage matrix** — when the change touches anything with siblings (v4/v6, address/port,
   CE/Plus versions, parse modes, providers, every caller of a touched symbol, every branch of
   a touched conditional): the planner enumerates ALL rows **from the source** — grep output,
   the version-matrix file, the structure's own definition — **never from memory**. Each row
   maps to a test or an explicit justified deferral. A brief saying "all X" without the
   enumerated list is invalid; the planner generating the enumeration is the point
   (implementers execute enumerated lists well and under-generate them reliably: the
   #858→#900 five-fix chain, #901, #904, PR #881's missed port axis). A tool whose scope
   spans file types (a checker/parser over scan roots) gets a mandatory axis "per in-scope
   file type × its comment/quote syntax", enumerated from the roots' actual extensions
   (`git ls-files <roots>`) — PR #937 shipped a PHP false-positive class because only the
   languages the author thought of got rows (#941).
4. **Hostile-input rows** — for any new/changed parser, regex, or input guard the planner
   supplies the adversarial input set with expected outcomes: punycode/IDN labels, empty
   input, header/no-header, quotes + shell/regex metacharacters, tabs and consecutive spaces,
   oversized values, wrong encoding (#903, #904, #907, #908, #920 were all misses of exactly
   these).
5. **Constraints** — the do-NOT-touch list, plus the **never-weaken rule**: a brief may never
   weaken a CLAUDE.md mandate. In particular, red→green is **test-first** (Test coverage #1):
   the reproduction test authored and executed RED before any production edit, frozen
   byte-identical, re-run GREEN unchanged after — **executed runs with output pasted**, never
   "reasoned through" or "verified by reading". Comments follow "Comments —
   constraint, not narration" (Code standards): gate-facing justification goes in the
   handoff, never the code.
6. **Verification** — the canonical gates (table below) plus per-item acceptance checks, each
   a runnable command with its expected observable (the shape "WHEN `<command/input>` THEN
   `<observable>`"), mapping 1:1 to the tests the step ships.
7. **ESCALATE contract** — if any factual claim in the brief/ADR is contradicted by the code
   or a live probe, **STOP and return a structured blocker**; never silently patch the plan,
   never proceed on a premise you have just falsified. Reality outranks the brief, loudly.
   An environmental claim the brief tags ASSUMED (or embeds with no evidence) is probed
   before anything is built on it — same STOP rule if the probe refutes it. Same rule when
   the fix requires **inventing a mechanism the brief never named** (an exemption layer, a
   state machine, a heuristic): escalate, or at minimum return DONE-WITH-DEVIATION — never
   plain DONE. PR #937's only blocking bug lived in an improvised exemption layer that had
   no hostile-input rows because nobody had planned for it to exist (#943).
8. **Implementer scope — trust the brief, don't re-investigate it.** The brief embeds its
   evidence (facts carry their run artifacts), so the implementer's reading scope is the
   brief + its named refs + the code it edits: no re-fetching the issue/ADR, no re-running
   the brief's enumeration greps, no re-deriving its matrix — the independent verifier and
   the PR review carry the skepticism, and duplicating them in the implementer is pure
   step-budget burn. ESCALATE (item 7) is reactive: an *encountered* contradiction
   triggers it; proactively auditing the brief does not.

#### THE HANDOFF (implementer → planner) — fixed fields, missing field = gate reject

- **Verdict**: DONE / DONE-WITH-DEVIATION / BLOCKED.
- **What changed**: files + a one-line why each; the commit hash.
- **Gates**: the exact commands run + pasted output tails (pass/fail counts) — never bare
  claims.
- **Red→green proof** (behaviour-changing steps): the reproduction test's FAILING output —
  executed BEFORE any production edit — AND its PASSING output after, both pasted from
  executed runs, plus the test file's `git hash-object` at red time (must equal the committed
  file — Test coverage #1's freeze).
- **Coverage matrix**: every brief row ticked with its test, or its stated deferral.
- **Deviations / judgment calls** (or "none"); **carry-forward** for the next step.

#### THE GATE (planner, after every step) — mechanical, evidenced, artifact-producing

The producer never grades its own work; the gate **re-derives**, it never merely re-reads.
Every item below is mandatory; a skipped item is recorded as SKIPPED with the reason, so an
unrun check is visible instead of silent. **Terse prose, full checks** — brevity applies to
the gate report's wording, never to which checks run.

1. **Re-run the canonical gates yourself** (table below; "touched" is computed from the diff's
   file types **plus cross-language consumers** — a suite that parses an artifact the diff
   changes runs regardless of its language).
2. **Re-execute the red proof yourself** for behaviour changes — never accept the handoff's
   claim. Run `scripts/agent/verify-red-proof.sh --worktree <path> --test-cmd '<cmd>'
   --src <path>... --hash <test>=<red-time-sha>...` — it reverts the src paths to HEAD~1
   (tests stay), requires the test to FAIL, restores, requires PASS, and enforces the
   freeze (`git hash-object` of each committed reproduction test equals the handoff's
   red-time hash — a test edited between red and green, or with no red-time hash, proves
   nothing). Record its verdict lines.
3. **Read the full diff** (`git show` — never `--stat` alone) and tick **every** ACTION-PLAN
   item and **every** coverage-matrix row against what the diff actually does. `--stat` cannot
   see a hardcoded value, a stubbed branch, or a silently dropped plan item. A mechanism in
   the diff the brief never named = STOP: the planner writes hostile-input rows for it and
   their tests land before PASS (PR #937's F1, #943).
4. **Test honesty**: no weakened/removed assertions; every "does NOT contain X" assertion has
   an X-shaped fixture that could make it fail (vacuity check); no red-run manufactured by
   monkeypatching a fault production cannot produce (#900's phantom `OSError`); real failure
   modes exercised through the production surface (an on-disk corrupt file, not an injected
   exception).
5. **Conventions**: each new public symbol listed beside 3 sibling symbols proving the name
   matches the house pattern (#905); comments/docs mentioning touched symbols reconciled with
   the new reality (stale-comment defects recur); any comment/doc claim naming a **sibling
   file or house convention** verified by grep — in-repo claims are the cheapest probes there
   are (PR #937 shipped a fabricated "mirrors the URL-encoding checker" lineage, #941);
   added comments respect the comment budget ("Comments — constraint, not narration").
6. **Write the gate record** — a fixed-field block (or per-phase file where the skill says
   so): commands + results, red/green evidence, per-item diff verdicts, matrix confirmation,
   the SKIPPED list. This artifact is what makes a skipped check auditable.

#### Canonical gates (single source of truth — briefs and gates reference THIS table)

Mechanical runner: `scripts/agent/run-gates.sh [--diff <base>]` (`--plan` to preview) —
change the table and the runner together.

| Touched | Gates (all must pass) |
| ------- | --------------------- |
| Python (`*.py`) | `python3 -m pytest` · `ruff check .` · `ruff format --check .` · `mypy tests/` |
| PHP (`*.php`/`*.inc`) | `php -l` per touched file · `vendor/bin/phpunit` · `composer phpstan` · `composer phpcs -- --standard=phpcs.xml.dist src/` |
| Shell (`*.sh`) | `sh -n` · `shellcheck` · `shellspec --shell "$(command -v dash)"` (where specs exist; dash = strict-POSIX ash sibling of FreeBSD sh — bash-as-sh masks appliance divergences. Dash missing ⇒ the substitution goes empty and shellspec silently auto-detects — INSTALL dash (`brew`/`apt install dash`) instead of dropping the pin; plain `shellspec` is a last resort and says so in the handoff) |
| Markdown (`*.md`) | `npx markdownlint-cli2` |
| `www/` | Tier-A `ui_render` coverage exists for the change (test mandate #4) |

---

## Test coverage (mandatory)

Tests are how a change proves itself. **Five non-negotiable principles govern every change —
unit, integration, E2E, smoke, or UI. Each is a hard gate: a change that violates any one is
NOT done, no matter what the line-coverage number says.**

1. **A test is EVIDENCE the change works — for a behaviour change it MUST fail before and pass
   after, and the proof is TEST-FIRST.** Author the reproduction test(s) **before touching
   production code**, at full suite quality (every standard here applies — they ship in the
   suite and double as the defect's in-suite reproduction), and execute them on the untouched
   code: they **FAIL for the exact reason the change addresses**. From that red run the tests
   are **frozen** — byte-identical until green (a temporary skip/disable while developing is
   fine, but the committed file matches the red-run content exactly; record `git hash-object`
   of each test file at red time). After the change the SAME tests, **zero edits**, **PASS** —
   one green run proving both that the tests test the condition and that the fix works. Only
   then write the further tests the change needs. A test written after the fix, or edited
   between red and green, is evidence of nothing — same for a test already green before the
   change. **Two exceptions:** behaviour-**PRESERVING** work (refactors, ADR prep phases) pins
   the *existing* behaviour as an oracle and stays green across the change — still mandatory;
   and **brand-new code with no pre-existing behaviour to be wrong** needs no red run against
   the void — the only possible red there is a missing symbol/file, an *existence* test,
   itself coverage theater. Its tests still ship with it asserting real behaviour, and any
   change it makes to EXISTING observable behaviour still gets its red-first proof.
2. **Every change ships WITH its tests.** "The existing suite still passes" is **not**
   coverage of a new change.
3. **NEVER coverage theater.** A test must *validate* the code, not merely *execute* it — it
   carries an assertion that would **fail on a regression**. Green at 100% line coverage with
   no failable assertion is **rejected**.
4. **Front-end changes REQUIRE front-end tests.** A change touching `www/` must carry UI tests
   (ADR-14). **Tier A (`ui_render`) is always required.** **Tier B (`ui_e2e`/`ui_browser`) is
   REQUIRED IFF the change is observable *only* in Tier B** — which explicitly includes a
   **new page**, a **multi-step flow** (anything spanning more than one request/interaction),
   and **visual/structural** changes (element positioning/addition/removal, layout). When in
   doubt, add Tier B.
5. **Tests express the change's INTENT — they are documentation, not just coverage.** Name and
   comments state the intended outcome being pinned, never the mechanics of how it is coded.

The five above are the law; how to satisfy them:

- **Branch coverage — test every condition, not one side.** A boolean gets off *and* on (plus
  any third state); every `if`/`switch`/match branch and documented input class gets its own
  assertion (exemplar pair: `test_dnsbl_hsts_override_forces_null` /
  `test_dnsbl_hsts_disabled_keeps_vip`).
- **Assert the before-state in transition tests.** A test that flips a toggle asserts the
  *original* result first, so green proves the flip **caused** the change — never just the
  final state. Extends to any lifecycle (a blocked-after-listing test first asserts the
  domain *resolved*).
- **Self-encapsulated — never order-dependent.** Shared fixtures are fine; no test may depend
  on a sibling running first. Reset per-test state explicitly with an autouse fixture that
  **fails loudly** if the reset doesn't take (the `tick` smoke-module bug); a module-scoped
  baseline is NOT per-test isolation.
- **Specify complex behaviour BDD-style; keep trivial tests trivial.** Non-trivial behaviour
  (state transitions, precedence, multi-step flows) gets Scenario / Given–When–Then
  structure.
- **On failure, print expected vs actual — no guessing.** Every assertion/poll that can fail
  puts the comparison on the terminal (AssertJ-style, redacted against the usual secrets); a
  bare "False" matcher is not acceptable; a diagnostic filtering by token must match the
  value's **rendered** form (`pfctl` prints port 53 as `domain`). Exemplar:
  `_redir_match_report` in `tests/smoke/test_dns_redirect.py`.
- **CI-gate wiring proves its red path in-job (the red canary).** A CI job whose verdict
  rides shell wiring unit tests cannot cover (pipes, `set` options, exit propagation) ships
  a red canary: leading lines in the **same** `run:` block as the enforce command (same
  shell options, so option drift trips it) feed a known-violating input through the
  identical pipeline shape and require nonzero before the real check runs. The canary is
  that wiring's red→green (PR #933: the default `bash -e {0}` has no `pipefail`, so `| tee`
  masked the script's exit 1; exemplar: the `coverage-pairing` job in `test.yml`). Broader
  corollary: **any newly wired blocking gate** (a pre-commit block, a CI step) demonstrates
  its red path once, in-session — feed a violating input, watch the gate fail — even when
  the wiring is a bare `run:` line (PR #937's wiring shipped green-path-only, #943).

### ADR acceptance — automated tests, not a manual sign-off

An ADR flips to **Accepted** on **green automated coverage alone** — provided its smoke/UI
tests genuinely prove the behaviour (every branch, before-and-after, no coverage theater) on
the live-VM **CE + Plus fan-out**. A §7 item that **cannot** run in CI (HA/CARP sync, a real
HAProxy reload, load profiles, smallest-box RAM, true *visual* correctness) is a **documented
out-of-CI limitation**, not an acceptance blocker. Supersedes any older per-ADR "manual smoke
required" gate.

---

## Communication

**Mandatory at every session start (enforced by the `SessionStart` hook):** activate **both**
modes — ponytail at `full` (`/ponytail:ponytail` plugin form or `/ponytail` vendored form,
whichever exists; laziest working solution) and `/caveman` (terse, full technical accuracy). Ponytail governs what you build; caveman how you talk. A
per-prompt `UserPromptSubmit` hook re-injects the discipline capsule; the hooks are the
mechanism, this line is the rule.

Two style exceptions — still concise, but normal professional grammar: **external /
public-facing text** (issue/PR comments, PR bodies, commit messages) and **documentation**
(Markdown, code comments, docblocks, ADR text).

### Work-context marker

While actively working **an ADR, a GitHub issue, or a PR**, begin every reply with a one-line
status marker (plain markdown, no ANSI escapes), format
`<emoji> ***ID***(***#PR***): ***Title***` — ids/title ***bold+italic***, separators plain,
~28-char budget including the `(#PR)` group (trim the title with `…`). IDs: `ADR-NN` / `#NN`;
a PR belonging to an item appends `(#PR)`. Omit the marker on plain conversational turns.

| Emoji | State |
| ----- | ----- |
| 📝 | creating/authoring an ADR |
| 🏗️ | implementing an ADR |
| 🤔 | investigating a GitHub issue |
| 🛠️ | implementing/fixing a GitHub issue |
| 👀 | a PR is awaiting review |
| ⏳ | a PR is awaiting CI |
| 🏁 | a PR is merged — cleaning up |

Examples: `🛠️ ***#43***(***#56***): ***TLD-Allow KeyError on…***` ·
`🏗️ ***ADR-10***(***#56***): ***ABP precedence rework***`

---

## Code standards

### Naming — follow the established pattern

**A new variable, element `id`, dict key, or config key follows the conventions already in
that file (or similar files)** — match the surrounding pattern (prefix, casing, separators,
word order); with sibling `pfB_*` identifiers, a wizard flag is `pfB_wizard_disable`, not
`donotshowthisagain`. An off-pattern name is a smell even when it works. Spans the whole
stack.

### Comments — constraint, not narration

A comment states a constraint the code cannot show; default budget **≤3 lines**. Design
rationale lives in the ADR / architecture-notes and the comment carries a one-line pointer
(`// ADR-49: content-sanity gate; contract pinned by PfbTextSanityTest`) — never a
restatement: a contract stored in ADR + comment + test is three copies, two of which drift.
One-line regression breadcrumbs stay (`// issue #946: decode UTF-16 BOM first — else
nul_bytes false-positives`). **Compression sheds redundancy, never essential information: usage
instructions and function-contract facts (params, returns, invariants, defaults) that
are expressed nowhere else may be reworded tighter, never removed.** The budget bites
hardest mid-code; a file header carrying interface documentation may run long.
**Operational headers of executable scripts are interface documentation, not
narration** — usage, options/params with defaults, env vars, examples stay in the
header unless the script itself prints an equivalent `--help`/usage. **Never in
committed comments:** ADR **phase numbers**
("wired in Phase 4"), **`RESULTS/` handoff refs**, **review archaeology** (reviewer names,
`PR #N` finding IDs, `review-fanout CN`), or correctness argument aimed at the gate/reviewer
— that evidence belongs in the handoff / gate record / PR body, not the tree. Enforced on
**added** lines under `src/` + `scripts/` by `scripts/check_comment_narration.py`
(pre-commit + CI, diff-scoped — pre-existing narration is grandfathered until its cleanup
lands); escape a genuine need inline with `# narration-ok: <reason>`.

### PHP

- Indent **tabs** (`.editorconfig`); target PHP 8.3 (pfSense CE 2.8).
- pfSense-injected functions are declared in `stubs/pfsense/` — don't `require_once` pfSense
  files in tests.
- No `die()`/`exit()` in library code; return or throw.
- Web UI help text: brief yet clear — match neighbouring help texts' wording/length/style.

### Python

- Indent **4 spaces**; target Python 3.11+; `from __future__ import annotations`. Type-hint
  new functions; no bare `except:` (`except Exception` minimum).
- `pfb_unbound.py` runs in Unbound's Python loader — **stdlib only, no external deps**.
- **No Python interpreter ON the appliance — PHP or POSIX sh (HARD CONSTRAINT).** The box
  ships `python3.11` with no `python3` symlink, so `/usr/local/bin/python*` is rc=127 —
  and SILENT under `SmokeVM.ssh`'s `check=False`. Drive the box via PHP
  (`php`/`pfSsh.php`/`h.php_eval`) or POSIX sh; `pfb_unbound.py` (embedded loader) is the
  sole exception. Enforced by `scripts/check_appliance_python.py` (pre-commit + CI). Bare
  `python3` in dev/CI tooling under `scripts/` is fine — it names the developer's
  interpreter.
- **Content hashing:** the Python side uses `hashlib.md5` for its own self-comparisons only,
  never a cross-language digest (PHP/shell use `xxh128`) — ADR-42 policy; see
  architecture-notes "Change detection / content hashing".
- **No fixed-time waits to coordinate concurrency (issue #456).** Use a synchronisation
  primitive (`threading.Event`/`Condition`/`Semaphore`, `queue.Queue`); a timeout is a
  deadlock guard only and must **raise loudly**, never return silently (exemplar
  `_Harness.wait_builds`, `tests/test_adr10_watcher.py`). A poll is a last resort against
  unsignalable production code.
- Unbound injects API symbols (`log_info`, `RR_TYPE_*`, …) as runtime globals; declared once
  in `stubs/python/unboundmodule.py` (the suite copies them onto `builtins`,
  `tests/conftest.py`). Add a new injected symbol there.

### Shell

- POSIX sh only (`#!/bin/sh`); no bash-isms (`[[`, arrays, `$RANDOM`). Quote all expansions.
  **POSIX-compliant means correct under strict-POSIX SEMANTICS (ash/dash), not merely free of
  bashisms** — e.g. a redirection error on a special built-in (`:`, `exec`, `set`) exits a
  non-interactive ash/dash shell entirely while bash continues. bash-as-sh acceptance is not
  evidence; the shellspec gate executes under dash for exactly this reason.
- Absolute paths for add-on/privileged binaries (`iprange`/`grepcidr`/`mmdblookup`/`jq`/
  `pfctl`) as `path*` vars (see `pfblockerng.sh`); base utilities may be bare.
- AWS region pre-scripts: 25 thin wrappers over the shared
  `list_scripts/aws_region_prefixes.sh` — change that one, not 25.
- **Locale (ADR-26):** never `export LC_ALL`/`LANG` script-wide; every `sort -u`/`uniq`/
  `comm`/`join` over machine data (IPs, punycode) carries inline **`LC_ALL=C`** — a language
  collation can merge distinct strings and silently drop a blocklist entry. Full policy:
  architecture-notes "Locale policy".

### External processes — launching and waiting

Before writing/changing code that runs `timeout(1)`, `mwexec_bg()`, a spawned
daemon/`service` restart, or a live-tail/poll loop, read
[`docs/misc/external-process-waits.md`](docs/misc/external-process-waits.md) — FreeBSD
`timeout` is a process **reaper** by default (a survivor-spawning command needs
`--foreground`; a pipeline stays default-mode); `mwexec_bg()` returns no PID (track via
`daemon -p <pidfile>` + `isvalidpid()`, never a `ps` pattern); a daemon inheriting the
capture pipe blocks `exec()`.

### Code-quality conventions (ADR-28)

| Item | PHP 8.3 | Python 3.11+ | POSIX shell | `www/` JS |
| ---- | ------- | ------------ | ----------- | --------- |
| 1 — enums/bools over strings | backed `enum` for settings/mode values; predicates return `bool` | `enum.Enum` / `typing.Literal`; predicates return `bool` | **N/A** — keep flag strings | `const` enums/booleans for new code |
| 2 — short-circuit | cheap guard first in `&&`/`\|\|` | same | same; `case` guard before `grep` | same |
| 3 — `=` alignment | opportunistic, **touched blocks only** | same (respect `ruff format`) | opportunistic | same |
| 4 — string-ops over regex | `str_*` over `preg_*` where equivalent; hot loops first | `str` methods over `re` in per-line paths | parameter-expansion / `case` over `grep -E`/`sed` | `String.prototype` over `RegExp` |
| 5 — boolean literals | **uppercase `TRUE`/`FALSE`** (PHPCS-enforced) | `True`/`False` | N/A | lowercase |

Storage adapter rule (behaviour-preserving upgrades, grandfather seeds, downgrade tolerance,
`PfbStoredEnum` mechanics): [`workflow-reference.md`](docs/misc/workflow-reference.md)
"Config storage adapter rule"; per-field inventory:
[`docs/misc/config-gateway.md`](docs/misc/config-gateway.md).

### Config gateway — PfbConfig (ADR-29)

`PfbConfig` (`pfblockerng_extra.inc`) is the **single access point for every registered
`installedpackages/pfblockerng*` scalar field**:

- **Read/write/delete via `PfbConfig::read/write/delete($key)`** — never direct
  `config_*_path` on a registered key (enforced by the
  `PfBlockerNG.Config.RequireConfigGateway` sniff; adding a registered key ⇒ also add it to
  the sniff's `$registeredPaths`).
- Section helpers (`readSection`/`writeSection`/`deleteSection`) for whole-section,
  non-per-field access. Unregistered key → `InvalidArgumentException`.
- **No `write_config()` inside the gateway** — the caller decides when to flush. The registry
  (`pfb_cfg_registry()`) is read-only after boot.
- Adding a field, rollback invariants, field vocabulary, foreign-key exclusions:
  [`docs/misc/config-gateway.md`](docs/misc/config-gateway.md) — read it before adding a
  field or reasoning about the gateway's contract.

---

## Linting

Run linters while working; the `.githooks/pre-commit` hook blocks failing commits
(path-scoped to staged file types); CI is the final authority.

- **Python:** `ruff check .` / `ruff check . --fix` / `ruff format .` (config in
  `pyproject.toml`; `.flake8` mirrors the 120-col limit for IDE Flake8 — keep in sync).
- **PHP:** Intelephense (`.inc` = PHP via `files.associations`); PHPStan + PHPUnit + PHPCS via
  `composer install`; run PHPStan/PHPCS through the composer scripts — `composer phpstan` and
  `composer phpcs -- --standard=phpcs.xml.dist src/` — which carry the required
  `--memory-limit=1G`/`-d memory_limit=1G` (bare `vendor/bin/phpstan` OOMs at PHP's default
  128M on this codebase, and PHPStan accepts no memory limit in `phpstan.neon`). The
  `stubs/pfsense/` stubs are for PHPStan, NOT runtime doubles (those live in
  `tests/php/pfsense_doubles.php`). Three custom sniffs (`tests/phpcs/PfBlockerNG/`, each
  pinned by its own `*SniffTest.php`): **PFBL-01 `RequirePfbFilter`** (semantic validation
  before exec/manifest-write/path-build inside `pfblockerng.inc` input handlers — add new
  in-scope surfaces to `scopeFunctions`), **`UppercaseBooleanLiteral`** (all `src/` PHP),
  **`RequireConfigGateway`** (see PfbConfig above).
- **Shell:** ShellCheck; `.shellcheckrc` suppresses SC1091 + SC2154 only — don't suppress
  others without justification.
- **URL-encoding check** (`scripts/check_url_encoding.py`, pre-commit + CI): forbids naked
  shell-var interpolation into an HTTP-client URL query — let the value ride
  `curl --data-urlencode` instead.
- **Version-literal check** (`scripts/check_version_literals.py`, pre-commit + CI): forbids
  hardcoding a supported pfSense/FreeBSD version token (CE/Plus version, `FreeBSD:NN` ABI,
  `php8x`/`py31x` flavor, `ce-`/`plus-` varver) as a **value** — an exact quoted literal or a
  bare `key=value`/`key: value` RHS — anywhere under `src/`/`scripts/`/`.github/workflows/`.
  Read it from the ci-metadata matrix (`read-version-matrix.sh`) at runtime instead of
  restating it (a literal silently drifts when the matrix moves). Prose, comments, and Python
  docstrings stay clean; escape a genuine one-off with an inline `# version-literal-ok: <reason>`.
  The bare/explicit-path invocation is the authoritative pre-commit/CI gate (full scan); it
  also has diff-scoped `--staged`/`--diff <base>` modes (issue #1000) that judge only added
  lines — like `check_comment_narration.py`, but re-reading each changed file's whole content
  (needed for correct comment/docstring state) and filtering to the added lines, for ad-hoc
  and CI-PR invocation.
- **Comment-narration check** (`scripts/check_comment_narration.py`, pre-commit + CI,
  diff-scoped): forbids ADR phase numbers, `RESULTS/` handoff refs, and review archaeology on
  **added** lines under `src/` + `scripts/` ("Comments — constraint, not narration"); escape a
  genuine need inline with `# narration-ok: <reason>`.
- **Retired-token guard** (`scripts/check_retired_tokens.py`, issue #1059; pre-commit,
  CI-PR, and a Claude `PreToolUse` hook, diff-scoped, **warn-only during rollout**): a quoted literal
  removed on ≥3 scan-root lines and not re-added as the same exact quoted span is a
  *retirement*; any surviving occurrence (`git grep -F` over `src/`/`scripts/`/
  `.github/workflows/`) is reported as a straggler (the #1047 class). Findings warn; a tool
  error (exit ≥2) fails the CI job. Escapes: `# retired-token-ok: <reason>` on an intentional
  survivor, `--token-allowlist` for a staged migration. Promote to blocking once the observed
  false-positive rate is near zero.
- **Markdown:** `npx markdownlint-cli2` (`--fix` to autofix). Blank line around every
  heading/list/fence; a language on every fence (`text` for plain output); single trailing
  newline. Rules + rationale in `.markdownlint.jsonc`; clean lint enforced pre-commit + CI.

---

## Worktrees (mandatory for AI agents)

**Every AI agent MUST do all repository work in its own dedicated git worktree** — never the
primary checkout, never shared with another agent (concurrent agents race on the filesystem,
index, `HEAD`, refs).

**Exception — dev-only classes need no PR.** Classes never shipped to users skip the PR
stage: **ADR text** (`.ADRs/`), **skills** (`.claude/skills/`), **agent workflows**
(`.claude/workflows/`), and **documentation-only** changes (`**/*.md`, `docs/`). Each still
uses a worktree but commits/pushes **directly to `devel`** (fetch + rebase first). Anything
touching `src/`, `tests/`, or CI — ADR *implementation* included — uses the full worktree +
rebase-only-PR flow.

```sh
git worktree add -b <branch> <path> origin/devel   # branch off the latest base
# … work, commit, push, open the PR from inside <path> …
git worktree remove <path>                          # run from the PRIMARY checkout
```

- Branch off the **current** base (`git fetch` first); a stale-tip worktree needs a rebase
  before it can land.
- **Reuse only YOUR OWN worktree — never adopt one you merely found.** A worktree at the
  conventional path that you did not create this run may belong to a live parallel session:
  `git -C <path> status` — foreign uncommitted changes ⇒ not yours; never `--force`-remove
  it; cut a fresh uniquely-named worktree (suffix `-{epoch}`).
- **Reuse a branch for a follow-up ONLY when no other session owns its PR** (foreign
  commits/pushes, running CI, review replies, `WIP`/`Waiting PR` labels ⇒ another session
  owns it: wait, cooperate, or start a NEW branch after the merge). **Never force-push over
  another session's in-flight PR.**
- Name the branch for its work item — `adr/{NN}-{slug}` / `issue/{NN}-{slug}`.
- Gotchas: `git worktree remove` fails from inside the tree — run from the primary checkout.
  `gh pr merge --delete-branch` can't check out a base another worktree holds — verify the
  merge landed, then `git push origin --delete <branch>`.

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath`).
**Claude: if `git config core.hooksPath` is not `.githooks`, run it at session start
(idempotent).** Any GitHub Actions workflow that commits code runs it after checkout too.

- **`pre-commit`** — the fast linters/static-analysis, path-scoped to staged file types
  (Python → ruff + `mypy tests/`; Markdown → markdownlint; shell → shebang gate + `sh -n` +
  shellcheck + shellspec; PHP → `php -l` + PHPStan + PHPCS; the URL-encoding check when
  `*.sh`/`*.md` staged). NOT the unit suites — run `python3 -m pytest` yourself while
  iterating; CI is the hard gate. Missing tool = reported + skipped. The `--no-verify` bypass
  is for humans, not agents.
- **`prepare-commit-msg`** — appends the owner's `Co-authored-by:` trailer (see Commit
  style); runs even under `--no-verify`.
- **`pre-push`** — enforces the release tag scheme via `scripts/release-version.sh`.

---

## Running tests

```sh
python3 -m pytest        # from repo root; run after ANY change to pfb_unbound.py or tests/
composer install        # once; if it 403s in a managed cloud session, run
                        # scripts/composer-cloud-install.sh instead (issue #950)
vendor/bin/phpunit      # PHP suite: loads the REAL pfblockerng.inc off-appliance
```

Environment gotchas that read as fake "baseline failures" — fix the env, never dismiss the
red: the pytest suite needs a **zstd encoder** (the `zstd` binary or the `zstandard` module);
a bare managed-cloud container lacks one and ~70 pkg/repo tests fail — the `SessionStart`
hook auto-installs it (manual: `pip3 install zstandard`). PHPUnit permission-denial tests
(`chmod 0555` fixtures) **skip under root** via a `posix_getuid() === 0` guard — root
bypasses file permissions, so a root run cannot simulate the denial (a red there means the
guard is missing, not that the code broke). Any other local-only failure: diagnose before
dismissing — if it is genuinely pre-existing on the base branch, **file a tracking issue**
(exemplars #791, #894); never leave it as folklore.

The PHPUnit bootstrap satisfies `require_once` with empty shims (`tests/php/shims/`) +
behavioural doubles (`tests/php/pfsense_doubles.php`); when a tested path reaches a new
pfSense function, add a `function_exists()`-guarded double there (stubs can't serve —
empty-bodied). See `tests/php/README.md`.

**Architecture pointers — read
[`docs/misc/architecture-notes.md`](docs/misc/architecture-notes.md) before touching these**
(full designs in each `.ADRs/ADR_NN_*/`):

- **DNSBL/ABP pipeline** (ADR-06/07/10/12): preprocessing→Python, ABP support, zero-downtime
  swap/watcher, update hooks — read before touching `pfb_unbound.py`, the manifest boundary,
  the swap/watcher, or the hooks.
- **Feed change detection (ADR-42):** content-addressed, not mtime-based — tagged `xxh128`
  sidecars + a real conditional GET. Read "Change detection / content hashing" before
  touching `pfb_update_check`, `pfb_download`, or any change-detection site.
- **IP alias-table reloads (ADR-40):** a table reloads iff its **final membership set**
  changed (`pfb_alias_set_different()` vs the `/var/db/aliastables` mirror);
  `pfb_alias_delta_mode` (`auto`/`delta`/`replace`; upgrades grandfather-seeded to
  `replace`) and `pfb_alias_delta_batch` control the apply path.
- **Scheduling & trigger API (ADR-43):** `sync_package_pfblockerng()` takes
  `{scope, force, trigger}`; the legacy verbs are deprecated thin adapters; scheduling is one
  cron tick + the due-ledger (`pfb_due_ledger.json`; absent ⇒ due-now-jittered, past ⇒ due,
  corrupt ⇒ fail-safe due); knobs `pfb_tick_interval` (15) and `pfb_quiet_hours` ('').
- **Aggregated "Uber" aliases (ADR-11):** opt-in Native `pfB_<Type>_Aggregated_v{4,6}` built
  in-pass, mtime-gated, by `pfblockerng.sh aggregate`; membership pinned in
  `tests/php/AggregateMemberListTest.php`.

---

## Smoke tests (ADR-04 — live pfSense VM) — READ BEFORE TOUCHING `tests/smoke/`

`tests/smoke/` installs the branch `.pkg` on a REAL pfSense CE VM in CI and asserts
pfBlockerNG end-to-end. **Run it locally first** (no workflow spent):
[`docs/misc/local-smoke-debian.md`](docs/misc/local-smoke-debian.md), wrapped by
`scripts/local-smoke.sh` — it already exists; reach for it before asking.

Non-obvious truths, each costly to relearn:

- **Probe ON-BOX** (`drill @127.0.0.1` over SSH), never the runner-side SLIRP hostfwd.
  Python-mode DNSBL has no localhost exemption. After `reload()` → `wait_unbound_ready`, the
  **first** DNS response is authoritative — assert it, never loop for the expected value.
- **Test domains MUST be `helpers.unique_domain()`** (`uuid-*.com`): never RFC 6761 TLDs
  (Unbound's built-in `local-zone`s shadow them before DNSBL) and never HSTS-preload names
  (`pfb_hsts` default ON forces a would-be VIP block to NULL). Sole carve-out: byte-identity
  harnesses use fixed inert literals (same two prohibitions apply).
- **Block shapes (python mode):** NOERROR + VIP (`dnsbl_ipv4`) or NULL (`0.0.0.0`/`::`);
  NEVER NXDOMAIN for a feed match (SafeSearch-only). Per-list `logging` selects VIP vs NULL
  and is a LIST-level field, not per-row. Compare IPs by value (`::` == `::0`).
- **Unbound is chrooted at `/var/unbound`** — module-read files must be chroot-relative; a
  host-absolute path silently fails to load.
- **pfSense root's login shell is `tcsh` — always drive the guest via `/bin/sh`.** tcsh
  silently mangles POSIX syntax (`2>&1`, here-docs, `grep -E` with `()`/`|`/`$`) — it once
  produced a false `rules.debug:0` read. `SmokeVM.ssh` already wraps commands in `/bin/sh -c`;
  do the same for anything new or by hand. (`pfSsh.php` snippets are a separate
  stdin/`exec`/`exit` contract.)
- **Enable chain:** DNSBL `mode=='enabled'` needs `enable_cb=on` + `pfb_dnsbl=on` + the DNS
  Resolver enabled (`unbound_state`). On `devel`, `dnsbl_mode`/`pfb_py_block` are dead keys;
  on `main` they're still required.
- **The image bakes only deps + qemu-guest-agent** — the harness injects the DNSBL VIP
  (`ensure_dnsbl_vip`) and all per-case config; `pkg add` runs offline (RUN_DEPENDS baked via
  `scripts/misc/install_deps_CE_2.8.sh`); `pfb_dnsvip_auto` defaults OFF, so
  `ensure_dnsbl_vip` stays the fixture. The smoke qcow2 cache is content-keyed by GHCR
  digest.
- **The branch `.pkg` is built on a plain Linux runner** (`build-pkg-linux.yml` →
  `scripts/build-pkg-portable.py`) — pfBlockerNG is a `NO_BUILD` port; this is the **sole**
  builder for CI and releases.
- **Every run uploads a full guest snapshot** (`smoke-diagnostics`: `/var/log`, `dmesg`,
  `pfctl -sa`, unbound + pfBlockerNG state, scrubbed `config.xml`). On any failure, read it
  first.

Web-UI tiers (ADR-14, `tests/smoke/ui/`) + the mock-feed load smoke (ADR-16 Part C) are
documented in architecture-notes. Operative facts:

- **Tier A `ui_render` is the PR gate**: GET each page → 200, body free of PHP
  errors/warnings, a page-specific marker present, AND no new on-box `php_error.log` line —
  never HTTP 200 alone. Tiers B are schedule/dispatch-only. Run:
  `python3 -m pytest tests/smoke/ui -m ui_render --override-ini="addopts="`
  (`SMOKE_ADMIN_PASSWORD` must be set — the UI fixtures FAIL without it; a skip is not a
  pass).
- **Selective dispatch:** a bare `gh workflow run smoke.yml`/`ui-tests.yml` defaults to
  `scope=impacted` (min-CE leg + test modules changed vs `origin/devel`); pass
  `-f pytest_filter="a or b"` to add tests covering changed non-test code; `-f scope=full` =
  every leg, whole marker. Nightly/`workflow_call` gates stay full. Locally pass `-k`/`-m` to
  `scripts/local-smoke.sh`. Full reference: architecture-notes "Selective dispatch".
- Fixtures live in `tests/smoke/fixtures/` (inert data — RFC 5737/3849 IPs, `uuid-*.com`;
  never RFC 6761 TLDs or HSTS-preload names). Add one: the file + `fixtures/README.md` + a
  `test_smoke_feeds.py` case via `mock_feeds.feed_url("<name>")`.

---

## Branches and releases

| Branch | Channel | Ships to |
| ------ | ------- | -------- |
| `main` | Stable | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

**Tag scheme (single source of truth: `scripts/release-version.sh`; behaviour pinned by
`tests/test_release_version.py`).** Semver core `X.Y.Z`: pre-releases
`vX.Y.Z.alpha.N`/`.beta.N`/`.rc.N` cut from **`devel` only** → GitHub pre-release (FreeBSD
pkg orders the stage keywords natively below the bare release; the tag maps to `PORTVERSION`
verbatim); stable `vX.Y.Z` from **`main` only** (typically the final rc's commit; `devel`
then opens `X.(Y+1).0.alpha.1`). `release.yml` and `.githooks/pre-push` both consume the
script, so the rule never drifts. A versioned tag triggers: tests → GitHub Release → port
bump on our **`pfBlockerNG/FreeBSD-ports` fork** (self-hosted distribution, no upstream PR).
**Nightly builds get no GitHub Release.**

Release-notes pipeline (committed-file precedence, GitHub Models draft, persist job) +
dry-run harness: [`workflow-reference.md`](docs/misc/workflow-reference.md) "Release notes
pipeline".

**Self-hosted pkg repository (ADR-17).** GitHub Pages repo (`pfblockerng.github.io/pkg`);
repo `priority: 100` dominates version selection, so our build wins over Netgate's. **Hard
rule (ADR-20): the catalog is keyed by *varver* (`ce-2.8` / `plus-26.03`), NOT by `${ABI}`**
— an ABI is not 1:1 with a version/edition's `php`/`py3` build inputs; the incidental
CE→FreeBSD15 / Plus→FreeBSD16 split is not a licence to key by ABI. **Never make that
simplification.** Mechanics: workflow-reference + architecture-notes "Self-hosted pkg
distribution".

**Merge PRs by rebase only** — `gh pr merge <N> --rebase`; never a merge commit, never
squash. History stays strictly linear (`main` always an ancestor of `devel`).

**Default landing flow — `/pr-merge-flow N`** after completing any issue, ADR, or code
change: review feedback first, then merge. A **Claude adversarial review runs on EVERY PR
as the committed `review-single` workflow** — ONE reviewer sub-agent at effort `xhigh`
(never below, never `max`), latest Sonnet by default / latest Fable for a large/complex PR,
**never Opus, never a multi-agent fan-out** (`review-fanout` only on explicit user request);
the full reviewer contract lives in `.claude/workflows/review-single.js`, not here — in
addition to **GitHub
Copilot** (its review is *requested* when available, skipped
if already reviewing, and waited on, bounded) and **CodeRabbit** when it reviews. A CodeRabbit
rate-limit notice follows the **5-minute rule** (its stated resume time > 5 min ⇒ proceed
without it; ≤ 5 min ⇒ wait, nudge once, drop it on any further problem). **Snyk is advisory**
— never waited on, never a required check; only a terminal `failure` verdict where it actually
ran and flagged something is handled (as a security finding). A bot quota notice is an
acknowledgement with **no review** — surface the skipped reviewer; never read it as "PR is
clean". Only the dev-only no-PR classes are exempt.

**Applying review findings follows the coverage-matrix discipline.** A finding that names a
*class* ("the X clauses", "all Y", "… etc.") is fixed by re-enumerating the class **from the
source** (grep), never from the finding's wording — PR #933's review-fix pinned 2 of 4
equality clauses by trusting the reviewer's "etc." (#935). **The re-enumeration greps the
whole tree** (`git grep` over every scan root and file type), never just the file the finding
names — PR #1005's `[ NOW ]` retirement (#1008) removed all 29 tokens in `pfblockerng.inc`
and left 9 in `www/pfblockerng/pfblockerng.php` (#1047); when a change *retires* a literal
token, a zero-hit tree grep for it is part of done (mechanical backstop designed in #1059).
An APPLY delta that skips a full re-review still gets its coverage-matrix tick recorded in
the audit comment. **A
confirmed-real finding a reviewer itself downgrades to "pre-existing / no action needed" is
still a finding**: it enters triage as DEFER and lands as a tracking issue before the merge —
two real bugs from PR #937's re-review existed only in a session transcript until the
post-merge audit (#941). **A fix overturning Accepted/Implemented ADR text amends the ADR in
the same change** (§8 "Post-merge amendments"; stale text seeded #1047 — rule + exemplars:
[`workflow-reference.md`](docs/misc/workflow-reference.md) "ADR amendments after merge").

**Rebase onto the latest base before every push, PR, or CI/smoke dispatch.** `devel` advances
out of band: `git fetch origin` + `git rebase origin/devel` (or `origin/<pr-base>`),
`--force-with-lease` if rewritten; never reconcile with a merge commit. A stale base re-runs
bugs the base already fixed and sends you chasing a phantom regression (bit ADR-29); a
freshly-rebased branch that still fails is genuinely your bug.

**Clean the diff before you push/PR.** `git diff origin/devel...HEAD` and reduce it to only
what the change requires — strip debug logging, dead/commented-out experiments,
churned-then-reverted code, introduced-then-unused symbols, gratuitous reformatting, scratch
files. Cheapest before the PR exists.

### Branch naming (ADRs and issues)

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

#### Managed-remote sessions: branch policy + cross-session resume

**One branch per work item** always — never carry one item's branch over to a different item;
a branch name that disagrees with the work item is a smell. Preferred config: the
environment's push policy permits the canonical `adr/{NN}-{slug}` / `issue/{NN}-{slug}`
branches (`devel`/`main` stay PR-only) — resume is then native. When pushes are hard-pinned
to a minted `claude/*` branch, the pinned branch replaces the convention: record a greppable
`ADR-RESUME:`/`ISSUE-RESUME:` sentinel in the first handoff, **discover prior work before
starting fresh**, auto-resume only when unambiguous, and flag any name/item mismatch to the
user. Full policy: [`workflow-reference.md`](docs/misc/workflow-reference.md)
"Managed-remote sessions".

---

## GitHub issues

**Read the whole issue before working it** — title, body, AND every comment
(`gh issue view <N> --comments`); later comments routinely revise/narrow/downgrade/invalidate
the original (issue #25). Never act on the opening text alone. Branch: `issue/{NN}-{slug}`.

### TypeError-class tracker (#1143)

Every newly found TypeError-class defect (a request/array value reaching a string-typed sink
— the array-`$_POST` family: #1070/#1106/#1128/#1139) gets its own issue **and is linked as a
sub-issue of tracker #1143** (GraphQL `addSubIssue`); never folded into an older issue.

### Labels (lifecycle)

Keep labels in sync (`gh issue edit <N> --add-label/--remove-label`; they already exist —
`gh label list`): create → descriptive label(s) (`bug`, `enhancement`, …); pick up → add
`WIP`; PR open → remove `WIP`, add `Waiting PR`; PR merged → remove `Waiting PR`; resolved
without a PR → remove `WIP`; dropped/can't-fix → remove both + a status comment explaining
why.

---

## Commit style

`<scope>: <imperative summary>` (follow the existing log — e.g. `ci: simplify pytest
invocation`, `pfblockerng: fix IPv6 subnet match`). No trailing period; body optional for
non-obvious changes.

**Attribution:** both environments keep the human owner visible and earn a GitHub
**Verified** badge. On a box with the **user's own signing key**, the user
authors/commits/signs as themselves and Claude is credited via a `Co-authored-by:` trailer
with its GitHub-recognized identity (mandatory — never a user-signed commit with no mention
of Claude). In **agent/managed-remote** environments, Claude is committer+signer, the human
is author (`--author=`), and the `prepare-commit-msg` hook injects the owner's
`Co-authored-by:` trailer automatically. Full two-model spec + badge preconditions:
[`workflow-reference.md`](docs/misc/workflow-reference.md) "Author, committer, and signing".

---

## No orphaned waits — every trigger dies with its task

Background waits have been found running **20+ hours** after their task ended; there is no
platform-level timeout on polls/cron/`ScheduleWakeup`/subscriptions, so the guarantees are
ours. Three, ALL mandatory:

1. **Self-terminating by construction.** Every background wait carries a hard iteration cap
   AND a wall-clock deadline *inside the loop itself* (`scripts/agent/wait-*.sh` are the
   exemplars — and the standard transport when `gh` exists) so it dies on its own even if orphaned. A wait without a cap is a defect —
   never launch one. Event waits also follow the heartbeat ladder (10, 10/10/15/15/30/30 min,
   ≈2 h total, then give up + report the wait abandoned; never re-arm past it).
2. **Cancel-on-resolution sweep.** The instant a work item reaches a terminal state by ANY
   path — success, failure, give-up, or a user-driven check that supersedes the wait — sweep
   every trigger tied to it, by class: background polls → `TaskStop`; cron check-ins →
   `CronDelete`; PR/event subscriptions → unsubscribe. `ScheduleWakeup` **cannot be
   cancelled**, so: **never one long wakeup at a speculative future time** — arm the
   SHORTEST sensible rung, do a minimal state check on firing, and re-arm the next rung
   only if still unresolved (the ladder). Every wakeup prompt uses the self-invalidating
   template: `CHECK <concrete state/command>; IF RESOLVED: no-op, do NOT re-arm; ELSE <next action> + re-arm <n> min`. Wakeups are a *fallback* to harness completion
   notifications, never the primary wake. The wait-spawning skills carry this sweep as an
   explicit terminal step; it is not optional and not from memory.
3. **Pickup hygiene.** When starting or finishing any work item, run `TaskList` once and
   stop every stale wait you own from earlier items. If the task moved on, its future
   triggers are dead — good or bad outcome alike.
4. **Portability — no `gh`, no bash polls.** Background bash loops presume the local
   toolbox (`gh`); managed environments may lack it, and MCP tools are harness tools —
   unreachable from inside a shell loop. Detect once at task start (`command -v gh` +
   `gh auth status`); when absent, do GitHub reads/writes via the `mcp__github__*`
   equivalents and run every wait as **wakeup-paced checks**: one minimal MCP state check
   now → still unresolved → `ScheduleWakeup` the next ladder rung (self-invalidating
   template) → repeat. Same rungs, same 2 h cap, same sweep — only the transport changes.

Full ladder semantics + per-class mechanics:
[`workflow-reference.md`](docs/misc/workflow-reference.md) "Bounded waits".

---

## Repository structure

```text
pfBlockerNG/
├── src/                   # Production code — mirrors the pfSense filesystem; releases ship ONLY src/
│   └── usr/local/
│       ├── pkg/pfblockerng/   # pfblockerng.inc/.sh, pfb_unbound.py, list_scripts/, installers
│       ├── share/             # info.xml
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # pytest suite; tests/php/ (PHPUnit); tests/smoke/ (+ ui/); tests/phpcs/
├── docs/misc/             # Dev-only notes: architecture-notes, workflow-reference, runbooks
├── scripts/               # Dev tooling: deploy.sh, setup-hooks.sh, policy checkers, stub generator
├── stubs/                 # pfsense/ (PHPStan/IDE) + python/ (unboundmodule) — not shipped
└── pyproject.toml, phpunit.xml, phpcs.xml.dist, composer.json, .editorconfig, …
```

## Updating documentation

**Documentation-only changes skip CI** (`paths-ignore` on `**/*.md` + `docs/`) but still lint
pre-commit and still use a worktree + the normal landing flow. Update `README.md` when
workflow steps, min supported CE, or dev tooling change. **Stubs (`stubs/pfsense/`):**
regenerate on a min-CE bump (`scripts/update-pfsense-stubs.py`);
`globals.php`/`logging.php`/`supplemental.php` are always hand-maintained; prefer a real stub
over a `phpstan-baseline.neon` suppression. **Bumping the minimum pfSense version** is a
multi-step runbook: [`docs/misc/version-bump-runbook.md`](docs/misc/version-bump-runbook.md).
