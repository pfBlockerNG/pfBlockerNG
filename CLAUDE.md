# CLAUDE.md — pfBlockerNG

## Scope — the pfBlockerNG-org default

These rules, **plus** the project + user `.claude/settings.json` (the `SessionStart` hooks),
are the **default way of working for every repository in the `pfBlockerNG` GitHub
organization** — not only `pfBlockerNG/pfBlockerNG`. Any pfBlockerNG-org repo inherits them
**unless that repo explicitly overrides a rule in its own `CLAUDE.md`** (a repo-local rule wins
for that repo, and only there).

**Carries over — the general way of working:** communication (caveman + its exceptions), the
[Working principles](#working-principles--dont-guess) (don't-guess / investigate / confirm
ambiguity), worktrees + the rebase-only landing flow + `/pr-merge-flow`, branch naming, the
**test-coverage mandate** (the principle: every branch, before-and-after, no coverage theater),
linting discipline, GitHub-issue handling + the label lifecycle, and commit style.

**Excluded — the obviously `pfBlockerNG/pfBlockerNG`-only parts** do **not** carry over: how to
work with pfBlockerNG itself (the DNSBL/ABP pipeline, the smoke/UI suites, the self-hosted `pkg`
repo, the ports/release plumbing) and the language/runtime specifics tied to this package (the
per-language code-standard details, `stubs/`, PHPUnit/PHPCS, pfSense internals). When in doubt,
a rule about *this package's mechanics* is local; a rule about *how we work* is org-wide.

---

## Communication

**Mandatory at the start of every session — this step CANNOT be skipped:** if the `ponytail`
plugin is installed, activation of its **full** mode is mandatory (run `/ponytail:ponytail
full`); otherwise, run the `/caveman` skill (terse, no filler, full technical accuracy).
Enforced by a `SessionStart` hook in `.claude/settings.json` (project, shared) and
`~/.claude/settings.json` (user); the hook is the mechanism, this line is the rule.

Two style exceptions — both stay concise and to the point, but drop the caveman register for
**normal professional grammar**:

- **External / public-facing text** (GitHub issue & PR/MR comments, PR bodies, commit
  messages) — text other people read on the project.
- **Documentation** (Markdown, code comments, docblocks, READMEs, ADR text) — professional but
  still terse, optimised for clarity and ease of understanding; no unnecessary detail.

### Work-context marker

While actively working **an ADR, a GitHub issue, or a PR** (open / in progress), begin every
reply with a one-line status marker so the work item stays on-screen. Plain markdown only —
**no ANSI color escapes** (they render as literal `[..m` junk; only Bash/tool output
colorizes, only on a terminal). The emoji is the only cross-device state signal.

Format (one space after the emoji):

```text
<emoji> ***ID***(***#PR***): ***Title***
```

- **ID**: `ADR-NN` for an ADR, `#NN` for an issue, `#NN` (PR number) for a standalone PR with
  no issue/ADR.
- A **PR belonging to an issue/ADR** keeps that id and appends the PR number — `#43(#56)`,
  `ADR-10(#56)`. Omit `(#PR)` until a PR exists.
- **Emphasis**: ids and title are ***bold+italic*** (`***…***`); separators `( ) :` stay plain.
- **Budget**: ~28 chars **including the `(#PR)` group** (trailing `…` not counted; ~1 char
  slack for a 2-cell emoji). Trim the **title** with a trailing `…` to fit.

Emoji = current state:

| Emoji | State |
| ----- | ----- |
| 📝 | creating/authoring an ADR |
| 🏗️ | implementing an ADR |
| 🤔 | investigating a GitHub issue |
| 🛠️ | implementing/fixing a GitHub issue |
| 👀 | a PR is awaiting review |
| ⏳ | a PR is awaiting CI |
| 🏁 | a PR is merged — cleaning up |

Examples:

- 🛠️ ***#43***(***#56***): ***TLD-Allow KeyError on…***
- 👀 ***#61***: ***skip CI for documentation-only…***
- 🏗️ ***ADR-10***(***#56***): ***ABP precedence rework***

Omit the marker on plain conversational turns.

---

## Working principles — don't guess

The top rule across everything below: **never assume — read the source of truth, investigate
the live state, and confirm a genuine fork before building.** A clean grep of one file is not
proof; a plausible memory is not a fact.

### Ambiguity — confirm before you build

**Pick the obvious option and proceed when there is one; pause and ask (`AskUserQuestion`)
when the choice is genuinely the user's to make.** Before any non-trivial change — an ADR
phase, an issue fix, a refactor — stop and confirm when: the requirement/intent is unclear;
there is **more than one defensible approach** diverging in ways the user would care about; or
the change is **architecturally significant** (the DNSBL/ABP pipeline, the manifest boundary,
the zero-downtime swap/watcher, a `config.xml` schema/migration, a privilege/security surface,
or public behaviour). Don't guess through that fork — but don't ask what the code, the
request, or a sensible default already answers. Applies to autonomous flows too (`/gh-issue
--fix`, `/adr-phase` gate on the same test before spawning work).

### Investigate, don't assume — read sources, not proxies

When debugging real pfSense/FreeBSD behaviour, **verify against the source of truth and the
effective live state**; never infer presence/absence from one generated artifact.

- **Follow file inclusions.** *NIX config splits across `include:` directives and `*.d/`
  drop-ins — grep the whole tree, then follow the chain. Example that bit us: Unbound's
  DNS-Resolver ACLs live not in `/var/unbound/unbound.conf` but in the included
  `/var/unbound/access_lists.conf` (with `host_entries.conf`, `domainoverrides.conf`,
  `remotecontrol.conf`).
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
  `pkg00-atx.netgate.com`). Hence the smoke harness keeps egress OPEN during `deploy()`/reload
  — `pkg add` pulls RUN_DEPENDS from that mirror.
- **Confirm what's installed with `pkg`.** `pkg info` / `pkg info <pkg>` / `pkg info -l <pkg>`
  (files) / `pkg which <path>` (owner); available: `pkg search` / `pkg rquery`. The smoke
  image ships `ldns` (→ `drill`), `bind-tools` (→ `dig`/`host`/`nslookup`), `python311`,
  `unbound`, `php83`, `qemu-guest-agent` — check before adding a dep or coding a fallback.
- **`/conf/config.xml` is the source of truth** for pfSense settings; `/var/…` is generated
  from it. To check a setting, open the relevant `config.xml` section (e.g. `<unbound><acls>`)
  — don't assume.
- **"Everything is files" cuts both ways:** read the actual files (diff before/after) and
  confirm a set/empty value on the box, not from recollection.

### Resolve pfSense-provided PHP functions from upstream

When a pfSense-provided PHP function is missing, ambiguous, or possibly implicated in a bug
and isn't stubbed yet, **do NOT guess a workaround.** It's open source:
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
generator under "Updating documentation".

### Plan with a higher model, implement with Sonnet

Substantial coding work is **planned and gated by a higher model** (Opus / Fable) and
**implemented by Sonnet** sub-agents: the planner splits the task into steps, a Sonnet
implementer executes each, and the planner **independently checks every step** before the next
— that per-step gating is what makes a cheaper implementer safe. The skills already wire this
(`/adr-phase` and `/gh-issue --fix` spawn `model: sonnet` implementers under orchestrator
gates); for ad-hoc coding, follow the same shape. The higher model may also implement a fix
**directly** when it is estimated to be **relatively small and doable in one step** — not just
trivial one-line edits — and always handles **docs / config / settings / skills** directly.
Delegation is for non-trivial, multi-step `src/`/`tests/`/CI work.

- **The implementer implements; it never re-delegates — the split is exactly one level deep.**
  A Sonnet implementer spawned for a step does the work itself with Read/Edit/Write/Bash and
  **must not spawn further agents** (no `Agent`/Task call). Only the orchestrating higher model
  delegates. This section is read by both roles, so be explicit: **if you are reading it as a
  spawned implementer, you are the implementer, not a new planner** — build, don't re-delegate.
  (Recursion here is a real failure mode: an implementer that re-reads "implement with Sonnet"
  and spawns its own sub-agent returns an "I launched an agent…" no-op instead of code.)
- **The planner's brief to Sonnet must be self-contained, accurate, and well-referenced** — the
  exact objective, the files/symbols to read and change (paths, `file:line`), the constraints,
  the verification gates, and the prior step's handoff. A vague or wrong brief is a planner bug.
- **Propagate an active ponytail level to every delegate.** If the `ponytail` plugin is installed
  and active in the orchestrator's session (e.g. `/ponytail:ponytail full`), every spawned
  sub-agent MUST run at the **same level** — make the **first** line of its brief
  `Run /ponytail:ponytail <level>` (the level active here: full/lite/ultra) before any other work,
  so the delegate inherits the same laziness discipline. This is part of the mandatory handoff,
  not optional; skip it only when ponytail is not active in this session.
- **Sonnet follows every directive in this file** — communication, the working principles
  (investigate / "don't assume, read" / confirm ambiguity), code standards (style, naming,
  per-language rules), the test-coverage mandate, and how to work with the specific
  codes/frameworks/tests. The implementer is cheaper, not exempt.
- **Run at effort High or better** when available — set as the session default in
  `.claude/settings.json` (`effortLevel`).

---

## Bounded waits — scheduled tasks / triggers must self-terminate

**Any agent that waits on an external event MUST bound the wait so it dies on its own** — a
cron self-check-in, a `ScheduleWakeup` / `/loop`, or a PR-activity subscription. There is **no
platform-level timeout** on these (the only automatic backstop is a ~7-day hard expiry, far too
long), so a wait that re-arms on its event alone hangs for days when the event never fires — the
exact failure we are killing here. Two independent guards, **both required**:

### 1 — Never trust the event trigger alone: arm a self-check heartbeat ladder

A trigger can be **mis-wired** (wrong PR/run id, a webhook that never arrives, a queue that never
emits) — then the event-driven wake never fires and the agent would wait forever. So **always**
also arm a *self*-check-in, independent of the event, on this escalating ladder of delays:

- **First self-check: 10 minutes** after arming the wait — the agent wakes and **checks the real
  state itself** (poll the PR / CI run / job directly via its CLI or API; do **not** assume the
  trigger will wake you).
- **If still unresolved, re-arm on the ladder: 10, 10, 15, 15, 30, 30 minutes** — six further
  self-checks. Total budget ≈ **120 min (2 h)** across the seven checks.
- **After the final 30-minute rung with the awaited thing still not done → give up and die:**
  `unsubscribe` / `CronDelete` the check-in (and any subscription), then report that the wait was
  **abandoned because the event never fired** and that **the trigger may have been mis-configured**
  — so the user can see it failed rather than find it hung hours later. **Never re-arm past the
  ladder.**
- **Any check where the awaited thing HAS happened ends the ladder early** — handle it and stop.
  Genuine in-flight progress (e.g. CI still legitimately running) does not reset the ladder; the
  2 h cap is hard. If the work genuinely needs longer, that is the user's call to extend, not a
  silent re-arm.
- **Cancel on resolution — leave no orphaned trigger.** The instant the task reaches a terminal
  state by **any** path — a self-check (or the event) finds it done **whether the outcome is good
  or bad**, the give-up rung is hit, **or the user interrupts to ask you to check it** — immediately
  cancel **every** still-pending trigger tied to it: `CronDelete` each scheduled check-in, drop the
  `ScheduleWakeup`, `unsubscribe` the PR/event subscription. A **user-driven check supersedes the
  scheduled one** — once you have checked on request, the pending self-checks for that task are
  redundant, so kill them then and there. Never let a stale trigger re-fire hours later for a task
  that already moved on: **if the task moved on, good or bad, its future triggers are dead.**

### 2 — Event-deadline on the happy path

Independently, when waiting on a normal event (CI to go green, a PR to merge, a queued job), the
event-driven wait still carries its own **explicit deadline** — never an open-ended re-arm. The
ladder above is the safety net for a *broken* trigger; this is the cap for a *working* one. The
default cap is the same **2 h / seven-check** budget unless the user sets a longer one.

This is the org default for every pfBlockerNG-org repo. It supersedes any flow (the PR-babysit
check-in included) that re-arms a wait without a deadline.

---

## Code standards

### Naming — follow the established pattern

**A new variable, web-page element `id`, dict key, or config key follows the conventions
already in that file (or similar files)** — match the surrounding pattern, don't coin an
ad-hoc name. Spans the whole stack (PHP, Python, shell, JS, `www/`, `config.xml` keys). E.g.
with sibling `pfB_*` identifiers, a wizard "don't show again" flag is **`pfB_wizard_disable`**,
not `donotshowthisagain`. Check neighbours for prefix, casing, separators, word order; an
off-pattern name is a smell even when it works.

### PHP

- Indent **tabs** (`.editorconfig`); target PHP 8.3 (pfSense CE 2.8).
- pfSense-injected functions (`util.inc`, `config.lib.inc`, …) are declared in `stubs/pfsense/`
  — don't `require_once` pfSense files in tests.
- No `die()`/`exit()` in library code; return or throw.
- **Web UI help text** (field/page descriptions, mostly `www/`): brief yet clear — match the
  wording, length, and style of neighbouring help texts; don't out-prose them.

### Python

- Indent **4 spaces**; target Python 3.11+; `from __future__ import annotations` for forward
  refs.
- Type-hint new functions; leave existing untyped code alone unless touching it.
- No bare `except:` — `except Exception` minimum.
- `pfb_unbound.py` runs in Unbound's Python loader — **stdlib only, no external deps**.
- **No Python interpreter ON the pfSense appliance — use PHP or POSIX sh (HARD CONSTRAINT).** The
  appliance ships `python3.11` with **no `python3` symlink**, so any `/usr/local/bin/python*`
  invocation is `rc=127` "not found" — and SILENT under `SmokeVM.ssh`'s `check=False`, so the
  command no-ops and the caller proceeds on stale/empty state (this bit the `apply_on_change` +
  `tick` smoke modules — their ledger writes did nothing). Drive the box via **PHP** (`php` /
  `pfSsh.php` / `h.php_eval` — it owns the package's data structures, e.g. the `pfb_due_ledger_*`
  API) or **POSIX sh**. `pfb_unbound.py` is the **sole** exception: it runs in Unbound's *embedded*
  Python loader (`python-script:`), never spawned through the appliance interpreter. Enforced by
  `scripts/check_appliance_python.py` (pre-commit + CI; forbids `/usr/local/bin/python*` across
  `src/` + `tests/`; unit-tested in `tests/test_appliance_python_check.py`). Bare `python3` in
  dev/CI-host tooling under `scripts/` is fine — it names the developer's interpreter, not the box's.
- **Content hashing = `md5` on the Python side (ADR-42 policy).** `hashlib` has no xxhash and the
  module is stdlib-only + chrooted, so Python uses `hashlib.md5` for its own self-comparisons only
  — never a cross-language digest (PHP/shell use `xxh128`). No Python hashing code lands in ADR-42;
  it ships with its consumer (the deferred DNSBL structure-reuse ADR). See the architecture-notes
  "Change detection / content hashing" section.
- **No fixed-time waits to coordinate concurrency (issue #456).** Synchronising async work
  (threads, daemon loops, test harnesses) with `time.sleep()` or a polling deadline is a
  classical anti-pattern — flaky under load, needlessly slow otherwise. Use a synchronisation
  primitive so one side **signals** and the other **blocks deterministically**:
  `threading.Event` / `Condition` / `Semaphore`, or `queue.Queue`. A timeout is allowed **only**
  as a deadlock safety-guard, and must then **raise an explicit assertion** (never return
  silently) — exemplar `_Harness.wait_builds` in `tests/test_adr10_watcher.py`. (A poll is a last
  resort only when the other side is production code you cannot signal — keep the loud-timeout
  assertion regardless.)
- Unbound injects API symbols (`log_info`, `RR_TYPE_*`, `DNSMessage`, …) as runtime globals,
  used as bare names. Declared once in `stubs/python/unboundmodule.py` (Pylance/mypy resolve
  via the `TYPE_CHECKING` import; the suite copies them onto `builtins`, see
  `tests/conftest.py`). Add a new injected symbol there.

### Shell

- POSIX sh only (`#!/bin/sh`); no bash-isms (`[[`, arrays, `$RANDOM`).
- Quote all expansions: `"$var"`, `"${var}"`.
- Absolute paths only for **add-on/privileged** binaries (`iprange`/`grepcidr`/`mmdblookup`/
  `jq`/`pfctl`) — as `path*` vars (see `pfblockerng.sh`). Base utilities
  (`grep`/`sed`/`awk`/`sort`/`find`/`cut`…) may be **bare** (run under pfSense's controlled
  PATH); don't rely on `$PATH` outside base.
- AWS region pre-scripts: 25 thin `list_scripts/ip_pre_AWS_*.sh` wrappers pass a `jq` region
  filter to the shared `list_scripts/aws_region_prefixes.sh` — change that one, not 25.
- **Locale (ADR-26):** set locale **explicitly + per-command**; **never** `export
  LC_ALL`/`LANG` script-wide (poisons every child + risks mixed-collation pipelines). Every
  `sort -u`/`uniq`/`comm`/`join` (and any `sort` whose order feeds a later compare) over
  machine data (IPs, punycode) carries an inline **`LC_ALL=C`** — a UTF-8/language `LC_COLLATE`
  can merge distinct strings and silently drop a blocklist entry. A *future* raw-Unicode text
  path splits the knobs (`LC_COLLATE=C` + runtime-resolved `LC_CTYPE=<*.UTF-8>`), never bare
  `C`. Full policy + deferred resolver: `docs/misc/architecture-notes.md` ("Locale policy").

### Code-quality conventions (ADR-28)

Five conventions adopted as policy of record. Apply across the codebase in progressive phases
(ADR-28 §6); each phase is one behaviour-preserving commit.

#### Per-language convention table

| Item | PHP 8.3 | Python 3.11+ | POSIX shell | `www/` JS |
| ---- | ------- | ------------ | ----------- | --------- |
| 1 — enums/bools over strings | backed `enum` for settings/mode values; genuine **predicates return `bool`** | `enum.Enum` / `typing.Literal`; predicates return `bool` | **N/A** — keep flag strings | `const` enums/booleans for new code |
| 2 — short-circuit | cheap guard first in `&&`/`\|\|`; guard side-effect ordering | same | `&&`/`\|\|` order; `case` guard before `grep` | same |
| 3 — `=` alignment | opportunistic, **touched blocks only** | same (respect `ruff format`) | opportunistic | same |
| 4 — string-ops over regex | `str_*`/`strpos`/`str_contains` over `preg_*` where equivalent; **hot loops first** | `str` methods over `re` in per-query/per-line paths | parameter-expansion / `case` over `grep -E`/`sed` where equivalent | `String.prototype` methods over `RegExp` |
| 5 — uppercase `TRUE`/`FALSE` | **uppercase** literals | `True`/`False` (already correct) | N/A | `true`/`false` (JS is lowercase) |

#### Config storage adapter rule — preserve behaviour on upgrade (ADR-28 §2.2)

- **Storage is NOT frozen — we keep it consistent for back-compat where practical, not byte-for-byte.**
  There is no versioned migration routine. New options add new stored strings; the read-boundary
  adapters absorb legacy tokens and writes emit a canonical token (which **may** differ from the
  legacy one when **behaviour-equivalent**). The goal is to preserve *behaviour* on upgrade, not
  bytes.
- **Forward-compat (upgrade) has two cases:** an **existing config with the key absent** reads to a
  value that **preserves that user's prior behaviour**; a **brand-new config** gets the **new
  default**. When those differ, a one-time grandfather seed sets the key for existing installs at
  upgrade (e.g. `pfb_rdns_seed_value`, `pfb_feed_filter_install_default`) so the absent-default
  (= the new-install default) never silently changes an existing user's behaviour.
- **Downgrade-tolerant.** Older releases string-compared these values, so an unknown token falls
  through to that release's safe default. Reusing a legacy token as the canonical value (see
  `pfb_idn`) keeps downgrade behaviour intact; a genuinely new token (e.g. `'confusable'`) simply
  reads as off on an old release — acceptable, the feature didn't exist there.
- Enums/booleans are the **internal runtime representation**. Conversion at the boundary:
  stored string → enum on read; enum → canonical stored string on write.
- **The enum owns its stored-value semantics** via the `PfbStoredEnum` interface +
  `PfbStoredEnumAdapter` trait: `EnumClass::fromStored($raw)` (read) and `$enum->toStored()`
  (write) — so the gateway and the `pfb_cfg_*` helpers stay trivial. The per-field **absent
  default** is the registry's `$entry['default']` (applied by `PfbConfig::read()` *before* the
  adapter); the enum's `default()` is only the **parse-fallback** for unknown/non-scalar
  tokens, never the absent-default. A field's `''` vs `'off'` off-value is handled by its own enum.
- **Round-trip pinned by tests** (`CfgAdaptersTest`, `RollbackContractTest`): every canonical
  token round-trips (`write(read(v)) == v`); a legacy token reads to the right runtime value
  and writes to its behaviour-equivalent canonical token (itself a legacy-valid token, so no
  novel on-disk value reaches an older release).
- **Per-field adapter inventory** — which field maps to `PfbToggle` / `PfbLenient` /
  `PfbIdnMode`, the `pfb_idn`→`PfbIdnMode` token reuse (`All` = legacy `'on'`, so it round-trips
  with no migration), and the shared Python `IdnMode` vocabulary — lives in
  [`docs/misc/config-gateway.md`](docs/misc/config-gateway.md).

#### Explicitly out of scope (ADR-28 §2.4)

- `config.xml` — no versioned schema or migration pass; legacy tokens are absorbed at the
  read-boundary adapter and writes emit the canonical (behaviour-equivalent) token.
- `py_unbound.ini` and any manifest / serialized / wire value read by Python or shell.
- ADR-26 shell locale prefixes (`LC_ALL=C`) — untouched by shell phase.
- Genuine boolean predicates (yes/no functions) — return `bool`, not an enum.
- Mass realignment of untouched lines — alignment is opportunistic within touched blocks only.
- `stubs/`, generated artifacts, third-party vendored code.

#### Config gateway — PfbConfig (ADR-29)

`PfbConfig` in `pfblockerng_extra.inc` is the **single access point for every registered
`installedpackages/pfblockerng*` scalar field**. It wraps `config_get_path`/`config_set_path`/
`config_del_path` with the ADR-28 adapter layer and a declarative field registry
(`pfb_cfg_registry()`).

**Rules for all new code that touches a registered field:**

- **Read via `PfbConfig::read($key)`** — never call `config_get_path` directly for a key
  that is in the registry. The gateway applies the default-on-absent and the read adapter.
- **Write via `PfbConfig::write($key, $value)`** — never call `config_set_path` directly
  for a registered key. The gateway applies the write adapter (enum → stored string).
- **Delete via `PfbConfig::delete($key)`** — wraps `config_del_path` with registry check.
- **Section helpers** (`readSection`/`writeSection`/`deleteSection`) pass through to the
  raw `config_*_path` functions at the section granularity — use them for whole-section
  reads/writes that are not per-field (structural arrays, dynamic feed lists).
- **Unregistered key → `InvalidArgumentException`** — every unknown key throws at the call
  site, not silently; keeps blind-spots visible.
- **Do not `write_config()` inside the gateway.** `PfbConfig::write()` does not persist;
  the caller decides when to flush (same contract as direct `config_set_path`).
- **Registry is read-only after boot.** `pfb_cfg_registry()` is a static-cached function;
  never mutate its return value.
- **Enforcement sniff** (`PfBlockerNG.Config.RequireConfigGateway`) makes the rule mechanical:
  any `config_*_path` call on a registered key outside the gateway is a CI-blocking error.
  See the PHPCS sniff entry above for the precise scope and foreign-key exclusions.

**Mechanics → [`docs/misc/config-gateway.md`](docs/misc/config-gateway.md).** Read it before
adding a field or reasoning about the gateway's contract. It holds: **adding a new registered
field** (registry entry + `since` + round-trip test + inventory + the sniff's `$registeredPaths`);
the **rollback forward/backward invariants** + the no-versioned-schema scope limit; the
**field-vocabulary table** (`toggle`/`lenient`/`idn`/`plain`); the **since-version** convention;
the **off-VM downgrade gate**; and the **foreign-key exclusion list** — the
`installedpackages/pfblockerng*` paths that stay on direct `config_*_path` (dynamic per-row/feed
keys, wizard/sync/widget blobs, pfSense-core sections) and are **not** flagged by the sniff.

---

## Test coverage (mandatory)

Tests are how a change proves itself. **Five non-negotiable principles govern every change —
unit, integration, E2E, smoke, or UI. Each is a hard gate: a change that violates any one is
NOT done, no matter what the line-coverage number says.**

1. **A test is EVIDENCE the change works — for a behaviour change it MUST fail before and pass
   after.** When a change adds, modifies, or fixes behaviour, write/extend the test so that, run
   against the **pre-change** code it **FAILS** (for the exact reason the change addresses), and
   against the **post-change** code it **PASSES**. Prove *both* directions — watch it go red on
   the old code, green on the new (revert/stash the change, or land the test first, TDD-style).
   A test already green before the change is evidence of nothing. **Sole exception:**
   behaviour-**PRESERVING** work (refactors, the ADR prep phases) pins the *existing* behaviour
   as an oracle and stays green across the change — a regression guarantee, deliberately not
   red→green, and still mandatory.
2. **Every change ships WITH its tests.** No behaviour, feature, fix, or modified behaviour
   lands without the test(s) that exercise it. "The existing suite still passes" is **not**
   coverage of a new change.
3. **NEVER coverage theater.** A test must *validate* the code, not merely *execute* it — it
   carries an assertion that would **fail on a regression**. Green at 100% line coverage with no
   failable assertion is **rejected**.
4. **Front-end changes REQUIRE front-end tests.** A change touching front-end behaviour (`www/`)
   must carry UI tests (ADR-14; see "Smoke tests" / "Web-UI tiers" below). **Tier A (`ui_render`)
   is always required.** **Tier B (`ui_e2e`/`ui_browser`) is highly encouraged, and REQUIRED IFF
   the change produces behaviour or visual changes observable *only* in Tier B** (not already
   caught by Tier A's render/marker check). "Only in Tier B" explicitly **includes**:
   - a **new page**;
   - a **multi-step flow** — anything spanning more than one request/interaction (e.g. fill an
     element's data → save → navigate back → confirm it persisted);
   - **visual / structural** changes — element positioning, addition, or removal; page layout;
     and the like.

   When in doubt, add Tier B.
5. **Tests express the change's INTENT — they are documentation, not just coverage.** The test
   name and comments state the **intended outcome** (the behaviour being pinned), so a reader
   learns what the change is *for* — never the mechanics of how it is coded.

The five above are the **law**; the rest of this section is **how** to satisfy them — apply all
of it:

- **Branch coverage — test every condition, not one side.** When a result depends on a
  toggle/flag/mode/input-class, assert the outcome for **each** value: a boolean gets **off**
  *and* **on** (plus any third state); every `if`/`switch`/match branch and documented input
  class gets its own assertion. (In-tree: `test_dnsbl_hsts_override_forces_null` paired with
  `test_dnsbl_hsts_disabled_keeps_vip` — proves it's a real branch, not an always-null path.)
- **Assert the before-state in transition tests — no false passes.** A test that flips a
  toggle and asserts the *changed* result MUST first assert the *original*, so green proves the
  flip **caused** the change. If `i=false ⇒ a→x` and `i=true ⇒ a→y`: assert `a→x`, set
  `i=true`, **then** assert `a→y` — never just the final state. Extends to any lifecycle (a
  "blocked after listing" test first asserts the domain *resolved* before listing, and again
  after unblock — see the `tests/smoke` DNSBL lock/unlock cases).
- **Self-encapsulated — never order-dependent.** Tests may SHARE setup/teardown (fixtures), but no
  test may depend on another running before or after it. Each test establishes everything it needs
  from a known baseline (minus what is baked into the test *image*); the shared setup/teardown must
  be **idempotent** and provide that baseline. A test that passes only because a sibling ran first
  is a defect, not coverage — it masks the real behaviour. It bit the `tick` smoke module: one
  test's `mark_ran` left a future `next_due` that a later "skip" test silently relied on, so the
  skip never tested its own setup. Reset per-test state explicitly (e.g. an autouse fixture that
  wipes the artifact and **fails loudly** if the wipe doesn't take) rather than leaning on
  collection order; a module-scoped baseline reset does NOT give per-test isolation.
- **Specify complex behaviour BDD-style; keep trivial tests trivial.** A util / small rule /
  simple mapping needs only a plain, intent-named assertion. Non-trivial behaviour (state
  transitions, precedence, multi-step flows — DNSBL/ABP decision logic, the decision cache,
  smoke journeys) gets a **Scenario / Background + Given–When–Then** spec, the body split into
  explicit **Given** (arrange) / **When** (act) / **Then** (assert).

- **On failure, print expected vs actual — no guessing.** Every assertion/matcher (and every
  poll/`wait_until`) that can fail or time out MUST put the comparison on the terminal: what it
  **expected** next to what was **actually** there (the file contents, the `pfctl`/CLI output,
  the config value), formatted AssertJ-style and **redacted** against the usual secrets. We roll
  our own harness — there is no framework giving this for free, so **implement it where it's
  missing**: a bare boolean matcher that only says "False" is not acceptable. A diagnostic that
  filters by a token must also match the value's **rendered** form (e.g. `pfctl` prints port 53
  as `domain`) or it under-reports and misleads. Exemplar: `_redir_match_report` in
  `tests/smoke/test_dns_redirect.py`. This cost a whole misdiagnosis once — a present rule read
  as absent because nothing printed the actual ruleset.

### ADR acceptance — automated tests, not a manual sign-off

An ADR flips to **Accepted** on **green automated coverage alone — no manual maintainer
validation step required** — *provided* its smoke and/or UI tests (ADR-04 live-VM / ADR-14
Web-UI) are **properly implemented**: they **prove the solution works** (real behaviour, every
branch, before-and-after, per the mandate above) **and guard against regression**, green on
the live-VM **fan-out (CE + Plus** — the default validation). Coverage theater doesn't
qualify, so this never lowers the bar — it removes a redundant human gate once the machine
genuinely proves the behaviour. A §7 item that **cannot** run in CI (HA/CARP sync, a real
HAProxy reload, a continuous-traffic load profile, the smallest-box RAM gate, true *visual*
correctness) is a **documented out-of-CI limitation**, not an acceptance blocker. **Supersedes**
any older per-ADR "manual smoke required before Accept" gate.

---

## Linting

Run linters **while working** for fast feedback. Enforcement is layered: the
`.githooks/pre-commit` hook blocks any failing commit, and CI is the final authority (runs them
even when the local hook is inactive or a tool is missing).

### Python

```sh
ruff check .        # lint
ruff check . --fix  # lint + autofix
ruff format .       # format
```

Config in `pyproject.toml`; target Python 3.11+ (pfSense CE 2.8 / FreeBSD 15). Ruff is
canonical; `.flake8` exists only so Flake8 users (e.g. the VS Code extension) get the same
120-column limit + ignore set (Flake8 can't read `pyproject.toml` — else it falls back to 79
columns and whitespace checks Ruff delegates to `ruff format`). Keep them in sync.

### PHP

Intelephense in VS Code (`.inc` = PHP via `files.associations`); `stubs/pfsense/` resolves
pfSense functions — if one is flagged undefined, add it to the right stub file rather than
expanding `undefinedFunctions` in `.vscode/settings.json`. PHPStan + PHPUnit + PHPCS are the
gates (pulled by `composer install`, enforced in CI `test.yml` + the pre-commit hook). The
`stubs/pfsense/` stubs are for PHPStan, NOT runtime doubles (those live in
`tests/php/pfsense_doubles.php`).

**PHPCS — three targeted sniffs** (`tests/phpcs/PfBlockerNG/`, wired via `phpcs.xml.dist`; each
behaviour-pinned by its own `*SniffTest.php`, where the precise scope/exclusion mechanics live):

- **PFBL-01 `PfBlockerNG.Validation.RequirePfbFilter`** (scope: `pfblockerng.inc`) — inside an
  allow-listed input-handling function (the `scopeFunctions` property), an `exec`-family call,
  `json_encode` manifest write, or dynamic filesystem-path build must be **preceded by a
  semantic-validation call** (`pfb_filter()` / `pfb_sanitise_feed_header()` / `sanitize_ipaddr()`)
  — the layer `escapeshellarg()` can't provide. Add a new in-scope surface to `scopeFunctions`.
- **`PfBlockerNG.CodeStyle.UppercaseBooleanLiteral`** (scope: all `src/` PHP) — boolean **value**
  literals must be uppercase `TRUE`/`FALSE`; type-declaration positions, strings, and `null` are
  out of scope.
- **`PfBlockerNG.Config.RequireConfigGateway`** (scope: all `src/` PHP except
  `pfblockerng_extra.inc` / `pfblockerng_migrate.inc`) — a `config_*_path` call whose first arg is
  a static literal resolving to a **registered** key must go through `PfbConfig` instead; dynamic
  paths, foreign keys, and section-level reads are not flagged. Adding a registered key ⇒ also add
  its path to the sniff's `$registeredPaths`.

Run `vendor/bin/phpcs --standard=phpcs.xml.dist src/`.

### Shell

ShellCheck (VS Code extension); all scripts `#!/bin/sh` (POSIX, not bash). `.shellcheckrc`
suppresses SC1091 (pfSense sources unreachable locally) + SC2154 (rc(8)-injected vars); don't
suppress others without justification.

**URL-encoding check (`scripts/check_url_encoding.py`)** — forbids naked shell-var
interpolation into an HTTP-client (`curl`/`wget`/`fetch`) URL query (e.g.
`curl "http://h/cb?ip=$VAR"`): a space-separated/empty value (e.g. `PFB_CHANGED_IP_ALIASES`)
re-tokenises the command and the param collapses. Fix: let the value ride its own option so
curl percent-encodes it — `curl --data-urlencode "ip=$VAR" http://h/cb`. No-arg run scans every
tracked `*.sh` (the `src/**` hook/pre-script surface + dev `scripts`/`tests` shell) AND
`sh`/`bash`/`shell`-tagged fenced blocks in tracked Markdown; static params (`?fixed=1`) and
base/host/path interpolation are out of scope. Enforced pre-commit + CI; detection in
`find_violations()`, unit-tested in `tests/test_url_encoding_check.py`.

### Markdown

markdownlint (VS Code extension + CLI). From repo root:

```sh
npx markdownlint-cli2          # lint
npx markdownlint-cli2 --fix    # lint + autofix
```

Produce compliant output directly: blank line around every heading/list/fence; a language on
every fence (`text` for plain output/trees/ASCII); a single trailing newline. Long lines +
compact (unaligned) tables are fine (`MD013`/`MD060` disabled). Rules in `.markdownlint.jsonc`;
globs/ignores in `.markdownlint-cli2.jsonc`. Disabled to fit docs style: `MD013` (line length),
`MD060` (table alignment), `MD036` (ADR `**Positive**`/`**Negative**` sub-headers), `MD041`
(frontmatter-led files); `MD024` is `siblings_only`; `**/TRANSCRIPT.md` ignored. Keep the
rationale in `.markdownlint.jsonc` in sync. Clean lint (`0 error(s)`) enforced pre-commit + CI.

---

## Worktrees (mandatory for AI agents)

**Every AI agent MUST do all repository work in its own dedicated git worktree** — never the
primary checkout, never shared with another agent, even when solo (concurrent agents on one
checkout race on the filesystem, index, `HEAD`, refs).

**Exception — ADR docs and skills need no PR.** Two dev-only classes never shipped to users
(release archives are `src/` only) skip the PR stage: **ADR text** (`ADR.md` + the `/adr-phase`
`.txt` prompts under `.ADRs/`) and **skills** (`SKILL.md` under `.claude/skills/`). Each still
uses a worktree but commits/pushes **directly to `devel`** (fetch + rebase first). The carve-out
is the PR only, and only for those docs/tooling files; anything touching `src/`, `tests/`, or
CI — ADR *implementation* included — uses the full worktree + rebase-only-PR flow.

- Create at task start, remove when done:

  ```sh
  git worktree add -b <branch> <path> origin/devel   # branch off the latest base
  # … work, commit, push, open the PR from inside <path> …
  git worktree remove <path>                          # run from the PRIMARY checkout
  ```

- Branch off the **current** base (`git fetch` first); a stale-tip worktree needs a rebase onto
  the base before it can land (PRs are rebase-only).
- **Reuse only YOUR OWN worktree — never adopt one you merely found.** "Reuse" means resuming a
  worktree *you yourself* created earlier in *this* run (e.g. an `/adr-phase` / `/gh-issue` run
  continuing across phases/steps) — work there. A worktree already sitting at the conventional
  path (`.claude/worktrees/{adr,issue}-NN`) that you did **not** create this run is **not** yours
  to adopt: it may belong to a **live parallel session**. Before touching any worktree you didn't
  just create, run `git -C <path> status` — foreign uncommitted changes ⇒ another session owns it;
  do **not** reuse it and **never** `--force`-remove it. Cut your own uniquely-named worktree +
  branch instead (collision suffix `-{epoch}`, see "Branch naming"). `/adr-all` and `/adr-phase`
  reuse the per-ADR `adr/{NN}-{slug}` worktree across the phases of one run; create it only when
  absent.
- **Reuse a branch for a follow-up ONLY when no other session owns its PR.** Before reusing,
  `git fetch` and check for foreign activity: a commit/force-push you didn't make, or the
  branch's open PR showing activity that isn't yours (recent pushes, running CI, review
  replies, a `WIP`/`Waiting PR` label) ⇒ **another session owns it**. Then do exactly ONE of:
  (1) **wait**; (2) **cooperate** on the same branch; or (3) **wait for the merge, then start a
  NEW branch**. **Never force-push over another session's in-flight PR** — it can clobber their
  work, or (when the rewrite leaves the head with nothing ahead of base) silently auto-close
  their PR.
- **Name the branch for its work item** — `adr/{NN}-{slug}` / `issue/{NN}-{slug}` (see "Branch
  naming").
- Gotchas: `git worktree remove` fails from *inside* the tree being removed — run from the
  primary checkout. `gh pr merge --delete-branch` can't check out a base another worktree holds
  (it errors on the local post-merge step though the remote merge succeeded) — verify the merge
  landed, then `git push origin --delete <branch>` separately.

---

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath` to
`.githooks`). git can't auto-apply a committed hooks path, so this opt-in is required.

**Claude: ensure hooks are active before working here.** If `git config core.hooksPath` is not
`.githooks`, run `sh scripts/setup-hooks.sh` once at session start (idempotent). **Any GitHub
Actions workflow that commits code must run it after checkout, before commit/push** — so
automated commits hit the same checks (subject to the runner's installed tools).

- **`.githooks/pre-commit`** runs the fast **linters / static-analysis gates** — **not** the
  unit suites (no `pytest`, no `phpunit`: too slow for a commit gate; CI is their correctness
  gate). It is **path-scoped to the staged file types** so a commit only pays for the languages
  it touches: **`*.py`** → `ruff check`/`ruff format --check` + `mypy tests/`; **`*.md`** →
  `markdownlint-cli2`; **`*.sh`** → the no-`#!bash` shebang gate + `sh -n` + `shellcheck` +
  `shellspec`; **`*.php`/`*.inc`** → `php -l` + PHPStan + PHPCS; the URL-encoding check runs when
  `*.sh` or `*.md` is staged. Each check still runs only when its tool is installed (missing =
  reported + skipped; CI is the hard gate); PHPStan/PHPCS run only when `vendor/bin/` has them.
  Emergency bypass: `git commit --no-verify`.
- **`.githooks/prepare-commit-msg`** appends a `Co-authored-by:` trailer for the human owner so
  GitHub credits them even when an agent is the committer (see *Commit style → Author, committer,
  and signing*). It resolves the owner generically — `coauthor.email`/`coauthor.name` git config,
  else `$CLAUDE_CODE_USER_EMAIL`, else the commit author — and is a no-op when the human is already
  the committer or already credited. Runs even under `--no-verify` (that flag skips only
  `pre-commit`/`commit-msg`).
- **`.githooks/pre-push`** enforces the release tag scheme before pushes reach the remote — it
  delegates to `scripts/release-version.sh` (the single source of truth), so a `vX.Y.Z` tag must
  sit on `main` and a `vX.Y.Z.alpha.N`/`.beta.N`/`.rc.N` tag on `devel` (not yet on `main`).

---

## Running tests

```sh
python -m pytest
```

From repo root (`pyproject.toml` sets `testpaths` + `-v`; no `cd` needed). Run after **any**
change to `src/usr/local/pkg/pfblockerng/pfb_unbound.py` or `tests/`. The pre-commit hook does
**not** run the unit suite (linters only — too slow for a commit gate), so run `python -m pytest`
yourself while iterating; CI is the hard correctness gate.

PHP — the fast PHPUnit suite for the pure/extractable helpers of `pfblockerng.inc` (issue #39):

```sh
composer install      # once — installs phpunit into vendor/
vendor/bin/phpunit     # config in phpunit.xml
```

It loads the **real** `pfblockerng.inc` off-appliance: `tests/php/bootstrap.php` satisfies its
`require_once` with empty shims (`tests/php/shims/`) + behavioural doubles
(`tests/php/pfsense_doubles.php`); no production code is moved/modified. The `stubs/pfsense/`
stubs are empty-bodied (symbol existence only) — can't serve as doubles; add a faithful/no-op
`function_exists()`-guarded double to `pfsense_doubles.php` (+ an empty shim if it's a required
include) when a tested path reaches a new pfSense function. Deep pfSense-runtime integration is
the live-VM smoke's job (ADR-04). See `tests/php/README.md`.

**DNSBL/ABP pipeline architecture** — ADR-06 (preprocessing → Python), ADR-07 (ABP/EasyList),
ADR-10 (zero-downtime DNSBL swap), ADR-12 (update hooks) — and the per-ADR test/kill-gate map
are summarized in **`docs/misc/architecture-notes.md`**; read it before touching
`pfb_unbound.py`, the manifest boundary, the swap/watcher, or the hooks. Full design in each
`.ADRs/ADR_NN_*/`.

**Feed change detection (ADR-42)** — detection is **content-addressed**, not mtime-based: a
self-describing hash (`xxh128` on the PHP/shell side via `hash('xxh128')` / `xxh128sum`; `md5` on
the Python side, policy-only — code lands with its consumer), persisted as tagged
`{base}.xxhash128` sidecars (legacy `.md5` read + replaced on the next write), plus a real
conditional GET (`If-None-Match`/`If-Modified-Since` → `304` skips the body). Four comparison
scenarios, the migration, the downgrade/fail-safe rule, and the conditional-GET-first contract are
in **`docs/misc/architecture-notes.md`** ("Change detection / content hashing") — read it before
touching `pfb_update_check`, `pfb_download`, or any feed/file change-detection site. Sibling of
ADR-40 (IP pf-table set-membership gating); the deferred DNSBL structure-reuse ADR builds on it.

**IP alias-table reload model (ADR-40).** Alias tables are reloaded iff their **final
membership set changed** — not iff a member feed was re-fetched (the old feed-tracking model).
`pfb_alias_set_different()` compares the freshly computed canonical set against the last-applied
mirror at `/var/db/aliastables/pfB_<Alias>_v{4,6}.txt`; only aliases whose set actually changed
reload. For changed tables, `pfb_alias_delta_mode` controls the apply path: `auto` (default)
uses `pfctl -T add`/`-T delete` for small churn (< ~5%) and falls back to `pfctl -T replace`
for large churn, boot, or enable/disable; `delta` always applies the forward delta with NO
large-churn replace fallback (power-user override — can be slow on full-table rebuilds); `replace`
always does a full `-T replace`. Both paths produce the same `pfctl -t <t> -T show` membership
(end-state invariant). Two registered `PfbConfig` fields: `pfb_alias_delta_mode` (enum
`auto`/`delta`/`replace`, default `auto`) and `pfb_alias_delta_batch` (chunk size, default 512,
clamped 64–4096). See
`docs/misc/architecture-notes.md` ("ADR-40") for the cross-list dedup/reputation scope rules.

**Scheduling, trigger API & verb routing (ADR-43).** The reload entrypoint
`sync_package_pfblockerng()` takes an explicit **`{scope, force, trigger}`** request — `scope`
∈ ip/dnsbl/both, `force` bool (TRUE = always reparse; FALSE = respect ADR-42's detector), `trigger`
∈ cron/manual/force (→ ADR-12 `PFB_TRIGGER` via `pfb_req_to_hook_trigger()`). The legacy verbs
(`cron`/`update`/`updateip`/`updatednsbl` + Force) are **deprecated thin adapters** that build the
request via `pfb_trigger_request()` and log one deprecation line; `cron`/`noupdates`/`''` stay silent
internal triggers. CLI: `pfblockerng.php pfb_trigger scope=… force=true|false trigger=…`. **Scheduling
is one cron tick** — `*/<pfb_tick_interval>` (default 15 min) running `pfblockerng.php tick`, which
reads the **due-ledger** (`pfb_due_ledger.json` under `$pfb['dbdir']`: per-job `{last_run, next_due,
jitter}`) and dispatches only due jobs; `ss_refresh` rides every tick. **Absent ledger ⇒
due-now-jittered** (stable seeded jitter, no boot stampede), **`next_due` past ⇒ due** (offline
catch-up, runs once), corrupt ⇒ fail-safe due; the ledger is in issue #468's persist set so a clean
reboot keeps the schedule. A due job **applies on change** via ADR-40/ADR-10 (no separate apply
schedule); an optional `pfb_quiet_hours` window defers apply. Two config-only `PfbConfig` knobs
(no GUI, safe defaults): `pfb_tick_interval` (15) and `pfb_quiet_hours` (''=apply immediately). The
Update page exposes `pfb_scope`+`pfb_run_force`→Run-now plus a ledger-sourced Schedule view.
**This supersedes the old per-verb cron/hour-gate routing model** — see
`docs/misc/architecture-notes.md` ("Scheduling, trigger API & the Update page (ADR-43)") for the
full migration map + removal timeline.

**Aggregated "Uber" aliases (ADR-11, IP side — `pfblockerng.inc` + `pfblockerng.sh`).** The
`pfb_agg_types` multi-select (IP settings, **opt-in, default none**) builds, per selected
action type, the Native urltable aliases **`pfB_<Type>_Aggregated_v4`/`_v6`** = the deduped,
`iprange`d union of that type's effective set (Deny = post-suppression block set incl. DNSBLIP;
GeoIP folds in by each continent's action — no separate Geo alias). **Native (no firewall
rule)** — reference IP-sets only. Built **in-pass, mtime-gated** by `pfblockerng.sh aggregate`
via `pfb_build_aggregate_aliases()` (loads each pf table inline **before** the ADR-12 `post`
hook). Each is a **wired kernel pf table** (millions of entries for Deny) → enable only what
you consume. The never-empty `.lst` consumer files + Native aliases are ADR-12's HAProxy input;
freshness = a pfBlockerNG-triggered graceful HAProxy reload, **not** a socket push. Off-box
membership pinned in `tests/php/AggregateMemberListTest.php`; live legs are the ADR-11 §7
maintainer smoke.

---

## Smoke tests (ADR-04 — live pfSense VM) — READ BEFORE TOUCHING `tests/smoke/`

`tests/smoke/` installs the branch `.pkg` on a REAL pfSense CE VM in CI (`smoke-single.yml`,
workflow_dispatch) and asserts pfBlockerNG end-to-end.

**Run it LOCALLY (no workflow spent) on a Debian/KVM box** — the supported runbook is
[`docs/misc/local-smoke-debian.md`](docs/misc/local-smoke-debian.md), wrapped by
`scripts/local-smoke.sh` (handles the stub-DNS-on-:53 relay, the civm client image, and the
`SMOKE_*` vars). Prefer this over a CI dispatch when iterating. Reach for it before asking how
to run smoke locally — it already exists.

Non-obvious truths, each costly to relearn:

- **Probe ON-BOX** (`drill @127.0.0.1` over SSH), NOT the runner-side SLIRP hostfwd (the
  WAN-hostfwd DNS path isn't answered in CI). Python-mode DNSBL has **no localhost exemption** —
  a blocked name returns its block shape even from `127.0.0.1`. After `reload()` →
  `wait_unbound_ready`, the **first** DNS response is authoritative — assert it, never loop
  waiting for the expected value.
- **Test domains MUST be `helpers.unique_domain()`** (`uuid-*.com`): never RFC 6761 TLDs
  (`.test`/`.example`/`.invalid`/…) — Unbound's built-in `local-zone`s shadow them
  (NXDOMAIN/NODATA) before DNSBL — and never HSTS-preload names (`pfb_hsts`, default ON, forces
  a would-be VIP block to NULL).
- **Block shapes (python mode):** NOERROR + VIP (`dnsbl_ipv4`) or NULL (`0.0.0.0`/`::`); NEVER
  NXDOMAIN for a feed match (NXDOMAIN is SafeSearch-only). Per-list `logging` selects VIP vs
  NULL and is a **LIST-level** field (`$list['logging']`), not per-row. Compare IPs **by value**
  (`::` == `::0`).
- **Unbound is chrooted at `/var/unbound`** — files its python module reads must be
  chroot-relative; a host-absolute path silently fails to load.
- **pfSense root's login shell is `tcsh`, not `sh` — always drive the guest via `/bin/sh`.**
  A command sent to the bare login shell over SSH is parsed by **tcsh**, which mangles POSIX-sh
  syntax (`2>&1`/`>&` redirection, here-docs, and a `grep -E` whose pattern contains `()`/`|`/`$`),
  so it can silently mis-parse rather than error — it once produced a false `rules.debug:0` read
  and sent an investigation down the wrong path. `SmokeVM.ssh` already wraps every guest command
  in `/bin/sh -c`; when you add a new on-box command (or run one by hand), assume tcsh and force
  `/bin/sh` — never rely on the login shell being POSIX. (`pfSsh.php` snippets are the separate
  stdin/`exec`/`exit` contract, not a tcsh command line.)
- **Enable chain:** DNSBL `mode=='enabled'` needs `enable_cb=on` + `pfb_dnsbl=on` + the DNS
  Resolver enabled (`unbound_state`). On `devel`, `dnsbl_mode`/`pfb_py_block` are dead keys
  (python is the only mode); on `main` they're still required.
- **The image bakes only the deps + qemu-guest-agent** — the harness injects the DNSBL VIP
  (`ensure_dnsbl_vip`) and all per-case config; `pkg add` runs offline. The package can
  auto-create the sinkhole VIP (`pfb_dnsvip_auto`, ADR-13) but defaults **OFF**, so
  `ensure_dnsbl_vip` stays accurate. The ADR-23 setup wizard also exposes `pfb_dnsvip_auto`, but
  the harness doesn't run the wizard, so `ensure_dnsbl_vip` remains the fixture. The smoke qcow2
  cache is content-keyed by GHCR digest (a same-tag re-push invalidates automatically).
- **The branch `.pkg` is built on a plain Linux runner** (`build-pkg-linux.yml` →
  `scripts/build-pkg-portable.py`), NOT a FreeBSD VM: pfBlockerNG is a `NO_BUILD` port, so the
  portable builder reproduces `make package` from the Makefile + pkg-plist. `pkg add` checks a
  dep is PRESENT, not its version, so the portable `.pkg` installs identically on the baked-deps
  image. It's the **sole** `.pkg` builder for CI and releases — the FreeBSD `make package`
  workflow was retired (nothing to compile for a `NO_BUILD` port).
- **Every run uploads a full guest snapshot** (`smoke-diagnostics`: all `/var/log`, `dmesg`,
  `pfctl -sa`, unbound + pfBlockerNG state, `/var/db/pfblockerng`, `/var/db/aliastables`,
  scrubbed `config.xml`). On any failure, read it first.

Full journey, verified response model, and the `SMOKE_STATE_DIFF` instrument:
`.ADRs/ADR_04_VM_Smoke_Tests/RESULTS/`.

The **Web-UI tiers (ADR-14)** under `tests/smoke/ui/` and the **HTTP mock-feed load smoke
(ADR-16 Part C)** in `tests/smoke/test_smoke_feeds.py` — sample-fixture table, `_MockFeedServer`
mechanics, CI wiring (`ui-tests.yml`), gate status — are documented in
`docs/misc/architecture-notes.md`. Operative facts that stay here:

- Tier A `ui_render` is the **PR gate**: GET each page → 200, body free of `Fatal
  error`/`Parse error`/`Warning`/`Notice`/`Uncaught`, a page-specific marker present, AND no new
  on-box `php_error.log` line — **never HTTP 200 alone**. Tiers B `ui_e2e`/`ui_browser` are
  schedule/dispatch-only (non-PR-blocking). Run a tier: `python -m pytest tests/smoke/ui -m
  ui_render --override-ini="addopts="` (`SMOKE_ADMIN_PASSWORD` must be set, else the UI fixtures
  SKIP, never fail).
- **Selective dispatch (validate your own change cheaply).** A bare `gh workflow run
  smoke.yml`/`ui-tests.yml` defaults to **`scope=impacted`**: the **min CE leg** + only the test
  modules **changed vs `origin/devel`** (auto-derived). Pass **`-f pytest_k="a or b"`** to add the
  tests covering changed *non-test* code (a live-VM suite can't map src→test for you);
  `-f version=` / `-f pytest_marker=` (smoke) / `-f tier=` (UI) narrow further; **`-f scope=full`**
  is the every-leg whole-marker run. The nightly `schedule`, `version-tracker`'s post-bump
  dispatch, and the `workflow_call` gates (`test.yml`, `release.yml`) stay **full**. Locally it's
  pytest-native — pass `-k`/`-m` to `scripts/local-smoke.sh`. Full reference:
  `docs/misc/architecture-notes.md` ("Selective dispatch").
- Smoke feed fixtures live in `tests/smoke/fixtures/` (inert data — RFC 5737/3849 IPs,
  `uuid-*.com`; never RFC 6761 TLDs or HSTS-preload names). Add one: drop the file there, update
  `tests/smoke/fixtures/README.md`, add a case in `test_smoke_feeds.py` via
  `mock_feeds.feed_url("<name>")`.

---

## Repository structure

```text
pfBlockerNG/
├── src/                   # Production code — root mirrors pfSense filesystem
│   ├── etc/inc/priv/      # pfSense privilege definitions (.priv.inc)
│   └── usr/local/
│       ├── pkg/pfblockerng/   # Core package logic
│       │   ├── pfblockerng.inc        # Main PHP include
│       │   ├── pfblockerng_install.inc
│       │   ├── pfblockerng_extra.inc
│       │   ├── pfb_unbound_include.inc
│       │   ├── pfb_unbound.py         # Unbound Python plugin (matcher + DNSBL list build; incl. the ADR-08 TR39 IDN homoglyph analyzer, stdlib unicodedata.name())
│       │   ├── pfblockerng.sh         # Shell script (POSIX sh)
│       │   └── list_scripts/          # Feed pre/post transform scripts (AWS region wrappers + shared aws_region_prefixes.sh)
│       ├── share/             # Package metadata (info.xml)
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # Python test suite (pytest)
├── docs/misc/             # Dev-only reference notes (pfSense_versions.md, architecture-notes.md)
├── scripts/               # Developer tooling (deploy, stub generation)
│   ├── deploy.sh          # Push files to live pfSense over SSH
│   ├── setup-hooks.sh     # One-time: point git at .githooks (core.hooksPath)
│   ├── misc/              # Per-pfSense-version helpers (e.g. install_deps_CE_2.8.sh — bake RUN_DEPENDS on the image)
│   └── update-pfsense-stubs.py  # Regenerate stubs from pfSense source
├── stubs/pfsense/         # PHP stubs for Intelephense (IDE only, not shipped)
├── stubs/python/          # unboundmodule.py stub for Pylance/mypy + tests (not shipped)
├── .editorconfig          # Indent rules per language
├── .shellcheckrc          # ShellCheck suppressions
├── .flake8                # Flake8 config mirroring Ruff (Flake8 can't read pyproject.toml)
├── .markdownlint.jsonc    # markdownlint rule set (VS Code extension + markdownlint-cli2)
├── .markdownlint-cli2.jsonc  # markdownlint-cli2 globs + ignores
├── pyproject.toml         # pytest + ruff + mypy config
├── phpunit.xml            # PHPUnit config (PHP unit suite; tests/php/)
├── phpcs.xml.dist         # PHPCS config (PFBL-01 over pfblockerng.inc; ADR-28 UppercaseBooleanLiteral over all src/ PHP)
├── composer.json          # PHP dev deps: phpstan + phpunit + php_codesniffer
└── README.md
```

`tests/` holds the Python suite (pytest), `tests/php/` (PHPUnit for the pure/extractable
`pfblockerng.inc` helpers — bootstrap loads the real file off-appliance via include shims +
pfSense doubles; see `tests/php/README.md`), and `tests/smoke/` (the dispatch-only live-VM
suite, ADR-04, which also holds `tests/smoke/ui/` — the ADR-14 Web-UI tiers
`ui_render`/`ui_e2e`/`ui_browser` reusing the `smoke_vm` fixture + `helpers.py`).
`tests/phpcs/` holds the custom PHP_CodeSniffer standard (PFBL-01 `RequirePfbFilter`) + its
`fixtures/` (driven by `tests/php/RequirePfbFilterSniffTest.php`).

Release archives contain only `src/`. Everything else (stubs, scripts, tests, CI,
`pyproject.toml`, `.githooks/`) is dev-only.

---

## Updating documentation

**Documentation-only changes skip CI.** A commit/PR touching *only* Markdown (`**/*.md`, incl.
`CLAUDE.md`/`README.md`) or `docs/` is excluded from `test.yml` via `paths-ignore`. Touch any
code and the full suite runs. The pre-commit hook still lints Markdown. CI carve-out only — such
changes still go through a worktree + the normal landing flow.

Update `README.md` when: workflow steps change (test/deploy/release commands); min supported
pfSense CE changes; new developer tooling is added.

**Stubs (`stubs/pfsense/`):** regenerate when min CE is bumped, or hand-add a stub when
pfBlockerNG calls a new un-stubbed pfSense function. `globals.php` / `logging.php` /
`supplemental.php` are **always hand-maintained** (array shapes can't be auto-derived;
`supplemental.php` holds CE-2.8 functions absent from the 2.7.2 source). PHPStan is the gate —
**prefer a real stub over a `phpstan-baseline.neon` suppression.**

**Bumping the minimum pfSense version** is a multi-step runbook — regenerate stubs (commands +
the 2.7.2-source rationale), edit the `ci-metadata` version matrix, refresh the CE+Plus smoke
images, run the smoke fan-out — plus the ADR-08 "no UCD table to regenerate" note. Full
procedure: [`docs/misc/version-bump-runbook.md`](docs/misc/version-bump-runbook.md).

---

## Branches and releases

| Branch | Channel | Ships to |
| ------ | ------- | -------- |
| `main` | Stable  | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

New features land in `devel`. Pushing a versioned tag triggers CI: tests → GitHub Release → bump
the matching port on **our own `pfBlockerNG/FreeBSD-ports` fork** (`pfblockerng/use-github`, the
build-input branch) — self-hosted distribution, **no upstream `pfsense/FreeBSD-ports` PR**.

**Tag scheme (single source of truth: `scripts/release-version.sh`).** Semver core `X.Y.Z`, no
odd/even conventions:

- **Pre-releases — `vX.Y.Z.alpha.N` / `.beta.N` / `.rc.N`** (alpha / beta / rc; `N` ≥ 1): cut
  from **`devel` only** → GitHub **pre-release**. FreeBSD pkg orders them natively
  (`4.0.0.alpha.1 < 4.0.0.beta.1 < 4.0.0.rc.1 < 4.0.0` — pkg special-cases the `alpha`/`beta`/`rc`
  stage keywords as sorting below the bare release), and the tag maps to a pkg-safe `PORTVERSION`
  verbatim (carries no `-`).
- **Stable — `vX.Y.Z`**: cut from **`main` only** → full release. The stable tag is typically
  the same commit as the final `rc.N`, so `devel` stays in sync; `devel` then opens the next
  series (`X.(Y+1).0.alpha.1`).
- `release-version.sh` validates the shape + branch↔channel pairing; both `release.yml` and
  `.githooks/pre-push` consume it, so the rule never drifts. Behaviour pinned by
  `tests/test_release_version.py`.

**Release notes.** Body precedence: a **committed `docs/release-notes/TAG.md` wins** (curated, or
persisted from a prior run) — when present the Models step is **skipped**; else **GitHub Models**
(`actions/ai-inference`, model `openai/gpt-4.1` — **no secret**, the built-in token +
`permissions: models:read`, free tier) drafts it; else a placeholder (the release never blocks on
the generator). When Models runs, a shell step gathers the commits since the **previous
same-channel release** (`prev_tag` classifies each tag's channel via `release-version.sh`) and
feeds them with the static system prompt in **`scripts/release-notes-prompt.txt`**; the model
returns a `SUMMARY:` line (→ the Release **title** suffix, `pfBlockerNG VER — 3-word summary`) plus
a Markdown code block grouping user-facing changes under **Features / Improvements / Bug Fixes**
with PR/issue links (CI/test/tooling/ADR noise filtered out), ending with the compare link. A
**committed file** carries the same notes; its title summary rides in an optional first-line
`<!-- SUMMARY: … -->` marker (stripped from the rendered body). Generated notes are **persisted**
to `docs/release-notes/TAG.md` by the `persist-notes` job (committed to the channel branch;
docs-only ⇒ CI-skipped); a pre-committed file is left untouched. To author notes by hand (or to
"play the model" when Models is unavailable), commit `docs/release-notes/TAG.md` — same format,
optional `<!-- SUMMARY: … -->` first line. To swap models, change the `model:` input; to use Claude
Haiku on a Max plan instead, flip the step to the Claude CLI with `CLAUDE_CODE_OAUTH_TOKEN` (the
prompt file + parser are reused). **Nightly builds get no GitHub Release.**

**Dry-run.** `release.yml`'s `workflow_dispatch` is a no-publish harness: pass the `tag` to
simulate (e.g. `v4.0.0.alpha.1`) with `dry_run=true` (default) to validate the scheme, build the
`.pkg` artifacts, and render the body (the GitHub Models draft runs — no secret needed — and the
real body shows in the run summary) — **publishing nothing** (no Release, port bump, pkg-repo poke,
or notes persist). Dispatchable only from the default branch once merged.

### Self-hosted `pkg` repository (ADR-17)

Beyond the Netgate ports channel we publish a **self-hosted FreeBSD `pkg` repository on GitHub
Pages** (`pfblockerng.github.io/pkg`; NONE-signed, TLS-anchored; a derived index rebuilt from
**all** Releases each deploy). Cross-repo selection is keyed on repo **`priority:`** — it
**dominates version** — so our `priority: 100` (set by `add-repo.sh`) makes `pkg install`/`upgrade`
and the stock GUI **Install** pull our build over Netgate's. GUI discovery + the update badge stay
Netgate-bound; a GUI "Updates/Channel" panel is deferred (ADR-19; would touch `src/`).

**Hard rule — the catalog is keyed by *varver* (`ce-2.8` / `plus-26.03`), NOT by `${ABI}`** (ADR-20).
A pfSense `${ABI}` (`FreeBSD:<major>:<arch>`) is **not** 1:1 with a version/edition's `php`/`py3`
build inputs — two versions can share one FreeBSD major yet need different builds. The incidental
CE→FreeBSD15 / Plus→FreeBSD16 split is **not** a licence to key by `${ABI}`. **Never make that
simplification.**

**Mechanics → [`docs/misc/architecture-notes.md`](docs/misc/architecture-notes.md)** ("Self-hosted
pkg distribution"): the full varver/ABI rationale + live proof + upgrade-lag, the boot-time `rc.d`
conf regenerator (ADR-39), the publish pipeline (the separate `pfBlockerNG/pkg` repo + its OIDC
deploy), the generators + `add-repo.sh` bootstrap, and the `repo`-marker smoke flow.

**Merge PRs by rebase only** — `gh pr merge <N> --rebase` (or "Rebase and merge"); never a merge
commit, never squash. History across `main` ← `devel` stays strictly linear (`main` always an
ancestor of `devel`), so promotion and landing are a rebase/replay. Rebase a behind-base branch
onto its base first for a clean fast-forward.

**Default landing flow — `/pr-merge-flow N`.** After completing any GitHub issue, ADR, or code
change, land its PR with **`/pr-merge-flow N`** — roughly `/pr-comments N
--wait-for=coderabbitai && /pr-merge N`: get review feedback, validate + apply its findings and
reply, then (only if that completes cleanly) rebase-merge once real CI is green. The review
source adapts: **CodeRabbit** when active on the repo (it is — installed on the `pfBlockerNG`
org), else a **Claude Sonnet sub-agent reviewer**. **Snyk** reviews PRs too: when it is
reviewing (detectable via its `code/snyk` **commit status/gate** on the head SHA — Snyk posts
**no** review comments), wait for it **in parallel** and handle its security findings the same
way — every Snyk finding is an in-diff item to fix or justify-skip, read from the status detail.
**Either bot can run out of quota** — CodeRabbit replies with a "Review limit reached" / "run out
of usage credits" / "rate limited by coderabbit.ai" comment; Snyk's status goes to `error` ("Code
test limit reached"). A quota notice is an **acknowledgement with no review**, never a clean pass:
treat the bot as did-not-review — CodeRabbit's quota falls through to the Sonnet substitute, Snyk's
is dropped from the gate — and **surface the skipped reviewer** so it never reads as "PR is clean".
The **only** exemptions are the dev-only
classes that go straight to `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text, skills
— see "Worktrees"); everything touching `src/`, `tests/`, or CI uses this flow.

**Rebase onto the latest base before every push, PR, or CI/smoke dispatch.** `devel` advances out
of band — parallel agents replay on top, so the tip moves under you, **and** CI runs against your
branch tip. Before any commit/push, before opening a PR, and before any `workflow_dispatch`
smoke/fan-out: `git fetch origin` + `git rebase origin/devel` (or `origin/<pr-base>`), resolve,
`--force-with-lease` if rewritten — same for every follow-up commit on an open PR. **Never**
reconcile with a merge commit. A stale base re-runs bugs the base *already fixed* — most painfully
a flaky/broken test someone else fixed on `devel` still fails on your stale-based branch, sending
you to chase a phantom regression (it bit ADR-29). Validate against the base you will merge into;
a freshly-rebased branch that still fails is genuinely your bug.

**Clean the diff before you push/PR.** Diff the branch against its base (`git diff
origin/devel...HEAD`) and reduce it to **only what the change requires** — the substantive edit
plus the comments, tests, and docs that move *with* it. Strip the debris of getting there:
temporary debug logging (`log_info`/`print`/`DBG*`), dead/commented-out experiments, code churned
then reverted, an introduced-then-unused symbol, gratuitous reformatting of untouched lines,
scratch files. A reviewer (human, CodeRabbit, or stand-in) — and git history — should see the
minimal, intentional change, not the trial-and-error path. Cheapest to do **before** the PR
exists.

### Branch naming (ADRs and issues)

A branch tracking an **ADR** or **GitHub issue** carries the item's **number then a slug of its
title**: **ADR** `adr/{NN}-{slug}`, **issue** `issue/{NN}-{slug}`. `{slug}` derives from the
title (the ADR `{Name}`/`ADR.md` H1; the issue title) by this **mandatory** sanitiser (defends
against garbage/malicious input + keeps the ref legal):

1. **Lowercase.**
2. **Strip emojis + every non-ASCII char**, then drop anything not `[a-z0-9]`.
3. **Collapse** each removed/non-alphanumeric run to a single `-`; **trim** leading/trailing `-`.
4. **Truncate ≤30 chars** at a `-` boundary (never trailing `-`); don't go far past 30.
5. Empty slug → **omit it** (bare `adr/{NN}` / `issue/{NN}`).

Output is `[a-z0-9-]` only — no spaces, no `~ ^ : ? * [ \ .. @{`, no leading `-`, no `.lock`
suffix. **On collision** with an *unrelated* branch, append `-{epoch}` (epoch seconds). An ADR
reusing its own `adr/{NN}-*` branch across phases is reuse, not a collision — don't re-suffix.

Examples: `ADR_10_Zero_Downtime_DNSBL` → `adr/10-zero-downtime-dnsbl`; issue #43 "TLD-Allow
KeyError on …" → `issue/43-tld-allow-keyerror-on`.

#### Managed-remote sessions: branch policy + cross-session resume

A **managed remote (web/app) session mints its own branch** — `claude/<slug>-<rand>`, created
and checked out at container start. **Where you may push is set by the environment's branch-push
policy** (configured in the environment/trigger, *not* this repo — see
<https://code.claude.com/docs/en/claude-code-on-the-web>), and that choice decides which of the
two models below applies. Two configurations, **in order of preference**:

**Preferred — allow pushing to the canonical work-item branch.** Configure the environment's
push policy to permit the repo's own `adr/{NN}-{slug}` and `issue/{NN}-{slug}` branches (keep
`devel`/`main` **PR-only** — never a direct push). Then a managed-remote session works the item
on its canonical convention branch exactly as off-appliance: the worktree + branch-naming rules
apply unchanged, and **resume is native** — `/adr-phase` / `/gh-issue` recompute the slug and
find the existing branch with **no archaeology**. Prefer this; it makes the minted `claude/*`
branch a non-issue. The hard "never push anywhere but the session branch" pin is the wrong
default for this repo — it should always carve out this exception.

**One branch per work item — a fresh branch for each new issue/ADR.** Whichever model is in
force, a branch belongs to the **single** issue/ADR it was opened for; never carry one work
item's branch over to a different item. When you are asked to handle a **different** item than
the current branch was minted/named for — its name references another item (e.g. the branch is
`claude/gh-issue-7-…` but you are now working issue #8) — do **not** commit the new work onto
that mismatched branch. Cut a **new** branch named for the new item (the canonical
`issue/{NN}-{slug}` / `adr/{NN}-{slug}` when the push policy allows it, else a fresh
`claude/<new-item-slug>-<rand>`) off the latest `origin/devel`, and push there. Only when the
environment **hard-pins** pushes to that one stale branch and forbids every other ref is reuse
acceptable — and then **flag the name/item mismatch to the user** before proceeding, rather than
silently overloading it. A branch name that disagrees with the work item is a smell.

**Fallback — push hard-pinned to the minted `claude/*` branch.** When the environment forbids
pushing anywhere but the minted branch, you cannot reach the canonical name, so the pinned branch
**replaces** the convention for the session — adopt it; there is no start-time choice to confirm.
The cost: each session gets a *fresh* branch, so work spans sessions only if a resuming session
**finds the prior one**. The discover-and-fast-forward convention (managed-remote, pinned only):

- **Record the override loudly + machine-readably** in the first handoff (`RESULTS/01_Results.txt`,
  or the issue branch note): the prose override (actual branch replaces the `{NN}-{slug}`
  convention; a bare `/adr-phase {NN}` / `/adr-all {NN}` / `/gh-issue {NN}` recomputes the wrong
  name and misses the work) **plus a greppable sentinel line** `ADR-RESUME: branch=<actual-branch>
  next-phase=<N>` (or `ISSUE-RESUME:` for an issue).
- **Before starting an ADR/issue fresh, DISCOVER prior work.** `git fetch origin`; scan remote
  branches for that item's committed handoffs (`RESULTS/{NN}_*` for an ADR) and the `*-RESUME:`
  sentinel. Select the candidate with the **highest contiguous completed phase**.
- **Resume by fast-forward onto your own branch** (push is pinned — you cannot push to the
  discovered branch): replay/cherry-pick the discovered commits onto the current session branch
  (they share base `devel`, so it is a clean linear replay), continue the remaining phases, and
  push to *your* branch. Carry the sentinel forward with an updated `next-phase`.
- **Auto-resume WITHOUT asking iff unambiguous:** exactly one viable candidate, a valid `*-RESUME:`
  sentinel, and no sign of a concurrent live session on it (no recent foreign pushes — the "reuse
  only when no other session owns it" rule still holds). Then do **not** prompt — just resume.
- **`AskUserQuestion` only on genuine ambiguity:** multiple viable candidates, a missing/garbled
  sentinel, or a candidate that looks live (cooperate / wait instead of clobbering).

---

## GitHub issues

**Read the whole issue before working it** — title, description, AND every comment (`gh issue
view <N> --comments`). Later comments routinely revise/narrow/downgrade/invalidate the original
(issue #25: a follow-up downgraded a claimed crash to a defensive-consistency cleanup and
corrected the fix). Never act on the opening text alone. **Branch for the fix:**
`issue/{NN}-{slug}` per the slug rule above.

### Labels (lifecycle)

Keep an issue's labels in sync with its stage (`gh issue edit <N> --add-label/--remove-label`;
labels already exist — `gh label list`):

- **Create** — descriptive label(s) for what it is (`bug`, `enhancement`, `documentation`, …).
- **Pick up** (start work) — add `WIP`.
- **PR open** (a PR that fixes it exists) — remove `WIP`, add `Waiting PR`.
- **PR merged** — remove `Waiting PR`.
- **Resolved without a PR** (direct push, or closed as invalid) — remove `WIP`.
- **Dropped / can't fix** (won't-fix, not reproducible) — remove `WIP`/`Waiting PR` + leave a
  status comment explaining why.

---

## Commit style

`<scope>: <imperative summary>` (follow the existing log). E.g. `ci: simplify pytest
invocation`, `dev: add ShellCheck config`, `pfblockerng: fix IPv6 subnet match`. No trailing
period. Body optional for non-obvious changes.

### Author, committer, and signing

Two environments, two attribution shapes — both keep the **human owner visible** and earn a
GitHub **Verified** badge. Pick by whether the box has the **user's own signing key**.

**Default — agent / managed-remote environment (no user signing key on the box):**

- **Committer = signer = Claude's GitHub identity** (the account whose **verified email owns the
  registered signing key**). GitHub binds the Verified badge — and the credit it shows for a
  commit — to the **committer**, so the committer must be Claude for the signature to verify.
  (This is why "committed *by the user* yet signed by Claude" cannot be Verified — committer
  follows the signer.)
- **Author = the human owner** (`Andre Brait <andrebrait@gmail.com>`), set explicitly
  (`--author=` / `GIT_AUTHOR_*`) — keeps the human in the commit object.
- **Credit the human with a `Co-authored-by:` trailer for the owner** — the final line, after a
  blank line. **Mandatory:** the author field alone is *not* enough — with Claude as committer
  GitHub credits only Claude, so without this trailer the human is never surfaced as a contributor.
  This is injected automatically by the `.githooks/prepare-commit-msg` hook, which resolves the
  owner **generically** (`coauthor.email`/`coauthor.name` git config, else `$CLAUDE_CODE_USER_EMAIL`,
  else the commit author) — it credits whoever the owner is, not a fixed identity, and is a no-op
  when the human is already the committer or already credited. (A `Co-authored-by:` for *Claude* is
  redundant — Claude is already the committer — so omit Claude's.)
- **Sign every commit** (`-S`; SSH or GPG). Valid signature + key on Claude's account + matching
  committer email ⇒ **Verified**, attributed to Claude.

**User's personal environment, signing with the user's own key** (`commit.gpgsign = true`, or a
configured `user.signingkey`): do **not** override the local identity — let the user author,
commit, and sign as themselves, so the commit is **Verified as the user** (author = committer =
signer = the user). Claude is then *not* the committer, so the only way to credit it is the
trailer:

- **Add `Co-authored-by: Claude <…>` as the final line(s)** of the message, after a blank line,
  using Claude's **GitHub-recognized identity** (the same account used as committer in the default
  model) so it actually registers as a co-author — a trailer with an unrecognized email is just
  text and credits no one. **Mandatory in this environment:** never let a user-signed commit ship
  with no mention of Claude.
- Leave the user's `-S` signing in place; do **not** add `--author=` (the user is the author).

**Badge precondition** (one-time infrastructure, not per-commit): the default model needs Claude's
committer email verified on its GitHub account and that account holding the registered signing key.
In the **Claude Code managed-remote environment this is platform-provided** — every commit is signed
automatically by the platform key under the `claude` committer identity (with the human as author),
so the badge works with no setup. Only a **bare / self-hosted** agent setup must provision the
key + email itself (until then commits land correctly attributed but read *Unverified*). The
personal-environment model already has this via the user's own key.
