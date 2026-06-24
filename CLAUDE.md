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
gates); for ad-hoc coding, follow the same shape. The higher model may still make **trivial
one-line edits** and handle **docs / config / settings / skills** directly — delegation is for
non-trivial `src/`/`tests/`/CI work.

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
- **PHP adapters / enums** (`PfbToggle`, `PfbLenient`, `PfbIdnMode` + the thin
  `pfb_cfg_*_read/write` delegations) in `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc`:
  - `dnsbl_lenient` / `pfb_keep` → `PfbLenient` (`'on'`/`'off'`); `dnsbl_vip_auto` and ~76 other
    `'on'`/`''` checkbox fields → `PfbToggle` (off-value `''`).
  - **`pfb_idn` → `PfbIdnMode`** (registry adapters `pfb_cfg_idn_mode_read/write`): tokens
    `'on'` (= All) / `'confusable'` / `'off'`. `All` **reuses the original `'on'`** block-all
    token, so a pre-4.0.0 install round-trips with no migration *and* an older release reading
    `'on'` still blocks all IDN. `PfbConfig::read('pfb_idn')` returns the enum;
    `PfbConfig::write()` and the `py_unbound.ini` build both emit `toStored()`; consumers compare
    `=== PfbIdnMode::All` / `::Confusable`. The 4.0.0-alpha-only `'all'` token is **not** carried
    (alpha compatibility is intentionally not maintained) — it reads as Off. One canonical
    vocabulary spans `config.xml`, the ini, and the Python `IdnMode` enum.
- **Python** (`pfb_unbound.py`): the **`IdnMode` enum** shares that vocabulary — `All = 'on'`,
  `Confusable = 'confusable'`, `Off = 'off'` — and reads the ini `idn_mode` token directly (the
  legacy `python_idn` fallback is retained for a config predating the key). Toggle/lenient enums
  have **no Python consumer** (`config.getboolean()` reads all bool toggles), so they are
  PHP-only adapters.

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

**Adding a new registered field:**

1. Add an entry to `pfb_cfg_registry()` with the exact `config.xml` key, its section path,
   the default stored string, and the adapter pair (or `NULL`/`NULL` for plain string).
2. Set the `since` value to the package release that first introduced the key to `config.xml`
   (format: `'X.Y.Z'`; for legacy keys the earliest still-shipped release is acceptable).
3. Verify round-trip: `write(read(v)) == v` for every canonical stored vocabulary value.
4. Add a test in `tests/php/CfgGatewayTest.php` (round-trip + default-absent cases).
5. Update the `$inventory` in `testInventoryCompletenessAllKnownKeysAccountedFor()`.

**Rollback / backward-compat contract (ADR-29 Phase 3):**

The gateway is the enforcement mechanism for downgrade safety. Two invariants hold for every
registered field, asserted per-field by `tests/php/RollbackContractTest.php`:

- **FORWARD invariant** (old store → new code): `PfbConfig::read($key)` on any legacy stored
  token returns a well-formed runtime value — no crash, correct type, sane default for absent.
- **BACKWARD invariant** (new code → old store → old code): `PfbConfig::write($key, $v)` only
  ever emits a token from the field's **known vocabulary** — never a novel on-disk token an
  older release wouldn't understand. A write **may normalise** a legacy token to a
  behaviour-equivalent canonical one (e.g. `pfb_idn`: `All` persists as the legacy-understood
  `'on'`, and the dropped `'all'` normalises to `'off'`); the emitted token is always one an
  older release string-compares correctly. Guaranteed by construction: backed enums emit
  `toStored()` (a member of the vocabulary), and plain-string fields use identity adapters.

**Scope limit (no versioned schema).** This is *not* full backward compatibility — that needs a
versioned config schema this package deliberately lacks (ADR-28 §1.3). The invariants cover the
**vocabulary of existing registered fields** only. A genuinely **new option added in a later
release** is unknown to an older one: on rollback the old code **ignores** the key (inert, not
misread or corrupting) and its value is **preserved** in `config.xml` for roll-forward — the new
feature is simply unusable on the old version (inherent, out of scope). `since-version` bounds each
field's rollback claim to releases at/after that version; it is a per-field scope marker, not a
migration.

**Field vocabularies** (`pfb_cfg_field_vocab()`):

| Adapter type | Stored vocabulary |
| ------------ | ----------------- |
| `toggle`     | `{'on', ''}` |
| `lenient`    | `{'on', 'off', ''}` — `''` is a LEGACY READ token (pre-ADR-22 absent); write emits `'off'` |
| `idn`        | write `{'on' (=All), 'confusable', 'off'}`; legacy reads `'all'`→Off, `''`→Off (4.0.0-alpha `'all'` not carried) |
| `plain`      | identity — any stored value passes through unchanged |

**Excluded fields** — none. `pfb_idn` was previously excluded (`NULL`/`NULL` identity adapters);
it is now adopted as `PfbIdnMode` (see ADR-28 §2.2 above). `All` reuses the legacy `'on'` token,
so the adoption is migration-free and downgrade-safe.

**Since-version convention:**

Every registry entry carries a `'since'` field (`'X.Y.Z'` pattern). It records the first
package release that introduced the key to `config.xml`. For legacy keys that pre-date the
registry, the earliest still-shipped release is the baseline (`'1.0.0'` for original-era keys,
`'2.0.0'` for Python-mode era, `'3.x.y'` for ADR additions). Required format verified by
`RollbackContractTest::testSinceVersionFollowsVersionPattern`.

**Off-VM downgrade gate:**

`tests/smoke/test_upgrade_config_stability.py::test_pkg_downgrade_preserves_config_values`
carries the `repo` marker (deselected from `-m smoke`). Install HIGHER build → write config →
downgrade to LOWER build via `pkg delete` + reinstall → assert the stored config values are
preserved (sane reads, behaviour intact) AND the DNSBL probe still returns VIP. Skips cleanly
when `SMOKE_PKG`/`repo_vm` is absent.

**Foreign-key exclusion list (use `config_*_path` directly — NOT via `PfbConfig`):**

The following `installedpackages/pfblockerng*` paths are **not** registered in `pfb_cfg_registry()`
and stay on direct `config_*_path`. The enforcement sniff does NOT flag them (they are not in the
registered path set). Each annotation is committed in the relevant source file.

| Section / Key | Reason |
| --- | --- |
| `pfblockerngipsettings/config/0/v4suppression` | Foreign section — not in registry |
| `pfblockerngdnsbl/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockerngdnsbl/config/{row}/logging` | Dynamic per-row key, not in registry |
| `pfblockernglistsv4/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockernglistsv6/config/{row}/custom` | Dynamic per-row key, not in registry |
| `pfblockerngdnsbl` (section-level) | Dynamic per-feed list section |
| `pfblockernglistsv4` / `pfblockernglistsv6` (section-level) | Dynamic per-feed list sections |
| `pfblockerngsync/config/0/row/*` | Dynamic XMLRPC row blob, not in registry |
| `pfblockerngglobal/widget-*` | Dashboard widget keys, not in registry |
| `pfblockerngblacklist/*` | Entire section is foreign (not in registry) |
| `pfblockerngglobal/feed_*` + `feed_alt_*` | Dynamic alias-name keys, not in registry |
| `pfblockerngglobal` (section-level) | Dynamic feed-key section |
| `pfblockerng_wizard/*` | Wizard temp section, entirely foreign |
| `installedpackages` (bulk blob) | Bulk wizard init write, foreign structure |
| `pfblockerngreputation/config/0` | Static display section, no registered keys |
| `pfblockerng{continent}/config/0` | Dynamic per-continent structure |
| `pfblockerngdnsblsettings/config/0/dnsbl_webpage` | Out-of-scope key (ADR-29 §2.5); the registered key is `dnsblwebpage` |
| `pfblockerngdnsbl` / `pfblockernglistsv4/v6` (section-level reads) | Dynamic list sections |
| `aliases/alias`, `filter/rule`, `system/*`, `interfaces`, `unbound/*` | pfSense core sections |

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
   must carry UI tests (ADR-14; see "Smoke tests" / "Web-UI tiers" below): **Tier A
   (`ui_render`) is always required.** **Tier B (`ui_e2e`/`ui_browser`) is highly encouraged,
   and REQUIRED IFF the change produces behaviour or visual changes that can be observed *only*
   in Tier B** (i.e. not already caught by Tier A).
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

**PHPCS — three targeted sniffs** (in `tests/phpcs/PfBlockerNG/`), all wired via `phpcs.xml.dist`,
each with its own scope:

- **PFBL-01 `RequirePfbFilter`** (`PfBlockerNG.Validation.RequirePfbFilter`, scoped to
  `pfblockerng.inc` only): inside an **in-scope (allow-listed) function** — the
  ADR-06/07/10/13 input-handling surfaces — no `exec`-family call, `json_encode` manifest
  write, or dynamic filesystem-path build may appear **without a preceding semantic-validation
  call** (`pfb_filter()` / `pfb_sanitise_feed_header()` / `sanitize_ipaddr()`) in the same
  scope — the *semantic* layer `escapeshellarg()` can't provide (both required). Scope is an
  explicit allow-list (the `scopeFunctions` property); add a function name there when a new
  in-scope surface lands. Behaviour pinned by `tests/php/RequirePfbFilterSniffTest.php`.

- **ADR-28 `UppercaseBooleanLiteral`** (`PfBlockerNG.CodeStyle.UppercaseBooleanLiteral`,
  scoped to **all `src/` PHP** — all `.inc` files + `www/`): flags any `true`, `false`,
  `True`, `False` (etc.) boolean **value** literal that is not exactly uppercase `TRUE`/`FALSE`.
  Type-declaration positions (`string|false`, `?true`, `: false` return types, param types) are
  **excluded** — PHPCS's tokenizer converts them to `T_STRING` before the sniff fires. Strings
  (`'true'`/`"false"`), identifiers, and `null` are out of scope. Behaviour pinned by
  `tests/php/UppercaseBooleanLiteralSniffTest.php` against `tests/phpcs/fixtures/`.

- **ADR-29 `RequireConfigGateway`** (`PfBlockerNG.Config.RequireConfigGateway`, scoped to
  **all `src/` PHP** except `pfblockerng_extra.inc` and `pfblockerng_migrate.inc`): flags any
  `config_get_path` / `config_set_path` / `config_del_path` call whose first argument is a
  **static string literal** resolving to a **registered** `installedpackages/pfblockerng*` key
  (from `pfb_cfg_registry()`). All registered keys must go through `PfbConfig::read/write/delete`.
  Precise by design — does NOT flag: dynamic paths (`$var` interpolation), non-registered
  (foreign) keys, section-level reads (path ends at the section, no scalar key suffix), or
  pfSense-core sections. `pfblockerng_extra.inc` is excluded (the gateway itself). When adding a
  new registered key to `pfb_cfg_registry()`, also add its full path to the `$registeredPaths`
  property in `tests/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php`. Behaviour
  pinned by `tests/php/RequireConfigGatewaySniffTest.php` against `tests/phpcs/fixtures/`.

Run `vendor/bin/phpcs --standard=phpcs.xml.dist src/` (config from `phpcs.xml.dist`).

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
workflow_dispatch) and asserts pfBlockerNG end-to-end. Non-obvious truths, each costly to
relearn:

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

Update `stubs/pfsense/` when:

- Min CE is bumped — run:

  ```sh
  python scripts/update-pfsense-stubs.py            # newest public source
  python scripts/update-pfsense-stubs.py --version X.Y.Z
  ```

  Downloads pfSense source, emits one stub per module (`util.php`, `interfaces.php`, …) with
  cross-file dedup. Defaults to **2.7.2** (`STUB_SOURCE_VERSION`): the public mirror is frozen
  there (no `RELENG_2_8_0`) and signatures are stable 2.7→2.8, all PHPStan level 0 needs (symbol
  existence). Regenerate from a real 2.8 checkout if/when available.
- pfBlockerNG calls a new un-stubbed pfSense function — add it to the right `stubs/pfsense/`
  file manually.
- `globals.php` is **always** hand-maintained (array shapes can't be auto-derived);
  `logging.php` + `supplemental.php` likewise never regenerated (`supplemental.php` holds CE-2.8
  functions absent from the 2.7.2 source, e.g. `config_read_file`). PHPStan is the gate; prefer
  a real stub over a `phpstan-baseline.neon` suppression.

The **ADR-08 IDN homoglyph analyzer** (inlined in `src/usr/local/pkg/pfblockerng/pfb_unbound.py`,
backing **IDN Blocking → Confusable**) ships **no** Unicode data table: it resolves each code
point's script from the **stdlib `unicodedata.name()`** leading token (`LATIN…`→Latin,
`CJK…`→Han, …), so nothing regenerates on a UCD bump. It reads the runtime stdlib UCD (Python
3.11 ships 14.0.0, 3.12/3.13 15.1.0, 3.14 16.0.0); name tokens are stable across those for the
scripts in scope. The corpus/oracle GOLDEN (`tests/fixtures/adr08_*`) is pinned to UCD 15.1.0
and `tests/test_adr08_*` proves the analyzer agrees with it across versions. It lives **in
`pfb_unbound.py`** (not a sibling module) so it rides the existing chroot copy + `pkg-plist`
entry — no new shipped file, no extra deploy wiring.

When the min CE version changes, also:

1. **Update the supported-version matrix** — edit `supported-versions.json` on the
   **`ci-metadata` orphan branch** via a PR against `ci-metadata`. Single source of truth for
   supported versions + their `(freebsd_version, php_version)` build pair; workflows read it at
   runtime via `scripts/read-version-matrix.sh` + `.github/actions/read-version-matrix/` (see
   `scripts/README.md`). Build + CI: every `ci: true` entry — **CE and Plus** (ADR-24) — gets
   `.pkg` builds **and** live-VM smoke. Plus runs from a **PRIVATE, licensed** GHCR image
   (`pfsense-plus`); its VM identity (NIC MAC + SMBIOS uuid, keying the Netgate Device ID) comes
   from the `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` (+ optional `SMOKE_PLUS_NDI`) secrets —
   **never** the matrix — and the harness redacts it from diagnostics. Adding the entry + letting
   **version-tracker** (`version-tracker.yml`) run (or dispatching it) triggers
   `build-pkg-linux.yml`, `image-refresh.yml` (CE **and** Plus — see step 2), `smoke.yml`
   automatically — **no workflow YAML edit needed**.
2. **Refresh the smoke images** (ADR-04 + ADR-09) — `image-refresh.yml` (`Upgrade pfSense smoke
   images`) is a **CE + Plus matrix fan-out**: a `plan` job reads `ci-metadata`, and each
   `ci:true` variant is refreshed **only when its `upgrade.available` flag is set** (a curated
   per-variant signal that a public pre-release / GA / patch exists). Absent/`false` → that
   variant is skipped, so most days the run is a clean no-op. Each leg runs
   `scripts/image-upgrade.sh --type ce|plus --upgrade-pkgs` (and `--branch <id>` when
   `upgrade.branch` is set, to reach a **pre-release / development** build — the branch is stored
   in pfSense's `system/pkg_repo_conf_path` and applied via `pkg_switch_repo()`): pulls the
   current GHCR tag, conditionally upgrades baked deps, runs `pfSense-upgrade`, then an **alive
   health gate** (≤300 s for webConfigurator HTTP or a live `pfctl` ruleset) and publishes only
   when healthy — fail-closed. GA/patches within a floating tag (2.8.0→2.8.1, both tag `2.8`)
   self-replace that tag (`--force`); a new Major.Minor publishes a new tag. The **Plus** leg
   takes its license/NDI identity from the `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` secrets and
   refuses to boot on mismatch. A non-blocking post-publish smoke runs per variant on a discarded
   overlay (informational; authoritative validation is the fan-out, step 3; the Plus post-smoke
   skips cleanly if the Plus secrets are absent). Manual seed via `scripts/image-publish.sh`
   remains the fallback when the gate fails (and for the initial Plus image seed). To enable an
   upgrade, set the entry's `upgrade` block in `ci-metadata` (`{available, branch, target, from}`;
   `from` defaults to the entry's own floating tag = self-replace). See
   `.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`. (ADR-09 supersedes ADR-04 §2's "re-baseline on
   a major jump": `image-refresh.yml` handles all jumps via upgrade-in-place; a fresh re-seed is
   triggered only by a gate failure. Reconciling the ADR-04 §2 text is a tracked follow-up.)
3. **Run the smoke fan-out** — dispatch `smoke.yml` (no inputs; reads the CI matrix).
   Runs the ADR-04 suite against **all** `ci: true` entries — **CE and Plus** (ADR-24) — in
   parallel (`fail-fast: false`); the `all-smoke-passed` AND-gate fails if **any** leg fails.
   version-tracker triggers it daily; dispatch manually to verify a new image.

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
Pages** — a **derived index** (no stateful store): each deploy enumerates **all** Releases,
downloads their `.pkg`, buckets by ABI, regenerates the catalog per `<ABI>/`, and deploys to
`pfblockerng.github.io/pkg/${ABI}` (NONE-signed, TLS-anchored; the `${ABI}` conf auto-follows an
OS upgrade). Cross-repo selection is keyed on repo **`priority:`** (it **dominates version** —
Phase-1 live finding), so our above-Netgate `priority: 100` makes `pkg install`/`upgrade` and the
stock GUI **Install** pull our build. GUI discovery + the update badge stay Netgate-bound; a GUI
"Updates/Channel" panel is deferred (would touch `src/`).

**Hard rule — the catalog is keyed by *varver* (`ce-2.8` / `plus-26.03`), NOT by `${ABI}`.** (ADR-20
superseded ADR-17's `${ABI}` bucketing described in the paragraph above.) A pfSense `${ABI}`
(`FreeBSD:<major>:<arch>`) is **NOT in 1:1 correspondence** with a pfSense version or its
`php<XY>`/`py3<XY>` build inputs: two versions/editions can share one FreeBSD major — one `${ABI}` —
yet need different builds. Netgate's own conf proves it (it bakes the full `pfSense_plus_v26_03_1`
version in the URL, never the bare ABI). The current matrix being *incidentally* 1:1
(CE→FreeBSD15, Plus→FreeBSD16) is **not** a licence to "simplify" back to an `${ABI}`-keyed conf —
that 1:1 is not guaranteed. **Never make that simplification.** Full rationale + the upgrade-lag
consequence: `docs/misc/architecture-notes.md` → "Self-hosted pkg distribution — ABI is NOT 1:1".

- **Publish pipeline:** the catalog is hosted + deployed by the **separate `pfBlockerNG/pkg`
  repo** (its `.github/workflows/publish.yml`), NOT this repo. Each run it builds the current
  **devel** `.pkg` by running this repo's own `scripts/build-pkg-portable.py` against a checkout
  of the source (a reusable workflow can't be reused cross-repo — it runs in the caller's context
  — so it runs the *script*), folds in **every** Release `.pkg`, regenerates the per-ABI catalog
  with `scripts/build-repo-portable.py`, and deploys to its **own** GitHub Pages via same-repo
  OIDC `actions/deploy-pages` → `pfblockerng.github.io/pkg`. **No deploy key, no cross-repo
  secret** — everything it reads from here is public. Triggers: daily `schedule` +
  `workflow_dispatch`. This repo's `release.yml` `repo-publish` job just fires `gh workflow run
  publish.yml -R pfBlockerNG/pkg` (auth: a GitHub App token via
  `actions/create-github-app-token@v3`, secrets **`PKG_GITHUB_APP_ID`** +
  **`PKG_GITHUB_APP_PRIVATE_KEY`** — `Actions:write` on `pfBlockerNG/pkg` only) so a release
  publishes within seconds; additive + isolated (`needs: [release]`), so its failure never breaks
  `release`/`sync-ports-fork`/`attach-pkgs`. The FreeBSD `pkg repo` fidelity path
  (`scripts/build-repo.sh`) is retained as a script only.
- **Generators + bootstrap:** `scripts/build-repo-portable.py` (primary catalog gen),
  `scripts/build-repo.sh` (fallback + the single `--print-conf` conf template),
  `scripts/add-repo.sh` (client bootstrap — channel is a FLAG: no-arg = release repo, `--nightly`
  = nightly repo; `priority: 100`, `pkg update` + verify). The default writes the shared release
  conf `/usr/local/etc/pkg/repos/pfblockerng.conf` (repo `pfblockerng` carries BOTH stable and
  devel packages, Netgate-style — pick at install time); only `--nightly` writes its own
  `pfblockerng-nightly.conf`. The emitted conf is byte-identical across all three (drift-pinned in
  `tests/test_add_repo_conf.py` + `tests/test_build_repo_portable.py`).
- **Repo smoke flow:** `tests/smoke/test_repo_install.py` carries its **own marker `repo`** (a
  distribution flow, **deselected from `-m smoke`**) — install-from-our-repo (no `-f`), cross-repo
  precedence (both directions vs a `netgate-decoy`), `pkg upgrade` `_1`→`_9`, and the catalog
  accepted from both generators. The ADR-20 **variant topology** (each leg's ABI / PHP / Python /
  catalog, and the opposite-edition guard) is **derived entirely from the version matrix** — never
  hardcoded CE/Plus: `tests/smoke/_matrix.py` (unit-tested off-box by `tests/test_smoke_matrix.py`)
  reads `SMOKE_MATRIX_JSON` (smoke-single.yml injects `read-version-matrix.sh --print-build` at job start,
  egress open), falls back to running that script, and SKIPs the topology cases when neither is
  available. Per-leg `SMOKE_ABI`/`SMOKE_PHP_VERSION`/`SMOKE_PY_FLAVOR` select within it; adding a
  pfSense version needs no edit here. (`scripts/install-from-repo.sh` likewise derives its
  `py3xx-*` deps from the matrix via the box's ABI.) Dispatch: `gh workflow run smoke-single.yml -f
  pytest_marker=repo` (or `repo-install.yml` once it lands on `devel`). The gated
  `test_install_from_live_pages_url` (`SMOKE_REPO_LIVE_URL`) hits the real `pfblockerng.github.io`
  URL — post-merge (a new `workflow_dispatch` workflow is only dispatchable from the default
  branch).

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
reviewing (detectable via its PR check / review comments), wait for it **in parallel** and
handle its security findings the same way — except Snyk posts **no** nitpick or
outside-diff-range comments, so every Snyk finding is an in-diff item to fix or justify-skip.
The **only** exemptions are the dev-only
classes that go straight to `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text, skills
— see "Worktrees"); everything touching `src/`, `tests/`, or CI uses this flow.

**`devel` advances out of band — rebase onto the latest remote before every push.** Parallel
agents' commits replay on top of `devel`, so the tip moves under you. Before **any** commit/push
(to `devel` or a PR branch): `git fetch origin`, rebase onto the latest tip (`git rebase
origin/devel`, or `origin/<pr-base>`), resolve, push (`--force-with-lease` if rewritten). Never
reconcile with a merge commit. Same rule for each follow-up commit on an open PR.

**Rebase onto the latest base BEFORE opening a PR or dispatching CI/smoke on a branch.** CI runs
against your branch tip, so a stale base re-runs bugs the base has *already fixed* — most
painfully a flaky/broken test someone else fixed on `devel` still fails on your stale-based
branch, sending you to chase a "regression" that is not yours (it bit ADR-29: an upstream-block
smoke test was already fixed on `devel`, but the PR branch, cut from an older tip, still carried
the broken copy and failed CI). So the *first* step of opening a PR — and of any
`workflow_dispatch` smoke/fan-out on a feature branch — is `git fetch origin` + `git rebase
origin/devel` (resolve, `--force-with-lease`). Validate against the base you will merge into, not
a stale snapshot; if a freshly-rebased branch still fails, the failure is genuinely yours.

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
