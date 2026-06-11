# CLAUDE.md — pfBlockerNG

## Communication

**Always activate `/caveman` skill at session start.** Terse, no filler, full technical accuracy.

### Work-context marker

While actively working **an ADR, a GitHub issue, or a PR** (open / in progress), begin
every reply with a one-line status marker so the work item stays on-screen. Plain markdown
only — **no ANSI color escapes** (they render as literal `[..m` junk in assistant messages;
only Bash/tool output colorizes, only on a terminal). The emoji is the only cross-device
state signal; ids and title carry no color.

Format (one space after the emoji):

```text
<emoji> ***ID***(***#PR***): ***Title***
```

- **ID**: `ADR-NN` for an ADR, `#NN` for an issue, `#NN` (PR number) for a standalone PR
  with no issue/ADR.
- A **PR belonging to an issue/ADR** keeps that id and appends the PR number beside it —
  `#43(#56)`, `ADR-10(#56)`. Omit `(#PR)` until a PR exists.
- **Emphasis**: ids and title are ***bold+italic*** (`***…***`); separators `( ) :` stay plain.
- **Budget**: the whole marker fits ~28 chars **including the `(#PR)` group** (trailing `…`
  not counted; ~1 char slack for a 2-cell emoji). Trim the **title** with a trailing `…` to
  fit — a marker carrying a PR has a correspondingly shorter title.

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

## Worktrees (mandatory for AI agents)

**Every AI agent (Claude included) MUST do all repository work in its own dedicated git
worktree** — never the primary checkout, never shared with another agent, even when solo.
Reason: concurrent agents on one checkout race on the filesystem, index, `HEAD`, and refs.

**Exception — ADR docs and skills need no PR.** Two dev-only classes never shipped to users
(release archives contain only `src/`) skip the PR stage: **ADR text** (`ADR.md` + the
`/adr-phase` `.txt` prompts under `.ADRs/`) and **skills** (`SKILL.md` under
`.claude/skills/`). Each still uses a worktree, but commits and pushes **directly to
`devel`** (fetch + rebase first). The carve-out is the PR only, and only for those
docs/tooling files; anything touching `src/`, `tests/`, or CI — ADR *implementation*
included — uses the full worktree + rebase-only-PR flow.

- Create at task start, remove when done:

  ```sh
  git worktree add -b <branch> <path> origin/devel   # branch off the latest base
  # … work, commit, push, open the PR from inside <path> …
  git worktree remove <path>                          # run from the PRIMARY checkout
  ```

- Branch off the **current** base (`git fetch` first); a stale-tip worktree needs a rebase
  onto the base before it can land (PRs are rebase-only).
- **Reuse, don't recreate.** A worktree is keyed to its branch/task — if you're already in
  this branch's worktree (e.g. an ADR mid-implementation), work there. `/adr-all` and
  `/adr-phase` reuse the per-ADR `adr/{NN}-{slug}` worktree across all phases; create it
  (off the latest `devel`) only when absent.
- **Name the branch for its work item** — `adr/{NN}-{slug}` / `issue/{NN}-{slug}` (see
  "Branch naming (ADRs and issues)").
- Gotchas: `git worktree remove` fails from *inside* the tree being removed — run from the
  primary checkout. `gh pr merge --delete-branch` can't check out a base another worktree
  holds (it errors on the local post-merge step though the remote merge succeeded) — verify
  the merge landed, then delete the remote branch separately (`git push origin --delete <branch>`).

---

## Investigating the live system (read sources, not proxies)

When debugging real pfSense/FreeBSD behaviour, **verify against the source of truth and the
effective live state — never infer presence/absence from one generated artifact.** A clean
grep of one file is not proof.

- **Follow file inclusions.** *NIX config splits across `include:` directives and `*.d/`
  drop-ins. Grep the whole tree, then follow the chain. Example that bit us: Unbound's
  DNS-Resolver ACLs are **not** in `/var/unbound/unbound.conf` but in the included
  `/var/unbound/access_lists.conf` (with `host_entries.conf`, `domainoverrides.conf`,
  `remotecontrol.conf`); grepping `unbound.conf` alone misses them.
- **Some pfSense services run CHROOTED** — a chrooted process resolves absolute paths
  against its chroot root. **Unbound** → `/var/unbound` (e.g. `pfb_unbound.py` runs there:
  a host-absolute `/var/unbound/pfb_py_raw/x` becomes `/var/unbound/var/unbound/pfb_py_raw/x`
  inside and 404s — use in-chroot paths; files outside like `/usr/local/pkg/...` are
  unreachable). **HAProxy** → `/tmp/haproxy`. A file existing on the host can be unreadable
  purely from the chroot — caused a real DNSBL feed-loading bug (manifest stored
  host-absolute paths the chrooted module couldn't open).
- **Ask the tool for its effective state via its own CLI** (resolves includes, shows what's
  loaded):
  - **pf** → `pfctl` (`-sr` rules, `-sn` NAT, `-sTables`/`-t <t> -T show`, `-ss` states).
  - **Unbound** → `unbound-control` (`get_option <opt>` e.g. `access-control`,
    `list_local_zones`, `status`); `unbound-checkconf` validates.
  - pfSense in general: prefer the CLI/`pfSsh.php` over generated files.
- **Turn on a tool's debug/verbose mode when unsure what it's doing** — which URLs/files it
  hits, cache/304 behaviour. E.g. `pkg -d update` traces the underlying `curl` (catalogue
  `meta.conf`/`data.pkg`, the `If-Modified-Since` → "Simulate an HTTP 304" → "repository is
  up to date" path; local DB under `/var/db/pkg/repos/<repo>/db`); `curl -v` for raw HTTP.
  Gotcha this revealed: pfSense pkg uses the **`pkg+https`** scheme (mirror indirection) —
  `pkg.pfsense.org` doesn't resolve directly (a plain `dig` looks "broken") but pkg resolves
  it to a Netgate mirror (e.g. `pkg00-atx.netgate.com`). This is why the smoke harness keeps
  egress OPEN during `deploy()`/reload — `pkg add` pulls RUN_DEPENDS from that mirror.
- **Confirm what's installed with `pkg`.** Installed: `pkg info` / `pkg info <pkg>` /
  `pkg info -l <pkg>` (files) / `pkg which <path>` (owner). Available to install:
  `pkg search <name>` / `pkg rquery`. The smoke image ships `ldns` (→ `drill`), `bind-tools`
  (→ `dig`/`host`/`nslookup`), `python311`, `unbound`, `php83`, `qemu-guest-agent` — check
  before installing a dep or coding a runtime fallback.
- **`/conf/config.xml` is the source of truth** for pfSense settings; `/var/…` files are
  generated from it. To check whether something is configured, read the relevant
  `config.xml` section (e.g. `<unbound><acls>`) — actually open it, don't assume.
- **"Everything is files" cuts both ways:** read the actual files (diff before/after a
  change) and confirm a set/empty value on the box, not from recollection.

---

## Resolving pfSense-provided PHP functions (read the real upstream source)

When a pfSense-provided PHP function is missing, ambiguous, or possibly implicated in a bug
— and isn't stubbed yet — **do NOT guess or assume a workaround.** The real implementation
is open source: <https://github.com/pfsense/pfSense>.

Behaviour can differ across releases, so check the function in the **full source trees at
each relevant ref**:

1. **Minimum supported CE** — youngest commit ≤ the launch date of our min CE (currently **2.8.0**).
2. **Each CE release since the oldest supported** — youngest commit ≤ its launch date.
3. **Each pfSense Plus release since our oldest supported CE** — youngest commit ≤ its launch date.
4. **`master`** — current tip.

Resolve refs at investigation time (don't hardcode hashes): find the release date, take the
youngest commit at/before it (`git log --before="<date>" -1 <branch>`, or the GitHub commits
view filtered by date). The public mirror may lack release branches/tags (no `RELENG_2_8_0`),
so dated commits are the reliable handle.

**Always prefer stubbing the real function (from its actual upstream source) over an
exception** (a `phpstan-baseline.neon` suppression, an `undefinedFunctions` entry, or a code
workaround) — stubs encode reality and keep PHPStan/Intelephense honest. This is the by-hand
counterpart to the bulk generator under "Updating documentation".

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
├── phpcs.xml.dist         # PHPCS config (PFBL-01 RequirePfbFilter sniff over pfblockerng.inc)
├── composer.json          # PHP dev deps: phpstan + phpunit + php_codesniffer
└── README.md
```

`tests/` holds the Python suite (pytest), `tests/php/` (PHPUnit for the pure/extractable PHP
helpers — bootstrap loads the real `pfblockerng.inc` off-appliance via include shims +
pfSense doubles; see `tests/php/README.md`), and `tests/smoke/` (the dispatch-only live-VM
suite, ADR-04, which also holds `tests/smoke/ui/` — the ADR-14 Web-UI tiers
`ui_render`/`ui_e2e`/`ui_browser` reusing the `smoke_vm` fixture + `helpers.py`).
`tests/phpcs/` holds the custom PHP_CodeSniffer standard (the PFBL-01 `RequirePfbFilter`
sniff) plus its `fixtures/` (driven by `tests/php/RequirePfbFilterSniffTest.php`).

Release archives contain only `src/`. Everything else (stubs, scripts, tests, CI,
`pyproject.toml`, `.githooks/`) is dev-only.

---

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath` to
`.githooks`). git can't auto-apply a committed hooks path — cloning must not silently install
hooks — so this opt-in is required.

**Claude: ensure hooks are active before working here.** If `git config core.hooksPath` is
not `.githooks`, run `sh scripts/setup-hooks.sh` once at session start (idempotent).

**Claude: any GitHub Actions workflow that commits code must run `sh scripts/setup-hooks.sh`
after checkout, before its commit/push steps** — so automated commits hit the same checks
(subject to which tools the runner has installed).

- **`.githooks/pre-commit`** runs the fast linters + unit suites, blocking on any failure:
  `ruff check`/`ruff format --check`, `python -m pytest`, `mypy tests/` (the suite is fully
  typed — `tests.*` is `disallow_untyped_defs`; `tests/smoke` excluded), `markdownlint-cli2`,
  `sh -n` + `shellcheck`, `php -l`. Each runs only when its tool is installed (missing =
  reported + skipped; CI is the hard gate); PHPStan/PHPCS/PHPUnit run only when `vendor/bin/`
  has them. Emergency bypass: `git commit --no-verify`.
- **`.githooks/pre-push`** enforces tag naming before pushes reach the remote.

---

## Running tests

```sh
python -m pytest
```

From repo root (`pyproject.toml` sets `testpaths` + `-v`; no `cd` needed). Run after **any**
change to `src/usr/local/pkg/pfblockerng/pfb_unbound.py` or `tests/` — in-loop for fast
feedback. The pre-commit hook re-runs it and CI is final, so no separate manual pre-commit
run is needed.

PHP — the fast PHPUnit suite for the pure/extractable helpers of `pfblockerng.inc` (issue #39):

```sh
composer install      # once — installs phpunit into vendor/
vendor/bin/phpunit     # config in phpunit.xml
```

It loads the **real** `pfblockerng.inc` off-appliance: `tests/php/bootstrap.php` satisfies
the file's `require_once` with empty shims (`tests/php/shims/`) + behavioural doubles
(`tests/php/pfsense_doubles.php`); no production code is moved/modified. The PHPStan stubs in
`stubs/pfsense/` are empty-bodied (symbol existence only) — they can't serve as doubles; add
a faithful/no-op `function_exists()`-guarded double to `pfsense_doubles.php` (+ an empty shim
if it's a required include) when a tested path reaches a new pfSense function. Deep
pfSense-runtime integration stays the live-VM smoke's job (ADR-04). See `tests/php/README.md`.

**DNSBL/ABP pipeline architecture** — ADR-06 (preprocessing → Python), ADR-07 (ABP/EasyList),
ADR-10 (zero-downtime DNSBL swap), ADR-12 (update hooks) — and the per-ADR test/kill-gate map
are summarized in **`docs/misc/architecture-notes.md`**; read it before touching
`pfb_unbound.py`, the manifest boundary, the swap/watcher, or the hooks. Full design lives in
each `.ADRs/ADR_NN_*/`.

**Aggregated "Uber" aliases (ADR-11, IP side — `pfblockerng.inc` + `pfblockerng.sh`).** The
`pfb_agg_types` multi-select (General settings, **opt-in, default none**) builds, per selected
action type, the Native urltable aliases **`pfB_<Type>_Aggregated_v4`/`_v6`** = the deduped,
`iprange`d union of that type's effective set (Deny = post-suppression block set incl. DNSBLIP;
GeoIP folds in by each continent's action — no separate Geo alias). They are **Native (no
firewall rule)** — reference IP-sets only. Built **in-pass, mtime-gated** by the
`pfblockerng.sh aggregate` action via the `pfb_build_aggregate_aliases()` wiring (which loads
each pf table inline **before** the ADR-12 `post` hook). Each is a **wired kernel pf table**
(can be millions of entries for Deny) → enable only what you consume. The never-empty `.lst`
consumer files + the Native aliases are ADR-12's HAProxy input; freshness = a pfBlockerNG-
triggered graceful HAProxy reload, **not** a socket push. Off-box membership pinned in
`tests/php/AggregateMemberListTest.php`; live legs are the ADR-11 §7 maintainer smoke.

---

## Smoke tests (ADR-04 — live pfSense VM) — READ BEFORE TOUCHING `tests/smoke/`

`tests/smoke/` installs the branch `.pkg` on a REAL pfSense CE VM in CI (`smoke.yml`,
workflow_dispatch) and asserts pfBlockerNG end-to-end. These truths are non-obvious and each
cost real debugging — internalise them first:

- **Probe ON-BOX** (`drill @127.0.0.1` over SSH), NOT the runner-side SLIRP hostfwd (the
  WAN-hostfwd DNS path isn't answered in CI). Python-mode DNSBL has **no localhost
  exemption** — a blocked name returns its block shape even from `127.0.0.1`. After
  `reload()` → `wait_unbound_ready`, the **first** DNS response is authoritative — assert it,
  never loop waiting for the expected value.
- **Test domains MUST be `helpers.unique_domain()`** (`uuid-*.com`): never RFC 6761 TLDs
  (`.test`/`.example`/`.invalid`/…) — Unbound's built-in `local-zone`s shadow them
  (NXDOMAIN/NODATA) before DNSBL — and never HSTS-preload names (`pfb_hsts`, default ON,
  forces a would-be VIP block to NULL).
- **Block shapes (python mode):** NOERROR + VIP (`dnsbl_ipv4`) or NULL (`0.0.0.0`/`::`);
  NEVER NXDOMAIN for a feed match (NXDOMAIN is SafeSearch-only). Per-list `logging` selects
  VIP vs NULL and is a **LIST-level** field (`$list['logging']`), not per-row. Compare IPs
  **by value** (`::` == `::0`).
- **Unbound is chrooted at `/var/unbound`** — files its python module reads must be
  chroot-relative (see "Investigating the live system"); a host-absolute path silently fails
  to load.
- **Enable chain:** DNSBL `mode=='enabled'` needs `enable_cb=on` + `pfb_dnsbl=on` + the DNS
  Resolver enabled (`unbound_state`). On `devel`, `dnsbl_mode`/`pfb_py_block` are dead keys
  (python is the only mode); on `main` they're still required.
- **The image bakes only the deps + qemu-guest-agent** — the harness injects the DNSBL VIP
  (`ensure_dnsbl_vip`) and all per-case config; `pkg add` runs offline. The package can now
  auto-create the sinkhole VIP (`pfb_dnsvip_auto`, ADR-13) but defaults **OFF**, so
  `ensure_dnsbl_vip` stays accurate. The setup wizard (ADR-23) also exposes the
  `pfb_dnsvip_auto` toggle, but `ensure_dnsbl_vip` remains the harness fixture since the smoke
  harness does not run the wizard flow. The smoke qcow2 cache is content-keyed by GHCR digest
  (a same-tag re-push invalidates automatically).
- **The branch `.pkg` is built on a plain Linux runner** (`build-pkg-linux.yml` →
  `scripts/build-pkg-portable.py`), NOT a FreeBSD VM: pfBlockerNG is a `NO_BUILD` port, so
  the portable builder reproduces `make package` from the Makefile + pkg-plist. `pkg add`
  checks a dep is PRESENT, not its version, so the portable `.pkg` installs identically on
  the baked-deps image. The real FreeBSD `make package` path (`build-pkg.yml`) is retained as
  a dispatch-only fidelity oracle — not in the smoke gate.
- **Every run uploads a full guest snapshot** (`smoke-diagnostics`: all `/var/log`, `dmesg`,
  `pfctl -sa`, unbound + pfBlockerNG state, `/var/db/pfblockerng`, `/var/db/aliastables`,
  scrubbed `config.xml`). On any failure, read it first.

Full journey, verified response model, and the `SMOKE_STATE_DIFF` instrument:
`.ADRs/ADR_04_VM_Smoke_Tests/RESULTS/`.

The **Web-UI tiers (ADR-14)** under `tests/smoke/ui/` and the **HTTP mock-feed load smoke
(ADR-16 Part C)** in `tests/smoke/test_smoke_feeds.py` — including the sample-fixture table,
`_MockFeedServer` mechanics, the CI wiring (`ui-tests.yml`), and gate status — are documented
in **`docs/misc/architecture-notes.md`**. Operative facts that stay here:

- Tier A `ui_render` is the **PR gate**: GET each page → 200, body free of `Fatal
  error`/`Parse error`/`Warning`/`Notice`/`Uncaught`, a page-specific marker present, AND no
  new on-box `php_error.log` line — **never HTTP 200 alone**. Tiers B `ui_e2e`/`ui_browser`
  are schedule/dispatch-only (non-PR-blocking). Run a tier:
  `python -m pytest tests/smoke/ui -m ui_render --override-ini="addopts="` (`SMOKE_ADMIN_PASSWORD`
  must be set, else the UI fixtures SKIP, never fail).
- Smoke feed fixtures live in `tests/smoke/fixtures/` (inert data — RFC 5737/3849 IPs,
  `uuid-*.com`; never RFC 6761 TLDs or HSTS-preload names). Add one: drop the file there,
  update `tests/smoke/fixtures/README.md`, add a case in `test_smoke_feeds.py` using
  `mock_feeds.feed_url("<name>")`.

---

## Test coverage (mandatory)

When writing tests — **unit, integration, E2E, or smoke** — cover **every branch** of the
behaviour and assert the state **before** a change as well as after. **A test must validate
that the code is correct, not merely execute it:** running the code while asserting nothing
that would *fail* on a regression is coverage theater and is **not acceptable**, even at 100%
line coverage. The test's name/comments state the **intent** (the behaviour pinned), not the
mechanics. All three required:

- **Branch coverage — test every condition, not one side.** When a result depends on a
  toggle/flag/mode/input-class, assert the outcome for **each** value it can take: a boolean
  gets a case **off** *and* a case **on** (plus any third state); every `if`/`switch`/match
  branch and each documented input class gets its own assertion. (In-tree:
  `test_dnsbl_hsts_override_forces_null` paired with `test_dnsbl_hsts_disabled_keeps_vip` —
  HSTS on vs off — proves it's a real branch, not an always-null path.)
- **Assert the before-state in transition tests — no false passes.** A test that flips a
  toggle and asserts the *changed* result MUST first assert the *original*, so green proves
  the flip **caused** the change. If `i=false ⇒ a→x` and `i=true ⇒ a→y`: assert `a→x` at
  `i=false`, **then** set `i=true`, **then** assert `a→y` — never just the final state.
  Extends to any lifecycle: a "blocked after listing" test first asserts the domain *resolved*
  before listing (and resolves again after unblock) — see the `tests/smoke` DNSBL lock/unlock
  cases.
- **Specify complex behaviour BDD-style; keep trivial tests trivial.** A util / small rule /
  simple mapping needs only a plain, intent-named assertion. Non-trivial behaviour (state
  transitions, precedence, multi-step flows — the DNSBL/ABP decision logic, the decision
  cache, smoke journeys) gets a **Scenario / Background + Given–When–Then** spec next to the
  test, the body split into explicit **Given** (arrange) / **When** (act) / **Then** (assert).

---

## Linting

Run the linters below **while working**, for fast feedback. Enforcement is layered: the
`.githooks/pre-commit` hook blocks any commit that fails them, and CI is the final authority
(it runs them even when the local hook is inactive or a tool is missing).

### Python

```sh
ruff check .        # lint
ruff check . --fix  # lint + autofix
ruff format .       # format
```

Config in `pyproject.toml`. Target Python 3.11+ (pfSense CE 2.8 / FreeBSD 15). Ruff is
canonical; `.flake8` exists only so Flake8 users (e.g. the VS Code extension) get the same
120-column limit + ignore set (Flake8 can't read `pyproject.toml` — without it, it falls back
to 79 columns and whitespace checks Ruff delegates to `ruff format`). Keep them in sync.

### PHP

Intelephense in VS Code (`.inc` = PHP via `files.associations`). `stubs/pfsense/` resolves
pfSense-provided functions — if one is flagged undefined, add it to the right stub file rather
than expanding `undefinedFunctions` in `.vscode/settings.json`. PHPStan + PHPUnit + PHPCS are
the PHP gates (all pulled by `composer install`, enforced in CI `test.yml` + the pre-commit
hook). The `stubs/pfsense/` stubs are for PHPStan, NOT runtime doubles (those live in
`tests/php/pfsense_doubles.php`).

**PHPCS — the PFBL-01 RequirePfbFilter sniff.** A single custom PHP_CodeSniffer rule
(`PfBlockerNG.Validation.RequirePfbFilter`, in `tests/phpcs/PfBlockerNG/`) mechanically enforces
PFBL-01: inside an **in-scope (allow-listed) function** — the ADR-06/07/10/13 input-handling
surfaces — no `exec`-family call, `json_encode` manifest write, or dynamic filesystem-path
build may appear **without a preceding semantic-validation call** (`pfb_filter()` /
`pfb_sanitise_feed_header()` / `sanitize_ipaddr()`) in the same function scope. It enforces the
*semantic* layer `escapeshellarg()` cannot — both layers are required. Scope is an explicit
allow-list (the `scopeFunctions` property), so the ADR's "legacy code is out of scope"
carve-out is encoded by **not listing** a function, never a blanket scan; add a function name
there when a new in-scope surface lands. Run it: `vendor/bin/phpcs` (config auto-discovered
from `phpcs.xml.dist`). The sniff's own behaviour — fires on each sink class, silent when a
validator precedes the sink or the function is out of scope — is pinned by
`tests/php/RequirePfbFilterSniffTest.php` against fixtures in `tests/phpcs/fixtures/`.

### Shell

ShellCheck (VS Code extension). All scripts use `#!/bin/sh` (POSIX sh, not bash).
`.shellcheckrc` suppresses SC1091 (pfSense sources unreachable locally) + SC2154
(rc(8)-injected vars); don't suppress others without justification.

**URL-encoding check (`scripts/check_url_encoding.py`)** — a preventative gate forbidding
naked shell-var interpolation into an HTTP-client (`curl`/`wget`/`fetch`) URL query (e.g.
`curl "http://h/cb?ip=$VAR"`): a space-separated or empty value (such as
`PFB_CHANGED_IP_ALIASES`) re-tokenises the command and the param collapses. Fix: let the
value ride its own option so curl percent-encodes it — `curl --data-urlencode "ip=$VAR"
http://h/cb`. No-arg run scans every tracked `*.sh` (the `src/**` hook/pre-script surface +
dev `scripts`/`tests` shell) AND the `sh`/`bash`/`shell`-tagged fenced blocks in tracked
Markdown; static params (`?fixed=1`) and base/host/path interpolation are out of scope.
Enforced in pre-commit + CI; detection in `find_violations()`, unit-tested in
`tests/test_url_encoding_check.py`.

### Markdown

markdownlint (VS Code "markdownlint" extension + CLI). From repo root:

```sh
npx markdownlint-cli2          # lint
npx markdownlint-cli2 --fix    # lint + autofix
```

Produce compliant output directly: a blank line around every heading/list/fence; a language
on every fence (`text` for plain output/trees/ASCII); a single trailing newline. Long lines +
compact (unaligned) tables are fine (`MD013`/`MD060` disabled). Rules in `.markdownlint.jsonc`
(extension + CLI); globs/ignores in `.markdownlint-cli2.jsonc`. Disabled to fit the docs
style: `MD013` (line length), `MD060` (table alignment), `MD036` (ADR
`**Positive**`/`**Negative**` sub-headers), `MD041` (frontmatter-led files don't open with an
H1); `MD024` is `siblings_only`; `**/TRANSCRIPT.md` ignored. Keep the rationale in
`.markdownlint.jsonc` in sync. Clean lint (`0 error(s)`) enforced by pre-commit + CI.

---

## Code standards

### Naming — follow the established pattern

**A new variable, web-page element `id`, dict key, or config key follows the conventions
already in that file (or similar files) — match the surrounding pattern, don't coin an ad-hoc
name.** Spans the whole stack (PHP, Python, shell, JS, `www/`, `config.xml` keys). E.g. when
sibling identifiers are `pfB_*`, a wizard "don't show again" flag is **`pfB_wizard_disable`**,
not `donotshowthisagain`. Check neighbours (other fields on the page, other keys in the dict,
other settings in the section) for prefix, casing, separators, word order. An off-pattern name
is a smell even when it works.

### PHP

- Indent: **tabs** (`.editorconfig`)
- Target PHP 8.3 (pfSense CE 2.8)
- pfSense-injected functions (`util.inc`, `config.lib.inc`, …) are declared in
  `stubs/pfsense/` — don't `require_once` pfSense files in tests
- No `die()`/`exit()` in library code; return or throw
- **Web UI help text** (field/page descriptions, mostly in `www/`): brief yet clear — match
  the wording, length, and style of neighbouring help texts; don't out-prose them

### Python

- Indent: **4 spaces**
- Target Python 3.11+; `from __future__ import annotations` for forward refs
- Type-hint new functions; leave existing untyped code alone unless touching it
- No bare `except:` — `except Exception` minimum
- `pfb_unbound.py` runs in Unbound's Python loader — stdlib only, no external deps
- Unbound injects API symbols (`log_info`, `RR_TYPE_*`, `DNSMessage`, …) as runtime globals;
  `pfb_unbound.py` uses them as bare names. Declared once in `stubs/python/unboundmodule.py`
  (Pylance/mypy resolve via the `TYPE_CHECKING` import; the suite copies them onto `builtins`,
  see `tests/conftest.py`). Add a new injected symbol there.

### Shell

- POSIX sh only (`#!/bin/sh`), no bash-isms (`[[`, arrays, `$RANDOM`, etc.)
- Quote all expansions: `"$var"`, `"${var}"`
- Absolute paths only for **add-on/privileged** binaries (`iprange`/`grepcidr`/`mmdblookup`/
  `jq`/`pfctl`) — as `path*` vars, see `pfblockerng.sh`. Base utilities (`grep`/`sed`/`awk`/
  `sort`/`find`/`cut`…) may be **bare** (the code does so pervasively; these run under pfSense's
  controlled PATH). Don't rely on `$PATH` outside base.
- AWS region pre-scripts live in `list_scripts/`: 25 thin `ip_pre_AWS_*.sh` wrappers
  (UI-selectable) pass a `jq` region filter to the shared `list_scripts/aws_region_prefixes.sh`
  — change that one, not 25.

---

## Updating documentation

**Documentation-only changes skip CI.** A commit/PR touching *only* Markdown (`**/*.md`,
including `CLAUDE.md`/`README.md`) or `docs/` is excluded from `test.yml` via `paths-ignore`.
Touch any code (anything outside those paths) and the full suite runs again. The pre-commit
hook still lints Markdown. This is a CI carve-out only — such changes still go through a
worktree + the normal PR/landing flow.

Update `README.md` when: workflow steps change (test/deploy/release commands); min supported
pfSense CE changes; new developer tooling is added.

Update `stubs/pfsense/` when:

- Min CE is bumped — run:

  ```sh
  python scripts/update-pfsense-stubs.py            # newest public source
  python scripts/update-pfsense-stubs.py --version X.Y.Z
  ```

  Downloads pfSense source, emits one stub per module (`util.php`, `interfaces.php`, … ) with
  cross-file dedup. Defaults to **2.7.2** (`STUB_SOURCE_VERSION`): the public mirror is frozen
  there (no `RELENG_2_8_0`) and signatures are stable 2.7→2.8, all PHPStan level 0 needs
  (symbol existence). Regenerate from a real 2.8 checkout if/when available.
- pfBlockerNG calls a new un-stubbed pfSense function — add it to the right `stubs/pfsense/`
  file manually.
- `globals.php` is **always** hand-maintained (array shapes can't be auto-derived);
  `logging.php` + `supplemental.php` likewise never regenerated (`supplemental.php` holds
  CE-2.8 functions absent from the 2.7.2 source, e.g. `config_read_file`). PHPStan is the
  gate: prefer a real stub over a `phpstan-baseline.neon` suppression.

The **ADR-08 IDN homoglyph analyzer** (inlined in
`src/usr/local/pkg/pfblockerng/pfb_unbound.py`, backing **IDN Blocking → Confusable**) ships
**no** Unicode data table: it resolves each code point's script from the **stdlib
`unicodedata.name()`** leading token (`LATIN…`→Latin, `CJK…`→Han, …), so there is nothing to
regenerate on a UCD bump. It reads the runtime stdlib UCD (Python 3.11 ships 14.0.0, 3.12/3.13
15.1.0, 3.14 16.0.0); the name tokens are stable across those for the established scripts in
scope. The corpus/oracle GOLDEN (`tests/fixtures/adr08_*`) is pinned to UCD 15.1.0 and the
`tests/test_adr08_*` suite proves the analyzer agrees with it across versions. It lives **in
`pfb_unbound.py`** (not a sibling module) precisely so it rides the existing chroot copy +
`pkg-plist` entry — no new shipped file, no extra deploy wiring.

When the min CE version changes, also:

1. **Update the supported-version matrix** — edit `supported-versions.json` on the
   **`ci-metadata` orphan branch** via a PR against `ci-metadata`. Single source of truth for
   supported versions + their `(freebsd_version, php_version)` build pair; workflows read it
   at runtime via `scripts/read-version-matrix.sh` + `.github/actions/read-version-matrix/`
   (see `scripts/README.md`). Build vs CI split: CE gets `.pkg` builds + live-VM smoke
   (`ci: true`); Plus gets builds only (`ci: false`, no licensed CI image). Adding the entry +
   letting **version-tracker** (`version-tracker.yml`) run (or dispatching it) triggers
   `build-pkg-linux.yml`, `image-refresh.yml`, `smoke-fanout.yml` automatically — **no
   workflow YAML edit needed**.
2. **Refresh the CE smoke image** (ADR-04 + ADR-09) — dispatch `image-refresh.yml` with
   `pfsense_version` + `freebsd_version` from the new entry. It runs
   `scripts/image-upgrade.sh --upgrade-pkgs`: pulls the current GHCR tag, conditionally
   upgrades baked deps (`pkg upgrade -n` dry-run gate; `pkg upgrade -y` + reboot only if
   pending), runs `pfSense-upgrade` (any bump incl. major), then an **alive health gate**
   (polls ≤300 s for the webConfigurator to answer HTTP or `pfctl` to show a live ruleset) and
   publishes the tag only when healthy — fail-closed. A non-blocking post-publish smoke
   (`continue-on-error`) runs on a discarded overlay (informational only — authoritative
   validation is the fan-out, step 3). Manual seed via `scripts/image-publish.sh` is the
   fallback when the gate fails. See `.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`. (ADR-09
   supersedes ADR-04 §2's "re-baseline on a major jump": `image-refresh.yml` handles all jumps
   via upgrade-in-place; a fresh re-seed is triggered only by a gate failure. Reconciling the
   ADR-04 §2 text is a tracked follow-up.)
3. **Run the smoke fan-out** — dispatch `smoke-fanout.yml` (no inputs; it reads the CI
   matrix). Runs the ADR-04 suite against **all** `ci: true` CE images in parallel
   (`fail-fast: false`); the `all-smoke-passed` AND-gate fails if any CE leg fails. Never
   Plus. version-tracker triggers it daily; dispatch manually to verify a new image.

---

## Branches and releases

| Branch | Channel | Ships to |
| ------ | ------- | -------- |
| `main` | Stable  | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

New features land in `devel`. Pushing a `vX.Y.Z` tag triggers CI: tests → GitHub Release → PR
on `pfsense/FreeBSD-ports`. Tags from `devel` become pre-releases; from `main`, stable releases.

### Self-hosted `pkg` repository (ADR-17)

Beyond the Netgate ports channel we publish a **self-hosted FreeBSD `pkg` repository on
GitHub Pages** — a **derived index** (no stateful store): each deploy enumerates **all**
Releases, downloads their `.pkg`, buckets by ABI, regenerates the catalog per `<ABI>/`, and
deploys the tree to `pfblockerng.github.io/pkg/${ABI}` (NONE-signed, TLS-anchored; the `${ABI}`
conf auto-follows an OS upgrade). Cross-repo selection is keyed on repo **`priority:`** (it
**dominates version** — Phase-1 live finding), so our above-Netgate `priority: 100` makes
`pkg install`/`upgrade` and the stock GUI **Install** pull our build. GUI discovery + the
update badge stay Netgate-bound; a GUI "Updates/Channel" panel is deferred (would touch
`src/`).

- **Publish pipeline:** the catalog is hosted + deployed by the **separate
  `pfBlockerNG/pkg` repo** (its `.github/workflows/publish.yml`), NOT this repo. Each run
  it builds the current **devel** `.pkg` by running this repo's own
  `scripts/build-pkg-portable.py` against a checkout of the source (a reusable workflow
  can't be reused cross-repo — it runs in the caller's context — so it runs the *script*),
  folds in **every** Release `.pkg`, regenerates the per-ABI catalog with
  `scripts/build-repo-portable.py`, and deploys to its **own** GitHub Pages via same-repo
  OIDC `actions/deploy-pages` → served at `pfblockerng.github.io/pkg`. **No deploy key, no
  cross-repo secret** — everything it reads from here is public. Triggers: a daily
  `schedule` + `workflow_dispatch`. This repo's `release.yml` `repo-publish` job just fires
  `gh workflow run publish.yml -R pfBlockerNG/pkg` (auth: a GitHub App token via
  `actions/create-github-app-token@v3`, secrets **`PKG_GITHUB_APP_ID`** +
  **`PKG_GITHUB_APP_PRIVATE_KEY`** — `Actions:write` on `pfBlockerNG/pkg` only) so a release publishes
  within seconds; additive + isolated (only `needs: [release]`), so its failure never
  breaks `release`/`ports-pr`/`attach-pkgs`. The FreeBSD `pkg repo` fidelity path
  (`scripts/build-repo.sh`) is retained as a script only.
- **Generators + bootstrap:** `scripts/build-repo-portable.py` (primary catalog gen),
  `scripts/build-repo.sh` (fallback + the single `--print-conf` conf template),
  `scripts/add-repo.sh` (client bootstrap — `devel|stable` channel arg, `priority: 100`,
  writes `/usr/local/etc/pkg/repos/pfblockerng-<channel>.conf`, `pkg update` + verify). The
  emitted conf is byte-identical across all three (drift-pinned in
  `tests/test_add_repo_conf.py` + `tests/test_build_repo_portable.py`).
- **Repo smoke flow:** `tests/smoke/test_repo_install.py` carries its **own marker `repo`**
  (a distribution flow, **deselected from `-m smoke`**) — install-from-our-repo (no `-f`),
  cross-repo precedence (both directions vs a `netgate-decoy`), `pkg upgrade` `_1`→`_9`, and
  the catalog accepted from both generators. Dispatch:
  `gh workflow run smoke.yml -f pytest_marker=repo` (or `repo-install.yml` once it lands on
  `devel`). The gated `test_install_from_live_pages_url` (`SMOKE_REPO_LIVE_URL`) hits the
  real `pfblockerng.github.io` URL — post-merge (a new `workflow_dispatch` workflow is only
  dispatchable from the default branch).

**Merge PRs by rebase only** — `gh pr merge <N> --rebase` (or GitHub's "Rebase and merge");
never a merge commit, never squash. History across `main` ← `devel` stays strictly linear
(`main` always an ancestor of `devel`, no merge commits), so promotion up the chain — and
landing any PR — is a rebase/replay. Rebase a behind-base branch onto its base first for a
clean fast-forward.

**Default landing flow — `/pr-merge-flow N`.** After completing any GitHub issue, ADR, or
code change in general, land its PR with **`/pr-merge-flow N`** — roughly
`/pr-comments N --wait-for=coderabbitai && /pr-merge N`: get the review feedback, validate +
apply its findings and reply, then (only if that completes cleanly) rebase-merge once the
real CI is green. The review source adapts: it waits on **CodeRabbit** when that bot is
active on the repo (it is — installed on the `pfBlockerNG` org), else falls back to a **Claude
Sonnet sub-agent reviewer**. The **only** exemptions are the dev-only
classes that go straight to `devel` with no PR (documentation-only, `CLAUDE.md`, ADR text,
skills — see "Worktrees"); everything touching `src/`, `tests/`, or CI uses this flow.

**`devel` advances out of band — rebase onto the latest remote before every push.** Parallel
agents' commits replay on top of `devel`, so the tip moves under you. Before **any**
commit/push (to `devel` or a PR branch): `git fetch origin`, rebase onto the latest tip
(`git rebase origin/devel`, or `origin/<pr-base>` for a PR), resolve, push
(`--force-with-lease` if rewritten). New work always replays after what's on the remote; never
reconcile with a merge commit. Same rule for each follow-up commit on an open PR.

**Clean the diff before you push/PR.** Before the first push (and before each follow-up commit),
diff the branch against its base (`git diff origin/devel...HEAD`) and reduce it to **only what
the change requires** — the substantive edit plus the comments, tests, and docs that move *with*
it. Strip the debris of getting there: temporary debug logging (`log_info`/`print`/`DBG*`
probes), dead or commented-out experiments, code churned then reverted, an introduced-then-
unused symbol, gratuitous reformatting/whitespace of untouched lines, and scratch files. A
reviewer (human, CodeRabbit, or a stand-in) — and the permanent git history — should see the
minimal, intentional change, not the trial-and-error path you took to find it. If a probe was
genuinely useful, either delete it or make it a deliberate, justified part of the change (not a
leftover). The cheapest time to do this is **before** the PR exists.

### Branch naming (ADRs and issues)

A branch tracking an **ADR** or a **GitHub issue** carries the item's **number then a slug of
its title**, so it's self-describing:

- **ADR:** `adr/{NN}-{slug}`
- **GitHub issue:** `issue/{NN}-{slug}`

`{slug}` derives from the title (the ADR `{Name}`/`ADR.md` H1; the issue title) by this
**mandatory** sanitiser (defends against garbage/malicious input + keeps the ref legal):

1. **Lowercase.**
2. **Strip emojis + every non-ASCII char**, then drop anything not `[a-z0-9]`.
3. **Collapse** each removed/non-alphanumeric run to a single `-`; **trim** leading/trailing `-`.
4. **Truncate ≤30 chars** at a `-` boundary (never a trailing `-`); don't go far past 30.
5. Empty slug → **omit it** (bare `adr/{NN}` / `issue/{NN}`).

Output is `[a-z0-9-]` only — no spaces, no `~ ^ : ? * [ \ .. @{`, no leading `-`, no `.lock`
suffix — always a legal ref. **On collision** with an *unrelated* branch, append `-{epoch}`
(epoch seconds). An ADR reusing its own `adr/{NN}-*` branch across phases is reuse, not a
collision — don't re-suffix.

Examples: `ADR_10_Zero_Downtime_DNSBL` → `adr/10-zero-downtime-dnsbl`; issue #43 "TLD-Allow
KeyError on …" → `issue/43-tld-allow-keyerror-on`.

---

## GitHub issues

**Read the whole issue before working it** — title, description, AND every comment
(`gh issue view <N> --comments`). Later comments routinely revise/narrow/downgrade/invalidate
the original (issue #25: a follow-up downgraded a claimed crash to a defensive-consistency
cleanup and corrected the fix). Never act on the opening text alone.

**Branch for the fix:** `issue/{NN}-{slug}` per the slug rule above.

### Labels (lifecycle)

Keep an issue's labels in sync with its stage (`gh issue edit <N> --add-label/--remove-label`;
labels already exist — see `gh label list`):

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
