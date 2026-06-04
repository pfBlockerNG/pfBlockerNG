# CLAUDE.md — pfBlockerNG

## Communication

**Always activate `/caveman` skill at session start.** Terse, no filler, full technical accuracy.

---

## Worktrees (mandatory for AI agents)

**Every AI agent (Claude included) MUST do all repository work in its own
dedicated git worktree — never directly in the primary checkout, and never
sharing a worktree with another agent.** This applies even when only one agent is
active. Reason: multiple agents operating on the same checkout race on the
filesystem, the index, `HEAD`, and branch/ref state; isolated worktrees prevent
those conflicts.

**Exception — ADR docs and skills need no PR.** Two dev-only classes that never ship
to users (release archives contain only `src/`) skip the PR stage: **ADR text** (the
`ADR.md` plus the `/adr-phase` prompt `.txt` files under `.ADRs/`) and **skills** (the
`SKILL.md` files under `.claude/skills/`). Each still goes through a **worktree** (the
worktree rule always holds), but needs **no PR** — commit it there and push **directly
to `devel`** (fetch + rebase first, as always). The carve-out is the PR only, and only
for those *docs/tooling* files; any change that touches `src/`, `tests/`, or CI — ADR
*implementation* included — still uses the full worktree + rebase-only-PR flow.

- Create one at the start of a task and remove it when done:

  ```sh
  git worktree add -b <branch> <path> origin/devel   # branch off the latest base
  # … work, commit, push, open the PR from inside <path> …
  git worktree remove <path>                          # run from the PRIMARY checkout
  ```

- Branch off the **current** base (`git fetch` first); a worktree created off a
  stale tip needs a rebase onto the base before it can land (PRs are
  rebase-only — see "Branches and releases").
- The primary checkout stays free for the human; each agent gets its own tree.
- **Reuse, don't recreate.** A worktree is keyed to its branch/task: if you are already
  in the worktree for this branch — e.g. an ADR's `adr/NN` worktree mid-implementation —
  work there, don't spin up a second one. `/adr-all` and `/adr-phase` **reuse the per-ADR
  `adr/NN` worktree across all phases**; create it (off the latest `devel`) only when it
  doesn't already exist.
- Gotchas (both hit in practice): `git worktree remove` fails when run from
  *inside* the tree being removed — run it from the primary checkout. And
  `gh pr merge --delete-branch` can't check out a base branch that another
  worktree already holds (it errors on the local post-merge step even though the
  remote merge succeeded) — verify the merge landed, then delete the remote
  branch separately (`git push origin --delete <branch>`).

---

## Investigating the live system (be thorough — read sources, not proxies)

When debugging real pfSense/FreeBSD behaviour, **verify against the source of truth
and the effective live state — never infer presence/absence from a single generated
artifact.** A clean grep of one file is not proof. Specifically:

- **Follow file inclusions.** *NIX config is routinely split across `include:`
  directives and `*.d/` drop-in directories. Grep the whole tree, then follow the
  chain — don't grep one top-level file and conclude. Example that bit us: Unbound's
  DNS-Resolver ACLs are **not** in `/var/unbound/unbound.conf`; they're in the
  included `/var/unbound/access_lists.conf` (alongside `host_entries.conf`,
  `domainoverrides.conf`, `remotecontrol.conf`). `grep -rn … /var/unbound/` +
  `grep include /var/unbound/unbound.conf` finds them; grepping `unbound.conf` alone
  silently misses them.
- **Some pfSense services run CHROOTED — account for it when they read files.** A
  chrooted process resolves absolute paths against its chroot root, not `/`.
  **Unbound** is chrooted at **`/var/unbound`** (e.g. `pfb_unbound.py` runs there:
  a host-absolute `/var/unbound/pfb_py_raw/x` becomes `/var/unbound/var/unbound/pfb_py_raw/x`
  inside and 404s — reference such files by their in-chroot path, or relative to the
  chroot root; files outside the chroot like `/usr/local/pkg/...` are simply
  unreachable unless mounted/copied in). **HAProxy** is chrooted at **`/tmp/haproxy`**.
  A file that plainly exists on the host can be unreadable by the service purely
  because of the chroot — this caused a real DNSBL feed-loading bug (manifest stored
  host-absolute paths the chrooted module couldn't open).
- **Ask the tool for its effective state via its own CLI.** It resolves includes and
  shows what's actually loaded, not what a file says:
  - **pf** → `pfctl` (`-sr` rules, `-sn` NAT, `-sTables`/`-t <t> -T show` tables,
    `-ss` states).
  - **Unbound** → `unbound-control` (`get_option <opt>` e.g. `access-control`,
    `list_local_zones`, `status`); `unbound-checkconf` to validate.
  - pfSense services in general: prefer the CLI/`pfSsh.php` over reading generated files.
- **Turn on a tool's debug/verbose mode when unsure what it's actually doing** —
  which URLs/hosts it hits, which files it reads/writes, cache/304 behaviour —
  instead of guessing. E.g. `pkg -d update` traces the underlying `curl` (repo
  catalogue `meta.conf`/`data.pkg`, the `If-Modified-Since` → "Simulate an HTTP
  304" → "repository is up to date" path; local catalogue DB under
  `/var/db/pkg/repos/<repo>/db`); `curl -v` for raw HTTP. Non-obvious gotcha this
  revealed: pfSense's pkg uses the **`pkg+https`** scheme — a *mirror indirection*,
  so `pkg.pfsense.org` does not resolve directly (a plain `dig` looks "broken")
  while pkg resolves it to a Netgate mirror host (e.g. `pkg00-atx.netgate.com`)
  and fetches fine. This is why the smoke harness keeps egress OPEN during
  `deploy()`/reload — `pkg add` pulls RUN_DEPENDS from that mirror.
- **Confirm what's actually installed with `pkg` — don't assume a tool is present
  or absent.** Installed: `pkg info` (all), `pkg info <pkg>` (one), `pkg info -l
  <pkg>` (its files), `pkg which <path>` (owning package). Available to install (repo
  catalogue, not yet installed): `pkg search <name>` / `pkg rquery` — the answer to
  "is dependency X available?". The smoke image ships `ldns` (→ `drill`),
  `bind-tools` (→ `dig`/`host`/`nslookup`), `python311`, `unbound`, `php83`, and
  `qemu-guest-agent` — so check before installing a dependency or coding a runtime
  fallback. (`pkg help` / `pkg <cmd> -h` for the full command surface.)
- **`/conf/config.xml` is the source of truth** for pfSense settings; the files under
  `/var/…` are *generated* from it. To check whether something is configured, read the
  relevant `config.xml` section (e.g. `<unbound><acls>`), not just the generated output.
  If you cite config.xml in your reasoning, actually open that section — don't assume.
- **"Everything is files" cuts both ways:** read the actual files (and diff
  before/after a change), and when a value is set/empty, confirm it on the box rather
  than trusting recollection.

---

## Resolving pfSense-provided PHP functions (read the real upstream source)

When a pfSense-provided PHP function is missing, undocumented, ambiguous, or you
can't tell whether it's implicated in a bug — and it isn't stubbed yet — **do NOT
assume it can be worked around or guess its behaviour.** We depend on open-source
software; the real implementation is available, so read it. Source of truth:
<https://github.com/pfsense/pfSense>.

A function's existence, signature, or behaviour can differ across releases, so
treat the **full source trees at these refs** as the authority — check the
function in each that's relevant:

1. **Minimum supported CE** — youngest commit at or before the launch date of our
   minimum pfSense CE version (currently **2.8.0**).
2. **Every CE release since the oldest supported** — youngest commit at or before
   each CE version's launch date.
3. **Every pfSense Plus release since our oldest supported CE** — youngest commit
   at or before each Plus version's launch date.
4. **`master`** — current upstream tip.

Resolve each ref at investigation time, don't hardcode hashes: find the version's
release date, then take the youngest commit at/before it
(`git log --before="<release-date>" -1 <branch>`, or the GitHub commits view
filtered by date). The public mirror may lack release branches/tags (e.g. no
`RELENG_2_8_0`), so dated commits on the available history are the reliable handle.
Checking across this set shows whether behaviour is stable across our support
matrix or version-specific.

**Always prefer stubbing the real function — based on its actual upstream source
— over making an exception** (a `phpstan-baseline.neon` suppression, an
`undefinedFunctions` entry, or a code workaround). Stubs encode reality and keep
PHPStan/Intelephense honest; exceptions hide it. This is the same principle as the
stub guidance under "Updating documentation" — that section covers the bulk
generator (`scripts/update-pfsense-stubs.py`); this covers investigating and
stubbing a single function from upstream by hand.

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
│       │   ├── pfb_unbound.py         # Unbound Python plugin (matcher + DNSBL list build: parse/classify/build from the manifest)
│       │   ├── pfblockerng.sh         # Shell script (POSIX sh)
│       │   └── ip_pre_AWS_*.sh        # Per-region AWS IP-prefix pre-scripts (hand-maintained)
│       ├── share/             # Package metadata (info.xml)
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # Python test suite (pytest)
├── docs/misc/             # Dev-only reference notes (e.g. pfSense_versions.md — per-version base facts + pfBlockerNG deps)
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
├── composer.json          # PHP dev deps: phpstan + phpunit
└── README.md
```

`tests/` holds the Python suite (pytest) plus `tests/php/` — the PHPUnit suite
for the pure/extractable PHP helpers (bootstrap loads the real `pfblockerng.inc`
off-appliance via include shims + pfSense doubles; see `tests/php/README.md`).

Release archives contain only `src/`. Everything else (stubs, scripts, tests, CI, pyproject.toml, `.githooks/`) is dev-only.

---

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath`
to `.githooks`; or run `git config core.hooksPath .githooks` directly). git cannot
auto-apply a committed hooks path — cloning must not silently install hooks — so
this one-time opt-in is required.

**Claude: before working in this repo, ensure the hooks are active.** If
`git config core.hooksPath` is not `.githooks`, run `sh scripts/setup-hooks.sh`
once at the start of the session (idempotent; safe to re-run).

**Claude: any GitHub Actions workflow that commits code must activate the hooks
first.** Have the workflow run `sh scripts/setup-hooks.sh` before its commit/push
steps (after checkout) so automated commits go through the same `pre-commit` /
`pre-push` checks — subject to which tools the runner has installed.

- **`.githooks/pre-commit`** runs the fast linters (and the unit suites) and blocks
  the commit on any failure: `ruff check`/`ruff format --check`, `python -m pytest`,
  `mypy tests/` (the test suite is fully typed — `tests.*` is `disallow_untyped_defs`
  in pyproject.toml; `tests/smoke` is excluded), `markdownlint-cli2`, `sh -n` +
  `shellcheck`, and `php -l`. Each check runs only when its tool is installed (a
  missing tool is reported and skipped — CI is the hard gate); PHPStan and PHPUnit
  run only when `vendor/bin/phpstan` / `vendor/bin/phpunit` exist. Bypass in an
  emergency with `git commit --no-verify`.
- **`.githooks/pre-push`** enforces tag naming before pushes reach the remote.

---

## Running tests

```sh
python -m pytest
```

Run from repo root. `pyproject.toml` sets `testpaths` and `-v`. No `cd` needed.

Run after **any** change to `src/usr/local/pkg/pfblockerng/pfb_unbound.py` or
`tests/` — in-loop, for fast feedback; don't wait for the commit to find breakage.
The pre-commit hook re-runs the suite at commit time and CI is the final authority,
so a separate manual pre-commit run is not needed.

PHP side — the fast PHPUnit suite for the pure/extractable helpers of
`pfblockerng.inc` (issue #39):

```sh
composer install      # once — installs phpunit/phpunit into vendor/
vendor/bin/phpunit     # config in phpunit.xml
```

It loads the **real** `pfblockerng.inc` off-appliance — `tests/php/bootstrap.php`
satisfies the file's pfSense `require_once` with empty shims (`tests/php/shims/`)
and provides behavioural doubles (`tests/php/pfsense_doubles.php`) for the pfSense
runtime functions; **no production code is moved or modified**. The PHPStan stubs
in `stubs/pfsense/` are empty-bodied (symbol existence only) so they cannot serve
as runtime doubles — add a faithful/no-op `function_exists()`-guarded double to
`pfsense_doubles.php` (and an empty shim if it's a required include) when a tested
path reaches a new pfSense function. Deep pfSense-runtime integration stays the
live-VM smoke's job (ADR-04). See `tests/php/README.md`.

DNSBL list preprocessing (parse → normalise → classify data/zone → build dicts +
feed/group index + `whiteDB`, then emit `pfb_py_count`) lives in `pfb_unbound.py`'s
pure `dnsbl_build_from_manifest()` / `build()`, fed by the PHP/shell-written
manifest (`/var/unbound/pfb_py_sources.json` + per-feed raw). PHP/shell only
download + tag + run the DNSBL-IP firewall pass. Decision-equivalence is pinned by
`tests/test_adr06_*` (golden oracle, build module, init-from-raw, PHP boundary);
the init/peak-RAM kill-gate is `benchmarks/spike_adr06_build.py`. See
`.ADRs/ADR_06_DNSBL_Preprocessing_To_Python/`.

ABP/EasyList feeds are parsed **entirely in Python** (ADR-07): PHP header-sniffs an
ABP feed, tags it `format_hint='abp'`, and passes its raw lines through verbatim
(IP anchors `||1.2.3.4^` and hosts IPs still divert to the DNSBL-IP firewall pass);
the old PHP `$easylist` lite parser is deleted. `parse('abp', …)` is the one DNS-only
ABP parser — it adds `@@` allow exceptions, regex (block `regexDB` / allow
`allowRegexDB`, with anchored patterns folded to dicts), and `$important`/`$badfilter`
precedence resolved by a 6-band numeric scale, with a build-emitted `important_rules`
flag preserving a byte-identical fast path when no ABP precedence feature is loaded.
Untrusted feed + user regex is guarded by an opt-in "Limit long/complex regex" static
cap (drops over-long/nested-quantifier patterns at load) plus an always-on runtime
warn/evict timer (warn 10 ms / evict 100 ms thread-CPU; snapshot-iterate,
evict-after-loop). Pinned by `tests/test_adr07_*` (decision spec/oracle, parser,
reconcile, matcher strata, emit/wire, regex safety, PHP boundary); the regex/ReDoS
kill-gate is `benchmarks/spike_adr07_regex.py`. See
`.ADRs/ADR_07_ABP_DNSBL_Support/`.

---

## Smoke tests (ADR-04 — live pfSense VM) — READ BEFORE TOUCHING `tests/smoke/`

`tests/smoke/` installs the branch `.pkg` on a REAL pfSense CE VM in CI
(`smoke.yml`, workflow_dispatch) and asserts pfBlockerNG end-to-end. These
truths are non-obvious and each cost real debugging — internalise them first:

- **Probe ON-BOX** (`drill @127.0.0.1` over SSH), NOT the runner-side SLIRP
  hostfwd — the WAN-hostfwd DNS path is not answered in CI. Python-mode DNSBL has
  **no localhost exemption**: a blocked name returns its block shape even from
  `127.0.0.1`. After `reload()` → `wait_unbound_ready`, the **first** DNS response
  is authoritative — assert it, never loop waiting for the expected value.
- **Test domains MUST be `helpers.unique_domain()`** (`uuid-*.com`): never RFC 6761
  TLDs (`.test`/`.example`/`.invalid`/…) — Unbound's built-in `local-zone`s shadow
  them (NXDOMAIN/NODATA) before DNSBL — and never HSTS-preload names — HSTS
  (`pfb_hsts`, default ON) forces a would-be VIP block to NULL.
- **Block shapes (python mode):** NOERROR + VIP (`dnsbl_ipv4`) or NULL
  (`0.0.0.0` / `::`); NEVER NXDOMAIN for a feed match (NXDOMAIN is SafeSearch-only).
  Per-list `logging` selects VIP vs NULL and is a **LIST-level** field
  (`$list['logging']`), not per-row. Compare IPs **by value** (`::` == `::0`).
- **Unbound is chrooted at `/var/unbound`** — files its python module reads must be
  chroot-relative (see the chroot note under "Investigating the live system"); a
  host-absolute path silently fails to load.
- **Enable chain:** DNSBL `mode=='enabled'` needs `enable_cb=on` + `pfb_dnsbl=on` +
  the DNS Resolver enabled (`unbound_state`). On `devel`, `dnsbl_mode`/`pfb_py_block`
  are dead keys (python is the only mode); on `main` they're still required.
- **The image bakes only the deps + qemu-guest-agent** — the harness injects the
  DNSBL VIP (`ensure_dnsbl_vip`) and all per-case config; `pkg add` runs offline.
  The smoke qcow2 cache is content-keyed by GHCR digest, so a same-tag re-push
  invalidates automatically.
- **The branch `.pkg` is built on a plain Linux runner** (`build-pkg-linux.yml` →
  `scripts/build-pkg-portable.py`), NOT on a FreeBSD VM: pfBlockerNG is a `NO_BUILD`
  port, so the portable builder reproduces `make package` from the port's
  Makefile + pkg-plist. `pkg add` checks a dep is PRESENT, not its version, so the
  portable `.pkg` installs identically on the baked-deps image. The real FreeBSD
  `make package` path (`build-pkg.yml`, image cache content-keyed by published
  SHA256) is RETAINED as a dispatch-only fidelity oracle — not in the smoke gate.
- **Every run uploads a full guest snapshot** (`smoke-diagnostics` artifact: all
  `/var/log`, `dmesg`, `pfctl -sa`, unbound + pfBlockerNG state,
  `/var/db/pfblockerng` and `/var/db/aliastables`, scrubbed `config.xml`). On any
  failure, read it first.

Full journey, verified response model, and per-step instrument (`SMOKE_STATE_DIFF`):
`.ADRs/ADR_04_VM_Smoke_Tests/RESULTS/`.

---

## Linting

Run the linters below **while working**, for fast feedback. Enforcement is layered,
so treat them as feedback rather than a manual pre-commit checklist: the
`.githooks/pre-commit` hook blocks any commit that fails them, and CI is the final
authority. (CI runs them even when the local hook is inactive or a tool is missing.)

### Python

```sh
ruff check .        # lint
ruff check . --fix  # lint + autofix
ruff format .       # format
```

Config in `pyproject.toml`. Target: Python 3.11+ (pfSense CE 2.8 / FreeBSD 15).

Ruff is the canonical linter. `.flake8` exists only so contributors who run
Flake8 (e.g. the VS Code extension) get the same 120-column limit and ignore set
— Flake8 can't read `pyproject.toml`, so without it Flake8 falls back to a
79-column default and to whitespace checks Ruff delegates to `ruff format`. Keep
the two in sync if the Ruff config changes.

### PHP

Intelephense in VS Code. `.inc` files are PHP — `files.associations` handles this.
Stubs in `stubs/pfsense/` resolve pfSense-provided functions. If Intelephense flags
a pfSense function as undefined, add it to the appropriate stub file rather than
expanding the `undefinedFunctions` suppression in `.vscode/settings.json`.

PHPStan (static analysis, `vendor/bin/phpstan`) and PHPUnit (functional unit
tests, `vendor/bin/phpunit`) are the PHP gates — both pulled by `composer install`
and enforced in CI (`test.yml`) and the pre-commit hook. See "Running tests" for
the PHPUnit suite; the `stubs/pfsense/` empty-bodied stubs are for PHPStan, NOT
runtime test doubles (those live in `tests/php/pfsense_doubles.php`).

### Shell

ShellCheck via VS Code extension. All scripts use `#!/bin/sh` (POSIX sh, not bash).
`.shellcheckrc` suppresses SC1091 (pfSense source files unreachable locally) and
SC2154 (rc(8)-injected variables). Do not suppress other rules without justification.

### Markdown

markdownlint via the VS Code "markdownlint" extension and the CLI. Run from repo root:

```sh
npx markdownlint-cli2          # lint
npx markdownlint-cli2 --fix    # lint + autofix
```

When writing Markdown, produce compliant output directly: put a blank line around
every heading, list, and fenced code block; give each fenced block a language
(use a `text` fence for plain output, trees, or ASCII); and end the file with a
single trailing newline. Long lines and compact (unaligned) tables are fine — `MD013`
and `MD060` are disabled.

Rule set is in `.markdownlint.jsonc` (read by both the extension and the CLI);
globs/ignores are in `.markdownlint-cli2.jsonc`. The ruleset is pragmatic — it
enforces structural/consistency rules but disables ones that fight the
documentation style: `MD013` (line length), `MD060` (table-column alignment),
`MD036` (the ADR `**Positive**`/`**Negative**` inline sub-headers), and `MD041`
(frontmatter-led files such as `.claude/skills/*.md` don't open with an H1);
`MD024` is `siblings_only`. `**/TRANSCRIPT.md` is ignored (verbatim transcript,
not maintained docs). Keep the disabled-rule rationale in `.markdownlint.jsonc`
in sync if the set changes. A clean lint (`0 error(s)`) is enforced by the
pre-commit hook and in CI (`test.yml`) alongside ShellCheck/PHP; run
`npx markdownlint-cli2 --fix` while editing for fast feedback.

---

## Code standards

### PHP

- Indent: **tabs** (enforced by `.editorconfig`)
- Target: PHP 8.3 (pfSense CE 2.8)
- Functions injected by pfSense at runtime (from `util.inc`, `config.lib.inc`, etc.)
  are declared in `stubs/pfsense/` — do not `require_once` pfSense files in tests
- No `die()`/`exit()` in library code; return values or throw

### Python

- Indent: **4 spaces**
- Target: Python 3.11+; use `from __future__ import annotations` for forward refs
- Add type hints to new functions; leave existing untyped code alone unless touching it
- No bare `except:`; use `except Exception` at minimum
- `pfb_unbound.py` runs inside Unbound's Python loader — no dependencies outside stdlib
- Unbound injects its API symbols (`log_info`, `RR_TYPE_*`, `DNSMessage`, …) as
  globals at runtime; `pfb_unbound.py` references them as bare names. They are
  declared once in `stubs/python/unboundmodule.py` (a dev/test stand-in), which
  Pylance/mypy resolve via the `TYPE_CHECKING` import and the test suite copies
  onto `builtins` (see `tests/conftest.py`). Add a new injected symbol there.

### Shell

- POSIX sh only (`#!/bin/sh`), no bash-isms (`[[`, arrays, `$RANDOM`, etc.)
- Quote all variable expansions: `"$var"`, `"${var}"`
- Use absolute paths for all binaries (pfSense convention); do not rely on `$PATH`
- `ip_pre_AWS_*.sh` are near-identical, hand-maintained per-region pre-scripts
  (selectable in the UI) that differ only by a `jq` region filter; when changing
  shared logic, apply it uniformly across all of them

---

## Updating documentation

**Documentation-only changes skip CI.** A commit/PR that touches *only* Markdown
(`**/*.md` — includes `CLAUDE.md` and `README.md`) or `docs/` is excluded from the
`test.yml` workflow via `paths-ignore` — there is nothing in the suite to exercise
for docs. The moment a change also touches code (anything outside those paths), the
full suite runs again. The local pre-commit hook still lints Markdown regardless, so
docs stay clean. This is a CI carve-out only: such changes still go through a
worktree and the normal PR/landing flow ("Worktrees", "Branches and releases").

Update `README.md` when:

- Workflow steps change (test command, deploy command, release steps)
- Minimum supported pfSense CE version changes
- New developer tooling is added

Update `stubs/pfsense/` when:

- Minimum supported pfSense CE version is bumped — run:

  ```sh
  python scripts/update-pfsense-stubs.py            # defaults to the newest public source
  python scripts/update-pfsense-stubs.py --version X.Y.Z
  ```

  The generator downloads pfSense source from GitHub and emits one stub file per
  module (`util.php`, `interfaces.php`, `certs.php`, …) with cross-file dedup. It
  defaults to **2.7.2** (`STUB_SOURCE_VERSION`): Netgate's public mirror is frozen
  there — no `RELENG_2_8_0` ref — and those signatures are stable across 2.7→2.8,
  which is all PHPStan level 0 needs (symbol existence). Generate from a real 2.8
  checkout if/when one is available.
- pfBlockerNG starts calling a new pfSense API function not yet stubbed — add it
  to the appropriate file in `stubs/pfsense/` manually
- `globals.php` is **always** manually maintained (array shapes can't be auto-derived);
  `logging.php` and `supplemental.php` are likewise hand-maintained and never
  regenerated (`supplemental.php` holds pfSense functions used on CE 2.8 that are
  absent from the 2.7.2 stub source, e.g. `config_read_file`). PHPStan is the gate:
  prefer stubbing a real pfSense function over a `phpstan-baseline.neon` suppression.

When the minimum supported CE version changes, also **rebuild + republish the
pfSense CE smoke image** (ADR-04): upgrade-in-place for a patch/minor bump, a
fresh seed on a major — via `.github/workflows/build-image.yml` (publish-on-pass,
gated by the smoke round-trip). See `.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`.

---

## Branches and releases

| Branch | Channel | Ships to |
| ------ | ------- | -------- |
| `main` | Stable  | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

New features land in `devel`. Pushing a `vX.Y.Z` tag triggers CI: tests → GitHub
Release → PR on `pfsense/FreeBSD-ports`. Tags from `devel` become pre-releases;
tags from `main` become stable releases.

**Merge PRs by rebase only** — `gh pr merge <N> --rebase` (or GitHub's "Rebase and
merge" button); never a merge commit, never squash. History across `main` ← `devel`
is kept strictly linear (`main` is always an ancestor of `devel`, no merge commits),
so promotion up the chain — and landing any PR — is a rebase/replay, not a merge. If
a PR branch is behind its base, rebase it onto the base first so the merge is a clean
fast-forward.

**`devel` advances out of band — rebase onto the latest remote before every push.**
Multiple agents work in parallel and their commits are rebased on top of `devel`, so the
remote tip moves under you between operations. Before **any** commit or push — to `devel`
*or* to a PR branch — `git fetch origin` and rebase your local branch onto the latest
remote tip (`git rebase origin/devel`, or `origin/<pr-base>` for a PR), resolve, then push
(`--force-with-lease` if the branch was rewritten). New work always replays **after** what
is already on the remote; never reconcile with a merge commit. This keeps the chain
strictly linear (above) and every PR a clean fast-forward — the same rule applies to each
follow-up commit you push onto an open PR.

---

## GitHub issues

**Read the whole issue before working it.** Whenever you are told to fix or pick up
a GitHub issue, read its **title and description AND every comment/update** on it
(`gh issue view <N> --comments`) before starting. Later comments routinely revise,
narrow, downgrade, or invalidate the original report — issue #25 is a live example: a
follow-up comment downgraded a claimed crash to a defensive-consistency cleanup and
corrected the fix. Never act on the opening text alone.

### Labels (lifecycle)

Keep an issue's labels in sync with its stage in the workflow (the labels already
exist in the repo — see `gh label list`). Apply them with
`gh issue edit <N> --add-label <l>` / `--remove-label <l>`:

- **Creating an issue** — apply the appropriate descriptive label(s) for what it is
  (`bug`, `enhancement`, `documentation`, …).
- **Picking it up** (starting work) — add `WIP`.
- **It reaches the PR stage** (a PR that fixes it is open) — remove `WIP`, add
  `Waiting PR`.
- **That PR is merged** — remove `Waiting PR`.
- **Resolved/closed without a PR** (e.g. fixed by a direct push, or closed as
  invalid) — remove `WIP`.
- **Dropped / can't fix** (won't-fix, not reproducible, …) — remove `WIP`/`Waiting
  PR` and leave a status-update comment explaining why.

---

## Commit style

Follow existing log: `<scope>: <imperative summary>`.
Examples: `ci: simplify pytest invocation`, `dev: add ShellCheck config`, `pfblockerng: fix IPv6 subnet match`.
No period at end of subject line. Body optional for non-obvious changes.
