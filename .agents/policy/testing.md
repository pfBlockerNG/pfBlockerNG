# Testing — how to satisfy the mandate, and the test environment

Scope: writing/changing tests, running suites. Load when: any change ships tests (every change does) or suite runs locally.

## Test coverage (mandatory) — the five principles

Tests = how change proves itself. **Five non-negotiable principles govern every change — unit, integration, E2E, smoke, UI. Each a hard gate: change violating any one is NOT done, no matter what line-coverage number says.**

1. **Test is EVIDENCE change works — for behaviour change it MUST fail before and pass after, and proof is TEST-FIRST.** Write reproduction test(s) **before touching production code**, at full suite quality (every standard here applies — they ship in suite and double as defect's in-suite reproduction), and run on untouched code: they **FAIL for exact reason change addresses**. From that red run tests **frozen** — byte-identical until green (temporary skip/disable while developing fine, but committed file matches red-run content exactly; record `git hash-object` of each test file at red time). After change SAME tests, **zero edits**, **PASS** — one green run proving both that tests test condition and that fix works. Only then write further tests change needs. Test written after fix, or edited between red and green, proves nothing — same for test already green before change. **Two exceptions:** behaviour-**PRESERVING** work (refactors, prep phases) pins *existing* behaviour as oracle and stays green across change — still mandatory; and **brand-new code with no pre-existing behaviour to be wrong** needs no red run against void — only possible red there is missing symbol/file, an *existence* test, itself coverage theater. Its tests still ship with it asserting real behaviour, and any change it makes to EXISTING observable behaviour still gets red-first proof.
2. **Every change ships WITH its tests.** "Existing suite still passes" is **not** coverage of new change.
3. **NEVER coverage theater.** Test must *validate* code, not merely *execute* it — carries assertion that would **fail on regression**. Green at 100% line coverage with no failable assertion is **rejected**.
4. **Front-end changes REQUIRE front-end tests.** Change touching `www/` must carry UI tests (ADR-14). webConfigurator-reachable surface requires **Tier A (`ui_render`)**. Surface recorded in `test_render_smoke.py`'s `EXCLUDED_FROM_TIER_A` because Tier A cannot reach it requires live tier named by that exclusion plus focused hermetic coverage; never relabel unreachable Tier-B flow as Tier A. **Tier B (`ui_e2e`/`ui_browser`) also REQUIRED IFF change observable *only* in Tier B** — explicitly includes **new page**, **multi-step flow** (anything spanning more than one request/interaction), and **visual/structural** changes (element positioning/addition/removal, layout). When in doubt, add Tier B.
5. **Tests express change's INTENT — documentation, not just coverage.** Name and comments state intended outcome being pinned, never mechanics of how it coded.

## Satisfying the principles

- **Branch coverage — test every condition, not one side.** Boolean gets off *and* on (plus any third state); every `if`/`switch`/match branch and documented input class gets own assertion (exemplar pair: `test_dnsbl_hsts_override_forces_null` / `test_dnsbl_hsts_disabled_keeps_vip`).
- **Assert before-state in transition tests.** Test that flips toggle asserts *original* result first, so green proves flip **caused** change — never just final state. Extends to any lifecycle (blocked-after-listing test first asserts domain *resolved*).
- **Self-encapsulated — never order-dependent.** Shared fixtures fine; no test may depend on sibling running first. Reset per-test state explicitly with autouse fixture that **fails loudly** if reset doesn't take (the `tick` smoke-module bug); module-scoped baseline is NOT per-test isolation.
- **Specify complex behaviour BDD-style; keep trivial tests trivial.** Non-trivial behaviour (state transitions, precedence, multi-step flows) gets Scenario / Given–When–Then structure.
- **Synchronize — duration never an assertion.** Test waits by consuming event it needs (marker, observed condition, join) and asserts on THAT — never "work completed within N seconds", never fixed sleep as coordination. Only time bound allowed is generous salvage cap whose sole job is reaping stuck run; its expiry reports "stuck/environment", loudly and distinguishably from behaviour under test. Widening deadline or scaling by CI factor never a flake fix: deadline doing assertion work and no constant large enough (PR #1499 widened 4 s → 16 s; same test flaked at 16 s five hours later — #1459; class removal tracked in #1517).
- **On failure, print expected vs actual — no guessing.** Every assertion/poll that can fail puts comparison on terminal (AssertJ-style, redacted against usual secrets); bare "False" matcher not acceptable; diagnostic filtering by token must match value's **rendered** form (`pfctl` prints port 53 as `domain`). Exemplar: `_redir_match_report` in `tests/smoke/test_dns_redirect.py`.
- **CI-gate wiring proves its red path in-job (the red canary).** CI job whose verdict rides shell wiring unit tests cannot cover (pipes, `set` options, exit propagation) ships red canary: leading lines in **same** `run:` block as enforce command (same shell options, so option drift trips it) feed known-violating input through identical pipeline shape and require nonzero before real check runs. Canary is that wiring's red→green (PR #933: default `bash -e {0}` has no `pipefail`, so `| tee` masked script's exit 1; exemplar: `coverage-pairing` job in `test.yml`). Broader corollary: **any newly wired blocking gate** (pre-commit block, CI step) demonstrates its red path once, in-session — feed violating input, watch gate fail — even when wiring is bare `run:` line (PR #937's wiring shipped green-path-only, #943).

## Running tests

**Tools run directly on the host — no container** (issue #2513 deleted `scripts/run-in-docker.sh` and the `ci-runner` images). Python comes from `uv` against the committed `uv.lock`; PHP tools from `vendor/bin` after `composer install`.

```sh
uv sync --locked --group dev    # pyproject [dependency-groups]; .python-version pins 3.11
uv run pytest                   # testpaths/addopts live in pyproject.toml
uv run mypy tests/
uv run ruff check . && uv run ruff format --check .
uv sync --locked --group smoke  # ADR-04 live-VM harness (--group bench: the benchmarks)
composer install                # if it 403s in a managed cloud session, use
                                # scripts/composer-cloud-install.sh (issue #950)
vendor/bin/phpunit              # PHP suite: loads the REAL .inc off-appliance
vendor/bin/phpstan analyse --no-progress --memory-limit=2G
vendor/bin/phpcs
shellspec --shell dash          # POSIX gate; bash-as-sh masks ash divergence
```

`--locked` FAILS rather than re-resolving when `uv.lock` is stale — that is the gate keeping a transitive package from moving a verdict with no diff, so never downgrade it to a bare `uv sync` or `uv pip install`. `scripts/agent/run-gates.sh` and `.githooks/pre-commit` invoke these same tools directly; a gate whose tool is missing is a FAILURE for run-gates, never a skip.

**The host toolchain is NOT automatically CI's** — accepted regression of #2513 (parity was the container's whole job; ADR-47 rests on the same idea). CI grades on Linux with pinned tools: ShellCheck **v0.11.0**, shellspec **0.28.1**, actionlint **1.7.12**, PHP **8.3** and **8.5**, `dash` as the shellspec shell, Python from `uv.lock`. Install those same versions locally; when a claim rides a local run, say which toolchain produced it, and where host and CI disagree **CI is the authoritative answer**.

**Divergence shows up as a SKIP, not a red**, which is the harder thing to notice — read the skip list, never just the exit status. Locale data, `file(1)` classification, the PHP build (whether `php://memory` can fail `flock()`), the invoking uid and the `tar` flavour (bsdtar on macOS and the appliance, GNU tar on Linux) each decide whether a case runs at all. Never read a skip as coverage.

**The skip SET is gated, not just readable** (issues #2359 and #2369): every blocking test row writes JUnit and runs `scripts/check_skip_allowlist.py` against `tests/skip-allowlist.txt`. One allowlist remains canonical because ids are suite-prefixed `<suite>:<classname>::<name>`; the Node invocations use distinct prefixes. `scripts/agent/run-gates.sh` adds the same report/check only to pytest, PHPUnit, and ShellSpec when its touched-path mapping already selects them. A skip not on the file fails; an allowlisted id absent from one run is informational only. Add a legitimate skip as its own `# <reason>`-carrying entry — a bare id is a parse error (exit 2).

Environment gotchas that read as fake "baseline failures" — fix env, never dismiss red: pytest suite needs **zstd encoder** (`zstd` binary or `zstandard` module); bare managed-cloud container lacks one and ~70 pkg/repo tests fail — `SessionStart` hook auto-installs it (manual: `pip3 install zstandard`). PHPUnit permission-denial tests (`chmod 0555` fixtures) **skip under root** via `posix_getuid() === 0` guard — root bypasses file permissions, so root run cannot simulate denial (red there means guard missing, not code broke). Any other local-only failure: diagnose before dismissing — if genuinely pre-existing on base branch, **file tracking issue** (exemplars #791, #894); never leave as folklore.

PHPUnit bootstrap satisfies `require_once` with empty shims (`tests/php/shims/`) + behavioural doubles (`tests/php/pfsense_doubles.php`); when tested path reaches new pfSense function, add `function_exists()`-guarded double there (stubs can't serve — empty-bodied). See `tests/php/README.md`.
