# Testing — how to satisfy the mandate, and the test environment

Scope: writing/changing tests and running the suites. Load when: any change ships tests
(every change does) or a suite runs locally. The five non-negotiable test-coverage
principles live in `CLAUDE.md` "Test coverage (mandatory)"; this file is how to satisfy
them plus the environment gotchas.

## Satisfying the principles

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
