# Shell test suite (shellspec)

Functional tests for the project's POSIX `sh` — the `ip_pre_AWS_*.sh` region
pre-scripts and the testable functions in `pfblockerng.sh`. This complements the
existing static gating (ShellCheck + `sh -n`) with behavioural coverage, and locks
in the fixes for issues #27, #28, and #30.

Framework: [shellspec](https://shellspec.info/) (pure POSIX, BDD-style, native
kcov coverage). Tests run under `/bin/sh`.

## Running

```sh
shellspec                     # from the repo root; reads ./.shellspec
shellspec tests/shell/ip_pre_aws_spec.sh   # a single spec
shellspec --kcov              # with coverage (writes ./coverage/, needs kcov)
```

Install: `brew install shellspec` (macOS) or the official installer
(`curl -fsSL https://git.io/shellspec | sh`); `kcov` is only needed for `--kcov`.
The pre-commit hook and CI run the suite automatically when `shellspec` is present.

## Layout

```text
tests/shell/
├── spec_helper.sh                       # shared setup (loaded via --require)
├── bin/iprange                          # PATH shim for the FreeBSD aggregator
├── fixtures/aws-ip-ranges.json          # AWS ip-ranges.json shape, 1 prefix/region
├── ip_pre_aws_spec.sh                   # region-filter family (the headline target)
├── pfblockerng_reputation_max_spec.sh   # issue #27
├── pfblockerng_iptoasn_spec.sh          # issue #28
└── pfblockerng_tempfile_spec.sh         # issue #30
```

Config lives in the repo-root `.shellspec` (`--shell sh`, `--default-path`/
`--load-path tests/shell`, `--require spec_helper`, kcov include path).

## How it works — three contracts to know

- **`iprange` shim (`bin/iprange`).** The AWS pre-scripts pipe their v4 prefixes
  through `iprange`, a FreeBSD-only CIDR aggregator not installable on the CI/dev
  hosts. `spec_helper.sh` prepends `tests/shell/bin` to `PATH` so a `sort -u` shim
  stands in (`jq` stays the real binary). The fixture uses one **non-adjacent** /24
  per region, so there is nothing to coalesce and the shim is faithful. Do not rely
  on the shim for aggregation behaviour.

- **AWS fixture + per-region assertion.** `aws_filter <script> <_v4|_v6>` copies
  `fixtures/aws-ip-ranges.json` (each region has a unique prefix), runs the script
  over the copy — which it overwrites in place — and emits the result sorted and
  space-joined. The spec asserts the exact surviving set per script. The
  `us-`/`us-gov-` overlap is pinned intentionally (see the spec's header comment).

- **Sourcing `pfblockerng.sh` for unit tests.** The script is *library on source,
  run on exec*: it defines its functions, then `[ -n "${PFB_SOURCED:-}" ] && return`
  before running any top-level init or the argument dispatch. `pfb_source` (in
  `spec_helper.sh`) sets `PFB_SOURCED=1` and dot-sources it, so a spec can set the
  globals a function reads and call it directly — with **no** system side effects.
  GeoIP lookups are replaced by a stub (`make_geoip_stub`).
