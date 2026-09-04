# PHP unit tests (PHPUnit)

Fast, off-appliance unit tests for the **pure / extractable** PHP logic in
`src/usr/local/pkg/pfblockerng/pfblockerng.inc` — the functional layer beneath
the live-VM smoke (ADR-04). Added for issue #39; mirrors the Python suite's
"test the pure functions in isolation" philosophy.

## Running

```sh
composer install      # once — pulls phpunit/phpunit into vendor/
vendor/bin/phpunit     # config: phpunit.xml at the repo root
```

Requires PHP 8.3+ (CE 2.8 baseline) with the `curl`, `intl`, `mbstring`,
`ctype` and `filter` extensions. Run `vendor/bin/phpunit` explicitly while
iterating. The pre-commit hook does not run unit suites; for staged PHP it runs
the Composer vendor guard, syntax checks, PHPStan and PHPCS. CI (`test.yml`,
`php-unit` job) runs PHPUnit with an informational `--coverage-text` summary
(no enforced floor yet — see issues #38/#39).

## How it works — testing the *real* code, no live box

`pfblockerng.inc` is mostly pfSense-integration code: it opens with
`require_once` of eight pfSense core includes, calls a handful of pfSense
runtime functions at load time, and defines the helpers we want to test. We load
that **real file unmodified** (so tests exercise shipped code, not copies) by
making it resolvable off-appliance. `tests/php/bootstrap.php`:

1. **Include shims** — `tests/php/shims/` holds empty files named after the
   eight pfSense includes (`util.inc`, `config.lib.inc`, …). Prepending that dir
   to `include_path` satisfies the top-of-file `require_once` as no-ops.
2. **pfSense doubles** — `tests/php/pfsense_doubles.php` defines the pfSense
   runtime functions the code reaches. The PHPStan stubs in `stubs/pfsense/`
   only assert symbol *existence* (empty bodies), so they are useless as
   behavioural doubles; the doubles here implement faithful behaviour where a
   tested result depends on it (`is_ipaddrv4`/`is_ipaddrv6`/`is_ipaddr` mirror
   pfSense `util.inc`; `safe_mkdir`/`rmdir_recursive` really touch the temp
   sandbox) and no-ops where it does not (`write_rcfile`, `system_get_uniqueid`,
   host-resolution helpers reached only by URL/MIME paths the suite skips).
   Each is `function_exists()`-guarded.
3. **Sandbox `$g`/`$pfb`** — load-time `$pfb[...]` path assignments are pointed
   at a writable temp dir so any `pfb_logger` (`@file_put_contents`) writes are
   harmless.
4. **Dormant dispatch** — `$argv` is cleared so the bottom-of-file daemon
   dispatch (`if (isset($argv[1]))`) does not fire under PHPUnit.

Pre-existing legacy `E_DEPRECATED`/`E_WARNING` notices emitted while *loading*
the file are silenced narrowly around the include and full reporting is restored
for test execution.

## What's covered (seed)

| Test file | Function under test |
| --------- | ------------------- |
| `PfbFilterTest` | `pfb_filter` (DOMAIN/IP/IPV4/WORD/HEX_COLOR/ON_OFF/NUM) |
| `TextAreaDecodeTest` | `pfb_text_area_decode` (base64/CRLF/comment/IDN) |
| `AbpExtractIpTest` | `pfb_dnsbl_abp_extract_ip` (ADR-07 DNSBL-IP extraction) |
| `SanitizeIpaddrTest` | `sanitize_ipaddr` (IPv4 normalise + suppression) |
| `ValidateDomainLabelsTest` | `pfb_validate_domain_labels` (63-char labels) |
| `PfbStrtolowerTest` | `pfb_strtolower` |
| `UnboundPythonSourcesTest` | `pfb_unbound_python_sources` (ADR-06/07 manifest writer) |
| `BootstrapSmokeTest` | bootstrap sanity (functions/constants loaded) |

A few tests pin **real production quirks** (e.g. `pfb_filter` NUM returns the
default for `'0'` because of the final loose `== FALSE` comparison) — these are
regression anchors, not endorsements.

## Out of scope

Deep pfSense-runtime integration (config apply, service reloads, pf/Unbound
wiring, URL/MIME validation that shells out to `/usr/bin/file` or resolves
hosts) stays the live-VM smoke's job — see `legacy/ADRs/ADR_04_VM_Smoke_Tests/`.

## Host archive toolchain

On FreeBSD and macOS, `/usr/bin/tar` is **bsdtar** (libarchive). On Linux,
`bsdtar` is provided by `libarchive-tools` (typically at `/usr/bin/bsdtar`).

The PHPUnit test bootstrap resolves the platform archiver cleanly and asserts
`bsdtar` is executable, crashing fast on startup if missing on Linux.
Linux development seats install it via `sh scripts/agent/setup-agent-tools.sh`
or directly via:

```sh
sudo apt-get install -y --no-install-recommends libarchive-tools
```

No `dpkg-divert` or host binary mutation is required.

## Adding a test

- Put `*Test.php` here; it is picked up automatically (`phpunit.xml` testsuite
  is this directory).
- The function under test is already defined by the bootstrap — just call it.
- Need a pfSense runtime function not yet doubled? Add a faithful (or no-op)
  `function_exists()`-guarded double to `pfsense_doubles.php`; if it's an
  include the production file requires, add an empty shim under `shims/`.
- Reads/writes via `$pfb[...]`? Set the relevant keys on `$GLOBALS['pfb']` in the
  test's `setUp()` and use a temp dir.
