<?php
/*
 * PHPUnit bootstrap for the pfBlockerNG PHP unit suite.
 *
 * Strategy (see tests/php/README.md): load the REAL production include
 * src/usr/local/pkg/pfblockerng/pfblockerng.inc unmodified, so the tests
 * exercise shipped code rather than copies. pfblockerng.inc opens with
 * require_once() of eight pfSense core includes and runs a little top-level
 * code; we make that resolvable off-appliance without touching production:
 *
 *   1. Prepend tests/php/shims/ to include_path — empty files named after the
 *      eight required pfSense includes satisfy require_once() as no-ops.
 *   2. Provide behavioural doubles (pfsense_doubles.php) for the pfSense
 *      runtime functions the load-time code and the tested functions call.
 *   3. Seed $g / $pfb so load-time $pfb[...] path assignments point at a
 *      writable temp sandbox (pfb_logger uses @file_put_contents — harmless).
 *   4. Clear $argv so the bottom-of-file daemon dispatch (if (isset($argv[1])))
 *      stays dormant under PHPUnit.
 *
 * The two top-level service installers (pfb_filter_service/pfb_dnsbl_service)
 * only build an rc array and call write_rcfile(), which we double to a no-op.
 */

require_once __DIR__ . '/pfsense_doubles.php';

// 1. Shims for the eight pfSense includes required at the top of pfblockerng.inc.
set_include_path(__DIR__ . '/shims' . PATH_SEPARATOR . get_include_path());

// 3. Writable sandbox for any load-time/log file writes.
$pfb_test_tmp = sys_get_temp_dir() . '/pfb_php_unit_' . getmypid();
@mkdir($pfb_test_tmp, 0777, true);
@mkdir("{$pfb_test_tmp}/db", 0777, true);
@mkdir("{$pfb_test_tmp}/log", 0777, true);
@mkdir("{$pfb_test_tmp}/tmp", 0777, true);

$GLOBALS['g'] = [
	'vardb_path'  => "{$pfb_test_tmp}/db",
	'varlog_path' => "{$pfb_test_tmp}/log",
	'tmp_path'    => "{$pfb_test_tmp}/tmp",
	'pfblockerng_install' => false,
];
$GLOBALS['pfb'] = [];

// 4. Keep the daemon dispatch dormant. Save/replace argv (PHPUnit has already
//    parsed its own arguments by now, so this is safe).
$GLOBALS['argv'] = ['pfblockerng.inc'];
$GLOBALS['argc'] = 1;

// 2 + load. Define the production functions by including the real source.
// pfblockerng.inc is legacy code that emits some load-time E_DEPRECATED/E_WARNING
// notices (e.g. an optional-before-required parameter, a switch `continue`) that
// are pre-existing and unrelated to the tests. Silence them around the include
// only, then restore full reporting so test execution stays strict.
$pfb_prev_er = error_reporting();
error_reporting($pfb_prev_er & ~E_DEPRECATED & ~E_WARNING);
require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
error_reporting($pfb_prev_er);
