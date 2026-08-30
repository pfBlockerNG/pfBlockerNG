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

// 3. Writable per-invocation sandbox for any load-time/log file writes.
$pfb_test_owner_pid = getmypid();
$pfb_test_tmp = sys_get_temp_dir() . '/pfb_php_unit_' . $pfb_test_owner_pid . '_' . bin2hex(random_bytes(8));
if (!mkdir($pfb_test_tmp, 0777, TRUE)) {
	throw new RuntimeException("PHPUnit sandbox creation failed: {$pfb_test_tmp}");
}
register_shutdown_function(static function () use ($pfb_test_tmp, $pfb_test_owner_pid): void {
	// pcntl_fork() inherits shutdown callbacks; only the process that created this tree owns it.
	if (getmypid() === $pfb_test_owner_pid) {
		rmdir_recursive($pfb_test_tmp);
	}
});
unset($pfb_test_owner_pid);
foreach (['db', 'log', 'tmp'] as $pfb_test_subdir) {
	$pfb_test_path = "{$pfb_test_tmp}/{$pfb_test_subdir}";
	if (!mkdir($pfb_test_path, 0777, TRUE)) {
		throw new RuntimeException("PHPUnit sandbox directory creation failed: {$pfb_test_path}");
	}
}
unset($pfb_test_path, $pfb_test_subdir);

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

// 4b. Keep the resolver start dormant too, the sibling of step 4: no unit test may
//     start Unbound (issue #2613) or pay either appliance wait. The executable double
//     exits 127 because an absent binary returns exactly that off-appliance, which keeps
//     the caller's retval != 0 retry branch exercised without a shell compound escaping
//     the timeout wrapper. Guarded: a re-load stays silent.
$GLOBALS['pfb_test_unbound_start_log'] = "{$pfb_test_tmp}/unbound_start.log";
$pfb_test_unbound_start_cmd = "{$pfb_test_tmp}/unbound-start-double";
file_put_contents($pfb_test_unbound_start_cmd, <<<'SH'
	#!/bin/sh
	printf '%s\n' 'unit-test double: Unbound start suppressed' | tee -a "$1"
	exit 127
	SH);
chmod($pfb_test_unbound_start_cmd, 0755);
if (!defined('PFB_UNBOUND_START_CMD')) {
	define('PFB_UNBOUND_START_CMD', escapeshellarg($pfb_test_unbound_start_cmd) . ' '
		. escapeshellarg($GLOBALS['pfb_test_unbound_start_log']));
}
if (!defined('PFB_UNBOUND_STOP_WAIT')) {
	define('PFB_UNBOUND_STOP_WAIT', 2);
}
if (!defined('PFB_UNBOUND_START_WAIT')) {
	define('PFB_UNBOUND_START_WAIT', 2);
}
unset($pfb_test_unbound_start_cmd);

// 2 + load. Define the production functions by including the real source.
// pfblockerng.inc is legacy code that emits some load-time E_DEPRECATED/E_WARNING
// notices (e.g. an optional-before-required parameter, a switch `continue`) that
// are pre-existing and unrelated to the tests. Silence them around the include
// only, then restore full reporting so test execution stays strict.
$pfb_prev_er = error_reporting();
error_reporting($pfb_prev_er & ~E_DEPRECATED & ~E_WARNING);
require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
error_reporting($pfb_prev_er);
$pfb_test_timeout_out = [];
$pfb_test_timeout_rc = 0;
exec('command -v timeout 2>/dev/null', $pfb_test_timeout_out, $pfb_test_timeout_rc);
$pfb_test_timeout = trim((string) ($pfb_test_timeout_out[0] ?? ''));
if ($pfb_test_timeout_rc !== 0 || !is_executable($pfb_test_timeout)) {
	throw new RuntimeException('PHPUnit requires a real timeout(1) on PATH for bounded process tests.');
}
$GLOBALS['pfb']['timeout'] = $pfb_test_timeout;
unset($pfb_test_timeout_out, $pfb_test_timeout_rc, $pfb_test_timeout);

// Snapshot the SHIPPED $pfb['mime_types'] allow-list exactly as the just-loaded
// production source defines it, before any test mutates/unsets $GLOBALS['pfb']
// (several sibling tests overwrite it in setUp/tearDown). This immutable copy
// lets allow-list oracles assert against the REAL shipped list, not a hand-mirror.
$GLOBALS['pfb_shipped_mime_types'] = $GLOBALS['pfb']['mime_types'] ?? [];

// 5. Load the setup-wizard controller's FUNCTIONS so the unit suite can invoke
//    them on shipped code (WizardVipAutoTest -> step3_submitphpaction). The wizard
//    .inc cannot be require()d as-is here: it opens with four require_once()s —
//    three relative (config.inc/util.inc/services.inc, satisfiable by the shims)
//    plus one HOST-ABSOLUTE require of /usr/local/pkg/pfblockerng/pfblockerng.inc
//    (NOT resolvable via include_path, and a duplicate of the real include already
//    loaded above) — and then runs top-level wiring (pfb_global(), interface-list
//    build) that needs runtime pfSense state we deliberately do not stand up.
//    So we read the source, strip its require_once() lines, and eval only from the
//    first function definition onward: the function bodies are the shipped code
//    under test, defined verbatim; no production file is modified. Guarded so a
//    real include path (on-appliance) never double-defines.
// 6. Load the ADR-28 adapter helpers so tests can exercise them against the
//    real bootstrap environment (enums + adapter fns; inlined into pfblockerng_extra.inc,
//    ADR-28 P4).  On-appliance pfblockerng.inc loads extra.inc via a host-absolute
//    file_exists() check that is not satisfied off-appliance, so we load it explicitly
//    here by its repo-relative path.
require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
if (!function_exists('step3_submitphpaction')) {
	$pfb_wizard_src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc'
	);
	if ($pfb_wizard_src === false) {
		throw new RuntimeException('test bootstrap: failed to read pfblockerng_wizard.inc for the wizard-function load');
	}
	// Drop the top-of-file require_once() statements (shims/real include already
	// satisfy them); keep everything else byte-for-byte.
	$pfb_wizard_src = preg_replace('/^\s*require_once\(.*\);\s*$/m', '', $pfb_wizard_src);
	// Eval only the function definitions (from the first `function ` keyword),
	// skipping the top-level wiring that would call into unprovisioned runtime.
	$pfb_fn_pos = strpos($pfb_wizard_src, 'function ');
	if ($pfb_fn_pos !== false) {
		eval("\n" . substr($pfb_wizard_src, $pfb_fn_pos));
	}
	unset($pfb_wizard_src, $pfb_fn_pos);
}

// 7. Parity snapshot of the package's loaded function surface (#1122 phase 0),
//    taken here so it reflects exactly what the umbrella + extra load defines,
//    before any test can add or shadow symbols (order-independent by
//    construction). The defining file selects package functions only — it
//    excludes the doubles, vendor code, and the wizard eval above — but the
//    snapshot records no file-of-origin, so relocating a function between
//    package files (the #1122 split) leaves it byte-identical.
//    Coupling caveat: extra.inc's function_exists()-guarded CE-compat shims
//    (localize_text, logger) are in the inventory only while
//    pfsense_doubles.php defines no double for them — adding such a double
//    later flips the parity test red with zero production change.
$pfb_pkg_dir = realpath(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng') . DIRECTORY_SEPARATOR;
$pfb_inventory = [];
foreach (get_defined_functions()['user'] as $pfb_fn_name) {
	$pfb_fn_ref = new ReflectionFunction($pfb_fn_name);
	$pfb_fn_file = $pfb_fn_ref->getFileName();
	if ($pfb_fn_file === false
	    || strncmp((string) realpath($pfb_fn_file), $pfb_pkg_dir, strlen($pfb_pkg_dir)) !== 0) {
		continue;
	}
	$pfb_fn_params = [];
	foreach ($pfb_fn_ref->getParameters() as $pfb_fn_param) {
		$pfb_fn_params[] = [
			'name'     => $pfb_fn_param->getName(),
			'byRef'    => $pfb_fn_param->isPassedByReference(),
			'variadic' => $pfb_fn_param->isVariadic(),
			'type'     => $pfb_fn_param->hasType() ? (string) $pfb_fn_param->getType() : null,
			'default'  => $pfb_fn_param->isDefaultValueAvailable()
				? var_export($pfb_fn_param->getDefaultValue(), true)
				: null,
		];
	}
	$pfb_inventory[$pfb_fn_ref->getName()] = [
		'returnsRef'  => $pfb_fn_ref->returnsReference(),
		'returnType'  => $pfb_fn_ref->hasReturnType() ? (string) $pfb_fn_ref->getReturnType() : null,
		'params'      => $pfb_fn_params,
	];
}
ksort($pfb_inventory, SORT_STRING);
$GLOBALS['pfb_function_inventory'] = $pfb_inventory;
unset($pfb_pkg_dir, $pfb_inventory, $pfb_fn_name, $pfb_fn_ref, $pfb_fn_file, $pfb_fn_params, $pfb_fn_param);
