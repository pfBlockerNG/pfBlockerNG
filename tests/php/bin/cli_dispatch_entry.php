<?php

declare(strict_types=1);

/*
 * issue #3041 — standalone off-appliance runner for pfblockerng.inc's CLI
 * dispatch (`if (isset($argv[1])) {`). Mirrors tests/php/bootstrap.php's
 * essential doubles/sandbox wiring, but does NOT require bootstrap.php --
 * its step 4 defuses $argv, which would keep the dispatch dormant here too.
 * Usage: php cli_dispatch_entry.php <verb>  (verb: dnsbl|index|filterlog)
 */

// 1. Forward the verb as the production dispatch expects it (argv[0] is the
// script name pfblockerng.inc is invoked as; only argv[1] is compared).
$GLOBALS['argv'] = ['pfblockerng.inc', $argv[1] ?? ''];
$GLOBALS['argc'] = 2;

require_once __DIR__ . '/../pfsense_doubles.php';

// Shims for the eight pfSense includes required at the top of pfblockerng.inc.
set_include_path(__DIR__ . '/../shims' . PATH_SEPARATOR . get_include_path());

// Writable per-invocation sandbox: safe_mkdir()/rmdir_recursive() (doubled in
// pfsense_doubles.php) really touch these paths.
$pfbTmp = sys_get_temp_dir() . '/pfb_cli_dispatch_' . getmypid() . '_' . bin2hex(random_bytes(8));
foreach (['', '/db', '/log', '/tmp'] as $sub) {
	if (!mkdir($pfbTmp . $sub, 0777, TRUE)) {
		fwrite(STDERR, "sandbox creation failed: {$pfbTmp}{$sub}\n");
		exit(2);
	}
}
register_shutdown_function(static fn (): bool => rmdir_recursive($pfbTmp));

$GLOBALS['g'] = [
	'vardb_path'  => "{$pfbTmp}/db",
	'varlog_path' => "{$pfbTmp}/log",
	'tmp_path'    => "{$pfbTmp}/tmp",
	'pfblockerng_install' => FALSE,
];
$GLOBALS['pfb'] = [];

// issue #3041 repro: an empty DNSBL section takes pfb_dnsbl_policy_config()'s
// fresh-install early return, which never touches the moved constant -- only a
// migrated box (global_log_mode present, every live nightly-smoke box) exercises
// the path that fatals. Seed the minimal non-fresh shape.
$GLOBALS['config'] = [];
config_set_path('installedpackages/pfblockerngdnsblsettings/config/0',
	['global_log_mode' => 'override', 'global_log' => 'enabled']);

// issue #3041: the 'filterlog' branch's missing-/var/log/filter.log guard calls
// logger()/localize_text() -- CE-compat shims defined only inside
// pfblockerng_extra.inc, which pfblockerng.inc's own top-of-file file_exists()
// guard never finds off-appliance. Preload them BEFORE the dispatch can fire.
require_once dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';

// Load the real file unmodified. The dispatch fires mid-include (this is the
// mechanism bootstrap.php step 4 defuses); silence the same pre-existing
// load-time E_DEPRECATED/E_WARNING noise bootstrap.php silences.
$prevEr = error_reporting();
error_reporting($prevEr & ~E_DEPRECATED & ~E_WARNING);
require_once dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
error_reporting($prevEr);
