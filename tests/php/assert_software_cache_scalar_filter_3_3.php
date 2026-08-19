<?php

declare(strict_types=1);

/*
 * pfb_software_read_cache() must drop non-scalar values.
 *
 * Every consumer reads these through a (string) cast. An array-valued entry in the
 * cache JSON therefore emits "Array to string conversion" on every call -- a correct
 * verdict with a noisy log, and the UI tiers read a warning in php_error.log as a page
 * defect (issue #2377; devel closed the class reader-side in PR #2373).
 *
 * Asserts the drop AND that no diagnostic is raised, since the warning is the defect.
 */

$failures = 0;
function check(bool $cond, string $label): void
{
	global $failures;
	if ($cond) {
		echo "PASS {$label}\n";
		return;
	}
	$failures++;
	echo "FAIL {$label}\n";
}

$tmp = sys_get_temp_dir() . '/pfb-sw-cache-' . getmypid();
@mkdir($tmp, 0755, true);
$GLOBALS['pfb'] = ['dbdir' => $tmp];

$root_path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng';
require_once $root_path . '/pfblockerng_extra.inc';
require_once $root_path . '/pfblockerng_software.inc';

$cache = $tmp . '/software_update.json';
file_put_contents($cache, json_encode([
	'channel'       => 'stable',
	'installed'     => '3.3.2',
	'latest'        => ['unexpected' => 'array'],
	'last_checked'  => 1787000000,
	'last_notified' => null,
]));

$seen = [];
set_error_handler(static function (int $no, string $str) use (&$seen): bool {
	$seen[] = $str;
	return true;
});
try {
	$out = pfb_software_read_cache();
	// Force the (string) cast every consumer performs; unfiltered, this is what warns.
	$rendered = '';
	foreach ($out as $v) {
		$rendered .= (string) $v;
	}
} finally {
	restore_error_handler();
}

check(is_array($out), 'read_cache returns an array');
check(!array_key_exists('latest', $out), 'array-valued entry is dropped');
check(($out['channel'] ?? null) === 'stable', 'scalar entries survive');
check(($out['installed'] ?? null) === '3.3.2', 'installed survives');
check(!array_key_exists('last_notified', $out), 'stored NULL drops (recomputed live)');
check($seen === [], 'no diagnostic raised: ' . implode(' | ', $seen));

/* The matcher keeps its OWN guard: its verdict, not just its log line, depends on the
 * type. A caller handing over a cache array from anywhere else does not pass through
 * read_cache(), and a JSON null would otherwise coalesce to '' and match an install whose
 * own name is empty. */
$seen2 = [];
set_error_handler(static function (int $no, string $str) use (&$seen2): bool {
	$seen2[] = $str;
	return true;
});
try {
	$arr_name  = pfb_software_cache_matches_install(['pkgname' => ['a']], 'pfSense-pkg-pfBlockerNG', 'x');
	$null_name = pfb_software_cache_matches_install(['pkgname' => null], '', 'x');
	$arr_repo  = pfb_software_cache_matches_install(
		['pkgname' => 'pfSense-pkg-pfBlockerNG', 'repo' => ['a']], 'pfSense-pkg-pfBlockerNG', 'x'
	);
	$ok        = pfb_software_cache_matches_install(
		['pkgname' => 'pfSense-pkg-pfBlockerNG', 'repo' => 'x'], 'pfSense-pkg-pfBlockerNG', 'x'
	);
} finally {
	restore_error_handler();
}
check($arr_name === false, 'matcher refuses a non-scalar pkgname');
check($null_name === false, 'matcher refuses a null pkgname rather than matching empty');
check($arr_repo === false, 'matcher refuses a non-scalar repo');
check($ok === true, 'matcher still matches a well-formed cache');
check($seen2 === [], 'matcher raises no diagnostic: ' . implode(' | ', $seen2));

@unlink($cache);
@rmdir($tmp);

if ($failures === 0) {
	echo "ALL PASS\n";
	exit(0);
}
exit(1);
