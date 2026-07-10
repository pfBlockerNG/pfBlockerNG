<?php
declare(strict_types=1);

// ADR-62 perf-benchmark PHP worker: times pfb_unbound_python_sources()
// (the manifest writer -- the DNSBL download loop itself has no off-appliance
// driver, ADR.md SS1) over a pre-staged '.txt' feed of arbitrary size.
//
// Usage: php bench_dnsbl_line_parsing.php <worktree_root> <sandbox_dir> <iterations>
// <sandbox_dir>/dnsbl/benchfeed.txt must already exist (see the .py driver).
// Prints key=value lines; per-iteration timings go to stderr.

$worktree   = $argv[1];
$sandbox    = $argv[2];
$iterations = (int) $argv[3];

require_once "{$worktree}/tests/php/bootstrap.php";

@mkdir("{$sandbox}/db", 0777, true);

$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
	'log'                => "{$sandbox}/pfblockerng.log",
	'errlog'             => "{$sandbox}/error.log",
	'unbound_py_rawdir'  => "{$sandbox}/pfb_py_raw",
	'dnsdir'             => "{$sandbox}/dnsbl",
	'unbound_py_sources' => "{$sandbox}/pfb_py_sources.json",
	'dbdir'              => "{$sandbox}/db",
	'dnsbl_top1m'        => 'off',
	'dnsbl_tld_data'     => "{$sandbox}/does_not_exist",
	'dnsbl_unlock'       => "{$sandbox}/dnsbl_unlock",
	'dnsblconfig'        => [
		'tldblacklist' => '',
		'tldexclusion' => '',
		'suppression'  => '',
	],
]);

$feeds = [
	['header' => 'benchfeed', 'group' => 'grp', 'log' => '1', 'format' => 'plain', 'provenance' => 'feed'],
];

$durations = [];
for ($i = 0; $i < $iterations; $i++) {
	$t0 = microtime(true);
	pfb_unbound_python_sources($feeds);
	$durations[] = microtime(true) - $t0;
	fwrite(STDERR, sprintf("[php] iter %d: %.4fs\n", $i, end($durations)));
}
sort($durations);
$mid = (int) floor(count($durations) / 2);

printf("isolated_median_seconds=%.4f\n", $durations[$mid]);
printf("isolated_min_seconds=%.4f\n", $durations[0]);
printf("isolated_max_seconds=%.4f\n", $durations[count($durations) - 1]);

// Sanity: prove the raw output actually has the expected line count (not silently empty).
$rawFile = "{$sandbox}/pfb_py_raw/benchfeed.raw";
$lineCount = (int) exec('wc -l < ' . escapeshellarg($rawFile));
printf("raw_line_count=%d\n", $lineCount);
