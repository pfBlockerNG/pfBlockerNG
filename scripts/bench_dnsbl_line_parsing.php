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
if ($iterations < 1) {
	fwrite(STDERR, "iterations must be a positive integer\n");
	exit(1);
}

require_once "{$worktree}/tests/php/bootstrap.php";

@mkdir("{$sandbox}/db", 0777, TRUE);

$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
	'log'                => "{$sandbox}/pfblockerng.log",
	'errlog'             => "{$sandbox}/error.log",
	'unbound_py_rawdir'  => "{$sandbox}/pfb_py_raw",
	'dnsdir'             => "{$sandbox}/dnsbl",
	'unbound_py_sources' => "{$sandbox}/pfb_py_sources.json",
	'dbdir'              => "{$sandbox}/db",
	'dnsbl_top1m'        => 'off',
	'dnsbl_unlock'       => "{$sandbox}/dnsbl_unlock",
	'dnsblconfig'        => [
		'tld_wildcard_blacklist' => '',
		'tld_wildcard_exclusion' => '',
		'suppression'  => '',
	],
]);

$feeds = [
	['header' => 'benchfeed', 'group' => 'grp', 'log' => '1', 'format' => 'plain', 'provenance' => 'feed'],
];

$durations = [];
for ($i = 0; $i < $iterations; $i++) {
	$t0 = microtime(TRUE);
	pfb_unbound_python_sources($feeds);
	$durations[] = microtime(TRUE) - $t0;
	fwrite(STDERR, sprintf("[php] iter %d: %.4fs\n", $i, end($durations)));
}
sort($durations);
$mid = (int) floor(count($durations) / 2);

printf("isolated_median_seconds=%.4f\n", $durations[$mid]);
printf("isolated_min_seconds=%.4f\n", $durations[0]);
printf("isolated_max_seconds=%.4f\n", $durations[count($durations) - 1]);

// Sanity: a missing/empty raw output means the pipeline never ran -- fail, never
// report timings for a no-op (a broken worker must not read as a perf PASS).
$manifest = json_decode((string) file_get_contents("{$sandbox}/pfb_py_sources.json"), TRUE);
$rawRef = $manifest['feeds'][0]['raw'] ?? NULL;
$sandboxReal = realpath($sandbox);
$rawFile = is_string($rawRef) && $rawRef !== '' && !str_contains($rawRef, "\0")
	? "{$sandbox}/{$rawRef}" : '';
$rawReal = $rawFile !== '' ? realpath($rawFile) : FALSE;
if ($sandboxReal === FALSE || $rawReal === FALSE
		|| ($rawReal !== $sandboxReal && !str_starts_with($rawReal, "{$sandboxReal}/"))
		|| !is_file($rawReal) || filesize($rawReal) === 0) {
	fwrite(STDERR, "benchmark output missing, empty, or outside sandbox: {$rawFile}\n");
	exit(1);
}
$rawFile = $rawReal;
$lineCount = (int) exec('wc -l < ' . escapeshellarg($rawFile));
printf("raw_line_count=%d\n", $lineCount);
