<?php

declare(strict_types=1);

// Issue #1542 dev-host benchmark worker. The Python driver starts one fresh
// process per trial and wraps it with /usr/bin/time for peak RSS.

if ($argc !== 5 || !in_array($argv[1], ['write', 'patch'], TRUE)) {
	fwrite(STDERR, "usage: php bench_top1m_fixed_file.php write|patch WORKTREE SANDBOX EXPECTED_LINES\n");
	exit(2);
}

[$script, $phase, $worktree, $sandbox, $expected_arg] = $argv;
$expected_lines = (int) $expected_arg;
$sample_domain = 'top1m-0000000.benchmark.invalid';

require_once "{$worktree}/tests/php/bootstrap.php";

@mkdir("{$sandbox}/db", 0777, TRUE);
@mkdir("{$sandbox}/dnsbl", 0777, TRUE);

$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
	'log'                 => "{$sandbox}/pfblockerng.log",
	'errlog'              => "{$sandbox}/error.log",
	'unbound_py_rawdir'   => "{$sandbox}/pfb_py_raw",
	'unbound_py_sources'  => "{$sandbox}/pfb_py_sources.json",
	'unbound_py_top1m'    => "{$sandbox}/pfb_py_top1m.txt",
	'dnsdir'              => "{$sandbox}/dnsbl",
	'dbdir'               => "{$sandbox}/db",
	'dnsbl_top1m'         => 'on',
	'dnsbl_tld_wildcard'  => '',
	'dnsbl_tld_data'      => "{$sandbox}/does_not_exist",
	'dnsbl_unlock'        => "{$sandbox}/dnsbl_unlock",
	'dnsblconfig'         => [
		'tldblacklist' => '',
		'tldexclusion' => '',
		'suppression'  => '',
	],
]);

function benchmark_manifest_contains_key(array $value, string $needle): bool
{
	foreach ($value as $key => $child) {
		if ($key === $needle) {
			return TRUE;
		}
		if (is_array($child) && benchmark_manifest_contains_key($child, $needle)) {
			return TRUE;
		}
	}
	return FALSE;
}

function benchmark_read_manifest(string $path, string $sample_domain): array
{
	$json = @file_get_contents($path);
	$manifest = is_string($json) ? json_decode($json, TRUE) : NULL;
	if (!is_array($manifest)) {
		throw new RuntimeException("manifest missing or invalid: {$path}");
	}
	foreach (['top1m_list', 'top1m_ref'] as $retired_key) {
		if (benchmark_manifest_contains_key($manifest, $retired_key)) {
			throw new RuntimeException("manifest contains retired key: {$retired_key}");
		}
	}
	if (str_contains($json, $sample_domain)) {
		throw new RuntimeException('manifest contains sampled TOP1M domain');
	}
	return $manifest;
}

try {
	if ($phase === 'write') {
		$fixture = "{$sandbox}/db/pfbalexawhitelist.txt";
		if (!is_file($fixture)) {
			throw new RuntimeException("TOP1M fixture missing: {$fixture}");
		}
		$start = hrtime(TRUE);
		$result = pfb_unbound_python_sources([], [
			// Dev hosts need not have the appliance's root:unbound identities.
			// Only metadata ownership is substituted; real stream/copy/fsync/rename
			// and the real manifest writer remain on the timed path.
			'top1m_atomic' => [
				'chown' => static fn(string $file, string $owner): bool => TRUE,
				'chgrp' => static fn(string $file, string $group): bool => TRUE,
				'chmod' => static fn(string $file, int $mode): bool => TRUE,
			],
		]);
		$elapsed = (hrtime(TRUE) - $start) / 1_000_000_000;
		if (!is_array($result)) {
			throw new RuntimeException('pfb_unbound_python_sources returned failure');
		}
		$manifest = benchmark_read_manifest($GLOBALS['pfb']['unbound_py_sources'], $sample_domain);
		if (($manifest['config']['top1m_enabled'] ?? NULL) !== TRUE) {
			throw new RuntimeException('manifest did not enable fixed-file TOP1M');
		}

		$fixed = $GLOBALS['pfb']['unbound_py_top1m'];
		$handle = @fopen($fixed, 'rb');
		if ($handle === FALSE) {
			throw new RuntimeException("fixed TOP1M output missing: {$fixed}");
		}
		$line_count = 0;
		while (fgets($handle) !== FALSE) {
			$line_count++;
		}
		fclose($handle);
		if ($line_count !== $expected_lines) {
			throw new RuntimeException("fixed TOP1M line count {$line_count}; expected {$expected_lines}");
		}

		printf("wall_seconds=%.9f\n", $elapsed);
		printf("manifest_bytes=%d\n", filesize($GLOBALS['pfb']['unbound_py_sources']));
		printf("fixed_bytes=%d\n", filesize($fixed));
		printf("fixed_lines=%d\n", $line_count);
		exit(0);
	}

	$start = hrtime(TRUE);
	$ok = pfb_unbound_python_sources_patch('user_unlock', ['benchmark-unlock.invalid']);
	$elapsed = (hrtime(TRUE) - $start) / 1_000_000_000;
	if (!$ok) {
		throw new RuntimeException('pfb_unbound_python_sources_patch returned failure');
	}
	$manifest = benchmark_read_manifest($GLOBALS['pfb']['unbound_py_sources'], $sample_domain);
	if (($manifest['config']['user_unlock'] ?? NULL) !== ['benchmark-unlock.invalid']) {
		throw new RuntimeException('scalar manifest patch was not observable');
	}
	printf("wall_seconds=%.9f\n", $elapsed);
	printf("manifest_bytes=%d\n", filesize($GLOBALS['pfb']['unbound_py_sources']));
} catch (Throwable $error) {
	fwrite(STDERR, "benchmark assertion failed: {$error->getMessage()}\n");
	exit(1);
}
