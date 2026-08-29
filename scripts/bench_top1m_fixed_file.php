<?php

declare(strict_types=1);

// Issue #1542 dev-host benchmark worker. The Python driver starts one fresh
// process per trial and wraps it with /usr/bin/time for peak RSS.

if ($argc !== 6 || !in_array($argv[1], ['write', 'patch'], TRUE)
	|| !in_array($argv[2], ['embedded', 'fixed'], TRUE)) {
	fwrite(STDERR,
		"usage: php bench_top1m_fixed_file.php write|patch embedded|fixed WORKTREE SANDBOX EXPECTED_LINES\n");
	exit(2);
}

[$script, $phase, $contract, $worktree, $sandbox, $expected_arg] = $argv;
$expected_lines = (int) $expected_arg;
$sample_domain = 'top1m-0000000.benchmark.invalid';
$last_domain = sprintf('top1m-%07d.benchmark.invalid', $expected_lines - 1);

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
	'dnsbl_unlock'        => "{$sandbox}/dnsbl_unlock",
	'dnsblconfig'         => [
		'tld_wildcard_blacklist' => '',
		'tld_wildcard_exclusion' => '',
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

function benchmark_read_manifest(string $path, string $contract, int $expected_lines,
	string $sample_domain, string $last_domain): array
{
	$json = @file_get_contents($path);
	$manifest = is_string($json) ? json_decode($json, TRUE) : NULL;
	if (!is_array($manifest)) {
		throw new RuntimeException("manifest missing or invalid: {$path}");
	}
	if (benchmark_manifest_contains_key($manifest, 'top1m_ref')) {
		throw new RuntimeException('manifest contains unsupported key: top1m_ref');
	}
	$top1m_list = $manifest['config']['top1m_list'] ?? NULL;
	if ($contract === 'embedded') {
		if (!is_array($top1m_list) || count($top1m_list) !== $expected_lines
			|| ($top1m_list[0] ?? NULL) !== $sample_domain
			|| ($top1m_list[$expected_lines - 1] ?? NULL) !== $last_domain) {
			throw new RuntimeException('embedded TOP1M contract missing exact deterministic domain list');
		}
	} elseif (benchmark_manifest_contains_key($manifest, 'top1m_list') || str_contains($json, $sample_domain)) {
		throw new RuntimeException('fixed-file TOP1M contract leaked list or sampled domain into manifest');
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
		$manifest = benchmark_read_manifest($GLOBALS['pfb']['unbound_py_sources'], $contract,
			$expected_lines, $sample_domain, $last_domain);
		if (($manifest['config']['top1m_enabled'] ?? NULL) !== TRUE) {
			throw new RuntimeException('manifest did not enable TOP1M');
		}

		$fixed = $GLOBALS['pfb']['unbound_py_top1m'];
		$fixed_bytes = 0;
		if ($contract === 'fixed') {
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
			$fixed_bytes = (int) filesize($fixed);
		} elseif (file_exists($fixed)) {
			throw new RuntimeException('embedded TOP1M writer unexpectedly published fixed sidecar');
		}

		printf("wall_seconds=%.9f\n", $elapsed);
		printf("manifest_bytes=%d\n", filesize($GLOBALS['pfb']['unbound_py_sources']));
		printf("fixed_bytes=%d\n", $fixed_bytes);
		printf("top1m_lines=%d\n", $expected_lines);
		exit(0);
	}

	$start = hrtime(TRUE);
	$ok = pfb_unbound_python_sources_patch('user_unlock', ['benchmark-unlock.invalid']);
	$elapsed = (hrtime(TRUE) - $start) / 1_000_000_000;
	if (!$ok) {
		throw new RuntimeException('pfb_unbound_python_sources_patch returned failure');
	}
	$manifest = benchmark_read_manifest($GLOBALS['pfb']['unbound_py_sources'], $contract,
		$expected_lines, $sample_domain, $last_domain);
	if (($manifest['config']['user_unlock'] ?? NULL) !== ['benchmark-unlock.invalid']) {
		throw new RuntimeException('scalar manifest patch was not observable');
	}
	printf("wall_seconds=%.9f\n", $elapsed);
	printf("manifest_bytes=%d\n", filesize($GLOBALS['pfb']['unbound_py_sources']));
} catch (Throwable $error) {
	fwrite(STDERR, "benchmark assertion failed: {$error->getMessage()}\n");
	exit(1);
}
