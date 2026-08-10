<?php

declare(strict_types=1);

$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
$failures = 0;
$root = sys_get_temp_dir() . '/pfb_alias_reload_v3216_' . bin2hex(random_bytes(5));
mkdir($root, 0700, true);
$log = $root . '/pfctl.log';
$pfctl = $root . '/pfctl';
file_put_contents($pfctl, <<<'SH'
#!/bin/sh
if [ "$1" = "-s" ] && [ "$2" = "Tables" ]; then
	printf '%s\n' pfB_updated pfB_unchanged pfB_inactive
	exit 0
fi
printf '%s\n' "$*" >> "$PFB_TEST_PFCTL_LOG"
SH);
chmod($pfctl, 0700);
putenv("PFB_TEST_PFCTL_LOG={$log}");

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function same(mixed $expected, mixed $actual, string $message): void
{
	if ($expected !== $actual) {
		throw new RuntimeException($message . ': expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
	}
}

function row(string $name, callable $test): void
{
	global $failures;
	try {
		$test();
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	}
}

function source_slice(string $source, string $startNeedle, string $endNeedle, int $offset = 0): string
{
	$start = strpos($source, $startNeedle, $offset);
	check($start !== false, "missing source marker {$startNeedle}");
	$end = strpos($source, $endNeedle, $start);
	check($end !== false && $end > $start, "missing source marker {$endNeedle}");
	return substr($source, $start, $end - $start);
}

row('autorules and removal initialize active-alias tracking', static function () use ($source): void {
	$start = strpos($source, '$pfb_active_aliases = null;');
	check($start !== false, 'active-alias initialization missing');
	$set = '$pfb_active_aliases = [];';
	$end = strpos($source, $set, $start);
	check($end !== false, 'active-alias rule-path initialization missing');
	$snippet = substr($source, $start, $end + strlen($set) - $start) . "\n}";

	foreach (
		[
			'autorules' => [['autorules' => true, 'enable' => 'on', 'remove' => false], []],
			'removal' => [['autorules' => false, 'enable' => 'on', 'remove' => true], []],
			'no rule work' => [['autorules' => false, 'enable' => 'on', 'remove' => false], null],
		] as $name => [$pfb, $expected]
	) {
		$pfb_active_aliases = 'unset';
		eval($snippet);
		same($expected, $pfb_active_aliases, $name);
	}
});

row('source and destination rule aliases are tracked uniquely', static function () use ($source): void {
	$snippet = source_slice(
		$source,
		'// Track pfB aliases referenced by rules.',
		"// Remove 'created' tag",
	);
	$pfb_active_aliases = [];
	foreach (
		[
			['source' => ['address' => 'pfB_source'], 'destination' => ['address' => 'any']],
			['source' => ['address' => 'pfB_source'], 'destination' => ['address' => 'pfB_destination']],
		] as $rule
	) {
		eval($snippet);
	}
	same(['pfB_source', 'pfB_destination'], $pfb_active_aliases, 'tracked rule aliases');
});

row('updated active tables replace, unchanged active tables survive, inactive tables die', static function () use ($source, $pfctl, $root, $log): void {
	$sync = strpos($source, 'function sync_package_pfblockerng');
	$block = source_slice(
		$source,
		'exec("{$pfb[\'pfctl\']} -s Tables | {$pfb[\'grep\']} \'^pfB_\'", $pfb_tables);',
		"\$pfb['filter_configure'] = TRUE;",
		$sync,
	);
	foreach ([false, true] as $reputation) {
		@unlink($log);
		$pfb = [
			'pfctl' => $pfctl,
			'grep' => '/usr/bin/grep',
			'aliasdir' => $root,
			'repcheck' => $reputation,
			'drep' => $reputation ? 'on' : '',
			'prep' => '',
		];
		$pfb_active_aliases = ['pfB_updated', 'pfB_unchanged'];
		$pfb_alias_lists = $reputation ? [] : ['pfB_updated'];
		$pfb_alias_lists_all = $reputation ? ['pfB_updated'] : [];
		unset($pfb_tables);
		eval($block);
		$commands = file($log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		check(count(array_filter($commands, static fn(string $line): bool => str_contains($line, '-t pfB_updated -T replace -f '))) === 1, 'updated active table not replaced');
		check(count(array_filter($commands, static fn(string $line): bool => str_contains($line, 'pfB_unchanged'))) === 0, 'unchanged active table was modified');
		check(count(array_filter($commands, static fn(string $line): bool => $line === '-t pfB_inactive -T kill')) === 1, 'inactive table not killed');
	}
});

@unlink($log);
@unlink($pfctl);
@rmdir($root);
echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
