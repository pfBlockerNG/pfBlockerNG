<?php

declare(strict_types=1);

/** Standalone #2532/#697 assertions for the release/3.3 source tree. */

$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
if (!is_string($source)) {
	throw new RuntimeException('pfblockerng.inc is unreadable');
}

$failures = 0;
$status_messages = [];
$log_messages = [];

defined('LOG_NOTICE') || define('LOG_NOTICE', 5);
define('LOG_PREFIX_PKG_PFBLOCKERNG', 'pfBlockerNG');

function update_status(string $message): void
{
	$GLOBALS['status_messages'][] = $message;
}

function logger(int $priority, string $message, string $prefix): void
{
	$GLOBALS['log_messages'][] = [$priority, $message, $prefix];
}

function localize_text(string $message): string
{
	return $message;
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

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function same(mixed $expected, mixed $actual, string $message): void
{
	if ($expected !== $actual) {
		throw new RuntimeException($message . ' expected=' . var_export($expected, true) . ' actual=' . var_export($actual, true));
	}
}

function function_source(string $source, string $name): string
{
	$start = strpos($source, "function {$name}");
	if ($start === false) {
		throw new RuntimeException("missing {$name}");
	}
	$open = strpos($source, '{', $start);
	if ($open === false) {
		throw new RuntimeException("missing {$name} body");
	}
	$depth = 0;
	$length = strlen($source);
	for ($i = $open; $i < $length; $i++) {
		if ($source[$i] === '{') {
			$depth++;
		} elseif ($source[$i] === '}' && --$depth === 0) {
			return substr($source, $start, $i - $start + 1);
		}
	}
	throw new RuntimeException("unterminated {$name}");
}

function slice_from_function(string $source, string $name): string
{
	$start = strpos($source, "function {$name}");
	check($start !== false, "missing {$name}");
	$end = strpos($source, "\n}\n", $start);
	check($end !== false, "missing end of {$name}");
	return substr($source, $start, $end + 2 - $start);
}

row('operation helpers are present and unique', static function () use ($source): void {
	foreach (['pfb_pkg_argv_subcommand', 'pfb_parse_pkg_operation', 'pfb_pkg_operation', 'pfb_pkg_op_tears_down'] as $name) {
		same(1, substr_count($source, "function {$name}"), "{$name} count");
	}
	foreach (['pfb_pkg_argv_subcommand', 'pfb_parse_pkg_operation', 'pfb_pkg_op_tears_down'] as $name) {
		eval(function_source($source, $name));
	}
});

row('argv grammar classifies package operations', static function (): void {
	$cases = [
		[['pkg', 'install'], 'install'],
		[['pkg', 'install', '-f'], 'reinstall'],
		[['pkg', 'install', '--force'], 'reinstall'],
		[['pkg', 'install', '-fy'], 'reinstall'],
		[['pkg', 'add'], 'install'],
		[['pkg', 'add', '-f', '/tmp/pfSense-pkg-pfBlockerNG.pkg'], 'reinstall'],
		[['pkg', 'upgrade'], 'upgrade'],
		[['pkg', 'delete'], 'delete'],
		[['pkg', 'remove'], 'delete'],
		[['pkg', 'autoremove'], 'delete'],
		[['pkg', 'info'], ''],
		[[], ''],
		[['pkg', '-r'], ''],
		[['pkg', '-j'], ''],
		[['pkg', '--rootdir'], ''],
		[['pkg', '-r', '/root', 'delete'], 'delete'],
		[['pkg', '-r/root', 'delete'], 'delete'],
		[['pkg', '-jname', 'install'], 'install'],
		[['pkg', '--rootdir=/root', 'delete'], 'delete'],
		[['pkg', '--option', 'value', 'upgrade'], 'upgrade'],
		[['pkg', '--jail', '/jail', 'install'], 'install'],
		[['pkg', '-4', '-y', 'install', '-f'], 'reinstall'],
		[['/fake/pkg-helper', 'delete'], 'delete'],
	];
	foreach ($cases as [$argv, $expected]) {
		same($expected, pfb_pkg_argv_subcommand($argv), implode(' ', $argv));
	}
});

function process_chain(string $pkgCommand): array
{
	$lines = ['  PID  PPID COMMAND'];
	$lines[] = ' 100   90 /usr/local/bin/php -f hook.php';
	$lines[] = '  90   80 /bin/sh -c rc.packages';
	$lines[] = "  80    1 {$pkgCommand}";
	return $lines;
}

row('process ancestry is fail-safe and bounded', static function (): void {
	same('delete', pfb_parse_pkg_operation(process_chain('pkg delete -y'), 100), 'pkg ancestor');
	same('upgrade', pfb_parse_pkg_operation(process_chain('pkg-static upgrade'), 100), 'pkg-static ancestor');
	same('', pfb_parse_pkg_operation([
		'PID PPID COMMAND',
		'not a process row',
		'100 90 /usr/local/bin/php',
		'90 1 /usr/sbin/cron',
	], 100), 'malformed and no pkg rows');
	same('', pfb_parse_pkg_operation([
		'100 100 /usr/local/bin/php',
	], 100), 'self parent');
	same('', pfb_parse_pkg_operation([
		'100 90 /usr/local/bin/php',
		'90 100 /bin/sh',
		'80 1 pkg delete',
	], 100), 'cycle');
	$inside = [];
	for ($pid = 100; $pid < 163; $pid++) {
		$inside[] = "{$pid} " . ($pid + 1) . ' /bin/sh';
	}
	$inside[] = '163 1 pkg delete';
	same('delete', pfb_parse_pkg_operation($inside, 100), '63rd ancestor is examined');
	$outside = [];
	for ($pid = 100; $pid < 164; $pid++) {
		$outside[] = "{$pid} " . ($pid + 1) . ' /bin/sh';
	}
	$outside[] = '164 1 pkg delete';
	same('', pfb_parse_pkg_operation($outside, 100), '64-hop bound excludes next ancestor');
	same('', pfb_parse_pkg_operation(process_chain('/usr/local/sbin/pkg-helper delete'), 100), 'fake pkg command');
	same('delete', pfb_parse_pkg_operation([
		'100 90 /usr/local/bin/php hook.php',
		'90 80 /tmp/pkg install -f',
		'80 1 /usr/local/sbin/pkg delete',
	], 100), 'fake exact-basename child skipped for real pkg ancestor');
	same('', pfb_parse_pkg_operation(process_chain('pkg unknown'), 100), 'unknown command');
});

row('teardown decision requires a positive delete', static function (): void {
	check(pfb_pkg_op_tears_down('delete'), 'delete tears down');
	foreach (['', 'install', 'reinstall', 'upgrade'] as $op) {
		check(!pfb_pkg_op_tears_down($op), "{$op} stays live");
	}
});

row('real pre-deinstall function returns before teardown on upgrade', static function () use ($source): void {
	$fixture = sys_get_temp_dir() . '/pfb-predeinstall-' . bin2hex(random_bytes(5));
	mkdir($fixture, 0700, true);
	file_put_contents($fixture . '/config.inc', "<?php\n");
	$old_include_path = get_include_path();
	set_include_path($fixture . PATH_SEPARATOR . $old_include_path);
	try {
		eval(function_source($source, 'pfblockerng_php_pre_deinstall_command'));
		$GLOBALS['pfb'] = [];
		$GLOBALS['status_messages'] = [];
		pfblockerng_php_pre_deinstall_command(static fn (): string => 'upgrade');
		check(
			count($GLOBALS['status_messages']) === 1
				&& str_contains($GLOBALS['status_messages'][0], 'Keeping pfBlockerNG active'),
			'upgrade returns through the live guard'
		);
	} finally {
		set_include_path($old_include_path);
		@unlink($fixture . '/config.inc');
		@rmdir($fixture);
	}
});

row('unknown operation is labeled and logged before preserving state', static function (): void {
	$fixture = sys_get_temp_dir() . '/pfb-predeinstall-unknown-' . bin2hex(random_bytes(5));
	mkdir($fixture, 0700, true);
	file_put_contents($fixture . '/config.inc', "<?php\n");
	$old_include_path = get_include_path();
	set_include_path($fixture . PATH_SEPARATOR . $old_include_path);
	$GLOBALS['status_messages'] = [];
	$GLOBALS['log_messages'] = [];
	try {
		pfblockerng_php_pre_deinstall_command(static fn (): string => '');
		check(
			count($GLOBALS['status_messages']) === 1
				&& str_contains($GLOBALS['status_messages'][0], "operation 'unknown'"),
			'unknown operation status label'
		);
		check(
			count($GLOBALS['log_messages']) === 1
				&& str_contains($GLOBALS['log_messages'][0][1], 'Package operation not detected'),
			'unknown operation log'
		);
	} finally {
		set_include_path($old_include_path);
		@unlink($fixture . '/config.inc');
		@rmdir($fixture);
	}
});

row('pre-deinstall guard precedes all mutation', static function () use ($source): void {
	$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
	check($start !== false, 'pre-deinstall missing');
	$block = slice_from_function($source, 'pfblockerng_php_pre_deinstall_command');
	$operation = strpos($block, '$pfb_pkg_op = pfb_pkg_operation();');
	$decision = strpos($block, 'if (!pfb_pkg_op_tears_down($pfb_pkg_op))');
	$save = strpos($block, "\$pfb['save'] = \$pfb['install'] = TRUE;");
	$sync = strpos($block, 'sync_package_pfblockerng();');
	check($operation !== false && $decision !== false && $save !== false && $sync !== false, 'guard markers');
	check($operation < $decision && $decision < $save && $save < $sync, 'guard source order');
	check(strpos(substr($block, $decision), 'return;') !== false, 'non-teardown path returns');
	check(str_contains($block, "if (\$pfb['keep'] != 'on')"), 'real delete keep-settings branch retained');
	check(str_contains($block, 'pfb_remove_config_settings();'), 'real delete config removal retained');
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
