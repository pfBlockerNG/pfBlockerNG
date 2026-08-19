<?php

declare(strict_types=1);

/*
 * logger() and localize_text() are pfSense-core helpers on Plus/master but are
 * absent from released CE <= 2.8.1. pfblockerng.inc calls both, so extra.inc
 * must supply guarded fallbacks or every caller fatals on CE. Regression cover
 * for a shipped 3.3.2 that reached CE 2.8.1 without them: sync_package_pfblockerng()
 * died on "Call to undefined function logger()" and pfb_filter never started.
 */

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];

function config_get_path(string $path, mixed $default = null): mixed
{
	return $default;
}

function config_set_path(string $path, mixed $value): void
{
}

function write_config(string $desc = ''): void
{
}

function pfb_global(): void
{
}

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

/* Neither helper exists in this process before extra.inc is loaded — the same
 * starting condition as a CE 2.8.1 box. */
check(!function_exists('logger'), 'logger() absent before extra.inc');
check(!function_exists('localize_text'), 'localize_text() absent before extra.inc');

/* Standalone resolver setup must log mount failures without the package fallback. */
$unbound = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfb_unbound_include.inc';
$unbound_source = file_get_contents($unbound);
check(
	is_string($unbound_source)
		&& preg_match('/function pfb_python_mount\\b.*?^\\}/ms', $unbound_source, $mount_function) === 1,
	'pfb_python_mount() source is readable'
);

$mount_errors = [];
$mount_exists = FALSE;
$mount_command_fails = FALSE;
function log_error(string $message): void
{
	global $mount_errors;
	$mount_errors[] = $message;
}

function pfb_test_exec(string $command, mixed &$output, mixed &$retval): void
{
	global $mount_exists, $mount_command_fails;
	if (str_starts_with($command, '/sbin/mount |')) {
		$output = $mount_exists ? ['fixture mounted'] : [];
		$retval = $mount_exists ? 0 : 1;
		return;
	}
	$output = $mount_command_fails ? ['forced failure'] : [];
	$retval = $mount_command_fails ? 1 : 0;
}

function safe_mkdir(string $path): void
{
}

$mount_source = str_replace('exec(', 'pfb_test_exec(', $mount_function[0], $exec_count);
check($exec_count === 5, 'all pfb_python_mount() commands are isolated');
eval($mount_source);
foreach (
	[
		[TRUE, FALSE, TRUE, 'mount failure', '[Unbound-pymod]: Failed to mount /pfb-test-noop'],
		[TRUE, FALSE, FALSE, 'mount success', NULL],
		[FALSE, TRUE, TRUE, 'unmount failure', '[Unbound-pymod]: Failed to unmount /pfb-test-noop'],
		[FALSE, TRUE, FALSE, 'unmount success', NULL],
	] as [$python_mode, $mounted, $command_fails, $operation, $expected_error]
) {
	$mount_exists = $mounted;
	$mount_command_fails = $command_fails;
	$error_count = count($mount_errors);
	$threw = FALSE;
	try {
		pfb_python_mount(
			$python_mode,
			FALSE,
			'pfb-test-invalid',
			'pfb-test-invalid',
			'',
			'pfb-test-noop',
			'fixture'
		);
	} catch (Throwable $e) {
		$threw = TRUE;
	}
	$logged_expected = $expected_error === NULL
		? count($mount_errors) === $error_count
		: count($mount_errors) === $error_count + 1 && end($mount_errors) === $expected_error;
	check(
		!$threw && $logged_expected,
		"{$operation} logs without logger() fallback"
	);
}
check(
	$mount_errors === [
		'[Unbound-pymod]: Failed to mount /pfb-test-noop',
		'[Unbound-pymod]: Failed to unmount /pfb-test-noop',
	],
	'mount and unmount failures use log_error()'
);

$extra = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
require_once $extra;

check(function_exists('logger'), 'extra.inc defines logger() fallback');
check(function_exists('localize_text'), 'extra.inc defines localize_text() fallback');

/* The guards must be conditional so core wins on Plus/master. */
$source = file_get_contents($extra);
check(
	is_string($source) && str_contains($source, "if (!function_exists('logger'))"),
	'logger() fallback is guarded by function_exists'
);
check(
	is_string($source) && str_contains($source, "if (!function_exists('localize_text'))"),
	'localize_text() fallback is guarded by function_exists'
);

/* Behaviour: single argument passes through, extra arguments format. */
check(localize_text('plain string') === 'plain string', 'localize_text() returns single argument');
check(localize_text('%s-%s', 'a', 'b') === 'a-b', 'localize_text() formats with sprintf');

/* logger() must accept the call shape pfblockerng.inc uses and not throw. */
$threw = false;
try {
	logger(LOG_NOTICE, localize_text('regression probe'), 'pfBlockerNG');
} catch (Throwable $e) {
	$threw = true;
}
check(!$threw, 'logger(priority, message, prefix) callable without error');

if ($failures === 0) {
	echo "ALL PASS\n";
	exit(0);
}
exit(1);
