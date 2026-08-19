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
