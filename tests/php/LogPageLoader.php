<?php

declare(strict_types=1);

/**
 * Shared off-appliance loader for pfb_validate_filepath() (pfblockerng_log.php).
 *
 * Unlike AlertsPageLoader.php/UpdatePageLoader.php, this function takes
 * $pfb_logtypes as a plain PARAMETER (not a global read) and calls no pfSense
 * runtime function -- so no surrounding top-level wiring or fixture is needed:
 * extract just the function's own span (its `function` line up to the next
 * top-level statement, `$pconfig = ...`) and eval it. The end marker stops at the
 * assignment operator, like AlertsPageLoader's, so rewriting the initialiser
 * (array() -> []) cannot strand it.
 */
function pfb_test_load_log_page_functions(): void
{
	if (function_exists('pfb_validate_filepath')) {
		return;
	}
	$src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_log.php'
	);
	if ($src === false) {
		throw new RuntimeException('failed to read pfblockerng_log.php');
	}
	$start = strpos($src, "\nfunction pfb_validate_filepath");
	$end   = strpos($src, "\n\$pconfig = ");
	if ($start === false || $end === false || $end <= $start) {
		throw new RuntimeException('could not locate pfb_validate_filepath() in pfblockerng_log.php');
	}
	eval("\n" . substr($src, $start + 1, $end - $start - 1));
}
