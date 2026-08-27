<?php

declare(strict_types=1);

/**
 * Shared off-appliance loader for pfb_ledger_entry_html()/pfb_dnsbl_category_schedule_html().
 *
 * Unlike pfblockerng_alerts.php (AlertsPageLoader.php), pfblockerng_update.php
 * interleaves function definitions with top-level page-building code (head.inc,
 * display_top_tabs(), ...) -- so "from the first `function` keyword" would pull in
 * unrunnable top-level statements too. These two formatters ARE contiguous with
 * EACH OTHER, immediately followed by `// Create Form` (the page's Form-building
 * code): extract exactly that span, not the whole file's first-function-onward tail.
 */
function pfb_test_load_update_page_functions(): void
{
	if (function_exists('pfb_ledger_entry_html')) {
		return;
	}
	$src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php'
	);
	if ($src === false) {
		throw new RuntimeException('failed to read pfblockerng_update.php');
	}
	$start = strpos($src, "\nfunction pfb_ledger_entry_html");
	$end   = strpos($src, "\n// Create Form");
	if ($start === false || $end === false || $end <= $start) {
		throw new RuntimeException('could not locate the pfb_ledger_entry_html/pfb_dnsbl_category_schedule_html block');
	}
	eval("\n" . substr($src, $start + 1, $end - $start - 1));
}
