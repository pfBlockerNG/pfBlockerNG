<?php

declare(strict_types=1);

/**
 * Shared off-appliance loader for the pfblockerng_alerts.php function block.
 *
 * Three sibling test classes (WhitelistTrashIconTest, AlertsRowOutputEncodingTest,
 * AlertsIpConvertPrefetchParityTest) each need convert_ip_log() / convert_dnsbl_log() /
 * pfb_whitelist_trash_icon() and friends defined off-appliance, without running the
 * page's top-level render wiring (which needs a live pfSense runtime). All of them
 * live in ONE contiguous function block in the page source, so one load covers every
 * caller: read the source, strip its top-of-file require_once() lines (the bootstrap
 * has already loaded the real pfblockerng.inc + shims), and eval only from the first
 * `function` keyword up to the first top-level statement that follows the block --
 * `$pgtitle = array(...)`, which precedes include_once('head.inc') and
 * display_top_tabs(). No production file is modified to make it testable.
 */
function pfb_test_load_alerts_page_functions(): void
{
	if (function_exists('convert_ip_log')) {
		return;
	}
	$src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
	);
	if ($src === false) {
		throw new RuntimeException('failed to read pfblockerng_alerts.php');
	}
	$src = preg_replace('/^\s*require_once\(.*\);\s*$/m', '', $src);
	$start = strpos($src, "\nfunction ");
	$end   = strpos($src, "\n\$pgtitle = ");
	if ($start === false || $end === false || $end <= $start) {
		throw new RuntimeException('could not locate the function block in pfblockerng_alerts.php');
	}
	eval("\n" . substr($src, $start + 1, $end - $start - 1));
}
