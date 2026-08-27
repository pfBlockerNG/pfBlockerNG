<?php

declare(strict_types=1);

/**
 * Shared off-appliance loader for the pfblockerng_feeds.php predefined-feeds render
 * block: url_compare() and pfb_feeds_render_predefined_type() (issue #1330).
 *
 * pfblockerng_feeds.php carries top-level execution (require_once + POST handling +
 * head.inc) and cannot be require()d off-appliance. Both target functions are
 * self-contained top-level `function` declarations with no pfSense-runtime calls in
 * their bodies, so — same pattern as AlertsPageLoader.php — the source is read, its
 * top-of-file require_once() lines are stripped, and everything from the first
 * `function` keyword up to the first top-level statement that follows the block
 * (`$type_label = array(...)`, which precedes the page's head.inc include) is eval'd
 * verbatim. No production file is modified to make it testable.
 */
function pfb_test_load_feeds_predefined_type_functions(): void
{
	if (function_exists('url_compare')) {
		return;
	}
	$src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php'
	);
	if ($src === false) {
		throw new RuntimeException('failed to read pfblockerng_feeds.php');
	}
	$src = preg_replace('/^\s*require_once\(.*\);\s*$/m', '', $src);
	$start = strpos($src, "\nfunction ");
	$end   = strpos($src, "\n\$type_label = array(");
	if ($start === false || $end === false || $end <= $start) {
		throw new RuntimeException('could not locate the function block in pfblockerng_feeds.php');
	}
	eval("\n" . substr($src, $start + 1, $end - $start - 1));
}
