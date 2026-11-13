<?php

declare(strict_types=1);

/**
 * Hermetic access to REAL www-page source: the pages cannot be require()d off-appliance (top-level
 * rendering), so a test extracts the page's own statement/region verbatim and evals it with the
 * page's variables in scope. A test therefore fails when the SHIPPED page changes behaviour --
 * never when a hand-copied stand-in drifts (same rationale as Issue1792SweepSiteLoader.php).
 */

function pfb_test_page_source(string $relpath): string
{
	$src = file_get_contents(dirname(__DIR__, 2) . '/' . $relpath);
	if ($src === FALSE) {
		throw new RuntimeException("test bootstrap: failed to read {$relpath}");
	}
	return $src;
}

/** The first statement of $relpath that starts at a match of $pattern, through its closing ';'. */
function pfb_test_page_statement(string $relpath, string $pattern): string
{
	$src = pfb_test_page_source($relpath);
	if (preg_match($pattern, $src, $match, PREG_OFFSET_CAPTURE) !== 1) {
		throw new RuntimeException("test bootstrap: statement {$pattern} not found in {$relpath}");
	}

	$statement = '';
	$depth     = 0;
	foreach (token_get_all('<?php ' . substr($src, (int) $match[0][1])) as $index => $token) {
		if ($index === 0) {
			continue;	// the open tag
		}
		$text      = is_array($token) ? $token[1] : $token;
		$statement .= $text;
		if ($text === '(' || $text === '[' || $text === '{') {
			$depth++;
		} elseif ($text === ')' || $text === ']' || $text === '}') {
			$depth--;
		} elseif ($text === ';' && $depth === 0) {
			return $statement;
		}
	}
	throw new RuntimeException("test bootstrap: statement {$pattern} in {$relpath} has no closing ';'");
}

/** The source between two markers (start inclusive, end exclusive). */
function pfb_test_page_region(string $relpath, string $start, string $end): string
{
	$src    = pfb_test_page_source($relpath);
	$from   = strpos($src, $start);
	$length = $from === FALSE ? FALSE : strpos($src, $end, $from + strlen($start));
	if ($from === FALSE || $length === FALSE) {
		throw new RuntimeException("test bootstrap: region {$start} .. {$end} not found in {$relpath}");
	}
	return substr($src, $from, $length - $from);
}

/**
 * Eval $code with $vars in scope; returns the scope afterwards (the plumbing variables removed).
 *
 * @param array<string, mixed> $vars
 * @return array<string, mixed>
 */
function pfb_test_page_eval(string $code, array $vars): array
{
	return (static function (string $pfb_eval_code, array $pfb_eval_vars): array {
		extract($pfb_eval_vars);
		eval($pfb_eval_code);
		$scope = get_defined_vars();
		unset($scope['pfb_eval_code'], $scope['pfb_eval_vars']);
		return $scope;
	})($code, $vars);
}

/** The source from $start to the `}` that closes the block $start sits in (exclusive). */
function pfb_test_page_block_from(string $relpath, string $start): string
{
	$src  = pfb_test_page_source($relpath);
	$from = strpos($src, $start);
	if ($from === FALSE) {
		throw new RuntimeException("test bootstrap: {$start} not found in {$relpath}");
	}
	$code  = '';
	$depth = 0;
	foreach (token_get_all('<?php ' . substr($src, $from)) as $index => $token) {
		if ($index === 0) {
			continue;	// the open tag
		}
		$text = is_array($token) ? $token[1] : $token;
		if ($text === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE))) {
			$depth++;
		} elseif ($text === '}' && --$depth < 0) {
			return $code;
		}
		$code .= $text;
	}
	throw new RuntimeException("test bootstrap: the block holding {$start} in {$relpath} has no end");
}

/**
 * The variables the General page's save region ($region) reads, with $_POST set: every field the region reads is posted blank unless
 * $post says otherwise.
 *
 * @param array<string, string> $post
 * @return array<string, mixed>
 */
function pfb_test_general_save_vars(string $region, array $post): array
{
	preg_match_all("~\\\$_POST\\['([a-z0-9_]+)'\\]~", $region, $keys);
	$log_suffixes = pfb_test_page_eval(pfb_test_page_statement(PFB_TEST_GENERAL_PAGE, '/\$log_suffixes\s*=/'), [])['log_suffixes'];
	$_POST        = array_fill_keys($keys[1], '');
	foreach ($log_suffixes as $suffix) {
		$_POST["log_max_{$suffix}"] = $_POST["log_max_days_{$suffix}"] = '';
	}
	$_POST = array_replace($_POST, $post);

	return [
		'pfb'                      => ['gconfig' => ['enable_cb' => 'on']],
		'input_errors'             => [],
		'log_suffixes'             => $log_suffixes,
		'schedule_values'          => array_fill_keys(['pfb_scheduled_feed_updates', 'pfb_schedule_weekday', 'pfb_schedule_hour', 'pfb_schedule_minute', 'pfb_quiet_hours'], ''),
		'metrics_export_pkg'       => FALSE,
		'metrics_export_stored_on' => FALSE,
	];
}

const PFB_TEST_GENERAL_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_general.php';
/** Where the General page's save region starts: its metrics export gate. */
const PFB_TEST_GENERAL_SAVE_FROM = '// Server-side gate: a crafted POST';

/**
 * The General page's save, from its metrics export gate to the verdict on the save, run over the doubles. The region ends inside two
 * blocks (`if (!$input_errors)` and `if ($privacy_error !== NULL)`): they are closed here. The branch after it (the schedule cache, the
 * redirect) ends in exit: see support/GeneralSaveWorker.php.
 *
 * @param array<string, string> $post
 * @return array<string, mixed> the region's variables afterwards
 */
function pfb_test_general_save(array $post): array
{
	$region = pfb_test_page_region(PFB_TEST_GENERAL_PAGE, PFB_TEST_GENERAL_SAVE_FROM, '} elseif (!$pfb_core_errors) {');

	return pfb_test_page_eval($region . "\n}\n}", pfb_test_general_save_vars($region, $post));
}
