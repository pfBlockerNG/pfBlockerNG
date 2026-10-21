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
