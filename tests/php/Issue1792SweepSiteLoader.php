<?php

declare(strict_types=1);

/**
 * Issue #1792: eval REAL single-statement sites straight out of the www pages
 * -- not hand-copied stand-ins -- so a red run against the pre-sweep
 * `?: `-idiom sites genuinely exercises the buggy statement, and the SAME test
 * goes green once the site is swept, with zero test edits (the same rationale
 * as AlertsCustomlistDecodeLoader.php, which evals brace blocks; these sites
 * are one-line assignments, so the extractor here is line-scoped).
 */

/**
 * Extract the single full statement starting at $marker (through the first
 * ';' at line end) from $relpath and eval it with $vars in scope; returns the
 * eval scope's variables afterwards (get_defined_vars minus the plumbing).
 *
 * @param array<string, mixed> $vars
 * @return array<string, mixed>
 */
function pfb_test_1792_eval_site(string $relpath, string $marker, array $vars): array
{
	$src = file_get_contents(dirname(__DIR__, 2) . '/' . $relpath);
	if ($src === false) {
		throw new RuntimeException("failed to read {$relpath}");
	}
	$start = strpos($src, $marker);
	if ($start === false) {
		throw new RuntimeException("could not locate marker in {$relpath}: {$marker}");
	}
	$end = strpos($src, ";\n", $start);
	if ($end === false) {
		throw new RuntimeException("no statement end after marker in {$relpath}: {$marker}");
	}
	$statement = substr($src, $start, $end - $start + 1);

	return (static function (string $pfb_test_1792_statement, array $pfb_test_1792_vars): array {
		extract($pfb_test_1792_vars);
		eval($pfb_test_1792_statement);
		$result = get_defined_vars();
		unset($result['pfb_test_1792_statement'], $result['pfb_test_1792_vars']);
		return $result;
	})($statement, $vars);
}
