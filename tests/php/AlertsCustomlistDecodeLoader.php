<?php

declare(strict_types=1);

/**
 * Issue #1782: eval the REAL "decode a Custom_List/Suppression/Exclusion textarea
 * into the Alerts page's domain-keyed lookup map" statements straight out of
 * pfblockerng_alerts.php -- not a hand-copied stand-in -- so a red run against the
 * file BEFORE the $idn fix genuinely exercises the buggy call, and the SAME test
 * goes green once the call site is fixed, with zero test edits. Two call sites,
 * two extractors (AlertsPageLoader.php's docblock explains why this file cannot
 * reuse its function-block eval: this code is top-level script, not inside a
 * function). No production file is modified to make it testable.
 */

/**
 * The 'ipsuppression'/'ipsuppression_v6'/'dnsblwhitelist'/'tld_wildcard_exclusion' loop's
 * decode block (pfblockerng_alerts.php, inside the `foreach (array(...) as $key
 * => $type)` loop). Pre-seeds $clists[$type]['base64'] and evals the assignment +
 * if-block verbatim; $type/$clists never leak (function-local `eval()` scope).
 */
function pfb_test_alerts_decode_suppression_list(string $type, string $base64): array
{
	static $snippet = null;
	if ($snippet === null) {
		$snippet = pfb_test_alerts_extract_block(
			"\t\t\$clists[\$type]['data']\t\t= array();\n\t\tif (isset(\$clists[\$type]['base64'])"
		);
	}
	$clists = [$type => ['base64' => $base64]];
	eval($snippet);
	return $clists[$type]['data'] ?? [];
}

/**
 * The per-DNSBL-group/per-IP-alias custom list decode block (pfblockerng_alerts.php,
 * inside the `foreach ($c_config['config'] as $row => $data)` loop). Pre-seeds
 * $data['custom']/$type/$lname and evals the decode-assignment + if-block verbatim.
 */
function pfb_test_alerts_decode_group_customlist(string $type, string $lname, string $custom): array
{
	static $snippet = null;
	if ($snippet === null) {
		$snippet = pfb_test_alerts_extract_block(
			"\$decoded = pfb_text_area_decode(\$data['custom'],"
		);
	}
	$clists = [$type => [$lname => ['data' => []]]];
	$data = ['custom' => $custom];
	eval($snippet);
	return $clists[$type][$lname]['data'] ?? [];
}

/** Depth-match the enclosing brace block starting at $marker's position (same technique as RegexIniTransportTest::functionBody()). */
function pfb_test_alerts_extract_block(string $marker): string
{
	$src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
	);
	if ($src === false) {
		throw new RuntimeException('failed to read pfblockerng_alerts.php');
	}
	$start = strpos($src, $marker);
	if ($start === false) {
		throw new RuntimeException("could not locate marker in pfblockerng_alerts.php: {$marker}");
	}
	$open = strpos($src, '{', $start);
	if ($open === false) {
		throw new RuntimeException('no opening brace found after marker');
	}
	$depth = 0;
	for ($i = $open, $len = strlen($src); $i < $len; $i++) {
		if ($src[$i] === '{') {
			$depth++;
		} elseif ($src[$i] === '}') {
			$depth--;
			if ($depth === 0) {
				return substr($src, $start, $i - $start + 1);
			}
		}
	}
	throw new RuntimeException('closing brace missing for the extracted block');
}
