<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Alerts-page array-request guard (issue #1128, #1139).
 *
 * A crafted request submitting an array-valued 'save' or 'ip' field
 * ('save[]=x', 'ip[]=x') reached a strictly-typed string sink
 * (strstr()/strpos()) before any type check, TypeError-ing the page
 * (HTTP 500). The fix defaults 'save' to '' (matching the file's existing
 * default-on-bad-input style) and adds is_string() to the outer 'ip' strpos()
 * guard (the inner check at the nested preg_match() already had one).
 *
 * Issue #1139 adds region 3: the 'Filter selection' preprocessor's three
 * explode(',', $_POST[...]) sinks TypeError the same way on an array-valued
 * 'filterlogentries_submit_*' field.
 *
 * The page carries top-level execution and cannot be require()d off-appliance,
 * so each region below is eval-extracted verbatim from the REAL source,
 * anchored on text stable across both the pre-fix and post-fix code so the
 * same test file proves red on the old code and green on the new.
 */
final class AlertsPostGuardTest extends TestCase
{
	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_alerts.php');
		}

		// Region 1: the 'save' -> $pageview computation.
		if (!function_exists('pfb_alerts_oracle_pageview')) {
			if (!preg_match(
				'/unset\(\$pfb\[\'aglobal\'\]\[\'hostlookup\'\]\);\n\t\t\}\n\n(.*?)\n\t\tif \(!in_array\(\$pageview,/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: pageview region not found');
			}
			eval(
				'function pfb_alerts_oracle_pageview(): string {'
				. $m[1]
				. ' return $pageview; }'
			);
		}

		// Region 2: the 'ip_remove' -> $ip computation.
		if (!function_exists('pfb_alerts_oracle_ip_remove')) {
			if (!preg_match(
				'/\$ip = \'\';\n(.*?)\$table = pfb_filter\(\$_POST\[\'table\'\], PFB_FILTER_WORD, \'alerts ip_remove\'\);/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: ip_remove region not found');
			}
			eval(
				'function pfb_alerts_oracle_ip_remove(): string {'
				. ' $ip = \'\';'
				. $m[1]
				. ' return $ip; }'
			);
		}

		// Region 3: the 'Filter selection' preprocessor -> mutated $_POST.
		if (!function_exists('pfb_alerts_oracle_filter_selection')) {
			if (!preg_match(
				'/\$filter_type = array\(\);\n(.*?)\n\t\/\/ Filter Alerts based on user defined/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: filter-selection region not found');
			}
			eval(
				'function pfb_alerts_oracle_filter_selection(): array {'
				. ' $filter_type = array();'
				. $m[1]
				. ' return $_POST; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
	}

	// --- site 1: 'save' -> $pageview -----------------------------------

	public function testSaveArrayValueDoesNotThrowAndYieldsBlankPageview(): void
	{
		$_POST['save'] = ['x', 'y'];
		try {
			$pageview = pfb_alerts_oracle_pageview();
		} catch (\TypeError $e) {
			$this->fail('an array save value must not TypeError strstr(): ' . $e->getMessage());
		}
		$this->assertSame('', $pageview, 'an array save value must default to the blank pageview');
	}

	public function testSaveScalarValueStillResolvesPageview(): void
	{
		// Regression guard: real submissions carry a leading verb + space + view
		// name ("Save dnsbl_stat") -- strstr(..., FALSE) keeps the needle onward.
		$_POST['save'] = 'Save dnsbl_stat';
		$pageview = pfb_alerts_oracle_pageview();
		$this->assertSame('dnsbl_stat', $pageview, 'a scalar save value must still resolve its view');
	}

	public function testSaveMissingKeyDoesNotWarnAndYieldsBlankPageview(): void
	{
		unset($_POST['save']);
		$pageview = pfb_alerts_oracle_pageview();
		$this->assertSame('', $pageview, 'a missing save key must yield the blank pageview, not a warning');
	}

	// --- site 2: 'ip' -> $ip (ip_remove) ---------------------------------

	public function testIpArrayValueDoesNotThrowAndYieldsBlankIp(): void
	{
		$_POST['ip'] = ['1.2.3.4'];
		try {
			$ip = pfb_alerts_oracle_ip_remove();
		} catch (\TypeError $e) {
			$this->fail('an array ip value must not TypeError strpos(): ' . $e->getMessage());
		}
		$this->assertSame('', $ip, 'an array ip value must resolve to the blank/rejected ip');
	}

	public function testIpScalarCidrValueStillParses(): void
	{
		$_POST['ip'] = '10.0.0.5/24';
		$ip = pfb_alerts_oracle_ip_remove();
		$this->assertSame('10.0.0.5', $ip, 'a scalar CIDR ip value must still parse via the preg_match path');
	}

	public function testIpScalarPlainValueStillResolvesViaElseBranch(): void
	{
		$_POST['ip'] = '10.0.0.5';
		$ip = pfb_alerts_oracle_ip_remove();
		$this->assertSame('10.0.0.5', $ip, 'a scalar plain ip value must still resolve via the else/pfb_filter branch');
	}

	public function testIpMissingKeyDoesNotWarnAndYieldsBlankIp(): void
	{
		unset($_POST['ip']);
		$ip = pfb_alerts_oracle_ip_remove();
		$this->assertSame('', $ip, 'a missing ip key must yield the blank ip, not a warning');
	}

	public function testIpNestedArrayValueDoesNotThrowAndYieldsBlankIp(): void
	{
		// A nested array ('ip[0][]=x', parse_str-shaped) reached pfb_filter()'s own
		// control-char preg_match() loop, which TypeErrors on a non-string $vline --
		// the flat-array case above alone doesn't cover this shape.
		parse_str('ip[0][]=x', $parsed);
		$_POST['ip'] = $parsed['ip'];
		try {
			$ip = pfb_alerts_oracle_ip_remove();
		} catch (\TypeError $e) {
			$this->fail('a nested array ip value must not TypeError: ' . $e->getMessage());
		}
		$this->assertSame('', $ip, 'a nested array ip value must resolve to the blank/rejected ip');
	}

	// --- site 3: 'Filter selection' preprocessor -------------------------

	public function testFilterSelectionReplySrcIpdArrayValueDoesNotThrowAndSkipsField(): void
	{
		$_POST['filterlogentries_submit_replysrcipd'] = ['x', 'y'];
		try {
			$post = pfb_alerts_oracle_filter_selection();
		} catch (\TypeError $e) {
			$this->fail('an array replysrcipd value must not TypeError explode(): ' . $e->getMessage());
		}
		$this->assertArrayNotHasKey('filterlogentries_submit', $post, 'an array value must not flip filterlogentries_submit to Apply Filter');
		$this->assertArrayNotHasKey('filterlogentries_replydomain', $post, 'a skipped field must not set the split domain key');
		$this->assertArrayNotHasKey('filterlogentries_replysrcip', $post, 'a skipped field must not set the split ip key');
	}

	public static function ipPairFieldProvider(): array
	{
		return [
			'ipsrcipin'  => ['ipsrcipin', 'filterlogentries_ipsrcip'],
			'ipsrcipout' => ['ipsrcipout', 'filterlogentries_ipsrcip'],
			'ipdstipin'  => ['ipdstipin', 'filterlogentries_ipdstip'],
			'ipdstipout' => ['ipdstipout', 'filterlogentries_ipdstip'],
		];
	}

	#[DataProvider('ipPairFieldProvider')]
	public function testFilterSelectionIpPairArrayValueDoesNotThrowAndSkipsField(string $submitType, string $finalKey): void
	{
		$_POST['filterlogentries_submit_' . $submitType] = ['x', 'y'];
		try {
			$post = pfb_alerts_oracle_filter_selection();
		} catch (\TypeError $e) {
			$this->fail("an array {$submitType} value must not TypeError explode(): " . $e->getMessage());
		}
		$this->assertArrayNotHasKey('filterlogentries_submit', $post, 'an array value must not flip filterlogentries_submit to Apply Filter');
		$this->assertArrayNotHasKey($finalKey, $post, 'a skipped field must not set its split ip key');
		$this->assertArrayNotHasKey('filterlogentries_ipgeoip', $post, 'a skipped field must not set the split geoip key');
	}

	public function testFilterSelectionNestedArrayValueDoesNotThrowAndSkipsField(): void
	{
		// A nested array ('...replysrcipd[0][]=x', parse_str-shaped) reaches the same
		// explode() sink as the flat-array case -- covered separately since parse_str()
		// shapes it differently than a literal PHP array.
		parse_str('filterlogentries_submit_replysrcipd[0][]=x', $parsed);
		$_POST['filterlogentries_submit_replysrcipd'] = $parsed['filterlogentries_submit_replysrcipd'];
		try {
			$post = pfb_alerts_oracle_filter_selection();
		} catch (\TypeError $e) {
			$this->fail('a nested array replysrcipd value must not TypeError explode(): ' . $e->getMessage());
		}
		$this->assertArrayNotHasKey('filterlogentries_submit', $post, 'a nested array value must not flip filterlogentries_submit to Apply Filter');
	}

	public function testFilterSelectionReplySrcIpdScalarValueStillSplits(): void
	{
		$_POST['filterlogentries_submit_replysrcipd'] = 'dom.com,1.2.3.4';
		$post = pfb_alerts_oracle_filter_selection();
		$this->assertSame('dom.com', $post['filterlogentries_replydomain'] ?? null, 'a scalar value must still split into the domain field');
		$this->assertSame('1.2.3.4', $post['filterlogentries_replysrcip'] ?? null, 'a scalar value must still split into the ip field');
		$this->assertSame('Apply Filter', $post['filterlogentries_submit'] ?? null, 'a scalar value must still flip filterlogentries_submit');
	}

	public function testFilterSelectionIpSrcIpInScalarValueStillSplits(): void
	{
		$_POST['filterlogentries_submit_ipsrcipin'] = '1.2.3.4,US';
		$post = pfb_alerts_oracle_filter_selection();
		$this->assertSame('1.2.3.4', $post['filterlogentries_ipsrcip'] ?? null, 'a scalar value must still split into the ip field');
		$this->assertSame('US', $post['filterlogentries_ipgeoip'] ?? null, 'a scalar value must still split into the geoip field');
		$this->assertSame('Apply Filter', $post['filterlogentries_submit'] ?? null, 'a scalar value must still flip filterlogentries_submit');
	}

	public function testFilterSelectionElseBranchScalarValueStillApplies(): void
	{
		$_POST['filterlogentries_submit_ipdate'] = 'Jul 10';
		$post = pfb_alerts_oracle_filter_selection();
		$this->assertSame('Jul 10', $post['filterlogentries_ipdate'] ?? null, 'a scalar value must still reach the else/pfb_filter branch');
		$this->assertSame('Apply Filter', $post['filterlogentries_submit'] ?? null, 'a scalar value must still flip filterlogentries_submit');
	}

	public function testFilterSelectionElseBranchArrayValueSkipsFieldInsteadOfApplying(): void
	{
		// pfb_filter() is already array-safe post-#1070/#1139 (returns the caller
		// default instead of throwing), so this is not a TypeError repro -- it pins
		// that the new top-level guard skips the field instead of silently applying
		// a blanked-out value and flipping filterlogentries_submit anyway.
		$_POST['filterlogentries_submit_ipdate'] = ['x'];
		$post = pfb_alerts_oracle_filter_selection();
		$this->assertArrayNotHasKey('filterlogentries_ipdate', $post, 'an array value must not set the else-branch field, even to a blanked default');
		$this->assertArrayNotHasKey('filterlogentries_submit', $post, 'an array value must not flip filterlogentries_submit to Apply Filter');
	}
}
