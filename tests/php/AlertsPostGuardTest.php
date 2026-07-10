<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Alerts-page array-request guard (issue #1128).
 *
 * A crafted request submitting an array-valued 'save' or 'ip' field
 * ('save[]=x', 'ip[]=x') reached a strictly-typed string sink
 * (strstr()/strpos()) before any type check, TypeError-ing the page
 * (HTTP 500). The fix defaults 'save' to '' (matching the file's existing
 * default-on-bad-input style) and adds is_string() to the outer 'ip' strpos()
 * guard (the inner check at the nested preg_match() already had one).
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
}
