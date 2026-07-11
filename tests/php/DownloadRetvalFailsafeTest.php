<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_download()'s $retval fail-safe default (issue #1158).
 *
 * pfb_download() drives real cURL + the appliance exec pipeline before any of
 * the sites under test run, so behaviourally exercising the function off-appliance
 * is infeasible -- this is a source-inspection pin instead (house precedent:
 * tests/php/PfbSyncStatusDnsblWritersTest.php's
 * testRestartFallbackBranchesNeverCallLedgerFunctionsDirectly()).
 *
 * The bug: `unset($retval);` left $retval undefined on any code path that fell
 * through the decompression switch without assigning it. PHP's loose `== 0`
 * then treats NULL as equal to 0, so an unassigned $retval silently reads as
 * the SUCCESS gate (`if ($retval == 0)`) instead of failure. Two such paths
 * exist: the ZIP xlsx-conversion-failure branch (the reported defect -- a
 * failed conversion must FAIL, not succeed) and the gzip 'blacklist' success
 * branch (which must keep succeeding under the new fail-safe default).
 *
 * issue #1166: the gzip-blacklist branch's unconditional `$retval = 0;` after
 * the .update touch is itself a defect superseding this file's original pin
 * -- it reported success even when the preceding tar extraction failed. The
 * route now derives $retval from tar's real captured exit code and guards
 * the .update touch with it; see DownloadExtractionExitCodeTest for the full
 * per-site exit-code coverage.
 */
final class DownloadRetvalFailsafeTest extends TestCase
{
	private static string $body;

	public static function setUpBeforeClass(): void
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if ($source === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}

		$start = strpos($source, 'function pfb_download(');
		if ($start === false) {
			throw new RuntimeException('test bootstrap: function pfb_download( not found');
		}

		// Whitespace-tolerant: the next top-of-line 'function <name>' declaration
		// (an indented closure inside the body, e.g. the CURLOPT_HEADERFUNCTION
		// callback, never matches '^function' since it is never at column 0).
		if (!preg_match('/^function\s+\w+/m', $source, $m, PREG_OFFSET_CAPTURE, $start + 20)) {
			throw new RuntimeException('test bootstrap: end-of-function boundary not found');
		}
		$end = $m[0][1];

		self::$body = substr($source, $start, $end - $start);
	}

	// -----------------------------------------------------------------------
	// Vacuity guards -- each marker this test's assertions depend on must
	// actually be present, or the assertions below prove nothing.
	// -----------------------------------------------------------------------

	public function testVacuityRetvalGateExists(): void
	{
		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval\s*==\s*0\s*\)/', self::$body,
			'the $retval == 0 success gate must exist for this test to mean anything');
	}

	public function testVacuityXlsxExecMarkerExists(): void
	{
		$this->assertStringContainsString("{\$pfb['script']} xlsx {\$header_esc}", self::$body,
			'the xlsx-conversion exec call must exist -- this is the reported defect route');
	}

	public function testVacuityUpdateTouchMarkerExists(): void
	{
		$this->assertStringContainsString('{$filename}/{$filename}.update', self::$body,
			'the gzip-blacklist .update touch marker must exist -- Route 2 pins against it');
	}

	public function testVacuityAtLeastFourExecSitesAssignRetval(): void
	{
		$count = substr_count(self::$body, ', $output, $retval)');
		$this->assertGreaterThanOrEqual(4, $count,
			"expected >= 4 exec(...,\$output,\$retval) sites (gzip-default/asn/top1m, bzip2, zip-pipeline, 7z); found {$count}");
	}

	// -----------------------------------------------------------------------
	// Red row A -- the fail-safe default itself.
	// -----------------------------------------------------------------------

	public function testRetvalDefaultsToOneNotUnset(): void
	{
		$this->assertStringNotContainsString('unset($retval);', self::$body,
			'unset($retval) must be gone -- it let an unassigned path read as 0 == success');
		$this->assertMatchesRegularExpression('/\$retval\s*=\s*1\s*;/', self::$body,
			'a $retval = 1 fail-safe default must replace the unset() -- unassigned must mean FAILURE');
	}

	// -----------------------------------------------------------------------
	// Red row B -- Route 2 (gzip-blacklist) keeps succeeding under the new default.
	// -----------------------------------------------------------------------

	public function testGzipBlacklistUpdateTouchGuardedByCapturedRetvalNotUnconditionalAssignment(): void
	{
		$touchPos = strpos(self::$body, '{$filename}/{$filename}.update');
		$this->assertNotFalse($touchPos, 'the .update touch marker must be locatable (vacuity re-check)');

		// issue #1166: success no longer comes from a hardcoded $retval = 0;
		// after the touch -- it comes from the tar extraction's own captured
		// exit code, and the touch itself is now gated on that code being 0.
		$preWindow = substr(self::$body, max(0, $touchPos - 100), 100);
		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval\s*==\s*0\s*\)/', $preWindow,
			'the .update touch must be guarded by if ($retval == 0); found before touch: '
			. json_encode($preWindow));

		$window = substr(self::$body, $touchPos, 200);
		$this->assertDoesNotMatchRegularExpression('/\$retval\s*=\s*0\s*;/', $window,
			'no unconditional $retval = 0; may remain near the .update touch -- the new fail-safe default is '
			. 'satisfied by tar\'s own captured exit code, not a hardcoded override; found near touch: '
			. json_encode($window));
	}

	// -----------------------------------------------------------------------
	// Additional semantics pin -- the hazard this fail-safe defends against.
	// -----------------------------------------------------------------------

	public function testNullEqualsZeroHazardBackingTheFailsafe(): void
	{
		// phpcs:ignore -- deliberately loose comparison: this IS the hazard.
		$this->assertTrue(null == 0,
			"PHP's loose '==' treats an unassigned (NULL) \$retval as equal to 0, "
			. 'so any code path that falls through without assigning $retval silently '
			. '"succeeds" at the if ($retval == 0) gate -- this is exactly the bug '
			. '$retval = 1 (fail-safe default) defends against');
	}
}
