<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_download()'s extraction sites must route a nonzero exec() exit to the
 * function's existing failure paths (issue #1166), not report success blind.
 *
 * Same off-appliance constraint as DownloadRetvalFailsafeTest: pfb_download()
 * drives real cURL + appliance exec before any site under test runs, so this
 * is a source-inspection pin, not a behavioural exercise.
 */
final class DownloadExtractionExitCodeTest extends TestCase
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

		if (!preg_match('/^function\s+\w+/m', $source, $m, PREG_OFFSET_CAPTURE, $start + 20)) {
			throw new RuntimeException('test bootstrap: end-of-function boundary not found');
		}
		$end = $m[0][1];

		self::$body = substr($source, $start, $end - $start);
	}

	// -----------------------------------------------------------------------
	// Row 1 -- gzip geoip: /usr/bin/tar -xzf site.
	// -----------------------------------------------------------------------

	public function testGzipGeoipTarCapturesRetvalAndIsCheckedBeforeReturnTrue(): void
	{
		$tarPos = strpos(self::$body, "/usr/bin/tar -xzf {\$file_dwn_esc} --strip=1 -C {\$pfb['geoipshare']}");
		$this->assertNotFalse($tarPos, 'vacuity: the gzip-geoip tar -xzf site must exist for this test to mean anything');

		$returnTrue = strpos(self::$body, 'return TRUE;', $tarPos);
		$this->assertNotFalse($returnTrue, 'vacuity: gzip-geoip site must reach a return TRUE;');
		$segment = substr(self::$body, $tarPos, $returnTrue + strlen('return TRUE;') - $tarPos);

		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segment,
			'gzip-geoip tar -xzf must capture $output, $retval -- a corrupt archive currently reports success unconditionally');
		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval/', $segment,
			'gzip-geoip must check $retval before its return TRUE -- a nonzero exit must not report success');
	}

	// -----------------------------------------------------------------------
	// Row 2 -- gzip asn: gunzip already captures $retval but never checks it
	// before the asn_table rebuild runs off a possibly-partial file.
	// -----------------------------------------------------------------------

	public function testGzipAsnChecksRetvalBeforeRebuildingAsnTable(): void
	{
		$asnAnchor = strpos(self::$body, "\$type == 'asn'");
		$this->assertNotFalse($asnAnchor, 'vacuity: the gzip-asn branch must exist');

		$gunzip = strpos(self::$body, 'exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}"', $asnAnchor);
		$this->assertNotFalse($gunzip, 'vacuity: gzip-asn gunzip exec must exist');

		$asnTable = strpos(self::$body, 'asn_table', $gunzip);
		$this->assertNotFalse($asnTable, 'vacuity: the asn_table rebuild exec must exist after the gunzip');

		$segment = substr(self::$body, $gunzip, $asnTable - $gunzip);

		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval\s*!=\s*0\s*\)|if\s*\(\s*\$retval\s*<>\s*0\s*\)/', $segment,
			'gzip-asn must check $retval and bail BEFORE the asn_table exec -- else a failed decompress '
			. 'rebuilds the ASN table from a stale/partial file; found between gunzip and asn_table: '
			. json_encode($segment));
		$this->assertStringContainsString('return FALSE', $segment,
			'gzip-asn nonzero-retval path must return FALSE before asn_table runs');
	}

	// -----------------------------------------------------------------------
	// Row 3 -- gzip top1m: same gunzip-capture-but-ignored shape as asn.
	// -----------------------------------------------------------------------

	public function testGzipTop1mChecksRetvalBeforeReturnTrue(): void
	{
		$top1mAnchor = strpos(self::$body, "\$type == 'top1m'");
		$this->assertNotFalse($top1mAnchor, 'vacuity: the gzip-top1m branch must exist');

		$gunzip = strpos(self::$body, 'exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}"', $top1mAnchor);
		$this->assertNotFalse($gunzip, 'vacuity: gzip-top1m gunzip exec must exist');

		$returnTrue = strpos(self::$body, 'return TRUE;', $gunzip);
		$this->assertNotFalse($returnTrue, 'vacuity: gzip-top1m site must reach a return TRUE;');
		$segment = substr(self::$body, $gunzip, $returnTrue + strlen('return TRUE;') - $gunzip);

		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval/', $segment,
			'gzip-top1m must check $retval before its return TRUE -- a nonzero gunzip exit must not report success; '
			. 'segment: ' . json_encode($segment));
	}

	// -----------------------------------------------------------------------
	// Row 4 -- gzip blacklist: THE reported defect. tar exec must capture
	// $output/$retval; the .update touch must be guarded by $retval == 0;
	// the unconditional $retval = 0; must be gone from the touch window.
	// -----------------------------------------------------------------------

	public function testGzipBlacklistTarCapturesRetval(): void
	{
		$tarPos = strpos(self::$body, 'exec("/usr/bin/tar -xf " . escapeshellarg("{$file_dwn}")');
		$this->assertNotFalse($tarPos, 'vacuity: the gzip-blacklist tar -xf site must exist');

		$window = substr(self::$body, $tarPos, 150);
		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $window,
			'gzip-blacklist tar -xf must capture $output, $retval -- issue #1166 (a corrupt/partial UT1-style '
			. 'archive currently reports success unconditionally); found: ' . json_encode($window));
	}

	public function testGzipBlacklistUpdateTouchGuardedByRetvalNotUnconditionalAssignment(): void
	{
		$touchPos = strpos(self::$body, '{$filename}/{$filename}.update');
		$this->assertNotFalse($touchPos, 'vacuity: the .update touch marker must be locatable');

		$preWindow = substr(self::$body, max(0, $touchPos - 100), 100);
		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval\s*==\s*0\s*\)/', $preWindow,
			'the .update touch must be guarded by if ($retval == 0) -- a failed extraction must not stage the '
			. 'update indicator; found before touch: ' . json_encode($preWindow));

		$postWindow = substr(self::$body, $touchPos, 150);
		$this->assertDoesNotMatchRegularExpression('/\$retval\s*=\s*0\s*;/', $postWindow,
			'no unconditional $retval = 0; may remain in the touch window -- success must come from the tar '
			. 'exec\'s real exit code, not a hardcoded assignment; found: ' . json_encode($postWindow));
	}

	// -----------------------------------------------------------------------
	// Row 5 & 6 -- zip extras: both the multi-member (-xf) and single-member
	// (-xOf) tar sites must capture $retval; a check must gate their shared
	// return TRUE.
	// -----------------------------------------------------------------------

	public function testZipExtrasBothTarSitesCaptureRetvalAndAreCheckedBeforeReturnTrue(): void
	{
		$multi = strpos(self::$body, 'exec("/usr/bin/tar -xf {$file_dwn_esc} --strip=1 -C {$header_esc}');
		$this->assertNotFalse($multi, 'vacuity: the zip multi-member tar -xf site must exist');

		$single = strpos(self::$body, 'exec("/usr/bin/tar -xOf {$file_dwn_esc} > {$header_esc}"', $multi);
		$this->assertNotFalse($single, 'vacuity: the zip single-member tar -xOf site must exist');

		$returnTrue = strpos(self::$body, 'return TRUE;', $single);
		$this->assertNotFalse($returnTrue, 'vacuity: zip extras must reach a shared return TRUE;');

		$segMulti = substr(self::$body, $multi, $single - $multi);
		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segMulti,
			'zip multi-member tar -xf must capture $output, $retval; segment: ' . json_encode($segMulti));

		$segSingleToReturn = substr(self::$body, $single, $returnTrue + strlen('return TRUE;') - $single);
		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segSingleToReturn,
			'zip single-member tar -xOf must capture $output, $retval; segment: ' . json_encode($segSingleToReturn));
		$this->assertMatchesRegularExpression('/if\s*\(\s*\$retval/', $segSingleToReturn,
			'zip extras must check $retval before their shared return TRUE; segment: '
			. json_encode($segSingleToReturn));
	}

	// -----------------------------------------------------------------------
	// Row 7 -- uncompressed extras: @rename() result must be checked.
	// -----------------------------------------------------------------------

	public function testUncompressedExtrasChecksRenameResult(): void
	{
		$renamePos = strpos(self::$body, '@rename("{$file_download}", "{$head_download}");');
		$this->assertNotFalse($renamePos, 'vacuity: the uncompressed-extras rename site must exist');

		$nextBranch = strpos(self::$body, "elseif (\$type == 'blacklist') {", $renamePos);
		$this->assertNotFalse($nextBranch, 'vacuity: the uncompressed-blacklist sibling branch must exist');
		$segment = substr(self::$body, $renamePos, $nextBranch - $renamePos);

		$this->assertDoesNotMatchRegularExpression('/@rename\([^;]*\);\s*return TRUE;/', $segment,
			'a bare @rename(...); return TRUE; ignores rename()\'s own failure -- a failed rename must not '
			. 'report success; segment: ' . json_encode($segment));
		$this->assertStringContainsString('return FALSE', $segment,
			'a failed rename() must have a return FALSE path; segment: ' . json_encode($segment));
	}
}
