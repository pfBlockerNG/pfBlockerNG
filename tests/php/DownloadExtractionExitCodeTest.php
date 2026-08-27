<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The helper assertions below exercise the pure exit-code decision directly.
 * The eight outer pins retain the destructive/live orchestration coverage:
 * pfb_download() executes archive tools and writes appliance paths, so driving
 * those branches here would mutate real state. php_strip_whitespace() bounds
 * each code branch; comments and docblocks are never extraction boundaries.
 */
final class DownloadExtractionExitCodeTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if (self::$source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng.inc');
		}
	}

	public function testSuccessfulExtractionIsObservableOnlyForZeroExit(): void
	{
		$this->assertTrue(pfb_download_extraction_succeeded(0));
		$this->assertFalse(pfb_download_extraction_succeeded(1));
		$this->assertFalse(pfb_download_extraction_succeeded(127));
	}

	public function testFailureExitCannotReachSuccessPath(): void
	{
		foreach ([1, 2, 7, 127] as $exitCode) {
			$this->assertFalse(
				pfb_download_extraction_succeeded($exitCode),
				"extraction exit {$exitCode} must fail"
			);
		}
	}

	/**
	 * pfb_download() runs a disk-writing tar extraction into the GeoIP share;
	 * the comment-free scope must keep its distinct exec exit gate, independent
	 * of prose/docblock wording.
	 */
	public function testGzipGeoipBodyCapturesAndChecksTarExit(): void
	{
		$gzip = strpos(self::$source, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$geoip = strpos(self::$source, "if (\$type == 'geoip') {", $gzip === FALSE ? 0 : $gzip);
		$asn = strpos(self::$source, "elseif (\$type == 'asn') {", $geoip === FALSE ? 0 : $geoip);
		$this->assertNotFalse($gzip);
		$this->assertNotFalse($geoip);
		$this->assertNotFalse($asn);
		$scope = substr(self::$source, $geoip, $asn - $geoip);
		$this->assertMatchesRegularExpression('/exec\(pfb_extract_cmd\(".*tar -xzf .*\\$output, \\$retval\);/', $scope);
		$this->assertStringContainsString('pfb_download_extraction_succeeded($retval)', $scope);
	}

	/**
	 * pfb_download() gunzips ASN data and then rebuilds its lookup table; the
	 * live exec is not safe off-appliance, so pin only this comment-free branch
	 * and its nonzero-exit gate. Comments/docblocks cannot define this scope.
	 */
	public function testGzipAsnBodyCapturesAndChecksGunzipExit(): void
	{
		$gzip = strpos(self::$source, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$asn = strpos(self::$source, "elseif (\$type == 'asn') {", $gzip === FALSE ? 0 : $gzip);
		$top1m = strpos(self::$source, "elseif (\$type == 'top1m') {", $asn === FALSE ? 0 : $asn);
		$this->assertNotFalse($gzip);
		$this->assertNotFalse($asn);
		$this->assertNotFalse($top1m);
		$scope = substr(self::$source, $asn, $top1m - $asn);
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("/usr/bin/gunzip -c {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);', $scope);
		// issue #2169: the exit code is now gated inside pfb_stage_publish(), which
		// publishes onto the live target only when it reports success.
		$this->assertStringContainsString('if (!pfb_stage_publish($head_download,', $scope);
	}

	/**
	 * pfb_download() decompresses bzip2 feeds onto the live publication; pin this
	 * comment-free branch and its staged-publish guard so the branch cannot revert
	 * to a raw redirect. Comments/docblocks cannot define this scope.
	 */
	public function testBzip2BodyCapturesAndChecksExit(): void
	{
		$bzip2 = strpos(self::$source, "elseif (\$file_type == 'application/x-bzip2') {");
		$zip = strpos(self::$source, "elseif (\$file_type == 'application/zip') {", $bzip2 === FALSE ? 0 : $bzip2);
		$this->assertNotFalse($bzip2);
		$this->assertNotFalse($zip);
		$scope = substr(self::$source, $bzip2, $zip - $bzip2);
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("/usr/bin/bzip2 -dkc {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);', $scope);
		$this->assertStringContainsString('if (!pfb_stage_publish($orig_download,', $scope);
	}

	/**
	 * pfb_download() gunzips TOP1M into a staged file before publication; this
	 * live filesystem/exec path is pinned independently of all other branches.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testGzipTop1mBodyCapturesAndChecksGunzipExit(): void
	{
		$gzip = strpos(self::$source, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$top1m = strpos(self::$source, "elseif (\$type == 'top1m') {", $gzip === FALSE ? 0 : $gzip);
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $top1m === FALSE ? 0 : $top1m);
		$this->assertNotFalse($gzip);
		$this->assertNotFalse($top1m);
		$this->assertNotFalse($blacklist);
		$scope = substr(self::$source, $top1m, $blacklist - $top1m);
		$this->assertStringContainsString('exec(pfb_extract_cmd("/usr/bin/gunzip -c {$file_dwn_esc} > {$header_esc}"), $output, $retval);', $scope);
		$this->assertStringContainsString('pfb_download_extraction_succeeded($retval)', $scope);
	}

	/**
	 * The gzip blacklist branch writes extracted categories and an update marker;
	 * executing its tar against appliance paths is destructive, so keep this
	 * separate code-only call/exit pin. Comments/docblocks cannot define it.
	 */
	public function testGzipBlacklistBodyCapturesAndChecksTarExit(): void
	{
		$gzip = strpos(self::$source, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $gzip === FALSE ? 0 : $gzip);
		$end = strpos(self::$source, 'else { $reject_detail = array();', $blacklist === FALSE ? 0 : $blacklist);
		$this->assertNotFalse($gzip);
		$this->assertNotFalse($blacklist);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $blacklist, $end - $blacklist);
		$this->assertMatchesRegularExpression('/exec\(pfb_extract_cmd\(".*tar -xf .*\\$output, \\$retval\);/', $scope);
		$this->assertStringContainsString('pfb_download_extraction_succeeded($retval)', $scope);
		// issue #2735: success return is immediately after the update marker (not a
		// decoy elsewhere in the 1710-byte scope).
		$this->assertMatchesRegularExpression(
			'/touch\("\{\$pfb\[.dbdir.\]\}\/\{\$filename\}\/\{\$filename\}\.update"\);\s*return PfbDownloadResult::success\(\);/',
			$scope
		);
	}

	/**
	 * Issue #2635 — the uncompressed Blacklist branch must fail closed.
	 * `$retval = 0` with no extract reports a successful update while
	 * category files stay stale or missing. Comments/docblocks cannot
	 * define this scope.
	 */
	public function testUncompressedBlacklistBodyFailsClosedWithoutExtraction(): void
	{
		$uncomp = strpos(self::$source, "if (\$type == 'geoip' || \$type == 'asn')");
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $uncomp === FALSE ? 0 : $uncomp);
		$end = strpos(self::$source, 'else {', $blacklist === FALSE ? 0 : $blacklist);
		$this->assertNotFalse($uncomp);
		$this->assertNotFalse($blacklist);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $blacklist, $end - $blacklist);
		$this->assertStringNotContainsString(
			'$retval = 0;',
			$scope,
			'uncompressed Blacklist must not treat a non-archive body as a successful extract'
		);
		$this->assertStringContainsString(
			"pfb_validate_log(\$header, 'extract', 'blacklist_not_archive', \$file_type);",
			$scope,
			'reject must name the detected type'
		);
		$this->assertStringContainsString('unlink_if_exists($file_download);', $scope);
		$this->assertStringContainsString('return PfbDownloadResult::failure();', $scope);
		// The gzip Blacklist branch publishes through pfb_stage_publish_dir() so a
		// failed tar cannot replace live category files. This uncompressed reject
		// must not extract or publish at all — unlink the .raw body and return.
		$this->assertStringNotContainsString('pfb_stage_publish_dir', $scope);
		$this->assertStringNotContainsString('tar -xf', $scope);
		$this->assertStringNotContainsString('$pfb[\'dbdir\']', $scope);
	}

	/**
	 * GeoIP ZIP extraction writes either a directory or stdout-derived target;
	 * both live tar calls must remain in this dedicated, comment-free scope.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testZipGeoipBodyCapturesBothTarModesAndChecksExit(): void
	{
		$zip = strpos(self::$source, "elseif (\$file_type == 'application/zip') {");
		$geoip = strpos(self::$source, "if (\$type == 'geoip') {", $zip === FALSE ? 0 : $zip);
		$top1m = strpos(self::$source, "if (\$type == 'top1m') {", $geoip === FALSE ? 0 : $geoip);
		$this->assertNotFalse($zip);
		$this->assertNotFalse($geoip);
		$this->assertNotFalse($top1m);
		$scope = substr(self::$source, $geoip, $top1m - $geoip);
		$this->assertStringContainsString('exec(pfb_extract_cmd("/usr/bin/tar -xf {$file_dwn_esc} --strip=1 -C {$header_esc} >/dev/null 2>&1"), $output, $retval);', $scope);
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("/usr/bin/tar -xOf {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);', $scope);
		// issue #2169: the stdout mode publishes through the staged helper; the
		// directory mode still reaches the shared zero-only gate below it.
		$this->assertStringContainsString('if (!pfb_stage_publish($head_download,', $scope);
		$this->assertStringContainsString('pfb_download_extraction_succeeded($retval)', $scope);
	}

	/**
	 * TOP1M ZIP extraction stages into a temporary directory and publishes it;
	 * that destructive live path gets its own tar/exit pin rather than a global
	 * occurrence count that could pass on the wrong branch. Comments/docblocks
	 * cannot define this scope.
	 */
	public function testZipTop1mBodyCapturesAndChecksTarExit(): void
	{
		$zip = strpos(self::$source, "elseif (\$file_type == 'application/zip') {");
		$top1m = strpos(self::$source, "if (\$type == 'top1m') {", $zip === FALSE ? 0 : $zip);
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $top1m === FALSE ? 0 : $top1m);
		$this->assertNotFalse($zip);
		$this->assertNotFalse($top1m);
		$this->assertNotFalse($blacklist);
		$scope = substr(self::$source, $top1m, $blacklist - $top1m);
		$this->assertMatchesRegularExpression('/exec\(pfb_extract_cmd\(".*tar -xf .*\\$output, \\$retval\);/', $scope);
		$this->assertStringContainsString('pfb_download_extraction_succeeded($retval)', $scope);
	}

	/**
	 * pfb_download() hands the XLSX container to the shell helper, which extracts
	 * it; issue #2666 gave that helper an exit contract, so this branch is pinned
	 * like its siblings — captured exec, nonzero-exit gate, and the ceiling wrap
	 * that only an exit gate makes safe. The absent assertions matter as much as
	 * the present ones: deciding the ingest by the output file existing, or
	 * unlinking the live publication before the helper runs, both republish a
	 * truncated feed as a success.
	 */
	public function testXlsxBodyCapturesAndChecksHelperExit(): void
	{
		$xlsx = strpos(self::$source, "if (strpos(\$xlsxtest, '.xlsx') !== FALSE) {");
		$this->assertNotFalse($xlsx);
		$zipBranch = strpos(self::$source, '} else {', $xlsx);
		$this->assertNotFalse($zipBranch);
		$scope = substr(self::$source, $xlsx, $zipBranch - $xlsx);
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("{$pfb[\'script\']} xlsx {$header_esc} {$elog}"), $output, $retval);', $scope);
		$this->assertStringContainsString('pfb_download_extraction_succeeded($retval)', $scope);
		$this->assertStringNotContainsString('file_exists("{$orig_download}")', $scope);
		$this->assertStringNotContainsString('unlink_if_exists("{$orig_download}")', $scope);
	}
}
