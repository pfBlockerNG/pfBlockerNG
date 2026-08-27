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
		// issue #2638: bsdtar auto-detects compression; -xf serves gzip and plain tar.
		$this->assertMatchesRegularExpression('/exec\(pfb_extract_cmd\(".*tar -xf .*\\$output, \\$retval\);/', $scope);
		$this->assertStringContainsString('-C {$pfb[\'geoipshare\']}', $scope);
		$this->assertStringContainsString('pfb_archive_unsafe_member', $scope);
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
	 * Issue #2739 — a bzip2 Blacklist body must fail closed. The arm
	 * extracts onto $orig_download for IP feeds; Blacklist has no category
	 * extract here, so a successful empty update is a lie. Comments and
	 * docblocks cannot define this scope.
	 */
	public function testBzip2BlacklistBodyFailsClosedWithoutExtraction(): void
	{
		$bzip2 = strpos(self::$source, "elseif (\$file_type == 'application/x-bzip2') {");
		$zip = strpos(self::$source, "elseif (\$file_type == 'application/zip') {", $bzip2 === FALSE ? 0 : $bzip2);
		$this->assertNotFalse($bzip2);
		$this->assertNotFalse($zip);
		$scope = substr(self::$source, $bzip2, $zip - $bzip2);
		$reject = strpos($scope, "if (\$type == 'blacklist') {");
		$publish = strpos($scope, 'if (!pfb_stage_publish($orig_download,');
		$this->assertNotFalse($reject, $scope);
		$this->assertNotFalse($publish, $scope);
		$this->assertLessThan($publish, $reject, 'Blacklist reject must run before the IP-feed extract');
		$this->assertStringContainsString(
			"pfb_validate_log(\$header, 'extract', 'blacklist_not_archive', \$file_type);",
			$scope,
			'reject must name the detected type'
		);
		$brace = strpos($scope, '{', $reject);
		$this->assertNotFalse($brace);
		$reject_scope = substr($scope, $reject, self::closingBraceExclusive($scope, $brace) - $reject);
		$this->assertSame(
			1,
			substr_count($reject_scope, 'return PfbDownloadResult::failure();'),
			'reject scope must not swallow a sibling failure return'
		);
		$this->assertStringContainsString('unlink_if_exists($file_download);', $reject_scope);
		$this->assertStringContainsString('return PfbDownloadResult::failure();', $reject_scope);
		$this->assertStringNotContainsString('pfb_stage_publish', $reject_scope);
		$this->assertStringNotContainsString('$pfb[\'dbdir\']', $reject_scope);
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
	 * Issue #2738 — a successful gzip Blacklist update must drop leftover
	 * `{feed}.orig` and hash sidecars the pre-#2735 fall-through wrote.
	 * Nothing consumes them for a Blacklist feed; a zero-length orig is
	 * the #2632-style misread. Pin the purge immediately before the
	 * update marker so it cannot hide in the failure arm. Comments and
	 * docblocks cannot define this scope.
	 */
	public function testGzipBlacklistSuccessArmUnlinksStaleOrigAndHashSidecars(): void
	{
		$gzip = strpos(self::$source, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $gzip === FALSE ? 0 : $gzip);
		$end = strpos(self::$source, 'else { $reject_detail = array();', $blacklist === FALSE ? 0 : $blacklist);
		$this->assertNotFalse($gzip);
		$this->assertNotFalse($blacklist);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $blacklist, $end - $blacklist);
		$this->assertMatchesRegularExpression(
			'/foreach \(array\("\{\$file_dwn\}\.orig", "\{\$file_dwn\}\.xxhash128", "\{\$file_dwn\}\.md5"\) as \$blacklist_stale\) \{\s*unlink_if_exists\(\$blacklist_stale\);\s*\}\s*touch\("\{\$pfb\[.dbdir.\]\}\/\{\$filename\}\/\{\$filename\}\.update"\);\s*return PfbDownloadResult::success\(\);/',
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
		// issue #2638 extracts application/x-tar in this same elseif; HTML/plain
		// still fail closed. The no-extract assertions live on the reject arm
		// via blacklist_not_archive + failure return above.
	}

	/**
	 * Issue #2638 — an uncompressed application/x-tar Blacklist body must be
	 * extracted into the category tree, not fail-closed as a non-archive.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testUncompressedTarBlacklistBodyExtractsCategories(): void
	{
		$uncomp = strpos(self::$source, "if (\$type == 'geoip' || \$type == 'asn')");
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $uncomp === FALSE ? 0 : $uncomp);
		$end = strpos(self::$source, 'else {', $blacklist === FALSE ? 0 : $blacklist);
		$this->assertNotFalse($uncomp);
		$this->assertNotFalse($blacklist);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $blacklist, $end - $blacklist);
		$this->assertStringContainsString("if (\$file_type == 'application/x-tar') {", $scope);
		$this->assertStringContainsString('pfb_stage_publish_dir', $scope);
		$this->assertStringContainsString('/usr/bin/tar -xf', $scope);
		// issue #2632 smoke: downloadPath may end in .tar, not .tar.gz; WORD rejects a leftover dot.
		$this->assertStringContainsString("basename(basename(\"{\$file_esc}\", '.tar.gz'), '.tar')", $scope);
		$reject = strpos($scope, "pfb_validate_log(\$header, 'extract', 'blacklist_not_archive', \$file_type);");
		$tar = strpos($scope, "if (\$file_type == 'application/x-tar') {");
		$this->assertNotFalse($reject);
		$this->assertNotFalse($tar);
		$this->assertLessThan($reject, $tar, 'x-tar extract must run before the non-archive reject');
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
	 * Issue #2739 — a zip Blacklist body must fail closed. After geoip/top1m
	 * return, the arm falls into stdout extract onto $orig_download and the
	 * text pipeline. Blacklist has no category extract here. Comments and
	 * docblocks cannot define this scope.
	 */
	public function testZipBlacklistBodyFailsClosedWithoutExtraction(): void
	{
		$zip = strpos(self::$source, "elseif (\$file_type == 'application/zip') {");
		$uncomp = strpos(self::$source, "if (\$type == 'geoip' || \$type == 'asn')", $zip === FALSE ? 0 : $zip);
		$this->assertNotFalse($zip);
		$this->assertNotFalse($uncomp);
		$scope = substr(self::$source, $zip, $uncomp - $zip);
		$reject = strpos($scope, "if (\$type == 'blacklist') {");
		$geoip = strpos($scope, "if (\$type == 'geoip') {");
		$this->assertNotFalse($reject, $scope);
		$this->assertNotFalse($geoip, $scope);
		$this->assertLessThan($geoip, $reject, 'Blacklist reject must run before zip geoip/generic extract');
		$this->assertStringContainsString(
			"pfb_validate_log(\$header, 'extract', 'blacklist_not_archive', \$file_type);",
			$scope,
			'reject must name the detected type'
		);
		$brace = strpos($scope, '{', $reject);
		$this->assertNotFalse($brace);
		$reject_scope = substr($scope, $reject, self::closingBraceExclusive($scope, $brace) - $reject);
		$this->assertSame(
			1,
			substr_count($reject_scope, 'return PfbDownloadResult::failure();'),
			'reject scope must not swallow a sibling failure return'
		);
		$this->assertStringContainsString('unlink_if_exists($file_download);', $reject_scope);
		$this->assertStringContainsString('return PfbDownloadResult::failure();', $reject_scope);
		$this->assertStringNotContainsString('pfb_stage_publish', $reject_scope);
		$this->assertStringNotContainsString('tar -xf', $reject_scope);
		$this->assertStringNotContainsString('$pfb[\'dbdir\']', $reject_scope);
	}

	/**
	 * Issue #2638 B7 — uncompressed geoip x-tar must not tar -C a .mmdb file
	 * path ($header). Disk-writing extract goes to geoipshare and keeps ADR-46.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testUncompressedGeoipTarDoesNotExtractIntoHeaderFile(): void
	{
		$uncomp = strpos(self::$source, "if (\$type == 'geoip' || \$type == 'asn')");
		$top1m = strpos(self::$source, "if (\$type == 'top1m') {", $uncomp === FALSE ? 0 : $uncomp);
		$this->assertNotFalse($uncomp);
		$this->assertNotFalse($top1m);
		$scope = substr(self::$source, $uncomp, $top1m - $uncomp);
		$this->assertStringNotContainsString(
			'-C {$header_esc}',
			$scope,
			'geoip tar -C must be geoipshare, not $header (.mmdb file)'
		);
	}

	/**
	 * Issue #2638 B9 — glob() matches directories, so a *domains directory
	 * satisfies an empty($list) guard. Category publish must count files.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testBlacklistEmptyTreeGuardCountsFilesNotDirectories(): void
	{
		$this->assertStringContainsString(
			"array_filter(\$list, 'is_file')",
			self::$source,
			'glob() of staged categories must drop directory hits before the empty-tree guard'
		);
	}

	/**
	 * Issue #2638 B2 — a plain-tar TOP1M body must extract, not copy-as-text.
	 * Route into the zip/container archive branch. Comments/docblocks cannot
	 * define this scope.
	 */
	public function testPlainTarTop1mRoutesThroughArchiveExtract(): void
	{
		$this->assertStringContainsString(
			"\$file_type == 'application/x-tar' && \$type == 'top1m'",
			self::$source,
			'plain tar TOP1M must extract as a container archive, not copy-as-text'
		);
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

	/** Exclusive end index of the brace block whose `{` is at `$openBrace`. */
	private static function closingBraceExclusive(string $source, int $openBrace): int
	{
		$depth = 0;
		$length = strlen($source);
		for ($index = $openBrace; $index < $length; $index++) {
			if ($source[$index] === '{') {
				$depth++;
			} elseif ($source[$index] === '}') {
				$depth--;
				if ($depth === 0) {
					return $index + 1;
				}
			}
		}
		return $length;
	}
}
