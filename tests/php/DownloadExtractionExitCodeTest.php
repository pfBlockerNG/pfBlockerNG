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
		$this->assertStringContainsString(
			'pfb_geoip_extract_tar_to_share($header, $file_download, $file_dwn_esc, $retval)',
			$scope
		);
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
	 * pfb_download() decompresses bzip2 feeds onto the selected publication stage;
	 * pin this comment-free branch and its staged-publish guard so the branch cannot
	 * revert to a raw redirect. Comments/docblocks cannot define this scope.
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
		$this->assertStringContainsString('if (!pfb_stage_publish($text_download,', $scope);
	}

	/**
	 * Issue #2739 — a bzip2 Blacklist body must fail closed. The arm
	 * extracts onto the standard/ET-selected text target for IP feeds; Blacklist
	 * has no category extract here, so a successful empty update is a lie. Comments
	 * and docblocks cannot define this scope.
	 */
	public function testBzip2BlacklistBodyFailsClosedWithoutExtraction(): void
	{
		$bzip2 = strpos(self::$source, "elseif (\$file_type == 'application/x-bzip2') {");
		$zip = strpos(self::$source, "elseif (\$file_type == 'application/zip') {", $bzip2 === FALSE ? 0 : $bzip2);
		$this->assertNotFalse($bzip2);
		$this->assertNotFalse($zip);
		$scope = substr(self::$source, $bzip2, $zip - $bzip2);
		$reject = strpos($scope, "if (\$type == 'blacklist') {");
		$publish = strpos($scope, 'if (!pfb_stage_publish($text_download,');
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
		$this->assertStringContainsString('pfb_archive_unsafe_member', $scope);
		$this->assertStringContainsString(
			'pfb_blacklist_tar_finalize_staged($staged, $filename, $retval)',
			$scope
		);
		$this->assertStringContainsString(
			'pfb_blacklist_tar_mark_updated($file_dwn, $filename)',
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
		$this->assertStringContainsString(
			'pfb_blacklist_tar_mark_updated($file_dwn, $filename)',
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
		$tar = strpos($scope, "if (\$file_type == 'application/x-tar') {");
		$this->assertNotFalse($tar);
		$tarBrace = strpos($scope, '{', $tar);
		$this->assertNotFalse($tarBrace);
		$reject_scope = substr($scope, self::closingBraceExclusive($scope, $tarBrace));
		$this->assertStringNotContainsString(
			'$retval = 0;',
			$reject_scope,
			'uncompressed Blacklist must not treat a non-archive body as a successful extract'
		);
		$this->assertStringContainsString(
			"pfb_validate_log(\$header, 'extract', 'blacklist_not_archive', \$file_type);",
			$reject_scope,
			'reject must name the detected type'
		);
		$this->assertSame(
			1,
			substr_count($reject_scope, 'return PfbDownloadResult::failure();'),
			'reject scope must not swallow the x-tar arm failure return'
		);
		$this->assertStringContainsString('unlink_if_exists($file_download);', $reject_scope);
		$this->assertStringContainsString('return PfbDownloadResult::failure();', $reject_scope);
		$this->assertStringNotContainsString('pfb_stage_publish_dir', $reject_scope);
		$this->assertStringNotContainsString('tar -xf', $reject_scope);
		$this->assertStringNotContainsString('$pfb[\'dbdir\']', $reject_scope);
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
		$this->assertStringContainsString('pfb_archive_unsafe_member', $scope);
		$reject = strpos($scope, "pfb_validate_log(\$header, 'extract', 'blacklist_not_archive', \$file_type);");
		$tar = strpos($scope, "if (\$file_type == 'application/x-tar') {");
		$this->assertNotFalse($reject);
		$this->assertNotFalse($tar);
		$this->assertLessThan($reject, $tar, 'x-tar extract must run before the non-archive reject');
		$this->assertStringContainsString(
			'pfb_blacklist_tar_mark_updated($file_dwn, $filename)',
			$scope
		);
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
		// issue #2668: the directory mode extracts into staging inside its target
		// and publishes the members only on a clean exit, so its -C is the staged
		// path rather than the live publication. issue #2659: the disk-writing mode
		// carries the restriction flags; the stdout mode below must not.
		$this->assertStringContainsString('exec(pfb_extract_cmd("/usr/bin/tar -xf {$file_dwn_esc} " . PFB_TAR_EXTRACT_FLAGS . " --strip=1 -C " . escapeshellarg($staged) . " >/dev/null 2>&1"), $output, $retval);', $scope);
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("/usr/bin/tar -xOf {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);', $scope);
		// issue #2169: the stdout mode publishes through the staged helper; the
		// directory mode publishes through the staged merge helper.
		$this->assertStringContainsString('if (!pfb_stage_publish($head_download,', $scope);
		$this->assertStringContainsString('if (!pfb_stage_publish_dir_merge($head_download,', $scope);
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
			'geoip tar -C must stage inside geoipshare, never $header (.mmdb file)'
		);
		$geoip = strpos($scope, "if (\$type == 'geoip') {");
		$this->assertNotFalse($geoip);
		$brace = strpos($scope, '{', $geoip);
		$this->assertNotFalse($brace);
		$geoip_scope = substr($scope, $geoip, self::closingBraceExclusive($scope, $brace) - $geoip);
		$this->assertStringContainsString(
			'pfb_geoip_extract_tar_to_share($header, $file_download, $file_dwn_esc, $retval)',
			$geoip_scope
		);
	}

	/**
	 * Issue #2764 — gzip inner-tar extract (generic/IP) must stdout-extract
	 * (`tar -xOf -`) and only when the inner MIME is x-tar. Mutations (c)
	 * drop `-O` and (e) invert the comparison stay green without this pin.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testGzipInnerTarExtractIsStdoutAndTypeGated(): void
	{
		$gzip = strpos(self::$source, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $gzip === FALSE ? 0 : $gzip);
		$inner = strpos(self::$source, 'else { $reject_detail = array();', $blacklist === FALSE ? 0 : $blacklist);
		$bzip = strpos(self::$source, "elseif (\$file_type == 'application/x-bzip2')", $inner === FALSE ? 0 : $inner);
		$this->assertNotFalse($gzip);
		$this->assertNotFalse($inner);
		$this->assertNotFalse($bzip);
		$scope = substr(self::$source, $inner, $bzip - $inner);
		$this->assertStringContainsString(
			'$extract_tar = ($inner_type == \'application/x-tar\')',
			$scope,
			'inner tar extract must be gated on application/x-tar'
		);
		$this->assertStringContainsString(
			'tar -xOf -',
			$scope,
			'gzip inner tar must stdout-extract (-O); dropping it writes a tar archive as a feed'
		);
	}

	/**
	 * Issue #2764 — both Blacklist tar staging sites share one helper that
	 * drops directory glob hits. A site-count of 2 breaks when the arms
	 * unify. Comments/docblocks cannot define this scope.
	 */
	public function testBlacklistEmptyTreeGuardCountsFilesNotDirectories(): void
	{
		$this->assertTrue(
			function_exists('pfb_blacklist_tar_finalize_staged'),
			'Blacklist tar staging must share pfb_blacklist_tar_finalize_staged'
		);
		$this->assertGreaterThanOrEqual(
			2,
			substr_count(self::$source, 'pfb_blacklist_tar_finalize_staged($staged'),
			'gzip and uncompressed Blacklist tar arms must both call the helper'
		);
		$this->assertGreaterThanOrEqual(
			2,
			substr_count(self::$source, 'pfb_blacklist_tar_mark_updated($file_dwn, $filename)'),
			'gzip and uncompressed Blacklist tar arms must both mark updated via the helper'
		);
		$this->assertGreaterThanOrEqual(
			2,
			substr_count(self::$source, 'pfb_geoip_extract_tar_to_share($header, $file_download, $file_dwn_esc, $retval)'),
			'gzip and uncompressed geoip tar arms must both call the share helper'
		);
		$this->assertStringContainsString(
			"array_filter(\$list, 'is_file')",
			self::$source,
			'helper must still drop directory glob hits'
		);
	}

	/**
	 * Issue #2764 — a *domains directory in the staged tree is not a
	 * category file. The helper returns the empty-tree sentinel.
	 */
	public function testBlacklistTarFinalizeTreatsDirectoryOnlyTreeAsEmpty(): void
	{
		$this->assertTrue(function_exists('pfb_blacklist_tar_finalize_staged'));
		$staged = sys_get_temp_dir() . '/pfb2764_' . (string) getmypid();
		@mkdir($staged, 0700, TRUE);
		@mkdir($staged . '/feed_cat', 0700);
		try {
			$this->assertSame(
				pfb_download_initial_retval(),
				pfb_blacklist_tar_finalize_staged($staged, 'feed', 0)
			);
		} finally {
			@rmdir($staged . '/feed_cat');
			@rmdir($staged);
		}
	}

	/**
	 * Issue #2764 F2 — sidecar purge and .update live in one helper so gzip/x-tar
	 * cannot drift. Comments/docblocks cannot define this scope.
	 */
	public function testBlacklistTarMarkUpdatedUnlinksSidecarsAndTouchesUpdate(): void
	{
		$start = strpos(self::$source, 'function pfb_blacklist_tar_mark_updated(');
		$this->assertNotFalse($start);
		$brace = strpos(self::$source, '{', $start);
		$this->assertNotFalse($brace);
		$body = substr(self::$source, $start, self::closingBraceExclusive(self::$source, $brace) - $start);
		$this->assertMatchesRegularExpression(
			'/foreach \(array\("\{\$file_dwn\}\.orig", "\{\$file_dwn\}\.xxhash128", "\{\$file_dwn\}\.md5"\) as \$blacklist_stale\) \{\s*unlink_if_exists\(\$blacklist_stale\);\s*\}/',
			$body
		);
		$this->assertStringContainsString(
			'touch("{$pfb[\'dbdir\']}/{$filename}/{$filename}.update")',
			$body
		);
		// issue #2735: success return is immediately after the update marker.
		$this->assertMatchesRegularExpression(
			'/touch\("\{\$pfb\[.dbdir.\]\}\/\{\$filename\}\/\{\$filename\}\.update"\);\s*return PfbDownloadResult::success\(\);/',
			$body
		);
	}

	/**
	 * Issue #2764 F3 — geoip tar has ADR-46 in one helper, and since issue #2668 its
	 * -C is a staging directory inside geoipshare rather than the live share itself.
	 * Comments/docblocks cannot define this scope.
	 */
	public function testGeoipTarExtractHelperWritesShareNotHeader(): void
	{
		$start = strpos(self::$source, 'function pfb_geoip_extract_tar_to_share(');
		$this->assertNotFalse($start);
		$brace = strpos(self::$source, '{', $start);
		$this->assertNotFalse($brace);
		$body = substr(self::$source, $start, self::closingBraceExclusive(self::$source, $brace) - $start);
		$this->assertStringContainsString('pfb_stage_publish_dir_merge($pfb[\'geoipshare\'],', $body);
		$this->assertStringNotContainsString('-C {$pfb[\'geoipshare\']}', $body);
		$this->assertStringNotContainsString('-C {$header_esc}', $body);
		$this->assertStringContainsString('pfb_archive_unsafe_member', $body);
		$this->assertMatchesRegularExpression('/exec\(pfb_extract_cmd\(".*tar -xf .*\\$output, \\$retval\);/', $body);
	}

	/**
	 * Issue #2638 B2 — a plain-tar TOP1M body must extract, not copy-as-text.
	 * Route into the zip/container archive branch. Comments/docblocks cannot
	 * define this scope.
	 */
	public function testPlainTarTop1mRoutesThroughArchiveExtract(): void
	{
		$uncomp = strpos(self::$source, "if (\$type == 'geoip' || \$type == 'asn')");
		$top1m = strpos(self::$source, "if (\$type == 'top1m') {", $uncomp === FALSE ? 0 : $uncomp);
		$blacklist = strpos(self::$source, "elseif (\$type == 'blacklist') {", $top1m === FALSE ? 0 : $top1m);
		$this->assertNotFalse($uncomp);
		$this->assertNotFalse($top1m);
		$this->assertNotFalse($blacklist);
		$scope = substr(self::$source, $top1m, $blacklist - $top1m);
		$this->assertStringContainsString("if (\$file_type == 'application/x-tar') {", $scope);
		$this->assertStringContainsString('tar -xOf', $scope);
		$this->assertStringContainsString('count($archive_members) !== 1', $scope);
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

	/**
	 * Issue #2682: an extraction that parses but yields no address is refused by the
	 * helper, and the refusal has to stop the pass. The content-hash sidecar is
	 * refreshed by pfb_download_finalize_text() further down the same function, so a
	 * gate that logged and fell through would persist a digest for bytes that were
	 * never ingested — and the next cron would then read the feed as unchanged.
	 */
	public function testXlsxRefusalReturnsBeforeTheSidecarRefresh(): void
	{
		$xlsx = strpos(self::$source, "if (strpos(\$xlsxtest, '.xlsx') !== FALSE) {");
		$this->assertNotFalse($xlsx);
		$zipBranch = strpos(self::$source, '} else {', $xlsx);
		$this->assertNotFalse($zipBranch);
		// Bounded by the branch, so a neutered xlsx gate cannot be satisfied by the
		// ET branch's identical one further down the function.
		$scope = substr(self::$source, $xlsx, $zipBranch - $xlsx);
		$gate = strpos($scope, 'if (!pfb_download_extraction_succeeded($retval)) {');
		$this->assertNotFalse($gate, 'the xlsx branch must gate on the helper exit status');
		$refusal = substr($scope, $gate,
			self::closingBraceExclusive($scope, strpos($scope, '{', $gate)) - $gate);
		$this->assertStringContainsString('return PfbDownloadResult::failure();', $refusal,
			'the xlsx refusal must return, not fall through into the text pipeline');
		$this->assertStringNotContainsString('pfb_download_finalize_text', $refusal);
		// Searched from the end of the branch, so the helper's own definition (far
		// earlier in the file) cannot satisfy it: moving the refresh ahead of the
		// archive branch leaves no later occurrence and this fails.
		$this->assertNotFalse(strpos(self::$source, 'pfb_download_finalize_text(', $zipBranch),
			'the sidecar refresh must sit downstream of the xlsx refusal, never ahead of it');
	}

	/**
	 * pfb_download_fetch() keeps the downloaded ET IQRisk body at its raw staging
	 * path until processet() accepts the selected categories. A refusal removes
	 * only that stage here: the live publication and its source-hash baseline
	 * remain last-good, while pfb_download() owns the #2820 HTTP-validator clear.
	 */
	public function testEtBodyStagesUntilTheHelperAcceptsIt(): void
	{
		$isEt = strpos(self::$source, "\$is_et = strpos(\$list_url, 'iprepdata.txt') !== FALSE;");
		$this->assertNotFalse($isEt, 'the ET URL decision must be normalized once');
		$this->assertStringContainsString('$et_stage = "{$orig_download}.etstage";', self::$source);
		$this->assertGreaterThanOrEqual(
			4,
			substr_count(self::$source, 'pfb_stage_publish($text_download,'),
			'gzip, bzip2, zip, and tar standard-feed payloads must target the ET stage'
		);
		$guard = strpos(self::$source, 'if (!$is_et) {', $isEt);
		$this->assertNotFalse($guard, 'the plain-body rename must be gated away from ET input');
		$guardBrace = strpos(self::$source, '{', $guard);
		$this->assertNotFalse($guardBrace);
		$guardEnd = self::closingBraceExclusive(self::$source, $guardBrace);
		$rename = strpos(self::$source, '@rename("{$file_download}", "{$orig_download}")', $guard);
		$this->assertNotFalse($rename, 'non-ET plain bodies must retain their existing rename');
		$this->assertLessThan($guardEnd, $rename,
			'the raw-to-live rename must remain inside the non-ET guard');

		$start = strpos(self::$source, 'if ($is_et) {', $guardEnd);
		$this->assertNotFalse($start, 'the ET helper branch must still be in pfb_download()');
		$brace = strpos(self::$source, '{', $start);
		$this->assertNotFalse($brace);
		$scopeEnd = self::closingBraceExclusive(self::$source, $brace);
		$scope = substr(self::$source, $start, $scopeEnd - $start);
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("{$pfb[\'script\']} et {$header_esc} x x x x x '
			. '{$pfb[\'etblock\']} {$pfb[\'etmatch\']} {$elog}"), $output, $retval);', $scope);
		$fail = strpos($scope, 'if (!pfb_download_extraction_succeeded($retval)) {');
		$this->assertNotFalse($fail, 'the ET branch must gate on the helper exit status');
		$refusal = substr($scope, $fail);
		$this->assertStringContainsString('unlink_if_exists($file_download);', $refusal,
			'a refused staged body must be discarded');
		$this->assertStringContainsString('unlink_if_exists($et_stage);', $refusal,
			'a refused decompressed ET stage must be discarded');
		$this->assertStringContainsString('return PfbDownloadResult::failure();', $refusal);
		$this->assertStringNotContainsString('unlink_if_exists("{$orig_download}', $refusal,
			'the ET branch must not bypass the wrapper by clearing live artifacts directly');

		$finalize = strpos(self::$source, 'pfb_download_finalize_text(', $start);
		$this->assertNotFalse($finalize);
		$this->assertGreaterThan($scopeEnd, $finalize,
			'the accepted raw body hash and text finalization must happen after processet succeeds');
	}


	public function testEtAlertsReaderDefersWhileGenerationCommitOwnsTheLock(): void
	{
		$savedPfb = $GLOBALS['pfb'];
		$savedContinents = $GLOBALS['continents'] ?? NULL;
		$dir = sys_get_temp_dir() . '/pfb_et_lock_' . bin2hex(random_bytes(8));
		$etdir = "{$dir}/ET";
		$aliasdir = "{$dir}/alias";
		$marker = "{$dir}/reader-invoked";
		$this->assertTrue(mkdir($etdir, 0700, TRUE));
		$this->assertTrue(mkdir($aliasdir, 0700, TRUE));
		$this->assertNotFalse(file_put_contents("{$etdir}/ET_Cnc.txt", "192.0.2.10\n"));
		$grep = "{$dir}/grep-probe";
		$probe = "#!/bin/sh\ntouch " . escapeshellarg($marker) . "\necho "
			. escapeshellarg("{$etdir}/ET_Cnc.txt:192.0.2.10") . "\n";
		$this->assertNotFalse(file_put_contents($grep, $probe));
		$this->assertTrue(chmod($grep, 0700));
		$GLOBALS['pfb']['etdir'] = $etdir;
		$GLOBALS['pfb']['aliasdir'] = $aliasdir;
		$GLOBALS['pfb']['grep'] = $grep;
		$GLOBALS['continents'] = [];
		$fields = array_fill(0, 18, '');
		$fields[3] = 'block';
		$fields[4] = 4;
		$fields[7] = '192.0.2.10';
		$fields[11] = 'in';
		$fields[13] = 'pfB_ET_v4';
		$fields[14] = '192.0.2.10';
		$fields[15] = 'IQRisk:ET_Cnc';
		pfb_ip_render_memos_reset();
		$lock = fopen("{$etdir}.transaction.lock", 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));

		try {
			$result = pfb_ip_render_attribution($fields);
			$this->assertSame('Not listed!', $result['feed_new']);
			$this->assertSame(['validate' => [], 'miss' => []], pfb_ip_render_memos());
			$this->assertFileDoesNotExist($marker);
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
			pfb_ip_render_memos_reset();
			$GLOBALS['pfb'] = $savedPfb;
			if ($savedContinents === NULL) {
				unset($GLOBALS['continents']);
			} else {
				$GLOBALS['continents'] = $savedContinents;
			}
			rmdir_recursive($dir);
		}
	}

	public function testEveryEtAttributionReaderUsesTheGenerationCommitLock(): void
	{
		$render = strpos(self::$source, 'function pfb_ip_render_attribution(array $fields): array {');
		$renderEnd = strpos(self::$source, 'function &pfb_ip_render_memos(', $render === FALSE ? 0 : $render);
		$this->assertNotFalse($render);
		$this->assertNotFalse($renderEnd);
		$renderScope = substr(self::$source, $render, $renderEnd - $render);
		$this->assertStringContainsString('"{$pfb[\'etdir\']}.transaction.lock"', $renderScope);
		$this->assertStringContainsString('LOCK_SH | LOCK_NB', $renderScope);


		$prefetch = strpos(self::$source, 'function pfb_ip_prefetch(array $rows): void {');
		$prefetchEnd = strpos(self::$source, 'function pfb_ip_in_cidr(', $prefetch === FALSE ? 0 : $prefetch);
		$this->assertNotFalse($prefetch);
		$this->assertNotFalse($prefetchEnd);
		$prefetchScope = substr(self::$source, $prefetch, $prefetchEnd - $prefetch);
		$this->assertStringContainsString('"{$pfb[\'etdir\']}.transaction.lock"', $prefetchScope);
		$this->assertStringContainsString('LOCK_SH | LOCK_NB', $prefetchScope);
		$daemon = strpos(self::$source, 'if ($et_enabled && strpos($pfb_query[0], "{$et_header}") !== FALSE) {');
		$daemonEnd = strpos(self::$source, 'if (!empty($pathgeoip)) {', $daemon === FALSE ? 0 : $daemon);
		$this->assertNotFalse($daemon);
		$this->assertNotFalse($daemonEnd);
		$daemonScope = substr(self::$source, $daemon, $daemonEnd - $daemon);
		$this->assertStringContainsString('"{$pfb[\'etdir\']}.transaction.lock"', $daemonScope);
		$this->assertStringContainsString('LOCK_SH | LOCK_NB', $daemonScope);
	}

	public function testEtRefusalLeavesHttpValidatorClearingToTheDownloadWrapper(): void
	{
		$wrapper = strpos(self::$source, 'function pfb_download(PfbDownloadRequest $request): PfbDownloadResult {');
		$fetch = strpos(self::$source, 'function pfb_download_fetch(PfbDownloadRequest $request): PfbDownloadResult {');
		$this->assertNotFalse($wrapper);
		$this->assertNotFalse($fetch);
		$wrapperScope = substr(self::$source, $wrapper, $fetch - $wrapper);
		$this->assertStringContainsString("if (!\$result->success && \$request->type === '')", $wrapperScope,
			'standard-list failures must enter the one #2820 validator-clear boundary');
		$this->assertStringContainsString('unlink_if_exists("{$request->downloadPath}.orig.etag");', $wrapperScope);
		$this->assertStringContainsString('unlink_if_exists("{$request->downloadPath}.orig.lastmod");', $wrapperScope);
		$this->assertStringNotContainsString('.orig.xxhash128', $wrapperScope,
			'the last-good source hash is publication state, not an HTTP validator');

		$et = strpos(self::$source, 'if ($is_et) {', $fetch);
		$this->assertNotFalse($et);
		$etBrace = strpos(self::$source, '{', $et);
		$this->assertNotFalse($etBrace);
		$etScope = substr(self::$source, $et, self::closingBraceExclusive(self::$source, $etBrace) - $et);
		$this->assertStringNotContainsString('.orig.etag', $etScope,
			'the ET branch must leave HTTP-validator clearing to the wrapper');
		$this->assertStringNotContainsString('.orig.lastmod', $etScope,
			'the ET branch must leave HTTP-validator clearing to the wrapper');
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
