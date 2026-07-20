<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_download()'s extraction sites must route a nonzero exec() exit -- and,
 * for the uncompressed branches, a failed @rename() (issue #1188) -- to the
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
		if ($source === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}

		$start = strpos($source, 'function pfb_download(');
		if ($start === FALSE) {
			throw new RuntimeException('test bootstrap: function pfb_download( not found');
		}

		if (!preg_match('/^function\s+\w+/m', $source, $m, PREG_OFFSET_CAPTURE, $start + 20)) {
			throw new RuntimeException('test bootstrap: end-of-function boundary not found');
		}
		$end = $m[0][1];

		self::$body = substr($source, $start, $end - $start);
	}

	/**
	 * @return list<array{id: int|null, text: string}>
	 */
	private static function significantTokens(string $source): array
	{
		$tokens = array();
		foreach (token_get_all('<?php ' . $source) as $token) {
			if (is_array($token)) {
				if (in_array($token[0], [T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], TRUE)) {
					continue;
				}
				$tokens[] = array('id' => $token[0], 'text' => $token[1]);
			} else {
				$tokens[] = array('id' => NULL, 'text' => $token);
			}
		}

		return $tokens;
	}

	private static function hasNonzeroRetvalGuard(string $segment): bool
	{
		$tokens = self::significantTokens($segment);
		$depths = self::structuralDepths($tokens);
		$outerDepth = $depths === array() ? 0 : min($depths);
		for ($i = 0, $last = count($tokens) - 7; $i <= $last; $i++) {
			if ($depths[$i] === $outerDepth
				&& $tokens[$i]['id'] === T_IF
				&& $tokens[$i + 1]['text'] === '('
				&& $tokens[$i + 2] === array('id' => T_VARIABLE, 'text' => '$retval')
				&& $tokens[$i + 3]['id'] === T_IS_NOT_EQUAL
				&& $tokens[$i + 4] === array('id' => T_LNUMBER, 'text' => '0')
				&& $tokens[$i + 5]['text'] === ')') {
				return $tokens[$i + 6]['text'] === '{'
					&& self::hasDirectFailureResult($tokens, $i + 6);
			}
		}

		return FALSE;
	}

	/**
	 * @return array{bound: bool, directFailureResult: bool}
	 */
	private static function analyzeRenameGuard(string $segment, string $destination, int $outerDepth = 0): array
	{
		$tokens = self::significantTokens($segment);
		$depths = self::structuralDepths($tokens);
		$count = count($tokens);
		for ($i = 0; $i < $count; $i++) {
			$previousId = $tokens[$i - 1]['id'] ?? NULL;
			$isGlobalRename = ($tokens[$i]['id'] === T_STRING
					&& strcasecmp($tokens[$i]['text'], 'rename') === 0)
				|| ($tokens[$i]['id'] === T_NAME_FULLY_QUALIFIED
					&& strcasecmp($tokens[$i]['text'], '\\rename') === 0);
			if (!$isGlobalRename
				|| ($tokens[$i + 1]['text'] ?? '') !== '('
				|| in_array($previousId, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW, T_FUNCTION], TRUE)) {
				continue;
			}
			if ($depths[$i] !== $outerDepth) {
				continue;
			}

			$assignment = $i - 1;
			if (($tokens[$assignment]['text'] ?? '') === '@') {
				$assignment--;
			}
			$lhs = $assignment - 1;
			$boundary = $tokens[$lhs - 1]['text'] ?? NULL;
			if (($tokens[$assignment]['text'] ?? '') !== '='
				|| ($tokens[$lhs] ?? NULL) !== array('id' => T_VARIABLE, 'text' => '$renamed')
				|| ($depths[$assignment] ?? NULL) !== $outerDepth
				|| ($depths[$lhs] ?? NULL) !== $outerDepth
				|| ($boundary !== NULL && !in_array($boundary, [';', '{', '}'], TRUE))) {
				return array('bound' => FALSE, 'directFailureResult' => FALSE);
			}

			$args = array(array());
			$depth = 1;
			$close = NULL;
			for ($j = $i + 2; $j < $count; $j++) {
				if ($tokens[$j]['text'] === '(') {
					$depth++;
				} elseif ($tokens[$j]['text'] === ')') {
					$depth--;
					if ($depth === 0) {
						$close = $j;
						break;
					}
				} elseif ($tokens[$j]['text'] === ',' && $depth === 1) {
					$args[] = array();
					continue;
				}
				$args[array_key_last($args)][] = $tokens[$j];
			}

			$argumentText = array_map(
				static fn(array $arg): string => implode('', array_map(
					static fn(array $token): string => $token['text'],
					$arg
				)),
				$args
			);
			if ($close === NULL || $argumentText !== ['"{$file_download}"', '"{' . $destination . '}"']) {
				return array('bound' => FALSE, 'directFailureResult' => FALSE);
			}

			$guard = $close + 2;
			$bound = ($tokens[$close + 1]['text'] ?? '') === ';'
				&& ($depths[$close] ?? NULL) === $outerDepth
				&& ($tokens[$guard]['id'] ?? NULL) === T_IF
				&& ($depths[$guard] ?? NULL) === $outerDepth
				&& ($tokens[$guard + 1]['text'] ?? '') === '('
				&& ($tokens[$guard + 2]['text'] ?? '') === '!'
				&& ($tokens[$guard + 3] ?? NULL) === array('id' => T_VARIABLE, 'text' => '$renamed')
				&& ($tokens[$guard + 4]['text'] ?? '') === ')'
				&& ($tokens[$guard + 5]['text'] ?? '') === '{';
			if (!$bound) {
				return array('bound' => FALSE, 'directFailureResult' => FALSE);
			}

			return array(
				'bound' => TRUE,
				'directFailureResult' => self::hasDirectFailureResult($tokens, $guard + 5)
			);
		}

		return array('bound' => FALSE, 'directFailureResult' => FALSE);
	}

	/**
	 * @param list<array{id: int|null, text: string}> $tokens
	 * @return list<int>
	 */
	private static function structuralDepths(array $tokens): array
	{
		$depth = 0;
		$interpolationDepth = 0;
		$depths = array();
		foreach ($tokens as $token) {
			$depths[] = $depth;
			if ($token['id'] === T_CURLY_OPEN || $token['id'] === T_DOLLAR_OPEN_CURLY_BRACES) {
				$interpolationDepth++;
				continue;
			}
			if ($interpolationDepth > 0) {
				if ($token['text'] === '{') {
					$interpolationDepth++;
				} elseif ($token['text'] === '}') {
					$interpolationDepth--;
				}
				continue;
			}
			if ($token['text'] === '{') {
				$depth++;
			} elseif ($token['text'] === '}') {
				$depth--;
			}
		}

		return $depths;
	}

	/**
	 * @param list<array{id: int|null, text: string}> $tokens
	 */
	private static function hasDirectFailureResult(array $tokens, int $openingBrace): bool
	{
		$depth = 1;
		$interpolationDepth = 0;
		$count = count($tokens);
		for ($i = $openingBrace + 1; $i < $count; $i++) {
			if ($tokens[$i]['id'] === T_CURLY_OPEN || $tokens[$i]['id'] === T_DOLLAR_OPEN_CURLY_BRACES) {
				$interpolationDepth++;
				continue;
			}
			if ($interpolationDepth > 0) {
				if ($tokens[$i]['text'] === '{') {
					$interpolationDepth++;
				} elseif ($tokens[$i]['text'] === '}') {
					$interpolationDepth--;
				}
				continue;
			}
			if ($tokens[$i]['text'] === '{') {
				$depth++;
			} elseif ($tokens[$i]['text'] === '}') {
				$depth--;
				if ($depth === 0) {
					break;
				}
			} elseif ($depth === 1 && $tokens[$i]['id'] === T_RETURN) {
				return (($tokens[$i + 1] ?? NULL) === array('id' => T_STRING, 'text' => 'PfbDownloadResult')
					&& ($tokens[$i + 2]['id'] ?? NULL) === T_DOUBLE_COLON
					&& ($tokens[$i + 3] ?? NULL) === array('id' => T_STRING, 'text' => 'failure')
					&& ($tokens[$i + 4]['text'] ?? '') === '('
					&& ($tokens[$i + 5]['text'] ?? '') === ')'
					&& ($tokens[$i + 6]['text'] ?? '') === ';');
			}
		}

		return FALSE;
	}

	public function testEveryPfbDownloadReturnUsesTypedResultExceptHeaderCallback(): void
	{
		$tokens = self::significantTokens(self::$body);
		$typedResultCount = 0;
		$headerCallbackCount = 0;
		$unexpectedReturns = array();

		for ($i = 0, $count = count($tokens); $i < $count; $i++) {
			if ($tokens[$i]['id'] !== T_RETURN) {
				continue;
			}

			$isTypedResult = ($tokens[$i + 1] ?? NULL) === array('id' => T_STRING, 'text' => 'PfbDownloadResult')
				&& ($tokens[$i + 2]['id'] ?? NULL) === T_DOUBLE_COLON
				&& in_array($tokens[$i + 3] ?? NULL, [
					array('id' => T_STRING, 'text' => 'success'),
					array('id' => T_STRING, 'text' => 'failure'),
				], TRUE)
				&& ($tokens[$i + 4]['text'] ?? '') === '(';
			if ($isTypedResult) {
				$typedResultCount++;
				continue;
			}

			$isHeaderCallback = ($tokens[$i + 1] ?? NULL) === array('id' => T_STRING, 'text' => 'strlen')
				&& ($tokens[$i + 2]['text'] ?? '') === '('
				&& ($tokens[$i + 3] ?? NULL) === array('id' => T_VARIABLE, 'text' => '$hdr_line')
				&& ($tokens[$i + 4]['text'] ?? '') === ')'
				&& ($tokens[$i + 5]['text'] ?? '') === ';';
			if ($isHeaderCallback) {
				$headerCallbackCount++;
				continue;
			}

			$expression = '';
			for ($j = $i; $j < min($i + 8, $count); $j++) {
				$expression .= $tokens[$j]['text'];
			}
			$unexpectedReturns[] = $expression;
		}

		$this->assertStringContainsString('function ($curl_handle, $hdr_line)', self::$body,
			'vacuity: the sole non-result return must remain the cURL header callback');
		$this->assertGreaterThan(0, $typedResultCount,
			'vacuity: pfb_download() must expose PfbDownloadResult success/failure returns');
		$this->assertSame(1, $headerCallbackCount,
			'pfb_download() may have only the header callback strlen return outside PfbDownloadResult');
		$this->assertSame(array(), $unexpectedReturns,
			'pfb_download() has an untyped return; every return must be PfbDownloadResult success/failure '
			. 'except the header callback strlen: ' . json_encode($unexpectedReturns));
	}

	// -----------------------------------------------------------------------
	// Row 1 -- gzip geoip: /usr/bin/tar -xzf site.
	// -----------------------------------------------------------------------

	public function testGzipGeoipTarCapturesRetvalAndIsCheckedBeforeSuccessResult(): void
	{
		$tarPos = strpos(self::$body, "/usr/bin/tar -xzf {\$file_dwn_esc} --strip=1 -C {\$pfb['geoipshare']}");
		$this->assertNotFalse($tarPos, 'vacuity: the gzip-geoip tar -xzf site must exist for this test to mean anything');

		$successResult = strpos(self::$body, 'return PfbDownloadResult::success();', $tarPos);
		$this->assertNotFalse($successResult, 'vacuity: gzip-geoip site must reach a success result;');
		$segmentStart = strrpos(substr(self::$body, 0, $tarPos), "\n");
		$segmentStart = $segmentStart === FALSE ? 0 : $segmentStart + 1;
		$segment = substr(self::$body, $segmentStart, $successResult + strlen('return PfbDownloadResult::success();') - $segmentStart);

		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segment,
			'gzip-geoip tar -xzf must capture $output, $retval -- a corrupt archive currently reports success unconditionally');
		$this->assertTrue(self::hasNonzeroRetvalGuard($segment),
			'gzip-geoip must check nonzero $retval before its success result -- a nonzero exit must not report success');
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
		$this->assertStringContainsString('PfbDownloadResult::failure()', $segment,
			'gzip-asn nonzero-retval path must return failure before asn_table runs');
	}

	// -----------------------------------------------------------------------
	// Row 3 -- gzip top1m: same gunzip-capture-but-ignored shape as asn.
	// -----------------------------------------------------------------------

	public function testGzipTop1mChecksRetvalBeforeSuccessResult(): void
	{
		$top1mAnchor = strpos(self::$body, "\$type == 'top1m'");
		$this->assertNotFalse($top1mAnchor, 'vacuity: the gzip-top1m branch must exist');

		$gunzip = strpos(self::$body, 'exec("/usr/bin/gunzip -c {$file_download} > {$header_esc}"', $top1mAnchor);
		$this->assertNotFalse($gunzip, 'vacuity: gzip-top1m gunzip exec must exist');

		$successResult = strpos(self::$body, 'return PfbDownloadResult::success();', $gunzip);
		$this->assertNotFalse($successResult, 'vacuity: gzip-top1m site must reach a success result;');
		$segment = substr(self::$body, $gunzip, $successResult + strlen('return PfbDownloadResult::success();') - $gunzip);

		$this->assertTrue(self::hasNonzeroRetvalGuard($segment),
			'gzip-top1m must check nonzero $retval before its success result -- a nonzero gunzip exit must not report success; '
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
	// success result.
	// -----------------------------------------------------------------------

	public function testZipExtrasBothTarSitesCaptureRetvalAndAreCheckedBeforeSuccessResult(): void
	{
		$multi = strpos(self::$body, 'exec("/usr/bin/tar -xf {$file_dwn_esc} --strip=1 -C {$header_esc}');
		$this->assertNotFalse($multi, 'vacuity: the zip multi-member tar -xf site must exist');

		$single = strpos(self::$body, 'exec("/usr/bin/tar -xOf {$file_dwn_esc} > {$header_esc}"', $multi);
		$this->assertNotFalse($single, 'vacuity: the zip single-member tar -xOf site must exist');

		$successResult = strpos(self::$body, 'return PfbDownloadResult::success();', $single);
		$this->assertNotFalse($successResult, 'vacuity: zip extras must reach a shared success result;');

		$segMulti = substr(self::$body, $multi, $single - $multi);
		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segMulti,
			'zip multi-member tar -xf must capture $output, $retval; segment: ' . json_encode($segMulti));

		$segSingleToReturn = substr(self::$body, $single, $successResult + strlen('return PfbDownloadResult::success();') - $single);
		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segSingleToReturn,
			'zip single-member tar -xOf must capture $output, $retval; segment: ' . json_encode($segSingleToReturn));
		$this->assertTrue(self::hasNonzeroRetvalGuard($segSingleToReturn),
			'zip extras must check nonzero $retval before their shared success result; segment: '
			. json_encode($segSingleToReturn));
	}

	// -----------------------------------------------------------------------
	// Row 7 -- uncompressed extras: @rename() result must be checked.
	// -----------------------------------------------------------------------

	public function testUncompressedExtrasChecksRenameResult(): void
	{
		$branchPos = strpos(self::$body, '// Uncompressed file format.');
		$this->assertNotFalse($branchPos, 'vacuity: the uncompressed-format branch must exist');

		$nextBranch = strpos(self::$body, "elseif (\$type == 'blacklist') {", $branchPos);
		$this->assertNotFalse($nextBranch, 'vacuity: the uncompressed-blacklist sibling branch must exist');
		$segment = substr(self::$body, $branchPos, $nextBranch - $branchPos);

		$analysis = self::analyzeRenameGuard($segment, '$head_download', 1);
		$this->assertTrue($analysis['bound'],
			'uncompressed extras must check !$renamed before success result; segment: ' . json_encode($segment));
		$this->assertTrue($analysis['directFailureResult'],
			'a failed rename() must have a failure result path; segment: ' . json_encode($segment));
	}

	// -----------------------------------------------------------------------
	// Row 8 -- generic uncompressed feeds: @rename() to .orig result must be
	// checked before the branch falls into the $retval == 0 success gate.
	// -----------------------------------------------------------------------

	public function testGenericUncompressedRenameResultChecked(): void
	{
		$commentPos = strpos(self::$body, "// Rename file to 'orig' format");
		$this->assertNotFalse($commentPos, 'vacuity: the generic-uncompressed orig-rename comment must exist');

		$secondPos = strpos(self::$body, "// Rename file to 'orig' format", $commentPos + 1);
		$this->assertFalse($secondPos, 'vacuity: "Rename file to \'orig\' format" must appear exactly once');

		$gatePos = strpos(self::$body, 'if ($retval == 0) {', $commentPos);
		$this->assertNotFalse($gatePos, 'vacuity: the $retval == 0 success gate must follow the generic-uncompressed branch');

		$segment = substr(self::$body, $commentPos, $gatePos - $commentPos);

		$analysis = self::analyzeRenameGuard($segment, '$orig_download');
		$this->assertTrue($analysis['bound'],
			'generic uncompressed feeds must check !$renamed before the $retval == 0 success gate; segment: '
			. json_encode($segment));
		$this->assertTrue($analysis['directFailureResult'],
			'a failed rename() must have a failure result path before the success gate; segment: ' . json_encode($segment));
	}
}
