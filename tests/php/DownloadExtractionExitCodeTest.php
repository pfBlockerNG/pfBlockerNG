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
		for ($i = 0, $last = count($tokens) - 6; $i <= $last; $i++) {
			if ($tokens[$i]['id'] === T_IF
				&& $tokens[$i + 1]['text'] === '('
				&& $tokens[$i + 2] === array('id' => T_VARIABLE, 'text' => '$retval')
				&& $tokens[$i + 3]['id'] === T_IS_NOT_EQUAL
				&& $tokens[$i + 4] === array('id' => T_LNUMBER, 'text' => '0')
				&& $tokens[$i + 5]['text'] === ')') {
				return TRUE;
			}
		}

		return FALSE;
	}

	/**
	 * @return array{bound: bool, directReturn: bool}
	 */
	private static function analyzeRenameGuard(string $segment, string $destination): array
	{
		$tokens = self::significantTokens($segment);
		$count = count($tokens);
		for ($i = 0; $i < $count; $i++) {
			if ($tokens[$i] !== array('id' => T_VARIABLE, 'text' => '$renamed')
				|| ($tokens[$i + 1]['text'] ?? '') !== '=') {
				continue;
			}

			$call = $i + 2;
			if (($tokens[$call]['text'] ?? '') === '@') {
				$call++;
			}
			if (($tokens[$call] ?? NULL) !== array('id' => T_STRING, 'text' => 'rename')
				|| ($tokens[$call + 1]['text'] ?? '') !== '(') {
				continue;
			}

			$args = array(array());
			$depth = 1;
			$close = NULL;
			for ($j = $call + 2; $j < $count; $j++) {
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

			$variables = array_map(
				static fn(array $arg): array => array_values(array_map(
					static fn(array $token): string => $token['text'],
					array_filter($arg, static fn(array $token): bool => $token['id'] === T_VARIABLE)
				)),
				$args
			);
			if ($close === NULL || $variables !== [['$file_download'], [$destination]]) {
				return array('bound' => FALSE, 'directReturn' => FALSE);
			}

			$guard = $close + 2;
			$bound = ($tokens[$close + 1]['text'] ?? '') === ';'
				&& ($tokens[$guard]['id'] ?? NULL) === T_IF
				&& ($tokens[$guard + 1]['text'] ?? '') === '('
				&& ($tokens[$guard + 2]['text'] ?? '') === '!'
				&& ($tokens[$guard + 3] ?? NULL) === array('id' => T_VARIABLE, 'text' => '$renamed')
				&& ($tokens[$guard + 4]['text'] ?? '') === ')'
				&& ($tokens[$guard + 5]['text'] ?? '') === '{';
			if (!$bound) {
				return array('bound' => FALSE, 'directReturn' => FALSE);
			}

			return array(
				'bound' => TRUE,
				'directReturn' => self::hasDirectFalseReturn($tokens, $guard + 5)
			);
		}

		return array('bound' => FALSE, 'directReturn' => FALSE);
	}

	/**
	 * @param list<array{id: int|null, text: string}> $tokens
	 */
	private static function hasDirectFalseReturn(array $tokens, int $openingBrace): bool
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
			} elseif ($depth === 1
				&& $tokens[$i]['id'] === T_RETURN
				&& ($tokens[$i + 1] ?? NULL) === array('id' => T_STRING, 'text' => 'FALSE')
				&& ($tokens[$i + 2]['text'] ?? '') === ';') {
				return TRUE;
			}
		}

		return FALSE;
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
		$segmentStart = strrpos(substr(self::$body, 0, $tarPos), "\n");
		$segmentStart = $segmentStart === FALSE ? 0 : $segmentStart + 1;
		$segment = substr(self::$body, $segmentStart, $returnTrue + strlen('return TRUE;') - $segmentStart);

		$this->assertMatchesRegularExpression('/\$output,\s*\$retval\s*\)/', $segment,
			'gzip-geoip tar -xzf must capture $output, $retval -- a corrupt archive currently reports success unconditionally');
		$this->assertTrue(self::hasNonzeroRetvalGuard($segment),
			'gzip-geoip must check nonzero $retval before its return TRUE -- a nonzero exit must not report success');
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

		$this->assertTrue(self::hasNonzeroRetvalGuard($segment),
			'gzip-top1m must check nonzero $retval before its return TRUE -- a nonzero gunzip exit must not report success; '
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
		$this->assertTrue(self::hasNonzeroRetvalGuard($segSingleToReturn),
			'zip extras must check nonzero $retval before their shared return TRUE; segment: '
			. json_encode($segSingleToReturn));
	}

	// -----------------------------------------------------------------------
	// Row 7 -- uncompressed extras: @rename() result must be checked.
	// -----------------------------------------------------------------------

	public function testUncompressedExtrasChecksRenameResult(): void
	{
		$renameCall = strpos(self::$body, '@rename("{$file_download}", "{$head_download}")');
		$this->assertNotFalse($renameCall, 'vacuity: the uncompressed-extras rename site must exist');
		$renamePos = strrpos(substr(self::$body, 0, $renameCall), "\n");
		$renamePos = $renamePos === FALSE ? 0 : $renamePos + 1;

		$nextBranch = strpos(self::$body, "elseif (\$type == 'blacklist') {", $renamePos);
		$this->assertNotFalse($nextBranch, 'vacuity: the uncompressed-blacklist sibling branch must exist');
		$segment = substr(self::$body, $renamePos, $nextBranch - $renamePos);

		$analysis = self::analyzeRenameGuard($segment, '$head_download');
		$this->assertTrue($analysis['bound'],
			'uncompressed extras must check !$renamed before return TRUE; segment: ' . json_encode($segment));
		$this->assertTrue($analysis['directReturn'],
			'a failed rename() must have a return FALSE path; segment: ' . json_encode($segment));
	}

	// -----------------------------------------------------------------------
	// Row 8 -- generic uncompressed feeds: @rename() to .orig result must be
	// checked before the branch falls into the $retval == 0 success gate.
	// -----------------------------------------------------------------------

	public function testGenericUncompressedRenameResultChecked(): void
	{
		$commentPos = strpos(self::$body, "Rename file to 'orig' format");
		$this->assertNotFalse($commentPos, 'vacuity: the generic-uncompressed orig-rename comment must exist');

		$secondPos = strpos(self::$body, "Rename file to 'orig' format", $commentPos + 1);
		$this->assertFalse($secondPos, 'vacuity: "Rename file to \'orig\' format" must appear exactly once');

		$gatePos = strpos(self::$body, 'if ($retval == 0) {', $commentPos);
		$this->assertNotFalse($gatePos, 'vacuity: the $retval == 0 success gate must follow the generic-uncompressed branch');

		$segment = substr(self::$body, $commentPos, $gatePos - $commentPos);

		$analysis = self::analyzeRenameGuard($segment, '$orig_download');
		$this->assertTrue($analysis['bound'],
			'generic uncompressed feeds must check !$renamed before the $retval == 0 success gate; segment: '
			. json_encode($segment));
		$this->assertTrue($analysis['directReturn'],
			'a failed rename() must have a return FALSE path before the success gate; segment: ' . json_encode($segment));
	}
}
