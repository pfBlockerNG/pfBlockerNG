<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1263: pfb_download()'s finalizer must call pfb_ensure_trailing_newline()
 * on the stored '.orig' -- AFTER the ADR-42 hash write (digest stays over the
 * untouched wire/raw body) and AFTER the UTF-16 transcode (operates on the
 * final bytes). pfb_download() drives real cURL + appliance exec before any
 * site under test runs, so this is a source-inspection pin (same technique as
 * DownloadExtractionExitCodeTest), not a behavioural exercise -- the actual
 * newline-append behaviour is proven directly in EnsureTrailingNewlineTest.
 */
final class DownloadTrailingNewlineWiringTest extends TestCase
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

	public function testEnsureTrailingNewlineIsCalledOnOrigDownload(): void
	{
		$this->assertStringContainsString('pfb_ensure_trailing_newline("{$orig_download}")', self::$body,
			'the finalizer must normalize the stored .orig -- else a feed served without a trailing newline stays welded downstream');
	}

	public function testEnsureTrailingNewlineRunsAfterTheHashWrite(): void
	{
		$hashPos = strpos(self::$body, 'pfb_hash_write("{$orig_download}"');
		$this->assertNotFalse($hashPos, 'vacuity: the ADR-42 hash-write site must exist');

		$normalizePos = strpos(self::$body, 'pfb_ensure_trailing_newline("{$orig_download}")');
		$this->assertNotFalse($normalizePos, 'vacuity: the trailing-newline call must exist');

		$this->assertGreaterThan($hashPos, $normalizePos,
			'appending a newline BEFORE the hash write would change the ADR-42 digest away from the raw wire body');
	}

	public function testEnsureTrailingNewlineRunsAfterTheUtf16Transcode(): void
	{
		$transcodePos = strpos(self::$body, 'pfb_utf16_transcode_file("{$orig_download}")');
		$this->assertNotFalse($transcodePos, 'vacuity: the UTF-16 transcode site must exist');

		$normalizePos = strpos(self::$body, 'pfb_ensure_trailing_newline("{$orig_download}")');
		$this->assertNotFalse($normalizePos, 'vacuity: the trailing-newline call must exist');

		$this->assertGreaterThan($transcodePos, $normalizePos,
			'normalizing before the transcode risks the rewrite silently dropping/duplicating the appended byte -- '
			. 'run last, on the final bytes');
	}
}
