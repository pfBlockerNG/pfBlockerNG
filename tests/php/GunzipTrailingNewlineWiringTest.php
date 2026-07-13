<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1263: the ET-IQRisk reuse path rebuilds '.orig' via a raw gunzip exec()
 * OUTSIDE pfb_download() -- pfb_download()'s own newline-termination guarantee
 * (DownloadTrailingNewlineWiringTest) never runs on this path. Source-inspection
 * pin (same technique as DownloadTrailingNewlineWiringTest): the surrounding
 * sync_package_pfblockerng() is thousands of lines and drives real cURL/appliance
 * exec, so this is not behaviourally exercised here -- the append behaviour itself
 * is proven in EnsureTrailingNewlineTest.
 */
final class GunzipTrailingNewlineWiringTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if ($source === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}
		self::$source = $source;
	}

	public function testEnsureTrailingNewlineRunsAfterTheGunzipExec(): void
	{
		$gunzipPos = strpos(self::$source, 'exec("/usr/bin/gunzip -c {$file_dwn_esc} > {$file_org_esc}");');
		$this->assertNotFalse($gunzipPos, 'vacuity: the ET-IQRisk gunzip exec site must exist');

		$nextExecPos = strpos(self::$source, "exec(\"{\$pfb['script']} et {\$header_esc}", $gunzipPos);
		$this->assertNotFalse($nextExecPos, 'vacuity: the following ET-processing exec must exist');

		$between = substr(self::$source, $gunzipPos, $nextExecPos - $gunzipPos);
		$this->assertStringContainsString('pfb_ensure_trailing_newline("{$file_dwn}.orig")', $between,
			'the reuse path must normalize the rebuilt .orig -- else a gzip payload without a trailing '
			. 'newline stays welded downstream, exactly like the pfb_download() path this bypasses');
	}
}
