<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1263: the GeoIP continent builder rewrites a stored '.orig' via
 * @rename() OUTSIDE pfb_download() -- its newline-termination guarantee never
 * runs on this path either. Source-inspection pin, same rationale as
 * GunzipTrailingNewlineWiringTest.
 */
final class GeoipOrigTrailingNewlineWiringTest extends TestCase
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

	public function testEnsureTrailingNewlineRunsAfterTheGeoipRename(): void
	{
		$renamePos = strpos(self::$source, '@rename("{$pfb[\'geoip_tmp\']}", "{$pfborig}/{$cc_alias}.orig");');
		$this->assertNotFalse($renamePos, 'vacuity: the GeoIP continent .orig rename site must exist');

		$copyPos = strpos(
			self::$source,
			'@copy("{$pfborig}/{$cc_alias}.orig", "{$pfbfolder}/{$cc_alias}.txt");',
			$renamePos
		);
		$this->assertNotFalse($copyPos, 'vacuity: the following .txt mirror copy must exist');

		$between = substr(self::$source, $renamePos, $copyPos - $renamePos);
		$this->assertStringContainsString('pfb_ensure_trailing_newline("{$pfborig}/{$cc_alias}.orig")', $between,
			'the rebuilt .orig must be normalized before the .txt mirror copy propagates its raw bytes');
	}
}
