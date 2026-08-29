<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-60: DNSBL stats update and disabled rows carry year-bearing timestamps.
 */
#[CoversFunction('dnsbl_stats_update')]
#[CoversFunction('pfb_iso_timestamp')]
final class DnsblStatsUpdateTimestampFormatTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['pfb']['dnsbl_info_stats'] = [];
	}

	public function testUpdateModeStoresYearBearingIsoTimestamp(): void
	{
		dnsbl_stats_update('update', 'PFB_TS_FMT_TEST', 3);

		$this->assertNotEmpty($GLOBALS['pfb']['dnsbl_info_stats']);
		$stamp = $GLOBALS['pfb']['dnsbl_info_stats'][0]['timestamp'];
		$this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $stamp);
		$this->assertSame($stamp, pfb_iso_timestamp($stamp));
	}

	public function testDisabledModeStoresYearBearingIsoTimestamp(): void
	{
		dnsbl_stats_update('disabled', 'PFB_TS_FMT_TEST_DISABLED', '');

		$this->assertNotEmpty($GLOBALS['pfb']['dnsbl_info_stats']);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$GLOBALS['pfb']['dnsbl_info_stats'][0]['timestamp']
		);
	}

	public function testOldNoYearFormatLosesTheRealWriteYearOnReadback(): void
	{
		$oldStoredValue = date('M j H:i:s', mktime(23, 0, 0, 12, 31, 2024));
		$this->assertSame('Dec 31 23:00:00', $oldStoredValue);
		$this->assertStringNotContainsString('2024', pfb_iso_timestamp($oldStoredValue));
	}

	public function testNewYearBearingFormatPreservesTheRealWriteYearOnReadback(): void
	{
		$newStoredValue = date('Y-m-d H:i:s', mktime(23, 0, 0, 12, 31, 2024));
		$this->assertSame('2024-12-31 23:00:00', $newStoredValue);
		$this->assertSame($newStoredValue, pfb_iso_timestamp($newStoredValue));
	}
}
