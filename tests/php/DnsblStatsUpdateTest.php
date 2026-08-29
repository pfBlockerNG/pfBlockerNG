<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * DNSBL widget-stat update semantics after plaintext summary retirement.
 */
#[CoversFunction('dnsbl_stats_update')]
final class DnsblStatsUpdateTest extends TestCase
{
	private array $originalStats = [];
	private bool $hadStats = false;

	protected function setUp(): void
	{
		$this->hadStats = array_key_exists('dnsbl_info_stats', $GLOBALS['pfb'] ?? []);
		$this->originalStats = $GLOBALS['pfb']['dnsbl_info_stats'] ?? [];
		$GLOBALS['pfb']['dnsbl_info_stats'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadStats) {
			$GLOBALS['pfb']['dnsbl_info_stats'] = $this->originalStats;
		} else {
			unset($GLOBALS['pfb']['dnsbl_info_stats']);
		}
	}

	public function testUpdateExistingRowRefreshesTimestampAndEntriesButRetainsCounter(): void
	{
		$GLOBALS['pfb']['dnsbl_info_stats'] = [[
			'groupname' => 'DNSBL_Test',
			'timestamp' => '2024-01-01 00:00:00',
			'entries' => '2',
			'counter' => 17,
		]];

		dnsbl_stats_update('update', 'DNSBL_Test', 9);

		$row = $GLOBALS['pfb']['dnsbl_info_stats'][0];
		$this->assertSame('DNSBL_Test', $row['groupname']);
		$this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $row['timestamp']);
		$this->assertSame(9, $row['entries']);
		$this->assertSame(17, $row['counter']);
	}

	public function testUpdateMissingRowCreatesZeroCounter(): void
	{
		dnsbl_stats_update('update', 'DNSBL_New', 4);

		$this->assertCount(1, $GLOBALS['pfb']['dnsbl_info_stats']);
		$row = $GLOBALS['pfb']['dnsbl_info_stats'][0];
		$this->assertSame('DNSBL_New', $row['groupname']);
		$this->assertSame(4, $row['entries']);
		$this->assertSame(0, $row['counter']);
	}

	public function testDisabledExistingRowRemainsUntouched(): void
	{
		$existing = [
			'groupname' => 'DNSBL_Disabled',
			'timestamp' => '2024-01-01 00:00:00',
			'entries' => '6',
			'counter' => 3,
		];
		$GLOBALS['pfb']['dnsbl_info_stats'] = [$existing];

		dnsbl_stats_update('disabled', 'DNSBL_Disabled', '');

		$this->assertSame([$existing], $GLOBALS['pfb']['dnsbl_info_stats']);
	}

	public function testDisabledMissingRowCreatesDisabledZeroCounter(): void
	{
		dnsbl_stats_update('disabled', 'DNSBL_Disabled', '');

		$row = $GLOBALS['pfb']['dnsbl_info_stats'][0];
		$this->assertSame('DNSBL_Disabled', $row['groupname']);
		$this->assertSame('disabled', $row['entries']);
		$this->assertSame(0, $row['counter']);
		$this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $row['timestamp']);
	}
}
