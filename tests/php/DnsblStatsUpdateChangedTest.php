<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12: stats updates are inert with respect to the changed-group accumulator.
 * The feed loop records genuine changes before the TLD/non-TLD routing split.
 */
#[CoversFunction('dnsbl_stats_update')]
final class DnsblStatsUpdateChangedTest extends TestCase
{
	private array $originalPfb = [];
	private bool $hadPfb = false;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb']['changed_dnsbl_groups'] = [];
		$GLOBALS['pfb']['dnsbl_info_stats'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	public function testUpdateModeDoesNotRecordGroup(): void
	{
		$this->assertSame([], $GLOBALS['pfb']['changed_dnsbl_groups']);
		dnsbl_stats_update('update', 'DNSBL_ads', 7);
		$this->assertSame([], $GLOBALS['pfb']['changed_dnsbl_groups']);
	}

	public function testSpecialsUpdateCallsDoNotRecord(): void
	{
		$this->assertSame([], $GLOBALS['pfb']['changed_dnsbl_groups']);
		dnsbl_stats_update('update', 'DNSBL_IDN', 1);
		dnsbl_stats_update('update', 'DNSBL_TLD_Allow', 1);
		dnsbl_stats_update('update', 'DNSBL_Regex', 1);
		$this->assertSame([], $GLOBALS['pfb']['changed_dnsbl_groups']);
	}

	public function testDisabledModeRecordsNothing(): void
	{
		$this->assertSame([], $GLOBALS['pfb']['changed_dnsbl_groups']);
		dnsbl_stats_update('disabled', 'DNSBL_ads', '');
		$this->assertSame([], $GLOBALS['pfb']['changed_dnsbl_groups']);
	}

	public function testAccumulatorPreservedAcrossCalls(): void
	{
		$GLOBALS['pfb']['changed_dnsbl_groups'] = ['DNSBL_realfeed'];
		dnsbl_stats_update('update', 'DNSBL_Regex', 1);
		dnsbl_stats_update('disabled', 'DNSBL_other', '');
		$this->assertSame(['DNSBL_realfeed'], $GLOBALS['pfb']['changed_dnsbl_groups']);
	}
}
