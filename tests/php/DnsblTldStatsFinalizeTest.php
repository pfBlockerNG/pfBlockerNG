<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1283/#1349: TLD blacklist stats retain exact normalization and counts.
 */
#[CoversFunction('pfb_dnsbl_tld_stats_finalize')]
#[CoversFunction('dnsbl_stats_update')]
final class DnsblTldStatsFinalizeTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/dnsbl_tld_stats_' . uniqid('', true);
		$this->assertTrue(mkdir($this->tmp, 0700, true));
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		rmdir_recursive($this->tmp);
	}

	public function testMixedBlacklistCountsOnlyValidEntries(): void
	{
		$this->runFinalize(".zip.\r\n.\r\n..\r\n...\r\n\r\n");
		$this->assertTldCount(1);
	}

	public function testDotsOnlyEntriesCreateNoBookkeeping(): void
	{
		$this->runFinalize(".\r\n..\r\n...\r\n");
		$this->assertNoTldBookkeeping();
	}

	public function testWhitespaceHeaderAndBlankRemainIgnored(): void
	{
		$this->runFinalize("   \r\n# header\r\n\r\n");
		$this->assertNoTldBookkeeping();
	}

	public function testZeroRowCountsAsEntry(): void
	{
		// issue #1707: "0" is a valid row -- the old !empty() guard silently dropped it
		$this->runFinalize("0\r\n");
		$this->assertTldCount(1);
	}

	public function testLeadingDotsAndPlainValidTldsRemainRawDistinctBeforeTrim(): void
	{
		$this->runFinalize(".zip.\r\nzip\r\n");
		$this->assertTldCount(2);
	}

	public function testPunycodeAndRawIdnPreserveDecoderBehavior(): void
	{
		$this->runFinalize("xn--p1ai\r\nрф\r\n");
		$this->assertTldCount(1);
	}

	public function testEmptyConfiguredValueCreatesNoBookkeeping(): void
	{
		$this->runFinalize('');
		$this->assertNoTldBookkeeping();
	}

	public function testOrdinaryDeferredGroupUsesProvidedCountAndRetainsCounter(): void
	{
		$this->configure('', true, [
			'groupname' => 'DNSBL_Group',
			'timestamp' => '2024-01-01 00:00:00',
			'entries' => '2',
			'counter' => 11,
		]);

		pfb_dnsbl_tld_stats_finalize(['DNSBL_Group' => 8]);

		$row = $this->statsRow('DNSBL_Group');
		$this->assertNotNull($row);
		$this->assertSame('8', (string) $row['entries']);
		$this->assertSame(11, $row['counter']);
	}

	public function testDomainUpdateFalseLeavesRowsUntouched(): void
	{
		$existing = [
			'groupname' => 'DNSBL_Group',
			'timestamp' => '2024-01-01 00:00:00',
			'entries' => '2',
			'counter' => 11,
		];
		$this->configure('zip', false, $existing);

		pfb_dnsbl_tld_stats_finalize(['DNSBL_Group' => 8]);

		$this->assertSame([$existing], $GLOBALS['pfb']['dnsbl_info_stats']);
		$this->assertNotContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_info']);
	}

	public function testFinalizerPersistsActiveRowAndDeletesStaleNumericRow(): void
	{
		$active = [
			'groupname' => 'DNSBL_Group',
			'timestamp' => '2024-01-01 00:00:00',
			'entries' => '2',
			'counter' => 11,
		];
		$stale = [
			'groupname' => 'DNSBL_Stale',
			'timestamp' => '2024-01-01 00:00:00',
			'entries' => '3',
			'counter' => 4,
		];
		$this->configure('', true, $active);
		$GLOBALS['pfb']['dnsbl_info_stats'][] = $stale;

		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertTrue($db->exec(
			'CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries TEXT, counter INTEGER)'
		));
		$this->assertTrue($db->exec(
			"INSERT INTO dnsbl VALUES ('DNSBL_Group', '2024-01-01 00:00:00', '2', 11)," .
			" ('DNSBL_Stale', '2024-01-01 00:00:00', '3', 4)"
		));
		$db->close();

		pfb_dnsbl_tld_stats_finalize(['DNSBL_Group' => 8]);

		$activeAfter = $this->statsRow('DNSBL_Group');
		$this->assertNotNull($activeAfter);
		$this->assertNotSame($active['timestamp'], $activeAfter['timestamp']);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
			$activeAfter['timestamp']
		);
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$persisted = $db->querySingle(
			"SELECT timestamp, entries, counter FROM dnsbl WHERE groupname = 'DNSBL_Group'",
			true
		);
		$staleCount = $db->querySingle("SELECT COUNT(*) FROM dnsbl WHERE groupname = 'DNSBL_Stale'");
		$db->close();
		$this->assertSame($activeAfter['timestamp'], $persisted['timestamp']);
		$this->assertSame('8', $persisted['entries']);
		$this->assertSame(11, $persisted['counter']);
		$this->assertSame(0, $staleCount);
	}

	private function runFinalize(string $blacklist): void
	{
		$this->configure($blacklist);
		pfb_dnsbl_tld_stats_finalize([]);
	}

	private function configure(string $blacklist, bool $domainUpdate = true, ?array $existing = null): void
	{
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log' => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'dnsbl_info' => "{$this->tmp}/dnsbl_info.sqlite",
			'sqlite_timeout' => 2000,
			'alias_dnsbl_all' => $existing === null ? [] : [$existing['groupname']],
			'dnsbl_info_stats' => $existing === null ? [] : [$existing],
			'domain_update' => $domainUpdate,
			'dnsblconfig' => ['tld_wildcard_blacklist' => base64_encode($blacklist)],
		]);
	}

	private function assertTldCount(int $expected): void
	{
		$row = $this->statsRow('DNSBL_TLD');
		$this->assertNotNull($row, 'DNSBL_TLD stats row must be registered');
		$this->assertSame((string) $expected, (string) $row['entries']);
		$this->assertContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
	}

	private function assertNoTldBookkeeping(): void
	{
		$this->assertNull($this->statsRow('DNSBL_TLD'));
		$this->assertNotContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
	}

	private function statsRow(string $group): ?array
	{
		foreach ($GLOBALS['pfb']['dnsbl_info_stats'] as $row) {
			if (($row['groupname'] ?? '') === $group) {
				return $row;
			}
		}
		return null;
	}
}
