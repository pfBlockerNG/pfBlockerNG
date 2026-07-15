<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1283 -- empty-after-dot-trim TLD blacklist rows must not create
 * alias or statistics bookkeeping, while valid rows remain counted.
 */
#[CoversFunction('tld_analysis')]
final class TldAnalysisBlacklistHostileInputTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];
	private bool $hadTlds = false;
	private mixed $originalTlds = null;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->hadTlds = array_key_exists('tlds', $GLOBALS);
		$this->originalTlds = $GLOBALS['tlds'] ?? null;
		$GLOBALS['tlds'] = array();

		$this->tmp = sys_get_temp_dir() . '/adr65_p6_blacklist_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/dnsalias", 0777, true);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadTlds) {
			$GLOBALS['tlds'] = $this->originalTlds;
		} else {
			unset($GLOBALS['tlds']);
		}
		rmdir_recursive($this->tmp);
	}

	public function testMixedBlacklistCountsOnlyValidEntries(): void
	{
		$this->runAnalysis(".zip.\r\n.\r\n..\r\n...\r\n\r\n");
		$this->assertSame(
			['feeds' => ['DNSBL_TLD'], 'count' => 1],
			$GLOBALS['pfb']['tld_update']['DNSBL_TLD'] ?? null,
			'dots-only and blank rows must not inflate valid TLD bookkeeping'
		);
		$this->assertContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
		$this->assertFileExists("{$GLOBALS['pfb']['dnsalias']}/DNSBL_TLD");
	}

	public function testDotsOnlyEntriesCreateNoBookkeeping(): void
	{
		$this->runAnalysis(".\r\n..\r\n...\r\n");
		$this->assertNoTldBookkeeping();
	}

	public function testWhitespaceHeaderBlankAndZeroRemainIgnored(): void
	{
		$this->runAnalysis("   \r\n# header\r\n\r\n0\r\n");
		$this->assertNoTldBookkeeping();
	}

	public function testLeadingDotsAndPlainValidTldsRemainCounted(): void
	{
		$this->runAnalysis(".zip.\r\nzip\r\n");
		$this->assertSame(
			['feeds' => ['DNSBL_TLD'], 'count' => 2],
			$GLOBALS['pfb']['tld_update']['DNSBL_TLD'] ?? null
		);
		$this->assertContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
		$this->assertFileExists("{$GLOBALS['pfb']['dnsalias']}/DNSBL_TLD");
	}

	public function testPunycodeAndRawIdnRemainCounted(): void
	{
		$this->runAnalysis("xn--p1ai\r\nрф\r\n");
		$this->assertSame(
			['feeds' => ['DNSBL_TLD'], 'count' => 1],
			$GLOBALS['pfb']['tld_update']['DNSBL_TLD'] ?? null
		);
		$this->assertContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
		$this->assertFileExists("{$GLOBALS['pfb']['dnsalias']}/DNSBL_TLD");
	}

	private function runAnalysis(string $blacklist): void
	{
		$tldMaster = "{$this->tmp}/tld_master.txt";
		file_put_contents($tldMaster, "com\n");

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'              => "{$this->tmp}/pfblockerng.log",
			'errlog'           => "{$this->tmp}/error.log",
			'dnsdir'           => "{$this->tmp}/dnsbl",
			'dnsbl_file'       => "{$this->tmp}/pfb_dnsbl",
			'dnsbl_tld_data'   => $tldMaster,
			'unbound_py_data'  => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone'  => "{$this->tmp}/pfb_py_zone.txt",
			'domain_max_cnt'   => 1000000,
			'dnsbl_info'       => "{$this->tmp}/dnsbl_info.sqlite",
			'sqlite_timeout'   => 2000,
			'alias_dnsbl_all'  => [],
			'dnsbl_info_stats' => [],
			'tld_update'       => [],
			'dnsalias'         => "{$this->tmp}/dnsalias",
			'domain_update'    => TRUE,
			'dnsblconfig'      => [
				'tldblacklist' => base64_encode($blacklist),
				'tldexclusion' => '',
			],
		]);

		file_put_contents("{$GLOBALS['pfb']['dnsbl_file']}.raw", '');
		tld_analysis();
	}

	private function assertNoTldBookkeeping(): void
	{
		$this->assertArrayNotHasKey('DNSBL_TLD', $GLOBALS['pfb']['tld_update']);
		$this->assertNotContains('DNSBL_TLD', $GLOBALS['pfb']['alias_dnsbl_all']);
		$this->assertFileDoesNotExist("{$GLOBALS['pfb']['dnsalias']}/DNSBL_TLD");
	}
}
