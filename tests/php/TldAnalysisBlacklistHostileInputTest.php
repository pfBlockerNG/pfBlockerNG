<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 -- tld_analysis()'s retained TLD-blacklist counting, hostile
 * textarea rows. This logic (pfbng_text_area_decode() + the unconditional
 * per-entry $tld_cnt++) is carried over VERBATIM from before the phase --
 * behaviour-preserving, so this pins the pre-existing widget-count contract
 * rather than proving a new change.
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

	/**
	 * Given: a textarea with a leading/trailing-dot entry ('.zip.'), an
	 * all-dots entry ('...'), and a blank line (dropped by the decoder before
	 * it ever reaches the counting loop)
	 * When: tld_analysis() runs
	 * Then: the widget count is exactly 2 (the blank line never counts; the
	 * two non-empty hostile entries do, unconditionally, exactly as today)
	 */
	public function testHostileTextareaEntriesCountedExactlyAsToday(): void
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
				'tldblacklist' => base64_encode(".zip.\r\n...\r\n"),
				'tldexclusion' => '',
			],
		]);

		// Old code's early gate requires the .raw to exist; new code's gate is
		// $pfb['domain_update'] instead -- an empty .raw satisfies BOTH, so this
		// stays a genuine preservation-oracle across the change.
		file_put_contents("{$GLOBALS['pfb']['dnsbl_file']}.raw", '');

		tld_analysis();

		$this->assertSame(
			2,
			$GLOBALS['pfb']['tld_update']['DNSBL_TLD']['count'] ?? null,
			'the blank line must be dropped by the decoder; the two hostile-but-non-empty entries must both count'
		);
	}
}
