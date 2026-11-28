<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 -- pfb_py_data.txt/pfb_py_zone.txt writer retirement.
 *
 * R1: pfb_dnsbl_tld_stats_finalize() keeps its TLD-mode stats bookkeeping but never (re)writes
 * the interchange files -- classification now lives solely in the manifest
 * build (pfb_unbound_python_sources() / pfb_unbound.py).
 */
#[CoversFunction('pfb_dnsbl_tld_stats_finalize')]
final class DnsblInterchangeRetirementTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/adr65_p6_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/raw", 0777, true);
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

	// --- R1: TLD-ON writer axis + bookkeeping retention -----------------------

	public function testTldModeNeverWritesInterchangeFilesButKeepsAliasAndStatBookkeeping(): void
	{
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'              => "{$this->tmp}/pfblockerng.log",
			'errlog'           => "{$this->tmp}/error.log",
			'dnsdir'           => "{$this->tmp}/dnsbl",
			'dnsbl_file'       => "{$this->tmp}/pfb_dnsbl",
			'unbound_py_data'  => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone'  => "{$this->tmp}/pfb_py_zone.txt",
			'domain_max_cnt'   => 1000000,
			'dnsbl_info'       => "{$this->tmp}/dnsbl_info.sqlite",
			'sqlite_timeout'   => 2000,
			'alias_dnsbl_all'  => [],
			'dnsbl_info_stats' => [],
			'domain_update'    => TRUE,
			'dnsblconfig'      => [
				'tld_wildcard_blacklist' => base64_encode('zip'),
				'tld_wildcard_exclusion' => '',
			],
		]);

		file_put_contents(
			"{$GLOBALS['pfb']['dnsbl_file']}.raw",
			'["d","sub.deep.example"]' . "\n"
		);

		pfb_dnsbl_tld_stats_finalize([]);

		// (i)-(ii): the interchange files themselves must never be (re)created.
		$this->assertFileDoesNotExist(
			$GLOBALS['pfb']['unbound_py_data'],
			'TLD stats finalization must never (re)write pfb_py_data.txt -- classification lives in the manifest build'
		);
		$this->assertFileDoesNotExist(
			$GLOBALS['pfb']['unbound_py_zone'],
			'TLD stats finalization must never (re)write pfb_py_zone.txt -- classification lives in the manifest build'
		);

		// (iii): the classification .raw staging intermediates must never exist either.
		$this->assertFileDoesNotExist(
			"{$GLOBALS['pfb']['unbound_py_data']}.raw",
			'the retired classification .raw intermediate must not be created'
		);
		$this->assertFileDoesNotExist(
			"{$GLOBALS['pfb']['unbound_py_zone']}.raw",
			'the retired classification .raw intermediate must not be created'
		);

		// (iv)-(v): the TLD-mode alias/stat bookkeeping must still run untouched.
		$tldStats = array_values(array_filter(
			$GLOBALS['pfb']['dnsbl_info_stats'],
			static fn(array $row): bool => ($row['groupname'] ?? '') === 'DNSBL_TLD'
		));
		$this->assertCount(1, $tldStats);
		$this->assertSame('1', (string) $tldStats[0]['entries']);
		$this->assertContains(
			'DNSBL_TLD',
			$GLOBALS['pfb']['alias_dnsbl_all'],
			'DNSBL_TLD must still be registered in the alias-all list'
		);
	}
}
