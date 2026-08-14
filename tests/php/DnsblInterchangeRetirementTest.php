<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 -- pfb_py_data.txt/pfb_py_zone.txt writer retirement.
 *
 * R1: pfb_dnsbl_tld_stats_finalize() keeps its TLD-mode stats bookkeeping but never (re)writes
 * the interchange files -- classification now lives solely in the manifest
 * build (pfb_unbound_python_sources() / pfb_unbound.py). R2/R3: a stale
 * on-disk copy of the retired files, alone, no longer counts as "loaded feeds"
 * nor moves the reload fingerprint -- only a raw referenced by the published
 * manifest does, in EITHER TLD toggle state.
 */
#[CoversFunction('pfb_dnsbl_tld_stats_finalize')]
#[CoversFunction('pfb_dnsbl_has_loaded_feeds')]
#[CoversFunction('pfb_dnsbl_reload_fingerprint')]
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
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'sub.deep.example')
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

	// --- R2: issue #546 re-key -- retired interchange files alone are not "loaded" --

	public function testHasLoadedFeedsIgnoresStaleRetiredInterchangeFilesAlone(): void
	{
		$pfb = $this->makeLoadedFeedsPfb();
		file_put_contents($pfb['unbound_py_data'], "stale.example,1\n");
		file_put_contents($pfb['unbound_py_zone'], "stale-zone.example\n");

		$this->assertFalse(
			pfb_dnsbl_has_loaded_feeds($pfb),
			'stale retired interchange files alone no longer count as loaded feeds'
		);
	}

	/** Vacuity twin: the SAME stale files, plus a manifest-referenced raw -> TRUE. */
	public function testHasLoadedFeedsVacuityTwinRawFileStillCounts(): void
	{
		$pfb = $this->makeLoadedFeedsPfb();
		file_put_contents($pfb['unbound_py_data'], "stale.example,1\n");
		file_put_contents($pfb['unbound_py_zone'], "stale-zone.example\n");
		$this->publishRawFixture($pfb, "blocked.example\n");

		$this->assertTrue(
			pfb_dnsbl_has_loaded_feeds($pfb),
			'sanity: a manifest-referenced raw must still count as loaded (proves the FALSE assertion above can fail)'
		);
	}

	private function makeLoadedFeedsPfb(): array
	{
		return [
			'unbound_py_data'   => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone'   => "{$this->tmp}/pfb_py_zone.txt",
			'unbound_py_sources'=> "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_rawdir' => "{$this->tmp}/raw",
		];
	}

	// --- R3: fingerprint decoupling -- non-TLD mode also excludes retired files ---

	public function testReloadFingerprintDecoupledFromRetiredInterchangeFiles(): void
	{
		$pfb = $this->makeFingerprintPfb();
		$pfb['dnsbl_tld_wildcard'] = '';
		file_put_contents($pfb['unbound_py_data'], 'v1');

		$fp_before = pfb_dnsbl_reload_fingerprint($pfb);
		file_put_contents($pfb['unbound_py_data'], 'v2-mutated');
		$fp_after = pfb_dnsbl_reload_fingerprint($pfb);

		$this->assertSame(
			$fp_before,
			$fp_after,
			'a retired pfb_py_data.txt mutation must not move the reload fingerprint in non-TLD mode either'
		);
	}

	/** Vacuity twin: a manifest-referenced raw mutation between snapshots MUST move it. */
	public function testReloadFingerprintVacuityTwinRawMutationStillMovesIt(): void
	{
		$pfb = $this->makeFingerprintPfb();
		$pfb['dnsbl_tld_wildcard'] = '';
		$rawPath = $this->publishRawFixture($pfb, 'v1');

		$fp_before = pfb_dnsbl_reload_fingerprint($pfb);
		file_put_contents($rawPath, 'v2-mutated');
		$fp_after = pfb_dnsbl_reload_fingerprint($pfb);

		$this->assertNotSame(
			$fp_before,
			$fp_after,
			'sanity: a real rawdir *.raw mutation must still move the fingerprint (proves the SAME assertion above can fail)'
		);
	}

	private function makeFingerprintPfb(): array
	{
		return [
			'unbound_py_data'    => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmp}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmp}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_hsts'    => "{$this->tmp}/pfb_py_hsts.txt",
			'unbound_py_psl'     => "{$this->tmp}/dnsbl_psl",
			'unbound_py_rawdir'  => "{$this->tmp}/raw",
		];
	}

	private function publishRawFixture(array $pfb, string $contents): string
	{
		$rawPath = "{$pfb['unbound_py_rawdir']}/feed.raw";
		file_put_contents($rawPath, $contents);
		$manifest = [
			'version' => 1,
			'config' => [],
			'feeds' => [[
				'raw' => 'raw/feed.raw',
				'feed' => 'feed',
				'group' => 'test',
				'log_flag' => '1',
			]],
		];
		file_put_contents($pfb['unbound_py_sources'], json_encode($manifest));
		return $rawPath;
	}
}
