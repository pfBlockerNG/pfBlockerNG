<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_unbound_python_sources() — ADR-06/07 shell->Python manifest writer. Builds
 * the per-feed manifest + per-feed IP-stripped raw files consumed by
 * pfb_unbound.py. This pins the parts the issue calls out: format/provenance
 * tagging, the chroot-relative (basename) raw path, and plain-vs-ABP raw
 * extraction. It runs against a temp $pfb sandbox (no live box).
 *
 * Also covers the #51 temporary-unlock plumbing: the full build clears
 * config.user_unlock (Force/Cron re-lock), and pfb_unbound_python_sources_unlock()
 * recomputes it in place from the live pfb_unlock store (pfb_dnsbl_unlock_lines()).
 */
#[CoversFunction('pfb_unbound_python_sources')]
#[CoversFunction('pfb_unbound_python_sources_unlock')]
#[CoversFunction('pfb_dnsbl_unlock_lines')]
final class UnboundPythonSourcesTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		// Snapshot the global so this class's heavy $pfb mutations (temp paths,
		// replaced dnsblconfig subtree) don't leak into later test classes.
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_sources_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/db", 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_alexa'        => 'off',
			'dnsbl_tld_data'     => "{$this->tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsblconfig'        => [
				'tldblacklist' => '',
				'tldexclusion' => '',
				'suppression'  => '',
			],
		]);

		// Plain feed: 6-col CSV, bare domain in column index 1.
		file_put_contents("{$this->tmp}/dnsbl/feed1.txt",
			"1,example.com,a,b,c,d\n" .
			"1,foo.com,a,b,c,d\n" .
			"1,,a,b,c,d\n");                 // empty col1 => skipped

		// ABP feed: raw ABP lines passed through verbatim.
		file_put_contents("{$this->tmp}/dnsbl/abpfeed.txt",
			"||ads.example^\n@@||good.example^\n");
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

	private function feeds(): array
	{
		return [
			['header' => 'feed1',   'group' => 'pfb_grp', 'log' => '1', 'format' => 'plain', 'provenance' => 'feed'],
			['header' => 'abpfeed', 'group' => 'pfb_abp', 'log' => '0', 'format' => 'abp',   'provenance' => 'user'],
			['header' => 'missing', 'group' => 'pfb_x',   'log' => '1'],   // no .txt => skipped
		];
	}

	public function testManifestStructureAndTagging(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());

		$this->assertSame(1, $m['version']);
		$this->assertCount(2, $m['feeds'], 'feed without a .txt must be skipped');

		$plain = $m['feeds'][0];
		$this->assertSame('feed1', $plain['feed']);
		$this->assertSame('pfb_grp', $plain['group']);
		$this->assertSame('plain', $plain['format_hint']);
		$this->assertSame('feed', $plain['provenance']);
		$this->assertSame('1', $plain['log_flag']);
		// chroot-relative: basename(rawdir)/<feed>.raw, never host-absolute.
		$this->assertSame('pfb_py_raw/feed1.raw', $plain['raw']);

		$abp = $m['feeds'][1];
		$this->assertSame('abp', $abp['format_hint']);
		$this->assertSame('user', $abp['provenance']);
		$this->assertSame('0', $abp['log_flag']);
		$this->assertSame('pfb_py_raw/abpfeed.raw', $abp['raw']);
	}

	public function testProvenanceDefaultsToFeedWhenUnset(): void
	{
		$m = pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => 'g', 'log' => '1', 'format' => 'plain'],
		]);
		$this->assertSame('feed', $m['feeds'][0]['provenance']);
	}

	public function testPlainRawIsBareDomainColumn(): void
	{
		pfb_unbound_python_sources($this->feeds());
		$raw = file_get_contents("{$this->tmp}/pfb_py_raw/feed1.raw");
		$this->assertSame("example.com\nfoo.com\n", $raw);
	}

	public function testAbpRawIsVerbatim(): void
	{
		pfb_unbound_python_sources($this->feeds());
		$raw = file_get_contents("{$this->tmp}/pfb_py_raw/abpfeed.raw");
		$this->assertSame("||ads.example^\n@@||good.example^\n", $raw);
	}

	public function testConfigBlockEmptyWhenUnconfigured(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());
		$this->assertSame([], $m['config']['tld_master']);
		$this->assertSame([], $m['config']['tld_blacklist']);
		$this->assertSame([], $m['config']['user_whitelist']);
		$this->assertSame([], $m['config']['user_unlock']);
		$this->assertFalse($m['config']['top1m_enabled']);
	}

	public function testManifestIsWrittenAsJson(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());
		$json = file_get_contents("{$this->tmp}/pfb_py_sources.json");
		$this->assertSame($m, json_decode($json, true));
	}

	// #51: a FULL build CLEARS the temporary unlock set even when the live store has
	// entries -- a Force/Cron deletes the store right after, so baking it in would let
	// unlocks survive the re-lock. The full build must emit user_unlock => [].
	public function testFullBuildClearsUserUnlockEvenWithStore(): void
	{
		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\nfoo.org,python\n");
		$m = pfb_unbound_python_sources($this->feeds());
		$this->assertSame([], $m['config']['user_unlock']);
	}

	// #51: pfb_dnsbl_unlock_lines() reads the pfb_unlock store and returns its domains.
	public function testDnsblUnlockLinesReadsStoreDomains(): void
	{
		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\nfoo.org,python\n");
		$this->assertSame(['evil.com', 'foo.org'], pfb_dnsbl_unlock_lines());
	}

	public function testDnsblUnlockLinesEmptyWhenStoreAbsent(): void
	{
		$this->assertSame([], pfb_dnsbl_unlock_lines());
	}

	// #51: the incremental path patches ONLY config.user_unlock from the live store,
	// leaving the rest of the manifest intact.
	public function testSourcesUnlockRecomputesFromStore(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());            // full build: user_unlock => []
		$this->assertSame([], $m['config']['user_unlock']);

		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\nfoo.org,python\n");
		$this->assertTrue(pfb_unbound_python_sources_unlock());

		$patched = json_decode(file_get_contents("{$this->tmp}/pfb_py_sources.json"), true);
		$this->assertSame(['evil.com', 'foo.org'], $patched['config']['user_unlock']);
		// The feeds and the rest of config are untouched by the in-place patch.
		$this->assertSame($m['feeds'], $patched['feeds']);
		$this->assertSame($m['config']['user_whitelist'], $patched['config']['user_whitelist']);
	}

	// Store deleted => manifest user_unlock cleared. This is BOTH the handler
	// 'lock'/'reunlock' that empties the store AND the Cron/Force re-lock step the fix
	// added at inc:3451 (pfb_update_unbound unlinks the store, then calls
	// pfb_unbound_python_sources_unlock so the reload re-reads a cleared whiteDB). With
	// the file gone pfb_dnsbl_unlock_lines() yields [] and the recompute empties the key.
	public function testSourcesUnlockEmptiesWhenStoreCleared(): void
	{
		pfb_unbound_python_sources($this->feeds());
		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\n");
		pfb_unbound_python_sources_unlock();

		unlink("{$this->tmp}/dnsbl_unlock");           // store emptied (lock / Cron / Force)
		$this->assertTrue(pfb_unbound_python_sources_unlock());
		$patched = json_decode(file_get_contents("{$this->tmp}/pfb_py_sources.json"), true);
		$this->assertSame([], $patched['config']['user_unlock']);
	}

	public function testSourcesUnlockReturnsFalseWithoutManifest(): void
	{
		// No full build ran -> no manifest to patch.
		$this->assertFileDoesNotExist("{$this->tmp}/pfb_py_sources.json");
		$this->assertFalse(pfb_unbound_python_sources_unlock());
	}
}
