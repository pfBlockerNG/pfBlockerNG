<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_loaded_input_paths() and pfb_unbound_py_manifest_raw_paths() — the
 * Python-loaded DNSBL input set. The PHP fingerprint helpers that gated the reload
 * on it (pfb_dnsbl_loaded_fingerprint(), pfb_dnsbl_reload_fingerprint()) left with
 * the PHP Update pass in the Go cutover (#3977), with their tests.
 */
#[CoversFunction('pfb_dnsbl_loaded_input_paths')]
#[CoversFunction('pfb_unbound_py_manifest_raw_paths')]
final class DnsblLoadedFingerprintTest extends TestCase
{
	private string $tmpDir;

	protected function setUp(): void
	{
		$this->tmpDir = sys_get_temp_dir() . '/pfb_fp_test_' . getmypid() . '_' . mt_rand();
		mkdir($this->tmpDir, 0700, TRUE);
		mkdir("{$this->tmpDir}/raw", 0700, TRUE);
	}

	protected function tearDown(): void
	{
		// Recursive clean of tmpDir.
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmpDir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($files as $f) {
			$f->isDir() ? rmdir((string) $f) : unlink((string) $f);
		}
		rmdir($this->tmpDir);
	}

	// -----------------------------------------------------------------------
	// pfb_dnsbl_loaded_input_paths
	// -----------------------------------------------------------------------

	/**
	 * Scenario: returns the three flat inputs (incl. the PSL authority) plus sorted
	 * manifest-authoritative raw files -- NOT orphan raw files or the retired
	 * unbound_py_data/unbound_py_zone (ADR-65).
	 *
	 * Given:  a $pfb array with two referenced raw files and one orphan raw file
	 * When:   pfb_dnsbl_loaded_input_paths() is called
	 * Then:   result contains wh/sources/tld plus both referenced paths, in
	 *         sorted order, and excludes the orphan and retired data/zone paths
	 */
	public function testReturnsFlatInputsPlusSortedRaws(): void
	{
		$rawDir = "{$this->tmpDir}/raw";
		file_put_contents("{$rawDir}/zz_feed.raw", 'z');
		file_put_contents("{$rawDir}/aa_feed.raw", 'a');
		file_put_contents("{$rawDir}/orphan.raw", 'orphan');
		file_put_contents("{$this->tmpDir}/pfb_py_sources.json", json_encode([
			'version' => 1,
			'feeds' => [
				['raw' => 'raw/zz_feed.raw'],
				['raw' => 'raw/aa_feed.raw'],
			],
		]));

		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_psl'     => "{$this->tmpDir}/dnsbl_psl",
			'unbound_py_rawdir'  => $rawDir,
			// Keys that must NOT appear in the result:
			'unbound_py_hsts'        => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_count'       => "{$this->tmpDir}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmpDir}/pfb_py_regex_count",
			'unbound_py_ss'          => "{$this->tmpDir}/pfb_py_ss.txt",
		];

		$result = pfb_dnsbl_loaded_input_paths($pfb);

		// The three flat inputs must be present (incl. the PSL authority).
		// ADR-65: unbound_py_data/unbound_py_zone are retired writer targets --
		// they must NOT appear (a stray on-disk copy must never gate the reload).
		$this->assertNotContains($pfb['unbound_py_data'], $result, 'retired unbound_py_data must NOT be in the path list (ADR-65)');
		$this->assertNotContains($pfb['unbound_py_zone'], $result, 'retired unbound_py_zone must NOT be in the path list (ADR-65)');
		$this->assertContains($pfb['unbound_py_wh'],      $result, 'unbound_py_wh must be in the path list');
		$this->assertContains($pfb['unbound_py_sources'], $result, 'unbound_py_sources must be in the path list');
		$this->assertContains($pfb['unbound_py_psl'],     $result, 'unbound_py_psl must be in the path list (shipped PSL authority)');

		// Both .raw files must be present.
		$this->assertContains("{$rawDir}/aa_feed.raw", $result, 'aa_feed.raw must be in the path list');
		$this->assertContains("{$rawDir}/zz_feed.raw", $result, 'zz_feed.raw must be in the path list');
		$this->assertNotContains("{$rawDir}/orphan.raw", $result, 'unreferenced raw files must be excluded');

		// Excluded output keys must NOT appear.
		$this->assertNotContains($pfb['unbound_py_count'],       $result, 'unbound_py_count must be excluded (Python-emitted output)');
		$this->assertNotContains($pfb['unbound_py_regex_count'], $result, 'unbound_py_regex_count must be excluded (Python-emitted output)');
		$this->assertNotContains($pfb['unbound_py_ss'],          $result, 'unbound_py_ss must be excluded (has its own SafeSearch gate)');
		$this->assertNotContains($pfb['unbound_py_hsts'],        $result, 'the retired HSTS list must be excluded (#4053)');

		// The .raw files must be sorted (aa before zz).
		$raw_in_result = array_filter($result, static fn(string $p) => str_ends_with($p, '.raw'));
		$raw_in_result = array_values($raw_in_result);
		$this->assertSame("{$rawDir}/aa_feed.raw", $raw_in_result[0], 'aa_feed.raw must sort before zz_feed.raw');
		$this->assertSame("{$rawDir}/zz_feed.raw", $raw_in_result[1], 'zz_feed.raw must be second');
	}

	/**
	 * Scenario: empty rawdir — no .raw files, just the three flat inputs (incl. the PSL).
	 *
	 * Given:  a rawdir that is empty (no .raw files)
	 * When:   pfb_dnsbl_loaded_input_paths() is called
	 * Then:   result has exactly 3 entries (wh/sources/tld only -- ADR-65
	 *         retired unbound_py_data/unbound_py_zone are never in the returned list)
	 */
	public function testEmptyRawdirReturnsOnlyFlatInputs(): void
	{
		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_psl'     => "{$this->tmpDir}/dnsbl_psl",
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
			'unbound_py_count'       => "{$this->tmpDir}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmpDir}/pfb_py_regex_count",
			'unbound_py_ss'          => "{$this->tmpDir}/pfb_py_ss.txt",
		];

		$result = pfb_dnsbl_loaded_input_paths($pfb);

		$this->assertCount(3, $result, 'With no .raw files, exactly the three flat inputs are returned (wh/sources/tld)');
	}

	public function testManifestPathsIncludeMissingConfinedRefButRejectEscapesAndSymlinks(): void
	{
		$outside = dirname($this->tmpDir) . '/pfb_outside_' . uniqid() . '.raw';
		try {
			file_put_contents($outside, 'outside');
			symlink($outside, "{$this->tmpDir}/raw/link.raw");
			$manifest = "{$this->tmpDir}/pfb_py_sources.json";
			file_put_contents($manifest, json_encode([
				'version' => 1,
				'feeds' => [
					['raw' => 'raw/missing.raw'],
					['raw' => '../' . basename($outside)],
					['raw' => 'raw/link.raw'],
					['raw' => "raw/\0hostile.raw"],
					['raw' => ['/wrong/type']],
					['feed' => 'missing-key'],
				],
			]));

			$paths = pfb_unbound_py_manifest_raw_paths($manifest);
			$this->assertSame(["{$this->tmpDir}/raw/missing.raw"], $paths);
		} finally {
			@unlink($outside);
		}
	}
}
