<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_loaded_fingerprint() and pfb_dnsbl_loaded_input_paths() —
 * pure helpers that gate the DNSBL reload on a real input-file change.
 *
 * Design intent: fingerprint the Python-loaded files BEFORE and AFTER a pass.
 * Equal fingerprints => the rebuild would be byte-identical => skip the Unbound
 * reload. The all-missing stable sentinel means empty→empty equals (no reload on
 * a steady-state no-feeds pass), while any file appearing or changing produces
 * a difference (reload fires exactly once).
 */
#[CoversFunction('pfb_dnsbl_loaded_fingerprint')]
#[CoversFunction('pfb_dnsbl_loaded_input_paths')]
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
	// pfb_dnsbl_loaded_fingerprint
	// -----------------------------------------------------------------------

	/**
	 * Scenario: all-missing paths — stable sentinel enables empty→empty equality.
	 *
	 * Given:  paths that do not exist on disk
	 * When:   fingerprint is computed twice with the same path list
	 * Then:   both calls return the same string (pinning the stable-sentinel guarantee)
	 *
	 * Proves: an unchanged no-feeds steady state (all files absent before AND after)
	 * yields equal fingerprints, suppressing the Unbound reload.
	 */
	public function testAllMissingPathsAreStable(): void
	{
		$paths = [
			"{$this->tmpDir}/nonexistent_data.txt",
			"{$this->tmpDir}/nonexistent_zone.txt",
		];

		$fp1 = pfb_dnsbl_loaded_fingerprint($paths);
		$fp2 = pfb_dnsbl_loaded_fingerprint($paths);

		$this->assertSame($fp1, $fp2, 'Two calls with all-missing paths must return the same fingerprint (empty==empty)');
	}

	/**
	 * Scenario: same path, unchanged content — no reload on a no-op pass.
	 *
	 * Given:  a file whose content does not change between two calls
	 * When:   fingerprint is computed twice for the same path list
	 * Then:   fingerprints are equal (idempotent on unmodified files)
	 */
	public function testUnchangedFileProducesEqualFingerprints(): void
	{
		$file = "{$this->tmpDir}/feed.txt";
		file_put_contents($file, "example.com\n");

		$fp1 = pfb_dnsbl_loaded_fingerprint([$file]);
		$fp2 = pfb_dnsbl_loaded_fingerprint([$file]);

		$this->assertSame($fp1, $fp2, 'Unchanged file must yield the same fingerprint on repeated calls');
	}

	/**
	 * Scenario: one byte changed — reload fires when feed changes.
	 *
	 * Given:  a file with content "example.com\n"
	 * When:   one byte is mutated and the fingerprint is recomputed
	 * Then:   fingerprints differ
	 *
	 * Before-state assertion is mandatory so a buggy always-equal or always-differ
	 * implementation cannot silently pass.
	 */
	public function testOneByteMutationProducesDifferentFingerprint(): void
	{
		$file = "{$this->tmpDir}/feed.txt";
		file_put_contents($file, "example.com\n");

		// Before: record fingerprint of the original content.
		$fp_before = pfb_dnsbl_loaded_fingerprint([$file]);

		// Mutate one byte.
		file_put_contents($file, "Example.com\n");

		// After: fingerprint must differ.
		$fp_after = pfb_dnsbl_loaded_fingerprint([$file]);

		$this->assertNotSame(
			$fp_before,
			$fp_after,
			'A one-byte change must produce a different fingerprint (change branch proven red→green)'
		);
	}

	/**
	 * Scenario: permuted path order — order-stability prevents false positives.
	 *
	 * Given:  two files and two path lists in opposite order
	 * When:   fingerprint is computed for each list
	 * Then:   fingerprints are equal (internal sort neutralises order)
	 */
	public function testPermutedPathOrderProducesEqualFingerprint(): void
	{
		$f1 = "{$this->tmpDir}/f1.txt";
		$f2 = "{$this->tmpDir}/f2.txt";
		file_put_contents($f1, "alpha\n");
		file_put_contents($f2, "beta\n");

		$fp_ab = pfb_dnsbl_loaded_fingerprint([$f1, $f2]);
		$fp_ba = pfb_dnsbl_loaded_fingerprint([$f2, $f1]);

		$this->assertSame($fp_ab, $fp_ba, 'Path order must not affect the fingerprint');
	}

	/**
	 * Scenario: subset present vs full set present — file appearance is detected.
	 *
	 * Given:  a base fingerprint with only file A
	 * When:   file B is added to the path list
	 * Then:   fingerprint differs (new file detected as a change)
	 *
	 * Before-state assertion proves the flip is caused by adding B.
	 */
	public function testSubsetVsFullSetProducesDifferentFingerprint(): void
	{
		$fileA = "{$this->tmpDir}/a.txt";
		$fileB = "{$this->tmpDir}/b.txt";
		file_put_contents($fileA, "alpha\n");
		file_put_contents($fileB, "beta\n");

		// Before: only A.
		$fp_subset = pfb_dnsbl_loaded_fingerprint([$fileA]);

		// After: A + B.
		$fp_full   = pfb_dnsbl_loaded_fingerprint([$fileA, $fileB]);

		$this->assertNotSame(
			$fp_subset,
			$fp_full,
			'Adding a present file to the path set must change the fingerprint'
		);
	}

	/**
	 * Scenario: empty-string paths are skipped.
	 *
	 * Given:  a path list containing only empty strings
	 * When:   fingerprint is computed
	 * Then:   it equals a call with an empty array (both all-missing, same stable sentinel)
	 */
	public function testEmptyStringPathsAreIgnored(): void
	{
		$fp_blanks = pfb_dnsbl_loaded_fingerprint(['', '', '']);
		$fp_empty  = pfb_dnsbl_loaded_fingerprint([]);

		$this->assertSame($fp_blanks, $fp_empty, 'Empty-string paths must be skipped, same result as empty array');
	}

	// -----------------------------------------------------------------------
	// pfb_dnsbl_loaded_input_paths
	// -----------------------------------------------------------------------

	/**
	 * Scenario: returns the four flat inputs plus sorted *.raw from rawdir.
	 *
	 * Given:  a $pfb array with the standard keys and two .raw files in rawdir
	 * When:   pfb_dnsbl_loaded_input_paths() is called
	 * Then:   result contains data/zone/wh/sources plus both .raw paths, in sorted order
	 */
	public function testReturnsFlatInputsPlusSortedRaws(): void
	{
		$rawDir = "{$this->tmpDir}/raw";
		file_put_contents("{$rawDir}/zz_feed.raw", 'z');
		file_put_contents("{$rawDir}/aa_feed.raw", 'a');

		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_rawdir'  => $rawDir,
			// Keys that must NOT appear in the result:
			'unbound_py_count'       => "{$this->tmpDir}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmpDir}/pfb_py_regex_count",
			'unbound_py_ss'          => "{$this->tmpDir}/pfb_py_ss.txt",
		];

		$result = pfb_dnsbl_loaded_input_paths($pfb);

		// The four flat inputs must be present.
		$this->assertContains($pfb['unbound_py_data'],    $result, 'unbound_py_data must be in the path list');
		$this->assertContains($pfb['unbound_py_zone'],    $result, 'unbound_py_zone must be in the path list');
		$this->assertContains($pfb['unbound_py_wh'],      $result, 'unbound_py_wh must be in the path list');
		$this->assertContains($pfb['unbound_py_sources'], $result, 'unbound_py_sources must be in the path list');

		// Both .raw files must be present.
		$this->assertContains("{$rawDir}/aa_feed.raw", $result, 'aa_feed.raw must be in the path list');
		$this->assertContains("{$rawDir}/zz_feed.raw", $result, 'zz_feed.raw must be in the path list');

		// Excluded output keys must NOT appear.
		$this->assertNotContains($pfb['unbound_py_count'],       $result, 'unbound_py_count must be excluded (Python-emitted output)');
		$this->assertNotContains($pfb['unbound_py_regex_count'], $result, 'unbound_py_regex_count must be excluded (Python-emitted output)');
		$this->assertNotContains($pfb['unbound_py_ss'],          $result, 'unbound_py_ss must be excluded (has its own SafeSearch gate)');

		// The .raw files must be sorted (aa before zz).
		$raw_in_result = array_filter($result, static fn(string $p) => str_ends_with($p, '.raw'));
		$raw_in_result = array_values($raw_in_result);
		$this->assertSame("{$rawDir}/aa_feed.raw", $raw_in_result[0], 'aa_feed.raw must sort before zz_feed.raw');
		$this->assertSame("{$rawDir}/zz_feed.raw", $raw_in_result[1], 'zz_feed.raw must be second');
	}

	/**
	 * Scenario: empty rawdir — no .raw files, just the four flat inputs.
	 *
	 * Given:  a rawdir that is empty (no .raw files)
	 * When:   pfb_dnsbl_loaded_input_paths() is called
	 * Then:   result has exactly 4 entries (the flat inputs only)
	 */
	public function testEmptyRawdirReturnsOnlyFlatInputs(): void
	{
		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
			'unbound_py_count'       => "{$this->tmpDir}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmpDir}/pfb_py_regex_count",
			'unbound_py_ss'          => "{$this->tmpDir}/pfb_py_ss.txt",
		];

		$result = pfb_dnsbl_loaded_input_paths($pfb);

		$this->assertCount(4, $result, 'With no .raw files, exactly the four flat inputs are returned');
	}
}
