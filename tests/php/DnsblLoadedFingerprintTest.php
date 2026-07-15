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
#[CoversFunction('pfb_dnsbl_reload_fingerprint')]
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
	 * Scenario: returns the four flat inputs (incl. HSTS + TLD oracle) plus sorted
	 * *.raw from rawdir -- NOT the retired unbound_py_data/unbound_py_zone (ADR-65).
	 *
	 * Given:  a $pfb array with the standard keys and two .raw files in rawdir
	 * When:   pfb_dnsbl_loaded_input_paths() is called
	 * Then:   result contains wh/sources/hsts/tld plus both .raw paths, in sorted
	 *         order, and excludes the retired data/zone paths
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
			'unbound_py_hsts'    => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_tld'     => "{$this->tmpDir}/pfb_py_tld.txt",
			'unbound_py_rawdir'  => $rawDir,
			// Keys that must NOT appear in the result:
			'unbound_py_count'       => "{$this->tmpDir}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmpDir}/pfb_py_regex_count",
			'unbound_py_ss'          => "{$this->tmpDir}/pfb_py_ss.txt",
		];

		$result = pfb_dnsbl_loaded_input_paths($pfb);

		// The four flat inputs must be present (incl. HSTS + TLD-Wildcard oracle).
		// ADR-65: unbound_py_data/unbound_py_zone are retired writer targets --
		// they must NOT appear (a stray on-disk copy must never gate the reload).
		$this->assertNotContains($pfb['unbound_py_data'], $result, 'retired unbound_py_data must NOT be in the path list (ADR-65)');
		$this->assertNotContains($pfb['unbound_py_zone'], $result, 'retired unbound_py_zone must NOT be in the path list (ADR-65)');
		$this->assertContains($pfb['unbound_py_wh'],      $result, 'unbound_py_wh must be in the path list');
		$this->assertContains($pfb['unbound_py_sources'], $result, 'unbound_py_sources must be in the path list');
		$this->assertContains($pfb['unbound_py_hsts'],    $result, 'unbound_py_hsts must be in the path list (shipped HSTS preload; #520)');
		$this->assertContains($pfb['unbound_py_tld'],     $result, 'unbound_py_tld must be in the path list (shipped TLD-Wildcard oracle; issue #1255)');

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
	 * Scenario: empty rawdir — no .raw files, just the four flat inputs (incl. HSTS + TLD).
	 *
	 * Given:  a rawdir that is empty (no .raw files)
	 * When:   pfb_dnsbl_loaded_input_paths() is called
	 * Then:   result has exactly 4 entries (wh/sources/hsts/tld only -- ADR-65
	 *         retired unbound_py_data/unbound_py_zone are never in the returned list)
	 */
	public function testEmptyRawdirReturnsOnlyFlatInputs(): void
	{
		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_tld'     => "{$this->tmpDir}/pfb_py_tld.txt",
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
			'unbound_py_count'       => "{$this->tmpDir}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmpDir}/pfb_py_regex_count",
			'unbound_py_ss'          => "{$this->tmpDir}/pfb_py_ss.txt",
		];

		$result = pfb_dnsbl_loaded_input_paths($pfb);

		$this->assertCount(4, $result, 'With no .raw files, exactly the four flat inputs are returned (wh/sources/hsts/tld)');
	}

	/**
	 * Scenario: HSTS file content change is detected by the fingerprint — #520 regression guard.
	 *
	 * The shipped pfb_py_hsts.txt is re-staged by dnsbl_cache_stage() (cp -f) between the
	 * $pfb_fp_old and $pfb_fp_new snapshots.  Before the #520 fix, hsts was absent from the
	 * path list so a package update shipping a new HSTS list never flipped the fingerprint
	 * and the zero-downtime reload was skipped.
	 *
	 * Given:  an HSTS file included in the path set via pfb_dnsbl_loaded_input_paths()
	 * When:   the file content changes (simulating a package update staging a new list)
	 * Then:   the fingerprint differs (reload is triggered)
	 *
	 * Before-state assertion is mandatory: proves the flip is caused by the HSTS file change.
	 */
	public function testHstsFileChangeChangesFingerprint(): void
	{
		$hsts = "{$this->tmpDir}/pfb_py_hsts.txt";
		file_put_contents($hsts, "preload-domain.example\n");

		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => $hsts,
			'unbound_py_tld'     => "{$this->tmpDir}/pfb_py_tld.txt",
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
		];

		// Before: record fingerprint with the original HSTS content.
		$fp_before = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		// Simulate dnsbl_cache_stage() cp -f staging a new shipped list.
		file_put_contents($hsts, "preload-domain.example\nnew-preload.example\n");

		// After: fingerprint must differ (reload fires).
		$fp_after = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		$this->assertNotSame(
			$fp_before,
			$fp_after,
			'A change to pfb_py_hsts.txt must produce a different fingerprint (#520: shipped HSTS update must trigger a zero-downtime reload)'
		);
	}

	/**
	 * Scenario: HSTS file unchanged between snapshots — no spurious reload.
	 *
	 * Given:  an HSTS file that does not change between two fingerprint calls
	 * When:   the fingerprint is computed twice via pfb_dnsbl_loaded_input_paths()
	 * Then:   fingerprints are equal (no reload on an identical re-stage)
	 */
	public function testHstsFileUnchangedProducesEqualFingerprint(): void
	{
		$hsts = "{$this->tmpDir}/pfb_py_hsts.txt";
		file_put_contents($hsts, "preload-domain.example\n");

		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => $hsts,
			'unbound_py_tld'     => "{$this->tmpDir}/pfb_py_tld.txt",
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
		];

		$fp1 = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));
		$fp2 = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		$this->assertSame($fp1, $fp2, 'Unchanged HSTS file must not cause a spurious fingerprint change');
	}

	/**
	 * Scenario: TLD-Wildcard oracle content change is detected by the fingerprint —
	 * issue #1255, HSTS-parity (#520) applied to the public-suffix oracle.
	 *
	 * The shipped pfb_py_tld.txt is re-staged by dnsbl_cache_stage() (cp -f) between
	 * the $pfb_fp_old and $pfb_fp_new snapshots, exactly like pfb_py_hsts.txt. A
	 * package update shipping a new TLD oracle must flip the fingerprint so the
	 * zero-downtime reload picks it up.
	 *
	 * Given:  a TLD oracle file included in the path set via pfb_dnsbl_loaded_input_paths()
	 * When:   the file content changes (simulating a package update staging a new oracle)
	 * Then:   the fingerprint differs (reload is triggered)
	 */
	public function testTldOracleFileChangeChangesFingerprint(): void
	{
		$tld = "{$this->tmpDir}/pfb_py_tld.txt";
		file_put_contents($tld, "com\nnet\n");

		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_tld'     => $tld,
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
		];

		// Before: record fingerprint with the original oracle content.
		$fp_before = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		// Simulate dnsbl_cache_stage() cp -f staging a new shipped oracle.
		file_put_contents($tld, "com\nnet\norg\n");

		// After: fingerprint must differ (reload fires).
		$fp_after = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		$this->assertNotSame(
			$fp_before,
			$fp_after,
			'A change to pfb_py_tld.txt must produce a different fingerprint (issue #1255: shipped TLD oracle update must trigger a zero-downtime reload)'
		);
	}

	/**
	 * Scenario: TLD-Wildcard oracle appearing (absent -> present) is detected.
	 *
	 * Given:  a path set with the oracle ABSENT
	 * When:   the oracle file is created and the fingerprint recomputed
	 * Then:   the fingerprint differs (a first-seen shipped oracle is detected)
	 */
	public function testTldOracleAbsentVsPresentChangesFingerprint(): void
	{
		$tld = "{$this->tmpDir}/pfb_py_tld.txt";
		$pfb = [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_tld'     => $tld,
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
		];

		// Before: the oracle file does not exist.
		$fp_absent = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		file_put_contents($tld, "com\n");
		$fp_present = pfb_dnsbl_loaded_fingerprint(pfb_dnsbl_loaded_input_paths($pfb));

		$this->assertNotSame($fp_absent, $fp_present, 'The oracle appearing on disk must flip the fingerprint');
	}

	// -----------------------------------------------------------------------
	// pfb_dnsbl_reload_fingerprint (issue #1255; ADR-65)
	//
	// unbound_py_data/unbound_py_zone are retired writer targets (never written
	// again) and are excluded from pfb_dnsbl_loaded_input_paths() unconditionally --
	// the TLD-mode-only array_diff narrowing this helper used to apply is gone
	// (a no-op once the base path list never carried them). A content change to
	// either retired file therefore never moves the fingerprint, in EITHER
	// dnsbl_tld_wildcard state; every other input (the TLD oracle included)
	// still gates the reload normally.
	// -----------------------------------------------------------------------

	private function reloadFpBasePfb(): array
	{
		return [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_tld'     => "{$this->tmpDir}/pfb_py_tld.txt",
			'unbound_py_rawdir'  => "{$this->tmpDir}/raw",
		];
	}

	public function testTldModeIgnoresDataZoneChangeButOracleChangeStillTriggersReload(): void
	{
		$pfb = $this->reloadFpBasePfb();
		$pfb['dnsbl_tld_wildcard'] = 'on';
		file_put_contents($pfb['unbound_py_data'], 'stale-legacy-data');
		file_put_contents($pfb['unbound_py_tld'], "com\n");

		$fp_before = pfb_dnsbl_reload_fingerprint($pfb);

		// A retired unbound_py_data file is never in the path set -- its content must
		// NOT move the fingerprint...
		file_put_contents($pfb['unbound_py_data'], 'a-different-write-to-the-retired-file');
		file_put_contents($pfb['unbound_py_zone'], 'a-different-write-to-the-retired-zone');
		$fp_after_data_write = pfb_dnsbl_reload_fingerprint($pfb);
		$this->assertSame($fp_before, $fp_after_data_write,
			'a retired unbound_py_data/unbound_py_zone write must never move the fingerprint (ADR-65)');

		// ...but a staged oracle content change (dnsbl_cache_stage cp -f) MUST.
		file_put_contents($pfb['unbound_py_tld'], "com\nnet\n");
		$fp_after_oracle_change = pfb_dnsbl_reload_fingerprint($pfb);
		$this->assertNotSame($fp_after_data_write, $fp_after_oracle_change,
			'issue #1255: a TLD oracle content change must still flip the fingerprint in TLD mode (the upgrade requirement)');
	}

	/**
	 * ADR-65: renamed + inverted from testNonTldModeIncludesDataZoneChange --
	 * unbound_py_data is a retired writer target excluded from the path set
	 * UNCONDITIONALLY now, so non-TLD mode no longer differs from TLD mode here.
	 */
	public function testNonTldModeAlsoExcludesRetiredDataZoneChange(): void
	{
		$pfb = $this->reloadFpBasePfb();
		$pfb['dnsbl_tld_wildcard'] = '';
		file_put_contents($pfb['unbound_py_data'], 'v1');
		file_put_contents($pfb['unbound_py_zone'], 'z1');

		$fp_before = pfb_dnsbl_reload_fingerprint($pfb);
		file_put_contents($pfb['unbound_py_data'], 'v2');
		file_put_contents($pfb['unbound_py_zone'], 'z2');
		$fp_after = pfb_dnsbl_reload_fingerprint($pfb);

		$this->assertSame($fp_before, $fp_after,
			'Non-TLD mode must ALSO exclude the retired unbound_py_data/unbound_py_zone -- never in the path set (ADR-65)');
	}
}
