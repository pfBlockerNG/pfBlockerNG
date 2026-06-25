<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_has_loaded_feeds() — detects genuine feed-derived DNSBL content.
 *
 * Design intent: distinguish a no-feeds steady-state (empty py_data, no zone, no raw files)
 * from a setup where feeds were actually loaded. The shipped pfb_py_hsts and the
 * manifest/whitelist are deliberately EXCLUDED: counting them makes a no-feeds setup
 * look "loaded", which caused a clear+reload every cron pass (#546).
 *
 * The empty-feed clear path now materializes files as present-but-empty rather than
 * deleting them, so this helper gates the "Clearing all DNSBL Feeds" log/flag on whether
 * FEED-derived content was present — not merely whether ANY path existed.
 */
#[CoversFunction('pfb_dnsbl_has_loaded_feeds')]
final class DnsblHasLoadedFeedsTest extends TestCase
{
	private string $tmpDir;
	private string $rawDir;

	protected function setUp(): void
	{
		$this->tmpDir = sys_get_temp_dir() . '/pfb_hlf_test_' . getmypid() . '_' . mt_rand();
		$this->rawDir = "{$this->tmpDir}/raw";
		mkdir($this->tmpDir, 0700, TRUE);
		mkdir($this->rawDir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmpDir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($files as $f) {
			$f->isDir() ? rmdir((string) $f) : unlink((string) $f);
		}
		rmdir($this->tmpDir);
	}

	/** Build a minimal $pfb array with all paths under tmpDir. */
	private function makePfb(): array
	{
		return [
			'unbound_py_data'    => "{$this->tmpDir}/pfb_py_data.txt",
			'unbound_py_zone'    => "{$this->tmpDir}/pfb_py_zone.txt",
			'unbound_py_wh'      => "{$this->tmpDir}/pfb_py_whitelist.txt",
			'unbound_py_sources' => "{$this->tmpDir}/pfb_py_sources.json",
			'unbound_py_hsts'    => "{$this->tmpDir}/pfb_py_hsts.txt",
			'unbound_py_rawdir'  => $this->rawDir,
		];
	}

	/**
	 * Scenario: empty setup — no data file, no zone, no raw files → no feeds loaded.
	 *
	 * Given:  a clean $pfb with no files on disk
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns FALSE (nothing feed-derived is present)
	 *
	 * This is the initial install / freshly-cleared state.
	 */
	public function testEmptySetupReturnsFalse(): void
	{
		$pfb = $this->makePfb();
		$this->assertFalse(pfb_dnsbl_has_loaded_feeds($pfb), 'No files at all → FALSE');
	}

	/**
	 * Scenario: 0-byte py_data (the materialized steady-state) → no feeds loaded (#546).
	 *
	 * Given:  pfb_py_data exists but is empty (written by the empty-feed clear path)
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns FALSE
	 *
	 * This is the key regression case: an empty-but-present py_data must NOT look like a
	 * loaded feed, otherwise the "Clearing all DNSBL Feeds" log fires on every cron pass.
	 */
	public function testZeroByteDataFileReturnsFalse(): void
	{
		$pfb = $this->makePfb();
		file_put_contents($pfb['unbound_py_data'], '');

		$this->assertFalse(pfb_dnsbl_has_loaded_feeds($pfb), '0-byte py_data → FALSE (steady-state empty; #546)');
	}

	/**
	 * Scenario: non-empty py_data → feeds are loaded.
	 *
	 * Given:  pfb_py_data contains at least one byte of CSV content
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns TRUE
	 *
	 * Before-state assertion (empty → FALSE) proves the non-empty file caused the flip.
	 */
	public function testNonEmptyDataFileReturnsTrue(): void
	{
		$pfb = $this->makePfb();

		// Before: no file → FALSE.
		$this->assertFalse(pfb_dnsbl_has_loaded_feeds($pfb), 'Before: absent py_data → FALSE');

		// Write feed content.
		file_put_contents($pfb['unbound_py_data'], "blocked.example.com,127.0.0.1\n");

		// After: non-empty py_data → TRUE.
		$this->assertTrue(pfb_dnsbl_has_loaded_feeds($pfb), 'Non-empty py_data → TRUE');
	}

	/**
	 * Scenario: py_zone present → feeds are loaded (TLD mode).
	 *
	 * Given:  pfb_py_zone exists (even with no py_data)
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns TRUE
	 *
	 * Before-state assertion (no zone → FALSE) proves the zone caused the flip.
	 */
	public function testZoneFilePresentReturnsTrue(): void
	{
		$pfb = $this->makePfb();

		// Before: no zone → FALSE.
		$this->assertFalse(pfb_dnsbl_has_loaded_feeds($pfb), 'Before: absent py_zone → FALSE');

		// Create zone file (TLD mode writes this).
		file_put_contents($pfb['unbound_py_zone'], "local-zone: example.com redirect\n");

		// After: zone present → TRUE.
		$this->assertTrue(pfb_dnsbl_has_loaded_feeds($pfb), 'py_zone present → TRUE');
	}

	/**
	 * Scenario: at least one *.raw in rawdir → feeds are loaded.
	 *
	 * Given:  a single *.raw file exists in the rawdir
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns TRUE
	 *
	 * Before-state assertion (empty rawdir → FALSE) proves the raw file caused the flip.
	 */
	public function testRawFilePresentReturnsTrue(): void
	{
		$pfb = $this->makePfb();

		// Before: empty rawdir → FALSE.
		$this->assertFalse(pfb_dnsbl_has_loaded_feeds($pfb), 'Before: empty rawdir → FALSE');

		// Drop a raw file (pfb_unbound_python_sources() writes these for each feed).
		file_put_contents("{$this->rawDir}/some_feed.raw", "blocked.example.com\n");

		// After: *.raw present → TRUE.
		$this->assertTrue(pfb_dnsbl_has_loaded_feeds($pfb), '*.raw in rawdir → TRUE');
	}

	/**
	 * Scenario: only pfb_py_hsts present (no feed-derived files) → FALSE (#546 regression guard).
	 *
	 * Given:  pfb_py_hsts exists (the shipped HSTS preload list, always staged),
	 *         but no py_data, py_zone, or *.raw files
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns FALSE
	 *
	 * This is the central regression the fix addresses: before #546, the loaded-input-paths
	 * check included pfb_py_hsts, so a no-feeds setup (hsts always present) always returned
	 * TRUE → "Clearing all DNSBL Feeds" + unlink(py_wh) + Unbound restart every cron.
	 */
	public function testOnlyHstsPresentReturnsFalse(): void
	{
		$pfb = $this->makePfb();

		// Stage the shipped HSTS list (always present after package install).
		file_put_contents($pfb['unbound_py_hsts'], "preload-domain.example\n");

		// Must return FALSE: hsts is NOT a feed-derived file.
		$this->assertFalse(
			pfb_dnsbl_has_loaded_feeds($pfb),
			'Only pfb_py_hsts present → FALSE (hsts is not feed-derived; #546 regression guard)'
		);
	}

	/**
	 * Scenario: whitelist and manifest present (non-feed files) → FALSE.
	 *
	 * Given:  pfb_py_wh (whitelist) and pfb_py_sources (manifest) exist but no feeds
	 * When:   pfb_dnsbl_has_loaded_feeds() is called
	 * Then:   returns FALSE
	 *
	 * pfb_unbound_python() owns py_wh; pfb_unbound_python_sources() maintains py_sources.
	 * Neither constitutes "loaded feeds".
	 */
	public function testOnlyWhitelistAndManifestPresentReturnsFalse(): void
	{
		$pfb = $this->makePfb();
		file_put_contents($pfb['unbound_py_wh'],      "allow.example.com\n");
		file_put_contents($pfb['unbound_py_sources'], '{"version":1,"feeds":[]}');

		$this->assertFalse(pfb_dnsbl_has_loaded_feeds($pfb), 'Whitelist + manifest only → FALSE');
	}
}
