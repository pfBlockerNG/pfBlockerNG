<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-42 Phase 3 — conditional-GET validator sidecar maintenance.
 *
 * Tests cover:
 *   pfb_force_clear_validators() — sweeps .etag/.lastmod (and optionally hash) sidecars.
 *   pfb_force_scope_dirs()       — the origin dirs a Force Download scope touches.
 *
 * The conditional-GET read/write/decision helpers were removed with the Go cutover (#3977).
 * Every test carries a failable assertion.
 */
#[CoversFunction('pfb_force_clear_validators')]
#[CoversFunction('pfb_force_scope_dirs')]
final class ConditionalGetHelpersTest extends TestCase
{
	/** @var string Writable temp directory for this test class. */
	private string $dir;

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_cget_test_' . getmypid() . '_' . mt_rand(0, 0xffff);
		if (!mkdir($base, 0777, TRUE)) {
			$this->fail("Could not create temp dir: {$base}");
		}
		$this->dir = $base;
	}

	protected function tearDown(): void
	{
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($it as $f) {
			$f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
		}
		rmdir($this->dir);
	}

	// -------------------------------------------------------------------------
	// pfb_force_clear_validators() — sidecar sweep for Force Download / Both
	//
	// These tests are RED on the pre-change code (pfb_force_clear_validators
	// is a new function — calling it before the change gives a fatal error).
	// -------------------------------------------------------------------------

	/**
	 * clear_hashes=FALSE removes only .etag and .lastmod; leaves .orig, .xxhash128, .md5.
	 *
	 *  GIVEN feedA.orig, feedA.orig.etag, feedA.orig.lastmod, feedA.orig.xxhash128,
	 *        feedB.orig, feedB.orig.md5;
	 *   WHEN pfb_force_clear_validators([$dir], FALSE) is called;
	 *   THEN .etag and .lastmod are removed; .orig, .xxhash128, .md5 are kept;
	 *   AND  the return value is 2 (two sidecars removed).
	 */
	public function test_force_clear_validators_etag_lastmod_only(): void
	{
		$dir = $this->dir;
		// Arrange: plant fixture files.
		file_put_contents("{$dir}/feedA.orig",          'content');
		file_put_contents("{$dir}/feedA.orig.etag",     '"abc"');
		file_put_contents("{$dir}/feedA.orig.lastmod",  '1700000000');
		file_put_contents("{$dir}/feedA.orig.xxhash128", 'deadbeef');
		file_put_contents("{$dir}/feedB.orig",          'content2');
		file_put_contents("{$dir}/feedB.orig.md5",      'abc123');

		// Assert BEFORE: all files exist.
		$this->assertFileExists("{$dir}/feedA.orig.etag",     'fixture: .etag must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.lastmod",  'fixture: .lastmod must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.xxhash128",'fixture: .xxhash128 must exist before clear');
		$this->assertFileExists("{$dir}/feedB.orig.md5",      'fixture: .md5 must exist before clear');

		// Act.
		$removed = pfb_force_clear_validators([$dir], FALSE);

		// Assert: only validators removed; hashes and .orig content kept.
		$this->assertFileDoesNotExist(
			"{$dir}/feedA.orig.etag",
			'clear_hashes=FALSE must remove .etag sidecars'
		);
		$this->assertFileDoesNotExist(
			"{$dir}/feedA.orig.lastmod",
			'clear_hashes=FALSE must remove .lastmod sidecars'
		);
		$this->assertFileExists(
			"{$dir}/feedA.orig.xxhash128",
			'clear_hashes=FALSE must NOT remove .xxhash128 (hash sidecars must survive)'
		);
		$this->assertFileExists(
			"{$dir}/feedB.orig.md5",
			'clear_hashes=FALSE must NOT remove .md5 (hash sidecars must survive)'
		);
		$this->assertFileExists(
			"{$dir}/feedA.orig",
			'clear_hashes=FALSE must never remove .orig content files'
		);

		$this->assertSame(
			2,
			$removed,
			sprintf('Expected 2 sidecars removed (etag + lastmod), got %d', $removed)
		);
	}

	/**
	 * clear_hashes=TRUE removes .etag, .lastmod, .xxhash128, and .md5; leaves .orig content.
	 *
	 *  GIVEN the same fixture set as above;
	 *   WHEN pfb_force_clear_validators([$dir], TRUE) is called;
	 *   THEN .etag, .lastmod, .xxhash128, and .md5 are removed; .orig is kept;
	 *   AND  the return value is 4.
	 */
	public function test_force_clear_validators_clears_hashes_too(): void
	{
		$dir = $this->dir;
		file_put_contents("{$dir}/feedA.orig",          'content');
		file_put_contents("{$dir}/feedA.orig.etag",     '"abc"');
		file_put_contents("{$dir}/feedA.orig.lastmod",  '1700000000');
		file_put_contents("{$dir}/feedA.orig.xxhash128", 'deadbeef');
		file_put_contents("{$dir}/feedB.orig",          'content2');
		file_put_contents("{$dir}/feedB.orig.md5",      'abc123');

		$this->assertFileExists("{$dir}/feedA.orig.etag",      'fixture: .etag must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.lastmod",   'fixture: .lastmod must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.xxhash128", 'fixture: .xxhash128 must exist before clear');
		$this->assertFileExists("{$dir}/feedB.orig.md5",       'fixture: .md5 must exist before clear');

		$removed = pfb_force_clear_validators([$dir], TRUE);

		$this->assertFileDoesNotExist("{$dir}/feedA.orig.etag",      'clear_hashes=TRUE must remove .etag');
		$this->assertFileDoesNotExist("{$dir}/feedA.orig.lastmod",   'clear_hashes=TRUE must remove .lastmod');
		$this->assertFileDoesNotExist("{$dir}/feedA.orig.xxhash128", 'clear_hashes=TRUE must remove .xxhash128');
		$this->assertFileDoesNotExist("{$dir}/feedB.orig.md5",       'clear_hashes=TRUE must remove .md5');
		$this->assertFileExists(
			"{$dir}/feedA.orig",
			'clear_hashes=TRUE must never remove .orig content files'
		);

		$this->assertSame(
			4,
			$removed,
			sprintf('Expected 4 sidecars removed (etag + lastmod + xxhash128 + md5), got %d', $removed)
		);
	}

	/**
	 * issue #1797: clear_hashes=TRUE also removes the normalize-stage source-digest
	 * baseline (.norm.src.xxhash128) so a forced pass regenerates and fail-safes to
	 * 'changed' (the downstream norm-skip gate must not survive a Force). The .norm
	 * content file itself is kept, mirroring how .orig is kept.
	 */
	public function test_force_clear_validators_clears_norm_source_baseline_only_with_hashes(): void
	{
		$dir = $this->dir;
		file_put_contents("{$dir}/feedA.orig",                'content');
		file_put_contents("{$dir}/feedA.norm",                'content');
		file_put_contents("{$dir}/feedA.norm.src.xxhash128",  'deadbeef');

		$removed = pfb_force_clear_validators([$dir], FALSE);
		$this->assertFileExists("{$dir}/feedA.norm.src.xxhash128",
			'clear_hashes=FALSE must NOT remove the .norm.src baseline');
		$this->assertSame(0, $removed);

		$removed = pfb_force_clear_validators([$dir], TRUE);
		$this->assertFileDoesNotExist("{$dir}/feedA.norm.src.xxhash128",
			'clear_hashes=TRUE must remove the .norm.src baseline');
		$this->assertFileExists("{$dir}/feedA.norm", 'the .norm content file itself must be kept');
		$this->assertFileExists("{$dir}/feedA.orig", 'the .orig content file itself must be kept');
		$this->assertSame(1, $removed);
	}

	/**
	 * Two dirs each with one .orig.etag → returns 2.
	 *
	 *  GIVEN dirA with feedA.orig.etag and dirB with feedB.orig.etag;
	 *   WHEN pfb_force_clear_validators([dirA, dirB], FALSE) is called;
	 *   THEN both .etag files are removed and the return value is 2.
	 */
	public function test_force_clear_validators_two_dirs(): void
	{
		$dirA = $this->dir . '/origA';
		$dirB = $this->dir . '/origB';
		mkdir($dirA, 0777, TRUE);
		mkdir($dirB, 0777, TRUE);
		file_put_contents("{$dirA}/feedA.orig.etag", '"etagA"');
		file_put_contents("{$dirB}/feedB.orig.etag", '"etagB"');

		$this->assertFileExists("{$dirA}/feedA.orig.etag", 'fixture: dirA etag must exist');
		$this->assertFileExists("{$dirB}/feedB.orig.etag", 'fixture: dirB etag must exist');

		$removed = pfb_force_clear_validators([$dirA, $dirB], FALSE);

		$this->assertFileDoesNotExist("{$dirA}/feedA.orig.etag", 'dirA .etag must be removed');
		$this->assertFileDoesNotExist("{$dirB}/feedB.orig.etag", 'dirB .etag must be removed');
		$this->assertSame(
			2,
			$removed,
			sprintf('Expected 2 removed across two dirs, got %d', $removed)
		);
	}

	/**
	 * Nonexistent dir → returns 0, no error.
	 *
	 *  GIVEN a dir path that does not exist;
	 *   WHEN pfb_force_clear_validators(['/nonexistent/xyz'], FALSE) is called;
	 *   THEN it returns 0 without throwing.
	 */
	public function test_force_clear_validators_nonexistent_dir_returns_zero(): void
	{
		$removed = pfb_force_clear_validators(['/nonexistent/xyz_pfb_test_' . getmypid()], FALSE);
		$this->assertSame(
			0,
			$removed,
			'A nonexistent dir must produce 0 removals and no error'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_force_scope_dirs — Run Now scope -> orig dir(s). Covers all three scope
	// branches deterministically so the live (scope x force-mode) matrix does not
	// have to retest the dir selection on a VM. Red->green: the function is new.
	// -----------------------------------------------------------------------

	private const IP_DIR = '/var/db/pfblockerng/original';
	private const DNSBL_DIR = '/var/db/pfblockerng/dnsblorig';

	public function test_force_scope_dirs_ip_is_ip_origdir_only(): void
	{
		$this->assertSame(
			[self::IP_DIR],
			pfb_force_scope_dirs('ip', self::IP_DIR, self::DNSBL_DIR),
			"scope=ip must map to the IP orig dir only"
		);
	}

	public function test_force_scope_dirs_dnsbl_is_dnsbl_origdir_only(): void
	{
		$this->assertSame(
			[self::DNSBL_DIR],
			pfb_force_scope_dirs('dnsbl', self::IP_DIR, self::DNSBL_DIR),
			"scope=dnsbl must map to the DNSBL orig dir only"
		);
	}

	public function test_force_scope_dirs_both_is_both_origdirs(): void
	{
		$this->assertSame(
			[self::IP_DIR, self::DNSBL_DIR],
			pfb_force_scope_dirs('both', self::IP_DIR, self::DNSBL_DIR),
			"scope=both must map to both orig dirs (IP first, then DNSBL)"
		);
	}

	public function test_force_scope_dirs_unknown_scope_fails_safe_to_both(): void
	{
		// An unrecognized scope falls through to 'both' so a clear never under-covers.
		$this->assertSame(
			[self::IP_DIR, self::DNSBL_DIR],
			pfb_force_scope_dirs('bogus', self::IP_DIR, self::DNSBL_DIR),
			"an unrecognized scope must fail safe to both orig dirs"
		);
	}
}
