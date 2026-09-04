<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Live-tool wiring test for pfb_validate_archive(): proves the function accepts
 * a real valid archive and rejects a truncated/corrupt one per format, using the
 * actual host tools (gunzip -t, bzip2 -t, tar -tf).
 *
 * Each format is guarded with markTestSkipped when the required host tool is
 * absent, so CI hosts without every tool do not fail instead of skip.
 *
 * The end-to-end pfb_download() corrupt-archive rejection — a corrupt archive
 * supplied as a feed download, rejected before extraction — is pinned by the
 * Phase 4 smoke test (red on a fix-reverted pkg). pfb_download() is not
 * off-appliance unit-testable per ADR §5; these wiring tests cover the
 * pfb_validate_archive() function boundary against the real host tools.
 */
#[CoversFunction('pfb_validate_archive')]
final class ArchiveValidateWiringTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_arc_wiring_' . uniqid('', TRUE);
		mkdir($this->dir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
	}

	// -----------------------------------------------------------------------
	// gzip
	// -----------------------------------------------------------------------

	/**
	 * Scenario: gzip — valid archive accepted, truncated rejected
	 *
	 * Given  a real gzip file produced by PHP's gzencode() and a copy truncated
	 *        to 8 bytes (magic + flags; omits data + CRC)
	 * When   pfb_validate_archive() is called on each with 'application/gzip'
	 * Then   the valid file returns TRUE and the truncated file returns FALSE,
	 *        proving the gunzip -t probe is wired and distinguishes them.
	 */
	public function test_gzip_valid_accepted_and_corrupt_rejected(): void
	{
		if (!is_executable('/usr/bin/gunzip')) {
			$this->markTestSkipped('/usr/bin/gunzip not available on this host');
		}

		$validPath   = $this->dir . '/test.gz';
		$corruptPath = $this->dir . '/corrupt.gz';

		$content = gzencode('pfblockerng archive wiring test ' . uniqid('', TRUE));
		$this->assertNotFalse($content, 'gzencode() failed — PHP zlib support missing');
		file_put_contents($validPath, $content);
		// Truncate: keep only 8 bytes (gzip magic + flags); omit compressed data + CRC.
		file_put_contents($corruptPath, substr((string) $content, 0, 8));

		$validResult   = pfb_validate_archive($validPath, 'application/gzip');
		$corruptResult = pfb_validate_archive($corruptPath, 'application/gzip');

		$this->assertTrue($validResult,
			"Expected pfb_validate_archive(valid.gz, 'application/gzip') === TRUE; got FALSE.\n"
			. 'File size: ' . filesize($validPath) . ' bytes'
		);
		$this->assertFalse($corruptResult,
			"Expected pfb_validate_archive(corrupt.gz, 'application/gzip') === FALSE; got TRUE.\n"
			. 'File size: ' . filesize($corruptPath) . ' bytes (truncated)'
		);
	}

	/**
	 * Scenario: gzip — application/x-gzip alias accepted
	 *
	 * Given  the same valid gzip file
	 * When   pfb_validate_archive() is called with 'application/x-gzip'
	 * Then   returns TRUE, proving the x-gzip alias routes to the same gunzip -t probe.
	 */
	public function test_gzip_x_gzip_alias_valid_accepted(): void
	{
		if (!is_executable('/usr/bin/gunzip')) {
			$this->markTestSkipped('/usr/bin/gunzip not available on this host');
		}

		$validPath = $this->dir . '/alias.gz';
		$content   = gzencode('alias test ' . uniqid('', TRUE));
		$this->assertNotFalse($content, 'gzencode() failed');
		file_put_contents($validPath, $content);

		$result = pfb_validate_archive($validPath, 'application/x-gzip');
		$this->assertTrue($result,
			"Expected pfb_validate_archive(valid.gz, 'application/x-gzip') === TRUE; "
			. "got FALSE — x-gzip alias not wired to gunzip -t"
		);
	}

	// -----------------------------------------------------------------------
	// bzip2
	// -----------------------------------------------------------------------

	/**
	 * Scenario: bzip2 — valid archive accepted, truncated rejected
	 *
	 * Given  a real bzip2 file created by the host bzip2 binary and a copy
	 *        truncated to 10 bytes (BZh header; omits block data)
	 * When   pfb_validate_archive() is called on each with 'application/x-bzip2'
	 * Then   the valid file returns TRUE and the truncated file returns FALSE,
	 *        proving the bzip2 -t probe is wired and distinguishes them.
	 */
	public function test_bzip2_valid_accepted_and_corrupt_rejected(): void
	{
		if (!is_executable('/usr/bin/bzip2')) {
			$this->markTestSkipped('/usr/bin/bzip2 not available on this host');
		}

		$inputPath   = $this->dir . '/input.txt';
		$validPath   = $this->dir . '/test.bz2';
		$corruptPath = $this->dir . '/corrupt.bz2';

		file_put_contents($inputPath, 'pfblockerng bzip2 wiring test ' . uniqid('', TRUE));
		exec('/usr/bin/bzip2 -k ' . escapeshellarg($inputPath) . ' 2>/dev/null', $out, $rc);
		if ($rc !== 0 || !file_exists($inputPath . '.bz2')) {
			$this->markTestSkipped('Could not create a bzip2 archive with the host bzip2 binary');
		}
		rename($inputPath . '.bz2', $validPath);

		$raw = file_get_contents($validPath);
		$this->assertNotFalse($raw, 'Could not read created bzip2 file');
		// Truncate: keep only 10 bytes (BZh header magic; omit compressed block data).
		file_put_contents($corruptPath, substr((string) $raw, 0, 10));

		$validResult   = pfb_validate_archive($validPath, 'application/x-bzip2');
		$corruptResult = pfb_validate_archive($corruptPath, 'application/x-bzip2');

		$this->assertTrue($validResult,
			"Expected pfb_validate_archive(valid.bz2) === TRUE; got FALSE.\n"
			. 'File size: ' . filesize($validPath) . ' bytes'
		);
		$this->assertFalse($corruptResult,
			"Expected pfb_validate_archive(corrupt.bz2) === FALSE; got TRUE.\n"
			. 'File size: ' . filesize($corruptPath) . ' bytes (truncated)'
		);
	}

	// -----------------------------------------------------------------------
	// zip
	// -----------------------------------------------------------------------

	/**
	 * Scenario: zip — valid archive accepted, unreadable one rejected
	 *
	 * Given  a real zip file built via ZipArchive and a copy truncated to
	 *        20 bytes (a partial local file header — no member, no central
	 *        directory, unreadable to every unzip implementation)
	 * When   pfb_validate_archive() is called on each with 'application/zip'
	 * Then   the valid file returns TRUE and the truncated file returns FALSE,
	 *        proving the `unzip -t` probe is wired and distinguishes them.
	 *
	 * Issue #3068 removed the skip that used to sit here. The probe was `tar -tf`,
	 * which only reads ZIP when /usr/bin/tar is bsdtar, so this case never ran on a
	 * GNU-tar dev host and the whole zip arm of ADR-45 was CI-only. /usr/bin/unzip
	 * exists on both platforms, so it runs everywhere now.
	 *
	 * The 20-byte truncation is chosen because all three implementations agree on it
	 * (bsdtar -tf rc 1, bsdunzip -t rc 1, Info-ZIP -t rc 9). A LARGER truncation that
	 * still carries a local header does NOT agree — bsdunzip accepts it, Info-ZIP
	 * rejects it — so pinning one of those would pass on the appliance and fail on a
	 * plain Debian host, which is the trap this issue exists to remove.
	 */
	public function test_zip_valid_accepted_and_corrupt_rejected(): void
	{
		if (!is_executable('/usr/bin/unzip')) {
			$this->markTestSkipped('/usr/bin/unzip not available on this host');
		}
		if (!class_exists('ZipArchive')) {
			$this->markTestSkipped('ZipArchive not available (php-zip extension missing)');
		}

		$validPath   = $this->dir . '/test.zip';
		$corruptPath = $this->dir . '/corrupt.zip';

		$zip    = new ZipArchive();
		$opened = $zip->open($validPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
		$this->assertSame(TRUE, $opened, 'ZipArchive::open() failed to create test.zip');
		$zip->addFromString('data.txt', 'pfblockerng zip wiring test ' . uniqid('', TRUE));
		$zip->close();

		$raw = file_get_contents($validPath);
		$this->assertNotFalse($raw, 'Could not read created zip file');
		// Truncate: keep only 20 bytes (local file header start; omits end-of-central-dir).
		file_put_contents($corruptPath, substr((string) $raw, 0, 20));

		$validResult   = pfb_validate_archive($validPath, 'application/zip');
		$corruptResult = pfb_validate_archive($corruptPath, 'application/zip');

		$this->assertTrue($validResult,
			"Expected pfb_validate_archive(valid.zip) === TRUE; got FALSE.\n"
			. 'File size: ' . filesize($validPath) . ' bytes'
		);
		$this->assertFalse($corruptResult,
			"Expected pfb_validate_archive(corrupt.zip) === FALSE; got TRUE.\n"
			. 'File size: ' . filesize($corruptPath) . ' bytes (truncated)'
		);
	}

	/**
	 * Scenario: issue #3068 — the zip probe must not accept a tar.
	 *
	 * Given  a perfectly valid gzip TAR
	 * When   pfb_validate_archive() is called on it with 'application/zip'
	 * Then   it returns FALSE.
	 *
	 * This is the reason the mapping had to change rather than merely be made
	 * portable. The old probe was `tar -tf`, and libarchive's tar reads gzip, tar AND
	 * zip — so "is this a valid application/zip?" answered TRUE for a gzip tarball on
	 * the appliance. pfb_filter()'s octet-stream recovery loop asks exactly that
	 * question, application/zip FIRST, and adopts the first type that answers TRUE:
	 * an octet-stream-typed .tar.gz feed was therefore recovered as application/zip
	 * and routed down the zip arm. `unzip -t` cannot make that mistake.
	 */
	public function test_zip_probe_refuses_a_gzip_tar(): void
	{
		if (!is_executable('/usr/bin/unzip')) {
			$this->markTestSkipped('/usr/bin/unzip not available on this host');
		}
		$member = $this->dir . '/member.txt';
		$tgz    = $this->dir . '/feed.tar.gz';
		$this->assertNotFalse(file_put_contents($member, "203.0.113.7\n"));
		$output = [];
		$retval = 1;
		exec(escapeshellarg(pfb_test_tar()) . ' -czf ' . escapeshellarg($tgz) . ' -C ' . escapeshellarg($this->dir)
			. ' member.txt 2>/dev/null', $output, $retval);
		$this->assertSame(0, $retval, 'the fixture tarball must be built');

		// Control: it really is a valid archive of its own type, so a FALSE below is
		// the probe discriminating, not the fixture being broken.
		$this->assertTrue(pfb_validate_archive($tgz, 'application/gzip'),
			'the fixture must be a valid gzip stream, or the assertion below proves nothing');

		$this->assertFalse(pfb_validate_archive($tgz, 'application/zip'),
			'a gzip tarball must never pass the application/zip probe — that misidentification '
			. 'is what the octet-stream recovery loop turns into a wrong MIME type');
	}
}
