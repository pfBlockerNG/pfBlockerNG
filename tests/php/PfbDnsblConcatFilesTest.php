<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_concat_files() unchecked-fopen guard (issue #1097).
 *
 * Three DNSBL assembly loops in sync_package_pfblockerng() (DNSBLIP_v4, DNSBLIP_v6, the
 * master .raw) opened their destination without checking the return, then unconditionally
 * fwrote/fclosed it. On PHP 8, fwrite(FALSE)/fclose(FALSE) throw TypeError ('@' only
 * silences warnings), so an unwritable destination directory aborted the whole DNSBL
 * update. The extracted helper guards the destination open (skip + log on failure) and
 * each source open (skip a vanished/empty source, keep going).
 *
 * The unwritable destination is modeled as a NON-EXISTENT directory (fopen fails for any
 * uid, unlike a chmod fixture, which root bypasses).
 */
#[CoversFunction('pfb_dnsbl_concat_files')]
#[CoversFunction('pfb_dnsbl_concat_write_ok')]
final class PfbDnsblConcatFilesTest extends TestCase
{
	private string $workdir = '';

	/** @var array<string,mixed> saved $pfb keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbconcat');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['log', 'errlog', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	public function testConcatenatesSourcesInOrderByteExact(): void
	{
		// Given: two sources; the LAST one has NO trailing newline, pinning fgets copy
		// fidelity (no trimming/normalization may be introduced).
		$src1 = "{$this->workdir}/one.txt";
		$src2 = "{$this->workdir}/two.txt";
		file_put_contents($src1, "1.example.com\n2.example.com\n");
		file_put_contents($src2, "3.example.com");
		$dest = "{$this->workdir}/dest.txt";

		$result = pfb_dnsbl_concat_files($dest, [$src1, $src2]);

		$this->assertTrue($result, 'a writable destination must return TRUE');
		$this->assertSame(
			"1.example.com\n2.example.com\n3.example.com",
			file_get_contents($dest),
			'sources must land concatenated, in order, with byte-exact fidelity'
		);
	}

	public function testUnwritableDestinationDegradesInsteadOfThrowing(): void
	{
		// Given: the destination directory does not exist, so the destination fopen fails.
		$dest = "{$this->workdir}/does-not-exist/dest.txt";
		$src  = "{$this->workdir}/one.txt";
		file_put_contents($src, "1.example.com\n");

		// When/Then: before the guard this threw TypeError from fwrite(FALSE) (PHP 8;
		// '@' does not suppress it) and aborted the whole DNSBL assembly pass.
		$result = pfb_dnsbl_concat_files($dest, [$src]);

		$this->assertFalse($result, 'a failed destination open must return FALSE, not throw');
		$this->assertFileDoesNotExist($dest);
		$logged = @file_get_contents($GLOBALS['pfb']['errlog']) . @file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString(
			'failed to open',
			$logged,
			'the skip must be operator-visible, not silent'
		);
	}

	public function testVanishedSourceIsSkippedNotFatal(): void
	{
		// Given: one existing and one missing source (a list vanished mid-loop).
		$src = "{$this->workdir}/one.txt";
		file_put_contents($src, "1.example.com\n");
		$dest = "{$this->workdir}/dest.txt";

		$result = pfb_dnsbl_concat_files($dest, [$src, "{$this->workdir}/gone.txt"]);

		$this->assertTrue($result);
		$this->assertSame(
			"1.example.com\n",
			file_get_contents($dest),
			'the existing source must still be copied when a sibling vanished'
		);
	}

	public function testEmptyStringSourcePathIsSkippedGracefully(): void
	{
		// Given: an empty-string entry in the sources array (never a valid path).
		$src = "{$this->workdir}/one.txt";
		file_put_contents($src, "1.example.com\n");
		$dest = "{$this->workdir}/dest.txt";

		$result = pfb_dnsbl_concat_files($dest, ['', $src]);

		$this->assertTrue($result);
		$this->assertSame(
			"1.example.com\n",
			file_get_contents($dest),
			'an empty-string source must be skipped, never passed to fopen unguarded'
		);
	}

	/**
	 * The write-outcome predicate must flag a SHORT (partial, non-FALSE) fwrite as a
	 * failure -- not just a bare FALSE -- so a truncated destination can never advance
	 * the rebuild bookkeeping as current. A genuine disk-full short write cannot be
	 * forced deterministically/portably in a unit test (same constraint documented at
	 * DnsblPrefetchTest::test_write_complete_helper_flags_a_short_write_as_incomplete),
	 * so this pins the extracted decision predicate directly with fabricated byte counts.
	 */
	public function testWriteOkPredicateFlagsShortAndFailedWritesAsIncomplete(): void
	{
		$line = "1.example.com\n";

		$this->assertFalse(
			pfb_dnsbl_concat_write_ok(strlen($line) - 3, $line),
			'a short byte count must be flagged as an incomplete write'
		);
		$this->assertFalse(
			pfb_dnsbl_concat_write_ok(FALSE, $line),
			'FALSE must be flagged as an incomplete write'
		);
		$this->assertTrue(
			pfb_dnsbl_concat_write_ok(strlen($line), $line),
			'an exact full-length write must be flagged as complete'
		);
	}

	public function testEmptySourcesArrayCreatesEmptyDestination(): void
	{
		// Given: no sources at all.
		$dest = "{$this->workdir}/dest.txt";

		$result = pfb_dnsbl_concat_files($dest, []);

		$this->assertTrue($result, 'fopen "w" truncate semantics must still apply with zero sources');
		$this->assertSame('', file_get_contents($dest), 'the destination must exist and be empty');
	}
}
