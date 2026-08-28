<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_count_lines() -- issue #1257: the ONE line-count primitive, replacing two
 * counters that disagreed on what "a line" is. Counts a line as tail(1)/
 * `grep -c ^` does: an unterminated trailing chunk IS a line. Returns NULL on
 * any failure to count reliably (unopenable path, unreadable, or a
 * short/failed read) -- there is no universally safe default, so each caller
 * maps NULL to its own fail direction (see LogTrimNeededTest /
 * IpRecomputeSnapshotTest for the caller mappings).
 */
#[CoversFunction('pfb_count_lines')]
final class CountLinesTest extends TestCase
{
	private string $tmpFile;

	protected function setUp(): void
	{
		$this->tmpFile = (string) tempnam(sys_get_temp_dir(), 'pfb_count_lines_');
	}

	protected function tearDown(): void
	{
		if (in_array('pfbtrunc', stream_get_wrappers(), TRUE)) {
			stream_wrapper_unregister('pfbtrunc');
		}
		if (is_file($this->tmpFile)) {
			unlink($this->tmpFile);
		}
	}

	// -----------------------------------------------------------------------
	// A -- counting semantics (oracle: grep -c '^' / tail, never wc -l).
	// -----------------------------------------------------------------------

	public function testTrailingNewlineCountsExactLines(): void
	{
		file_put_contents($this->tmpFile, "a\nb\nc\n");
		$this->assertSame(3, pfb_count_lines($this->tmpFile), '3 newline-terminated lines must count as 3');
	}

	public function testDanglingLastLineCountsAsALineLikeTail(): void
	{
		// tail(1)/grep -c ^ both call an unterminated trailing chunk a line;
		// counting bare "\n" bytes alone would undercount it.
		file_put_contents($this->tmpFile, "a\nb\nc");
		$this->assertSame(3, pfb_count_lines($this->tmpFile), '3 lines with no trailing newline must count as 3');
	}

	public function testSingleUnterminatedLineNoNewlineCountsAsOne(): void
	{
		// The empty/one-line boundary: zero newline bytes, but still one line.
		file_put_contents($this->tmpFile, 'abc');
		$this->assertSame(1, pfb_count_lines($this->tmpFile), 'one unterminated line with no newline must count as 1');
	}

	public function testEmptyFileCountsZeroNotOne(): void
	{
		file_put_contents($this->tmpFile, '');
		$this->assertSame(0, pfb_count_lines($this->tmpFile), 'an empty file must count as 0, not 1');
	}

	public function testSingleNewlineOnlyCountsAsOne(): void
	{
		file_put_contents($this->tmpFile, "\n");
		$this->assertSame(1, pfb_count_lines($this->tmpFile), 'a lone newline byte is one (empty) line');
	}

	public function testMultipleTrailingNewlinesCountEachAsALine(): void
	{
		file_put_contents($this->tmpFile, "a\nb\nc\n\n\n");
		$this->assertSame(5, pfb_count_lines($this->tmpFile), '3 content lines + 2 blank lines must count as 5, not 3');
	}

	public function testChunkExactMultipleFileSizeCountsCorrectly(): void
	{
		// File size is EXACTLY one fread() chunk (1048576 bytes): the final
		// fread() must return '' cleanly, not clobber $last_byte via a bogus
		// extra iteration.
		$line = str_repeat('x', 15) . "\n"; // 16 bytes/line
		file_put_contents($this->tmpFile, str_repeat($line, 65536)); // 65536*16 = 1048576
		$this->assertSame(65536, pfb_count_lines($this->tmpFile), 'a file exactly one chunk long must count exactly');
	}

	public function testLargerThanOneChunkWithDanglingLastLineCountsCorrectly(): void
	{
		// $last_byte must survive across loop iterations: pad past one chunk,
		// then end on an unterminated line in the NEXT chunk.
		$line = str_repeat('x', 15) . "\n"; // 16 bytes/line
		file_put_contents($this->tmpFile, str_repeat($line, 65536) . 'TAIL'); // >1 chunk + dangling line
		$this->assertSame(65537, pfb_count_lines($this->tmpFile), '65536 terminated lines + 1 dangling line = 65537');
	}

	// -----------------------------------------------------------------------
	// B -- the ?int failure contract.
	// -----------------------------------------------------------------------

	public function testMissingPathReturnsNull(): void
	{
		$missing = $this->tmpFile . '-does-not-exist';
		$this->assertNull(pfb_count_lines($missing), 'a missing/unopenable path must return NULL, not a hardcoded default');
	}

	public function testUnreadableFileReturnsNullNotZero(): void
	{
		// A file that EXISTS but cannot be opened must fail the same way a missing one does.
		// Returning 0 here would read as "no lines" -- a count every caller would believe.
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions; cannot simulate an unreadable file');
		}

		file_put_contents($this->tmpFile, "a\nb\nc\n");
		chmod($this->tmpFile, 0000);
		try {
			$this->assertNull(pfb_count_lines($this->tmpFile), 'an unreadable file must return NULL, never a count');
		} finally {
			chmod($this->tmpFile, 0644);
		}
	}

	public function testShortReadThatNeverReachesEofReturnsNull(): void
	{
		// issue #1257 B2: a read that stalls/aborts mid-stream (feof() never goes TRUE)
		// must never be reported as a completed, trustworthy count.
		//
		// The scenario is SYNTHETIC and defence-in-depth: for a real local file an
		// fread() returning '' always coincides with feof() === TRUE, so production
		// reaches the sibling fread()===FALSE branch (e.g. a directory), not this one.
		// The guard still ships because the fail direction here is destructive -- an
		// undercount silently skips a trim -- and a future non-local stream would hit it.
		require_once __DIR__ . '/PfbTruncatedReadStreamWrapper.php';
		stream_wrapper_register('pfbtrunc', PfbTruncatedReadStreamWrapper::class);
		PfbTruncatedReadStreamWrapper::setData("a\nb\nc\n");
		$this->assertNull(
			pfb_count_lines('pfbtrunc://short-read-source'),
			'a read that never reaches EOF must return NULL, never a partial count'
		);
	}

	// -----------------------------------------------------------------------
	// Hostile inputs (issue #1257 S4).
	// -----------------------------------------------------------------------

	public function testDirectoryPathReturnsNullNotABogusCount(): void
	{
		// Probed: @fopen() on a directory SUCCEEDS (returns a resource), but the
		// first fread() FAILS -- must not be misread as a legitimate empty file.
		$dir = sys_get_temp_dir() . '/pfb_count_lines_dir_' . uniqid();
		mkdir($dir);
		try {
			$this->assertNull(pfb_count_lines($dir), 'a directory must never report a line count');
		} finally {
			rmdir($dir);
		}
	}

	public function testSingleByteFileNoNewlineCountsAsOne(): void
	{
		file_put_contents($this->tmpFile, 'a');
		$this->assertSame(1, pfb_count_lines($this->tmpFile), 'a single non-newline byte is one unterminated line');
	}

	public function testPathWithSpacesAndShellMetacharactersCountsNormally(): void
	{
		// No exec()/shell involved -- fopen() takes the path literally.
		$path = sys_get_temp_dir() . "/pfb count 'lines\$(rm) & ;.txt";
		file_put_contents($path, "a\nb\n");
		try {
			$this->assertSame(2, pfb_count_lines($path), 'shell metacharacters in the path must not affect counting');
		} finally {
			unlink($path);
		}
	}

	public function testManyTimesOneChunkStaysWithinBoundedMemory(): void
	{
		// issue #1027 discipline: must stream, never slurp (file()/file_get_contents()
		// peaked at ~68MB on a 1M-line file per issue #1084's review). 32 chunks is
		// already 32x any per-chunk buffer, so a slurp cannot hide inside the headroom.
		$lineWidth  = 16; // 15 'x' + "\n"
		$chunk      = str_repeat(str_repeat('x', 15) . "\n", 65536); // exactly 1048576 bytes
		$chunkCount = 32; // 32 MiB -- enough to prove streaming without 200MiB of CI disk churn
		$fh         = fopen($this->tmpFile, 'wb');
		for ($i = 0; $i < $chunkCount; $i++) {
			fwrite($fh, $chunk);
		}
		fclose($fh);

		memory_reset_peak_usage();
		$before = memory_get_usage(true);
		$count  = pfb_count_lines($this->tmpFile);
		$peak   = memory_get_peak_usage(true);

		$this->assertSame($chunkCount * (1048576 / $lineWidth), $count, 'a multi-chunk file must still count exactly');
		$this->assertLessThan(
			$before + (10 * 1048576),
			$peak,
			'peak memory must stay near one chunk (~1MiB), not scale with file size'
		);
	}
}
