<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ensure_trailing_newline() -- issue #1263: cat concatenates bytes, not
 * records. A downloaded/extracted feed with no trailing newline welds its
 * last line onto the next file's first line in every downstream multi-file
 * `cat` pipeline. This guarantees the stored '.orig' always ends in '\n'.
 * Brand-new function (no prior behaviour to be wrong) -- tests assert real
 * behaviour, not mere existence.
 */
/**
 * Seekable stream whose every read returns '' -- the fread()-after-fseek()
 * short-read shape (a racing truncation, a device path). Records fopen()
 * modes so a test can assert no append-mode reopen happens. Single-consumer,
 * so it lives in this file (unlike the shared PfbTruncatedReadStreamWrapper).
 */
final class PfbEmptyReadSeekableStream
{
	/** @var resource|null */
	public $context;
	/** @var list<string> */
	public static array $openModes = [];

	public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
	{
		self::$openModes[] = $mode;
		return TRUE;
	}

	public function stream_read(int $count): string
	{
		return '';
	}

	public function stream_write(string $data): int
	{
		return strlen($data);
	}

	public function stream_seek(int $offset, int $whence = SEEK_SET): bool
	{
		return TRUE;
	}

	public function stream_tell(): int
	{
		return 0;
	}

	public function stream_eof(): bool
	{
		return TRUE;
	}

	/** @return array<string,int> */
	public function stream_stat(): array
	{
		return [];
	}

	public function stream_close(): void
	{
	}
}

#[CoversFunction('pfb_ensure_trailing_newline')]
final class EnsureTrailingNewlineTest extends TestCase
{
	private string $tmpFile;

	protected function setUp(): void
	{
		$this->tmpFile = (string) tempnam(sys_get_temp_dir(), 'pfb_ensure_nl_');
	}

	protected function tearDown(): void
	{
		if (is_file($this->tmpFile)) {
			unlink($this->tmpFile);
		}
	}

	public function testAppendsNewlineWhenLastLineIsUnterminated(): void
	{
		file_put_contents($this->tmpFile, "1.2.3.4\n5.6.7.8");
		$this->assertTrue(pfb_ensure_trailing_newline($this->tmpFile), 'an unterminated file must be reported as changed');
		$this->assertSame("1.2.3.4\n5.6.7.8\n", file_get_contents($this->tmpFile), 'content must be preserved with exactly one appended newline');
	}

	public function testSingleByteFileNoNewlineGetsTerminated(): void
	{
		file_put_contents($this->tmpFile, 'x');
		$this->assertTrue(pfb_ensure_trailing_newline($this->tmpFile));
		$this->assertSame("x\n", file_get_contents($this->tmpFile));
	}

	public function testAlreadyTerminatedFileIsUntouched(): void
	{
		file_put_contents($this->tmpFile, "a\nb\n");
		$this->assertFalse(pfb_ensure_trailing_newline($this->tmpFile), 'an already-terminated file must report no change');
		$this->assertSame("a\nb\n", file_get_contents($this->tmpFile), 'content must be byte-identical -- no double newline');
	}

	public function testEmptyFileIsUntouched(): void
	{
		file_put_contents($this->tmpFile, '');
		$this->assertFalse(pfb_ensure_trailing_newline($this->tmpFile), 'an empty file has nothing to weld -- must not gain a spurious blank line');
		$this->assertSame('', file_get_contents($this->tmpFile));
	}

	public function testMissingPathReturnsFalseWithoutError(): void
	{
		$missing = $this->tmpFile . '-does-not-exist';
		$this->assertFalse(pfb_ensure_trailing_newline($missing));
	}

	public function testDirectoryPathReturnsFalseWithoutError(): void
	{
		// Probed: fopen(dir, 'rb') succeeds and fseek(-1, SEEK_END) even returns 0,
		// but fopen(dir, 'ab') fails -- the append branch is the real guard here.
		$dir = sys_get_temp_dir() . '/pfb_ensure_nl_dir_' . uniqid();
		mkdir($dir);
		try {
			$this->assertFalse(pfb_ensure_trailing_newline($dir), 'a directory must never be written to');
		} finally {
			rmdir($dir);
		}
	}

	public function testLoneNewlineByteIsUntouched(): void
	{
		file_put_contents($this->tmpFile, "\n");
		$this->assertFalse(pfb_ensure_trailing_newline($this->tmpFile));
		$this->assertSame("\n", file_get_contents($this->tmpFile));
	}

	/** A short/failed last-byte read (fread '' after a successful open+seek --
	 *  probed via the wrapper above) cannot tell terminated from not: the file
	 *  must be left alone and never reopened for append. */
	public function testShortReadLeavesFileAloneAndReportsNoChange(): void
	{
		stream_wrapper_register('pfbemptyread', PfbEmptyReadSeekableStream::class);
		try {
			PfbEmptyReadSeekableStream::$openModes = [];
			$this->assertFalse(
				pfb_ensure_trailing_newline('pfbemptyread://feed'),
				'a failed/short read must report no change -- a spurious append here would corrupt a stored feed'
			);
			$this->assertSame(
				['rb'],
				PfbEmptyReadSeekableStream::$openModes,
				'the file must never be reopened for append after a failed/short last-byte read'
			);
		} finally {
			stream_wrapper_unregister('pfbemptyread');
		}
	}
}
