<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin pfb_log_tail_chunk() -- the read primitive behind the AJAX live-log tail endpoint
 * (issue #671). The client polls with the byte offset it last received; this function returns
 * the next slice and the offset to ask for next time. The contract that keeps the tail correct:
 *
 *   - whole lines only by default (a trailing partial line is held back), so a multibyte UTF-8
 *     char is never split across two polls and corrupted by the JSON encoder;
 *   - $flush = TRUE emits the held partial on the final read (run done, no more lines coming);
 *   - the offset is a RAW byte position even though CR is stripped from the returned text;
 *   - an offset past EOF (run log truncated by a fresh run) resets to 0 instead of desyncing.
 */
#[CoversFunction('pfb_log_tail_chunk')]
final class LiveLogTailChunkTest extends TestCase
{
	private string $file;

	protected function setUp(): void
	{
		$this->file = tempnam(sys_get_temp_dir(), 'pfb_tail_');
	}

	protected function tearDown(): void
	{
		@unlink($this->file);
	}

	public function testMissingFileYieldsEmptyAtZero(): void
	{
		@unlink($this->file);
		$r = pfb_log_tail_chunk($this->file, 0);
		$this->assertSame(['data' => '', 'offset' => 0], $r);
	}

	public function testReadsCompleteLinesAndAdvancesOffset(): void
	{
		file_put_contents($this->file, "line one\nline two\n");
		$r = pfb_log_tail_chunk($this->file, 0);

		$this->assertSame("line one\nline two\n", $r['data']);
		$this->assertSame(18, $r['offset'], 'offset must land at EOF after a full read');

		// A follow-up poll at the returned offset sees nothing new.
		$this->assertSame(['data' => '', 'offset' => 18], pfb_log_tail_chunk($this->file, 18));
	}

	public function testIncrementalAppendIsStreamedFromTheOffset(): void
	{
		file_put_contents($this->file, "first\n");
		$r1 = pfb_log_tail_chunk($this->file, 0);
		$this->assertSame("first\n", $r1['data']);

		// Append more; the next poll from the prior offset returns ONLY the new line.
		file_put_contents($this->file, "second\n", FILE_APPEND);
		$r2 = pfb_log_tail_chunk($this->file, $r1['offset']);
		$this->assertSame("second\n", $r2['data']);
		$this->assertSame(13, $r2['offset']);
	}

	public function testTrailingPartialLineIsHeldBackUntilFlush(): void
	{
		// A line still being written (no terminating newline yet).
		file_put_contents($this->file, "complete\npartial-no-nl");

		// Without flush: only the complete line is emitted; the partial is held, so the offset
		// stops at the newline and the partial is re-read next time.
		$held = pfb_log_tail_chunk($this->file, 0);
		$this->assertSame("complete\n", $held['data']);
		$this->assertSame(9, $held['offset']);

		// Polling again at that offset still holds the partial (no newline yet) -> nothing new.
		$still = pfb_log_tail_chunk($this->file, $held['offset']);
		$this->assertSame('', $still['data']);
		$this->assertSame(9, $still['offset']);

		// On the FINAL read (run done) flush emits the trailing partial too.
		$flushed = pfb_log_tail_chunk($this->file, $held['offset'], TRUE);
		$this->assertSame('partial-no-nl', $flushed['data']);
		$this->assertSame(22, $flushed['offset']);
	}

	public function testCarriageReturnsStrippedFromTextButOffsetCountsRawBytes(): void
	{
		// CRLF content: 6 raw bytes ("a\r\nb\r\n"), display strips the CRs.
		file_put_contents($this->file, "a\r\nb\r\n");
		$r = pfb_log_tail_chunk($this->file, 0);

		$this->assertSame("a\nb\n", $r['data'], 'CR stripped for display');
		$this->assertSame(6, $r['offset'], 'offset must count raw bytes (incl. CR), not stripped length');
	}

	public function testOffsetPastEofResetsToZero(): void
	{
		// Simulate a fresh run truncating the run log to fewer bytes than the client's offset.
		file_put_contents($this->file, "short\n");
		$r = pfb_log_tail_chunk($this->file, 9999);

		$this->assertSame("short\n", $r['data'], 'a stale past-EOF offset restarts from 0');
		$this->assertSame(6, $r['offset']);
	}
}
