<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4263 (owner, 2026-11-23): the version 2 apply discards a pending marker whose token it does not take, and files the
 * issue; any other mark stays. The marker is set aside by a rename and the content set aside decides: a bad token is removed, a
 * valid or empty mark (a save that marked meanwhile) is put back unless a newer marker stands. The seams `read` (after the first
 * read) and `aside` (after the rename) stand in for a save landing there.
 */
#[CoversFunction('pfb_outpost_repair_pending_marker')]
final class OutpostRepairPendingMarkerTest extends TestCase
{
	private const BAD = "bad token\n";

	private array $priorPfb;
	private string $dir;
	private string $marker;

	protected function setUp(): void
	{
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_repair_marker_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$this->marker = "{$this->dir}/pending";
		$GLOBALS['pfb']['pending_marker'] = $this->marker;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->dir);
	}

	/** @return list<string> */
	private function left(): array
	{
		$names = array_values(array_diff(scandir($this->dir) ?: [], ['.', '..']));
		sort($names);
		return $names;
	}

	public function testABadTokenIsRemovedWithItsAppliedRecordAndReported(): void
	{
		file_put_contents($this->marker, self::BAD);
		file_put_contents("{$this->marker}.applied", 'older');

		$issues = pfb_outpost_repair_pending_marker();

		$this->assertSame([], $this->left(), 'the marker, its applied record and nothing set aside remain');
		$this->assertSame([['resource' => 'pending-marker', 'stage' => 'apply', 'code' => 'pending_token_invalid',
			'message' => 'the pending-changes marker held a token that is not 1 to 64 printable ASCII characters; it was discarded']],
			$issues);
	}

	public function testAValidOrEmptyMarkIsLeftAlone(): void
	{
		foreach (['0123456789abcdef', ''] as $mark) {
			file_put_contents($this->marker, $mark);
			$this->assertSame([], pfb_outpost_repair_pending_marker(), json_encode($mark));
			$this->assertSame($mark, file_get_contents($this->marker));
			$this->assertSame(['pending'], $this->left());
		}
	}

	public function testASaveBetweenTheReadAndTheSetAsideKeepsItsMark(): void
	{
		file_put_contents($this->marker, self::BAD);

		$issues = pfb_outpost_repair_pending_marker(['read' => fn () => file_put_contents($this->marker, 'fresh-mark')]);

		$this->assertSame([], $issues, 'nothing bad was discarded');
		$this->assertSame('fresh-mark', file_get_contents($this->marker));
		$this->assertSame(['pending'], $this->left());
	}

	public function testASaveAfterTheSetAsideKeepsItsOwnMark(): void
	{
		file_put_contents($this->marker, self::BAD);

		$issues = pfb_outpost_repair_pending_marker(['aside' => fn () => file_put_contents($this->marker, 'newer-mark')]);

		$this->assertCount(1, $issues, 'the bad token set aside is discarded');
		$this->assertSame('newer-mark', file_get_contents($this->marker));
		$this->assertSame(['pending'], $this->left());
	}

	public function testAMarkSetAsideIsNotPutBackOverANewerOne(): void
	{
		file_put_contents($this->marker, self::BAD);

		$issues = pfb_outpost_repair_pending_marker([
			'read'  => fn () => file_put_contents($this->marker, 'fresh-mark'),
			'aside' => fn () => file_put_contents($this->marker, 'newer-mark'),
		]);

		$this->assertSame([], $issues);
		$this->assertSame('newer-mark', file_get_contents($this->marker), 'the newer mark is never replaced');
		$this->assertSame(['pending'], $this->left());
	}

	public function testWhatAStoppedRepairSetAsideIsSettledFirst(): void
	{
		file_put_contents("{$this->marker}.discard", 'kept-mark');
		$this->assertSame([], pfb_outpost_repair_pending_marker());
		$this->assertSame('kept-mark', file_get_contents($this->marker), 'a valid mark set aside is put back');
		$this->assertSame(['pending'], $this->left());

		unlink($this->marker);
		file_put_contents("{$this->marker}.discard", self::BAD);
		file_put_contents("{$this->marker}.applied", 'older');
		$this->assertCount(1, pfb_outpost_repair_pending_marker(), 'a bad token set aside is discarded and reported');
		$this->assertSame([], $this->left(), 'with its applied record');
	}

	public function testAnAsideThatVanishesIsNotReportedAsDiscarded(): void
	{
		file_put_contents($this->marker, self::BAD);
		file_put_contents("{$this->marker}.applied", 'older');

		$issues = pfb_outpost_repair_pending_marker(['aside' => fn () => unlink("{$this->marker}.discard")]);

		$this->assertSame([], $issues, 'nothing known was discarded here');
		$this->assertSame(['pending.applied'], $this->left(), 'the applied record stays');
	}
}
