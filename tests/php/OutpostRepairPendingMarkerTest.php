<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4263 (owner, 2026-11-23): the version 2 apply discards a pending marker's token it does not take and files the issue.
 * The marker is rewritten with a fresh mark (pfb_mark_pending_changes()), not removed: what was pending stays pending until an
 * apply settles the new mark, and a save writing meanwhile writes a valid mark too, so none is lost. Any other mark stays.
 */
#[CoversFunction('pfb_outpost_repair_pending_marker')]
final class OutpostRepairPendingMarkerTest extends TestCase
{
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

	public function testABadTokenIsReplacedByAFreshMarkAndReported(): void
	{
		file_put_contents($this->marker, "bad token\n");
		file_put_contents("{$this->marker}.applied", 'older');

		$issues = pfb_outpost_repair_pending_marker();

		$this->assertSame([['resource' => 'pending-marker', 'stage' => 'apply', 'code' => 'pending_token_invalid',
			'message' => 'the pending-changes marker held a token that is not 1 to 64 printable ASCII characters; it was replaced by a new mark']],
			$issues);
		$this->assertTrue(pfb_pending_token_valid((string) file_get_contents($this->marker)), 'the marker holds a token the apply takes');
		$this->assertTrue(pfb_pending_changes(), 'what was pending stays pending');
	}

	public function testAValidOrEmptyMarkIsLeftAlone(): void
	{
		foreach (['0123456789abcdef', ''] as $mark) {
			file_put_contents($this->marker, $mark);
			$this->assertSame([], pfb_outpost_repair_pending_marker(), json_encode($mark));
			$this->assertSame($mark, file_get_contents($this->marker));
		}
	}

	public function testWithoutAMarkerNothingIsWritten(): void
	{
		$this->assertSame([], pfb_outpost_repair_pending_marker());
		$this->assertFileDoesNotExist($this->marker);
	}
}
