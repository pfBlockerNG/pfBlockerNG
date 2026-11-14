<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_core_feed_artifact_copy')]
final class FeedPhaseArtifactTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_feed_phase_artifact_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	public function testPublishesTheCompleteArtifactAndConfiguredPlaceholder(): void
	{
		$source = $this->dir . '/feed.parsed.ip';
		$target = $this->dir . '/action/feed.txt';
		mkdir(dirname($target), 0700, TRUE);
		file_put_contents($source, "203.0.113.1\n");
		file_put_contents($target, "old\n");

		$this->assertTrue(pfb_core_feed_artifact_copy($source, $target, "::1\n"));
		$this->assertSame("203.0.113.1\n::1\n", file_get_contents($target));
	}

	public function testMissingArtifactLeavesLastKnownGoodOutputUntouched(): void
	{
		$target = $this->dir . '/action/feed.txt';
		mkdir(dirname($target), 0700, TRUE);
		file_put_contents($target, "last-known-good\n");

		$this->assertFalse(pfb_core_feed_artifact_copy($this->dir . '/missing.parsed.ip', $target));
		$this->assertSame("last-known-good\n", file_get_contents($target));
	}
}
