<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
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

	public static function refusedSidecars(): array
	{
		return ['IPv4' => ['v4'], 'IPv6 after IPv4' => ['v6']];
	}

	#[DataProvider('refusedSidecars')]
	public function testRefusedSidecarDoesNotPublishAMixedArtifactGeneration(string $refused): void
	{
		$orig = "{$this->dir}/orig";
		$action = "{$this->dir}/action";
		mkdir($orig, 0700);
		mkdir($action, 0700);
		$old = [
			'feed.bk' => "[\"d\",\"kept.example\"]\n",
			'feed_v4.ip' => "192.0.2.1\n",
			'feed_v6.ip' => "2001:db8::1\n",
		];
		foreach ($old as $name => $content) {
			file_put_contents("{$action}/{$name}", $content);
		}
		file_put_contents("{$orig}/feed.parsed.ndjson", "[\"d\",\"recovered.example\"]\n");
		file_put_contents("{$orig}/feed.parsed.v4.ip", "192.0.2.2\n");
		file_put_contents("{$orig}/feed.parsed.v6.ip", "2001:db8::2\n");
		$blocked = "feed_{$refused}.ip";
		unlink("{$action}/{$blocked}");
		mkdir("{$action}/{$blocked}");
		file_put_contents("{$action}/{$blocked}/guard", 'do not remove');
		$this->assertFalse(pfb_dnsbl_feed_phase_copy_artifacts(['disposition' => 'changed'], $orig, $action, 'feed'));
		$this->assertDirectoryExists("{$action}/{$blocked}");
		$this->assertSame('do not remove', file_get_contents("{$action}/{$blocked}/guard"));
		foreach (array_diff_key($old, [$blocked => TRUE]) as $name => $content) {
			$this->assertSame($content, file_get_contents("{$action}/{$name}"), "failed {$refused} publication must not advance {$name}");
		}
	}
}
