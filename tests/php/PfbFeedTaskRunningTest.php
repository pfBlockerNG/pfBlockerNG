<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_feed_task_running')]
final class PfbFeedTaskRunningTest extends TestCase
{
	/** @return array<int, string> */
	private function psLine(string $verb): array
	{
		return ["  999  -  Ss    0:00.01 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php {$verb}"];
	}

	public function testDeprecatedScopedUpdateVerbsRemainVisibleToRunNowGuard(): void
	{
		$this->assertTrue(pfb_feed_task_running($this->psLine('updateip')));
		$this->assertTrue(pfb_feed_task_running($this->psLine('updatednsbl')));
	}

	public function testVerbBoundaryRejectsUnrelatedUpdatePrefix(): void
	{
		$this->assertFalse(pfb_feed_task_running($this->psLine('update-other')));
	}
}
