<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4257 (owner, 2026-11-26, decision 3 on #3977): the widget's "Clear Failed Downloads" resets the Core Updater's
 * per-feed retry count through Core's ResetFeedFailures, beside what it clears today. Core not answering, or answering with an
 * error, never stops the rest of the clear: the helper says why, for the log.
 */
#[CoversFunction('pfb_reset_feed_failures')]
final class ResetFeedFailuresTest extends TestCase
{
	public function testItAsksCoreToResetEveryFeedWithARequestId(): void
	{
		$calls = [];
		$call = static function (string $method, array $params, ?string $socket, int $timeout) use (&$calls): array {
			$calls[] = [$method, array_keys($params), $socket];
			return ['status' => 200, 'body' => [], 'error' => NULL];
		};

		$this->assertNull(pfb_reset_feed_failures($call));
		$this->assertSame([['ResetFeedFailures', ['requestId'], NULL]], $calls, 'every feed: no feeds parameter');
	}

	public function testCoreNotAnsweringOrRefusingIsReportedNotThrown(): void
	{
		$down = static fn (): array => ['status' => 0, 'body' => NULL, 'error' => 'the Core API did not answer: no socket'];
		$this->assertSame('the Core API did not answer: no socket', pfb_reset_feed_failures($down));

		$busy = static fn (): array => ['status' => 409, 'body' => ['error' => ['code' => 'conflict',
			'message' => 'an Update is running; nothing was reset']], 'error' => NULL];
		$this->assertSame('conflict: an Update is running; nothing was reset', pfb_reset_feed_failures($busy));
	}
}
