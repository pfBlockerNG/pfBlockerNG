<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #2591: the exit status of a feed pass keeps completion, failure and lock deferral apart. The pass runs as Core's Update
 * program (the core_update verb), whose status Core reports as the Update's result; since #4260 the CLI update verbs start that
 * Update through Core (CliUpdateVerbsTest) and run no pass of their own.
 */
final class FeedPassCliExitStatusTest extends TestCase
{
	public static function exitCodeProvider(): array
	{
		return [
			'completed pass' => [TRUE, NULL, 0],
			'real failure' => [FALSE, NULL, 1],
			'benign bool with dispatcher deferral' => [TRUE, 'dispatcher-lock', 75],
			'failure bool with feed-pass deferral' => [FALSE, 'feed-pass-lock', 75],
		];
	}

	#[DataProvider('exitCodeProvider')]
	public function testExitCodeKeepsCompletionFailureAndDeferralDistinct(
		bool $completed,
		?string $deferredBy,
		int $expected
	): void {
		$this->assertSame($expected, pfb_feed_pass_exit_code($completed, $deferredBy));
	}

	public function testLockedExitCodeIsExTempfail(): void
	{
		$this->assertSame(75, PFB_EXIT_LOCKED);
	}
}
