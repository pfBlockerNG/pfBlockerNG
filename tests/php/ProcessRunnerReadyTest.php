<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/** pfb_test_await_ready(), the wait for a started process (a stand-in) to say "ready": it drains both pipes while it waits. */
final class ProcessRunnerReadyTest extends TestCase
{
	/** WHEN a child fills its stderr pipe before it says ready THEN the wait returns once it says it, and the child runs to its end. */
	public function testAChildThatWritesMuchToStderrBeforeItIsReadyIsSeenReady(): void
	{
		$started = pfb_test_start_process([PHP_BINARY, '-r', 'fwrite(STDERR, str_repeat("x", 1 << 20)); echo "ready\n";']);

		pfb_test_await_ready($started, 5.0);

		$this->assertSame(0, pfb_test_finish_process($started, 5.0)['exit']);
	}

	/** WHEN a child exits before it is ready THEN the wait fails at once with all it wrote to stderr, the part read while waiting included. */
	public function testAChildThatExitsFirstFailsWithAllItsStderr(): void
	{
		$started = pfb_test_start_process([PHP_BINARY, '-r', 'fwrite(STDERR, "the start" . str_repeat("x", 1 << 17) . "the end"); exit(3);']);

		$this->expectExceptionMessageMatches('/exited \(3\) before it was ready: the startx+the end$/');
		pfb_test_await_ready($started, 5.0);
	}
}
