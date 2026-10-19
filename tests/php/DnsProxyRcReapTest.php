<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- a stuck rc() reaps everything it started. The script under test starts a background child, records its pid and
 * hangs. Once rc() has reported STUCK/ENVIRONMENT, that child must be gone: the runner terminates only its direct child, so the
 * timeout(1) wrapper around rc() is what signals the whole process group and takes the background child down with it.
 */
final class DnsProxyRcReapTest extends TestCase
{
	use DnsProxyRcSandboxTrait;

	protected function setUp(): void
	{
		$this->sandboxUp();
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	public function testAStuckRcLeavesNoBackgroundChildBehind(): void
	{
		// Given a script that starts a background child, records its pid, and hangs until something kills it
		$pidFile = "{$this->dir}/grandchild.pid";
		file_put_contents("{$this->dir}/run.sh", "#!/bin/sh\n/bin/sleep 61 &\necho \$! > " . escapeshellarg($pidFile) . "\nwait\n");

		// When rc() runs past its 3 s limit
		$verdict = '';
		try {
			$this->rc('start', 3);
			$this->fail('a stuck rc must not return a status');
		} catch (RuntimeException $e) {
			$verdict = $e->getMessage();
		}
		$grandchild = (int) trim((string) @file_get_contents($pidFile));

		try {
			// Then the verdict is an environment one, and the background child is gone
			$this->assertStringStartsWith('STUCK/ENVIRONMENT:', $verdict, 'a stuck rc is an environment verdict, not a product result');
			$this->assertGreaterThan(0, $grandchild, 'the script recorded its background child before the limit');
			$this->waitUntilGone($grandchild);
		} finally {
			// Even on failure, nothing this test started is left running
			if ($grandchild > 0 && !self::gone($grandchild)) {
				posix_kill($grandchild, SIGKILL);
			}
		}
	}

	/**
	 * Waits, on the process table, until $pid is gone. A process that is still alive past the watchdog is a survivor of the
	 * reap, which fails the test with its state; the watchdog only bounds the poll.
	 */
	private function waitUntilGone(int $pid): void
	{
		$deadline = hrtime(TRUE) + 10 * 1000000000;
		while (!self::gone($pid) && hrtime(TRUE) < $deadline) {
			usleep(20000);
		}
		$this->assertSame(TRUE, self::gone($pid), "background child {$pid} outlived the stuck rc: state " . self::stateOf($pid));
	}

	/** The process's state letter from /proc, or 'absent' once there is no entry for it. */
	private static function stateOf(int $pid): string
	{
		$stat = @file_get_contents("/proc/{$pid}/stat");
		if ($stat === FALSE) {
			return 'absent';
		}
		// The state follows the last ')' of "pid (comm) state ...", and comm may itself contain ')'
		return trim(substr($stat, (int) strrpos($stat, ')') + 2, 1));
	}

	/** Gone: no entry, or a zombie. A zombie has exited; only its parent's reap is left, and it runs nothing. */
	private static function gone(int $pid): bool
	{
		return in_array(self::stateOf($pid), ['absent', 'Z', 'X'], TRUE);
	}
}
