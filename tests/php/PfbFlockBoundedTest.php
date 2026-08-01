<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1780 — the shared bounded flock() acquire helper.
 *
 * The owner's premise ("an update pass cannot hang forever, since every wait is
 * capped") was refuted for five blocking flock() acquires with no bound. This
 * suite pins the shared helper those five call sites were rewritten to use:
 *
 *   pfb_flock_bounded($fp, int $operation, float $timeout_s): bool
 *   pfb_unbound_py_publication_lock_timeout(): float
 *
 * Contention tests use a REAL second process (pcntl_fork), not a single-process
 * simulation, mirroring the harness shape in PfbSyncStatusLedgerTest.php: a child
 * takes a real flock() on a temp file, signals readiness via a marker file (never
 * a guessed sleep), and holds the lock LONGER than the parent's injected budget.
 */
#[CoversFunction('pfb_flock_bounded')]
#[CoversFunction('pfb_unbound_py_publication_lock_timeout')]
final class PfbFlockBoundedTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_flock_bounded_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	/**
	 * Fork a child that opens $lockPath fresh (never an inherited fd -- a genuine
	 * second, independent lock holder), takes LOCK_EX, signals readiness via a
	 * marker file, holds for $holdMicros, then releases.
	 *
	 * @return int the child pid (caller must pcntl_waitpid it).
	 */
	private function forkRealLockHolder(string $lockPath, string $markerPath, int $holdMicros): int
	{
		$pid = pcntl_fork();
		if ($pid === -1) {
			$this->markTestSkipped('pcntl_fork() failed.');
		}
		if ($pid === 0) {
			$fp = fopen($lockPath, 'c');
			flock($fp, LOCK_EX);
			touch($markerPath);
			usleep($holdMicros);
			flock($fp, LOCK_UN);
			fclose($fp);
			exit(0);
		}
		return $pid;
	}

	private function waitForMarker(string $markerPath, int $pid): void
	{
		$deadline = microtime(TRUE) + 2.0;
		while (!file_exists($markerPath)) {
			if (microtime(TRUE) >= $deadline) {
				pcntl_waitpid($pid, $waitStatus);
				$this->fail('child process never signalled lock acquisition (marker file never appeared) -- deadlock or fork failure?');
			}
			usleep(1000);
		}
	}

	// -----------------------------------------------------------------------
	// A. Real contention -- the bounded acquire returns FALSE at ~budget, not
	// at the holder's release, for BOTH LOCK_EX and LOCK_SH.
	// -----------------------------------------------------------------------

	public function testBoundedExAcquireExpiresAtBudgetNotAtRealHolderRelease(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl not available -- cannot spawn a real concurrent process for this test.');
		}

		$lockPath   = $this->dir . '/ex_contended.lock';
		$markerPath = $this->dir . '/ex_contended.marker';
		// Holder keeps the lock for 800ms -- well past the 200ms budget under test.
		$pid = $this->forkRealLockHolder($lockPath, $markerPath, 800000);
		$this->waitForMarker($markerPath, $pid);

		$fp = fopen($lockPath, 'c');	// fresh handle -- genuine second contender
		$start   = microtime(TRUE);
		$ok      = pfb_flock_bounded($fp, LOCK_EX, 0.2);
		$elapsed = microtime(TRUE) - $start;
		fclose($fp);

		pcntl_waitpid($pid, $waitStatus);

		$this->assertFalse($ok, 'a bounded LOCK_EX acquire against a real, still-held lock must return FALSE, not block');
		$this->assertLessThan(0.6, $elapsed,
			'bounded acquire must expire near its own budget (0.2s), not wait out the holder\'s 0.8s hold; elapsed=' . $elapsed);
	}

	public function testBoundedShAcquireExpiresAtBudgetNotAtRealHolderRelease(): void
	{
		if (!function_exists('pcntl_fork')) {
			$this->markTestSkipped('pcntl not available -- cannot spawn a real concurrent process for this test.');
		}

		$lockPath   = $this->dir . '/sh_contended.lock';
		$markerPath = $this->dir . '/sh_contended.marker';
		// An EX holder blocks a SH waiter too -- reuse the same holder shape.
		$pid = $this->forkRealLockHolder($lockPath, $markerPath, 800000);
		$this->waitForMarker($markerPath, $pid);

		$fp = fopen($lockPath, 'c');
		$start   = microtime(TRUE);
		$ok      = pfb_flock_bounded($fp, LOCK_SH, 0.2);
		$elapsed = microtime(TRUE) - $start;
		fclose($fp);

		pcntl_waitpid($pid, $waitStatus);

		$this->assertFalse($ok, 'a bounded LOCK_SH acquire against a real EX holder must return FALSE, not block');
		$this->assertLessThan(0.6, $elapsed,
			'bounded SH acquire must expire near its own budget (0.2s), not wait out the holder\'s 0.8s hold; elapsed=' . $elapsed);
	}

	// -----------------------------------------------------------------------
	// B. Uncontended success -- returns TRUE promptly, and the lock is REALLY
	// held (proven by a second independent handle failing a non-blocking probe).
	// -----------------------------------------------------------------------

	public function testBoundedAcquireSucceedsPromptlyAndActuallyHoldsTheLock(): void
	{
		$path = $this->dir . '/uncontended.lock';
		$fp   = fopen($path, 'c');

		$start   = microtime(TRUE);
		$ok      = pfb_flock_bounded($fp, LOCK_EX, 5.0);
		$elapsed = microtime(TRUE) - $start;

		$this->assertTrue($ok, 'an uncontended acquire must succeed');
		$this->assertLessThan(0.5, $elapsed,
			'an uncontended acquire must return promptly, not consume the full 5.0s budget; elapsed=' . $elapsed);

		// Prove the lock is REALLY held: an independent second handle on the
		// SAME file must fail a non-blocking probe while $fp still holds it.
		$probe = fopen($path, 'c');
		$wouldBlock = 0;
		$probeOk = @flock($probe, LOCK_EX | LOCK_NB, $wouldBlock);
		$this->assertFalse($probeOk, 'a second independent handle must be unable to acquire while the first still holds the lock');
		$this->assertSame(1, $wouldBlock, 'the second handle\'s failure must be a real contention (would-block), not some other flock() error');

		flock($fp, LOCK_UN);
		fclose($fp);
		fclose($probe);
	}

	// -----------------------------------------------------------------------
	// D. Publication-lock NULL default resolves to a finite, positive budget.
	// (Never actually waits 60s -- only the accessor's return value is checked.)
	// -----------------------------------------------------------------------

	public function testPublicationLockDefaultTimeoutIsFiniteAndPositive(): void
	{
		$timeout = pfb_unbound_py_publication_lock_timeout();

		$this->assertIsFloat($timeout);
		$this->assertTrue(is_finite($timeout), 'the default publication-lock timeout must be finite -- got ' . var_export($timeout, TRUE));
		$this->assertGreaterThan(0.0, $timeout, 'the default publication-lock timeout must be strictly positive -- got ' . $timeout);
	}
}
