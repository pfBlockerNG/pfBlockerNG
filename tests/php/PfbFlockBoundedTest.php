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
 *   pfb_flock_bounded($fp, int $operation, float $timeout_s, ?bool &$timed_out = NULL): bool
 *   pfb_unbound_py_publication_lock_timeout(): float
 *
 * Contention tests use a REAL second process (pcntl_fork), not a single-process
 * simulation, mirroring the harness shape in PfbSyncStatusLedgerTest.php: a child
 * takes a real flock() on a temp file, signals readiness via a marker file (never
 * a guessed sleep), and holds the lock LONGER than the parent's injected budget.
 *
 * F4 review round (issue #1780): the helper originally collapsed "a genuine
 * flock() error" (would-block byref stays 0 -- not a contention signal at all)
 * and "the wait genuinely expired" into the same bare FALSE, so every caller lost
 * the ability to tell them apart (the pre-refactor code DID distinguish: see
 * pfb_unbound_py_publication_lock()'s "unavailable" vs "timed out" messages).
 * $timed_out is the restored signal: TRUE only when the deadline/poll-cap
 * genuinely elapsed; FALSE on every other return (a real flock() error, or
 * success). testBoundedAcquireRealErrorReturnsFalsePromptlyWithTimedOutFalse
 * proves the FALSE side with a real, portable flock() error (a php://memory
 * stream, whose stream wrapper never implements locking -- verified on both
 * Linux and macOS, unlike a FIFO, which is lockable on Linux) instead of a
 * contended wait.
 *
 * F7: the two contention tests below now also assert a LOWER bound on elapsed
 * time (previously upper-bound-only) -- a broken helper that returned FALSE
 * instantly, without ever attempting the lock, would have passed the old
 * assertions.
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
			if ($fp === FALSE || !flock($fp, LOCK_EX)) {
				exit(1);	// never signal readiness without a REAL hold -- the parent
					// would then run with no contention and a negative assertion
					// ("no dispatch", "entry survived") would pass for the wrong reason
			}
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
		$start     = microtime(TRUE);
		$timedOut  = FALSE;
		$ok        = pfb_flock_bounded($fp, LOCK_EX, 0.2, $timedOut);
		$elapsed   = microtime(TRUE) - $start;
		fclose($fp);

		pcntl_waitpid($pid, $waitStatus);

		$this->assertFalse($ok, 'a bounded LOCK_EX acquire against a real, still-held lock must return FALSE, not block');
		// F7: LOWER bound -- a helper that returned FALSE instantly, never actually
		// attempting/polling the lock, must not pass. 0.15s (budget 0.2s minus margin).
		$this->assertGreaterThanOrEqual(0.15, $elapsed,
			'bounded acquire must have actually waited ~its budget (0.2s), not returned instantly; elapsed=' . $elapsed);
		$this->assertLessThan(0.6, $elapsed,
			'bounded acquire must expire near its own budget (0.2s), not wait out the holder\'s 0.8s hold; elapsed=' . $elapsed);
		// F4: a genuine expiry must set the out-param TRUE.
		$this->assertTrue($timedOut, 'a genuine deadline expiry must set $timed_out = TRUE');
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
		$start    = microtime(TRUE);
		$timedOut = FALSE;
		$ok       = pfb_flock_bounded($fp, LOCK_SH, 0.2, $timedOut);
		$elapsed  = microtime(TRUE) - $start;
		fclose($fp);

		pcntl_waitpid($pid, $waitStatus);

		$this->assertFalse($ok, 'a bounded LOCK_SH acquire against a real EX holder must return FALSE, not block');
		// F7: LOWER bound -- see the EX test above for rationale.
		$this->assertGreaterThanOrEqual(0.15, $elapsed,
			'bounded SH acquire must have actually waited ~its budget (0.2s), not returned instantly; elapsed=' . $elapsed);
		$this->assertLessThan(0.6, $elapsed,
			'bounded SH acquire must expire near its own budget (0.2s), not wait out the holder\'s 0.8s hold; elapsed=' . $elapsed);
		// F4: a genuine expiry must set the out-param TRUE.
		$this->assertTrue($timedOut, 'a genuine deadline expiry must set $timed_out = TRUE');
	}

	// -----------------------------------------------------------------------
	// B. Uncontended success -- returns TRUE promptly, and the lock is REALLY
	// held (proven by a second independent handle failing a non-blocking probe).
	// -----------------------------------------------------------------------

	public function testBoundedAcquireSucceedsPromptlyAndActuallyHoldsTheLock(): void
	{
		$path = $this->dir . '/uncontended.lock';
		$fp   = fopen($path, 'c');

		$start    = microtime(TRUE);
		$timedOut = TRUE;	// deliberately wrong initial value -- success must flip it to FALSE
		$ok       = pfb_flock_bounded($fp, LOCK_EX, 5.0, $timedOut);
		$elapsed  = microtime(TRUE) - $start;

		$this->assertTrue($ok, 'an uncontended acquire must succeed');
		$this->assertLessThan(0.5, $elapsed,
			'an uncontended acquire must return promptly, not consume the full 5.0s budget; elapsed=' . $elapsed);
		// F4 discrimination: success must never report a timeout.
		$this->assertFalse($timedOut, 'an uncontended success must never set $timed_out = TRUE');

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
	// C. F4 — a genuine flock() ERROR (not contention) must be distinguishable
	// from a genuine timeout: $timed_out stays FALSE, and the call returns
	// immediately (it never entered the poll-wait loop at all).
	//
	// A php://memory stream is the portable way to force this deterministically:
	// its stream wrapper implements no locking at all, so flock() on it fails
	// immediately with the would-block byref left at 0 (verified on both Linux
	// and macOS) -- a REAL, non-contention error, unlike e.g. a FIFO, which is
	// lockable (and so merely contends, never errors) on Linux.
	// -----------------------------------------------------------------------

	public function testBoundedAcquireRealErrorReturnsFalsePromptlyWithTimedOutFalse(): void
	{
		$fp = fopen('php://memory', 'r+');

		// Pre-flight: confirm this environment's flock() really does treat
		// php://memory as a genuine error (would-block byref stays 0), not
		// would-block -- otherwise this test would silently prove nothing.
		$probeWouldBlock = 99;
		$probeOk = @flock($fp, LOCK_EX | LOCK_NB, $probeWouldBlock);
		if ($probeOk !== FALSE || $probeWouldBlock === 1) {
			$this->markTestSkipped('this PHP build\'s php://memory does not fail flock() as a real error -- cannot force the scenario this test needs.');
		}

		$start    = microtime(TRUE);
		$timedOut = TRUE;	// deliberately wrong initial value -- a real error must set it FALSE
		$ok       = pfb_flock_bounded($fp, LOCK_EX, 5.0, $timedOut);
		$elapsed  = microtime(TRUE) - $start;
		fclose($fp);

		$this->assertFalse($ok, 'a genuine flock() error must return FALSE');
		$this->assertFalse($timedOut,
			'a genuine flock() error (not a would-block/timeout) must leave $timed_out = FALSE -- '
			. 'collapsing it into TRUE is exactly the F4 defect (both consumer sites would then '
			. 'misreport a real error as "timed out")');
		$this->assertLessThan(0.5, $elapsed,
			'a genuine flock() error must be reported immediately, never after waiting out the '
			. "budget (5.0s) as if it were contention; elapsed={$elapsed}");
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

	// -----------------------------------------------------------------------
	// E. A budget that is not representable as an int must not silently UNBIND
	// the poll cap. $timeout_s is a public float parameter, so INF (or any float
	// whose /0.02 quotient overflows int) reaches the `(int) ceil(...)` poll-cap
	// computation; that cast raises "not representable as an int" and yields 0,
	// collapsing the cap from "one poll per 20ms of budget" to 2 attempts total.
	// The second of the two independent bounds then stops bounding anything.
	// -----------------------------------------------------------------------

	public function testNonRepresentableBudgetRaisesNoDiagnosticAndStillAcquires(): void
	{
		foreach (['INF' => INF, 'huge' => 1e300] as $label => $budget) {
			$path = tempnam(sys_get_temp_dir(), 'pfbflock');
			$fp   = fopen($path, 'c');

			$diagnostics = [];
			set_error_handler(function (int $no, string $str) use (&$diagnostics): bool {
				$diagnostics[] = "[{$no}] {$str}";
				return TRUE;
			});
			try {
				$acquired = pfb_flock_bounded($fp, LOCK_EX, $budget);
			} finally {
				restore_error_handler();
			}

			$this->assertSame(
				[],
				$diagnostics,
				"a {$label} budget must not raise a PHP diagnostic: the poll-cap cast warns and "
				. 'collapses the cap to 2 attempts, so the wait is no longer bounded by polls -- got '
				. implode('; ', $diagnostics)
			);
			$this->assertTrue($acquired, "an uncontended acquire must still succeed with a {$label} budget");

			flock($fp, LOCK_UN);
			fclose($fp);
			@unlink($path);
		}
	}
}
