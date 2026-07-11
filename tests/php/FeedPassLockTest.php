<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1175 — cross-process, non-blocking feed-pass mutual exclusion.
 *
 * Functions under test: pfb_feed_pass_acquire(), pfb_feed_pass_release(),
 * pfb_feed_pass_busy() in pfblockerng.inc -- siblings of pfb_feed_task_running()
 * and pfb_update_pass_running() (ps-scan guards), but flock-based and exclusive
 * rather than advisory-by-process-list. Lock file: "{dbdir}/pfb_feed_pass.lock".
 *
 * flock(2) semantics this suite relies on: a lock belongs to the OPEN FILE
 * DESCRIPTION, not the process, so two separate fopen() handles on the SAME
 * path conflict even within one process -- that is what makes the same-process
 * contention tests below (Rows 1/2/5/6) valid without a second process. The
 * kernel releases the lock automatically when the holding process dies, so a
 * crashed feed pass can never wedge the system (Row 10b SIGKILLs a real
 * holder child and asserts the lock frees).
 *
 * Brand-new code (CLAUDE.md Test coverage #1 exception): pfb_feed_pass_* did
 * not exist before this change, so there is no pre-existing behaviour to pin
 * red-first -- these tests assert real behaviour against the finished
 * implementation directly.
 */
final class FeedPassLockTest extends TestCase
{
	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	/** Raw fds opened directly by a test (bypassing the helpers) -- closed in tearDown. */
	private array $rawFps = [];

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->dbdir = sys_get_temp_dir() . '/pfb_feedpass_lock_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'  => $this->dbdir,
			'log'    => "{$this->dbdir}/pfblockerng.log",
			'errlog' => "{$this->dbdir}/error.log",
		]);
	}

	protected function tearDown(): void
	{
		foreach ($this->rawFps as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		$this->rawFps = [];

		// Never leave this process holding the lock across tests (self-encapsulation).
		pfb_feed_pass_release();

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->rrmdir($this->dbdir);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = "{$dir}/{$entry}";
			is_dir($path) ? $this->rrmdir($path) : @unlink($path);
		}
		@rmdir($dir);
	}

	private function lockPath(): string
	{
		return "{$this->dbdir}/pfb_feed_pass.lock";
	}

	/** A second, independent fd probing the lock -- proves whether it is held. */
	private function rawProbeStillLocked(): bool
	{
		$fp = fopen($this->lockPath(), 'c');
		$this->assertNotFalse($fp, 'test probe: failed to open the lock file');
		$this->rawFps[] = $fp;
		$got = flock($fp, LOCK_EX | LOCK_NB);
		if ($got) {
			flock($fp, LOCK_UN);	// don't leave our own probe holding it
		}
		return !$got;
	}

	// -----------------------------------------------------------------------
	// Row 1 -- acquire on a free lock.
	// -----------------------------------------------------------------------

	public function testAcquireOnFreeLockSucceedsAndHoldsTheLock(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire(), 'acquire on a free lock must return TRUE');
		$this->assertTrue($this->rawProbeStillLocked(),
			'a second raw-fd flock(LOCK_EX|LOCK_NB) must fail while the helper holds the lock');
	}

	// -----------------------------------------------------------------------
	// Row 2 -- acquire while another handle holds it.
	// -----------------------------------------------------------------------

	public function testAcquireWhileAnotherHandleHoldsReturnsFalseAndHolderUndisturbed(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: failed to flock the holder fd');

		$this->assertFalse(pfb_feed_pass_acquire(), 'acquire must FALSE while another handle holds the lock');

		// Holder undisturbed: it can still explicitly re-affirm/extend its own lock.
		$this->assertTrue(flock($holder, LOCK_EX | LOCK_NB),
			'the original holder must remain able to operate on its own lock afterwards');
	}

	// -----------------------------------------------------------------------
	// Row 3 -- reentrant acquire.
	// -----------------------------------------------------------------------

	public function testReentrantAcquireReturnsTrueWithoutReopeningAndOneReleaseFrees(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire());
		$firstHandle = $GLOBALS['pfb_feed_pass_lock'];

		$this->assertTrue(pfb_feed_pass_acquire(), 'a second acquire in the same process must return TRUE');
		$this->assertSame($firstHandle, $GLOBALS['pfb_feed_pass_lock'],
			'a reentrant acquire must not open/replace the held handle');

		// Still held after two acquires.
		$this->assertTrue($this->rawProbeStillLocked(), 'the lock must still be held after the reentrant acquire');

		// ONE release fully frees it (no reference counting).
		pfb_feed_pass_release();
		$this->assertFalse($this->rawProbeStillLocked(), 'a single release must fully free a reentrantly-held lock');
	}

	// -----------------------------------------------------------------------
	// Row 4 -- release without holding; double release.
	// -----------------------------------------------------------------------

	public function testReleaseWithoutHoldingIsSilentNoOp(): void
	{
		pfb_feed_pass_release();	// must not throw/warn
		$this->assertFalse($this->rawProbeStillLocked(), 'releasing an unheld lock must leave it free');
	}

	public function testDoubleReleaseIsSafe(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire());
		pfb_feed_pass_release();
		pfb_feed_pass_release();	// second call must not throw/warn
		$this->assertFalse($this->rawProbeStillLocked(), 'the lock must stay free after a double release');
	}

	// -----------------------------------------------------------------------
	// Row 5 -- busy() with no holder.
	// -----------------------------------------------------------------------

	public function testBusyWithNoHolderReturnsFalseAndLeavesTheLockFree(): void
	{
		$this->assertFalse(pfb_feed_pass_busy(), 'busy() must be FALSE when nothing holds the lock');
		$this->assertFalse($this->rawProbeStillLocked(),
			'busy()\'s momentary probe must release before returning -- a subsequent raw flock must succeed');
	}

	// -----------------------------------------------------------------------
	// Row 6 -- busy() while another handle holds it.
	// -----------------------------------------------------------------------

	public function testBusyWhileAnotherHandleHoldsReturnsTrue(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX));

		$this->assertTrue(pfb_feed_pass_busy(), 'busy() must be TRUE while another handle holds the lock');
	}

	// -----------------------------------------------------------------------
	// Row 7 -- busy() while THIS process holds it via the helper.
	// -----------------------------------------------------------------------

	public function testBusyWhileThisProcessHoldsViaHelperReturnsFalse(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire());
		$this->assertFalse(pfb_feed_pass_busy(), 'this process\'s own hold must not read as "busy" to itself');
	}

	// -----------------------------------------------------------------------
	// Row 8 -- fail-open on an unwritable dbdir.
	// -----------------------------------------------------------------------

	public function testFailOpenOnUnwritableDbdirAcquireTrueWarnsBusyFalse(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions; cannot simulate an unwritable dbdir');
		}

		$denydir = "{$this->dbdir}/deny";
		mkdir($denydir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $denydir;
		chmod($denydir, 0555);

		try {
			$this->assertTrue(pfb_feed_pass_acquire(),
				'an unwritable dbdir must fail OPEN -- acquire returns TRUE rather than blocking legitimate work');
			$this->assertFileExists($GLOBALS['pfb']['errlog'], 'the fail-open path must log a warning');
			$this->assertStringContainsString('lock', strtolower((string) file_get_contents($GLOBALS['pfb']['errlog'])),
				'the warning must reference the lock failure');

			$this->assertFalse(pfb_feed_pass_busy(),
				'busy() must also fail OPEN (FALSE, never reports busy) on an unwritable dbdir');
		} finally {
			chmod($denydir, 0755);
		}
	}

	// -----------------------------------------------------------------------
	// Row 9 -- pre-existing garbage content in the lock file.
	// -----------------------------------------------------------------------

	public function testGarbageLockFileContentDoesNotAffectBehaviour(): void
	{
		file_put_contents($this->lockPath(), "not json {{{ garbage \x00 bytes");

		$this->assertTrue(pfb_feed_pass_acquire(), 'flock ignores file content -- acquire must still succeed');
		$this->assertSame(
			"not json {{{ garbage \x00 bytes",
			file_get_contents($this->lockPath()),
			"fopen('c') must not truncate -- content is unchanged"
		);
		pfb_feed_pass_release();
		$this->assertFalse(pfb_feed_pass_busy(), 'busy() must behave identically regardless of file content');
	}

	// -----------------------------------------------------------------------
	// Row 10 -- cross-process contention via a real child process.
	// -----------------------------------------------------------------------

	/**
	 * Spawns a real child PHP process that flocks the SAME lock path, signals
	 * readiness over its stdout pipe (no fixed sleeps -- the parent blocks on
	 * fgets() until the child writes "ready\n"), then waits on its stdin for
	 * EOF before releasing and exiting. The parent probes acquire()/busy()
	 * while the child holds the lock, then closes the child's stdin to let it
	 * exit cleanly.
	 */
	public function testCrossProcessChildHoldingLockBlocksParentAcquireAndReportsBusy(): void
	{
		$childCode = <<<'PHP'
			$fp = fopen($argv[1], 'c');
			if ($fp === false) { fwrite(STDOUT, "openfail\n"); exit(1); }
			if (!flock($fp, LOCK_EX)) { fwrite(STDOUT, "lockfail\n"); exit(1); }
			fwrite(STDOUT, "ready\n");
			fflush(STDOUT);
			fgets(STDIN);	// blocks until the parent closes our stdin (EOF)
			flock($fp, LOCK_UN);
			fclose($fp);
			exit(0);
			PHP;

		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']];
		$proc = proc_open([PHP_BINARY, '-r', $childCode, $this->lockPath()], $descriptors, $pipes);
		$this->assertTrue(is_resource($proc), 'test setup: failed to spawn the child process');

		try {
			// Deadlock guard: the child must announce readiness within 10s -- fail loudly,
			// never hang. stream_select, NOT stream_set_timeout: the latter is a no-op on
			// proc_open pipes (returns FALSE; fgets blocks past it, timed_out stays FALSE).
			$read = [$pipes[1]];
			$write = $except = NULL;
			$this->assertSame(1, stream_select($read, $write, $except, 10),
				'deadlock guard: child never signalled readiness within 10s');
			$line = fgets($pipes[1]);
			$this->assertSame("ready\n", $line, 'child did not report holding the lock');

			$this->assertFalse(pfb_feed_pass_acquire(),
				'the parent process must NOT acquire while the CHILD process holds the lock');
			$this->assertTrue(pfb_feed_pass_busy(),
				'busy() must report TRUE while a real child process holds the lock');
		} finally {
			fclose($pipes[0]);	// EOF -> the child's fgets(STDIN) unblocks and it exits
			fclose($pipes[1]);
			$exitCode = proc_close($proc);
			$this->assertSame(0, $exitCode, 'the child process must have exited cleanly');
		}
	}

	// -----------------------------------------------------------------------
	// issue #1175 STEP 2 -- pfb_feed_pass_begin(), the acquire-or-log-skip
	// choke point both sync funnels (sync_package_pfblockerng(),
	// pfblockerng_sync_cron()) call. Brand-new code (CLAUDE.md Test coverage
	// #1 exception): asserts real behaviour directly, no red-first proof.
	// -----------------------------------------------------------------------

	// Coverage-matrix row 10 -- begin() on a free lock.
	public function testBeginOnFreeLockReturnsTrueAndHoldsTheLock(): void
	{
		$this->assertTrue(pfb_feed_pass_begin('sync'), 'begin() on a free lock must return TRUE');
		$this->assertTrue($this->rawProbeStillLocked(),
			'a second raw-fd flock(LOCK_EX|LOCK_NB) must fail while begin() holds the lock');
	}

	// Coverage-matrix row 11 -- begin() while another handle holds it: FALSE + a
	// logged skip line (failable -- asserts actual log content, not just the return).
	public function testBeginWhileAnotherHandleHoldsReturnsFalseAndLogsSkip(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: failed to flock the holder fd');

		$this->assertFalse(pfb_feed_pass_begin('sync'), 'begin() must FALSE while another handle holds the lock');

		$this->assertFileExists($GLOBALS['pfb']['log'], 'a skip must write to the main pfBlockerNG log');
		$this->assertStringContainsString(
			'skipped',
			(string) file_get_contents($GLOBALS['pfb']['log']),
			'the skip line must record that the pass was skipped'
		);

		// Holder undisturbed: the skip never touches the lock the other side owns.
		$this->assertTrue(flock($holder, LOCK_EX | LOCK_NB),
			'the original holder must remain able to operate on its own lock afterwards');
	}

	// Coverage-matrix row 12 -- ownership discipline: mirrors the exact pattern the
	// two funnels use ($owner = !isset($GLOBALS['pfb_feed_pass_lock']); begin(); ...;
	// if ($owner) release();). A nested (reentrant) call's owner flag is FALSE, so its
	// guarded release must NOT free the lock; only the outer, transitioning call's does.
	public function testNestedBeginOwnershipOnlyTheTransitioningCallReleases(): void
	{
		$outerOwner = !isset($GLOBALS['pfb_feed_pass_lock']);
		$this->assertTrue($outerOwner, 'test setup: process must not already hold the lock');
		$this->assertTrue(pfb_feed_pass_begin('sync'), 'outer begin() must acquire the free lock');

		// Simulates sync_package_pfblockerng() being reentered from inside
		// pfblockerng_sync_cron() -- the inner call observes the lock already held.
		$innerOwner = !isset($GLOBALS['pfb_feed_pass_lock']);
		$this->assertFalse($innerOwner, 'inner call must observe the lock already held by this process');
		$this->assertTrue(pfb_feed_pass_begin('cron'), 'reentrant inner begin() must no-op TRUE');

		if ($innerOwner) {
			pfb_feed_pass_release();
		}
		$this->assertTrue($this->rawProbeStillLocked(),
			'the inner guarded release (owner flag FALSE) must NOT free the lock');

		if ($outerOwner) {
			pfb_feed_pass_release();
		}
		$this->assertFalse($this->rawProbeStillLocked(),
			'the outer guarded release (owner flag TRUE) must free the lock');
	}

	// Hostile row -- lock file unopenable: begin() inherits acquire()'s fail-open
	// (an unwritable dbdir must never block a legitimate pass).
	public function testBeginFailsOpenWhenLockFileUnopenable(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions; cannot simulate an unwritable dbdir');
		}

		$denydir = "{$this->dbdir}/deny_begin";
		mkdir($denydir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $denydir;
		chmod($denydir, 0555);

		try {
			$this->assertTrue(pfb_feed_pass_begin('sync'),
				'an unwritable dbdir must fail OPEN -- begin() returns TRUE rather than blocking legitimate work');
		} finally {
			chmod($denydir, 0755);
		}
	}

	// -----------------------------------------------------------------------
	// Row 10b -- crash release: SIGKILL the holder, the kernel frees the lock.
	// -----------------------------------------------------------------------

	/**
	 * A feed pass that dies without releasing (crash, OOM-kill) must never
	 * wedge the box: the kernel drops a flock with its last open descriptor.
	 * Spawns the same holder child, SIGKILLs it mid-hold, and asserts the
	 * lock becomes acquirable again (bounded poll that fails loudly -- a
	 * deadlock guard, never a fixed wait).
	 */
	public function testCrossProcessLockReleasedWhenHolderKilled(): void
	{
		$childCode = <<<'PHP'
			$fp = fopen($argv[1], 'c');
			if ($fp === false) { fwrite(STDOUT, "openfail\n"); exit(1); }
			if (!flock($fp, LOCK_EX)) { fwrite(STDOUT, "lockfail\n"); exit(1); }
			fwrite(STDOUT, "ready\n");
			fflush(STDOUT);
			fgets(STDIN);	// never EOF'd in this test -- the parent kills us instead
			PHP;

		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']];
		$proc = proc_open([PHP_BINARY, '-r', $childCode, $this->lockPath()], $descriptors, $pipes);
		$this->assertTrue(is_resource($proc), 'test setup: failed to spawn the child process');

		$read = [$pipes[1]];
		$write = $except = NULL;
		$this->assertSame(1, stream_select($read, $write, $except, 10),
			'deadlock guard: child never signalled readiness within 10s');
		$this->assertSame("ready\n", fgets($pipes[1]), 'child did not report holding the lock');
		$this->assertTrue($this->rawProbeStillLocked(), 'child must genuinely hold the lock before the kill');

		proc_terminate($proc, 9);	// SIGKILL: no cleanup path runs in the child

		// Kernel releases the flock with the process; poll acquire under a 10s
		// deadline that fails loudly (deadlock guard, not a fixed wait).
		$deadline = microtime(TRUE) + 10.0;
		$freed = FALSE;
		while (microtime(TRUE) < $deadline) {
			if (pfb_feed_pass_acquire()) {
				$freed = TRUE;
				break;
			}
			usleep(50000);
		}
		fclose($pipes[0]);
		fclose($pipes[1]);
		proc_close($proc);
		$this->assertTrue($freed, 'the lock must be released by the kernel when the holder is SIGKILLed');
	}
}
