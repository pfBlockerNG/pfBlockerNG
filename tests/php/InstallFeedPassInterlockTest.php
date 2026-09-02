<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3062 -- a package install must not run on top of an in-flight feed pass.
 *
 * The install restages the Unbound chroot ('pfblockerng.sh dnsbl_cache stage'),
 * deletes caches, and stops/starts pfB services; a feed pass publishes into the
 * same chroot and wakes the ADR-10 reload watcher. Nothing serialised the two:
 * every feed-pass dispatcher takes the flock in "{dbdir}/pfb_feed_pass.lock"
 * (issue #1175) but pfblockerng_install.inc never did, so a scheduled pass and
 * an install could touch the same files and the same daemon at once.
 *
 * pfb_install_feed_pass_hold() closes that: it waits a bounded time for an
 * in-flight pass to finish, then holds the lock for the rest of the install
 * process so a tick firing mid-install defers with the usual skip line. The
 * wait is bounded because an install may never be abandoned -- on expiry it
 * logs and lets the install proceed.
 */
final class InstallFeedPassInterlockTest extends TestCase
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

		$this->dbdir = sys_get_temp_dir() . '/pfb_install_interlock_' . uniqid('', TRUE);
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

	/** TRUE when a second, independent fd cannot take the lock -- i.e. somebody holds it. */
	private function rawProbeStillLocked(): bool
	{
		$probe = fopen($this->lockPath(), 'c');
		$this->assertIsResource($probe, 'test setup: could not open the lock path for probing');
		$held = !flock($probe, LOCK_EX | LOCK_NB);
		if (!$held) {
			flock($probe, LOCK_UN);
		}
		fclose($probe);
		return $held;
	}

	private function logContents(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	/**
	 * Scenario: no feed pass is running when the install starts.
	 * Given a free feed-pass lock, When the install takes its hold,
	 * Then it succeeds and every other process is locked out for the rest of the install.
	 */
	public function testHoldTakesTheFeedPassLockWhenNoPassIsInFlight(): void
	{
		$this->assertFalse($this->rawProbeStillLocked(), 'test setup: the lock must start free');

		$this->assertTrue(pfb_install_feed_pass_hold(0.1), 'the install must take the free feed-pass lock');

		$this->assertTrue(is_resource($GLOBALS['pfb_feed_pass_lock'] ?? NULL),
			'the install must KEEP the lock (held for the remainder of the install process)');
		$this->assertTrue($this->rawProbeStillLocked(),
			'a feed pass starting mid-install must find the lock held and defer');
	}

	/**
	 * Scenario: a feed pass in another process is in flight, then finishes.
	 * Given a child process holding the lock, When the install asks for it,
	 * Then it is refused while the pass runs and takes the lock once the pass releases.
	 * Both halves are ordered by the child's own pipe, never by a sleep: the refusal is
	 * asserted while the child provably still holds, the acquisition only after EOF.
	 */
	public function testHoldIsRefusedWhileAnotherProcessHoldsAndSucceedsOnceItReleases(): void
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
		$proc = NULL;
		$pipes = [];
		try {
			$proc = proc_open([PHP_BINARY, '-r', $childCode, $this->lockPath()], $descriptors, $pipes);
			$this->assertTrue(is_resource($proc), 'test setup: failed to spawn the feed-pass holder');

			// 10s is a salvage cap for a stuck run, never the behaviour under test.
			$read = [$pipes[1]];
			$write = $except = NULL;
			$this->assertSame(1, stream_select($read, $write, $except, 10),
				'deadlock guard: the holder never signalled readiness within 10s');
			$this->assertSame("ready\n", fgets($pipes[1]), 'the holder did not report holding the lock');

			// The child cannot release before EOF, so this half is race-free.
			$this->assertFalse(pfb_install_feed_pass_hold(0.2),
				'the install must NOT take a lock another process is holding');

			fclose($pipes[0]);	// EOF -> the holder releases and exits
			$pipes[0] = NULL;

			$this->assertTrue(pfb_install_feed_pass_hold(10.0),
				'the install must take the lock once the in-flight pass releases it');
			$this->assertTrue(is_resource($GLOBALS['pfb_feed_pass_lock'] ?? NULL),
				'the install must hold the lock it waited for');
		} finally {
			if (is_resource($pipes[0] ?? NULL)) {
				fclose($pipes[0]);
			}
			if (is_resource($pipes[1] ?? NULL)) {
				fclose($pipes[1]);
			}
			if (is_resource($proc)) {
				$this->assertSame(0, proc_close($proc), 'the holder process must have exited cleanly');
			}
		}
	}

	/**
	 * Scenario: the in-flight pass outlasts the install's wait budget.
	 * Given another handle holding the lock for longer than the budget,
	 * When the install takes its hold,
	 * Then it spends the budget waiting, gives up rather than stalling the install
	 * forever, leaves the holder untouched, and records THAT it gave up -- the evidence
	 * a later post-install failure is traced with.
	 */
	public function testHoldSpendsItsBudgetThenLetsTheInstallProceed(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: failed to flock the holder fd');

		$started = microtime(TRUE);
		$held = pfb_install_feed_pass_hold(0.3);
		$elapsed = microtime(TRUE) - $started;

		$this->assertFalse($held, 'the install must not block forever on a pass that will not finish');
		// Floor, not a duration assertion: a hold that returned instantly never waited at
		// all, which is the regression (an ignored budget / a non-blocking acquire).
		$this->assertGreaterThanOrEqual(0.25, $elapsed,
			"the hold must spend its 0.3s budget waiting; it returned after {$elapsed}s");

		$this->assertFalse(isset($GLOBALS['pfb_feed_pass_lock']),
			'a failed hold must not leave a half-owned lock behind');
		$this->assertTrue($this->rawProbeStillLocked(),
			'the running feed pass must keep its own lock undisturbed');
		$this->assertStringContainsString('proceeding WITHOUT the feed-pass lock', $this->logContents(),
			'the give-up itself must be logged, not merely the decision to wait');
	}

	/**
	 * Every feed-pass dispatcher must keep deferring INSTANTLY -- the install's wait is the
	 * one exception. Pins the default: a contended acquire with no budget returns at once.
	 */
	public function testFeedPassAcquireStaysNonBlockingByDefault(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: failed to flock the holder fd');

		$started = microtime(TRUE);
		$acquired = pfb_feed_pass_acquire($contended);
		$elapsed = microtime(TRUE) - $started;

		$this->assertFalse($acquired, 'a contended acquire must fail');
		$this->assertTrue($contended, 'contention must be reported as contention, not as an error');
		$this->assertLessThan(0.05, $elapsed,
			"the default acquire must make ONE non-blocking attempt; it took {$elapsed}s");
	}

	/**
	 * Scenario: the hold runs in a process that already owns the lock.
	 * Given this process holds the feed-pass lock, When the install takes its hold,
	 * Then it reuses the existing hold instead of deadlocking against itself.
	 */
	public function testHoldIsReentrantWhenThisProcessAlreadyHoldsTheLock(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire(), 'test setup: failed to take the lock first');
		$outer = $GLOBALS['pfb_feed_pass_lock'];

		$this->assertTrue(pfb_install_feed_pass_hold(0.1), 'a reentrant hold must succeed');
		$this->assertSame($outer, $GLOBALS['pfb_feed_pass_lock'] ?? NULL,
			'a reentrant hold must reuse the existing handle, not replace it');
	}

	/**
	 * The interlock has to be WIRED, not merely available: pfblockerng_install.inc must
	 * take the hold before it touches anything a feed pass shares -- the pfB services and
	 * the 'dnsbl_cache stage' chroot restage.
	 *
	 * install.inc is a procedural migration script (host-absolute requires, sqlite, exec,
	 * real Unbound control) and is not loadable by the unit harness, so this pin scans
	 * executable tokens only; comments/docblocks cannot satisfy it.
	 */
	public function testInstallScriptTakesTheHoldBeforeTouchingSharedState(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
		$src = (string) @php_strip_whitespace($path);
		$this->assertNotSame('', $src, "could not read {$path}");

		$hold = strpos($src, 'pfb_install_feed_pass_hold(');
		$this->assertNotFalse($hold, 'install.inc never takes the feed-pass interlock (issue #3062)');

		foreach (['stop_service(', "dnsbl_cache stage"] as $shared) {
			$first = strpos($src, $shared);
			$this->assertNotFalse($first, "install.inc no longer contains [ {$shared} ]");
			$this->assertLessThan($first, $hold,
				"the interlock must be taken BEFORE install.inc reaches [ {$shared} ]");
		}
	}
}
