<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 — Pure sync-status ledger library.
 *
 * Tests the clock-injectable pfb_sync_status_* helpers defined in
 * pfblockerng_extra.inc, mirroring DueLedgerTest's shape.
 *
 * Functions under test:
 *   pfb_sync_status_open(string $facility, string $item, string $stage,
 *                          string $message, string $ledger_dir, ?callable $clock_fn = null,
 *                          float $timeout_s = 5.0): void
 *   pfb_sync_status_close(string $facility, string $item, string $stage, string $ledger_dir,
 *                          float $timeout_s = 5.0): void
 *   pfb_sync_status_list_open(string $ledger_dir, ?string $facility = null): array
 *   pfb_sync_status_read_all(string $ledger_dir, float $timeout_s = 5.0, ?bool &$unavailable = NULL): array
 *   pfb_sync_status_locked(string $ledger_dir, callable $fn, float $timeout_s = 5.0): void
 *
 * Coverage mandate (CLAUDE.md "Test coverage") — every branch:
 *   open:  new key creates an entry; an already-open key refreshes message/
 *          last_seen and preserves first_seen (no duplicate); clock is injectable;
 *          an invalid-UTF8 message must not wipe the rest of the ledger.
 *   close: existing key removed; absent key is a safe no-op (no write, no throw).
 *   list_open: filters by facility; NULL facility returns every facility.
 *   read:  absent file, corrupt (non-JSON) file, and corrupt (non-object JSON)
 *          file all read as an empty ledger — never throw.
 *   write: an unwritable ledger dir fails silently (no uncaught exception) —
 *          this suite's chosen contract; see testUnwritableLedgerDirFailsSafely().
 *   locked: the read-modify-write span is held under a real cross-process
 *          exclusive lock (proven against an actual second process, not a
 *          single-process simulation) — closes the TOCTOU window between a
 *          read and its paired write that would otherwise let two concurrent
 *          writers silently discard one another's update. issue #1780: the
 *          acquire is now BOUNDED -- a real, still-held lock past the budget
 *          logs an observable timeout and still runs $fn() (fail-open), and
 *          that signal discriminates (never fires on an uncontended success).
 *
 * issue #1780 F1/F2/F9 (review round) — unlike pfb_sync_status_locked() above
 * (whose EX acquire on pfb_sync_status.json.lock keeps its EXISTING fail-open
 * contract: still runs $fn() after a timeout), read_all()'s OWN SH acquire on
 * the DATA file (pfb_sync_status.json) itself is a SEPARATE lock. A bounded
 * expiry there returns [] — a value that already means "empty ledger" to every
 * caller — so open()/close() (both read-modify-write through read_all() inside
 * the _locked() span) must fail closed on it: ABORT, never write back an
 * (apparently empty, actually just-unreadable) ledger over intact data. The
 * signal is the read_all() out-param $unavailable — never conflated with []'s
 * existing "empty" meaning. $timeout_s is injectable end-to-end (open/close
 * gained an optional trailing param alongside read_all itself) so the expiry
 * branch is driven deterministically with a REAL second process (pcntl_fork).
 */
#[CoversFunction('pfb_sync_status_open')]
#[CoversFunction('pfb_sync_status_close')]
#[CoversFunction('pfb_sync_status_list_open')]
#[CoversFunction('pfb_sync_status_read_all')]
#[CoversFunction('pfb_sync_status_write_all')]
#[CoversFunction('pfb_sync_status_locked')]
#[CoversFunction('pfb_sync_status_close_removed_alias')]
final class PfbSyncStatusLedgerTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		// Restore a writable mode in case testUnwritableLedgerDirFailsSafely ran
		// (chmod 0555), so the recursive cleanup below can actually delete it.
		@chmod($this->dir, 0777);
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private static function clockAt(int $ts): callable
	{
		return static fn (): int => $ts;
	}

	private function readEvent(mixed $stream, string $awaited, bool $child = FALSE, mixed $report = NULL): string
	{
		$line = @fgets($stream);
		if ($line !== FALSE) {
			if (str_starts_with($line, 'SALVAGE_EXPIRED ')) {
				$this->fail(trim(substr($line, strlen('SALVAGE_EXPIRED '))));
			}
			return $line;
		}
		$meta = stream_get_meta_data($stream);
		$reason = ($meta['timed_out'] ?? FALSE) ? 'timeout' : (feof($stream) ? 'EOF' : 'read failure');
		$message = "salvage cap expired / stuck or environment: awaiting {$awaited}";
		if ($child) {
			$destination = is_resource($report) ? $report : $stream;
			@fwrite($destination, "SALVAGE_EXPIRED {$message} ({$reason})\n");
			exit(2);
		}
		$this->fail("{$message} ({$reason})");
	}

	private function expectChildEvent(mixed $stream, string $expected, string $awaited, mixed $report = NULL): void
	{
		$event = trim($this->readEvent($stream, $awaited, TRUE, $report));
		if ($event !== $expected) {
			$destination = is_resource($report) ? $report : $stream;
			@fwrite($destination, "EVENT_ERROR awaiting {$awaited}; expected {$expected}; got {$event}\n");
			exit(2);
		}
	}

	/** @return array{0:mixed,1:mixed} */
	private function signalPair(): array
	{
		$pair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
		if ($pair === FALSE) {
			$this->markTestSkipped('stream_socket_pair() failed -- cannot signal across the fork.');
		}
		return $pair;
	}

	/** @return array{0:int,1:mixed} */
	private function forkRealDataFileHolder(string $lockPath): array
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl_fork() and posix_kill() required for fork cleanup.');
		}
		[$parent, $child] = $this->signalPair();
		stream_set_timeout($parent, 5);
		stream_set_timeout($child, 5);
		$pid = pcntl_fork();
		if ($pid === -1) {
			$this->markTestSkipped('pcntl_fork() failed.');
		}
		if ($pid === 0) {
			fclose($parent);
			$fp = @fopen($lockPath, 'c');
			if ($fp === FALSE || !@flock($fp, LOCK_EX)) {
				@fwrite($child, "HOLDER_ERROR\n");
				exit(1);
			}
			fwrite($child, "LOCKED\n");
			$this->expectChildEvent($child, 'RELEASE', 'data-file holder release');
			@flock($fp, LOCK_UN);
			fclose($fp);
			fwrite($child, "UNLOCKED\n");
			fclose($child);
			exit(0);
		}
		fclose($child);
		return [$pid, $parent];
	}

	private function releaseDataFileHolder(?int &$pid, mixed &$parent): void
	{
		$cleanupError = NULL;
		$released = FALSE;
		if (is_resource($parent)) {
			@fwrite($parent, "RELEASE\n");
			try {
				$event = trim($this->readEvent($parent, 'data-file holder unlock'));
				if ($event !== 'UNLOCKED') {
					throw new RuntimeException("data-file holder cleanup expected UNLOCKED, got {$event}");
				}
				$released = TRUE;
			} catch (Throwable $error) {
				$cleanupError = $error;
			}
			@fclose($parent);
			$parent = NULL;
		}
		if (is_int($pid) && $pid > 0) {
			if ($released) {
				$waited = pcntl_waitpid($pid, $status);
			} else {
				$waited = pcntl_waitpid($pid, $status, WNOHANG);
				if ($waited === 0 && function_exists('posix_kill')) {
					@posix_kill($pid, SIGKILL);
					$waited = pcntl_waitpid($pid, $status);
				} elseif ($waited === 0 && $cleanupError === NULL) {
					$cleanupError = new RuntimeException('data-file holder cannot be reaped: posix_kill unavailable');
				}
			}
			if ($waited < 0 && $cleanupError === NULL) {
				$cleanupError = new RuntimeException('data-file holder waitpid failed');
			} elseif ($waited > 0 && (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0)
				&& $cleanupError === NULL) {
				$cleanupError = new RuntimeException('data-file holder exited unsuccessfully');
			}
			$pid = NULL;
		}
		if ($cleanupError !== NULL) {
			throw $cleanupError;
		}
	}

	// -----------------------------------------------------------------------
	// open() — new key, refresh-in-place, injectable clock.
	// -----------------------------------------------------------------------

	public function testOpenNewKeyCreatesOneEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'a brand-new key must create exactly one entry');
		$this->assertSame('ip', $open[0]['facility']);
		$this->assertSame('pfB_Example_v4', $open[0]['item']);
		$this->assertSame('download', $open[0]['stage']);
		$this->assertSame('HTTP 404', $open[0]['message']);
		$this->assertSame(1000, $open[0]['first_seen']);
		$this->assertSame(1000, $open[0]['last_seen']);
	}

	public function testOpenExistingKeyRefreshesWithoutDuplicating(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 500', $this->dir, self::clockAt(2000));

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'reopening the SAME key must refresh, never duplicate');
		$this->assertSame('HTTP 500', $open[0]['message'], 'message must be the LATEST refresh');
		$this->assertSame(1000, $open[0]['first_seen'], 'first_seen must be preserved from the original open');
		$this->assertSame(2000, $open[0]['last_seen'], 'last_seen must advance to the refresh time');
	}

	public function testOpenDefaultsToRealClockWhenNoneInjected(): void
	{
		$before = time();
		pfb_sync_status_open('dnsbl', 'SomeGroup', 'apply', 'stuck', $this->dir);
		$after = time();

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open);
		$this->assertGreaterThanOrEqual($before, $open[0]['first_seen']);
		$this->assertLessThanOrEqual($after, $open[0]['first_seen']);
	}

	// -----------------------------------------------------------------------
	// close() — existing key removed; absent key is a safe no-op.
	// -----------------------------------------------------------------------

	public function testCloseExistingKeyRemovesEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		// Before-state: the entry is genuinely open first, so close() closing it
		// is a real transition, not a no-op that happens to leave zero entries.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir));

		pfb_sync_status_close('ip', 'pfB_Example_v4', 'download', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'closing the open key must remove it');
	}

	public function testCloseAbsentKeyIsSafeNoOp(): void
	{
		// No exception, no warning, no ledger file created at all.
		pfb_sync_status_close('ip', 'never_opened', 'download', $this->dir);

		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_status.json', 'close on an absent key must not write a file');
		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	public function testCloseAbsentKeyAmongOthersLeavesOthersIntact(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		// Close a DIFFERENT stage under the same facility/item — must be a no-op.
		pfb_sync_status_close('ip', 'pfB_Example_v4', 'apply', $this->dir);

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'closing an unrelated stage must not touch the real entry');
		$this->assertSame('download', $open[0]['stage']);
	}

	// -----------------------------------------------------------------------
	// list_open() — facility filter.
	// -----------------------------------------------------------------------

	public function testListOpenFiltersByFacility(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'ip fail', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('dnsbl', 'SomeGroup', 'apply', 'dnsbl fail', $this->dir, self::clockAt(2000));

		$ip_only = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $ip_only);
		$this->assertSame('ip', $ip_only[0]['facility']);

		$dnsbl_only = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $dnsbl_only);
		$this->assertSame('dnsbl', $dnsbl_only[0]['facility']);

		$all = pfb_sync_status_list_open($this->dir);
		$this->assertCount(2, $all, 'NULL facility must return every facility');
	}

	// -----------------------------------------------------------------------
	// Fail-safe reads: absent / corrupt file -> empty ledger, never throw.
	// -----------------------------------------------------------------------

	public function testAbsentFileReadsAsEmpty(): void
	{
		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	public function testCorruptNonJsonFileReadsAsEmpty(): void
	{
		file_put_contents($this->dir . '/pfb_sync_status.json', 'this is not json{{{');

		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	public function testCorruptNonObjectJsonReadsAsEmpty(): void
	{
		// Valid JSON, but a scalar, not the expected facility->item->stage object.
		file_put_contents($this->dir . '/pfb_sync_status.json', '"just a string"');

		$this->assertSame([], pfb_sync_status_list_open($this->dir));
	}

	// -----------------------------------------------------------------------
	// Unwritable ledger dir — chosen contract: silent no-op, never an uncaught
	// exception. Root bypasses directory permissions entirely (a root run can't
	// simulate the denial — CLAUDE.md "Running tests"), so this is skipped there,
	// matching the repo's established chmod-0555 permission-test convention.
	// -----------------------------------------------------------------------

	public function testUnwritableLedgerDirFailsSafely(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions -- cannot simulate the denial.');
		}

		chmod($this->dir, 0555);

		// Must not throw / must not emit an uncaught error up to the caller.
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		// The chosen contract is a silent no-op: nothing observable changed.
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_status.json', 'an unwritable dir must not produce a ledger file');
	}

	// -----------------------------------------------------------------------
	// write_all() — an invalid-UTF8 message must never wipe the WHOLE ledger.
	// json_encode() returns FALSE on invalid UTF-8; file_put_contents(FALSE, ...)
	// casts to "" and SUCCEEDS (verified: it returns int(0), never FALSE), so a
	// naive "=== FALSE" guard on file_put_contents() alone never fires and an
	// empty file gets renamed over the real ledger.
	// -----------------------------------------------------------------------

	public function testOpenWithInvalidUtf8MessageDoesNotWipeExistingLedger(): void
	{
		pfb_sync_status_open('ip', 'pfB_Existing_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir), 'pre-condition: one entry exists before the bad write');

		// \xFF is never valid UTF-8 -- json_encode() of the WHOLE ledger (including
		// this new key) fails once this key is merged in.
		$badMessage = "pfctl: \xFF garbled stderr";
		pfb_sync_status_open('ip', 'pfB_Bad_v4', 'apply', $badMessage, $this->dir, self::clockAt(2000));

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(
			1,
			$open,
			'an invalid-UTF8 message must not silently wipe the pre-existing entry -- the bad write must be a no-op, not an empty-ledger rename'
		);
		$this->assertSame('pfB_Existing_v4', $open[0]['item']);
	}

	// -----------------------------------------------------------------------
	// pfb_sync_status_locked() — the read-modify-write span is held under a REAL
	// cross-process exclusive lock, not just the final write. Proven against an
	// actual second process (pcntl_fork), not a single-process simulation.
	// -----------------------------------------------------------------------

	public function testOpenBlocksUntilARealConcurrentProcessReleasesTheLedgerLock(): void
	{
		$this->assertOpenerBlocksWhileTheLedgerLockIsHeld(0);
	}

	/**
	 * @param int $openerStartDelayUs microseconds the opener waits, after proving the lock is
	 *                                contended, before it calls into the ledger -- the window in
	 *                                which the opener is running but has not reached the lock yet.
	 */
	private function assertOpenerBlocksWhileTheLedgerLockIsHeld(int $openerStartDelayUs): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('pcntl_async_signals')
			|| !function_exists('pcntl_signal') || !function_exists('posix_kill') || !defined('SIGUSR1')) {
			$this->markTestSkipped('pcntl not available -- cannot spawn a real concurrent process for this test.');
		}

		$lockPath   = $this->dir . '/pfb_sync_status.json.lock';
		$controlParent = NULL;
		$controlChild = NULL;
		$eventParent = NULL;
		$eventChild = NULL;
		$holderPid = NULL;
		$openerPid = NULL;
		try {
			[$controlParent, $controlChild] = $this->signalPair();
			stream_set_timeout($controlParent, 5);
			stream_set_timeout($controlChild, 5);
			[$eventParent, $eventChild] = $this->signalPair();
			stream_set_timeout($eventParent, 5);
			stream_set_timeout($eventChild, 5);
			$holderPid = pcntl_fork();
			if ($holderPid === -1) {
				$this->markTestSkipped('pcntl_fork() failed.');
			}
			if ($holderPid === 0) {
				fclose($controlParent);
				fclose($eventParent);
				$fp = @fopen($lockPath, 'c');
				if ($fp === FALSE || !@flock($fp, LOCK_EX)) {
					@fwrite($eventChild, "HOLDER_ERROR\n");
					exit(1);
				}
				fwrite($eventChild, "LOCKED\n");
				$this->expectChildEvent($controlChild, 'RELEASE', 'ledger lock holder release', $eventChild);
				fwrite($eventChild, "RELEASING\n");
				@flock($fp, LOCK_UN);
				fclose($fp);
				fclose($controlChild);
				fclose($eventChild);
				exit(0);
			}
			fclose($controlChild);
			$controlChild = NULL;
			$this->assertSame("LOCKED\n", $this->readEvent($eventParent, 'ledger lock holder acquisition'));

			$openerPid = pcntl_fork();
			if ($openerPid === -1) {
				$this->markTestSkipped('pcntl_fork() failed.');
			}
			if ($openerPid === 0) {
				fclose($controlParent);
				fclose($eventParent);
				pcntl_async_signals(TRUE);
				pcntl_signal(SIGUSR1, static function () use ($eventChild): void {
					$functions = array_values(array_filter(array_map(
						static fn(array $frame): string => (string) ($frame['function'] ?? ''),
						debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)
					), static fn(string $name): bool => $name !== ''));
					$required = ['pfb_flock_bounded', 'pfb_sync_status_locked', 'pfb_sync_status_open'];
					$blocked = count(array_intersect($required, $functions)) === count($required)
						&& !in_array('pfb_sync_status_read_all', $functions, TRUE);
					$event = $blocked ? 'BLOCKED' : 'NOT_BLOCKED ' . implode('|', array_slice($functions, 0, 24));
					@fwrite($eventChild, $event . "\n");
				});
				$probe = @fopen($lockPath, 'c');
				$wouldBlock = 0;
				$contended = $probe !== FALSE
					&& !@flock($probe, LOCK_EX | LOCK_NB, $wouldBlock)
					&& $wouldBlock === 1;
				if (is_resource($probe)) {
					fclose($probe);
				}
				if (!$contended) {
					fwrite($eventChild, "PROBE_FAILED\n");
					exit(1);
				}
				fwrite($eventChild, "CONTENDED\n");
				// Signal delivery cuts usleep() short, so hold the window against a
				// monotonic deadline -- the opener stays runnable and answers every probe,
				// and a wall-clock step cannot shorten or extend the window.
				$startAt = hrtime(TRUE) + ($openerStartDelayUs * 1000);
				while (hrtime(TRUE) < $startAt) {
					usleep(1000);
				}
				pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
				fwrite($eventChild, "RETURNED\n");
				fclose($eventChild);
				exit(0);
			}
			fclose($eventChild);
			$eventChild = NULL;
			$this->assertSame("CONTENDED\n", $this->readEvent($eventParent, 'concurrent opener contention'));
			$blocked = FALSE;
			$notBlockedSignals = [];
			// The wait ends on the observed BLOCKED state. A budget counted in signal
			// round trips is not a wait: an opener that is merely slow to reach the lock
			// answers NOT_BLOCKED as fast as the CPU allows and exhausts it in milliseconds
			// (#2183). The cap below is monotonic and generous -- its only job is reaping
			// a stuck run, and the pause between probes leaves the opener CPU to advance.
			$salvageDeadline = hrtime(TRUE) + (30 * 1000000000);
			while (hrtime(TRUE) < $salvageDeadline) {
				if (!@posix_kill($openerPid, SIGUSR1)) {
					$this->fail('salvage cap expired / stuck or environment: awaiting BLOCKED signal before release; opener exited');
				}
				$signalEvent = trim($this->readEvent($eventParent, 'opener blocked-state signal'));
				if ($signalEvent === 'BLOCKED') {
					$blocked = TRUE;
					break;
				}
				if (!str_starts_with($signalEvent, 'NOT_BLOCKED ')) {
					$this->fail('unexpected opener signal event: expected BLOCKED or NOT_BLOCKED, got ' . $signalEvent);
				}
				$notBlockedSignals[$signalEvent] = ($notBlockedSignals[$signalEvent] ?? 0) + 1;
				usleep(1000);
			}
			$observed = [];
			foreach ($notBlockedSignals as $signalEvent => $count) {
				$observed[] = $signalEvent . ' (x' . $count . ')';
			}
			$this->assertTrue($blocked,
				'salvage cap expired / stuck or environment: awaiting BLOCKED opener state until the salvage cap; '
				. 'observed=' . implode(';', $observed));
			fwrite($controlParent, "RELEASE\n");
			$this->assertSame("RELEASING\n", $this->readEvent($eventParent, 'ledger lock holder release while still locked'));
			$this->assertSame("RETURNED\n", $this->readEvent($eventParent, 'concurrent opener return after unlock'));
			fclose($controlParent);
			$controlParent = NULL;
			fclose($eventParent);
			$eventParent = NULL;
			pcntl_waitpid($holderPid, $holderStatus);
			$holderPid = NULL;
			pcntl_waitpid($openerPid, $openerStatus);
			$openerPid = NULL;
			$this->assertTrue(pcntl_wifexited($holderStatus) && pcntl_wexitstatus($holderStatus) === 0,
				'ledger lock holder must exit cleanly after the release event');
			$this->assertTrue(pcntl_wifexited($openerStatus) && pcntl_wexitstatus($openerStatus) === 0,
				'concurrent opener must return cleanly after the release event');
		} finally {
			if (is_resource($controlParent)) {
				@fwrite($controlParent, "RELEASE\n");
			}
			foreach ([$controlParent, $controlChild, $eventParent, $eventChild] as $stream) {
				if (is_resource($stream)) {
					@fclose($stream);
				}
			}
			foreach ([$holderPid, $openerPid] as $pid) {
				if (is_int($pid) && $pid > 0) {
					if (pcntl_waitpid($pid, $childStatus, WNOHANG) === 0 && function_exists('posix_kill')) {
						@posix_kill($pid, SIGKILL);
					}
					pcntl_waitpid($pid, $childStatus);
				}
			}
		}
	}

	// -----------------------------------------------------------------------
	// issue #2183 — the blocked-state observation must survive an opener that is
	// slow to reach the lock: it waits for the opener to BE blocked. A budget
	// counted in signal round trips is not that wait — it is spent in milliseconds
	// while the opener is still on its way, and reports the opener as NOT_BLOCKED.
	// -----------------------------------------------------------------------

	public function testOpenerIsObservedBlockedEvenWhenItIsSlowToReachTheLedgerLock(): void
	{
		$this->assertOpenerBlocksWhileTheLedgerLockIsHeld(250000);
	}

	// -----------------------------------------------------------------------
	// issue #1780 — pfb_sync_status_locked()'s EX acquire must be BOUNDED: on a
	// real, still-held lock it logs the timeout loudly (observable) and still
	// runs $fn() (fail-open contract unchanged), and that signal must
	// DISCRIMINATE -- never fire on an ordinary uncontended success.
	// -----------------------------------------------------------------------

	public function testSyncStatusLockedExpiryIsObservableAndStillRunsFn(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl_fork() and posix_kill() required for fork cleanup.');
		}

		$originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($originalPfb, [
			'log'    => $this->dir . '/pfblockerng.log',
			'errlog' => $this->dir . '/error.log',
		]);

		$lockPath   = $this->dir . '/pfb_sync_status.json.lock';
		$holderParent = NULL;
		$holderChild = NULL;
		$pid = NULL;
		$primaryError = NULL;
		$cleanupError = NULL;
		try {
			[$holderParent, $holderChild] = $this->signalPair();
			stream_set_timeout($holderParent, 5);
			stream_set_timeout($holderChild, 5);
			$pid = pcntl_fork();
			if ($pid === -1) {
				$this->markTestSkipped('pcntl_fork() failed.');
			}

			if ($pid === 0) {
				fclose($holderParent);
				$fp = @fopen($lockPath, 'c');
				if ($fp === FALSE || !@flock($fp, LOCK_EX)) {
					@fwrite($holderChild, "HOLDER_ERROR\n");
					@fclose($holderChild);
					exit(1);
				}
				fwrite($holderChild, "LOCKED\n");
				$this->expectChildEvent($holderChild, 'RELEASE', 'sync-status expiry holder release');
				@flock($fp, LOCK_UN);
				fclose($fp);
				fwrite($holderChild, "UNLOCKED\n");
				fclose($holderChild);
				exit(0);
			}

			fclose($holderChild);
			$holderChild = NULL;
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'sync-status expiry holder acquisition'));

			$fnRan = FALSE;
			pfb_sync_status_locked($this->dir, function () use (&$fnRan) {
				$fnRan = TRUE;
			}, 0.1);

			$this->assertTrue($fnRan,
				'the callable must still run under the fail-open contract even after the lock acquire times out');

			$log = (string) file_get_contents($GLOBALS['pfb']['log']);
			$this->assertStringContainsString('sync-status ledger lock timed out', $log,
				'a timed-out acquire must be logged loudly -- an operator-observable signal, never silent');
		} catch (Throwable $error) {
			$primaryError = $error;
		}
		$released = FALSE;
		if (is_resource($holderParent)) {
			@fwrite($holderParent, "RELEASE\n");
			try {
				$event = trim($this->readEvent($holderParent, 'sync-status expiry holder cleanup'));
				if ($event !== 'UNLOCKED') {
					throw new RuntimeException("sync-status expiry holder cleanup expected UNLOCKED, got {$event}");
				}
				$released = TRUE;
			} catch (Throwable $error) {
				$cleanupError = $error;
			}
			@fclose($holderParent);
			$holderParent = NULL;
		}
		if (is_int($pid) && $pid > 0) {
			if ($released) {
				$waited = pcntl_waitpid($pid, $waitStatus);
			} else {
				$waited = pcntl_waitpid($pid, $waitStatus, WNOHANG);
				if ($waited === 0 && function_exists('posix_kill')) {
					@posix_kill($pid, SIGKILL);
					$waited = pcntl_waitpid($pid, $waitStatus);
				} elseif ($waited === 0 && $cleanupError === NULL) {
					$cleanupError = new RuntimeException('sync-status expiry holder cannot be reaped: posix_kill unavailable');
				}
			}
			if ($waited < 0 && $cleanupError === NULL) {
				$cleanupError = new RuntimeException('sync-status expiry holder waitpid failed');
			} elseif ($waited > 0 && (!pcntl_wifexited($waitStatus) || pcntl_wexitstatus($waitStatus) !== 0)
				&& $cleanupError === NULL) {
				$cleanupError = new RuntimeException('sync-status expiry holder exited unsuccessfully');
			}
			$pid = NULL;
		}
		if (is_resource($holderChild)) {
			@fclose($holderChild);
		}
		$GLOBALS['pfb'] = $originalPfb;
		if ($primaryError !== NULL) {
			throw $primaryError;
		}
		if ($cleanupError !== NULL) {
			throw $cleanupError;
		}
	}

	public function testSyncStatusLockedSuccessDoesNotEmitTimeoutSignal(): void
	{
		$originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($originalPfb, [
			'log'    => $this->dir . '/pfblockerng_success.log',
			'errlog' => $this->dir . '/error_success.log',
		]);

		try {
			$fnRan = FALSE;
			pfb_sync_status_locked($this->dir, function () use (&$fnRan) {
				$fnRan = TRUE;
			}, 5.0);

			$this->assertTrue($fnRan, 'the callable must run on the ordinary uncontended success path');

			$log = file_exists($GLOBALS['pfb']['log']) ? (string) file_get_contents($GLOBALS['pfb']['log']) : '';
			$this->assertStringNotContainsString('lock timed out', $log,
				'the timeout signal must DISCRIMINATE -- it must never fire on an uncontended success');
		} finally {
			$GLOBALS['pfb'] = $originalPfb;
		}
	}

	// -----------------------------------------------------------------------
	// pfb_sync_status_close_removed_alias() — issue #1014/#1019: close an
	// orphaned stage=download entry when our own WebUI renames/deletes an alias.
	// -----------------------------------------------------------------------

	public function testCloseRemovedAliasIpv4ClosesDownloadEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		// Before-state: the download entry is genuinely open first.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', 'Foo', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'ipv4 removal must close pfB_Foo_v4/download');
	}

	public function testCloseRemovedAliasIpv6ClosesDownloadEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v6', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv6', 'Foo', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'ipv6 removal must close pfB_Foo_v6/download');
	}

	public function testCloseRemovedAliasDnsblClosesDownloadEntry(): void
	{
		pfb_sync_status_open('dnsbl', 'DNSBL_Foo', 'download', 'timeout', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		pfb_sync_status_close_removed_alias('dnsbl', 'Foo', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'dnsbl removal must close DNSBL_Foo/download');
	}

	public function testCloseRemovedAliasEmptyAliasnameIsNoOp(): void
	{
		// pfb_sync_status_close() already no-ops on an absent key, so the ONLY fixture that
		// discriminates "empty-guard present" from "absent" is a pre-opened pfB__v4 entry --
		// the exact key the un-guarded switch ('ipv4' + '') would build and wrongly close.
		pfb_sync_status_open('ip', 'pfB__v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', '', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'an empty aliasname must be a no-op even when pfB__v4 happens to be open');
		$this->assertSame('pfB__v4', $open[0]['item']);
	}

	public function testCloseRemovedAliasUnknownGtypeIsNoOp(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		// 'geoip' has no download ledger key shape -- must no-op, never crash.
		pfb_sync_status_close_removed_alias('geoip', 'Foo', $this->dir);

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'an unknown gtype must leave an unrelated open entry untouched');
		$this->assertSame('pfB_Foo_v4', $open[0]['item']);
	}

	public function testCloseRemovedAliasNeverClosesTheTickManagedApplyStage(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'apply', '[pfctl] failed', $this->dir, self::clockAt(1000));
		// Before-state: both stages genuinely open.
		$this->assertCount(2, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', 'Foo', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'the tick-managed apply stage must survive alias removal');
		$this->assertSame('apply', $open[0]['stage'], 'the surviving entry must be the apply stage');
	}

	public function testCloseRemovedAliasKeyPrecisionLeavesOtherAliasesOpen(): void
	{
		// Prefix-adjacent sibling proves EXACT-key match, not a prefix/substring match:
		// closing 'Foo' must close only pfB_Foo_v4 and leave pfB_FooBar_v4 open.
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_FooBar_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(2000));
		$this->assertCount(2, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', 'Foo', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'closing Foo must close only its exact key, leaving prefix-adjacent FooBar open');
		$this->assertSame('pfB_FooBar_v4', $open[0]['item']);
	}

	// -----------------------------------------------------------------------
	// issue #2060: stage='script' (#1958) is alias-pass-managed like 'download'
	// -- removal must close it too, else no later pass runs its paired clear.
	// -----------------------------------------------------------------------

	public function testCloseRemovedAliasIpv4ClosesScriptEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'script', 'Pre-script FAIL - serving last known-good', $this->dir, self::clockAt(1000));
		// Before-state: the script entry is genuinely open first.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', 'Foo', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'ipv4 removal must close pfB_Foo_v4/script');
	}

	public function testCloseRemovedAliasIpv6ClosesScriptEntry(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v6', 'script', 'Pre-script FAIL - serving last known-good', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv6', 'Foo', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'ipv6 removal must close pfB_Foo_v6/script');
	}

	public function testCloseRemovedAliasDnsblClosesScriptEntry(): void
	{
		pfb_sync_status_open('dnsbl', 'DNSBL_Foo', 'script', 'Pre-script FAIL - serving last known-good', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		pfb_sync_status_close_removed_alias('dnsbl', 'Foo', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir), 'dnsbl removal must close DNSBL_Foo/script');
	}

	public function testCloseRemovedAliasClosesEveryAliasPassManagedStageAndLeavesApplyOpen(): void
	{
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'script', 'Post-script FAIL', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'apply', '[pfctl] failed', $this->dir, self::clockAt(1000));
		// Before-state: all three stages genuinely open for the same item.
		$this->assertCount(3, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', 'Foo', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open,
			'download and script are alias-pass-managed and must close; apply is tick-managed and must survive');
		$this->assertSame('apply', $open[0]['stage'], 'the surviving entry must be the apply stage');
	}

	public function testCloseRemovedAliasScriptStageMatchesTheExactKeyOnly(): void
	{
		// Prefix-adjacent sibling proves EXACT-key match for the script stage too:
		// deleting 'Foo' must never sweep the live pfB_FooBar_v4's own entry.
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'script', 'Pre-script FAIL', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('ip', 'pfB_FooBar_v4', 'script', 'Pre-script FAIL', $this->dir, self::clockAt(2000));
		$this->assertCount(2, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_sync_status_close_removed_alias('ipv4', 'Foo', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'closing Foo must close only its exact script key, leaving prefix-adjacent FooBar open');
		$this->assertSame('pfB_FooBar_v4', $open[0]['item']);
	}

	public function testCloseRemovedAliasScriptStageDoesNotCrossFacilities(): void
	{
		// A DNSBL group and an IP alias may carry the same aliasname; removing
		// one must never close the other facility's script entry.
		pfb_sync_status_open('ip', 'pfB_Foo_v4', 'script', 'Pre-script FAIL', $this->dir, self::clockAt(1000));
		pfb_sync_status_open('dnsbl', 'DNSBL_Foo', 'script', 'Pre-script FAIL', $this->dir, self::clockAt(1000));
		$this->assertCount(2, pfb_sync_status_list_open($this->dir));

		pfb_sync_status_close_removed_alias('dnsbl', 'Foo', $this->dir);

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open, 'removing the DNSBL group must leave the same-named IP alias untouched');
		$this->assertSame('ip', $open[0]['facility']);
		$this->assertSame('pfB_Foo_v4', $open[0]['item']);
	}

	// -----------------------------------------------------------------------
	// issue #1780 F1/F2/F9 — read_all()'s $unavailable discrimination, and the
	// two read-modify-write callers (open/close) failing closed on it.
	// -----------------------------------------------------------------------

	public function testExtraOnlyLockTimeoutDoesNotRequireMain(): void
	{
		$holders = [];
		foreach (['pfb_due_ledger.json' => '{}', 'pfb_sync_status.json' => '{}', 'pfb_sync_status.json.lock' => ''] as $name => $contents) {
			$path = $this->dir . '/' . $name;
			file_put_contents($path, $contents);
			$holder = fopen($path, 'c');
			$this->assertNotFalse($holder, "test fixture must open {$name}");
			$this->assertTrue(flock($holder, LOCK_EX), "test fixture must lock {$name}");
			$holders[] = $holder;
		}

		$extraPath = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
		$childCode = <<<'PHP'
require $argv[1];
if (function_exists('pfb_logger') || !function_exists('logger')) {
	exit(3);
}
$dueUnavailable = FALSE;
$due = pfb_due_ledger_read_entry('dcc', $argv[2], 0.05, $dueUnavailable);
$syncUnavailable = FALSE;
$sync = pfb_sync_status_read_all($argv[2], 0.05, $syncUnavailable);
$callbackRan = FALSE;
pfb_sync_status_locked($argv[2], static function () use (&$callbackRan): void {
	$callbackRan = TRUE;
}, 0.05);
echo json_encode([
	'due' => $due,
	'due_unavailable' => $dueUnavailable,
	'sync' => $sync,
	'sync_unavailable' => $syncUnavailable,
	'callback_ran' => $callbackRan,
], JSON_THROW_ON_ERROR), "\n";
PHP;
		$descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $childCode, $extraPath, $this->dir], $descriptors, $pipes);
		$this->assertIsResource($process, 'test fixture must launch an extra-only child process');
		$deadline = hrtime(TRUE) + 5_000_000_000;
		do {
			$status = proc_get_status($process);
			if (!$status['running']) {
				break;
			}
			usleep(10000);
		} while (hrtime(TRUE) < $deadline);
		$timedOut = $status['running'];
		if ($timedOut) {
			proc_terminate($process, 9);
		}
		$output = stream_get_contents($pipes[1]);
		$errors = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$closeExitCode = proc_close($process);
		foreach ($holders as $holder) {
			flock($holder, LOCK_UN);
			fclose($holder);
		}

		$this->assertFalse($timedOut, 'extra-only child exceeded the 5-second hard deadline');
		$exitCode = $status['exitcode'] !== -1 ? $status['exitcode'] : $closeExitCode;
		$this->assertSame(0, $exitCode, "extra-only child failed: {$errors}");
		$result = json_decode($output, TRUE);
		$this->assertIsArray($result, "extra-only child output was invalid JSON: {$output}");
		$this->assertArrayHasKey('due', $result, 'extra-only child must report the due-read result');
		$this->assertNull($result['due'], 'a timed-out extra-only due read must return no entry');
		$this->assertTrue($result['due_unavailable'] ?? FALSE, 'a timed-out extra-only due read must report unavailable');
		$this->assertSame([], $result['sync'] ?? NULL, 'a timed-out extra-only sync read must return an empty ledger');
		$this->assertTrue($result['sync_unavailable'] ?? FALSE, 'a timed-out extra-only sync read must report unavailable');
		$this->assertTrue($result['callback_ran'] ?? FALSE, 'a timed-out extra-only sync lock must run its callback');
	}

	/**
	 * read_all()'s $unavailable discriminates: TRUE only on a genuine
	 * lock-acquire expiry against the DATA file (pfb_sync_status.json) itself --
	 * a SEPARATE lock from pfb_sync_status_locked()'s .json.lock EX acquire.
	 * FALSE on every other path (absent file, corrupt JSON, success). An
	 * always-TRUE or always-FALSE flag must fail this test.
	 */
	public function testReadAllUnavailableDiscriminatesLockTimeoutFromEveryOtherPath(): void
	{
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));

		$dataPath   = $this->dir . '/pfb_sync_status.json';
		[$pid, $holderParent] = $this->forkRealDataFileHolder($dataPath);
		$primaryError = NULL;
		$cleanupError = NULL;
		try {
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'read_all data-file holder acquisition'));
			$unavailable = FALSE;
			$data = pfb_sync_status_read_all($this->dir, 0.15, $unavailable);
			$this->assertSame([], $data, 'an expired read must still return [] (same as empty), never a stale/partial ledger');
			$this->assertTrue($unavailable, 'a genuine lock-acquire expiry must set $unavailable = TRUE');
		} catch (Throwable $error) {
			$primaryError = $error;
		}
		try {
			$this->releaseDataFileHolder($pid, $holderParent);
		} catch (Throwable $error) {
			$cleanupError = $error;
		}
		if ($primaryError !== NULL) {
			throw $primaryError;
		}
		if ($cleanupError !== NULL) {
			throw $cleanupError;
		}

		// FALSE: absent ledger file.
		$absentDir = $this->dir . '/absent_subdir';
		mkdir($absentDir, 0777, TRUE);
		$absentUnavailable = TRUE;	// deliberately wrong initial value
		$absentData = pfb_sync_status_read_all($absentDir, 5.0, $absentUnavailable);
		$this->assertSame([], $absentData);
		$this->assertFalse($absentUnavailable, 'an absent ledger file must never report $unavailable = TRUE');

		// FALSE: corrupt JSON.
		$corruptDir = $this->dir . '/corrupt_subdir';
		mkdir($corruptDir, 0777, TRUE);
		file_put_contents($corruptDir . '/pfb_sync_status.json', 'not valid json {{{{');
		$corruptUnavailable = TRUE;
		$corruptData = pfb_sync_status_read_all($corruptDir, 5.0, $corruptUnavailable);
		$this->assertSame([], $corruptData);
		$this->assertFalse($corruptUnavailable, 'a corrupt JSON ledger must never report $unavailable = TRUE');

		// FALSE: genuine success (the lock was released -- read the real data).
		$successUnavailable = TRUE;
		$successData = pfb_sync_status_read_all($this->dir, 5.0, $successUnavailable);
		$this->assertNotSame([], $successData, 'the lock was released by the child above -- this read must succeed');
		$this->assertFalse($successUnavailable, 'a successful read must never report $unavailable = TRUE');
	}

	/**
	 * pfb_sync_status_open() must ABORT its read-modify-write on a lock-acquire
	 * expiry against the DATA file -- never persist an apparently-empty (in
	 * truth just-unreadable) ledger over an intact pre-existing entry, and never
	 * add the NEW key it was asked to open either (the read it needed to merge
	 * against never completed). Discriminates a real fix from a no-op: code
	 * that merely waits out the contention and then reads the real ledger would
	 * successfully add the new key here, not abort.
	 */
	public function testSyncStatusOpenAbortsRmwOnDataFileLockTimeout(): void
	{
		pfb_sync_status_open('ip', 'pfB_Existing_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir), 'precondition: one entry exists before the contended open()');

		$dataPath   = $this->dir . '/pfb_sync_status.json';
		[$pid, $holderParent] = $this->forkRealDataFileHolder($dataPath);
		$primaryError = NULL;
		$cleanupError = NULL;
		try {
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'open abort data-file holder acquisition'));
			pfb_sync_status_open('dnsbl', 'SomeGroup', 'apply', 'should never persist', $this->dir, self::clockAt(2000), 0.15);
		} catch (Throwable $error) {
			$primaryError = $error;
		}
		try {
			$this->releaseDataFileHolder($pid, $holderParent);
		} catch (Throwable $error) {
			$cleanupError = $error;
		}
		if ($primaryError !== NULL) {
			throw $primaryError;
		}
		if ($cleanupError !== NULL) {
			throw $cleanupError;
		}

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open,
			'open() must have aborted on the lock-acquire expiry -- the new key must NOT have been added, '
			. 'got ' . var_export($open, TRUE));
		$this->assertSame('pfB_Existing_v4', $open[0]['item'],
			'the pre-existing entry must survive an aborted open() untouched');
	}

	/**
	 * pfb_sync_status_close() must ABORT its read-modify-write on a lock-acquire
	 * expiry against the DATA file -- the entry it was asked to close must
	 * still be OPEN afterwards (the read it needed never completed, so it never
	 * learned the key was even there to remove).
	 */
	public function testSyncStatusCloseAbortsRmwOnDataFileLockTimeout(): void
	{
		pfb_sync_status_open('ip', 'pfB_StillOpen_v4', 'download', 'HTTP 404', $this->dir, self::clockAt(1000));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir), 'precondition: the entry must be open before the contended close()');

		$dataPath   = $this->dir . '/pfb_sync_status.json';
		[$pid, $holderParent] = $this->forkRealDataFileHolder($dataPath);
		$primaryError = NULL;
		$cleanupError = NULL;
		try {
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'close abort data-file holder acquisition'));
			pfb_sync_status_close('ip', 'pfB_StillOpen_v4', 'download', $this->dir, 0.15);
		} catch (Throwable $error) {
			$primaryError = $error;
		}
		try {
			$this->releaseDataFileHolder($pid, $holderParent);
		} catch (Throwable $error) {
			$cleanupError = $error;
		}
		if ($primaryError !== NULL) {
			throw $primaryError;
		}
		if ($cleanupError !== NULL) {
			throw $cleanupError;
		}

		$open = pfb_sync_status_list_open($this->dir);
		$this->assertCount(1, $open,
			'close() must have aborted on the lock-acquire expiry -- the entry must still be OPEN, '
			. 'got ' . var_export($open, TRUE));
		$this->assertSame('pfB_StillOpen_v4', $open[0]['item']);
	}
}
