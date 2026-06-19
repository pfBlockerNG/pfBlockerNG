<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Control-channel writer: pfb_unbound_py_write_control(),
 * pfb_unbound_py_wait_control_applied(), and pfb_unbound_py_atomic_write_root().
 *
 * Scenario: the writer is the ROOT-only producer of the local privileged command
 * channel (/var/unbound/pfb_py_control, here redirected to a temp dnsbldir). It
 * validates the command + argument (the semantic layer), acquires an exclusive lock,
 * assembles a JSON record with a monotonically-advancing sequence, atomically publishes
 * it, and waits for the watcher to advance the applied marker before returning.
 * These tests pin:
 *   - the command allow-list (disable/enable/addbypass/removebypass) and rejection of
 *     anything else (no file written);
 *   - argument validation at the WRITER (invalid IP / out-of-range duration rejected,
 *     no side effect) -- the reader re-validates independently (Python suite);
 *   - the record shape (cmd/ip/duration/seq/ts) and the seq advance (replay safety);
 *   - the lock file is created on a successful write;
 *   - the applied-wait semantics: returns TRUE when the marker >= seq, FALSE on timeout;
 *   - the writer still returns the seq when the wait times out (command IS on disk);
 *   - the publisher's command-channel permission model (owner root, group unbound,
 *     mode 0640) and its atomic, no-temp-left-behind behaviour.
 *
 * Run against a temp $pfb sandbox (no live box, no chroot). chown('root') is a no-op
 * for a non-root test runner; mode 0640 is asserted because it does not need privilege.
 *
 * The applied marker is pre-seeded to PHP_INT_MAX in setUp() so the default-timeout
 * wait path returns immediately for all existing tests (simulates the watcher having
 * already applied any seq). New tests that exercise the wait directly use an explicit
 * $wait_timeout argument.
 */
#[CoversFunction('pfb_unbound_py_write_control')]
#[CoversFunction('pfb_unbound_py_wait_control_applied')]
#[CoversFunction('pfb_unbound_py_atomic_write_root')]
final class UnboundPyControlWriteTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = false;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_control_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->tmp,
			'supp'     => 'off',	// pfb_filter()'s private/reserved IP exclusion off for the test
		]);

		// Pre-seed the applied marker to PHP_INT_MAX so the default-timeout wait in
		// write_control returns immediately -- simulates the watcher having already applied
		// any seq. Tests that probe the wait directly overwrite this before calling.
		file_put_contents("{$this->tmp}/pfb_py_control.applied", (string) PHP_INT_MAX . "\n");
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->rrmdir($this->tmp);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $f) {
			if ($f === '.' || $f === '..') {
				continue;
			}
			$p = "{$dir}/{$f}";
			is_dir($p) ? $this->rrmdir($p) : @unlink($p);
		}
		@rmdir($dir);
	}

	private function channel(): string
	{
		return "{$this->tmp}/pfb_py_control";
	}

	private function readRecord(): array
	{
		$raw = file_get_contents($this->channel());
		$this->assertNotFalse($raw);
		$rec = json_decode(trim($raw), true);
		$this->assertIsArray($rec);
		return $rec;
	}

	private function channelApplied(): string
	{
		return "{$this->tmp}/pfb_py_control.applied";
	}

	// --- the four valid commands (record shape) -----------------------------

	public function testDisableWritesRecordSeqOne(): void
	{
		// Given: no channel yet (BEFORE).
		$this->assertFileDoesNotExist($this->channel());

		// When: a root-issued disable is written.
		$this->assertSame(1, pfb_unbound_py_write_control('disable'));

		// Then: a fresh record, seq 1, no ip/duration.
		$rec = $this->readRecord();
		$this->assertSame('disable', $rec['cmd']);
		$this->assertSame(1, $rec['seq']);
		$this->assertArrayNotHasKey('ip', $rec);
		$this->assertArrayNotHasKey('duration', $rec);
		$this->assertArrayHasKey('ts', $rec);
	}

	public function testDisableWithValidDurationCarriesIt(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('disable', '', '60'));
		$rec = $this->readRecord();
		$this->assertSame('disable', $rec['cmd']);
		$this->assertSame(60, $rec['duration']);
	}

	public function testEnableWritesRecord(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('enable'));
		$rec = $this->readRecord();
		$this->assertSame('enable', $rec['cmd']);
		$this->assertArrayNotHasKey('ip', $rec);
	}

	public function testAddbypassCarriesIpAndDuration(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('addbypass', '192.0.2.10', '120'));
		$rec = $this->readRecord();
		$this->assertSame('addbypass', $rec['cmd']);
		$this->assertSame('192.0.2.10', $rec['ip']);
		$this->assertSame(120, $rec['duration']);
	}

	public function testAddbypassWithoutDurationOmitsIt(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('addbypass', '2001:db8::1'));
		$rec = $this->readRecord();
		$this->assertSame('addbypass', $rec['cmd']);
		$this->assertSame('2001:db8::1', $rec['ip']);
		$this->assertArrayNotHasKey('duration', $rec);
	}

	public function testRemovebypassCarriesIpIgnoresDuration(): void
	{
		// removebypass takes no duration; a 4th arg must be ignored (no 'duration' key).
		$this->assertSame(1, pfb_unbound_py_write_control('removebypass', '192.0.2.10', '60'));
		$rec = $this->readRecord();
		$this->assertSame('removebypass', $rec['cmd']);
		$this->assertSame('192.0.2.10', $rec['ip']);
		$this->assertArrayNotHasKey('duration', $rec);
	}

	// --- the sequence advance (replay safety) -------------------------------

	public function testSequenceAdvancesAcrossCalls(): void
	{
		// BEFORE: first write -> seq 1.
		$this->assertSame(1, pfb_unbound_py_write_control('disable'));
		// AFTER each subsequent write the seq strictly advances, read from the prior record.
		$this->assertSame(2, pfb_unbound_py_write_control('enable'));
		$this->assertSame(3, pfb_unbound_py_write_control('disable'));
		$this->assertSame(3, $this->readRecord()['seq']);
	}

	public function testSequenceFromCorruptChannelRestartsAtOne(): void
	{
		// A non-JSON / seq-less channel is treated as seq 0 -> next write is 1 (fail-safe).
		file_put_contents($this->channel(), "garbage not json\n");
		$this->assertSame(1, pfb_unbound_py_write_control('enable'));
		$this->assertSame(1, $this->readRecord()['seq']);
	}

	// --- argument validation at the writer (no side effect on reject) -------

	public function testInvalidCommandRejectedNoFileWritten(): void
	{
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFalse(pfb_unbound_py_write_control('nuke-everything'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testEmptyCommandRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control(''));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testAddbypassWithInvalidIpRejectedNoFileWritten(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('addbypass', '999.1.1.1'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testAddbypassWithEmptyIpRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('addbypass', ''));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testRemovebypassWithInvalidIpRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('removebypass', 'not-an-ip'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDurationZeroRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('disable', '', '0'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDurationAboveMaxRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('disable', '', '3601'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDurationBoundariesAccepted(): void
	{
		// 1 and 3600 are the inclusive valid bounds.
		$this->assertSame(1, pfb_unbound_py_write_control('disable', '', '1'));
		$this->assertSame(1, $this->readRecord()['duration']);

		$this->assertSame(2, pfb_unbound_py_write_control('disable', '', '3600'));
		$this->assertSame(3600, $this->readRecord()['duration']);
	}

	public function testNonNumericDurationRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('addbypass', '192.0.2.10', 'abc'));
		$this->assertFileDoesNotExist($this->channel());
	}

	// --- the publisher's command-channel permission model -------------------

	public function testPublishedChannelIsMode0640(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('disable'));
		clearstatcache();
		// Owner read/write, group read, no other access (the command-channel model).
		$this->assertSame('0640', substr(sprintf('%o', fileperms($this->channel())), -4));
	}

	public function testAtomicWriteRootLeavesNoStagingTempBehind(): void
	{
		$path = "{$this->tmp}/cmd";
		$this->assertTrue(pfb_unbound_py_atomic_write_root($path, "x\n"));
		$leftover = array_filter(scandir($this->tmp), static function ($f) {
			return strpos($f, '.pfbctl_') === 0;
		});
		$this->assertSame([], array_values($leftover));
	}

	public function testAtomicWriteRootFailsWhenDirMissing(): void
	{
		// Staging dir absent -> tempnam fails -> FALSE, fail-safe (no crash).
		$this->assertFalse(
			pfb_unbound_py_atomic_write_root("{$this->tmp}/nope/deep/cmd", 'x')
		);
	}

	// --- wait_control_applied: poll semantics -------------------------------

	public function testWaitControlAppliedReturnsTrueWhenMarkerAlreadySatisfied(): void
	{
		// Given: applied marker already >= the seq we wait for.
		file_put_contents($this->channelApplied(), "10\n");

		// When/Then: returns TRUE immediately for seq <= 10.
		$this->assertTrue(pfb_unbound_py_wait_control_applied(10));
		$this->assertTrue(pfb_unbound_py_wait_control_applied(5));
		$this->assertTrue(pfb_unbound_py_wait_control_applied(1));
	}

	public function testWaitControlAppliedReturnsTrueWhenMarkerExceedsSeq(): void
	{
		// Marker strictly greater than requested seq is also satisfied.
		file_put_contents($this->channelApplied(), "99\n");
		$this->assertTrue(pfb_unbound_py_wait_control_applied(50));
	}

	public function testWaitControlAppliedReturnsFalseOnTimeoutWhenMarkerBelow(): void
	{
		// Given: marker is below the seq we wait for.
		file_put_contents($this->channelApplied(), "0\n");

		// When: wait with a very short timeout (0.4 s keeps the test fast).
		// Then: returns FALSE -- the marker never advanced.
		$result = pfb_unbound_py_wait_control_applied(5, 0.4);
		$this->assertFalse($result);
	}

	public function testWaitControlAppliedReturnsFalseWhenMarkerAbsent(): void
	{
		// Given: no applied marker file at all.
		@unlink($this->channelApplied());

		// When: wait with a short timeout.
		// Then: returns FALSE (file never appears).
		$this->assertFalse(pfb_unbound_py_wait_control_applied(1, 0.4));
	}

	// --- write_control with wait satisfied (marker high via setUp) ----------

	public function testWriteControlReturnsSeqWhenWaitSatisfied(): void
	{
		// Given: applied marker is at PHP_INT_MAX (setUp), so the wait returns instantly.
		// When/Then: write returns the published seq.
		$seq = pfb_unbound_py_write_control('enable');
		$this->assertSame(1, $seq);
		$this->assertSame(1, $this->readRecord()['seq']);
	}

	// --- write_control with wait NOT satisfied (marker low) -----------------

	public function testWriteControlReturnsSeqEvenWhenWaitTimesOut(): void
	{
		// Given: applied marker is below any seq the writer will publish.
		file_put_contents($this->channelApplied(), "0\n");

		// When: write with a small timeout so the wait times out quickly.
		// Then: STILL returns the published seq (the command IS on disk).
		$seq = pfb_unbound_py_write_control('enable', '', '', 0.4);
		$this->assertSame(1, $seq);

		// And: the channel record was written with the correct seq.
		$rec = $this->readRecord();
		$this->assertSame('enable', $rec['cmd']);
		$this->assertSame(1, $rec['seq']);
	}

	// --- write_control with wait_timeout = 0 (fire-and-forget) -------------

	public function testWriteControlSkipsWaitWhenTimeoutIsZero(): void
	{
		// Given: applied marker is NOT advanced (below any seq).
		file_put_contents($this->channelApplied(), "0\n");

		// When: write with $wait_timeout = 0 -- skip-wait path.
		// Then: returns the seq immediately without blocking.
		$seq = pfb_unbound_py_write_control('disable', '', '', 0);
		$this->assertSame(1, $seq);

		// And: the record is on disk.
		$rec = $this->readRecord();
		$this->assertSame('disable', $rec['cmd']);
		$this->assertSame(1, $rec['seq']);
	}

	// --- lock file ---------------------------------------------------------

	public function testLockFileExistsAfterSuccessfulWrite(): void
	{
		// Given: no lock file yet.
		$this->assertFileDoesNotExist("{$this->tmp}/pfb_py_control.lock");

		// When: a write succeeds (assert the seq so a FALSE return can't pass this test).
		$this->assertSame(1, pfb_unbound_py_write_control('enable'));

		// Then: the lock file was created.
		$this->assertFileExists("{$this->tmp}/pfb_py_control.lock");
	}

	// --- sequential writers advance the seq under the lock -----------------

	public function testTwoSequentialWritersAdvanceSeqCorrectly(): void
	{
		// Given: applied marker is high (setUp) so waits return immediately.
		// Note: true multi-process concurrency cannot be exercised in the unit sandbox;
		// this test proves the sequential case (lock does not break the normal advance).

		// When: first write.
		$seq1 = pfb_unbound_py_write_control('disable');

		// Then: seq is 1.
		$this->assertSame(1, $seq1);

		// When: second write.
		$seq2 = pfb_unbound_py_write_control('enable');

		// Then: seq strictly advances to 2, and the on-disk record reflects it.
		$this->assertSame(2, $seq2);
		$this->assertSame(2, $this->readRecord()['seq']);
	}
}
