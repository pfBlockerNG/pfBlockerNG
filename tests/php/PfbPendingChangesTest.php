<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfBlockerNG "pending changes" flag — mark/clear/pending lifecycle.
 *
 * A save on a deferred settings page (DNSBL/IP/Feeds) marks pending changes; a real Update pass
 * clears them; the GUI banner shows iff the flag is set. The flag is a PERSISTED marker file at
 * $pfb['pending_marker'] (/usr/local/etc — survives a RAM-disk-/var reboot, since pfBlockerNG
 * restores its cache on boot rather than re-applying config, so a still-unapplied change must stay
 * flagged). This pins the three-state lifecycle (clean -> dirty -> clean) and that the marker
 * really is the file at $pfb['pending_marker'].
 *
 * Also pins the deinstall-side clear (#738 F7, pfb_deinstall_clear_pending_changes()): the
 * update-end guard above only fires on `!$pfb['save']`, which the pre-deinstall disable pass
 * never satisfies, so nothing else unlinked the marker and it survived `pkg delete` into a later
 * reinstall. pfblockerng_php_pre_deinstall_command() itself cannot be driven off-appliance (it
 * runs a full sync_package_pfblockerng() pass plus pfctl/exec teardown), so this pins the
 * extracted clear helper it calls in isolation; that the helper is actually reached only past the
 * #697 non-delete early return is validated live (issue #738 F7 is a pending live-VM uninstall
 * check).
 */
#[CoversFunction('pfb_mark_pending_changes')]
#[CoversFunction('pfb_clear_pending_changes')]
#[CoversFunction('pfb_pending_changes')]
#[CoversFunction('pfb_pending_changes_marker')]
#[CoversFunction('pfb_deinstall_clear_pending_changes')]
#[CoversFunction('pfb_pending_changes_token')]
#[CoversFunction('pfb_settle_pending_changes')]
final class PfbPendingChangesTest extends TestCase
{
	private string $tmpdir;
	private string $marker;
	private mixed $savedMarker;

	protected function setUp(): void
	{
		// Point the marker at a private temp path so the test is self-encapsulated and
		// never touches the real /usr/local/etc location.
		$this->tmpdir = sys_get_temp_dir() . '/pfb_pending_' . uniqid('', true);
		mkdir($this->tmpdir, 0o755, true);
		$this->marker = "{$this->tmpdir}/pfb_pending_changes";
		$this->savedMarker = $GLOBALS['pfb']['pending_marker'] ?? null;
		$GLOBALS['pfb']['pending_marker'] = $this->marker;
	}

	protected function tearDown(): void
	{
		@unlink($this->marker);
		@unlink($this->marker . '.lock');
		@rmdir($this->tmpdir);
		if ($this->savedMarker === null) {
			unset($GLOBALS['pfb']['pending_marker']);
		} else {
			$GLOBALS['pfb']['pending_marker'] = $this->savedMarker;
		}
	}

	public function testLifecycleCleanThenDirtyThenClean(): void
	{
		$marker = $this->marker;

		// Given no pending changes
		$this->assertFalse(pfb_pending_changes(), 'flag must start clean');
		$this->assertFileDoesNotExist($marker, 'no marker file before any save');

		// When a deferred settings save marks pending changes
		pfb_mark_pending_changes();

		// Then the banner condition is true and the persisted marker exists
		$this->assertTrue(pfb_pending_changes(), 'mark must set the pending flag');
		$this->assertFileExists($marker, 'mark must create the persisted marker file');

		// When a real Update pass clears it
		pfb_clear_pending_changes();

		// Then it is clean again (the deferred changes have been applied)
		$this->assertFalse(pfb_pending_changes(), 'clear must reset the pending flag');
		$this->assertFileDoesNotExist($marker, 'clear must remove the marker file');
	}

	/**
	 * #738 F7: a stale marker must not survive a genuine uninstall. Before this helper existed,
	 * nothing on the deinstall path unlinked the marker (the update-end guard is gated on
	 * `!$pfb['save']`, which the deinstall disable pass never satisfies), so a reinstall showed a
	 * false "pending changes" banner until the first real Update.
	 */
	public function testDeinstallHelperClearsStaleMarker(): void
	{
		$marker = $this->marker;

		// Given a pending marker left over from an earlier deferred save
		pfb_mark_pending_changes();
		$this->assertFileExists($marker, 'setup: marker must exist before the deinstall clear');

		// When the deinstall path's clear helper runs
		pfb_deinstall_clear_pending_changes();

		// Then the marker is gone -- it must never survive a genuine uninstall
		$this->assertFalse(pfb_pending_changes(), 'deinstall clear must reset the pending flag');
		$this->assertFileDoesNotExist(
			$marker,
			'deinstall clear must remove the marker file so a later reinstall starts clean'
		);
		$this->assertFileDoesNotExist($marker . '.lock', 'and its lock file, so an uninstall leaves nothing behind');
	}

	/** @return list<string> every entry in the marker's directory */
	private function entries(): array
	{
		return array_values(array_diff(scandir($this->tmpdir), ['.', '..']));
	}

	/**
	 * Given two marks
	 * When each is read back
	 * Then every mark wrote its own non-empty token, so a later mark is distinguishable from an earlier one
	 */
	public function testEveryMarkWritesItsOwnToken(): void
	{
		pfb_mark_pending_changes();
		$first = (string) file_get_contents($this->marker);
		pfb_mark_pending_changes();
		$second = (string) file_get_contents($this->marker);

		$this->assertTrue(pfb_pending_changes(), 'a mark sets the pending flag');
		$this->assertNotSame('', $first, 'a mark writes a token');
		$this->assertNotSame($first, $second, 'a second mark writes a different token');
	}

	public function testTokenIsNullWithoutAMarkerAndEmptyForALegacyMarker(): void
	{
		$this->assertNull(pfb_pending_changes_token(), 'no marker, no token');

		touch($this->marker);	// what a pre-upgrade mark left behind

		$this->assertSame('', pfb_pending_changes_token(), 'an empty marker file is a valid token');
	}

	public function testSettleClearsTheMarkerHoldingTheSeenToken(): void
	{
		pfb_mark_pending_changes();
		$seen = pfb_pending_changes_token();
		$this->assertNotNull($seen, 'before-state check: the mark was seen');

		pfb_settle_pending_changes($seen);

		$this->assertFileDoesNotExist($this->marker, 'the marker still held the seen token, so it is cleared');
	}

	public function testSettleKeepsTheMarkerAMarkReplacedAfterTheToken(): void
	{
		pfb_mark_pending_changes();
		$seen = pfb_pending_changes_token();
		pfb_mark_pending_changes();
		$newer = pfb_pending_changes_token();
		$this->assertNotSame($seen, $newer, 'before-state check: the marker was re-marked since');

		pfb_settle_pending_changes($seen);

		$this->assertFileExists($this->marker, 'a mark taken after the seen token must survive the settle');
		$this->assertSame($newer, pfb_pending_changes_token(), 'and it still holds the newer token');
	}

	public function testSettleWithoutASeenTokenKeepsTheMarker(): void
	{
		pfb_mark_pending_changes();
		$token = pfb_pending_changes_token();

		pfb_settle_pending_changes(NULL);

		$this->assertSame($token, pfb_pending_changes_token(), 'a pass that saw no mark clears none');
	}

	public function testSettleWithoutAMarkerChangesNothing(): void
	{
		$this->assertSame([], $this->entries(), 'before-state check: the directory is empty');

		pfb_settle_pending_changes('gone');

		$this->assertSame([], array_diff($this->entries(), ['pfb_pending_changes.lock']), 'a marker removed between the read and the settle is not recreated');
	}

	public function testSettleClearsAnUnchangedLegacyEmptyMarker(): void
	{
		touch($this->marker);
		$seen = pfb_pending_changes_token();
		$this->assertSame('', $seen, 'before-state check: the legacy marker reads as the empty token');

		pfb_settle_pending_changes($seen);

		$this->assertFileDoesNotExist($this->marker, 'an unchanged legacy marker is cleared');
	}

	public function testTheTokenIsComparedVerbatim(): void
	{
		file_put_contents($this->marker, "token\n");

		pfb_settle_pending_changes('token');
		$this->assertFileExists($this->marker, 'trailing bytes are part of the token: no trimming');

		pfb_settle_pending_changes("token\n");
		$this->assertFileDoesNotExist($this->marker, 'the exact content clears it');
	}

	/**
	 * Given a mark in progress (holding the marker's lock, as pfb_mark_pending_changes() does)
	 * When a pass settles the token it saw at its start
	 * Then the settle waits for the mark and keeps the marker it wrote, instead of deleting it between its compare and its clear
	 */
	public function testSettleWaitsForAMarkInProgressAndKeepsIt(): void
	{
		pfb_mark_pending_changes();
		$seen = pfb_pending_changes_token();
		$lock = fopen($this->marker . '.lock', 'c');
		$this->assertTrue(flock($lock, LOCK_EX), 'before-state check: the test holds the mark lock');

		$pid = pcntl_fork();
		$this->assertNotSame(-1, $pid, 'before-state check: fork succeeded');
		if ($pid === 0) {
			pfb_settle_pending_changes($seen);
			exit(0);
		}
		usleep(300000);
		clearstatcache();
		$settledEarly = !file_exists($this->marker);
		file_put_contents($this->marker, 'newer');
		flock($lock, LOCK_UN);
		fclose($lock);
		pcntl_waitpid($pid, $status);

		$this->assertFalse($settledEarly, 'the settle must not clear the marker while a mark holds the lock');
		$this->assertSame('newer', pfb_pending_changes_token(), 'the mark written under the lock survives the settle');
	}

	public function testAMarkWaitsForASettleInProgress(): void
	{
		file_put_contents($this->marker, 'seen');
		$lock = fopen($this->marker . '.lock', 'c');
		$this->assertTrue(flock($lock, LOCK_EX), 'before-state check: the test holds the lock a settle holds');

		$pid = pcntl_fork();
		$this->assertNotSame(-1, $pid, 'before-state check: fork succeeded');
		if ($pid === 0) {
			pfb_mark_pending_changes();
			exit(0);
		}
		usleep(300000);
		$during = (string) file_get_contents($this->marker);
		unlink($this->marker);	// the settle's clear
		flock($lock, LOCK_UN);
		fclose($lock);
		pcntl_waitpid($pid, $status);

		$this->assertSame('seen', $during, 'a mark must not write while a settle holds the lock');
		$this->assertNotNull(pfb_pending_changes_token(), 'the mark lands after the settle, so it survives');
	}

	public function testTheTokenReadWaitsForAMarkInProgress(): void
	{
		file_put_contents($this->marker, '');	// a mark mid-write: truncated, token not yet written
		$lock = fopen($this->marker . '.lock', 'c');
		$this->assertTrue(flock($lock, LOCK_EX), 'before-state check: the test holds the lock a mark holds');

		$pid = pcntl_fork();
		$this->assertNotSame(-1, $pid, 'before-state check: fork succeeded');
		if ($pid === 0) {
			file_put_contents($this->marker . '.out', (string) pfb_pending_changes_token());
			exit(0);
		}
		usleep(300000);
		file_put_contents($this->marker, 'newer');
		flock($lock, LOCK_UN);
		fclose($lock);
		pcntl_waitpid($pid, $status);
		$read = (string) file_get_contents($this->marker . '.out');
		unlink($this->marker . '.out');

		$this->assertSame('newer', $read, 'a pass must not capture a half-written token, which would never settle');
	}
}
