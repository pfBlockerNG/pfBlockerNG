<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfBlockerNG "pending changes" flag — mark/settle/pending lifecycle.
 *
 * A save on a deferred settings page (DNSBL/IP/Feeds) marks pending changes; a real Update pass
 * applies them; the GUI banner shows iff changes are pending. Each mark writes a fresh version
 * into the PERSISTED marker file at $pfb['pending_marker'] (/usr/local/etc — survives a
 * RAM-disk-/var reboot, since pfBlockerNG restores its cache on boot rather than re-applying
 * config, so a still-unapplied change must stay flagged). A pass records the version it saw at
 * its start as applied, and changes are pending while the marker holds any other version
 * (#3481): the pass never deletes the marker, so a save during the pass cannot be lost.
 *
 * Also pins the deinstall-side clear (#738 F7, pfb_deinstall_clear_pending_changes()): the
 * update-end settle only runs on `!$pfb['save']`, which the pre-deinstall disable pass never
 * satisfies, so nothing else removed the pending state and it survived `pkg delete` into a later
 * reinstall. pfblockerng_php_pre_deinstall_command() itself cannot be driven off-appliance (it
 * runs a full sync_package_pfblockerng() pass plus pfctl/exec teardown), so this pins the
 * extracted clear helper it calls in isolation.
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
		array_map('unlink', glob("{$this->tmpdir}/*") ?: []);
		@rmdir($this->tmpdir);
		if ($this->savedMarker === null) {
			unset($GLOBALS['pfb']['pending_marker']);
		} else {
			$GLOBALS['pfb']['pending_marker'] = $this->savedMarker;
		}
	}

	/** @return list<string> every entry in the marker's directory */
	private function entries(): array
	{
		return array_values(array_diff(scandir($this->tmpdir), ['.', '..']));
	}

	public function testLifecycleCleanThenDirtyThenClean(): void
	{
		// Given no pending changes
		$this->assertFalse(pfb_pending_changes(), 'flag must start clean');

		// When a deferred settings save marks pending changes
		pfb_mark_pending_changes();

		// Then the banner condition is true and the persisted marker exists
		$this->assertTrue(pfb_pending_changes(), 'mark must set the pending flag');
		$this->assertFileExists($this->marker, 'mark must create the persisted marker file');

		// When a real Update pass applies the version it saw
		pfb_settle_pending_changes(pfb_pending_changes_token());

		// Then it is clean again
		$this->assertFalse(pfb_pending_changes(), 'the pass must reset the pending flag');
	}

	/**
	 * #738 F7: stale pending state must not survive a genuine uninstall. Before this helper
	 * existed, nothing on the deinstall path removed it (the update-end settle is gated on
	 * `!$pfb['save']`, which the deinstall disable pass never satisfies), so a reinstall showed a
	 * false "pending changes" banner until the first real Update.
	 */
	public function testDeinstallHelperClearsStaleMarker(): void
	{
		// Given an applied version and a newer pending mark
		pfb_mark_pending_changes();
		pfb_settle_pending_changes(pfb_pending_changes_token());
		pfb_mark_pending_changes();
		$this->assertTrue(pfb_pending_changes(), 'setup: a mark must be pending before the deinstall clear');

		// When the deinstall path's clear helper runs
		pfb_deinstall_clear_pending_changes();

		// Then nothing is left behind -- a later reinstall must start clean
		$this->assertFalse(pfb_pending_changes(), 'deinstall clear must reset the pending flag');
		$this->assertSame([], $this->entries(), 'deinstall clear must remove every pending-state file');
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

	public function testTokenIsNullWithoutAMarker(): void
	{
		$this->assertNull(pfb_pending_changes_token(), 'no marker, no token');
	}

	/**
	 * Given a pre-upgrade (or touched) empty marker
	 * When a pass reads its token and settles it
	 * Then the marker is versioned first, so the pass applies it like any other mark
	 */
	public function testALegacyEmptyMarkerIsVersionedAndSettles(): void
	{
		touch($this->marker);
		$this->assertTrue(pfb_pending_changes(), 'before-state check: an empty marker is pending');

		$seen = pfb_pending_changes_token();
		$this->assertNotSame('', $seen, 'the pass reads a real version, never the empty one');
		pfb_settle_pending_changes($seen);

		$this->assertFalse(pfb_pending_changes(), 'the pass applied it');
		touch($this->marker);
		$this->assertFalse(pfb_pending_changes(), 'touching the applied marker changes nothing');
	}

	public function testSettleAppliesTheSeenVersion(): void
	{
		pfb_mark_pending_changes();
		$seen = pfb_pending_changes_token();

		pfb_settle_pending_changes($seen);

		$this->assertFalse(pfb_pending_changes(), 'the version the pass saw is applied');
	}

	public function testSettlingAnAlreadyAppliedVersionDoesNotRewriteIt(): void
	{
		pfb_mark_pending_changes();
		$seen = pfb_pending_changes_token();
		pfb_settle_pending_changes($seen);
		touch($this->marker . '.applied', 1000000000);
		clearstatcache();

		pfb_settle_pending_changes($seen);
		clearstatcache();

		$this->assertSame(1000000000, filemtime($this->marker . '.applied'), 'a routine pass with nothing new must not write persistent storage');
		$this->assertFalse(pfb_pending_changes(), 'and nothing is pending');
	}

	public function testSettleKeepsAMarkTakenAfterTheToken(): void
	{
		pfb_mark_pending_changes();
		$seen = pfb_pending_changes_token();
		pfb_mark_pending_changes();
		$newer = pfb_pending_changes_token();
		$this->assertNotSame($seen, $newer, 'before-state check: the marker was re-marked since');

		pfb_settle_pending_changes($seen);

		$this->assertTrue(pfb_pending_changes(), 'a mark taken after the seen token stays pending');
		$this->assertSame($newer, pfb_pending_changes_token(), 'and the marker still holds it');
	}

	public function testAMarkAfterASettleIsPendingAgain(): void
	{
		pfb_mark_pending_changes();
		pfb_settle_pending_changes(pfb_pending_changes_token());
		$this->assertFalse(pfb_pending_changes(), 'before-state check: settled');

		pfb_mark_pending_changes();

		$this->assertTrue(pfb_pending_changes(), 'a new save is pending again');
	}

	public function testSettleWithoutASeenTokenKeepsTheMarker(): void
	{
		pfb_mark_pending_changes();

		pfb_settle_pending_changes(NULL);

		$this->assertTrue(pfb_pending_changes(), 'a pass that saw no mark applies none');
	}

	public function testSettleWithoutAMarkerLeavesNothingPending(): void
	{
		pfb_settle_pending_changes('gone');

		$this->assertFalse(pfb_pending_changes(), 'no marker, nothing pending');
	}

	public function testAnEmptyMarkerIsPendingEvenAgainstAnEmptyAppliedVersion(): void
	{
		// what two failed writes (full disk) leave: a truncated mark after a truncated settle
		file_put_contents($this->marker, '');
		file_put_contents($this->marker . '.applied', '');

		$this->assertTrue(pfb_pending_changes(), 'an unversioned marker is always pending, so a pass versions and applies it');
	}

	public function testTheTokenIsComparedVerbatim(): void
	{
		file_put_contents($this->marker, "token\n");

		pfb_settle_pending_changes('token');
		$this->assertTrue(pfb_pending_changes(), 'trailing bytes are part of the token: no trimming');

		pfb_settle_pending_changes("token\n");
		$this->assertFalse(pfb_pending_changes(), 'the exact content is applied');
	}

	/**
	 * Given a pass settling the version it saw at its start
	 * When a save marks pending right after ANY filesystem step of that settle (a slow disk, a scheduler gap)
	 * Then the save is still pending afterwards: no step of the settle can discard a newer mark
	 */
	public function testAMarkLandingAtAnyStepOfASettleStaysPending(): void
	{
		$GLOBALS['pfb']['pending_marker'] = 'pfbrace://' . $this->marker;
		stream_wrapper_register('pfbrace', PendingMarkerRaceStream::class);
		try {
			for ($step = 1; ; $step++) {
				array_map('unlink', glob("{$this->tmpdir}/*") ?: []);
				pfb_mark_pending_changes();
				$seen = pfb_pending_changes_token();

				PendingMarkerRaceStream::arm($step, $this->marker);
				pfb_settle_pending_changes($seen);
				if (!PendingMarkerRaceStream::disarm()) {
					break;
				}
				$this->assertTrue(pfb_pending_changes(), "a save landing after step {$step} of the settle must stay pending");
			}
		} finally {
			stream_wrapper_unregister('pfbrace');
		}
		$this->assertGreaterThan(1, $step, 'before-state check: the settle took at least one filesystem step');
	}
}

/** Passes pfbrace://<path> through to <path>; when armed, writes a concurrent mark right after the Nth completed step. */
final class PendingMarkerRaceStream
{
	/** @var resource|null */
	public $context;
	/** @var resource|null */
	private $fp;
	private static int $fireAt = 0;
	private static int $steps = 0;
	private static bool $fired = FALSE;
	private static string $marker = '';

	public static function arm(int $step, string $marker): void
	{
		[self::$fireAt, self::$steps, self::$fired, self::$marker] = [$step, 0, FALSE, $marker];
	}

	public static function disarm(): bool
	{
		self::$fireAt = 0;
		return self::$fired;
	}

	private static function step(): void
	{
		if (self::$fireAt > 0 && ++self::$steps === self::$fireAt) {
			self::$fired = TRUE;
			file_put_contents(self::$marker, 'concurrent-save');
		}
	}

	private static function real(string $url): string
	{
		return substr($url, strlen('pfbrace://'));
	}

	public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
	{
		$this->fp = @fopen(self::real($path), $mode) ?: NULL;
		return $this->fp !== NULL;
	}

	public function stream_read(int $count): string|false
	{
		return fread($this->fp, $count);
	}

	public function stream_write(string $data): int
	{
		return (int) fwrite($this->fp, $data);
	}

	public function stream_eof(): bool
	{
		return feof($this->fp);
	}

	public function stream_stat(): array|false
	{
		return fstat($this->fp);
	}

	public function stream_lock(int $operation): bool
	{
		return flock($this->fp, $operation);
	}

	public function stream_close(): void
	{
		fclose($this->fp);
		self::step();
	}

	// The step runs BEFORE the unlink: a save landing just before a delete is the interleaving that loses it.
	public function unlink(string $path): bool
	{
		self::step();
		return @unlink(self::real($path));
	}
}
