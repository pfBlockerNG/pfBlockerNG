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
	}
}
