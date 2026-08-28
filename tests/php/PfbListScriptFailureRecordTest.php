<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1958: a per-feed pre-script that exits non-zero must not let the alias
 * pass close as full success. pfb_list_script_failure_record() is the single
 * write site for that: it opens a distinct ADR-61 stage='script' ledger entry
 * (separate from stage='download' -- the download itself genuinely succeeded)
 * and (re)writes the '.update' retry marker so the next ordinary pass still
 * attempts the transform instead of taking the verbatim-reuse fast path.
 *
 * issue #2059: the same write site serves the POST-script call sites via
 * pfb_list_post_script_failure_record(), which passes a NULL marker.
 *
 * Decision (brief section 5): production code suppresses the marker touch()
 * with '@' (matches the existing @rename/@copy best-effort idiom already used
 * for filesystem side-writes in this file). PfbNoPhpWarningTrait does NOT fit
 * here -- verified directly: a custom error handler registered for E_WARNING
 * still fires even when the triggering statement is '@'-prefixed (PHP only
 * drops E_WARNING from the bitmask error_reporting() reports to a *handler
 * that checks it*; the trait's handler collects unconditionally). So this
 * suite asserts the weaker, correct contract instead: no exception escapes,
 * and the ledger entry is opened regardless of whether the marker write
 * succeeded.
 */
#[CoversFunction('pfb_list_script_failure_record')]
final class PfbListScriptFailureRecordTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		// 0700 + random_bytes: a world-writable scratch dir under a shared /tmp,
		// named from the time-based uniqid(), is guessable and pre-creatable by
		// another local user. Mode asserted, never assumed.
		$this->dir = sys_get_temp_dir() . '/pfb_list_script_failure_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE), "failed to create the scratch dir {$this->dir}");
	}

	protected function tearDown(): void
	{
		// No chmod during cleanup: chmod() follows symlinks, so a planted entry
		// would retarget it. No test here creates a read-only fixture, so the
		// unlink alone is sufficient.
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	// -----------------------------------------------------------------------
	// Row 1/2 -- opens a stage='script' entry, per facility.
	// -----------------------------------------------------------------------

	public function testRecordsScriptStageEntryForIpFacility(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'Pre-script FAIL', $this->dir, $marker);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'a pre-script failure must open exactly one entry');
		$this->assertSame('ip', $open[0]['facility']);
		$this->assertSame('pfB_Example_v4', $open[0]['item']);
		$this->assertSame('script', $open[0]['stage']);
		$this->assertSame('Pre-script FAIL', $open[0]['message']);
	}

	public function testRecordsScriptStageEntryForDnsblFacility(): void
	{
		$marker = "{$this->dir}/DNSBL_Example.update";

		pfb_list_script_failure_record('dnsbl', 'DNSBL_Example', 'Pre-script FAIL', $this->dir, $marker);

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'a pre-script failure must open exactly one entry');
		$this->assertSame('dnsbl', $open[0]['facility']);
		$this->assertSame('DNSBL_Example', $open[0]['item']);
		$this->assertSame('script', $open[0]['stage']);
		$this->assertSame('Pre-script FAIL', $open[0]['message']);
	}

	// -----------------------------------------------------------------------
	// Row 3/4 -- retry marker created when absent, preserved when present.
	// -----------------------------------------------------------------------

	public function testRetryMarkerIsCreatedWhenAbsent(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		// Before-state: mandatory -- prove the marker did not already exist.
		$this->assertFileDoesNotExist($marker, 'before: the retry marker must not exist yet');

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'msg', $this->dir, $marker);

		$this->assertFileExists($marker, 'after: the retry marker must be created');
	}

	public function testRetryMarkerAlreadyPresentIsPreservedNotTruncated(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		file_put_contents($marker, 'pre-existing-marker-content');
		$this->assertFileExists($marker, 'before: the marker is pre-created with known content');

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'msg', $this->dir, $marker);

		$this->assertFileExists($marker, 'after: the marker must still exist');
		$this->assertSame('pre-existing-marker-content', file_get_contents($marker),
			'touch() must not truncate an already-present marker\'s content');
	}

	// -----------------------------------------------------------------------
	// issue #2059 -- a NULL marker opens the entry and touches nothing.
	// -----------------------------------------------------------------------

	public function testNullRetryMarkerOpensTheLedgerEntryAndCreatesNoMarker(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		$state  = ['failed' => FALSE];
		// Before-state: mandatory -- neither the entry nor the marker exists yet.
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'), 'before: the ledger has no open entry');
		$this->assertFileDoesNotExist($marker, 'before: no retry marker exists');

		pfb_list_script_failure_record('ip', 'pfB_Example_v4',
			'Post-script FAIL - feed updated, side effects incomplete', $this->dir, NULL, $state);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'a post-script failure must open exactly one entry');
		$this->assertSame('script', $open[0]['stage']);
		$this->assertSame('Post-script FAIL - feed updated, side effects incomplete', $open[0]['message']);
		$this->assertTrue($state['failed'],
			'the alias-pass state must be marked, else the paired close wipes the entry in the same pass');
		$this->assertFileDoesNotExist($marker, 'a NULL marker must create no retry marker at all');
	}

	public function testNullRetryMarkerLeavesAPreExistingMarkerUntouched(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		$stamp  = 1000000000;
		file_put_contents($marker, 'pre-existing-marker-content');
		// An unchanged mtime is the ONLY thing that discriminates "not touched"
		// from "touched": touch() never truncates, so content alone proves nothing.
		$this->assertTrue(touch($marker, $stamp), 'before: pin the marker mtime to a known past value');
		clearstatcache(TRUE, $marker);
		$this->assertSame($stamp, filemtime($marker), 'before: the pinned mtime must have taken');

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'Post-script FAIL', $this->dir, NULL);

		clearstatcache(TRUE, $marker);
		$this->assertSame('pre-existing-marker-content', file_get_contents($marker),
			'a NULL marker must leave an unrelated pre-existing marker byte-identical');
		$this->assertSame($stamp, filemtime($marker),
			'a NULL marker must not touch() the marker -- an unchanged mtime is the proof');
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'),
			'the ledger entry must still open when no marker is written');
	}

	public function testNullRetryMarkerRaisesNoTouchDiagnostic(): void
	{
		// Without the NULL guard the call degrades to '@touch(NULL)', which
		// coerces to '' and merely returns FALSE today -- but it raises
		// "touch(): Passing null to parameter #1" as an E_DEPRECATED that '@'
		// hides from output and PHP 9 promotes to a TypeError. A custom handler
		// still sees a suppressed diagnostic, so its absence is the only
		// observable that discriminates "skipped the touch" from "did it anyway".
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		}, E_DEPRECATED | E_WARNING);
		try {
			pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'Post-script FAIL', $this->dir, NULL);
		} finally {
			restore_error_handler();
		}

		$touch = array_values(array_filter($diagnostics,
			static fn (string $d): bool => str_contains($d, 'touch(')));
		$this->assertSame([], $touch,
			'a NULL marker must skip the touch() outright, raising no diagnostic: ' . implode('; ', $touch));
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'),
			'the ledger entry must still open');
	}

	// -----------------------------------------------------------------------
	// Row 5 -- the opened entry is closeable by the paired ADR-61 close.
	// -----------------------------------------------------------------------

	public function testOpenedEntryIsCloseableByThePairedClose(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'msg', $this->dir, $marker);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'), 'before: entry genuinely open');

		pfb_sync_status_close('ip', 'pfB_Example_v4', 'script', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'the paired pfb_sync_status_close(..., \'script\', ...) must close the entry this helper opened');
	}

	// -----------------------------------------------------------------------
	// Row 6 -- 'script' stage does not collide with an open 'download' entry
	// for the SAME item; closing 'script' leaves 'download' untouched.
	// -----------------------------------------------------------------------

	public function testScriptStageDoesNotCollideWithOpenDownloadEntry(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'download', 'Download FAIL', $this->dir);
		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'Pre-script FAIL', $this->dir, $marker);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(2, $open, 'both the download and script stage entries for the same item must coexist');
		$stages = array_column($open, 'stage');
		sort($stages);
		$this->assertSame(['download', 'script'], $stages);

		pfb_sync_status_close('ip', 'pfB_Example_v4', 'script', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'closing the script stage must leave the download entry untouched');
		$this->assertSame('download', $open[0]['stage']);
	}

	// -----------------------------------------------------------------------
	// Hostile row -- marker's parent directory does not exist: touch() fails,
	// but the ledger entry must still open, and no exception may escape.
	// -----------------------------------------------------------------------

	public function testMarkerParentDirectoryMissingStillOpensLedgerEntryWithoutException(): void
	{
		$missingDir = "{$this->dir}/nonexistent/nested";
		$marker     = "{$missingDir}/pfB_Example_v4.update";
		$this->assertDirectoryDoesNotExist($missingDir, 'before: the marker\'s parent directory must not exist');

		$caught = null;
		try {
			pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'Pre-script FAIL', $this->dir, $marker);
		} catch (\Throwable $e) {
			$caught = $e;
		}

		$this->assertNull($caught, 'a failed marker write must never throw/escape as an exception: ' . ($caught?->getMessage() ?? ''));
		$this->assertFileDoesNotExist($marker, 'the marker cannot exist -- its parent directory is absent');

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'ledger visibility must not depend on the marker write succeeding');
		$this->assertSame('script', $open[0]['stage']);
	}

	// -----------------------------------------------------------------------
	// Hostile row -- a message with HTML-special and sigil-looking bytes must
	// round-trip byte-identical through the ledger JSON (the widget applies
	// its own htmlspecialchars(); the ledger itself must not mangle anything).
	// -----------------------------------------------------------------------

	public function testMessageWithSpecialCharactersRoundTripsByteIdentical(): void
	{
		$marker  = "{$this->dir}/pfB_Example_v4.update";
		$message = 'Pre-script FAIL: <script>&"$HOME" `rm -rf /`';

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', $message, $this->dir, $marker);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open);
		$this->assertSame($message, $open[0]['message'],
			'the message must round-trip byte-identical through the ledger JSON -- no HTML-escaping at the ledger layer');
	}
}
