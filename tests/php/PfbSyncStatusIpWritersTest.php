<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 2 — IP-side sync-status writer/clearer pairs.
 *
 * Wires the three IP failure classes to the Phase-1 ledger, alongside their
 * EXISTING logging (never replacing it): feed download, dedup-sanity, pfctl
 * apply. Each pair is tested directly against its writer function -- the
 * download pair via the extracted pfb_ip_download_ledger_update() helper
 * (the download loop itself lives inside sync_package_pfblockerng(), too
 * heavy to invoke in a unit test), the dedup pair via the new
 * pfb_sync_status_dedup_check() reader, and the apply pair via
 * pfb_pfctl_table_op() itself using the SAME mock-pfctl-binary seam
 * PfctlTableOpTest already established ($pfctl_bin injection).
 *
 * Functions under test:
 *   pfb_ip_download_ledger_update(bool $download_ok, string $item, string $message,
 *                                   string $ledger_dir): void
 *   pfb_sync_status_dedup_check(string $log_path, string $ledger_dir): void
 *   pfb_pfctl_table_op(...) -- ledger open/close added alongside its existing
 *                              pfb_logger(..., 2) call (byte-identical, untouched).
 */
#[CoversFunction('pfb_ip_download_ledger_update')]
#[CoversFunction('pfb_sync_status_dedup_check')]
#[CoversFunction('pfb_pfctl_table_op')]
final class PfbSyncStatusIpWritersTest extends TestCase
{
	private string $dir;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var string[] temp files (mock pfctl scripts, dedup log fixtures) to remove in tearDown */
	private array $tmpfiles = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_ip_writers_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		// pfb_pfctl_table_op() reads $pfb['dbdir']/['log']/['errlog'] via `global $pfb;`
		// -- not injectable params -- so they must point at THIS test's private sandbox,
		// never the shared cross-test bootstrap tmp dir (order-independence).
		foreach (['dbdir', 'log', 'errlog'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$GLOBALS['pfb']['dbdir'] = $this->dir;
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		$this->saved = [];

		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];

		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	/** Write an executable POSIX-sh mock pfctl that exits $rc, emitting $stderr on fd 2.
	 *  Same seam PfctlTableOpTest::mock_pfctl() establishes ($pfctl_bin injection) --
	 *  reimplemented here because PHPUnit test classes cannot share a private method. */
	private function mockPfctl(int $rc, string $stderr): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_pfctl_mock_');
		$this->assertNotFalse($path, 'could not create temp mock pfctl script');
		$this->tmpfiles[] = $path;
		$stderr_esc = str_replace("'", "'\\''", $stderr);
		$this->assertNotFalse(
			file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' '{$stderr_esc}' >&2\nexit {$rc}\n"),
			"could not write mock pfctl script {$path}"
		);
		$this->assertTrue(chmod($path, 0755), "could not chmod mock pfctl script {$path} executable");
		return $path;
	}

	private function writeLog(string $contents): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_dedup_log_');
		$this->assertNotFalse($path, 'could not create temp dedup-log fixture');
		$this->tmpfiles[] = $path;
		file_put_contents($path, $contents);
		return $path;
	}

	// -----------------------------------------------------------------------
	// Pair 1 — feed download fail/success (pfb_ip_download_ledger_update)
	// -----------------------------------------------------------------------

	public function testDownloadFailureOpensEntry(): void
	{
		pfb_ip_download_ledger_update(FALSE, 'pfB_Example_v4', '[ pfB_Example_v4 - pfB_Example_v4 ] Download FAIL', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'a download failure must open exactly one entry');
		$this->assertSame('ip', $open[0]['facility']);
		$this->assertSame('pfB_Example_v4', $open[0]['item']);
		$this->assertSame('download', $open[0]['stage']);
		$this->assertStringContainsString('Download FAIL', $open[0]['message']);
	}

	public function testDownloadSuccessClosesEntry(): void
	{
		pfb_ip_download_ledger_update(FALSE, 'pfB_Example_v4', 'Download FAIL', $this->dir);
		// Before-state: the entry is genuinely open first, so the success close
		// below is a real transition, not a no-op that happens to leave zero entries.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_ip_download_ledger_update(TRUE, 'pfB_Example_v4', '', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'a paired download success must close the SAME key');
	}

	public function testDownloadFailureTwiceRefreshesWithoutDuplicating(): void
	{
		pfb_ip_download_ledger_update(FALSE, 'pfB_Example_v4', 'HTTP 404', $this->dir);
		pfb_ip_download_ledger_update(FALSE, 'pfB_Example_v4', 'HTTP 500', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'two consecutive failures on the SAME item must refresh, never duplicate');
		$this->assertSame('HTTP 500', $open[0]['message'], 'message must be the LATEST refresh');
	}

	public function testDownloadCallSitesKeyOnTheAliasNotTheHeader(): void
	{
		// Regression pin: pfb_ip_download_ledger_update() was called with $header (the
		// per-row label, e.g. "Feodo_v4" -- never pfB_/DNSBL_-prefixed) instead of
		// $alias (the actual table name, e.g. "pfB_Feodo_v4"). The widget's deep-link
		// recognition matches ONLY on that prefix (pfblockerng.widget.php), so keying
		// on $header silently drops the link for every download-fail entry.
		// sync_package_pfblockerng() itself has no PHPUnit harness (issue #993 -- it is
		// smoke-only), so this pins the exact call-site argument via source inspection
		// rather than a functional call: narrow, but it catches a regression of this
		// specific defect, which the function-level unit tests above cannot (they call
		// the helper directly with an already-correct item name).
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertNotFalse($source, 'pfblockerng.inc must be readable');

		$this->assertMatchesRegularExpression(
			'/pfb_ip_download_ledger_update\(FALSE, \$alias,/',
			$source,
			'the download-fail call must key on $alias, not $header, or the widget deep link breaks'
		);
		$this->assertMatchesRegularExpression(
			'/pfb_ip_download_ledger_update\(TRUE, \$alias,/',
			$source,
			'the paired success-close call must key on the SAME $alias for symmetry'
		);
	}

	/**
	 * Issue #1048: source-inspection pin -- the per-row download loop must never
	 * close the ledger entry directly from a row's success branch (that let a
	 * later feed's success mask an earlier feed's still-open failure); the close
	 * must be gated by the once-per-alias-pass $pfb_dl_failed flag instead. RED on
	 * pre-fix code: the per-row close call is present, the gated call is absent.
	 */
	public function testIpDownloadCloseFiresOncePerAliasPassNotPerRow(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertNotFalse($source, 'pfblockerng.inc must be readable');

		$this->assertDoesNotMatchRegularExpression(
			'/unlink_if_exists\("\{\$pfbfolder\}\/\{\$header\}\.fail"\);\s*\n\s*pfb_ip_download_ledger_update\(TRUE,/',
			$source,
			'a row\'s success branch must not close the download ledger directly -- masks a sibling row\'s failure'
		);
		$this->assertMatchesRegularExpression(
			'/if \(!\$pfb_dl_failed\) \{\s*\n\s*pfb_ip_download_ledger_update\(TRUE, \$alias, \'\', \$pfb\[\'dbdir\'\]\);/',
			$source,
			'the close call must be gated by the once-per-alias-pass $pfb_dl_failed flag'
		);
	}

	/**
	 * Mirrors the row-loop's per-alias-pass contract (issue #1048): the FALSE
	 * (open) ledger call fires per failing row, and the TRUE (close) call fires
	 * ONCE after all rows -- iff none failed. Drives the REAL production ledger
	 * helper in the exact call pattern the fixed loop now follows
	 * (sync_package_pfblockerng() itself has no PHPUnit harness -- too heavy to
	 * invoke, see testDownloadCallSitesKeyOnTheAliasNotTheHeader's docblock --
	 * so this is the primary functional proof of the contract, supplemented by
	 * the source-inspection pin above).
	 *
	 * @param bool[] $rowOutcomes TRUE = row succeeded, FALSE = row failed, in order.
	 */
	private function runIpAliasPass(string $alias, array $rowOutcomes): void
	{
		$failed = FALSE;
		foreach ($rowOutcomes as $i => $ok) {
			if (!$ok) {
				$failed = TRUE;
				pfb_ip_download_ledger_update(FALSE, $alias, "[ {$alias} - row{$i} ] Download FAIL", $this->dir);
			}
		}
		if (!$failed) {
			pfb_ip_download_ledger_update(TRUE, $alias, '', $this->dir);
		}
	}

	public function testAliasPassFailThenSucceedLeavesEntryOpen(): void
	{
		$this->runIpAliasPass('pfB_Example_v4', [FALSE, TRUE]);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'),
			'a failing row followed by a succeeding sibling row must leave the entry OPEN -- a per-row close would mask this'
		);
	}

	public function testAliasPassSucceedThenFailLeavesEntryOpen(): void
	{
		$this->runIpAliasPass('pfB_Example_v4', [TRUE, FALSE]);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'),
			'a succeeding row followed by a failing sibling row must leave the entry OPEN'
		);
	}

	public function testAliasPassAllSuccessMultiFeedClosesEntry(): void
	{
		// Before-state: genuinely open first, so the close below is a real transition.
		$this->runIpAliasPass('pfB_Example_v4', [FALSE]);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		$this->runIpAliasPass('pfB_Example_v4', [TRUE, TRUE, TRUE]);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'an all-success multi-feed pass must close the entry'
		);
	}

	public function testAliasPassSingleFeedFailOpensEntry(): void
	{
		$this->runIpAliasPass('pfB_Example_v4', [FALSE]);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'),
			'a single-feed alias with one failing row must open the entry'
		);
	}

	public function testAliasPassSingleFeedSuccessClosesEntry(): void
	{
		// Before-state: genuinely open first (regression pin for the pre-#1048 behaviour).
		$this->runIpAliasPass('pfB_Example_v4', [FALSE]);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		$this->runIpAliasPass('pfB_Example_v4', [TRUE]);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'a single-feed alias with its one row succeeding must close the entry (regression)'
		);
	}

	public function testAliasPassAllReusedClosesPreviouslyOpenEntry(): void
	{
		// Before-state: genuinely open first.
		$this->runIpAliasPass('pfB_Example_v4', [FALSE]);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		// An all-reused pass makes ZERO ledger calls inside the loop (no row ever
		// hits the download branch) -- $pfb_dl_failed stays FALSE the whole pass,
		// so the post-loop close still fires.
		$this->runIpAliasPass('pfB_Example_v4', []);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'an all-reused pass (zero download attempts) must still close a previously-open entry'
		);
	}

	// -----------------------------------------------------------------------
	// Pair 2 — dedup sanity FAILED/PASSED (pfb_sync_status_dedup_check)
	// -----------------------------------------------------------------------

	public function testDedupSanityFailedLineOpensEntry(): void
	{
		$log = $this->writeLog("some other log line\nDatabase Sanity check [  FAILED  ] ** These two counts should match! **\n");

		pfb_sync_status_dedup_check($log, $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'a FAILED sanity-check line must open the dedup entry');
		$this->assertSame('dedup', $open[0]['item']);
		$this->assertSame('dedup', $open[0]['stage']);
		$this->assertStringContainsString('FAILED', $open[0]['message']);
	}

	public function testDedupSanityPassedLineClosesEntry(): void
	{
		$failLog = $this->writeLog("Database Sanity check [  FAILED  ] ** These two counts should match! **\n");
		pfb_sync_status_dedup_check($failLog, $this->dir);
		// Before-state: genuinely open first.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		$passLog = $this->writeLog("Database Sanity check [  PASSED  ]\n");
		pfb_sync_status_dedup_check($passLog, $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'a later PASSED sanity-check line must close the SAME dedup key');
	}

	public function testDedupSanityNoLineRecordedIsNoOp(): void
	{
		$log = $this->writeLog("nothing relevant here\n");

		pfb_sync_status_dedup_check($log, $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'no sanity-check line ever recorded must not open a false entry');
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_status.json',
			'a no-signal-yet log must not even create the ledger file');
	}

	public function testDedupSanityLastLineWinsOverAnEarlierOppositeLine(): void
	{
		// tail -1 semantics: an earlier PASSED followed by a later FAILED -> FAILED wins.
		$log = $this->writeLog(
			"Database Sanity check [  PASSED  ]\n" .
			"Database Sanity check [  FAILED  ] ** These two counts should match! **\n"
		);

		pfb_sync_status_dedup_check($log, $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'the LAST sanity-check line in the log must win, matching the widget\'s tail -1 read');
	}

	/**
	 * Issue #1052: pfb_sync_status_dedup_check() must not @file() the WHOLE
	 * pfblockerng.log into memory -- a 'nolimit' log has no size cap. A
	 * several-MB multi-chunk log with the Sanity check line near the end
	 * (within the bounded tail window) must resolve the SAME verdict as a
	 * small log, AND the memory_get_peak_usage(true) delta must stay far
	 * below the file size -- the old @file()-array approach scales its
	 * memory with file size, the bounded-tail read does not (same proof
	 * shape as LogAgeCutoffStreamTest::testStreamingTrimStaysMemoryBounded...).
	 * Bound justification: the old @file()-array approach costs a +7,065,600
	 * byte (~6.7 MiB) memory_get_peak_usage(true) delta on this exact fixture;
	 * the bounded-tail read costs ~0. The bound is 4 MiB, not 1: (true) reports
	 * real memory in 2 MiB emalloc chunks, so the bounded read shows either 0
	 * or one 2 MiB chunk depending on where $memBefore sits relative to a chunk
	 * boundary -- 4 MiB clears that quantization noise yet stays well under the
	 * ~6.7 MiB old cost, keeping old-code-fails / new-code-passes cleanly split.
	 * issue #1255: the old 1 MiB bound flaked on PHP 8.5 when an unrelated
	 * baseline shift tipped $memBefore across a chunk boundary.
	 */
	#[RunInSeparateProcess]
	public function testDedupSanityCheckStaysMemoryBoundedOnLargeLog(): void
	{
		$log = tempnam(sys_get_temp_dir(), 'pfb_dedup_big_log_');
		$this->tmpfiles[] = $log;

		$fh = fopen($log, 'w');
		// ~3 MiB of filler lines (well outside the 64 KiB tail window) before
		// the sanity line -- proves only the trailing window is ever read.
		for ($i = 0; $i < 40000; $i++) {
			fwrite($fh, 'filler line number ' . $i . ' of irrelevant log content padding out the file' . "\n");
		}
		fwrite($fh, "Database Sanity check [  FAILED  ] ** These two counts should match! **\n");
		fclose($fh);

		clearstatcache(TRUE, $log);
		$this->assertGreaterThan(1_000_000, filesize($log), 'Before: fixture must be several MB');

		gc_collect_cycles();
		$memBefore = memory_get_peak_usage(TRUE);

		pfb_sync_status_dedup_check($log, $this->dir);

		$memDelta = memory_get_peak_usage(TRUE) - $memBefore;

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'a FAILED sanity-check line within the tail window must open the dedup entry, got '
			. var_export($open, true));
		$this->assertStringContainsString('FAILED', $open[0]['message']);

		$this->assertLessThan(4 * 1024 * 1024, $memDelta,
			"dedup check's memory_get_peak_usage(true) delta must stay under 4 MiB on a several-MB log, got {$memDelta} bytes"
		);
	}

	// -----------------------------------------------------------------------
	// Pair 3 — IP pfctl apply fail/success (pfb_pfctl_table_op)
	// -----------------------------------------------------------------------

	public function testPfctlApplyFailureOpensEntry(): void
	{
		$pfctl_bin = $this->mockPfctl(1, 'pfctl: EINVAL');

		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $pfctl_bin);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'an attributed pfctl failure must open an apply entry');
		$this->assertSame('pfB_Test_v4', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
		$this->assertStringContainsString('op=replace', $open[0]['message']);
	}

	public function testPfctlApplySuccessClosesEntry(): void
	{
		$fail_bin = $this->mockPfctl(1, 'pfctl: EINVAL');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $fail_bin);
		// Before-state: genuinely open first.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		$ok_bin = $this->mockPfctl(0, '');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $ok_bin);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'a subsequent clean pfctl apply for the SAME table must close the entry');
	}

	public function testPfctlApplyFailureTwiceRefreshesWithoutDuplicating(): void
	{
		$bin1 = $this->mockPfctl(1, 'pfctl: EINVAL');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $bin1);

		$bin2 = $this->mockPfctl(2, 'pfctl: permission denied');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $bin2);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'two consecutive pfctl failures on the SAME table must refresh, never duplicate');
		$this->assertStringContainsString('permission denied', $open[0]['message'], 'message must be the LATEST refresh');
	}

	public function testPfctlApplyFailureLoggingLevelUnchanged(): void
	{
		// Kill-gate rehearsal: the EXISTING pfb_logger(..., 2) call this phase adds
		// the ledger write alongside must remain untouched (issue #980 / PR #987).
		$log    = tempnam(sys_get_temp_dir(), 'pfb_log_');
		$errlog = tempnam(sys_get_temp_dir(), 'pfb_errlog_');
		$this->tmpfiles[] = $log;
		$this->tmpfiles[] = $errlog;
		$GLOBALS['pfb']['log']    = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;
		$pfctl_bin = $this->mockPfctl(1, 'pfctl: EINVAL');

		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $pfctl_bin);

		$this->assertStringContainsString('op=replace', (string) file_get_contents($errlog),
			'the pfctl failure must still reach error.log at level 2, unchanged by this phase');
	}
}
