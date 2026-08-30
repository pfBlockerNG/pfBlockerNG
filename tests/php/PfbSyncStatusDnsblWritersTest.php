<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 3 (+ #998 follow-up) — DNSBL-side sync-status writer/clearer pairs.
 *
 * The apply-stage decision (pfb_dnsbl_apply_ledger_update(), built on
 * pfb_dnsbl_converged()) is tested directly for the open/close/refresh
 * contract, and separately end-to-end through the REAL pfb_reload_unbound()
 * to prove its swap-not-confirmed restart-fallback path reaches the shared
 * tail and converges (ADR SS1.3: "NOT an error: fail-safe by design"). That
 * the three restart-fallback branches never call a ledger function directly
 * is a SEPARATE, source-inspection-only invariant (the tail's write is
 * deterministic/idempotent-by-key, so no end-state assertion can prove it) --
 * see testRestartFallbackBranchesNeverCallLedgerFunctionsDirectly. The
 * feed-download pair (pfb_dnsbl_download_ledger_update()) mirrors the IP
 * side's PfbSyncStatusIpWritersTest Pair 1.
 *
 * Functions under test:
 *   pfb_dnsbl_apply_ledger_update(): void
 *   pfb_reload_unbound(...) -- the zero-downtime swap + restart-fallback paths.
 *   pfb_dnsbl_download_ledger_update(bool $download_ok, string $item, string $message,
 *                                      string $ledger_dir): void
 */
#[CoversFunction('pfb_dnsbl_apply_ledger_update')]
#[CoversFunction('pfb_reload_unbound')]
#[CoversFunction('pfb_dnsbl_download_ledger_update')]
final class PfbSyncStatusDnsblWritersTest extends TestCase
{
	private string $dir;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $savedPfb = [];

	/** @var array<string,mixed> saved $GLOBALS['g'] keys */
	private array $savedG = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_dnsbl_writers_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		foreach (['dnsbldir', 'dbdir', 'dnsbl_file', 'unbound_py_count', 'chroot_cmd',
			  'dnsbl_python_unmount', 'log', 'errlog'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		foreach (['varrun_path'] as $k) {
			$this->savedG[$k] = array_key_exists($k, $GLOBALS['g'] ?? []) ? $GLOBALS['g'][$k] : false;
		}

		$GLOBALS['pfb']['dnsbldir'] = $this->dir;
		$GLOBALS['pfb']['dbdir']    = $this->dir;
		$GLOBALS['pfb']['log']      = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']   = "{$this->dir}/error.log";
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
	}

	protected function tearDown(): void
	{
		// dnsbldir may have been chmod'd read-only by testRestartFallback... --
		// restore write permission BEFORE cleanup can unlink anything inside it.
		@chmod($this->dir, 0777);

		foreach ($this->savedPfb as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		$this->savedPfb = [];
		foreach ($this->savedG as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['g'][$k]);
			} else {
				$GLOBALS['g'][$k] = $prev;
			}
		}
		$this->savedG = [];
		unset($GLOBALS['pfb_test_process_running'], $GLOBALS['config']['unbound']);

		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function writeSentinel(int $gen): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload", "{$gen}\n");
	}

	private function writeApplied(int $gen): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "{$gen}\n");
	}

	private function writeUnboundConf(bool $referencesPfbUnbound): void
	{
		$body = $referencesPfbUnbound ? "python-script: \"/var/unbound/pfb_unbound.py\"\n" : "no python here\n";
		file_put_contents("{$this->dir}/unbound.conf", $body);
	}

	// -----------------------------------------------------------------------
	// pfb_dnsbl_apply_ledger_update() -- open/close/refresh
	// -----------------------------------------------------------------------

	public function testNotConvergedOpensEntry(): void
	{
		// No unbound.conf at all -> pfb_dnsbl_converged() is FALSE.
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;

		pfb_dnsbl_apply_ledger_update();

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'a non-converged DNSBL apply state must open exactly one entry');
		$this->assertSame('dnsbl', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
		$this->assertStringContainsString('not converged', $open[0]['message']);
	}

	public function testConvergedClosesEntry(): void
	{
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		pfb_dnsbl_apply_ledger_update();
		// Before-state: genuinely open first, so the close below is a real transition.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		$this->writeUnboundConf(TRUE);
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		pfb_dnsbl_apply_ledger_update();

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a subsequent converged read must close the SAME key');
	}

	public function testNotConvergedTwiceRefreshesWithoutDuplicating(): void
	{
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		pfb_dnsbl_apply_ledger_update();
		pfb_dnsbl_apply_ledger_update();

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'two consecutive non-converged reads must refresh, never duplicate');
	}

	// -----------------------------------------------------------------------
	// pfb_dnsbl_download_ledger_update() -- feed download fail/success (#998)
	// -----------------------------------------------------------------------

	public function testDnsblDownloadFailureOpensEntry(): void
	{
		pfb_dnsbl_download_ledger_update(FALSE, 'DNSBL_Example', '[ DNSBL_Example - Example ] Download FAIL', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'a DNSBL download failure must open exactly one entry');
		$this->assertSame('dnsbl', $open[0]['facility']);
		$this->assertSame('DNSBL_Example', $open[0]['item']);
		$this->assertSame('download', $open[0]['stage']);
		$this->assertStringContainsString('Download FAIL', $open[0]['message']);
	}

	public function testDnsblDownloadSuccessClosesEntry(): void
	{
		pfb_dnsbl_download_ledger_update(FALSE, 'DNSBL_Example', 'Download FAIL', $this->dir);
		// Before-state: the entry is genuinely open first, so the success close
		// below is a real transition, not a no-op that happens to leave zero entries.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		pfb_dnsbl_download_ledger_update(TRUE, 'DNSBL_Example', '', $this->dir);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a paired download success must close the SAME key');
	}

	public function testDnsblDownloadFailureTwiceRefreshesWithoutDuplicating(): void
	{
		pfb_dnsbl_download_ledger_update(FALSE, 'DNSBL_Example', 'HTTP 404', $this->dir);
		pfb_dnsbl_download_ledger_update(FALSE, 'DNSBL_Example', 'HTTP 500', $this->dir);

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'two consecutive failures on the SAME item must refresh, never duplicate');
		$this->assertSame('HTTP 500', $open[0]['message'], 'message must be the LATEST refresh');
	}

	public function testDnsblDownloadCallSitesKeyOnTheAliasNotTheHeader(): void
	{
		// Regression pin (mirrors PfbSyncStatusIpWritersTest): the widget's deep-link
		// recognition matches only the pfB_/DNSBL_-prefixed $alias, never $header, so
		// keying on $header would silently drop the link for every entry. The DNSBL
		// download loop has no PHPUnit harness of its own (too heavy to invoke), so
		// this pins the exact call-site argument via source inspection.
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertNotSame('', $source, 'pfblockerng_apply.inc must be readable');

		$this->assertMatchesRegularExpression(
			'/pfb_download_ledger_failure\(\x27dnsbl\x27, \$alias,/',
			$source,
			'the DNSBL download-fail call must key on $alias, not $header, or the widget deep link breaks'
		);
		$this->assertMatchesRegularExpression(
			'/pfb_download_ledger_close_if_clean\(\x27dnsbl\x27, \$alias, \$pfb_dl_failed,/',
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
	public function testDnsblDownloadCloseFiresOncePerAliasPassNotPerRow(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertNotSame('', $source, 'pfblockerng_apply.inc must be readable');

		$this->assertSame(1, substr_count($source, "pfb_download_ledger_close_if_clean('dnsbl', \$alias, \$pfb_dl_failed, \$pfb['dbdir']);"),
			'the DNSBL loop must close its ledger exactly once after the alias pass');
		$this->assertSame(1, substr_count($source, "pfb_dnsbl_download_ledger_update(TRUE, \$alias,"),
			'only the shared close helper may call the DNSBL ledger close');
	}

	/**
	 * Mirrors the row-loop's per-alias-pass contract (issue #1048): the FALSE
	 * (open) ledger call fires per failing row, and the TRUE (close) call fires
	 * ONCE after all rows -- iff none failed. Drives the REAL production ledger
	 * helper in the exact call pattern the fixed loop now follows (the loop
	 * itself has no PHPUnit harness -- too heavy to invoke, see the class
	 * docblock -- so this is the primary functional proof of the contract,
	 * supplemented by the source-inspection pin above).
	 *
	 * @param bool[] $rowOutcomes TRUE = row succeeded, FALSE = row failed, in order.
	 */
	private function runDnsblAliasPass(string $alias, array $rowOutcomes): void
	{
		$failed = FALSE;
		foreach ($rowOutcomes as $i => $ok) {
			if (!$ok) {
				$failed = TRUE;
				pfb_download_ledger_failure('dnsbl', $alias, "row{$i}", $this->dir);
			}
		}
		pfb_download_ledger_close_if_clean('dnsbl', $alias, $failed, $this->dir);
	}

	public function testAliasPassFailThenSucceedLeavesEntryOpen(): void
	{
		$this->runDnsblAliasPass('DNSBL_Example', [FALSE, TRUE]);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a failing row followed by a succeeding sibling row must leave the entry OPEN -- a per-row close would mask this'
		);
	}

	public function testAliasPassSucceedThenFailLeavesEntryOpen(): void
	{
		$this->runDnsblAliasPass('DNSBL_Example', [TRUE, FALSE]);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a succeeding row followed by a failing sibling row must leave the entry OPEN'
		);
	}

	public function testAliasPassAllSuccessMultiFeedClosesEntry(): void
	{
		// Before-state: genuinely open first, so the close below is a real transition.
		$this->runDnsblAliasPass('DNSBL_Example', [FALSE]);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		$this->runDnsblAliasPass('DNSBL_Example', [TRUE, TRUE, TRUE]);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'an all-success multi-feed pass must close the entry'
		);
	}

	public function testAliasPassSingleFeedFailOpensEntry(): void
	{
		$this->runDnsblAliasPass('DNSBL_Example', [FALSE]);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a single-feed alias with one failing row must open the entry'
		);
	}

	public function testAliasPassSingleFeedSuccessClosesEntry(): void
	{
		// Before-state: genuinely open first (regression pin for the pre-#1048 behaviour).
		$this->runDnsblAliasPass('DNSBL_Example', [FALSE]);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		$this->runDnsblAliasPass('DNSBL_Example', [TRUE]);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a single-feed alias with its one row succeeding must close the entry (regression)'
		);
	}

	public function testAliasPassAllReusedClosesPreviouslyOpenEntry(): void
	{
		// Before-state: genuinely open first.
		$this->runDnsblAliasPass('DNSBL_Example', [FALSE]);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		// An all-reused pass makes ZERO ledger calls inside the loop (no row ever
		// hits the download branch) -- $pfb_dl_failed stays FALSE the whole pass,
		// so the post-loop close still fires.
		$this->runDnsblAliasPass('DNSBL_Example', []);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'an all-reused pass (zero download attempts) must still close a previously-open entry'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_reload_unbound() end-to-end -- restart-fallback reaches a converged tail
	// -----------------------------------------------------------------------

	/**
	 * Drives the REAL swap-not-confirmed -> restart-fallback branch (dnsbldir
	 * made read-only, so the sentinel flip itself fails) through to the
	 * shared tail, exactly as a genuine stuck watcher would. Proves ONLY:
	 * (1) the fallback + shared restart path runs to completion without
	 * crashing/hanging ($calls sanity check), and (2) the tail's
	 * pfb_dnsbl_apply_ledger_update() correctly reflects the REAL final
	 * convergence outcome once Unbound is back up.
	 *
	 * Does NOT prove the fallback branch itself never calls a ledger
	 * function: the tail's write is deterministic/idempotent-by-key (see
	 * testConvergedClosesEntry / testNotConvergedTwiceRefreshesWithoutDuplicating),
	 * so it unconditionally overwrites the (dnsbl,dnsbl,apply) key regardless
	 * of what ran earlier in the same call -- a stray open() inside the
	 * fallback branch would be silently masked here. See
	 * testRestartFallbackBranchesNeverCallLedgerFunctionsDirectly for that
	 * invariant, pinned by source inspection instead.
	 */
	public function testRestartFallbackPathReachesTailWithConvergedState(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions -- cannot simulate the sentinel-flip failure.');
		}

		$writable = sys_get_temp_dir() . '/pfb_dnsbl_writable_' . getmypid() . '_' . uniqid();
		mkdir($writable, 0777, TRUE);

		$this->writeUnboundConf(TRUE);
		$GLOBALS['pfb']['dnsbl_file']           = "{$writable}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count']     = "{$writable}/unbound_py_count";
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "10");
		$GLOBALS['pfb']['chroot_cmd']            = '/bin/echo';
		$GLOBALS['pfb']['dnsbl_python_unmount']  = FALSE;
		$GLOBALS['g']['varrun_path']             = $writable;

		$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];

		// dnsbldir read-only: reads (unbound.conf, sentinel/applied) still work, but
		// pfb_unbound_py_atomic_write()'s rename() into it fails -> flip_sentinel()
		// returns FALSE -> the "sentinel flip failed" fallback fires (near-instant,
		// no 30s poll -- unlike the wait_applied-timeout sibling branch).
		chmod($this->dir, 0555);

		// is_process_running('unbound') call sequence inside ONE pfb_reload_unbound()
		// call, in order: (1) zero-downtime eligibility check, (2) the pre-restart
		// "should we log Reloading" check, (3)/(4) pfb_stop_start_unbound()'s own
		// "wait for it to stop" loop -- once per invocation, TWO invocations happen
		// here (the first restart, then this file's retval!=0 retry) -- FALSE so each
		// loop breaks on its very first check, (5) the post-restart "Confirm that
		// Resolver is running" check, (6) pfb_dnsbl_converged()'s own read at the tail.
		// Only calls 3 and 4 are FALSE.
		$calls = 0;
		$GLOBALS['pfb_test_process_running']['unbound'] = function () use (&$calls) {
			$calls++;
			return !in_array($calls, [3, 4], true);
		};

		$ledger_calls = 0;
		try {
			pfb_reload_unbound('enabled', FALSE, FALSE, TRUE, static function () use (&$ledger_calls): bool {
				$ledger_calls++;
				return pfb_dnsbl_apply_ledger_update();
			});
		} finally {
			chmod($this->dir, 0777);
			foreach (glob("{$writable}/*") ?: [] as $file) {
				@unlink($file);
			}
			@rmdir($writable);
		}

		$this->assertGreaterThanOrEqual(5, $calls,
			'the restart-fallback + shared restart path must have actually run (sanity check on the call-count assumption)');
		$this->assertSame(1, $ledger_calls,
			'the restart fallback must reach the shared ledger tail exactly once');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a swap-not-confirmed restart-fallback that ultimately converges must not leave a dnsbl apply entry open');
	}

	/**
	 * A failed bounded start is still the existing recovery event: restore the
	 * last-known-good config, retry exactly once, then leave apply explicitly open.
	 */
	public function testRestartFailurePreservesRollbackRetryAndApplyLedger(): void
	{
		$newConfig = "server:\n\tmodule-config: \"python validator iterator\"\n";
		$oldConfig = "server:\n\tmodule-config: \"validator iterator\"\n";
		file_put_contents("{$this->dir}/unbound.conf", $newConfig);
		file_put_contents("{$this->dir}/unbound.bk", $oldConfig);
		$GLOBALS['pfb']['dnsbl_file'] = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count'] = "{$this->dir}/unbound_py_count";
		$GLOBALS['pfb']['chroot_cmd'] = '/bin/echo';
		$GLOBALS['pfb']['dnsbl_python_unmount'] = FALSE;
		$GLOBALS['g']['varrun_path'] = $this->dir;
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;

		$startLog = (string) $GLOBALS['pfb_test_unbound_start_log'];
		$before = file_exists($startLog) ? count(file($startLog, FILE_IGNORE_NEW_LINES) ?: []) : 0;
		$ledgerCalls = 0;

		pfb_reload_unbound('enabled', FALSE, FALSE, FALSE,
			static function () use (&$ledgerCalls): bool {
				$ledgerCalls++;
				return pfb_dnsbl_apply_ledger_update();
			});

		$after = count(file($startLog, FILE_IGNORE_NEW_LINES) ?: []);
		$this->assertSame($before + 2, $after,
			'a non-zero start must still make the original attempt plus exactly one recovery retry');
		$this->assertSame($oldConfig, file_get_contents("{$this->dir}/unbound.conf"),
			'the retry must run only after restoring the last-known-good resolver config');
		$this->assertSame($newConfig, file_get_contents("{$this->dir}/unbound.conf.error"),
			'the failed candidate config must remain observable for diagnosis');
		$this->assertSame(1, $ledgerCalls,
			'the failed retry path must still reach the shared apply-ledger tail exactly once');
		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open,
			'a resolver that is still down after retry must leave one explicit apply entry open');
		$this->assertSame('apply', $open[0]['stage']);
	}

	// -----------------------------------------------------------------------
	// pfb_reload_unbound() -- zero-downtime swap SUCCESS early-return (issue #1024)
	// -----------------------------------------------------------------------

	/**
	 * Drives the REAL zero-downtime swap all the way to its own SUCCESS
	 * early-return (pfb_dnsbl_apply_ledger_update(); return;) -- distinct from
	 * testRestartFallbackPathReachesTailWithConvergedState, which only reaches
	 * the SHARED tail via the restart fallback. is_process_running('unbound')
	 * is called exactly twice on this path (the fast-path eligibility check,
	 * then pfb_dnsbl_converged() inside the ledger update this return makes) --
	 * any other count means the restart path (>=5 calls, see the fallback
	 * sibling above) ran instead.
	 */
	public function testZeroDowntimeSwapSuccessClosesLedgerViaEarlyReturn(): void
	{
		// Before-state: a stale dnsbl-apply entry genuinely open first (mirrors
		// testConvergedClosesEntry), so the close asserted below is a real transition.
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a stale dnsbl apply entry must exist before the zero-downtime swap under test');

		$this->writeUnboundConf(TRUE);
		$GLOBALS['pfb']['dnsbl_file']            = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count']      = "{$this->dir}/unbound_py_count";
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], '10');
		$GLOBALS['pfb']['chroot_cmd']            = '/bin/echo';
		$GLOBALS['pfb']['dnsbl_python_unmount']  = FALSE;
		$GLOBALS['config']['unbound']            = ['python' => 'on', 'python_script' => 'pfb_unbound'];

		// No sentinel written yet -> flip_sentinel()'s cur=0 -> next=1; pre-write the
		// applied marker to 1 so wait_applied(1) confirms on its FIRST read, never sleeping.
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "1\n");

		// TRUE only for the two expected success-path calls -- if a regression falls
		// through to the restart path instead, is_process_running() resolves FALSE
		// immediately so pfb_stop_start_unbound()'s wait loop never real-sleeps; the
		// call-count assertion below still catches the regression.
		$calls = 0;
		$GLOBALS['pfb_test_process_running']['unbound'] = function () use (&$calls) {
			$calls++;
			return $calls <= 2;
		};

		$ledger_calls = 0;
		pfb_reload_unbound('enabled', FALSE, FALSE, TRUE, static function () use (&$ledger_calls): bool {
			$ledger_calls++;
			return pfb_dnsbl_apply_ledger_update();
		});

		$this->assertSame(2, $calls,
			"the success path must call is_process_running('unbound') exactly twice (eligibility check + pfb_dnsbl_converged()); any other count means the restart path ran instead");
		$this->assertSame(1, $ledger_calls,
			'the zero-downtime success must write apply status exactly once before returning');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a converged zero-downtime swap must close the dnsbl apply entry via its own early return');
		$this->assertFileDoesNotExist("{$GLOBALS['pfb']['dnsbl_file']}.sync",
			'the success early-return must clear its own daemon-suppression marker before returning');
	}

	public function testGenericSwapReturnsAppliedAndLeavesFullFlushToCaller(): void
	{
		$this->writeUnboundConf(TRUE);
		$GLOBALS['pfb']['dnsbl_file']            = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count']      = "{$this->dir}/unbound_py_count";
		$GLOBALS['pfb']['chroot_cmd']            = "{$this->dir}/chroot-control-recorder";
		$GLOBALS['pfb']['dnsbl_python_unmount']  = FALSE;
		$GLOBALS['config']['unbound']            = ['python' => 'on', 'python_script' => 'pfb_unbound'];
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], '10');
		$this->writeApplied(1);

		$commands = "{$this->dir}/control-commands.log";
		$marker = escapeshellarg("{$this->dir}/pfb_py_reload.applied");
		file_put_contents(
			$GLOBALS['pfb']['chroot_cmd'],
			"#!/bin/sh\nprintf '%s|applied=%s\\n' \"\$*\" \"\$(cat {$marker})\" >> " . escapeshellarg($commands) . "\n"
		);
		chmod($GLOBALS['pfb']['chroot_cmd'], 0755);

		$calls = 0;
		$GLOBALS['pfb_test_process_running']['unbound'] = function () use (&$calls) {
			$calls++;
			return $calls <= 2;
		};

		$swapped = pfb_reload_unbound('enabled', TRUE, FALSE, TRUE);

		$this->assertSame(2, $calls, 'bulk apply must return through the zero-downtime success path');
		$this->assertTrue($swapped, 'successful applied-generation swap must return TRUE to its bulk caller');
		$this->assertSame(
			[],
			file_exists($commands) ? file($commands, FILE_IGNORE_NEW_LINES) : [],
			'generic reload must leave the full-cache policy to its bulk caller'
		);
	}

	public function testLockCallerTargetsOnlyAfterGenericReloadReturns(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$this->assertNotSame('', $source, 'pfblockerng_alerts.php must be readable');
		$start = strpos($source, "if (\$ua['mode'] !== '')");
		$end = strpos($source, 'header("Location:', $start);
		$this->assertNotFalse($start, 'Lock/Unlock handler must exist');
		$this->assertNotFalse($end, 'Lock/Unlock handler end boundary must exist');
		$region = substr($source, $start, $end - $start);

		$this->assertStringNotContainsString('$newly_blocked', $region);
		$targeted = 'pfb_unbound_py_ccache_flush(array($domain));';
		preg_match("/pfb_reload_unbound\('enabled',\s*FALSE,\s*(?:FALSE|TRUE),\s*TRUE\);/", $region, $reload_match, PREG_OFFSET_CAPTURE);
		$reload_pos = $reload_match[0][1] ?? FALSE;
		$targeted_pos = strpos($region, $targeted);
		$this->assertNotFalse($reload_pos, 'Lock/Unlock must call the four-argument generic reload');
		$this->assertNotFalse($targeted_pos, 'Lock must retain the validated targeted flush in its caller');
		$this->assertGreaterThan($reload_pos, $targeted_pos,
			'targeted Lock flush must run only after generic reload returns');
		$this->assertMatchesRegularExpression(
			'/if \(\$ua\[\x27mode\x27\] === \x27lock\x27\) \{\s*pfb_unbound_py_ccache_flush\(array\(\$domain\)\);/s',
			$region,
			'only Lock, not Unlock, may invoke the targeted helper'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_reload_unbound() -- non-'enabled' mode closes via the else branch (issue #1024)
	// -----------------------------------------------------------------------

	/**
	 * Drives the shared tail's ELSE branch (mode != 'enabled' -> a direct
	 * pfb_sync_status_close(), never pfb_dnsbl_apply_ledger_update()) with a
	 * state that stays NON-converged even after the call (is_process_running
	 * FALSE throughout, no unbound.conf) -- proving the close happens because
	 * mode != 'enabled', not because convergence happened to be met.
	 */
	public function testDisabledModeClosesLedgerEntryViaElseBranchRegardlessOfConvergence(): void
	{
		// Before-state: a stale dnsbl-apply entry genuinely open first (mirrors
		// testNotConvergedOpensEntry), so the close below is a real transition.
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a stale dnsbl apply entry must exist before the disabled-mode call under test');

		$GLOBALS['g']['varrun_path']            = $this->dir;
		$GLOBALS['pfb']['chroot_cmd']            = '/bin/echo';
		$GLOBALS['pfb']['dnsbl_python_unmount']  = FALSE;
		// is_process_running('unbound') stays FALSE for the whole call and no unbound.conf
		// is ever written -- pfb_dnsbl_converged() would read FALSE too, but mode !=
		// 'enabled' means it is never even reached on this path (confirmed by source read).

		pfb_reload_unbound('disabled', FALSE, FALSE);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a disabled-mode reload must close the dnsbl apply entry via the unconditional else branch, even though the state never converged');
	}
}
