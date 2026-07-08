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
 * to prove its swap-not-confirmed restart-fallback branch does not, by
 * itself, leave a ledger entry behind (ADR SS1.3: "NOT an error: fail-safe
 * by design"). The feed-download pair (pfb_dnsbl_download_ledger_update())
 * mirrors the IP side's PfbSyncStatusIpWritersTest Pair 1.
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
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertNotFalse($source, 'pfblockerng.inc must be readable');

		$this->assertMatchesRegularExpression(
			'/pfb_dnsbl_download_ledger_update\(FALSE, \$alias,/',
			$source,
			'the DNSBL download-fail call must key on $alias, not $header, or the widget deep link breaks'
		);
		$this->assertMatchesRegularExpression(
			'/pfb_dnsbl_download_ledger_update\(TRUE, \$alias,/',
			$source,
			'the paired success-close call must key on the SAME $alias for symmetry'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_reload_unbound() end-to-end -- restart-fallback opens nothing alone
	// -----------------------------------------------------------------------

	/**
	 * Drives the REAL swap-not-confirmed -> restart-fallback branch: the
	 * zero-downtime eligibility gate passes, but the sentinel flip itself
	 * fails (dnsbldir made read-only), so pfb_reload_unbound() falls through
	 * to the shared restart path exactly as it would on a genuine stuck
	 * watcher. Neither fallback branch calls any ledger function -- only the
	 * TAIL's pfb_dnsbl_apply_ledger_update() does, and it is proven
	 * (PfbDnsblConvergedTest) to correctly read "converged" once the
	 * sentinel/applied pair (both absent -> 0 == 0), Unbound liveness, and
	 * unbound.conf all agree -- so this test's PASSING assertion is a real
	 * proof that the fallback branch itself never wrote an entry, not an
	 * artifact of the tail masking one.
	 */
	public function testRestartFallbackAloneOpensNoEntry(): void
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
		// loop breaks on its very first check instead of spinning up to 30 real
		// seconds, (5) the post-restart "Confirm that Resolver is running" check, (6)
		// pfb_dnsbl_converged()'s own read at the tail. Only calls 3 and 4 are FALSE.
		$calls = 0;
		$GLOBALS['pfb_test_process_running']['unbound'] = function () use (&$calls) {
			$calls++;
			return !in_array($calls, [3, 4], true);
		};

		try {
			pfb_reload_unbound('enabled', FALSE, FALSE, TRUE, []);
		} finally {
			chmod($this->dir, 0777);
			foreach (glob("{$writable}/*") ?: [] as $file) {
				@unlink($file);
			}
			@rmdir($writable);
		}

		$this->assertGreaterThanOrEqual(5, $calls,
			'the restart-fallback + shared restart path must have actually run (sanity check on the call-count assumption)');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a swap-not-confirmed restart-fallback that ultimately converges must not leave a dnsbl apply entry open');
	}
}
