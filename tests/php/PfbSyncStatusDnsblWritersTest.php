<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

/**
 * ADR-61 Phase 3 (+ #998 follow-up) — DNSBL-side sync-status writer/clearer pairs.
 *
 * The apply-stage decision (pfb_dnsbl_apply_ledger_update(), built on
 * pfb_dnsbl_converged()) is tested directly for the open/close/refresh
 * contract, and separately end-to-end through the REAL pfb_reload_unbound()
 * to prove its restart path reaches the shared
 * tail and converges (ADR SS1.3: "NOT an error: fail-safe by design"). That
 * the three restart-fallback branches never call a ledger function directly
 * is a SEPARATE, source-inspection-only invariant (the tail's write is
 * deterministic/idempotent-by-key, so no end-state assertion can prove it) --
 * see testRestartFallbackBranchesNeverCallLedgerFunctionsDirectly.
 *
 * Functions under test:
 *   pfb_dnsbl_apply_ledger_update(): void
 *   pfb_reload_unbound(...) -- the data fast path + restart paths.
 */
#[CoversFunction('pfb_dnsbl_apply_ledger_update')]
#[CoversFunction('pfb_reload_unbound')]
final class PfbSyncStatusDnsblWritersTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private string $dir;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $savedPfb = [];

	/** @var array<string,mixed> saved $GLOBALS['g'] keys */
	private array $savedG = [];

	/** @var array<string,mixed> saved $GLOBALS['config'] keys */
	private array $savedConfig = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_dnsbl_writers_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		foreach (['dnsbldir', 'dbdir', 'dnsbl_file', 'unbound_py_count', 'chroot_cmd', 'enable', 'pfb_dns', 'dnsbl',
			  'dnsbl_python_unmount', 'log', 'errlog', 'php'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		foreach (['varrun_path'] as $k) {
			$this->savedG[$k] = array_key_exists($k, $GLOBALS['g'] ?? []) ? $GLOBALS['g'][$k] : false;
		}
		foreach (['unbound', 'installedpackages'] as $k) {
			$this->savedConfig[$k] = array_key_exists($k, $GLOBALS['config'] ?? []) ? $GLOBALS['config'][$k] : false;
		}

		$GLOBALS['pfb']['dnsbldir'] = $this->dir;
		$GLOBALS['pfb']['dbdir']    = $this->dir;
		$GLOBALS['pfb']['log']      = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']   = "{$this->dir}/error.log";
		$GLOBALS['pfb']['php']      = PHP_BINARY;
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		$this->setUpUpstreamFixture();
	}

	protected function tearDown(): void
	{
		$this->tearDownUpstreamFixture();
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
		unset($GLOBALS['pfb_test_process_running'],
			$GLOBALS['pfb_test_valid_pids'], $GLOBALS['pfb_test_sigkillbypid_calls'],
			$GLOBALS['pfb_test_sigkillbypid_effect'], $GLOBALS['pfb_test_sigkillbyname_calls'],
			$GLOBALS['pfb_test_sigkillbyname_effect']);
		// Restore rather than unset: the bootstrap may own config['unbound'], and
		// deleting it made every later test order-dependent.
		foreach ($this->savedConfig as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['config'][$k]);
			} else {
				$GLOBALS['config'][$k] = $prev;
			}
		}
		$this->savedConfig = [];

		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	/**
	 * pfB-DNS owns the Resolver (a snapshot) with DNSBL on, so the DNS proxy is the module host (issue #3770; Unbound never is).
	 * Its pid file answers $up: TRUE or FALSE, or a callable that counts the probes.
	 */
	private function pfbDnsHostsTheModule(bool|callable $up): void
	{
		$GLOBALS['pfb']['enable'] = $GLOBALS['pfb']['pfb_dns'] = $GLOBALS['pfb']['dnsbl'] = PfbToggle::On;
		$GLOBALS['config'] ??= [];
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl' => ['present' => FALSE, 'value' => NULL],
			'custom_options' => ['present' => FALSE, 'value' => NULL],
		])));
		$this->proxyUp($up);
	}

	private function proxyUp(bool|callable $up): void
	{
		$GLOBALS['pfb_test_valid_pids']['/var/run/pfb_dns_proxy.pid'] = $up;
	}

	/**
	 * The resolver is up around a restart but down at every stop check. This keeps the fixture stable as the stop
	 * implementation gains checks of its own.
	 */
	private static function unboundDownDuringStop(): callable
	{
		return static function (): bool {
			foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
				if (($frame['function'] ?? '') === 'pfb_stop_start_unbound') {
					return FALSE;
				}
			}
			return TRUE;
		};
	}

	// -----------------------------------------------------------------------
	// pfb_dnsbl_apply_ledger_update() -- open/close/refresh
	// -----------------------------------------------------------------------

	public function testNotConvergedOpensEntry(): void
	{
		// The proxy hosts the module but is down -> pfb_dnsbl_converged() is FALSE.
		$this->pfbDnsHostsTheModule(FALSE);

		pfb_dnsbl_apply_ledger_update();

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'a non-converged DNSBL apply state must open exactly one entry');
		$this->assertSame('dnsbl', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
		$this->assertStringContainsString('not converged', $open[0]['message']);
	}

	public function testConvergedClosesEntry(): void
	{
		$this->pfbDnsHostsTheModule(FALSE);
		pfb_dnsbl_apply_ledger_update();
		// Before-state: genuinely open first, so the close below is a real transition.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		$this->proxyUp(TRUE);
		pfb_dnsbl_apply_ledger_update();

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a subsequent converged read must close the SAME key');
	}

	public function testNotConvergedTwiceRefreshesWithoutDuplicating(): void
	{
		$this->pfbDnsHostsTheModule(FALSE);
		pfb_dnsbl_apply_ledger_update();
		pfb_dnsbl_apply_ledger_update();

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'two consecutive non-converged reads must refresh, never duplicate');
	}

	// -----------------------------------------------------------------------
	// pfb_reload_unbound() end-to-end -- the restart path reaches the ledger tail
	// -----------------------------------------------------------------------

	/**
	 * A data-only reload with nothing hosting the module (pfB-DNS does not own the Resolver) never takes the data fast path
	 * -- Unbound is never the host (issue #3770) -- so it takes the restart path to the shared ledger tail. Proves ONLY:
	 * the tail runs exactly once and records the REAL outcome, not converged even with Unbound back up.
	 *
	 * Does NOT prove the restart path itself never calls a ledger
	 * function: the tail's write is deterministic/idempotent-by-key (see
	 * testConvergedClosesEntry / testNotConvergedTwiceRefreshesWithoutDuplicating),
	 * so it unconditionally overwrites the (dnsbl,dnsbl,apply) key regardless
	 * of what ran earlier in the same call -- a stray open() inside the
	 * fallback branch would be silently masked here. See
	 * testRestartFallbackBranchesNeverCallLedgerFunctionsDirectly for that
	 * invariant, pinned by source inspection instead.
	 */
	public function testRestartPathReachesTailAndRecordsThatNothingHostsDnsbl(): void
	{
		$GLOBALS['pfb']['dnsbl_file']           = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count']     = "{$this->dir}/unbound_py_count";
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "10");
		$GLOBALS['pfb']['chroot_cmd']            = '/bin/echo';
		$GLOBALS['pfb']['dnsbl_python_unmount']  = FALSE;
		$GLOBALS['g']['varrun_path']             = $this->dir;

		$GLOBALS['pfb_test_process_running']['unbound'] = self::unboundDownDuringStop();

		$ledger_calls = 0;
		pfb_reload_unbound('enabled', FALSE, TRUE, static function () use (&$ledger_calls): bool {
			$ledger_calls++;
			return pfb_dnsbl_apply_ledger_update();
		});

		$this->assertSame(1, $ledger_calls,
			'the restart path must reach the shared ledger tail exactly once');
		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open,
			'a running Unbound does not converge DNSBL: pfB-DNS does not host it');
		$this->assertStringContainsString('pfB-DNS is not active', $open[0]['message']);
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

		pfb_reload_unbound('enabled', FALSE, FALSE,
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

	/**
	 * The only reachable control call on these failure paths is confirmation.
	 */
	private static function confirmRecorderCmd(string $probe): string
	{
		return '/usr/bin/touch ' . escapeshellarg($probe) . ' ;:';
	}

	/**
	 * issue #3094: a stop that could not be completed is NOT a broken unbound.conf.
	 *
	 * pfb_stop_start_unbound() refuses to start a second resolver when the daemon
	 * survives TERM and KILL (#3055). The caller used to read any non-zero retval as
	 * "the generated config is bad" and respond by saving unbound.conf aside as
	 * .error, restoring the previous config from unbound.bk, printing "Fix error(s)
	 * and a Force Reload required!", and retrying the whole restart. None of that is
	 * right here: the config was never the problem, there is nothing for the user to
	 * fix, and the retry cannot succeed where the refusal already stood -- and the
	 * daemon still answering is the OLD one, so the confirm block must not credit it.
	 */
	public function testStopFailureNeitherRollsBackNorRetriesNorCreditsTheOldDaemon(): void
	{
		$newConfig = "server:\n\tmodule-config: \"python validator iterator\"\n";
		$oldConfig = "server:\n\tmodule-config: \"validator iterator\"\n";
		file_put_contents("{$this->dir}/unbound.conf", $newConfig);
		file_put_contents("{$this->dir}/unbound.bk", $oldConfig);
		$GLOBALS['pfb']['dnsbl_file'] = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count'] = "{$this->dir}/unbound_py_count";
		$GLOBALS['pfb']['dnsbl_python_unmount'] = FALSE;
		$GLOBALS['g']['varrun_path'] = $this->dir;

		// The confirm block is the only caller of chroot_cmd on this path, so a recorder
		// here is a direct spy on whether it ran at all (leg 3 row 8: skipping it was
		// previously unasserted -- reverting the guard left every test green).
		$confirmProbe = "{$this->dir}/confirm_ran";
		$GLOBALS['pfb']['chroot_cmd'] = self::confirmRecorderCmd($confirmProbe);

		// The daemon outlives both budgets, so the stop refuses: this is the #3055 path.
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
		$GLOBALS['pfb_test_sigkillbyname_calls'] = array();

		$startLog = (string) $GLOBALS['pfb_test_unbound_start_log'];
		$before = file_exists($startLog) ? count(file($startLog, FILE_IGNORE_NEW_LINES) ?: []) : 0;

		pfb_reload_unbound('enabled', FALSE, FALSE,
			static fn (): bool => pfb_dnsbl_apply_ledger_update());

		$after = file_exists($startLog) ? count(file($startLog, FILE_IGNORE_NEW_LINES) ?: []) : 0;
		// This pins the callee's own guard (it returns before its start section). It does
		// NOT see a caller-side retry -- a retried refusal refuses again and never reaches
		// that section either, so the count is unchanged. The KILL count below is what
		// catches a retry; both are kept because they fail on different regressions.
		$this->assertSame($before, $after,
			'a refused stop must reach no start section at all');

		// A retry would call pfb_stop_start_unbound() a second time, and each call reaches
		// one KILL. Count KILL separately now that a missing pidfile also receives TERM.
		$this->assertSame(array(array('unbound', 'TERM'), array('unbound', 'KILL')),
			$GLOBALS['pfb_test_sigkillbyname_calls'],
			'a refused stop must attempt one TERM and one KILL in order');
		$kills = array_filter($GLOBALS['pfb_test_sigkillbyname_calls'],
			static fn(array $call): bool => $call[1] === 'KILL');
		$this->assertCount(1, $kills,
			'exactly one KILL proves the caller did not retry the refused stop');

		$this->assertFileDoesNotExist($confirmProbe,
			'the confirm block must not run for a refused stop: the process still answering '
			. 'is the daemon we failed to replace, so crediting it would report success');
		// That absence is only evidence if THIS test's recorder could have fired. An
		// unwritable probe path would satisfy the assertion above while proving nothing,
		// so fire it by hand now and require the file to appear (review leg 3, round 3).
		exec($GLOBALS['pfb']['chroot_cmd'] . ' status 2>&1');
		$this->assertFileExists($confirmProbe,
			'the recorder this test relies on must be capable of creating the probe; '
			. 'otherwise the absence assertion above passes for the wrong reason');

		$this->assertSame($newConfig, file_get_contents("{$this->dir}/unbound.conf"),
			'the resolver config must survive a stop failure: it was never the fault');
		$this->assertFileDoesNotExist("{$this->dir}/unbound.conf.error",
			'no candidate config may be quarantined for a fault that is not the config');
		$this->assertSame($oldConfig, file_get_contents("{$this->dir}/unbound.bk"),
			'the last-known-good copy must be left untouched, not consumed by a false rollback');

		// "Fix error(s) and a Force Reload required!" names an action that cannot help when
		// the resolver simply would not stop, so the log must carry the real cause instead.
		$log = (string) @file_get_contents($GLOBALS['pfb']['log'])
			. (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		// Pins THIS branch's own wording. 'could not be stopped' alone is also produced by
		// pfb_stop_start_unbound()'s result text, so it would survive a reword here (leg 3 row 6).
		$this->assertStringContainsString('config left unchanged', $log,
			'the caller must say the config was deliberately left alone, in its own words');
		$this->assertStringNotContainsString('Fix error(s)', $log,
			'a stop failure must not tell the operator to fix a config error that does not exist');
	}

	/**
	 * A completed failed start may coexist with an unrelated resolver another actor
	 * starts after this pass stopped its old daemon. That process is not evidence that
	 * either failed command succeeded, so the confirm control call must remain absent.
	 */
	public function testFailedStartsDoNotCreditAnUnrelatedDaemon(): void
	{
		$newConfig = "server:\n";
		$oldConfig = "server:\n\tverbosity: 1\n";
		file_put_contents("{$this->dir}/unbound.conf", $newConfig);
		file_put_contents("{$this->dir}/unbound.bk", $oldConfig);
		$GLOBALS['pfb']['dnsbl_file'] = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count'] = "{$this->dir}/unbound_py_count";
		$GLOBALS['pfb']['dnsbl_python_unmount'] = FALSE;
		$GLOBALS['g']['varrun_path'] = $this->dir;

		$confirmProbe = "{$this->dir}/confirm_ran";
		$GLOBALS['pfb']['chroot_cmd'] = self::confirmRecorderCmd($confirmProbe);
		$outside = 0;
		$GLOBALS['pfb_test_process_running']['unbound'] = static function () use (&$outside): bool {
			foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
				if (($frame['function'] ?? '') === 'pfb_stop_start_unbound') {
					return FALSE;
				}
			}
			$outside++;
			return $outside > 1;
		};
		$startLog = (string) $GLOBALS['pfb_test_unbound_start_log'];
		$before = file_exists($startLog) ? count(file($startLog, FILE_IGNORE_NEW_LINES) ?: []) : 0;

		pfb_reload_unbound('enabled', FALSE, FALSE, static fn (): bool => TRUE);

		$after = count(file($startLog, FILE_IGNORE_NEW_LINES) ?: []);
		$this->assertSame($before + 2, $after,
			'the genuine completed config failure must retain exactly one recovery retry');
		$this->assertSame($oldConfig, file_get_contents("{$this->dir}/unbound.conf"),
			'the completed config failure must still restore the last-known-good config');
		$this->assertFileDoesNotExist($confirmProbe,
			'two completed failed starts must not credit an unrelated running daemon');
	}

	// -----------------------------------------------------------------------
	// pfb_reload_unbound() -- the data fast path's early return (issue #1024)
	// -----------------------------------------------------------------------

	/**
	 * Drives the REAL data fast path to its own
	 * early-return (pfb_dnsbl_apply_ledger_update(); return;) -- distinct from
	 * testRestartPathReachesTailAndRecordsThatNothingHostsDnsbl, which only reaches
	 * the SHARED tail via the restart path. The module host (the DNS proxy) is
	 * probed exactly twice on this path (the fast-path eligibility check,
	 * then pfb_dnsbl_converged() inside the ledger update this return makes) --
	 * any other count means the restart path ran instead.
	 */
	public function testDataFastPathClosesLedgerViaEarlyReturn(): void
	{
		// Before-state: a stale dnsbl-apply entry genuinely open first (mirrors
		// testConvergedClosesEntry), so the close asserted below is a real transition.
		$this->pfbDnsHostsTheModule(FALSE);
		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a stale dnsbl apply entry must exist before the data fast path under test');

		$GLOBALS['pfb']['dnsbl_file']            = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count']      = "{$this->dir}/unbound_py_count";
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], '10');
		$GLOBALS['pfb']['chroot_cmd']            = '/bin/echo';
		$GLOBALS['pfb']['dnsbl_python_unmount']  = FALSE;

		// TRUE only for the two expected success-path probes of the module host -- if a regression falls
		// through to the restart path instead, the pid file reads dead immediately so the restart
		// never real-sleeps; the call-count assertion below still catches the regression.
		$calls = 0;
		$this->proxyUp(function () use (&$calls) {
			$calls++;
			return $calls <= 2;
		});

		$ledger_calls = 0;
		pfb_reload_unbound('enabled', FALSE, TRUE, static function () use (&$ledger_calls): bool {
			$ledger_calls++;
			return pfb_dnsbl_apply_ledger_update();
		});

		$this->assertSame(2, $calls,
			"the success path must probe the module host exactly twice (eligibility check + pfb_dnsbl_converged()); any other count means the restart path ran instead");
		$this->assertSame(1, $ledger_calls,
			'the data fast path must write apply status exactly once before returning');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'the data fast path must close the dnsbl apply entry via its own early return');
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

		pfb_reload_unbound('disabled', FALSE);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a disabled-mode reload must close the dnsbl apply entry via the unconditional else branch, even though the state never converged');
	}
}
