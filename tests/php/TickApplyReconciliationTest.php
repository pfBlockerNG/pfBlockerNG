<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 5 — tick-driven apply-stage reconciliation.
 *
 * pfblockerng_tick() gains one unconditional step (fires every tick, never
 * $due-gated) that retries every open stage='apply' ledger entry against
 * already-persisted content -- no re-download, re-parse, or re-dedup:
 *   - ip:    pfb_ip_apply_retry() -- a pfctl replace/kill against the aliasdir
 *            mirror, reusing pfb_pfctl_table_op()'s own ledger wiring.
 *   - dnsbl: pfb_dnsbl_apply_retry() -- re-publish the reload sentinel only
 *            (no wait, no restart -- see RESULTS/05_Results.txt), then re-run
 *            the existing convergence decision.
 * Unbounded (ADR SS2.4): no attempt counter, no backoff -- a continued failure
 * simply stays open for the next tick. Semantics #5: download/parse/dedup
 * stages are never touched by this step.
 *
 * Red→green: before this phase pfblockerng_tick() never read the ledger at
 * all -- every VERIFICATION case below fails against the pre-change worktree
 * because nothing retries (the seeded entry's underlying probe is never
 * invoked a second time).
 *
 * Functions under test:
 *   pfb_ip_apply_retry(string $item): void
 *   pfb_dnsbl_apply_retry(): void
 *   pfblockerng_tick() -- the new unconditional reconciliation step.
 */
#[CoversFunction('pfb_ip_apply_retry')]
#[CoversFunction('pfb_dnsbl_apply_retry')]
#[CoversFunction('pfblockerng_tick')]
final class TickApplyReconciliationTest extends TestCase
{
	private string $dir;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var string[] temp mock-pfctl scripts / counter files to remove in tearDown */
	private array $tmpfiles = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tick_apply_reconciliation_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);

		foreach (['dbdir', 'aliasdir', 'dnsbldir', 'pfctl', 'log', 'errlog', 'runlog', 'extraslog',
			  'dnsbl_file', 'dnsbl_python_unmount'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}

		$GLOBALS['pfb']['dbdir']      = $this->dir;
		$GLOBALS['pfb']['aliasdir']   = $this->dir;
		$GLOBALS['pfb']['dnsbldir']   = $this->dir;
		$GLOBALS['pfb']['log']        = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']     = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog']     = "{$this->dir}/run.log";
		$GLOBALS['pfb']['extraslog']  = "{$this->dir}/extras.log";
		$GLOBALS['pfb']['dnsbl_file'] = "{$this->dir}/dnsbl_file";
		unset($GLOBALS['pfb']['dnsbl_python_unmount']);

		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		$GLOBALS['config'] = [];

		$this->seedTickPrereqs();
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
		unset($GLOBALS['pfb_test_process_running'], $GLOBALS['config']['unbound']);

		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				@unlink($f);
			}
		}
		$this->tmpfiles = [];

		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	/**
	 * Minimum config keys pfb_global() reads (avoids undefined-array-key warnings --
	 * pfblockerng_ss_refresh() calls pfb_global() internally every tick), plus
	 * pfb_interval='Disabled' so the tick's own cron/dcc/bl dispatch branches
	 * never exec() anything real -- isolates every test here to the new
	 * reconciliation step alone. Mirrors TickEntrypointTest::seedTickPrereqs().
	 */
	private function seedTickPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');
		config_set_path("{$gen}/pfb_interval",    'Disabled');
		config_set_path("{$gen}/pfb_quiet_hours", '');

		config_set_path("{$ip}/suppression",     '');
		config_set_path("{$ip}/database_cc",     '');
		config_set_path("{$ip}/maxmind_locale",  'en');
		config_set_path("{$ip}/asn_reporting",   'disabled');
		config_set_path("{$ip}/asn_token",       '');
		config_set_path("{$ip}/maxmind_account", '');
		config_set_path("{$ip}/maxmind_key",     '');

		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');

		config_set_path("{$dnsbl}/pfb_dnsvip4",     '');
		config_set_path("{$dnsbl}/pfb_dnsvip6",     '');
		config_set_path("{$dnsbl}/pfb_dnsport",     '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path("{$dnsbl}/alexa_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/pfb_pytld",       '');
		config_set_path("{$dnsbl}/pfb_py_nolog",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa",      '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_gp",          '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}
	}

	/** Write an executable POSIX-sh mock pfctl that exits $rc, emitting $stderr on fd 2,
	 *  AND appends one line to $counterFile per invocation -- the spy KILL-GATE (a)
	 *  needs to prove the retry was actually attempted, not merely "no crash". */
	private function mockPfctlCounting(int $rc, string $stderr, string $counterFile): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_pfctl_mock_');
		$this->assertNotFalse($path, 'could not create temp mock pfctl script');
		$this->tmpfiles[] = $path;
		$stderr_esc  = str_replace("'", "'\\''", $stderr);
		$counter_esc = escapeshellarg($counterFile);
		$this->assertNotFalse(
			file_put_contents($path, "#!/bin/sh\necho x >> {$counter_esc}\nprintf '%s\\n' '{$stderr_esc}' >&2\nexit {$rc}\n"),
			"could not write mock pfctl script {$path}"
		);
		$this->assertTrue(chmod($path, 0755), "could not chmod mock pfctl script {$path} executable");
		return $path;
	}

	private function callCount(string $counterFile): int
	{
		if (!is_file($counterFile)) {
			return 0;
		}
		return count(array_filter(explode("\n", (string) file_get_contents($counterFile)), 'strlen'));
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

	private function tick(): void
	{
		pfb_global();
		pfblockerng_tick();
	}

	// -----------------------------------------------------------------------
	// VERIFICATION (a)/(b) — IP side
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given an open (ip,'pfB_Test_v4',apply) entry and a mirror file at
	 *   {aliasdir}/pfB_Test_v4.txt (already-persisted content).
	 *   And   $pfb['pfctl'] is a mock that ALWAYS fails (the underlying pfctl
	 *         condition is genuinely still broken).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the mock pfctl was invoked again (the spy counter increased) --
	 *         proving a real retry attempt happened, not just "no crash".
	 *   And   the entry is STILL open (continued failure, no backoff, no counter).
	 *
	 * Red->green: on pre-Phase-5 code, pfblockerng_tick() never reads the ledger
	 * at all, so the mock pfctl is never invoked a second time -- the spy count
	 * stays at 1 (only the seed call), not 2+.
	 */
	public function testTickRetriesOpenIpApplyEntryAndLeavesItOpenOnContinuedFailure(): void
	{
		$counter = tempnam(sys_get_temp_dir(), 'pfb_pfctl_calls_');
		$this->tmpfiles[] = $counter;
		@unlink($counter);

		file_put_contents("{$this->dir}/pfB_Test_v4.txt", "10.0.0.1\n10.0.0.2\n");

		$failBin = $this->mockPfctlCounting(1, 'pfctl: EINVAL', $counter);
		$GLOBALS['pfb']['pfctl'] = $failBin;

		// Seed: a real failing pfctl apply opens the entry (matches how production
		// gets here -- pfb_pfctl_table_op()'s own Phase-2 wiring).
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '-f ' . escapeshellarg("{$this->dir}/pfB_Test_v4.txt"), $failBin);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'), 'seed: entry must be open before the tick');
		$callsBeforeTick = $this->callCount($counter);
		$this->assertSame(1, $callsBeforeTick, 'seed: mock pfctl must have been invoked exactly once so far');

		$this->tick();

		$this->assertGreaterThan($callsBeforeTick, $this->callCount($counter),
			'expected pfblockerng_tick() to invoke pfctl again (a real retry attempt), got the SAME call '
			. "count ({$callsBeforeTick}) before and after -- the reconciliation step never ran");

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'a continued pfctl failure must leave the entry open (no backoff, no counter)');
		$this->assertSame('pfB_Test_v4', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
	}

	/**
	 * Scenario:
	 *   Given the SAME seeded open (ip,'pfB_Test_v4',apply) entry as above.
	 *   And   the underlying condition is FIXED before the tick runs (a clean
	 *         mock pfctl is swapped in, simulating the table's real state
	 *         resolving out-of-band).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the entry clears -- self-healed within one tick interval, no
	 *         source change / Force Reload required (ADR SS4 item 4).
	 */
	public function testTickClearsIpApplyEntryOnceUnderlyingConditionIsFixed(): void
	{
		file_put_contents("{$this->dir}/pfB_Test_v4.txt", "10.0.0.1\n");

		$failBin = $this->mockPfctlCounting(1, 'pfctl: EINVAL', tempnam(sys_get_temp_dir(), 'pfb_pfctl_calls_'));
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '-f ' . escapeshellarg("{$this->dir}/pfB_Test_v4.txt"), $failBin);
		// Before-state: genuinely open first, so the clear below is a real transition.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		// Fixed out-of-band: the box's pfctl now succeeds.
		$okBin = tempnam(sys_get_temp_dir(), 'pfb_pfctl_ok_');
		$this->tmpfiles[] = $okBin;
		file_put_contents($okBin, "#!/bin/sh\nexit 0\n");
		chmod($okBin, 0755);
		$GLOBALS['pfb']['pfctl'] = $okBin;

		$this->tick();

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'a fixed underlying pfctl condition must clear the entry within one tick');
	}

	// -----------------------------------------------------------------------
	// VERIFICATION (c) — Semantics #5: download/parse entries are untouched
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given an open (ip,'pfB_Test_v4',apply) entry (retried/cleared this tick)
	 *   ALONGSIDE an open (ip,'pfB_Other_v4',download) entry.
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the download entry's message/first_seen/last_seen are BYTE-IDENTICAL
	 *         before and after -- proving the tick genuinely never touched it,
	 *         not merely that it still exists.
	 */
	public function testTickNeverTouchesDownloadOrParseStageEntries(): void
	{
		pfb_sync_status_open('ip', 'pfB_Other_v4', 'download', 'HTTP 404', $this->dir, static fn() => 1000);
		pfb_sync_status_open('dnsbl', 'pfb_py_zone.txt', 'parse', 'csv read failed', $this->dir, static fn() => 1000);

		$before = pfb_sync_status_list_open($this->dir);
		$this->assertCount(2, $before, 'seed: exactly the two non-apply entries must be open, nothing else');

		// An apply-stage entry too, so the tick genuinely has an apply row to act on.
		file_put_contents("{$this->dir}/pfB_Test_v4.txt", "10.0.0.1\n");
		$okBin = tempnam(sys_get_temp_dir(), 'pfb_pfctl_ok_');
		$this->tmpfiles[] = $okBin;
		file_put_contents($okBin, "#!/bin/sh\nexit 0\n");
		chmod($okBin, 0755);
		$failBin = tempnam(sys_get_temp_dir(), 'pfb_pfctl_fail_');
		$this->tmpfiles[] = $failBin;
		file_put_contents($failBin, "#!/bin/sh\nprintf 'pfctl: EINVAL' >&2\nexit 1\n");
		chmod($failBin, 0755);
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '-f ' . escapeshellarg("{$this->dir}/pfB_Test_v4.txt"), $failBin);
		$GLOBALS['pfb']['pfctl'] = $okBin;

		$this->tick();

		$after = pfb_sync_status_list_open($this->dir);
		$byKey = static function (array $entries): array {
			$out = [];
			foreach ($entries as $e) {
				$out["{$e['facility']}|{$e['item']}|{$e['stage']}"] = $e;
			}
			return $out;
		};
		$beforeByKey = $byKey($before);
		$afterByKey  = $byKey($after);

		foreach (['ip|pfB_Other_v4|download', 'dnsbl|pfb_py_zone.txt|parse'] as $key) {
			$this->assertArrayHasKey($key, $afterByKey, "expected {$key} to still be open after the tick");
			$this->assertSame($beforeByKey[$key], $afterByKey[$key],
				"expected {$key} to be BYTE-IDENTICAL before/after the tick (Semantics #5), got before="
				. var_export($beforeByKey[$key], TRUE) . ' after=' . var_export($afterByKey[$key], TRUE));
		}

		// Sanity: the apply entry itself DID get acted on (cleared by the fixed pfctl).
		$this->assertArrayNotHasKey('ip|pfB_Test_v4|apply', $afterByKey,
			'sanity: the seeded apply entry should have cleared once pfctl succeeded');
	}

	// -----------------------------------------------------------------------
	// VERIFICATION (d)/(e) — DNSBL side
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given an open (dnsbl,dnsbl,apply) entry (sentinel=5, applied=3 --
	 *   genuinely not converged) with Unbound running and python mode wired.
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the reload sentinel was bumped again (a real re-flip attempt --
	 *         the spy, not just "no crash").
	 *   And   the entry is STILL open -- 'applied' never catches up in this
	 *         test (no real watcher process), so convergence genuinely stays
	 *         broken (no backoff, no counter).
	 */
	public function testTickRetriesOpenDnsblApplyEntryAndLeavesItOpenOnContinuedFailure(): void
	{
		$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];
		$this->writeUnboundConf(TRUE);
		$this->writeSentinel(5);
		$this->writeApplied(3);

		// Seed via the real decision function -- matches how production opens this key.
		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'), 'seed: entry must be open before the tick');

		$this->tick();

		$sentinelAfter = (int) trim((string) file_get_contents("{$this->dir}/pfb_py_reload"));
		$this->assertGreaterThan(5, $sentinelAfter,
			"expected pfblockerng_tick() to re-flip the reload sentinel past 5, got {$sentinelAfter} -- "
			. 'the reconciliation step never attempted a retry');

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'applied never catches up in this test, so convergence genuinely stays '
			. 'broken -- the entry must stay open (no backoff, no counter)');
		$this->assertSame('dnsbl', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
	}

	/**
	 * Scenario:
	 *   Given the SAME seeded open (dnsbl,dnsbl,apply) entry as above.
	 *   And   the underlying condition is FIXED before the tick runs (applied
	 *         catches up to sentinel out-of-band -- e.g. the watcher finished).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the entry clears within one tick, no restart / Force Reload.
	 */
	public function testTickClearsDnsblApplyEntryOnceUnderlyingConditionIsFixed(): void
	{
		$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];
		$this->writeUnboundConf(TRUE);
		$this->writeSentinel(5);
		$this->writeApplied(3);

		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		// Fixed out-of-band: applied has caught up to the sentinel.
		$this->writeApplied(5);

		$this->tick();

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'a fixed underlying convergence condition must clear the entry within one tick');
	}

	// -----------------------------------------------------------------------
	// KILL-GATE support -- pfb_dnsbl_apply_retry() never re-flips when nothing
	// could consume it (Unbound down): stays cheap, never a false "attempt".
	// -----------------------------------------------------------------------

	public function testDnsblRetryDoesNotFlipSentinelWhenUnboundIsNotRunning(): void
	{
		$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		$this->writeSentinel(5);
		$this->writeApplied(3);

		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));

		$this->tick();

		$sentinelAfter = (int) trim((string) file_get_contents("{$this->dir}/pfb_py_reload"));
		$this->assertSame(5, $sentinelAfter,
			'Unbound is not running -- nothing can consume a re-flipped sentinel, so '
			. "pfb_dnsbl_apply_retry() must not bump it (got {$sentinelAfter}, expected unchanged 5)");
	}
}
