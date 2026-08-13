<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 5 — tick-driven apply-stage reconciliation.
 *
 * pfblockerng_tick() gains one independent 900-second due-ledger step that retries
 * every open stage='apply' ledger entry against
 * already-persisted content -- no re-download, re-parse, or re-dedup:
 *   - ip:    pfb_ip_apply_retry() -- a pfctl replace/kill against the aliasdir
 *            mirror, reusing pfb_pfctl_table_op()'s own ledger wiring.
 *   - dnsbl: pfb_dnsbl_apply_retry() -- re-publish the reload sentinel only
 *            (no wait, no restart -- see RESULTS/05_Results.txt), then re-run
 *            the existing convergence decision.
 * Unbounded (ADR SS2.4): no attempt counter, no backoff -- a continued failure
 * simply stays open for the next reconciliation slot. Semantics #5: download/parse/dedup
 * stages are never touched by this step.
 *
 * Red→green: before this phase pfblockerng_tick() had no scheduled apply
 * reconciliation step.
 *
 * Functions under test:
 *   pfb_ip_apply_retry(string $item): void
 *   pfb_dnsbl_apply_retry(): void
 *   pfblockerng_tick() -- the new due-ledger reconciliation step.
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

		foreach (['dbdir', 'aliasdir', 'dnsbldir', 'pfctl', 'php', 'log', 'errlog', 'runlog', 'extraslog',
			  'dnsbl_file', 'dnsbl_python_unmount'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
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

		// Keep the legacy fixed-job entries future-dated and neuter $pfb['php'] so
		// this suite remains isolated to apply reconciliation.
		$this->installPhpArgvRecorder();
		$now = time();
		foreach (['cron', 'dcc', 'bl'] as $jobKey) {
			$this->seedFutureLedgerEntry($jobKey, $now);
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
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
	 * pfblockerng_ss_refresh() calls pfb_global() internally when its job is due), plus
	 * legacy interval fields retained only for this historical fixture. setUp()
	 * future-dates fixed-job entries and neuters $pfb['php'] so tick calls stay
	 * isolated to the reconciliation step.
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
		config_set_path("{$dnsbl}/top1m_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/tld_allow",       '');
		config_set_path("{$dnsbl}/pfb_py_nolog",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa",      '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_gp",          '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}
	}

	/** Ledger dir path a php-argv recorder logs to; see installPhpArgvRecorder(). */
	private function phpCallsLog(): string
	{
		return "{$this->dir}/pfb_php_calls.log";
	}

	/**
	 * issue #1666: point $pfb['php'] at a harmless recording stub instead of the
	 * real interpreter -- a backstop so that even if the due-ledger seeding below
	 * ever regresses, a dispatch branch that fires anyway writes a line to
	 * phpCallsLog() instead of forking a REAL "pfblockerng.php <verb>" background
	 * shell that a sibling suite's pfb_update_pass_running() `ps` scan could see.
	 * Saved via the generic $saved loop in setUp(); restored in tearDown().
	 */
	private function installPhpArgvRecorder(): void
	{
		$path = "{$this->dir}/pfb_php_recorder";
		$log  = escapeshellarg($this->phpCallsLog());
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$log}\n");
		chmod($path, 0755);
		$GLOBALS['pfb']['php'] = $path;
	}

	/**
	 * Mirrors TickEntrypointTest::seedFutureLedgerEntry() -- keeps cron/dcc/bl
	 * not-due so tick() calls in this suite dispatch nothing (issue #1666).
	 */
	private function seedFutureLedgerEntry(string $jobKey, int $now): void
	{
		pfb_due_ledger_write_entry($jobKey, [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $this->dir);
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

	private function assertApplyReservation(): void
	{
		$entry = pfb_due_ledger_read_entry('apply_reconcile', $this->dir);
		$this->assertNotNull($entry, 'completed reconciliation must reserve apply_reconcile');
		$this->assertSame(0, $entry['jitter'], 'apply_reconcile must have zero jitter');
		$this->assertSame(900, $entry['next_due'] - $entry['last_run'], 'apply_reconcile cadence must be exactly 900 seconds');
		$this->assertGreaterThan(time(), $entry['next_due'], 'completed reconciliation must reserve a future slot');
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
	 * Red->green: on the pre-reconciliation tick, the apply job was not paced by
	 * its own due-ledger reservation, so this scheduled retry did not exist.
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
		$this->assertApplyReservation();
	}

	/**
	 * Scenario:
	 *   Given the SAME seeded open (ip,'pfB_Test_v4',apply) entry as above.
	 *   And   the underlying condition is FIXED before the tick runs (a clean
	 *         mock pfctl is swapped in, simulating the table's real state
	 *         resolving out-of-band).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the entry clears -- self-healed within one reconciliation interval, no
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
			'a fixed underlying pfctl condition must clear the entry within one reconciliation interval');
	}

	/**
	 * Scenario:
	 *   Given an open (ip,'pfB_NoMirror_v4',apply) entry but NO mirror file at
	 *   {aliasdir}/pfB_NoMirror_v4.txt (pfb_ip_apply_retry()'s is_file() check
	 *   is FALSE -- e.g. the mirror was never written, or the alias/table no
	 *   longer has one).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  pfctl is invoked with the KILL op, not REPLACE -- there is no
	 *         mirror content to replace with, and the continued KILL failure
	 *         leaves the apply entry open for a later retry.
	 */
	public function testTickRetriesIpApplyEntryWithKillWhenMirrorFileIsAbsent(): void
	{
		$argsLog = tempnam(sys_get_temp_dir(), 'pfb_pfctl_args_');
		$this->tmpfiles[] = $argsLog;
		@unlink($argsLog);
		$mockBin = tempnam(sys_get_temp_dir(), 'pfb_pfctl_mock_');
		$this->tmpfiles[] = $mockBin;
		$argsLogEsc = escapeshellarg($argsLog);
		file_put_contents($mockBin, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$argsLogEsc}\nprintf 'pfctl: EINVAL' >&2\nexit 1\n");
		chmod($mockBin, 0755);

		// Seed directly -- no mirror file is ever written for this alias.
		pfb_sync_status_open('ip', 'pfB_NoMirror_v4', 'apply', '[pfctl] op=replace table=pfB_NoMirror_v4 failed (rc=1)', $this->dir);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'), 'seed: entry must be open before the tick');
		$this->assertFileDoesNotExist("{$this->dir}/pfB_NoMirror_v4.txt", 'seed: no mirror file must exist for this test');

		$GLOBALS['pfb']['pfctl'] = $mockBin;
		$this->tick();

		$this->assertFileExists($argsLog, 'expected pfctl to have been invoked at all -- the retry never ran');
		$invocation = trim((string) file_get_contents($argsLog));
		$this->assertStringContainsString('-T kill', $invocation,
			"expected the mirror-absent retry to invoke pfctl's KILL op, got: {$invocation}");
		$this->assertStringNotContainsString('-T replace', $invocation,
			"mirror-absent retry must not invoke REPLACE -- there is no mirror content, got: {$invocation}");

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'continued KILL failure must leave the apply entry open');
		$this->assertSame('pfB_NoMirror_v4', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
		$this->assertApplyReservation();
	}

	// -----------------------------------------------------------------------
	// VERIFICATION (c) — Semantics #5: non-apply entries are untouched
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given an open (ip,'pfB_Test_v4',apply) entry (retried/cleared this tick)
	 *   ALONGSIDE open (ip,'pfB_Other_v4',download), (ip,'pfB_Other_v4',dedup),
	 *         (ip,'pfB_Other_v4',script), and (dnsbl,'pfb_py_zone.txt',parse) entries.
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the download entry's message/first_seen/last_seen are BYTE-IDENTICAL
	 *         before and after -- proving the tick genuinely never touched it,
	 *         not merely that it still exists.
	 */
	public function testTickNeverTouchesDownloadOrParseStageEntries(): void
	{
		pfb_sync_status_open('ip', 'pfB_Other_v4', 'download', 'HTTP 404', $this->dir, static fn() => 1000);
		pfb_sync_status_open('ip', 'pfB_Other_v4', 'dedup', 'dedup failed', $this->dir, static fn() => 1000);
		pfb_sync_status_open('ip', 'pfB_Other_v4', 'script', 'pre-script failed', $this->dir, static fn() => 1000);
		pfb_sync_status_open('dnsbl', 'pfb_py_zone.txt', 'parse', 'csv read failed', $this->dir, static fn() => 1000);

		$before = pfb_sync_status_list_open($this->dir);
		$this->assertCount(4, $before, 'seed: exactly the four non-apply entries must be open, nothing else');

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

		foreach (['ip|pfB_Other_v4|download', 'ip|pfB_Other_v4|dedup', 'ip|pfB_Other_v4|script', 'dnsbl|pfb_py_zone.txt|parse'] as $key) {
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
		$this->assertApplyReservation();
	}

	/**
	 * Scenario:
	 *   Given the SAME seeded open (dnsbl,dnsbl,apply) entry as above.
	 *   And   the underlying condition is FIXED before the tick runs (applied
	 *         catches up to sentinel out-of-band -- e.g. the watcher finished).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  the entry clears within one due reconciliation attempt, no restart / Force Reload.
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
			'a fixed underlying convergence condition must clear within one due reconciliation attempt');
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

	// -----------------------------------------------------------------------
	// issue #1666 -- hermeticity tripwire: this suite must never dispatch a
	// real cron/dcc/bl background process (setUp() future-dates every
	// due-ledger entry and neuters $pfb['php']); this pins that guarantee
	// directly instead of relying on every other test here happening not to
	// notice a leak.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given setUp()'s future-dated fixed-job ledger entries and the
	 *   recording-stub $pfb['php'] (issue #1666).
	 *   When  pfblockerng_tick() runs once.
	 *   Then  fixed-job entries stay unchanged and the php-recorder stays absent.
	 *
	 * Red->green (manual scratch probe, issue #1666): temporarily removing the
	 * setUp() ledger seeding makes this FAIL -- the absent 'dcc' entry reads
	 * as due (pfb_due_ledger_is_due_from_entry(): NULL -> due now) and the
	 * tick dispatches it through the recorder, populating the calls log.
	 *
	 * The calls log alone is race-blind: a fired dispatch backgrounds the
	 * recorder exec (`&`), so its write can land after this assertion. Fixed-job
	 * ledger entries are synchronous; the runtime cache is the cron oracle.
	 */
	public function testTickDispatchesNothingWhenNoJobIsDue(): void
	{
		$before = [];
		foreach (['dcc', 'bl'] as $jobKey) {
			$before[$jobKey] = pfb_due_ledger_read_entry($jobKey, $this->dir);
		}

		$this->tick();

		foreach (['dcc', 'bl'] as $jobKey) {
			$this->assertSame($before[$jobKey], pfb_due_ledger_read_entry($jobKey, $this->dir),
				"expected the '{$jobKey}' due-ledger entry to stay unchanged across a tick with every "
				. 'fixed-job ledger entry future-dated (issue #1666)');
		}
		// Best-effort secondary check: the recorder's write is backgrounded, so
		// an absent calls log does NOT by itself prove nothing dispatched (the
		// write can land after this assertion runs) -- the ledger asserts above
		// are the deterministic proof. This only catches the case where a
		// dispatch fired AND its write already landed.
		$this->assertFileDoesNotExist($this->phpCallsLog(),
			'expected no fixed-job dispatch branch to fire on a tick with every '
			. 'ledger entry future-dated -- a populated calls log means this suite '
			. 'leaked a real pfblockerng.php dispatch (issue #1666)');
	}
}
