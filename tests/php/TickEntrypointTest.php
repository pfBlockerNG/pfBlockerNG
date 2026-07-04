<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #573 — scheduled log maintenance must survive pfb_interval='Disabled'.
 *
 * pfblockerng_tick() is the ONLY scheduled path to pfb_log_mgmt()/pfb_log_reset()
 * (ADR30-1). Before this change those two calls lived at the tail of
 * pfblockerng_sync_cron(), reachable only through the tick's feed-cron dispatch,
 * itself gated on `!$cron_disabled` (pfb_interval !== 'Disabled'). A user who set
 * Update Frequency to 'Disabled' therefore silently stopped ALL scheduled log
 * trim/reset, with no warning.
 *
 * This suite drives the REAL pfblockerng_tick() entrypoint -- relocated here
 * (from the www/ dispatcher script, which is never require()'d off-appliance)
 * so it is loadable by the PHPUnit bootstrap, per ADR43-5 -- and pins that log
 * maintenance now runs unconditionally, every tick, regardless of the feed-cron
 * cadence.
 *
 * Red→green: before this change pfblockerng_tick() existed only in
 * src/usr/local/www/pfblockerng/pfblockerng.php, a script the PHPUnit bootstrap
 * never loads -- every test below failed against the pre-change worktree with
 * "Call to undefined function pfblockerng_tick()".
 *
 * Branch coverage:
 *   Case A — pfb_interval='Disabled' (the bug): log maintenance still runs.
 *   Case B — pfb_interval numeric + feed cron NOT due (future ledger entry):
 *            log maintenance still runs -- proving it is unconditional, not
 *            merely re-homed behind the same due-job gate.
 */
final class TickEntrypointTest extends TestCase
{
	/** Per-test private sandbox for $pfb['dbdir'] -- see setUp(). */
	private string $dbdir = '';

	/** Whether $GLOBALS['pfb']['dbdir'] was set before this test, and its value. */
	private bool $hadDbdir = FALSE;
	private mixed $originalDbdir = NULL;

	/**
	 * Self-encapsulated (CLAUDE.md mandate): pfblockerng_tick() reads/writes the
	 * due-ledger + log-rotate marker at $pfb['dbdir'] (not injectable), a path a
	 * sibling suite (SoftwareUpdateCheckTest) also repoints at its own sandbox
	 * WITHOUT restoring the original on teardown -- so $pfb['dbdir'] cannot be
	 * trusted to reflect the bootstrap value by the time this suite runs. Give
	 * this suite its OWN private, guaranteed-empty dbdir per test instead of
	 * depending on (or wiping) whatever the shared one currently holds; restore
	 * the prior value afterwards so later suites see no side effect from this one.
	 */
	protected function setUp(): void
	{
		$this->hadDbdir      = array_key_exists('dbdir', $GLOBALS['pfb'] ?? []);
		$this->originalDbdir = $GLOBALS['pfb']['dbdir'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_tick_entrypoint_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;

		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->originalDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		$this->rrmdir($this->dbdir);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = "{$dir}/{$entry}";
			is_dir($path) ? $this->rrmdir($path) : @unlink($path);
		}
		@rmdir($dir);
	}

	// -----------------------------------------------------------------------
	// Seeding helpers (mirrors LogRotateResetTest::seedConfigForReset() -- the
	// established minimum pfb_global() needs to run warning-free off-box).
	// -----------------------------------------------------------------------

	private function logPath(string $logtype): string
	{
		return $GLOBALS['pfb'][$logtype];
	}

	private function ensureLogDir(): void
	{
		$logdir = $GLOBALS['pfb']['logdir'];
		if (!is_dir($logdir)) {
			@mkdir($logdir, 0755, TRUE);
		}
	}

	/**
	 * Seed the minimum config keys pfb_global() reads (avoids undefined-array-key
	 * warnings against a near-empty test config), the tick cadence knob under
	 * test ($rawInterval), an always-apply quiet-hours window, and a scheduled
	 * line-cap ('log') + calendar reset ('errlog') so a real tick call exercises
	 * BOTH log-maintenance functions distinguishably.
	 */
	private function seedTickPrereqs(string $rawInterval): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');

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

		// Tick cadence knobs under test (issue #573: 'Disabled' must not gate
		// log maintenance -- see pfblockerng_tick()).
		config_set_path("{$gen}/pfb_interval",    $rawInterval);
		config_set_path("{$gen}/pfb_quiet_hours", ''); // apply immediately, no deferral

		// pfb_log_mgmt(): cap 'log' to 3 lines; every other type stays at the
		// registry default (20000) -> no-op trim, keeping the test single-purpose.
		config_set_path("{$gen}/log_max_log", '3');

		// pfb_log_reset(): 'errlog' has a daily reset schedule; every other type
		// stays 'off' (registry default) -> no-op reset except for 'errlog'.
		config_set_path("{$gen}/log_rotate_errlog",     'daily');
		config_set_path("{$gen}/log_reset_keep_errlog", '0');
	}

	/**
	 * Write a stale (yesterday) log_rotate.last marker entry for $logtype, so
	 * pfb_log_reset() finds its daily schedule "due" (period rolled over).
	 */
	private function writeStaleMarker(string $logtype): void
	{
		$markerPath = $GLOBALS['pfb']['dbdir'] . '/log_rotate.last';
		$yesterday  = date('Y-m-d', strtotime('-1 day'));
		file_put_contents($markerPath, "{$logtype}={$yesterday}\n");
	}

	/**
	 * Seed a future (not-yet-due), non-pending ledger entry so pfblockerng_tick()
	 * does not dispatch a real exec() for $jobKey.
	 */
	private function seedFutureLedgerEntry(string $jobKey, int $now): void
	{
		pfb_due_ledger_write_entry($jobKey, [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $GLOBALS['pfb']['dbdir']);
	}

	// -----------------------------------------------------------------------
	// Case A — the bug: pfb_interval='Disabled' must not silently stop log
	// maintenance.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given pfb_interval='Disabled' (the feed cron is entirely gated off).
	 *   And   a 5-line 'log' file with log_max_log=3 (pfb_log_mgmt should trim it).
	 *   And   a non-empty 'errlog' file with a stale daily marker (pfb_log_reset
	 *         should clear it).
	 *   Before: 'log' has 5 lines; 'errlog' is non-empty.
	 *   When  pfblockerng_tick() is called.
	 *   Then  'log' is trimmed to its last 3 lines (pfb_log_mgmt ran).
	 *   And   'errlog' is fully cleared and its marker advanced to today
	 *         (pfb_log_reset ran) -- log maintenance survives a Disabled
	 *         Update Frequency (issue #573).
	 */
	public function testDisabledIntervalStillRunsLogMaintenance(): void
	{
		$this->seedTickPrereqs('Disabled');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- the real
		// dispatcher always calls pfb_global() once before routing to any verb
		// (including 'tick'), which is what populates $pfb['enable']/['blconfig']
		// and creates $pfb['dbdir']/['logdir'] on disk.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		// Prevent a real exec() dispatch for dcc/bl (both fail-safe "due" when
		// their ledger entry is absent); 'cron' needs no seeding here because
		// $cron_disabled short-circuits its dispatch regardless of due state.
		$this->seedFutureLedgerEntry('dcc', $now);
		$this->seedFutureLedgerEntry('bl',  $now);

		$logPath    = $this->logPath('log');
		$errlogPath = $this->logPath('errlog');

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");
		file_put_contents($errlogPath, "some error\n");
		$this->writeStaleMarker('errlog');

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore};\n"
			. '  content=' . var_export(file_get_contents($logPath), TRUE));
		$this->assertGreaterThan(0, filesize($errlogPath),
			"Before: expected 'errlog' non-empty, got " . filesize($errlogPath) . ' bytes');

		// Act.
		pfblockerng_tick();

		// After: pfb_log_mgmt() trimmed 'log' to its last 3 lines.
		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After tick with pfb_interval='Disabled': expected 'log' trimmed to [l3,l4,l5], got "
			. var_export($linesAfter, TRUE)
			. ' -- pfb_log_mgmt() must run every tick, not only when the feed cron is enabled');

		// After: pfb_log_reset() cleared 'errlog' and advanced its marker.
		clearstatcache(TRUE, $errlogPath);
		$this->assertSame(0, filesize($errlogPath),
			"After tick with pfb_interval='Disabled': expected 'errlog' fully cleared, got "
			. filesize($errlogPath) . ' bytes -- pfb_log_reset() must run every tick');

		$markerContents = (string) file_get_contents($GLOBALS['pfb']['dbdir'] . '/log_rotate.last');
		$entries        = pfb_log_rotate_marker_parse($markerContents);
		$this->assertSame(date('Y-m-d'), $entries['errlog'] ?? NULL,
			"After tick: expected 'errlog' marker advanced to today (" . date('Y-m-d') . '), got '
			. var_export($entries['errlog'] ?? NULL, TRUE));
	}

	// -----------------------------------------------------------------------
	// Case B — branch coverage: the feed cron NOT being due must not gate log
	// maintenance either (proves it is unconditional, not merely re-homed
	// behind the due-ledger check that used to gate pfblockerng_sync_cron()).
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given pfb_interval='24' (a normal numeric cadence, NOT disabled).
	 *   And   the 'cron' ledger entry is NOT due (next_due 1h in the future).
	 *   And   the same 'log'/'errlog' seeding as Case A.
	 *   Before: 'log' has 5 lines; 'errlog' is non-empty; 'cron' next_due is
	 *           1h in the future.
	 *   When  pfblockerng_tick() is called.
	 *   Then  the feed cron is NOT dispatched (its ledger entry is untouched --
	 *         no mark_ran).
	 *   And   'log' is STILL trimmed and 'errlog' STILL cleared -- log
	 *         maintenance runs regardless of whether the feed cron itself was
	 *         due this tick.
	 */
	public function testLogMaintenanceRunsEvenWhenFeedCronNotDue(): void
	{
		$this->seedTickPrereqs('24');
		// Mirrors src/usr/local/www/pfblockerng/pfblockerng.php:63 -- see the
		// sibling Case A test for why this must run before any ledger/log I/O.
		pfb_global();
		$this->ensureLogDir();

		$now = time();
		$this->seedFutureLedgerEntry('cron', $now);
		$this->seedFutureLedgerEntry('dcc',  $now);
		$this->seedFutureLedgerEntry('bl',   $now);

		$logPath    = $this->logPath('log');
		$errlogPath = $this->logPath('errlog');

		file_put_contents($logPath, implode("\n", ['l1', 'l2', 'l3', 'l4', 'l5']) . "\n");
		file_put_contents($errlogPath, "some error\n");
		$this->writeStaleMarker('errlog');

		// Before.
		$linesBefore = count(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(5, $linesBefore,
			"Before: expected 'log' to have 5 lines, got {$linesBefore}");
		$this->assertGreaterThan(0, filesize($errlogPath),
			"Before: expected 'errlog' non-empty, got " . filesize($errlogPath) . ' bytes');

		// Act.
		pfblockerng_tick();

		// The feed cron ledger entry must be unchanged (no mark_ran) -- confirms
		// the tick genuinely treated 'cron' as not-due this pass.
		$cronEntry = pfb_due_ledger_read_entry('cron', $GLOBALS['pfb']['dbdir']);
		$this->assertNotNull($cronEntry, 'cron ledger entry must still exist after the tick');
		$this->assertSame($now + 3600, $cronEntry['next_due'],
			'cron next_due must be unchanged (not marked ran): expected ' . ($now + 3600)
			. " got {$cronEntry['next_due']} -- the feed cron must NOT have dispatched this tick");

		// After: log maintenance ran anyway.
		clearstatcache(TRUE, $logPath);
		$linesAfter = array_values(array_filter(explode("\n", (string) file_get_contents($logPath)), 'strlen'));
		$this->assertSame(['l3', 'l4', 'l5'], $linesAfter,
			"After tick with feed cron NOT due: expected 'log' still trimmed to [l3,l4,l5], got "
			. var_export($linesAfter, TRUE)
			. ' -- log maintenance must be unconditional, not gated behind the feed-cron due check');

		clearstatcache(TRUE, $errlogPath);
		$this->assertSame(0, filesize($errlogPath),
			"After tick with feed cron NOT due: expected 'errlog' still fully cleared, got "
			. filesize($errlogPath) . ' bytes');
	}
}
