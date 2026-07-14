<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1277 -- a GUI Save/Force (sync_package_pfblockerng(), the funnel both
 * pfblockerng_general.php's Save and pfblockerng_update.php's Force/Run Now
 * call) must schedule a retry when it loses the cross-process feed-pass lock
 * race, mirroring pfblockerng_tick()'s existing 'cron' pending_apply deferral
 * (TickFeedPassDeferralTest::testDueCronDefersWhenFeedPassLockIsHeld) instead
 * of silently dropping the requested change.
 *
 * Lock-hold technique: FeedPassLockTest's -- a second, independent fopen()
 * handle flock(LOCK_EX)s the SAME lock path; flock is per open-file-
 * description, so this genuinely contends even within one PHP process.
 *
 * Red->green: before this change the lock-loss branch was a bare `return;`
 * with no due-ledger write, so `pfb_due_ledger_read_entry('cron', $dbdir)`
 * stayed NULL after a lost race -- nothing ever scheduled a retry.
 */
final class SyncFeedPassDeferralTest extends TestCase
{
	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	/** Raw fd simulating another process holding the feed-pass lock. */
	private $lockFp = NULL;

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->dbdir = sys_get_temp_dir() . '/pfb_sync_feedpass_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'  => $this->dbdir,
			'log'    => "{$this->dbdir}/pfblockerng.log",
			'errlog' => "{$this->dbdir}/error.log",
			'runlog' => "{$this->dbdir}/run.log",
		]);

		$GLOBALS['config'] = [];
		$this->seedSyncPrereqs();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->lockFp)) {
			@flock($this->lockFp, LOCK_UN);
			@fclose($this->lockFp);
			$this->lockFp = NULL;
		}
		// Self-encapsulation: never leave this process holding the lock across tests.
		pfb_feed_pass_release();

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
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

	/** The minimum config pfb_global() (called at the top of sync_package_pfblockerng()) needs. */
	private function seedSyncPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');
		config_set_path("{$gen}/pfb_interval",   '24');
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

	/** Hold the feed-pass lock as ANOTHER process would -- a second, independent fd. */
	private function holdLockAsAnotherProcess(): void
	{
		$this->lockFp = fopen("{$this->dbdir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->lockFp, 'test setup: failed to open the lock file');
		$this->assertTrue(flock($this->lockFp, LOCK_EX), 'test setup: failed to flock the lock file');
	}

	// -----------------------------------------------------------------------
	// The RED->GREEN pinning test.
	// -----------------------------------------------------------------------

	/**
	 * Scenario:
	 *   Given a 'cron' due-ledger entry with next_due far in the future (proves
	 *   the deferral does NOT go through mark_ran/mark_ran_anchored).
	 *   And   ANOTHER process holds the feed-pass lock (simulated raw flock).
	 *   Before: the entry's next_due is the seeded future timestamp.
	 *   When  sync_package_pfblockerng() (the GUI Save/Force funnel) runs and
	 *         loses the lock race.
	 *   Then  next_due is UNCHANGED (no dispatch happened) AND pending_apply is
	 *         set, so the next cron tick retries the dropped change -- mirrors
	 *         TickFeedPassDeferralTest::testDueCronDefersWhenFeedPassLockIsHeld's
	 *         assertion shape.
	 */
	public function testLockLossSetsPendingApplyWithoutAdvancingNextDue(): void
	{
		$now = time();

		pfb_due_ledger_write_entry('cron', [
			'last_run' => $now - 3600,
			'next_due' => $now + 3600,
			'jitter'   => 0,
		], $this->dbdir);

		$this->holdLockAsAnotherProcess();

		$before = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertNotNull($before, 'test setup: cron ledger entry must exist before the call');
		$this->assertSame($now + 3600, $before['next_due'], 'test setup sanity: seeded future next_due');

		// Act -- a GUI Save/Force loses the feed-pass lock race.
		sync_package_pfblockerng();

		$after = pfb_due_ledger_read_entry('cron', $this->dbdir);
		$this->assertNotNull($after, 'cron ledger entry must still exist after the lost race');
		$this->assertSame($now + 3600, $after['next_due'],
			'cron next_due must be UNCHANGED (no dispatch happened -- mark_ran/mark_ran_anchored never ran): '
			. "expected {$now}+3600 got {$after['next_due']}");
		$this->assertTrue(!empty($after['pending_apply']),
			'cron ledger entry must be marked pending_apply so the next tick retries the dropped GUI change');
	}
}
