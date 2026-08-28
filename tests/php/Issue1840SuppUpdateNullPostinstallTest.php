<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

define('PFB_ISSUE1840_PFB_BASELINE', $GLOBALS['pfb']);

/**
 * issue #1840 -- POST-INSTALL sync fatal: pfb_ip_suppress_body_active() receives a
 * NULL $supp_update.
 *
 * Production trace (pfSense Plus 26.03.1, alpha.21->22 upgrade):
 *   Uncaught TypeError: pfb_ip_suppress_body_active(): Argument #3 ($supp_update)
 *   must be of type bool, null given, called in pfblockerng_apply.inc on line 3738
 *   (pfblockerng.inc:6587).
 *
 * Root cause: `$pfb['supp_update'] = FALSE;` is initialised at pfblockerng_apply.inc
 * only INSIDE `if ($pfb['enable'] == 'on' && !$pfb['save'])`. The package XML's
 * `custom_php_resync_config_command` (the POST-INSTALL resync pfSense's
 * install_package_xml() evals on every package upgrade) sets `$pfb['save'] = TRUE`
 * unconditionally BEFORE calling sync_package_pfblockerng() -- so that init never
 * runs. The alias/firewall-rule configure loop that reads `$pfb['supp_update']`
 * is gated by a DIFFERENT, weaker condition -- `if (!empty($lists) && $pfb['enable']
 * == 'on')` -- that does NOT check `$pfb['save']` at all, so it still runs and
 * passes the never-initialised (NULL) key into pfb_ip_suppress_body_active()'s
 * non-nullable `bool $supp_update` parameter.
 *
 * Both read sites (the v4 call at :3738 and its v6 sibling at :3760) sit in the
 * SAME per-alias-row block and run unconditionally one after the other regardless
 * of which vtype ('_v4'/'_v6') is driving that pass -- vtype only changes the
 * TRUE/FALSE value threaded into each call's own vtype-match argument, never
 * whether the call happens. :3738 always runs first, so it always throws before
 * :3760 is ever reached pre-fix; post-fix both sites run, consuming the same
 * now-properly-initialised bool. The two tests below drive the SAME two call
 * sites through the two independent producers that can populate the alias-row
 * loop with real config -- the v4 $ip_types entry (pfblockernglistsv4) and the
 * v6 one (pfblockernglistsv6) -- covering both entry points into the shared block
 * (branch coverage: either family alone is enough to trigger the fatal).
 *
 * This test drives the REAL sync_package_pfblockerng() with the exact
 * production-shaped state (enable='on', save=TRUE, as the resync command sets it)
 * and one real enabled Deny list/row, so the alias-configure loop reaches the
 * suppression-body calls with no other guard able to skip them (suppression
 * itself can stay OFF -- the crash is in evaluating the calls' arguments, not in
 * the suppression logic those arguments feed).
 */
final class Issue1840SuppUpdateNullPostinstallTest extends TestCase
{
	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->hadConfig      = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_issue1840_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		mkdir("{$this->dbdir}/deny", 0755, TRUE);

		$GLOBALS['pfb'] = array_merge(PFB_ISSUE1840_PFB_BASELINE, [
			'dbdir'    => $this->dbdir,
			'schedule_state_dir' => $this->dbdir,
			'log'      => "{$this->dbdir}/pfblockerng.log",
			'errlog'   => "{$this->dbdir}/error.log",
			'runlog'   => "{$this->dbdir}/run.log",
			// This test's crash sits well past the download/geoip/recompute stages
			// ($pfb['save'] = TRUE skips all of them, mirroring the real resync path)
			// -- only the alias-configure folders below are actually read.
			'denydir'  => "{$this->dbdir}/deny",
		]);

		$GLOBALS['config'] = [];

		$gen = 'installedpackages/pfblockerng/config/0';
		$ip  = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		// Minimum pfb_global() prerequisites (mirrors SyncFeedPassDeferralTest).
		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');
		config_set_path("{$gen}/pfb_interval",   '24');
		config_set_path("{$gen}/pfb_quiet_hours", '');
		config_set_path("{$gen}/pfb_reuse",      '');
		// The bug's own trigger: pfBlockerNG enabled.
		config_set_path("{$gen}/enable_cb",      'on');

		config_set_path("{$ip}/suppression",     '');	// suppression OFF: the crash is in
								// evaluating the call's args, not the
								// suppression decision itself.
		config_set_path("{$ip}/database_cc",     '');
		config_set_path("{$ip}/maxmind_locale",  'en');
		config_set_path("{$ip}/asn_reporting",   'disabled');
		config_set_path("{$ip}/asn_token",       '');
		config_set_path("{$ip}/maxmind_account", '');
		config_set_path("{$ip}/maxmind_key",     '');
		config_set_path("{$ip}/enable_dup",      '');
		config_set_path("{$ip}/enable_agg",      '');
		config_set_path("{$ip}/enable_float",    '');
		config_set_path("{$ip}/enable_log",      '');
		config_set_path("{$ip}/killstates",      '');
		config_set_path("{$ip}/ip_placeholder",  '');
		config_set_path("{$ip}/inbound_deny_action",  '');
		config_set_path("{$ip}/outbound_deny_action", '');
		config_set_path("{$ip}/pass_order",      '');
		config_set_path("{$ip}/autorule_suffix", '');

		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Disable');
		config_set_path('installedpackages/pfblockerngreputation/config/0/enable_dedup', '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/enable_pdup',  '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/enable_rep',   '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/et_update',    '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/ccwhite',      '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/ccblack',      '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/etblock',      '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/etmatch',      '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/p24_max_var',  '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/p24_dmax_var', '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/p24_pmax_var', '');
		config_set_path('installedpackages/pfblockerngreputation/config/0/ccexclude',    '');

		config_set_path("{$dnsbl}/pfb_dnsvip4",     '');
		config_set_path("{$dnsbl}/pfb_dnsvip6",     '');
		config_set_path("{$dnsbl}/pfb_dnsport",     '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path("{$dnsbl}/top1m_enable",    '');
		config_set_path("{$dnsbl}/top1m_count",     '');
		config_set_path("{$dnsbl}/top1m_inclusion", '');
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
		config_set_path("{$dnsbl}/pfb_dnsbl_rule",  '');
		config_set_path("{$dnsbl}/tld_wildcard",    '');
		config_set_path("{$dnsbl}/pfb_control",     '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}

		// Plain runtime flags pfb_global()/the (skipped, save=TRUE) DNSBL block would
		// otherwise leave unset -- unrelated to issue #1840, seeded only to keep this
		// test's warning output limited to the ONE undefined key the bug is about.
		$GLOBALS['pfb']['install']      = FALSE;
		$GLOBALS['pfb']['domain_clear'] = FALSE;

		// No lists by default -- each test seeds the ONE family (v4 or v6) it drives
		// through seedDenyList(), so the OTHER family's empty $lists short-circuits
		// pfblockerng_apply.inc's `if (!empty($lists) && ...)` before it can reach
		// (or crash on) that family's own suppression-body call.
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);

		// PRODUCTION-SHAPED STATE: the package XML's custom_php_resync_config_command
		// sets this unconditionally BEFORE calling sync_package_pfblockerng() -- the
		// exact POST-INSTALL resync path from the issue.
		$GLOBALS['pfb']['save'] = TRUE;
	}

	/**
	 * One real, enabled Deny list+row for the given family -- reaches that family's
	 * suppression-body call (pfblockerng_apply.inc:3738 for '_v4', :3760 for '_v6')
	 * with file_exists()+member_eligible both TRUE. The autorule fields (autoproto,
	 * autonot, autoaddrnot, agateway, autoports, autoaddr -- each _in/_out) mirror
	 * a real saved GUI row with every "Advanced" option left off.
	 */
	private function seedDenyList(string $vtype): void
	{
		$section = ($vtype === '_v6') ? 'pfblockernglistsv6' : 'pfblockernglistsv4';
		$header  = 'Issue1840Feed';

		config_set_path("installedpackages/{$section}/config", [
			[
				'action'         => 'Deny_Both',
				'aliasname'      => 'Issue1840',
				'autoproto_in'   => '', 'autoproto_out'   => '',
				'autonot_in'     => '', 'autonot_out'     => '',
				'autoaddrnot_in' => '', 'autoaddrnot_out' => '',
				'agateway_in'    => '', 'agateway_out'    => '',
				'autoports_in'   => '', 'autoports_out'   => '',
				'autoaddr_in'    => '', 'autoaddr_out'    => '',
				'row'       => [
					['header' => $header, 'url' => 'file:///issue1840', 'state' => 'Enabled'],
				],
			],
		]);

		// The member file the loop concatenates -- must exist for file_exists() to let
		// the loop reach the suppression-body call at all. The on-disk name is
		// "{header}{vtype}.txt" (pfblockerng_apply.inc builds $header as
		// "{$row['header']}{$vtype}").
		file_put_contents("{$this->dbdir}/deny/{$header}{$vtype}.txt", "203.0.113.1\n");
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
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

	/**
	 * Scenario: POST-INSTALL resync (save=TRUE, enable='on') must not crash --
	 * entered via the v4 $ip_types producer (pfblockernglistsv4).
	 *   Given the exact state custom_php_resync_config_command puts $pfb in, and a
	 *   real enabled Deny alias/row (v4 family) whose member file already exists on
	 *   disk -- v6 stays empty, so only the v4 $ip_types iteration populates the
	 *   alias-row loop this pass.
	 *   When sync_package_pfblockerng() runs (the POST-INSTALL resync funnel).
	 *   Then it must NOT throw -- `$pfb['supp_update']` must be a real bool at BOTH
	 *   read sites the alias-configure loop reaches for this row
	 *   (pfblockerng_apply.inc:3738 then :3760 -- both run regardless of vtype), on
	 *   this path exactly as they do on the '!save' Update-pass path.
	 */
	public function testPostInstallResyncDoesNotCrashOnNullSuppUpdateV4(): void
	{
		$this->seedDenyList('_v4');

		try {
			sync_package_pfblockerng();
		} catch (\TypeError $e) {
			$this->fail(
				"sync_package_pfblockerng() must not TypeError on the POST-INSTALL resync path "
				. "(issue #1840, via the v4 \$ip_types producer): " . $e->getMessage()
			);
		}
		$this->assertIsBool(
			$GLOBALS['pfb']['supp_update'] ?? null,
			"\$pfb['supp_update'] must be deterministically initialised (a real bool) on every "
			. "path that reaches the alias-configure suppression loop, including save=TRUE"
		);
	}

	/**
	 * Scenario: POST-INSTALL resync (save=TRUE, enable='on') must not crash --
	 * entered via the v6 $ip_types producer (pfblockernglistsv6).
	 *   Given the same production-shaped state, but the real enabled list/row is on
	 *   the v6 side only (v4 stays empty, so only the v6 $ip_types iteration
	 *   populates the alias-row loop this pass -- a second, independent producer
	 *   into the SAME shared block :3738/:3760 sit in).
	 *   When sync_package_pfblockerng() runs.
	 *   Then it must NOT throw -- same dual-site assertion as the v4 test above,
	 *   proving the fix is not accidentally coupled to which family's config
	 *   happens to be non-empty.
	 */
	public function testPostInstallResyncDoesNotCrashOnNullSuppUpdateV6(): void
	{
		$this->seedDenyList('_v6');

		try {
			sync_package_pfblockerng();
		} catch (\TypeError $e) {
			$this->fail(
				"sync_package_pfblockerng() must not TypeError on the POST-INSTALL resync path "
				. "(issue #1840, via the v6 \$ip_types producer): " . $e->getMessage()
			);
		}
		$this->assertIsBool(
			$GLOBALS['pfb']['supp_update'] ?? null,
			"\$pfb['supp_update'] must be deterministically initialised (a real bool) on every "
			. "path that reaches the alias-configure suppression loop, including save=TRUE"
		);
	}
}
