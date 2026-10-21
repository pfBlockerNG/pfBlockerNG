<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #331 — a manual-mode DNSBL VIP validation failure (e.g. a restored config.xml
 * with a malformed VIP reference) force-disables DNSBL inside pfb_global() with only a
 * pfb_logger() entry — nothing in the pfSense GUI ever tells the operator why DNSBL
 * stopped. This pins the fix: the same force-disable now also raises a file_notice(),
 * mirroring the existing MaxMind/ASN credential-notice pattern in this same function.
 *
 * Scenario A (the bug) — manual mode, invalid VIP:
 *   Given pfb_dnsbl='on', pfb_dnsvip_auto='' (manual), pfb_dnsvip4 an id pfb_get_vips()
 *         cannot resolve (empty VIP list -> "invalid IPv4 VIP").
 *   Before: no notices raised.
 *   When  pfb_global() runs.
 *   Then  $pfb['dnsbl'] is force-disabled (unchanged behaviour) AND a file_notice()
 *         fires naming the reason -- FAILS on pre-fix code (no notice), PASSES after.
 *
 * Scenario B (must stay unaffected) — auto-create mode, invalid VIP:
 *   Given the same unresolvable VIP id, but pfb_dnsvip_auto='on' (interface is left at
 *         the 'lo0' default here, so validation actually fails on interface mismatch
 *         rather than Scenario A's "invalid IPv4 VIP" -- irrelevant to this branch,
 *         which only checks $vips_valid_result[0], never the reason string).
 *   Then  validation is deferred to the auto-create bootstrap (existing behaviour) and
 *         NO file_notice() fires -- the fix must not fire while auto-create still owns
 *         provisioning.
 *
 * Scenario C (must stay unaffected) — manual mode, valid VIP:
 *   Given a VIP id that resolves via the seeded pfb_test_vip_list on the matching
 *         interface, so pfb_validate_vips() returns valid.
 *   Then  DNSBL stays enabled and NO file_notice() fires.
 *
 * issue #3539 — the validation only runs while an effective DNSBL block still answers with the
 * VIP (pfb_dnsbl_vip_demand()). setUp() seeds one such group so the three scenarios above keep
 * exercising the validation; the demand scenarios below remove or flip it.
 */
#[CoversFunction('pfb_global')]
#[CoversFunction('pfb_dnsbl_vip_demand')]
final class DnsblVipDisableNoticeTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config']                    = [];
		$GLOBALS['pfb_test_file_notices']     = [];
		$GLOBALS['pfb_test_vip_list']         = [];
		unset($GLOBALS['pfb_test_specialnet']);
		$this->seedGlobalPrereqs();
	}

	/**
	 * Seed the minimum config keys pfb_global() reads (mirrors
	 * TickEntrypointTest::seedTickPrereqs() -- the established minimum pfb_global()
	 * needs to run warning-free off-box), trimmed to the non-DNSBL keys this suite
	 * does not vary.
	 */
	private function seedGlobalPrereqs(): void
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

		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'lo0');
		$this->seedVipGroup('enabled');
	}

	/** One unbound group with a feed row; 'enabled' answers with the VIP (demand), 'disabled_log' does not. */
	private function seedVipGroup(string $logging): void
	{
		config_set_path('installedpackages/pfblockerngdnsbl/config', [[
			'aliasname' => 'T1',
			'action'    => 'unbound',
			'logging'   => $logging,
			'row'       => [['url' => 'https://example.com/list.txt', 'state' => 'Enabled', 'header' => 'T1_a', 'format' => 'auto']],
		]]);
	}

	public function testManualModeInvalidVipSurfacesFileNotice(): void
	{
		// Given: manual mode (auto='off'), a VIP id on the matching (doubled) interface
		// but absent from the (empty) seeded vip list -> pfb_validate_vips() passes the
		// interface check, then fails "invalid IPv4 VIP" (unresolved).
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');

		// Before: no notices raised yet.
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice before pfb_global() runs');

		// When
		pfb_global();

		// Then: force-disable still happens (unchanged behaviour) ...
		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['dnsbl'], 'manual mode: an invalid VIP still force-disables DNSBL');

		// ... AND a file_notice() now surfaces the reason (the fix).
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'exactly one notice raised');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame('pfBlockerNG DNSBL', $notice['id']);
		$this->assertStringContainsString('DNSBL disabled:', $notice['notice']);
		$this->assertStringContainsString('invalid IPv4 VIP', $notice['notice']);
		$this->assertSame('/pfblockerng/pfblockerng_dnsbl.php', $notice['url']);
	}

	public function testAutoModeInvalidVipDoesNotSurfaceNotice(): void
	{
		// Given: the SAME invalid VIP, but auto-create mode owns provisioning.
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', 'on');

		// When
		pfb_global();

		// Then: auto-create's deferral is unchanged -- no notice, DNSBL stays enabled
		// for this same pass (pfb_manage_dnsbl_vip provisions it afterwards).
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'auto mode defers -- no notice fires');
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'auto mode: DNSBL is not force-disabled here');
	}

	public function testValidVipDoesNotSurfaceNotice(): void
	{
		// Given: a VIP id that DOES resolve -- seed the doubled VIP list + specialnet so
		// pfb_get_vips() finds it, and use the doubled 'opt-double' interface so the
		// interface check passes too (see pfsense_doubles.php get_configured_vip_interface).
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_valid');

		// When
		pfb_global();

		// Then: validation passes -- DNSBL stays enabled, no notice.
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'a genuinely valid VIP leaves DNSBL enabled');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice when the VIP is valid');
	}

	public function testManualModeWithoutAnyVipKeepsDnsblOnWhenNothingAnswersWithTheVip(): void
	{
		// Given: manual mode, no VIP configured, and the only group blocks with Null Blocking.
		$this->seedVipGroup('disabled_log');

		// When
		pfb_global();

		// Then: nothing needs the VIP, so there is nothing to validate, disable or notify.
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_demand'], 'no block answers with the VIP');
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'DNSBL stays enabled without a VIP');
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_disabled'], 'not force-disabled');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice without demand');
	}

	public function testManualModeWithStaleVipIdKeepsDnsblOnWhenNothingAnswersWithTheVip(): void
	{
		// Given: manual mode, a VIP id that no longer exists, and no block that answers with the VIP.
		$this->seedVipGroup('disabled_log');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');

		// When
		pfb_global();

		// Then
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_demand']);
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'a stale VIP reference is not an error without demand');
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_disabled']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testManualModeWithoutAnyVipForceDisablesWhileDemandExistsAndRecoversWhenItGoes(): void
	{
		// Before: setUp's group answers with the VIP and no VIP is configured -> today's force-disable + notice.
		pfb_global();

		$this->assertTrue($GLOBALS['pfb']['dnsbl_vip_demand'], 'the seeded group demands the VIP');
		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['dnsbl'], 'demand without a VIP force-disables DNSBL');
		$this->assertTrue($GLOBALS['pfb']['dnsbl_vip_disabled']);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('no VIP configured', $GLOBALS['pfb_test_file_notices'][0]['notice']);

		// Flip: the SAME configuration, only the group's mechanism moves off the VIP.
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->seedVipGroup('disabled_log');
		pfb_global();

		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_demand']);
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'DNSBL is enabled again once nothing needs the VIP');
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_disabled']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testABlacklistCategoryAloneDemandsTheVipThroughPfbGlobal(): void
	{
		// Given no DNSBL group at all, so only the Blacklist category can ask for the VIP
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		pfb_global();
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_demand'], 'before-state: nothing answers with the VIP');
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl'], 'before-state: DNSBL is on');

		// When an enabled Blacklist category with a category selection answers with the VIP
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'ut1', 'blacklist_logging' => 'enabled',
			'item' => [['xml' => 'ut1', 'title' => 'UT1', 'selected' => 'adult']],
		]);
		pfb_global();

		// Then pfb_global() hands the Blacklist to the demand predicate: the VIP is demanded, and its absence force-disables DNSBL
		$this->assertTrue($GLOBALS['pfb']['dnsbl_vip_demand'], 'the Blacklist category alone demands the VIP');
		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['dnsbl'], 'demand without a VIP force-disables DNSBL');
	}
}
