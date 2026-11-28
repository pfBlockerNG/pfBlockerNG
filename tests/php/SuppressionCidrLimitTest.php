<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3413 -- one global Suppression CIDR Limit (IP tab) for every IP list and for DNSBLIP: pfb_global() publishes
 * the stored IPv4 and IPv6 limits, Disabled when absent.
 */
#[CoversFunction('pfb_global')]
final class SuppressionCidrLimitTest extends TestCase
{
	private const IP = 'installedpackages/pfblockerngipsettings/config/0';

	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'g'] as $g) {
			$this->saved[$g] = [array_key_exists($g, $GLOBALS), $GLOBALS[$g] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $g => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$g] = $value;
			} else {
				unset($GLOBALS[$g]);
			}
		}
	}

	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		foreach (['pfb_min', 'pfb_hour', 'pfb_dailystart', 'skipfeed'] as $key) {
			config_set_path("{$gen}/{$key}", '0');
		}
		foreach (['suppression' => 'on', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
			'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path(self::IP . "/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '',
			'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '',
			'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => ''] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}
	}

	/** pfb_global() publishes the stored limits for the download loop; absent keys publish Disabled. */
	public function testPfbGlobalPublishesTheStoredGlobalLimits(): void
	{
		$this->seedGlobalPrereqs();

		pfb_global();
		$this->assertSame(['Disabled', 'Disabled'], [$GLOBALS['pfb']['supp_cidr'] ?? NULL, $GLOBALS['pfb']['supp_cidr_v6'] ?? NULL],
			'before: nothing stored, both limits are Disabled');

		config_set_path(self::IP . '/suppression_cidr', '8');
		config_set_path(self::IP . '/suppression_cidr_v6', '32');
		pfb_global();
		$this->assertSame(['8', '32'], [$GLOBALS['pfb']['supp_cidr'] ?? NULL, $GLOBALS['pfb']['supp_cidr_v6'] ?? NULL]);
	}
}
