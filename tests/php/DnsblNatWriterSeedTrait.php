<?php

declare(strict_types=1);

/**
 * The minimum a manual-mode, valid-VIP DNSBL needs for pfb_create_dnsbl() to reach the NAT
 * generation off-appliance (mirrors DnsblVipDisableNoticeTest scenario C), shared by the suites
 * that drive the DNSBL NAT writer.
 */
trait DnsblNatWriterSeedTrait
{
	/** @param list<array<string,mixed>> $natRows the nat/rule section the apply starts from */
	private function seedDnsblNatWriter(string $dir, array $natRows): void
	{
		global $pfb;

		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $dir;
		$pfb['dnsbl_conf'] = "{$dir}/lighty.conf";
		$pfb['dnsbl_cert'] = "{$dir}/cert.pem";
		touch($pfb['dnsbl_cert']);

		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0'] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path("{$ip}/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach ([
			'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '', 'pfb_cache' => '',
			'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '',
			'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'pfb_dnsvip4' => '_vip_test_valid',
		] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		config_set_path('virtualip/vip', [['uniqid' => '_test_valid', 'subnet' => '203.0.113.10']]);

		config_set_path('nat/rule', $natRows);
	}

	private function applyDnsblEnabled(): void
	{
		// The restart branch link()s the real lighttpd binary, which the sandbox lacks.
		set_error_handler(static fn (int $no, string $message): bool => str_starts_with($message, 'link('));
		try {
			pfb_create_dnsbl('enabled');
		} finally {
			restore_error_handler();
		}
	}
}
