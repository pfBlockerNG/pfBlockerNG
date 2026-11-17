<?php

declare(strict_types=1);

/**
 * The DNSBL NAT rows a box upgraded from a version with the DNSBL web server may still hold, for the suites that drive the
 * removal of those rows (issue #4053, pfb_dnsbl_webserver_retire()).
 */
trait DnsblNatWriterSeedTrait
{
	/** @param list<array<string,mixed>> $natRows the nat/rule section the retire starts from */
	private function seedDnsblNatWriter(string $dir, array $natRows): void
	{
		global $pfb;

		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $dir;
		$pfb['dnsbl_conf'] = "{$dir}/lighty.conf";
		$pfb['dnsbl_cert'] = "{$dir}/cert.pem";
		$pfb['unbound_py_vip'] = "{$dir}/pfb_py_vip";
		$GLOBALS['pfb_test_service_running'] = ['pfb_dnsbl' => FALSE];
		config_set_path('nat/rule', $natRows);
	}
}
