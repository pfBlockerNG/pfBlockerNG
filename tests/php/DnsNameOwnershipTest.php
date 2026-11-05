<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsNameOwnershipTest extends TestCase
{
	private array $saved = [];
	private string|false $rc;

	protected function setUp(): void
	{
		$this->rc = @file_get_contents(PFB_DNS_PROXY_RCFILE);
		foreach (['config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_interfaces', 'pfb_test_configured_ip_addresses'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		unset($GLOBALS['pfb_test_configured_ip_addresses']);
		PfbConfig::write('dns/pfb_dns', 'on');
		PfbConfig::write('dns/pfb_dns_interface', 'lan');
		PfbConfig::write('dns/pfb_dns_name', 'fw.example.lan');
		PfbConfig::write('gen/pfb_dns_listen_vip', 'on');
		PfbConfig::write('gen/pfb_dns_listen_vip_only', 'on');
	}

	protected function tearDown(): void
	{
		if ($this->rc === FALSE) {
			@unlink(PFB_DNS_PROXY_RCFILE);
		} else {
			file_put_contents(PFB_DNS_PROXY_RCFILE, $this->rc);
		}
		foreach ($this->saved as $name => [$exists, $value]) {
			if ($exists) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	public function testVipPairTransitionsRetainLoopbackOwnershipInFlagsAndControlTable(): void
	{
		foreach ([[4, 6], [4], [6], []] as $families) {
			$pair = $rows = [];
			foreach ([4 => '172.16.53.53', 6 => 'fd00:53::1'] as $family => $address) {
				$selected = in_array($family, $families, TRUE);
				PfbConfig::write("gen/pfb_dns_listen_vip{$family}", $selected ? "_vipv{$family}" : '');
				if ($selected) {
					$pair[] = $address;
					$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
						'subnet_bits' => $family === 4 ? '32' : '128', 'descr' => 'operator', 'uniqid' => "v{$family}"];
				}
			}
			config_set_path('virtualip/vip', $rows);
			$wanted = array_fill_keys([...$pair, '127.0.0.1', '::1'], $pair);
			$this->assertSame($wanted, pfb_dns_proxy_name_answers(), 'known loopbacks remain owned even with no VIP answers');
			$flags = pfb_dns_proxy_ddr_flags();
			foreach ($wanted as $local => $answers) {
				$this->assertStringContainsString(' --dns-name-answer ' . escapeshellarg($local . '=' . implode(',', $answers)), $flags);
			}
			file_put_contents(PFB_DNS_PROXY_RCFILE, "/usr/sbin/daemon -f /bin/sh pfb_dns.sh{$flags}\n");
			$lines = pfb_dns_proxy_command_name_answers();
			$this->assertSame(array_map(static fn (string $local): string => 'dns-name-answer ' . $local . '=' . implode(',', $pair), array_keys($wanted)), $lines, 'rc command parser must retain trailing equals in live control lines');
		}
		PfbConfig::write('gen/pfb_dns_listen_vip_only', '');
		$this->assertSame(['192.0.2.1' => ['192.0.2.1', '2001:db8::1'], '2001:db8::1' => ['192.0.2.1', '2001:db8::1']], pfb_dns_proxy_name_answers(), 'mode off keeps interface generation unchanged');
	}
}
