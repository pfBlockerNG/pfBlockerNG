<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsTransportSyslogTest extends TestCase
{
	public function testExistingDnsblEventAddsOnlyCanonicalTransportWhenProvided(): void
	{
		$base = ['q_name' => 'a,"b.test', 'q_ip' => '10.0.0.5', 'q_type' => 'A', 'group' => 'Group', 'feed' => 'Feed', 'b_type' => 'DNSBL', 'b_eval' => 'a,"b.test'];
		$old = pfb_syslog_format_dnsbl($base);
		$this->assertStringNotContainsString('transport=', $old);
		foreach (['TCP', 'UDP', 'DoT', 'DoH', 'DoQ', [], '<script>', null] as $value) {
			$expected = is_string($value) && in_array($value, ['TCP', 'UDP', 'DoT', 'DoH', 'DoQ'], TRUE) ? $value : 'Unknown';
			$this->assertSame($old . ' transport=' . $expected, pfb_syslog_format_dnsbl($base + ['transport' => $value]));
		}
	}
	public function testEndpointSyslogAddsCanonicalEscapedTokensWithoutChangingOldRows(): void
	{
		$base = ['q_name' => 'a.test', 'q_ip' => '198.51.100.1', 'transport' => 'UDP'];
		$old = pfb_syslog_format_dnsbl($base);
		$this->assertSame($old, pfb_syslog_format_dnsbl($base + ['listener_ip' => '', 'listener_interface' => '']));
		$this->assertSame($old . ' listener_ip=2001:db8::1 listener_interface=' . pfb_syslog_escape('Län,"\\'),
			pfb_syslog_format_dnsbl($base + ['listener_ip' => '2001:0db8::1', 'listener_interface' => 'Län,"\\']));
		foreach (['bad', '0.0.0.0', '::', '[::1]', 'fe80::1%lo0', '192.0.2.1/24'] as $invalid) {
			$this->assertSame($old, pfb_syslog_format_dnsbl($base + ['listener_ip' => $invalid, 'listener_interface' => 'LAN']));
		}
	}
	public function testSyslogOmitsControlInterfaceButKeepsKnownEndpoint(): void
	{
		$base = ['listener_ip' => '192.0.2.1'];
		$this->assertSame(pfb_syslog_format_dnsbl($base),
			pfb_syslog_format_dnsbl($base + ['listener_interface' => "LAN\u{0085}forged"]));
	}
}
