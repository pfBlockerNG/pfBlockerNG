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
	public function testEndpointSyslogPreservesLegacyFieldsAndRoundTripsAsciiJsonInterface(): void
	{
		$base = ['q_name' => 'a.test', 'q_ip' => '198.51.100.1', 'q_type' => 'AAAA', 'group' => 'Group', 'feed' => 'Feed', 'b_type' => 'DNSBL', 'b_eval' => 'a.test', 'transport' => 'UDP'];
		$old = pfb_syslog_format_dnsbl($base);
		$this->assertSame($old, pfb_syslog_format_dnsbl($base + ['listener_ip' => '', 'listener_interface' => '']));
		foreach ([
			'旧漢字 Ελληνικά 😀',
			'LAN',
			'LAN east, "quoted" & west',
			'LAN/uplink\\backslash=literal\\u0041',
			"\u{00A0}\u{0100}\u{07FF}\u{0800}\u{10000}",
		] as $interface) {
			$body = pfb_syslog_format_dnsbl($base + ['listener_ip' => '2001:0db8::1', 'listener_interface' => $interface]);
			$this->assertSame(0, preg_match('/[^\x00-\x7f]/', $body), 'Interface representation must survive an ASCII-only syslog transport');
			preg_match_all('/(?:^| )([a-z_]+)=("(?:[^"\\\\]|\\\\.)*"|[^ ]*)(?= |$)/', $body, $matches, PREG_SET_ORDER);
			$tokens = [];
			foreach ($matches as $match) {
				$tokens[$match[1]][] = $match[2];
			}
			foreach ([
				'act' => 'dnsbl', 'qname' => 'a.test', 'qip' => '198.51.100.1', 'qtype' => 'AAAA',
				'group' => 'Group', 'feed' => 'Feed', 'btype' => 'DNSBL', 'eval' => 'a.test', 'transport' => 'UDP',
				'listener_ip' => '2001:db8::1',
			] as $key => $value) {
				$this->assertSame([$value], $tokens[$key] ?? [], $key . ' must retain its value as one field');
			}
			$this->assertCount(1, $tokens['listener_interface'] ?? [], 'Exactly one actual interface field must be emitted');
			$token = $tokens['listener_interface'][0];
			$this->assertJson($token, 'Interface must be a quoted JSON token');
			$this->assertSame($interface, json_decode($token, TRUE, 512, JSON_THROW_ON_ERROR));
		}
		foreach (['bad', '0.0.0.0', '::', '[::1]', 'fe80::1%lo0', '192.0.2.1/24', "192.0.2.1\0"] as $invalid) {
			$this->assertSame($old, pfb_syslog_format_dnsbl($base + ['listener_ip' => $invalid, 'listener_interface' => 'LAN']));
		}
	}
	public function testSyslogOmitsInvalidInterfaceButKeepsKnownEndpoint(): void
	{
		$base = ['listener_ip' => '192.0.2.1'];
		foreach (["LAN\u{0085}forged", "LAN\nforged", "LAN\0forged", "LAN\xff", "LAN\u{200D}forged", "LAN\u{200E}forged", "LAN\u{2028}forged", "LAN\u{2029}forged", "LAN\u{FEFF}forged", [], FALSE, 42, null] as $interface) {
			$body = pfb_syslog_format_dnsbl($base + ['listener_interface' => $interface]);
			$this->assertMatchesRegularExpression('/(?:^| )listener_ip=192\.0\.2\.1(?: |$)/', $body);
			$this->assertStringNotContainsString('listener_interface=', $body);
		}
	}
}
