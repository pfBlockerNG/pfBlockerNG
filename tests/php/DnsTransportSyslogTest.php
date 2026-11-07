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
			$expected = is_string($value) && in_array($value, ['TCP', 'UDP', 'DoT', 'DoH', 'DoQ'], true) ? $value : 'Unknown';
			$this->assertSame($old . ' transport=' . $expected, pfb_syslog_format_dnsbl($base + ['transport' => $value]));
		}
	}
}
