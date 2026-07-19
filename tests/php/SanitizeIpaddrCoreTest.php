<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_sanitize_ipaddr')]
#[CoversFunction('pfb_sanitize_ipaddr_v6')]
final class SanitizeIpaddrCoreTest extends TestCase
{
	public function testIpv4CoreReturnsAddressAndClampMessage(): void
	{
		$this->assertSame(
			[
				'address' => '1.2.3.4',
				'messages' => ["\n  Feed /0 CIDR clamped to single host: 1.2.3.4/0"],
			],
			pfb_sanitize_ipaddr('1.2.3.4/0', false, 'Disabled', 'off')
		);
	}

	public function testIpv4CoreCarriesFloorMessageBeforeDrop(): void
	{
		$this->assertSame(
			[
				'address' => NULL,
				'messages' => ["\n  Suppression CIDR Limit: 10.0.0.5/8"],
			],
			pfb_sanitize_ipaddr('10.0.0.5/8', false, 24, 'on')
		);
	}

	public function testIpv4CoreHonorsCustomSlashZero(): void
	{
		$this->assertSame(
			['address' => '0.0.0.0/0', 'messages' => []],
			pfb_sanitize_ipaddr('0.0.0.0/0', true, 'Disabled', 'on')
		);
	}

	public function testIpv6CoreReturnsCanonicalAddressAndClampMessage(): void
	{
		$this->assertSame(
			[
				'address' => '2001:db8::1',
				'messages' => ["\n  Feed /0 CIDR clamped to single host: 2001:DB8::1/0"],
			],
			pfb_sanitize_ipaddr_v6('2001:DB8::1/0', false, 'Disabled', 'off')
		);
	}

	public function testIpv6CoreCarriesFloorMessageBeforeDrop(): void
	{
		$this->assertSame(
			[
				'address' => NULL,
				'messages' => ["\n  Suppression CIDR Limit: fc00::1/32"],
			],
			pfb_sanitize_ipaddr_v6('fc00::1/32', false, 48, 'on')
		);
	}

	public function testIpv6CoreDropsZoneWithoutMessages(): void
	{
		$this->assertSame(
			['address' => NULL, 'messages' => []],
			pfb_sanitize_ipaddr_v6('fe80::1%igb0', false, 'Disabled', 'off')
		);
	}
}
