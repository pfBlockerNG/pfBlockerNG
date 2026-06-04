<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * sanitize_ipaddr() — normalise an IPv4(/mask): strip leading zeros, drop a /32,
 * auto-/24 a trailing-zero host, force the 4th octet to 0 on /24, and (when
 * $pfb['supp']=='on' and not a custom list) drop loopback/reserved/private and
 * apply the Advanced CIDR floor.
 */
#[CoversFunction('sanitize_ipaddr')]
final class SanitizeIpaddrTest extends TestCase
{
	protected function setUp(): void
	{
		// Default: suppression OFF (no reserved/private filtering).
		$GLOBALS['pfb']['supp'] = 'off';
	}

	// --- Normalisation (suppression off) -------------------------------------

	public function testStripsSlash32(): void
	{
		$this->assertSame('192.0.2.5', sanitize_ipaddr('192.0.2.5/32', false, 'Disabled'));
	}

	public function testKeepsExplicitSubnet(): void
	{
		$this->assertSame('10.0.0.0/24', sanitize_ipaddr('10.0.0.0/24', false, 'Disabled'));
	}

	public function testAutoSlash24WhenTrailingOctetZeroAndNoMask(): void
	{
		$this->assertSame('192.0.2.0/24', sanitize_ipaddr('192.0.2.0', false, 'Disabled'));
	}

	public function testSlash24ForcesFourthOctetToZero(): void
	{
		$this->assertSame('192.0.2.0/24', sanitize_ipaddr('192.0.2.7/24', false, 'Disabled'));
	}

	public function testStripsLeadingZeroOctets(): void
	{
		$this->assertSame('192.0.2.5', sanitize_ipaddr('192.000.002.005/32', false, 'Disabled'));
	}

	// --- Suppression on (reserved/private dropped unless custom) --------------

	public function testSuppressionKeepsPublicIp(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('192.0.2.5', sanitize_ipaddr('192.0.2.5/32', false, 'Disabled'));
	}

	public function testSuppressionDropsPrivateIp(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('10.0.0.5/32', false, 'Disabled'));
	}

	public function testSuppressionDropsLoopback(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('127.0.0.1/32', false, 'Disabled'));
	}

	public function testCustomListBypassesSuppression(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// $custom = true -> private IP retained.
		$this->assertSame('10.0.0.5', sanitize_ipaddr('10.0.0.5/32', true, 'Disabled'));
	}

	public function testAdvancedCidrFloorClampsToSlash32(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// mask 8 < floor 24 -> clamped to /32 (public TEST-NET-2 survives the filter).
		$this->assertSame('198.51.100.0/32', sanitize_ipaddr('198.51.100.0/8', false, 24));
	}
}
