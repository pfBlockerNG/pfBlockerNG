<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * sanitize_ipaddr() — normalise an IPv4(/mask): strip leading zeros, drop a /32,
 * keep a bare address as a single host (/32) even when it ends in '.0', force
 * the 4th octet to 0 on an explicit /24, and (when $pfb['supp']=='on' and not a
 * custom list) drop loopback/reserved/private and apply the Advanced CIDR floor.
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

	// A bare IPv4 ending in '.0' is a single host (/32), not a /24 network.
	// '.0' is a valid host address; inferring /24 would silently over-block the
	// surrounding 255 addresses (issue #320). A feed that means the network
	// writes the mask explicitly ('192.0.2.0/24'), covered by the next test.
	public function testBareTrailingZeroAddressKeptAsSingleHostNotWidenedToSlash24(): void
	{
		$this->assertSame('192.0.2.0', sanitize_ipaddr('192.0.2.0', false, 'Disabled'));
	}

	// The paired branch: an EXPLICIT /24 is normalised to its network address.
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

	// --- RFC 4632-invalid prefix lengths are dropped, never rewritten (#719) ---

	// The old substring str_replace('32', '') rewrote an invalid mask into a
	// valid, far broader one (/132 -> /1 ingested half of IPv4 into a Deny
	// table; /320 and /3232 collapsed to a bare host). Such lines must be
	// dropped outright.
	public function testMaskContaining32AsSubstringDroppedNotRewritten(): void
	{
		$this->assertNull(sanitize_ipaddr('1.2.3.4/132', false, 'Disabled'));
		$this->assertNull(sanitize_ipaddr('10.0.0.0/232', false, 'Disabled'));
		$this->assertNull(sanitize_ipaddr('10.0.0.0/320', false, 'Disabled'));
		$this->assertNull(sanitize_ipaddr('1.2.3.4/3232', false, 'Disabled'));
	}

	public function testOutOfRangeMaskDropped(): void
	{
		$this->assertNull(sanitize_ipaddr('1.2.3.4/33', false, 'Disabled'));
	}

	// Suppression's old '> 32' guard rewrote /33 into a bare host instead of
	// rejecting it; with the mask validated up front the line is dropped on
	// this branch too.
	public function testOutOfRangeMaskDroppedUnderSuppression(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('192.0.2.1/33', false, 'Disabled'));
	}

	public function testNonNumericMaskDropped(): void
	{
		$this->assertNull(sanitize_ipaddr('1.2.3.4/abc', false, 'Disabled'));
	}
}
