<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * sanitize_ipaddr() — normalise an IPv4(/mask): strip leading zeros, drop a /32,
 * keep a bare address as a single host (/32) even when it ends in '.0', force
 * the 4th octet to 0 on an explicit /24, clamp a downloaded feed's /0 to a
 * single host while honoring /0 on a custom list (issue #744), and (when
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
		// 192.0.2.5 (RFC 5737 documentation space) no longer qualifies as
		// "public" under issue #760 — use a genuinely routable address.
		$this->assertSame('1.1.1.1', sanitize_ipaddr('1.1.1.1/32', false, 'Disabled'));
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
		// mask 8 < floor 24 -> clamped to /32 (public address survives the filter).
		// 198.51.100.0 (TEST-NET-2) would no longer survive under issue #760, so
		// this exemplar uses a genuinely routable /8.
		$this->assertSame('1.1.1.0/32', sanitize_ipaddr('1.1.1.0/8', false, 24));
	}

	// --- Additional reserved classes dropped under Suppression (issue #760) ---
	//
	// FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE keep documentation, multicast,
	// CGN, benchmarking and the deprecated 6to4 relay anycast prefix
	// routable; sanitize_ipaddr() explicitly drops these under Suppression,
	// judged on the address part only — the CIDR span is not inspected.

	public function testSuppressionDropsDocumentationRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('192.0.2.5/32', false, 'Disabled'), 'documentation (RFC 5737) is dropped');
	}

	// CIDR-form pin: the network address of a documentation /24 is judged the
	// same as a bare host — the mask itself is never inspected.
	public function testSuppressionDropsDocumentationRangeCidr(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('198.51.100.0/24', false, 'Disabled'), 'documentation (RFC 5737) is dropped');
	}

	public function testSuppressionDropsMulticastRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('224.0.0.1/32', false, 'Disabled'), 'multicast (224.0.0.0/4) is dropped');
	}

	public function testSuppressionDropsCgnRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('100.64.0.1/32', false, 'Disabled'), 'CGN (RFC 6598) is dropped');
	}

	public function testSuppressionDropsBenchmarkingRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('198.18.0.1/32', false, 'Disabled'), 'benchmarking (RFC 2544) is dropped');
	}

	public function testSuppressionDrops6to4RelayRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('192.88.99.1/32', false, 'Disabled'), '6to4 relay anycast (deprecated) is dropped');
	}

	// Suppression off keeps the same documentation-range address — proves the
	// new drop is gated on Suppression, not an unconditional block.
	public function testSuppressionOffKeepsDocumentationRange(): void
	{
		$this->assertSame('192.0.2.5', sanitize_ipaddr('192.0.2.5/32', false, 'Disabled'));
	}

	// A custom list bypasses the new drop, same as every other suppressed
	// class.
	public function testCustomListBypassesSuppressionForDocumentationRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('192.0.2.5', sanitize_ipaddr('192.0.2.5/32', true, 'Disabled'));
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
	// rejecting it (and the substring strip mangled /132 -> /1, /320 -> bare
	// host, on this branch too); with the mask validated up front the line is
	// dropped regardless of suppression state.
	public function testInvalidMasksDroppedUnderSuppression(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('192.0.2.1/33', false, 'Disabled'));
		$this->assertNull(sanitize_ipaddr('192.0.2.1/132', false, 'Disabled'));
		$this->assertNull(sanitize_ipaddr('192.0.2.1/320', false, 'Disabled'));
	}

	public function testNonNumericMaskDropped(): void
	{
		$this->assertNull(sanitize_ipaddr('1.2.3.4/abc', false, 'Disabled'));
	}

	// --- Explicit /0 masks (issue #744) ---------------------------------------

	// A downloaded feed's /0 covers the entire IPv4 space and is never honored:
	// it is clamped to a single host, so the address itself stays blocked
	// (dropping the whole line would under-block). Regression PIN: the old code
	// produced the same value by accident (empty('0') collapse); this pins it
	// as intentional — the red→green evidence is the log + custom-honor tests.
	public function testFeedSlashZeroClampedToSingleHost(): void
	{
		$this->assertSame('198.51.100.7', sanitize_ipaddr('198.51.100.7/0', false, 'Disabled'));
	}

	// The clamp keys on the numeric mask value, not the '0' literal — a
	// multi-zero spelling (/00) is clamped the same way (previously it leaked
	// through as 'ip/00' and the whole line was dropped by validation).
	public function testFeedMultiZeroMaskClampedToSingleHost(): void
	{
		$this->assertSame('198.51.100.7', sanitize_ipaddr('198.51.100.7/00', false, 'Disabled'));
	}

	// The clamp is visible in the pfBlockerNG log — never a silent rewrite.
	public function testFeedSlashZeroClampIsLogged(): void
	{
		$prev_log = $GLOBALS['pfb']['log'];	// bootstrap sandbox log — restore after
		$logfile = tempnam(sys_get_temp_dir(), 'pfb_log_');
		$GLOBALS['pfb']['log'] = $logfile;
		try {
			sanitize_ipaddr('198.51.100.7/0', false, 'Disabled');
			$this->assertStringContainsString('198.51.100.7/0', (string) file_get_contents($logfile));
		} finally {
			@unlink($logfile);
			$GLOBALS['pfb']['log'] = $prev_log;
		}
	}

	// The /0 is clamped to a host up front, so under suppression it no longer
	// slips past the Advanced CIDR floor as an "empty" mask — the result is
	// the same single host, not an unclamped /0. Regression PIN (same
	// accidental end-state as above, now deliberate). Uses a genuinely
	// routable address (198.51.100.x would now be dropped under issue #760).
	public function testFeedSlashZeroUnderSuppressionCidrFloorStillSingleHost(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('1.1.1.7', sanitize_ipaddr('1.1.1.7/0', false, 24));
	}

	// Interaction PIN: a feed 0.0.0.0/0 under suppression is clamped to the
	// host 0.0.0.0, which the pre-existing '0.0.0.0' exclusion then DROPS —
	// the line yields nothing, it does not survive as a host entry.
	public function testFeedZeroSlashZeroUnderSuppressionDropped(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr('0.0.0.0/0', false, 'Disabled'));
	}

	// Custom-list entries are user-authored: an explicit /0 is honored as
	// written, never clamped or collapsed to a bare host (e.g. 0.0.0.0/0 in a
	// custom list referenced by a manual firewall rule).
	public function testCustomListSlashZeroHonored(): void
	{
		$this->assertSame('0.0.0.0/0', sanitize_ipaddr('0.0.0.0/0', true, 'Disabled'));
	}

	public function testCustomListSlashZeroHonoredUnderSuppression(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('0.0.0.0/0', sanitize_ipaddr('0.0.0.0/0', true, 24));
	}
}
