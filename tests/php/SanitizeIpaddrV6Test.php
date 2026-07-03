<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * sanitize_ipaddr_v6() — IPv6 sibling of sanitize_ipaddr(): when
 * $pfb['supp']=='on' and not a custom list, drop private (ULA fc00::/7),
 * link-local (fe80::/10), loopback (::1) and the reserved set (::/128) from
 * loaded block lists; keep a genuinely public address. Suppression off, or a
 * custom list, keeps the entry unchanged. A downloaded feed's explicit /0 is
 * clamped to a single host; a custom list's /0 is honored (issue #744).
 */
#[CoversFunction('sanitize_ipaddr_v6')]
final class SanitizeIpaddrV6Test extends TestCase
{
	protected function setUp(): void
	{
		// Default: suppression OFF (no reserved/private filtering).
		$GLOBALS['pfb']['supp'] = 'off';
	}

	// --- Suppression on: reserved/private/loopback dropped -------------------

	public function testSuppressionDropsUla(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// ULA fc00::/7
		$this->assertNull(sanitize_ipaddr_v6('fc00::1', false));
	}

	public function testSuppressionDropsLinkLocal(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// Link-local fe80::/10
		$this->assertNull(sanitize_ipaddr_v6('fe80::1', false));
	}

	public function testSuppressionDropsLoopback(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// Loopback ::1
		$this->assertNull(sanitize_ipaddr_v6('::1', false));
	}

	public function testSuppressionDropsReserved(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// Reserved ::/128 (unspecified) — part of the NO_RES_RANGE set.
		$this->assertNull(sanitize_ipaddr_v6('::', false));
	}

	// --- Suppression on: a genuinely public address is kept ------------------

	public function testSuppressionKeepsPublicIp(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// Routable address (Cloudflare resolver) — genuinely public space, so
		// it must survive independently of the flag-coverage question below.
		$this->assertSame('2606:4700:4700::1111', sanitize_ipaddr_v6('2606:4700:4700::1111', false));
	}

	// --- Classes the PHP filter flags do NOT drop (issue #760) ---------------
	//
	// FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE keep documentation
	// (2001:db8::/32), multicast (ff00::/8) and NAT64 (64:ff9b::/96) space —
	// the same permissiveness as the v4 flags (192.0.2.0/24 and 224.0.0.0/4
	// are kept too). These pin today's behaviour; dropping these classes is a
	// policy decision tracked in issue #760 and would flip these tests.

	// 2001:db8::/32 is non-reserved only since PHP 8.3.16/8.4.3 (php-src
	// GH-16944, the RFC 6890 range refactor); an older 8.3.x patch level
	// DROPS it — a failure here on a stale toolchain is a PHP patch-floor
	// problem, not a #760 policy change.
	public function testSuppressionKeepsDocumentationRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('2001:db8::1', sanitize_ipaddr_v6('2001:db8::1', false), 'documentation (RFC 3849) is kept');
	}

	public function testSuppressionKeepsMulticastRange(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('ff02::1', sanitize_ipaddr_v6('ff02::1', false), 'multicast (ff00::/8) is kept');
	}

	public function testSuppressionKeepsNat64Range(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('64:ff9b::1', sanitize_ipaddr_v6('64:ff9b::1', false), 'NAT64 (RFC 6052) is kept');
	}

	// --- Suppression toggle is the cause (assert before-state, then flip) ----

	public function testSuppressionTogglesReservedDrop(): void
	{
		// Given suppression OFF, a reserved v6 entry is KEPT (before-state).
		$GLOBALS['pfb']['supp'] = 'off';
		$this->assertSame('fc00::1', sanitize_ipaddr_v6('fc00::1', false));

		// When suppression is flipped ON, the same entry is now DROPPED —
		// so green proves suppression caused the change.
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertNull(sanitize_ipaddr_v6('fc00::1', false));
	}

	// --- Custom list bypasses suppression ------------------------------------

	public function testCustomListBypassesSuppression(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// $custom = true -> reserved v6 retained.
		$this->assertSame('fc00::1', sanitize_ipaddr_v6('fc00::1', true));
	}

	// --- CIDR form: address part extracted before the filter -----------------

	public function testSuppressionDropsReservedCidr(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// 'fc00::/7' — address part 'fc00::' is ULA -> dropped.
		$this->assertNull(sanitize_ipaddr_v6('fc00::/7', false));
	}

	public function testSuppressionKeepsPublicCidr(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		// A routable v6 CIDR survives unchanged (returned as-is, mask intact).
		$this->assertSame('2606:4700:4700::/48', sanitize_ipaddr_v6('2606:4700:4700::/48', false));
	}

	// --- Explicit /0 masks (issue #744) ---------------------------------------

	// A downloaded feed's /0 covers the entire IPv6 space and is never honored:
	// it is clamped to a single host, so the address itself stays blocked
	// instead of the line loading as a block-everything table entry.
	public function testFeedSlashZeroClampedToSingleHost(): void
	{
		$this->assertSame('2606:4700:4700::1111', sanitize_ipaddr_v6('2606:4700:4700::1111/0', false));
	}

	// Same clamp with suppression ON: the public address survives the
	// reserved/private filter and is kept as a single host, not a /0.
	public function testFeedSlashZeroUnderSuppressionClampedToSingleHost(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('2606:4700:4700::1111', sanitize_ipaddr_v6('2606:4700:4700::1111/0', false));
	}

	// The clamp keys on the numeric mask value, not the '0' literal — a
	// multi-zero spelling (/00) is clamped the same way.
	public function testFeedMultiZeroMaskClampedToSingleHost(): void
	{
		$this->assertSame('2606:4700:4700::1111', sanitize_ipaddr_v6('2606:4700:4700::1111/00', false));
	}

	// Custom-list entries are user-authored: an explicit /0 is honored as
	// written (::/0 stays ::/0).
	public function testCustomListSlashZeroHonored(): void
	{
		$GLOBALS['pfb']['supp'] = 'on';
		$this->assertSame('::/0', sanitize_ipaddr_v6('::/0', true));
	}
}
