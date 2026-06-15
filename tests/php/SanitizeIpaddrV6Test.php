<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * sanitize_ipaddr_v6() — IPv6 sibling of sanitize_ipaddr(): when
 * $pfb['supp']=='on' and not a custom list, drop private (ULA fc00::/7),
 * link-local (fe80::/10), loopback (::1) and the reserved set (::/128) from
 * loaded block lists; keep a genuinely public address. Suppression off, or a
 * custom list, keeps the entry unchanged.
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
		// Routable address (Cloudflare resolver) — NOT 2001:db8::/32 (reserved).
		$this->assertSame('2606:4700:4700::1111', sanitize_ipaddr_v6('2606:4700:4700::1111', false));
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
}
