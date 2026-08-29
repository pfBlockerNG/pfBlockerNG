<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_sanitize_ipaddr_v6() — IPv6 sibling of pfb_sanitize_ipaddr(): when
 * $supp=='on' and not a custom list, drop private (ULA fc00::/7),
 * link-local (fe80::/10), loopback (::1) and the reserved set (::/128) from
 * loaded block lists; keep a genuinely public address. Suppression off, or a
 * custom list, keeps the entry unchanged. A downloaded feed's explicit /0 is
 * clamped to a single host; a custom list's /0 is honored (issue #744).
 * Returns the canonical inet_ntop() form (issue #1084): textual variants of
 * one address (case, zero-run, leading zeros) collapse to one string, and an
 * unparseable address is dropped rather than passed through.
 *
 * (Originally pinned through the sanitize_ipaddr_v6() wrapper; the wrapper was
 * dead in production — pfblockerng_apply.inc calls the pure function directly —
 * and was removed in issue #1654. Every assertion here pins the same address
 * verdict on the pure function.)
 */
#[CoversFunction('pfb_sanitize_ipaddr_v6')]
final class SanitizeIpaddrV6Test extends TestCase
{
	/**
	 * Address verdict of the pure sanitizer — the view every assertion below
	 * pins. $supp mirrors the retired wrapper's $pfb['supp'] global; $pfbcidr
	 * mirrors its 'Disabled' default.
	 */
	private static function sanitize(string $ipaddr, bool $custom, string|int $pfbcidr = 'Disabled', string $supp = 'off'): ?string
	{
		// issue #1887: production takes the enum; the helper keeps the terse string
		// signature and adapts at this single boundary.
		return pfb_sanitize_ipaddr_v6($ipaddr, $custom, $pfbcidr, pfb_cfg_toggle_read($supp))['address'];
	}

	// --- Suppression on: reserved/private/loopback dropped -------------------

	public function testSuppressionDropsUla(): void
	{
		// ULA fc00::/7
		$this->assertNull(self::sanitize('fc00::1', false, supp: 'on'));
	}

	public function testSuppressionDropsLinkLocal(): void
	{
		// Link-local fe80::/10
		$this->assertNull(self::sanitize('fe80::1', false, supp: 'on'));
	}

	public function testSuppressionDropsLoopback(): void
	{
		// Loopback ::1
		$this->assertNull(self::sanitize('::1', false, supp: 'on'));
	}

	public function testSuppressionDropsReserved(): void
	{
		// Reserved ::/128 (unspecified) — part of the NO_RES_RANGE set.
		$this->assertNull(self::sanitize('::', false, supp: 'on'));
	}

	// --- Suppression on: a genuinely public address is kept ------------------

	public function testSuppressionKeepsPublicIp(): void
	{
		// Routable address (Cloudflare resolver) — genuinely public space, so
		// it must survive independently of the flag-coverage question below.
		$this->assertSame('2606:4700:4700::1111', self::sanitize('2606:4700:4700::1111', false, supp: 'on'));
	}

	// --- Classes the PHP filter flags do NOT drop (issue #760) ---------------
	//
	// FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE keep documentation
	// (2001:db8::/32), multicast (ff00::/8) and NAT64 (64:ff9b::/96) space
	// routable — the same permissiveness as the v4 flags (192.0.2.0/24 and
	// 224.0.0.0/4 are kept too). Issue #760 resolved the policy: pfb_sanitize_
	// ipaddr_v6() now drops these classes explicitly under Suppression via
	// direct prefix checks rather than another filter flag, so the behaviour
	// is independent of PHP's patch level (the RFC 6890 refactor in PHP
	// 8.3.16/8.4.3 moved 2001:db8::/32 between filter sets — irrelevant here
	// since these prefixes are no longer judged through filter_var()).

	public function testSuppressionDropsDocumentationRange(): void
	{
		$this->assertNull(self::sanitize('2001:db8::1', false, supp: 'on'), 'documentation (RFC 3849) is dropped');
	}

	public function testSuppressionDropsMulticastRange(): void
	{
		$this->assertNull(self::sanitize('ff02::1', false, supp: 'on'), 'multicast (ff00::/8) is dropped');
	}

	public function testSuppressionDropsNat64Range(): void
	{
		$this->assertNull(self::sanitize('64:ff9b::1', false, supp: 'on'), 'NAT64 (RFC 6052) is dropped');
	}

	// Suppression off keeps the same documentation-range address — proves the
	// new drop is gated on Suppression, not an unconditional block.
	public function testSuppressionOffKeepsDocumentationRange(): void
	{
		$this->assertSame('2001:db8::1', self::sanitize('2001:db8::1', false, supp: 'off'));
	}

	// A custom list bypasses the new drop, same as every other suppressed
	// class.
	public function testCustomListBypassesSuppressionForDocumentationRange(): void
	{
		$this->assertSame('2001:db8::1', self::sanitize('2001:db8::1', true, supp: 'on'));
	}

	// --- Suppression toggle is the cause (assert before-state, then flip) ----

	public function testSuppressionTogglesReservedDrop(): void
	{
		// Given suppression OFF, a reserved v6 entry is KEPT (before-state).
		$this->assertSame('fc00::1', self::sanitize('fc00::1', false, supp: 'off'));

		// When suppression is flipped ON, the same entry is now DROPPED —
		// so green proves suppression caused the change.
		$this->assertNull(self::sanitize('fc00::1', false, supp: 'on'));
	}

	// --- Custom list bypasses suppression ------------------------------------

	public function testCustomListBypassesSuppression(): void
	{
		// $custom = true -> reserved v6 retained.
		$this->assertSame('fc00::1', self::sanitize('fc00::1', true, supp: 'on'));
	}

	// --- CIDR form: address part extracted before the filter -----------------

	public function testSuppressionDropsReservedCidr(): void
	{
		// 'fc00::/7' — address part 'fc00::' is ULA -> dropped.
		$this->assertNull(self::sanitize('fc00::/7', false, supp: 'on'));
	}

	public function testSuppressionKeepsPublicCidr(): void
	{
		// A routable v6 CIDR survives unchanged (returned as-is, mask intact).
		$this->assertSame('2606:4700:4700::/48', self::sanitize('2606:4700:4700::/48', false, supp: 'on'));
	}

	// --- Explicit /0 masks (issue #744) ---------------------------------------

	// A downloaded feed's /0 covers the entire IPv6 space and is never honored:
	// it is clamped to a single host, so the address itself stays blocked
	// instead of the line loading as a block-everything table entry.
	public function testFeedSlashZeroClampedToSingleHost(): void
	{
		$this->assertSame('2606:4700:4700::1111', self::sanitize('2606:4700:4700::1111/0', false));
	}

	// Same clamp with suppression ON: the public address survives the
	// reserved/private filter and is kept as a single host, not a /0.
	public function testFeedSlashZeroUnderSuppressionClampedToSingleHost(): void
	{
		$this->assertSame('2606:4700:4700::1111', self::sanitize('2606:4700:4700::1111/0', false, supp: 'on'));
	}

	// The clamp keys on the numeric mask value, not the '0' literal — a
	// multi-zero spelling (/00) is clamped the same way.
	public function testFeedMultiZeroMaskClampedToSingleHost(): void
	{
		$this->assertSame('2606:4700:4700::1111', self::sanitize('2606:4700:4700::1111/00', false));
	}

	// Custom-list entries are user-authored: an explicit /0 is honored as
	// written — for any address except '::', which issue #1922 rejects
	// unconditionally (below).
	public function testCustomListSlashZeroHonoredForNonZeroAddress(): void
	{
		$this->assertSame('2606:4700:4700::1111/0', self::sanitize('2606:4700:4700::1111/0', true, supp: 'on'));
	}

	// issue #1922: '::' is never a valid entry under any mask, suppression
	// setting, or list type — rejected even on a custom list.
	public function testCustomListAllZerosSlashZeroRejected(): void
	{
		$this->assertNull(self::sanitize('::/0', true, supp: 'on'));
	}

	public function testAllZerosRejectedWithSuppressionOff(): void
	{
		$this->assertNull(self::sanitize('::', false));
	}

	public function testAllZerosWithFullMaskRejected(): void
	{
		$this->assertNull(self::sanitize('::/128', true));
	}

	// --- Suppression CIDR floor (issue #760 §3) -------------------------------
	//
	// $pfbcidr is the per-category Advanced "Suppression CIDR Limit": under
	// Suppression, a downloaded feed's CIDR narrower than the floor is clamped
	// to a single host (bare address, no mask -- loads as /128), the v6 sibling
	// of pfb_sanitize_ipaddr()'s Advanced IPv4 Tunable floor.

	public function testAdvancedCidrFloorClampsToSingleHost(): void
	{
		// mask 32 < floor 48 -> clamped to a bare host (public address survives
		// the reserved/private filter).
		$this->assertSame('2606:4700:4700::', self::sanitize('2606:4700:4700::/32', false, 48, supp: 'on'));
	}

	// The paired branch: a mask AT OR ABOVE the floor is kept, mask intact --
	// proves the floor is a real threshold, not an unconditional clamp.
	public function testMaskAtOrAboveFloorKeptUnchanged(): void
	{
		$this->assertSame('2606:4700:4700::/48', self::sanitize('2606:4700:4700::/48', false, 48, supp: 'on'));
		$this->assertSame('2606:4700:4700::/64', self::sanitize('2606:4700:4700::/64', false, 48, supp: 'on'));
	}

	// Floor 'Disabled' (the default) never clamps, regardless of mask width.
	public function testFloorDisabledKeepsWideMaskUnchanged(): void
	{
		$this->assertSame('2606:4700:4700::/32', self::sanitize('2606:4700:4700::/32', false, 'Disabled', supp: 'on'));
	}

	// Suppression OFF bypasses the floor entirely, even when one is configured --
	// the floor is a sub-clause of the Suppression block, not a standalone check.
	public function testSuppressionOffBypassesFloor(): void
	{
		$this->assertSame('2606:4700:4700::/32', self::sanitize('2606:4700:4700::/32', false, 48, supp: 'off'));
	}

	// A custom list bypasses the floor, same as every other Suppression sub-check.
	public function testCustomListBypassesFloor(): void
	{
		$this->assertSame('2606:4700:4700::/32', self::sanitize('2606:4700:4700::/32', true, 48, supp: 'on'));
	}

	// --- Floor is the cause (assert before-state, then flip) ------------------

	public function testFloorTogglesClampOfTheSameCidr(): void
	{
		// Given the floor Disabled, a narrow mask is KEPT (before-state).
		$this->assertSame('2606:4700:4700::/32', self::sanitize('2606:4700:4700::/32', false, 'Disabled', supp: 'on'));

		// When a floor narrower than the mask is set, the SAME entry is now
		// CLAMPED -- so green proves the floor caused the change.
		$this->assertSame('2606:4700:4700::', self::sanitize('2606:4700:4700::/32', false, 48, supp: 'on'));
	}

	// --- Interplay with the issue #760 documentation-range drop ---------------
	//
	// The floor clamp runs before the reserved/private filter, but it only
	// rewrites $ipaddr -- the filter judges $s_ip (the address part), which is
	// untouched by the clamp. So a documentation-range CIDR under a floor is
	// still DROPPED entirely: the #760 drop wins over the floor clamp, it does
	// not survive as a clamped single host.
	public function testDocumentationRangeCidrStillDroppedUnderFloor(): void
	{
		$this->assertNull(self::sanitize('2001:db8::1/16', false, 24, supp: 'on'));
	}

	// --- Suppression on: IPv4-mapped is also dropped -------------------------
	//
	// Covered by the same reserved/private filter_var() call as ULA/link-local/
	// loopback above (no separate branch), but had no dedicated pin (issue #1084).

	public function testSuppressionDropsV4Mapped(): void
	{
		$this->assertNull(self::sanitize('::ffff:1.2.3.4', false, supp: 'on'));
	}

	// --- Canonicalization at parse (issue #1084) ------------------------------
	//
	// pfb_sanitize_ipaddr_v6() returns the inet_ntop(inet_pton()) round-trip, so
	// every textual spelling of one address collapses to a single string.

	public function testCanonicalizesUppercaseHex(): void
	{
		$this->assertSame('2001:db8::1', self::sanitize('2001:DB8::1', false, supp: 'off'));
	}

	public function testCanonicalizesZeroRunExpansion(): void
	{
		$this->assertSame('2001:db8::1', self::sanitize('2001:db8:0:0:0:0:0:1', false, supp: 'off'));
	}

	public function testCanonicalizesLeadingZerosInHextet(): void
	{
		$this->assertSame('2001:db8:aa:bb00::5', self::sanitize('2001:0db8:00aa:bb00::5', false, supp: 'off'));
	}

	// An already-canonical address is a no-op round-trip, not merely "no visible
	// change" by coincidence -- ULA space, so it also proves nothing suppression-
	// related interferes when suppression is off.
	public function testAlreadyCanonicalAddressReturnedUnchanged(): void
	{
		$this->assertSame('fd12:3456::1', self::sanitize('fd12:3456::1', false, supp: 'off'));
	}

	public function testCanonicalizesCidrAddressPartMaskPreserved(): void
	{
		$this->assertSame('2001:db8::/32', self::sanitize('2001:DB8::/32', false, supp: 'off'));
	}

	// The feed /0 clamp (issue #744) and canonicalization compose: the mask is
	// dropped by the clamp, and the surviving host is still canonical text.
	public function testFeedSlashZeroEmitsCanonicalHost(): void
	{
		$this->assertSame('2001:db8::5', self::sanitize('2001:DB8::5/0', false, supp: 'off'));
	}

	// A custom list's /0 is honored as written (issue #744): the mask survives,
	// only the address text is canonicalized.
	public function testCustomSlashZeroKeepsMaskCanonicalizesAddress(): void
	{
		$this->assertSame('2001:db8::5/0', self::sanitize('2001:DB8::5/0', true, supp: 'off'));
	}

	// The Suppression CIDR floor clamp (issue #760 §3) and canonicalization
	// compose the same way as the /0 clamp above.
	public function testAdvancedCidrFloorClampEmitsCanonicalHost(): void
	{
		$this->assertSame('2606:4700:4700::ab', self::sanitize('2606:4700:4700::AB/32', false, 48, supp: 'on'));
	}

	// A public address that survives Suppression's reserved/private filter is
	// still canonicalized, not merely passed through as-written.
	public function testSuppressionSurvivingPublicAddressCanonicalized(): void
	{
		$this->assertSame('2606:4700:4700::1111', self::sanitize('2606:4700:4700:0:0:0:0:1111', false, supp: 'on'));
	}

	// Canonicalization is independent of the Suppression flag -- Suppression off
	// still collapses non-canonical text to the canonical form.
	public function testCanonicalizationAppliesWithSuppressionOff(): void
	{
		$this->assertSame('2001:db8::1', self::sanitize('2001:DB8:0:0::1', false, supp: 'off'));
	}

	// --- Hostile input (issue #1084) ------------------------------------------

	public function testGarbageAddressDropped(): void
	{
		$this->assertNull(self::sanitize('nonsense', false, supp: 'off'));
	}

	public function testEmptyStringDropped(): void
	{
		$this->assertNull(self::sanitize('', false, supp: 'off'));
	}

	// v4-mapped survives inet_pton()/inet_ntop() as mixed notation on this
	// platform -- pinning the actual round-trip text, not an assumed one.
	public function testV4MappedAddressCanonicalFormPinned(): void
	{
		$this->assertSame('::ffff:1.2.3.4', self::sanitize('::ffff:1.2.3.4', false, supp: 'off'));
	}

	// issue #1084: a %zone form is dropped explicitly -- inet_pton()'s handling
	// of it is platform-dependent (FreeBSD/glibc reject it, macOS strips the
	// zone), so the guard makes the verdict identical everywhere.
	public function testZoneIdSuffixDropped(): void
	{
		$this->assertNull(self::sanitize('fe80::1%igb0', false, supp: 'off'));
	}
}
