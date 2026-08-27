<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_nat_enabled() (#381) — pure predicate that gates DNSBL sinkhole NAT
 * generation. NAT is generated only when BOTH conditions hold:
 *   (1) the listening interface is NOT localhost (lo0), and
 *   (2) the user has NOT opted out via pfb_dnsbl_nonat ('on' = opted out, '' = NAT on).
 *
 * All four branches of the 2×2 (iface × nonat) are pinned here so a regression is
 * immediately visible without a live VM.
 */
#[CoversFunction('pfb_dnsbl_nat_enabled')]
final class PfbDnsblNatEnabledTest extends TestCase
{
	// Scenario: localhost interface — NAT never generated regardless of nonat flag.

	public function testLocalhostWithNatEnabledReturnsFalse(): void
	{
		// Given: interface is lo0 (localhost), nonat opt-out is off (default).
		// Then: no NAT — localhost never ports to an external sinkhole.
		$this->assertFalse(pfb_dnsbl_nat_enabled('lo0', PfbToggle::Off));
	}

	public function testLocalhostWithNatOptedOutReturnsFalse(): void
	{
		// Given: interface is lo0, nonat opt-out is on.
		// Then: still no NAT (lo0 guard fires before the nonat check).
		$this->assertFalse(pfb_dnsbl_nat_enabled('lo0', PfbToggle::On));
	}

	// Scenario: real (non-lo0) interface — NAT controlled by the nonat toggle.

	public function testRealIfaceWithNatEnabledReturnsTrue(): void
	{
		// Given: real interface (lan), nonat opt-out is off ('' = NAT generated, the default).
		// Then: NAT IS generated — this is the existing/default behaviour.
		$this->assertTrue(pfb_dnsbl_nat_enabled('lan', PfbToggle::Off));
	}

	public function testRealIfaceWithNatOptedOutReturnsFalse(): void
	{
		// Given: real interface (lan), nonat opt-out is on ('on' = user manages NAT manually).
		// Then: NAT is NOT generated — this is the new #381 behaviour.
		$this->assertFalse(pfb_dnsbl_nat_enabled('lan', PfbToggle::On));
	}
}
