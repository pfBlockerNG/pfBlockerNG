<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-23 — the setup wizard's Auto VIP choice decides which DNSBL-VIP keys step 4 persists.
 * Since issue #3539 the wizard's setup answers no block with the VIP, so step 3 validates no VIP
 * in either mode (WizardVipDemandTest).
 */
#[CoversFunction('pfb_wizard_dnsvip_settings')]
final class WizardVipAutoTest extends TestCase
{
	/**
	 * Part B — the persisted DNSBL-VIP settings shape, on the pure helper
	 * step4_submitphpaction() now calls (pfb_wizard_dnsvip_settings). The controller
	 * itself can't be unit-invoked (it ends in header()+exit), so ADR-23 extracts the
	 * VIP-settings decision into this helper and the controller merges the returned
	 * slice into the DNSBL config — so testing the helper pins exactly what is written.
	 *
	 * Scenario: the Auto VIP choice decides which DNSBL-VIP keys are persisted.
	 *
	 *   Background:
	 *     Given step3 selected the manual lo0 VIP ids pfb_dnsvip4='_vip1', pfb_dnsvip6='_vip2'
	 *
	 *   When auto is OFF
	 *   Then pfb_dnsvip_auto persists as '' AND both manual ids are written through
	 *
	 *   --- the OFF before-state above is asserted FIRST ---
	 *
	 *   When auto is ON (same step3 ids passed)
	 *   Then pfb_dnsvip_auto persists as 'on' AND neither manual id is written
	 *        (ADR-13 owns/provisions the VIP, so the wizard must not pin a manual id)
	 *
	 * Passing the SAME ids to both calls proves the auto flag — not the id values —
	 * decides whether the manual ids are persisted.
	 */
	public function testAutoVipToggleDecidesPersistedDnsvipSettings(): void
	{
		// Given: step3's manual VIP selections.
		$vip4 = '_vip1';
		$vip6 = '_vip2';

		// When/Then (before-state): auto OFF persists the flag '' and BOTH manual ids.
		$off = pfb_wizard_dnsvip_settings(false, $vip4, $vip6);
		$this->assertSame('', $off['pfb_dnsvip_auto'], 'auto OFF must persist pfb_dnsvip_auto as empty');
		$this->assertSame('_vip1', $off['pfb_dnsvip4'], 'auto OFF must persist the manual IPv4 VIP id');
		$this->assertSame('_vip2', $off['pfb_dnsvip6'], 'auto OFF must persist the manual IPv6 VIP id');

		// When/Then (after-state): auto ON persists the flag 'on' and OMITS the manual
		// ids — the same ids are passed, so green here proves the flag drove the change.
		$on = pfb_wizard_dnsvip_settings(true, $vip4, $vip6);
		$this->assertSame('on', $on['pfb_dnsvip_auto'], 'auto ON must persist pfb_dnsvip_auto as on');
		$this->assertArrayNotHasKey('pfb_dnsvip4', $on, 'auto ON must NOT pin a manual IPv4 VIP id (ADR-13 owns it)');
		$this->assertArrayNotHasKey('pfb_dnsvip6', $on, 'auto ON must NOT pin a manual IPv6 VIP id (ADR-13 owns it)');
	}
}
