<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_find_marked_vip() (ADR-13 Phase 2) — the pure ownership predicate that gates the
 * VIP lifecycle manager (pfb_manage_dnsbl_vip). It decides which virtualip/vip entry the
 * package owns and may delete, by TWO predicates both required on delete:
 *   (1) the descr marker (PFB_AUTO_VIP_DESCR_V4/_V6), and
 *   (2) an exact subnet (IP) match against the address resolved from stored config.
 * With $match_ip === null it matches on the marker alone (idempotent reuse on create).
 * No pfSense-runtime coupling, so it is unit-tested here; the full create/delete
 * lifecycle (interface_ipalias_configure / interface_vip_bring_down / write_config)
 * depends on pfSense state and is covered by lint + manual smoke (see the ADR).
 */
#[CoversFunction('pfb_find_marked_vip')]
final class DnsblMarkedVipTest extends TestCase
{
	/** @return list<array<string,string>> */
	private function vips(): array
	{
		return [
			// A user's manually-created VIP — NO marker. Must never be matched.
			['descr' => 'my manual VIP', 'subnet' => '10.10.10.53'],
			// The package's auto-created v4 VIP — marker + a known address.
			['descr' => PFB_AUTO_VIP_DESCR_V4, 'subnet' => '10.10.0.53'],
			// The package's auto-created v6 VIP — marker + a known address.
			['descr' => PFB_AUTO_VIP_DESCR_V6, 'subnet' => 'fd00::53'],
		];
	}

	public function testMarkerPlusIpMatchReturnsTheOwnedEntryIndex(): void
	{
		$idx = pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V4, '10.10.0.53');
		$this->assertSame(1, $idx);

		$idx6 = pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V6, 'fd00::53');
		$this->assertSame(2, $idx6);
	}

	public function testMarkerWithoutIpMatchIsNotDeleted(): void
	{
		// The delete guard requires BOTH marker AND IP. A marked VIP whose subnet no
		// longer equals the stored-config address is NOT a match -> never deleted on
		// the marker alone.
		$this->assertNull(
			pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V4, '10.10.99.53')
		);
	}

	public function testIpMatchWithoutMarkerIsNeverMatched(): void
	{
		// A manually-created VIP at the very address the marker-IP would target is
		// untouchable because it lacks the marker. This is the core safety property:
		// the manual VIP at 10.10.10.53 is never returned for any marker.
		$this->assertNull(
			pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V4, '10.10.10.53')
		);
		$this->assertNull(
			pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V6, '10.10.10.53')
		);
	}

	public function testNullMatchIpReusesByMarkerAlone(): void
	{
		// Idempotent create path: with $match_ip === null the function reuses the
		// existing marked VIP regardless of its address (we created it earlier).
		$this->assertSame(1, pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V4, null));
		$this->assertSame(2, pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V6, null));

		// Empty string behaves like null (match on marker alone) — guards against a
		// '' resolved address spuriously narrowing the reuse lookup.
		$this->assertSame(1, pfb_find_marked_vip($this->vips(), PFB_AUTO_VIP_DESCR_V4, ''));
	}

	public function testNoMarkedVipReturnsNull(): void
	{
		// Before any auto VIP exists (or with the feature never enabled) there is
		// nothing owned -> null, so the manager creates on enable and deletes nothing
		// on disable.
		$onlyManual = [
			['descr' => 'manual A', 'subnet' => '192.168.1.10'],
			['descr' => 'manual B', 'subnet' => 'fd12::1'],
		];
		$this->assertNull(pfb_find_marked_vip($onlyManual, PFB_AUTO_VIP_DESCR_V4, null));
		$this->assertNull(pfb_find_marked_vip($onlyManual, PFB_AUTO_VIP_DESCR_V4, '192.168.1.10'));
		$this->assertNull(pfb_find_marked_vip([], PFB_AUTO_VIP_DESCR_V4, null));
	}
}
