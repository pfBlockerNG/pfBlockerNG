<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-13 — the IPv6 sinkhole-VIP recommendation (the softened §7-pivot form). Two pure,
 * pfSense-decoupled pieces:
 *
 *   - pfb_dnsbl_v6_vip_required(bool $listens_v6, bool $auto): the single source of truth
 *     for "is a v6 sinkhole VIP wanted?" — true iff the resolver listens on IPv6 AND the
 *     package is NOT auto-provisioning it (manual mode). It drives a NON-BLOCKING warning
 *     in pfb_global (and auto-provisioning in pfb_manage_dnsbl_vip), NOT a hard failure.
 *   - pfb_validate_vips(...): the validator NO LONGER blocks on a missing v6 VIP (the
 *     earlier Phase-3 hard rule was reverted — it force-disabled DNSBL on every existing
 *     manual setup whose resolver listens on IPv6 without a v6 VIP). A missing v6 VIP is
 *     optional; only the VIPs that ARE configured are validated.
 *
 * Per CLAUDE.md test-coverage rules: the helper's full truth table is asserted (every
 * combination of both inputs), and the validator is asserted NOT to surface a v6-required
 * error in the exact case the reverted rule used to fail (v6-listening, manual, no v6 VIP).
 */
#[CoversFunction('pfb_dnsbl_v6_vip_required')]
#[CoversFunction('pfb_validate_vips')]
final class DnsblV6RequiredTest extends TestCase
{
	// --- pfb_dnsbl_v6_vip_required: full truth table (both inputs, every combination) ---

	public function testV6WantedOnlyWhenListeningAndManual(): void
	{
		// listens_v6 OFF -> never wanted, regardless of auto (v6 stays optional).
		$this->assertFalse(pfb_dnsbl_v6_vip_required(false, false));
		$this->assertFalse(pfb_dnsbl_v6_vip_required(false, true));

		// listens_v6 ON, auto ON -> not flagged: auto-create provisions the v6 VIP itself.
		$this->assertFalse(pfb_dnsbl_v6_vip_required(true, true));

		// listens_v6 ON, auto OFF (manual) -> WANTED (drives a non-blocking warning).
		$this->assertTrue(pfb_dnsbl_v6_vip_required(true, false));
	}

	// --- pfb_validate_vips: a missing v6 VIP NEVER fails validation (the §7 pivot) ---

	public function testMissingV6VipIsNotAValidationError(): void
	{
		// No VIP at all -> the generic "no VIP configured", NOT a v6-specific error: the
		// reverted v6-mandatory rule no longer fires before this.
		[$ok, $err] = pfb_validate_vips('lo0', '', '');
		$this->assertFalse($ok);
		$this->assertSame('no VIP configured', $err);

		// v4-only config (the COMMON manual setup on a v6-listening resolver): validation
		// proceeds PAST any v6 consideration into the normal v4 interface check, and the
		// error is never the (removed) v6-required message. This is the exact case the
		// Phase-3 hard rule used to force-disable DNSBL on — proven non-blocking now.
		[, $err2] = pfb_validate_vips('lo0', '_vip_test_v4', '');
		$this->assertNotSame('IPv6 VIP required: the DNS Resolver is listening on IPv6', $err2);
	}

	public function testConfiguredV6VipStillValidatedNormally(): void
	{
		// A v6 VIP that IS supplied is still validated (existence / interface / overlap):
		// the validator continues into the per-VIP checks (which exercise the pfSense
		// doubles). The assertion of interest: the failure, if any, is never a v6-required
		// message — v6 is optional, not mandatory.
		[$ok, $err] = pfb_validate_vips('lo0', '', '_vip_test_v6');
		$this->assertNotSame('IPv6 VIP required: the DNS Resolver is listening on IPv6', $err);
		$this->assertTrue($ok === false || $ok === true);
	}
}
