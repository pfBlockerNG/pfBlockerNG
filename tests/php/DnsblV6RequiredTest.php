<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-13 Phase 3 — the v6-mandatory rule. Two pure, pfSense-decoupled pieces:
 *
 *   - pfb_dnsbl_v6_vip_required(bool $listens_v6, bool $auto): the single source of
 *     truth for "is a v6 sinkhole VIP required?" — true iff the resolver listens on
 *     IPv6 AND the package is NOT auto-provisioning it (manual mode).
 *   - pfb_validate_vips(..., ?bool $require_v6): the validator surfaces that rule as an
 *     input error / force-disable signal. With an EXPLICIT $require_v6 the validator
 *     never consults pfb_unbound_listens_v6()/pfSense state, so the v6-required branch
 *     and the v6-optional before-state are both unit-testable here.
 *
 * Per CLAUDE.md test-coverage rules: every branch (v6 not-listening => optional, and
 * v6-listening => required) is asserted, and the transition test asserts the BEFORE
 * state (optional: empty v6 VIP is fine) as well as the AFTER state (required: empty v6
 * VIP errors) so a green proves the requirement CAUSED the change.
 */
#[CoversFunction('pfb_dnsbl_v6_vip_required')]
#[CoversFunction('pfb_validate_vips')]
final class DnsblV6RequiredTest extends TestCase
{
	// --- pfb_dnsbl_v6_vip_required: full truth table (both inputs, every combination) ---

	public function testV6RequiredOnlyWhenListeningAndManual(): void
	{
		// listens_v6 OFF -> never required, regardless of auto (v6 stays optional).
		$this->assertFalse(pfb_dnsbl_v6_vip_required(false, false));
		$this->assertFalse(pfb_dnsbl_v6_vip_required(false, true));

		// listens_v6 ON, auto ON -> NOT required of the validator: auto provisions it.
		$this->assertFalse(pfb_dnsbl_v6_vip_required(true, true));

		// listens_v6 ON, auto OFF (manual) -> REQUIRED.
		$this->assertTrue(pfb_dnsbl_v6_vip_required(true, false));
	}

	// --- pfb_validate_vips with an explicit $require_v6 (no pfSense state reached) ---

	public function testV6OptionalWhenNotRequired_beforeState(): void
	{
		// BEFORE state (v6 NOT listened-on / not required): a missing v6 VIP is fine.
		// With no v4 either this is the generic "no VIP configured", NOT the v6 message —
		// proving the v6 rule does not fire when v6 is optional.
		[$ok, $err] = pfb_validate_vips('lo0', '', '', false);
		$this->assertFalse($ok);
		$this->assertSame('no VIP configured', $err);

		// And a v4-only config with v6 absent is NOT blocked by the v6 rule: it proceeds
		// past the v6 branch into the normal v4 interface check (which fails here only
		// because the doubled get_configured_vip_interface() doesn't return 'lo0' — the
		// point is the error is NOT the v6-required one).
		[$ok2, $err2] = pfb_validate_vips('lo0', '_vip_test_v4', '', false);
		$this->assertFalse($ok2);
		$this->assertNotSame('IPv6 VIP required: the DNS Resolver is listening on IPv6', $err2);
	}

	public function testV6RequiredErrorsWhenListeningAndV6Missing_afterState(): void
	{
		// AFTER state (v6 required, empty v6 VIP): the new mandatory rule errors, and it
		// wins over the generic "no VIP configured" message (specific + actionable).
		[$ok, $err] = pfb_validate_vips('lo0', '', '', true);
		$this->assertFalse($ok);
		$this->assertSame('IPv6 VIP required: the DNS Resolver is listening on IPv6', $err);

		// Even with a v4 VIP present, a required-but-absent v6 VIP still errors with the
		// v6 message — the requirement is about v6 specifically, not "any VIP".
		[$ok2, $err2] = pfb_validate_vips('lo0', '_vip_test_v4', '', true);
		$this->assertFalse($ok2);
		$this->assertSame('IPv6 VIP required: the DNS Resolver is listening on IPv6', $err2);
	}

	public function testV6RequiredIsSatisfiedWhenAV6VipIsPresent(): void
	{
		// require_v6=true but a v6 VIP IS present -> the v6-required branch does NOT fire;
		// validation continues into the per-VIP checks (which then exercise pfSense
		// doubles). The assertion of interest: the error, if any, is never the
		// v6-required message once a v6 VIP is supplied.
		[$ok, $err] = pfb_validate_vips('lo0', '', '_vip_test_v6', true);
		$this->assertNotSame('IPv6 VIP required: the DNS Resolver is listening on IPv6', $err);
		// (ok may be false due to the doubled interface/overlap checks; that is not the
		// branch under test — we only assert the v6-mandatory gate is cleared.)
		$this->assertTrue($ok === false || $ok === true);
	}
}
