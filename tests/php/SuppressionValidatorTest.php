<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_validate_suppression_line() -- ADR-53 Phase 4: the v4 suppression textarea's
 * per-line validator, extracted from pfblockerng_ip.php's POST handler so it is
 * unit-testable off-appliance (it was previously inline in the page and
 * unreachable by PHPUnit).
 *
 * BEHAVIOUR CHANGE (ADR-53 §2.3 fork 1): the old inline rule accepted ONLY masks
 * /32 or /24. Phase 3's engine swap (iprange --except set subtraction) made the
 * carve engine mask-agnostic, so the UI now accepts any v4 mask /8-/32 (the /8
 * floor is a fail-open-typo guard, not an engine limit). testSlash16NowValid()
 * and testSlash8FloorNowValid() are the red->green proof: both FAIL against the
 * old /32-or-/24 rule and PASS against the widened /8-/32 rule.
 *
 * BEHAVIOUR CHANGE (ADR-53 Phase 6): family='ipv6' now validates for real. Before
 * this phase every v6 line was unconditionally rejected ("not yet supported" --
 * Phase 4's deliberate placeholder, pinned by the since-removed
 * testIpv6NotYetSupported()). Phase 6 wires the Phase 5 pure-PHP v6 set-diff
 * engine end-to-end, so v6 accepts masks /32-/128 (the /32 floor is the same
 * fail-open-typo guard as v4's /8 floor -- the engine itself is mask-agnostic).
 * testSlash64NowValid() is the red->green proof: it FAILS against the pre-Phase-6
 * "always reject" stub and PASSES once the real v6 validation lands.
 */
#[CoversFunction('pfb_validate_suppression_line')]
final class SuppressionValidatorTest extends TestCase
{
	// --- v4: legacy-valid shapes keep working (upgrade contract, ADR-53 §2.2) ---

	public function testLegacyBareHostMaskStillValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('10.0.0.1/32', 'ipv4'));
	}

	public function testLegacySlash24MaskStillValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('10.0.0.0/24', 'ipv4'));
	}

	// --- v4: NEW masks the widened /8-/32 range unlocks (the red->green proof) ---

	public function testSlash16NowValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('10.0.0.0/16', 'ipv4'));
	}

	public function testSlash8FloorNowValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('10.0.0.0/8', 'ipv4'));
	}

	// --- v4: out-of-range masks stay rejected, message names the accepted range ---

	public function testSlash7BelowFloorRejected(): void
	{
		$error = pfb_validate_suppression_line('10.0.0.0/7', 'ipv4');
		$this->assertNotNull($error, '/7 is below the /8 floor -- must be rejected');
		$this->assertStringContainsString('/8', $error);
		$this->assertStringContainsString('/32', $error);
	}

	public function testSlash33AboveCeilingRejected(): void
	{
		$error = pfb_validate_suppression_line('10.0.0.0/33', 'ipv4');
		$this->assertNotNull($error, '/33 is above the /32 ceiling -- must be rejected');
		$this->assertStringContainsString('/8', $error);
		$this->assertStringContainsString('/32', $error);
	}

	// --- v4: malformed input rejected (generic subnet message, not the range message) ---

	public function testNonCidrGarbageRejected(): void
	{
		$error = pfb_validate_suppression_line('not-an-ip-address', 'ipv4');
		$this->assertNotNull($error, 'non-CIDR garbage must be rejected');
	}

	public function testBadOctetRejected(): void
	{
		$error = pfb_validate_suppression_line('10.0.0.999/32', 'ipv4');
		$this->assertNotNull($error, 'an out-of-range octet must be rejected');
	}

	/**
	 * ADR-53 review finding H5: pin CURRENT behaviour -- a bare v4 address with
	 * no mask is REJECTED (is_subnetv4() requires an explicit '/bits'), the
	 * same contract as testV6MissingMaskRejected() below. No behaviour change;
	 * this closes a parity gap in coverage (the v6 case was pinned, the v4
	 * sibling was not).
	 */
	public function testMissingMaskRejected(): void
	{
		$error = pfb_validate_suppression_line('10.0.0.1', 'ipv4');
		$this->assertNotNull($error, 'a bare address with no mask must be rejected');
	}

	// --- v4: tolerated textarea shapes (unchanged from today) ---

	public function testTrailingInlineCommentTolerated(): void
	{
		$this->assertNull(pfb_validate_suppression_line('10.0.0.1/32 # example.com', 'ipv4'));
	}

	public function testBlankLineSkipped(): void
	{
		$this->assertNull(pfb_validate_suppression_line('', 'ipv4'));
	}

	public function testCommentOnlyLineSkipped(): void
	{
		$this->assertNull(pfb_validate_suppression_line('# just a comment', 'ipv4'));
	}

	// --- v6: implemented in Phase 6 (masks /32-/128) -- the red->green proof ---

	public function testSlash64NowValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('2001:db8::/64', 'ipv6'), 'ADR-53 Phase 6: v6 suppression now validates -- FAILS against the pre-Phase-6 always-reject stub');
	}

	public function testSlash128HostMaskValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('2001:db8::1/128', 'ipv6'));
	}

	public function testSlash32FloorValid(): void
	{
		$this->assertNull(pfb_validate_suppression_line('2001:db8::/32', 'ipv6'));
	}

	// --- v6: out-of-range masks rejected, message names the accepted range ---

	public function testSlash31BelowFloorRejected(): void
	{
		$error = pfb_validate_suppression_line('2001:db8::/31', 'ipv6');
		$this->assertNotNull($error, '/31 is below the /32 floor -- must be rejected');
		$this->assertStringContainsString('/32', $error);
		$this->assertStringContainsString('/128', $error);
	}

	public function testSlash129AboveCeilingRejected(): void
	{
		$error = pfb_validate_suppression_line('2001:db8::1/129', 'ipv6');
		$this->assertNotNull($error, '/129 is above the /128 ceiling -- must be rejected');
		$this->assertStringContainsString('/32', $error);
		$this->assertStringContainsString('/128', $error);
	}

	// --- v6: malformed input rejected (generic subnet message, not the range message) ---

	public function testV6NonCidrGarbageRejected(): void
	{
		$error = pfb_validate_suppression_line('not-an-ipv6-address', 'ipv6');
		$this->assertNotNull($error, 'non-CIDR garbage must be rejected');
	}

	public function testV6MissingMaskRejected(): void
	{
		$error = pfb_validate_suppression_line('2001:db8::1', 'ipv6');
		$this->assertNotNull($error, 'a bare address with no mask must be rejected');
	}

	// --- v6: tolerated textarea shapes (same tolerance as v4) ---

	public function testV6TrailingInlineCommentTolerated(): void
	{
		$this->assertNull(pfb_validate_suppression_line('2001:db8::1/128 # example.com', 'ipv6'));
	}

	public function testV6BlankLineSkipped(): void
	{
		$this->assertNull(pfb_validate_suppression_line('', 'ipv6'));
	}

	public function testV6CommentOnlyLineSkipped(): void
	{
		$this->assertNull(pfb_validate_suppression_line('# just a comment', 'ipv6'));
	}
}
