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

	// --- v6: not yet implemented (Phase 6 flips this to green) ---

	public function testIpv6NotYetSupported(): void
	{
		$error = pfb_validate_suppression_line('2001:db8::1/64', 'ipv6');
		$this->assertNotNull($error, 'ADR-53 Phase 6 implements v6 suppression -- until then every v6 line is rejected');
	}
}
