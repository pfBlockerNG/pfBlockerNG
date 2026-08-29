<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1084 review — pfb_ip_suppress_body_active() decides whether the per-alias
 * suppression BODY (the v4 `suppress` exec / the v6 pfb_suppress_file_v6() call) runs
 * this reload.
 *
 * Pre-fix, the body ran only for a FEED-CHANGED alias ($final_alias_old). Snapshots are
 * pre-suppression captures, but recompute rewrites EVERY family alias on any trigger --
 * so a suppressed IP that recompute resurrects into an alias with NO feed change of its
 * own (an unrelated sibling feed changed, driving the shared family-wide recompute pass)
 * never got re-suppressed. The fix ORs in "recompute actually ran this pass for this
 * family" alongside the existing feed-changed gate -- brand-new pure predicate, no
 * pre-existing behaviour of its own to regress, but the DEFECT ROW below is the exact
 * case the fix exists for.
 *
 * Feature: suppression-body gate
 *   Scenario: every existing gate clause still needs to be TRUE (supp/vtype/supp_update/adv)
 *   Scenario: EITHER feed_changed OR recompute_ran unlocks the body (the OR is the fix)
 *   Scenario: the defect row -- feed unchanged, recompute ran -- must be TRUE
 */
#[CoversFunction('pfb_ip_suppress_body_active')]
final class IpSuppressBodyActiveTest extends TestCase
{
	public function testAllGatesOnAndFeedChangedIsActive(): void
	{
		$this->assertTrue(pfb_ip_suppress_body_active(true, true, true, true, true, false));
	}

	public function testDefectRowFeedUnchangedButRecomputeRanIsActive(): void
	{
		// The exact case pfb_ip_suppress_body_active exists to fix: recompute rewrote
		// this alias's content even though ITS OWN feed did not change this pass.
		$this->assertTrue(
			pfb_ip_suppress_body_active(true, true, true, true, false, true),
			'recompute having run this pass must unlock suppression even with no feed change of its own'
		);
	}

	public function testNeitherFeedChangedNorRecomputeRanIsInactive(): void
	{
		$this->assertFalse(pfb_ip_suppress_body_active(true, true, true, true, false, false));
	}

	public function testSuppOffIsInactiveEvenWithEverythingElseTrue(): void
	{
		$this->assertFalse(pfb_ip_suppress_body_active(false, true, true, true, true, true));
	}

	public function testVtypeMismatchIsInactiveEvenWithEverythingElseTrue(): void
	{
		$this->assertFalse(pfb_ip_suppress_body_active(true, false, true, true, true, true));
	}

	public function testSuppUpdateFalseIsInactiveEvenWithEverythingElseTrue(): void
	{
		$this->assertFalse(pfb_ip_suppress_body_active(true, true, false, true, true, true));
	}

	public function testNotAdvIsInactiveEvenWithEverythingElseTrue(): void
	{
		$this->assertFalse(pfb_ip_suppress_body_active(true, true, true, false, true, true));
	}
}
