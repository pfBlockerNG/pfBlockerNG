<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1084 — pfb_ip_recompute_matrix() decides how the batch `recompute` verb is invoked
 * from the enable_dup / dRep / pRep toggle state (the issue's "dedup-off invocation matrix").
 * Brand-new decision logic (no pre-existing behaviour) — pinned here at full branch coverage
 * per the coverage matrix: dup on/off x rep off/dmax/pmax, plus the both-dRep-and-pRep tie-break
 * cell in both dedup states.
 *
 * Feature: batch recompute invocation matrix
 *   Scenario: enable_dup on drives a full v4+v6 pass regardless of reputation state
 *   Scenario: enable_dup off + reputation alone is a v4-only passthrough pass
 *   Scenario: both off skips recompute entirely
 *   Scenario: both dRep and pRep on ties to dMax (via recompute) + a legacy pMax follow-up
 */
#[CoversFunction('pfb_ip_recompute_matrix')]
final class IpRecomputeMatrixTest extends TestCase
{
	// --- dedup on -------------------------------------------------------------------

	public function testDedupOnNoReputationInvokesBothFamiliesRepmodeOff(): void
	{
		$m = pfb_ip_recompute_matrix(true, false, false, false);
		$this->assertTrue($m['invoke_v4']);
		$this->assertTrue($m['invoke_v6'], 'v6 dedup is NEW behaviour under recompute -- deliberate');
		$this->assertSame('on', $m['dedup']);
		$this->assertSame('off', $m['repmode']);
		$this->assertFalse($m['legacy_pmax_followup']);
	}

	public function testDedupOnPlusDrepOnlyPicksDmax(): void
	{
		$m = pfb_ip_recompute_matrix(true, true, true, false);
		$this->assertTrue($m['invoke_v4']);
		$this->assertTrue($m['invoke_v6']);
		$this->assertSame('on', $m['dedup']);
		$this->assertSame('dmax', $m['repmode']);
		$this->assertFalse($m['legacy_pmax_followup']);
	}

	public function testDedupOnPlusPrepOnlyPicksPmax(): void
	{
		$m = pfb_ip_recompute_matrix(true, true, false, true);
		$this->assertSame('on', $m['dedup']);
		$this->assertSame('pmax', $m['repmode']);
		$this->assertFalse($m['legacy_pmax_followup']);
	}

	public function testDedupOnPlusBothDrepAndPrepTiesToDmaxWithLegacyPmaxFollowup(): void
	{
		$m = pfb_ip_recompute_matrix(true, true, true, true);
		$this->assertSame('on', $m['dedup']);
		$this->assertSame('dmax', $m['repmode'], 'dMax wins the recompute repmode slot');
		$this->assertTrue($m['legacy_pmax_followup'], 'pMax runs afterward via the legacy exec');
	}

	public function testDedupOnAndRepTriggerFalseAreIndependentGates(): void
	{
		// This combination cannot occur via the real caller -- $dedup_on is ANDed with
		// rep_trigger there (pfblockerng.inc's recompute call site) -- pins the function's
		// OWN branch in isolation: reputation gates strictly on rep_trigger, dedup does not.
		$m = pfb_ip_recompute_matrix(true, false, true, true);
		$this->assertTrue($m['invoke_v4']);
		$this->assertTrue($m['invoke_v6']);
		$this->assertSame('off', $m['repmode']);
		$this->assertFalse($m['legacy_pmax_followup']);
	}

	// --- dedup off --------------------------------------------------------------------

	public function testDedupOffNoReputationIsNotInvokedAtAll(): void
	{
		$m = pfb_ip_recompute_matrix(false, false, false, false);
		$this->assertFalse($m['invoke_v4']);
		$this->assertFalse($m['invoke_v6']);
	}

	public function testDedupOffRepTriggerFalseIsNotInvokedEvenWithTogglesOn(): void
	{
		$m = pfb_ip_recompute_matrix(false, false, true, true);
		$this->assertFalse($m['invoke_v4'], 'reputation toggles alone do not invoke without the change-trigger');
		$this->assertFalse($m['invoke_v6']);
	}

	public function testDedupOffPlusDrepIsV4OnlyPassthroughDmax(): void
	{
		$m = pfb_ip_recompute_matrix(false, true, true, false);
		$this->assertTrue($m['invoke_v4']);
		$this->assertFalse($m['invoke_v6'], 'v6 is never invoked with dedup off');
		$this->assertSame('off', $m['dedup']);
		$this->assertSame('dmax', $m['repmode']);
		$this->assertFalse($m['legacy_pmax_followup']);
	}

	public function testDedupOffPlusPrepIsV4OnlyPassthroughPmax(): void
	{
		$m = pfb_ip_recompute_matrix(false, true, false, true);
		$this->assertTrue($m['invoke_v4']);
		$this->assertFalse($m['invoke_v6']);
		$this->assertSame('off', $m['dedup']);
		$this->assertSame('pmax', $m['repmode']);
	}

	public function testDedupOffPlusBothDrepAndPrepTiesToDmaxWithLegacyPmaxFollowup(): void
	{
		$m = pfb_ip_recompute_matrix(false, true, true, true);
		$this->assertTrue($m['invoke_v4']);
		$this->assertFalse($m['invoke_v6']);
		$this->assertSame('off', $m['dedup']);
		$this->assertSame('dmax', $m['repmode']);
		$this->assertTrue($m['legacy_pmax_followup']);
	}
}
