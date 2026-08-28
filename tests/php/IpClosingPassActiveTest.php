<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1084 review — pfb_ip_closing_pass_active() decides whether the FINAL
 * REPORTING `closing` verb (emptyfiles() + closingprocess()) fires this reload, and
 * which alias arg ('on'/'off') it takes.
 *
 * Pre-fix, `closing` only ever ran when dedup ($pfb['dup']) was 'on' -- the dedup-off +
 * reputation-on invocation matrix cell ("v4 passthrough") never called it at all, so
 * emptyfiles()'s placeholder refill never ran for an alias pMax/dMax collapsed to zero
 * rows: it stayed a genuine 0-byte deny file forever. The fix: dedup off still invokes
 * `closing off` (skipping closingprocess()'s masterfile-specific sanity block, which
 * dedup-off never populates) whenever recompute actually ran the v4 family this pass.
 *
 * Feature: closing-pass invocation gate
 *   Scenario: dedup on always invokes with alias arg 'on' (today's contract, unchanged)
 *   Scenario: dedup off + recompute did NOT run -> never invoked (steady state, no v4 recompute)
 *   Scenario: the defect row -- dedup off + recompute DID run -> invoked with alias arg 'off'
 */
#[CoversFunction('pfb_ip_closing_pass_active')]
final class IpClosingPassActiveTest extends TestCase
{
	public function testDedupOnAlwaysInvokesWithAliasArgOnRegardlessOfRecomputeRan(): void
	{
		$this->assertSame([true, 'on'], pfb_ip_closing_pass_active(true, false));
		$this->assertSame([true, 'on'], pfb_ip_closing_pass_active(true, true));
	}

	public function testDedupOffAndRecomputeDidNotRunNeverInvokes(): void
	{
		[$invoke, $arg] = pfb_ip_closing_pass_active(false, false);
		$this->assertFalse($invoke);
		$this->assertSame('off', $arg);
	}

	public function testDefectRowDedupOffButRecomputeRanStillInvokesWithAliasArgOff(): void
	{
		// The exact case this fix exists for: a dup-off+rep-on pass emptied an alias
		// down to zero rows -- emptyfiles() must still run to refill the placeholder.
		[$invoke, $arg] = pfb_ip_closing_pass_active(false, true);
		$this->assertTrue($invoke, 'recompute having run the v4 family must invoke closing even with dedup off');
		$this->assertSame('off', $arg, 'dedup-off never populates the masterfile -- closingprocess must skip that block');
	}
}
