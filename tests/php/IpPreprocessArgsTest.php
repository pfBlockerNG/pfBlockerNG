<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1084 — pfb_ip_preprocess_args() decides which per-feed shell preprocessing stages
 * ('_255'/'_agg'/'_rep') run before a v4-Deny feed's snapshot is taken. The batch `recompute`
 * verb now owns cross-feed dedup (pfblockerng.sh pfb_recompute()), so '_dup' must NEVER be
 * appended, even when enable_dup is on — the change this test pins (pre-#1084: '_dup' was
 * appended whenever $dup_on).
 *
 * Feature: per-feed preprocessing arg string
 *   Branch coverage: every one of dup_on/agg_on/rep_on toggled independently, plus all-off
 *   and all-on, so '_dup' absence is proven across the WHOLE input space, not one corner.
 */
#[CoversFunction('pfb_ip_preprocess_args')]
final class IpPreprocessArgsTest extends TestCase
{
	public function testAllOffYieldsEmptyArgs(): void
	{
		$this->assertSame('', pfb_ip_preprocess_args(false, false, false));
	}

	public function testDupAloneYields255ButNeverDup(): void
	{
		$args = pfb_ip_preprocess_args(true, false, false);
		$this->assertSame('_255', $args, '_255 runs (dedup needs the 253-collapse pass), but _dup must be absent');
		$this->assertStringNotContainsString('_dup', $args);
	}

	public function testAggAloneYields255Agg(): void
	{
		$this->assertSame('_255_agg', pfb_ip_preprocess_args(false, true, false));
	}

	public function testRepAloneYieldsRepOnlyNo255(): void
	{
		// rep alone does not gate _255 (only dup/agg do) -- matches the pre-existing $args chain.
		$this->assertSame('_rep', pfb_ip_preprocess_args(false, false, true));
	}

	public function testDupAndAggYields255AggNeverDup(): void
	{
		$args = pfb_ip_preprocess_args(true, true, false);
		$this->assertSame('_255_agg', $args);
		$this->assertStringNotContainsString('_dup', $args);
	}

	public function testAllOnYields255AggRepNeverDup(): void
	{
		$args = pfb_ip_preprocess_args(true, true, true);
		$this->assertSame('_255_agg_rep', $args, 'the full preprocessing chain runs, minus the retired _dup stage');
		$this->assertStringNotContainsString('_dup', $args, 'issue #1084: recompute owns dedup now, not the per-feed _dup exec');
	}

	public function testDupAndRepWithoutAggYields255RepNeverDup(): void
	{
		$args = pfb_ip_preprocess_args(true, false, true);
		$this->assertSame('_255_rep', $args);
		$this->assertStringNotContainsString('_dup', $args);
	}
}
