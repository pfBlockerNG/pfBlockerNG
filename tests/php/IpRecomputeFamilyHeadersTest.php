<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1084 — pfb_ip_recompute_family_headers() filters $pfb['existing']['deny'] (the
 * removal-detection pre-pass's config-order, complete-for-the-family header list) down to
 * one family, preserving order: the recompute memberlist's PRIORITY order.
 *
 * Feature: per-family memberlist header selection
 *   Branch coverage: family filter selects disjoint v4/v6 subsets; order preserved (not
 *   re-sorted); unrelated-suffix names excluded; empty input; single-family-only input.
 */
#[CoversFunction('pfb_ip_recompute_family_headers')]
final class IpRecomputeFamilyHeadersTest extends TestCase
{
	public function testFamilyFilterSelectsDisjointV4AndV6Subsets(): void
	{
		$existing = array('FeedA_v4', 'FeedB_v6', 'FeedC_v4', 'FeedD_v6');

		$this->assertSame(array('FeedA_v4', 'FeedC_v4'), pfb_ip_recompute_family_headers($existing, 'v4'));
		$this->assertSame(array('FeedB_v6', 'FeedD_v6'), pfb_ip_recompute_family_headers($existing, 'v6'));
	}

	public function testOrderIsPreservedNotResorted(): void
	{
		// Config (priority) order, not alphabetical: 'Zeta' before 'Alpha'.
		$existing = array('Zeta_v4', 'Alpha_v4', 'Mu_v4');
		$this->assertSame(array('Zeta_v4', 'Alpha_v4', 'Mu_v4'), pfb_ip_recompute_family_headers($existing, 'v4'));
	}

	public function testContinentAliasesAreIncludedLikeAnyOtherHeader(): void
	{
		// Continents ($pfb['existing']['deny'][] = "{$pfb_alias}{$vtype}") are indistinguishable
		// from feed headers to this filter -- same suffix contract, same array.
		$existing = array('pfB_Top_v4', 'FeedA_v4');
		$this->assertSame(array('pfB_Top_v4', 'FeedA_v4'), pfb_ip_recompute_family_headers($existing, 'v4'));
	}

	public function testUnrelatedSuffixIsExcluded(): void
	{
		// A name that merely CONTAINS the family token but doesn't END with it must not match.
		$existing = array('FeedA_v4', 'FeedA_v46', 'v4_FeedB');
		$this->assertSame(array('FeedA_v4'), pfb_ip_recompute_family_headers($existing, 'v4'));
	}

	public function testEmptyInputReturnsEmptyArray(): void
	{
		$this->assertSame(array(), pfb_ip_recompute_family_headers(array(), 'v4'));
	}

	public function testSingleFamilyOnlyInputYieldsEmptyForTheOtherFamily(): void
	{
		$existing = array('FeedA_v4');
		$this->assertNotSame(array(), pfb_ip_recompute_family_headers($existing, 'v4'));
		$this->assertSame(array(), pfb_ip_recompute_family_headers($existing, 'v6'));
	}
}
