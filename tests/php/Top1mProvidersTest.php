<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-59 Phase 1 -- pfb_top1m_providers() extraction oracle.
 *
 * Before this phase, pfblockerng.php:162 picked the TOP1M download URL with a
 * hardcoded if/else on the Top1mSource enum. This phase moves both provider's
 * facts into one descriptor table so pfblockerng.php (and, from Phase 2 on, the
 * parser/extractor) reads a single source of truth. BEHAVIOUR-PRESERVING: no
 * new provider, no URL change -- this oracle pins the resolved URL for both
 * existing providers to the exact pre-change literal, so any future edit to the
 * table (this phase or later ones) that drifts tranco/cisco's URL fails loudly.
 */
#[CoversFunction('pfb_top1m_providers')]
final class Top1mProvidersTest extends TestCase
{
	/** Pre-ADR-59 literal from pfblockerng.php:163 -- must stay byte-identical. */
	public function testTrancoUrlIsPinnedToThePreChangeLiteral(): void
	{
		$this->assertSame(
			'https://tranco-list.eu/top-1m.csv.zip',
			pfb_top1m_providers()[Top1mSource::Tranco->value]['url'],
			'tranco TOP1M URL must not drift from the pre-ADR-59 literal'
		);
	}

	/** Pre-ADR-59 literal from pfblockerng.php:165 -- must stay byte-identical. */
	public function testCiscoUrlIsPinnedToThePreChangeLiteral(): void
	{
		$this->assertSame(
			'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
			pfb_top1m_providers()[Top1mSource::Cisco->value]['url'],
			'cisco TOP1M URL must not drift from the pre-ADR-59 literal'
		);
	}

	/** Phase 1 carries exactly the two pre-existing providers -- no new source yet. */
	public function testOnlyTrancoAndCiscoAreDescribedInPhase1(): void
	{
		$this->assertSame(['tranco', 'cisco'], array_keys(pfb_top1m_providers()));
	}

	/**
	 * Both providers keep today's implicit shape (zip container, rank_domain CSV
	 * parse, no auth) -- the fields later phases will generalize the parser/extractor
	 * against, pinned here so Phase 2+ cannot silently change what Phase 1 shipped.
	 */
	public function testBothProvidersDescribeTodaysZipRankDomainNoAuthShape(): void
	{
		foreach (pfb_top1m_providers() as $id => $descriptor) {
			$this->assertSame('zip', $descriptor['container'], "{$id}: container must be zip");
			$this->assertSame('rank_domain', $descriptor['parse'], "{$id}: parse must be rank_domain");
			$this->assertSame('none', $descriptor['auth'], "{$id}: auth must be none");
		}
	}
}
