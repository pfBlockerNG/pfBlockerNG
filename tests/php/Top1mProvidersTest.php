<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-59 Phase 1 -- pfb_top1m_providers() extraction oracle. Extended Phase 4
 * to add the keyless providers DomCop + Majestic.
 *
 * Before Phase 1, pfblockerng.php:162 picked the TOP1M download URL with a
 * hardcoded if/else on the Top1mSource enum. Phase 1 moved both provider's
 * facts into one descriptor table so pfblockerng.php (and, from Phase 2 on, the
 * parser/extractor) reads a single source of truth. Tranco/Cisco stay
 * BEHAVIOUR-PRESERVING throughout: this oracle pins their resolved URL to the
 * exact pre-ADR-59 literal, so any future edit to the table that drifts
 * tranco/cisco's URL fails loudly. Phase 4 adds DomCop + Majestic as two more
 * rows in the same table -- their own shape is pinned separately below.
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

	/** ADR-59 P4 -- the two new keyless providers' URLs, per the ADR §2.2 table. */
	public function testDomCopAndMajesticUrlsMatchTheAdrTable(): void
	{
		$this->assertSame(
			'https://www.domcop.com/files/top/top10milliondomains.csv.zip',
			pfb_top1m_providers()[Top1mSource::DomCop->value]['url']
		);
		$this->assertSame(
			'https://downloads.majestic.com/majestic_million.csv',
			pfb_top1m_providers()[Top1mSource::Majestic->value]['url']
		);
	}

	/** The provider table now carries exactly the four live keyless sources (P4). */
	public function testFourKeylessProvidersAreDescribed(): void
	{
		$this->assertSame(['tranco', 'cisco', 'domcop', 'majestic'], array_keys(pfb_top1m_providers()));
	}

	/**
	 * Tranco/Cisco keep today's implicit shape (zip container, rank_domain CSV
	 * parse, no auth) -- the fields later phases generalized the parser/extractor
	 * against, pinned here so no phase silently changes what Phase 1 shipped.
	 */
	public function testTrancoAndCiscoDescribeTodaysZipRankDomainNoAuthShape(): void
	{
		foreach ([Top1mSource::Tranco->value, Top1mSource::Cisco->value] as $id) {
			$descriptor = pfb_top1m_providers()[$id];
			$this->assertSame('zip', $descriptor['container'], "{$id}: container must be zip");
			$this->assertSame('rank_domain', $descriptor['parse'], "{$id}: parse must be rank_domain");
			$this->assertSame('none', $descriptor['auth'], "{$id}: auth must be none");
		}
	}

	/**
	 * ADR-59 P4 -- DomCop/Majestic's own shape (distinct container/parse/domain_col
	 * per the ADR §2.2 table + Phase 2's 0-indexed domain_col convention): DomCop's
	 * Domain is the 2nd CSV field (index 1, same index Tranco/Cisco use); Majestic's
	 * Domain is the 3rd field (index 2). Majestic's container is 'plain' (uncompressed
	 * CSV), not 'zip' -- the one provider so far that isn't a zip download.
	 */
	public function testDomCopAndMajesticDescribeTheirOwnCsvShape(): void
	{
		$domcop = pfb_top1m_providers()[Top1mSource::DomCop->value];
		$this->assertSame('zip', $domcop['container'], 'domcop: container must be zip');
		$this->assertSame('csv', $domcop['parse'], 'domcop: parse must be csv');
		$this->assertTrue($domcop['header'], 'domcop: header row must be skipped');
		$this->assertSame(1, $domcop['domain_col'], 'domcop: Domain is the 2nd CSV field -> index 1');
		$this->assertSame('none', $domcop['auth'], 'domcop: auth must be none');

		$majestic = pfb_top1m_providers()[Top1mSource::Majestic->value];
		$this->assertSame('plain', $majestic['container'], 'majestic: container must be plain (uncompressed)');
		$this->assertSame('csv', $majestic['parse'], 'majestic: parse must be csv');
		$this->assertTrue($majestic['header'], 'majestic: header row must be skipped');
		$this->assertSame(2, $majestic['domain_col'], 'majestic: Domain is the 3rd CSV field -> index 2');
		$this->assertSame('none', $majestic['auth'], 'majestic: auth must be none');
		$this->assertStringContainsString('CC BY 3.0', $majestic['licence'], 'majestic: CC BY 3.0 licence note must be present');
	}
}
