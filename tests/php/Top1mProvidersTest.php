<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-59 Phase 1 -- pfb_top1m_providers() extraction oracle. Extended Phase 4
 * to add the keyless providers DomCop (now OpenPageRank, #928 -- the DomCop
 * URL froze when the list's hosting moved) + Majestic, and Phase 5 to add the
 * token-authenticated Cloudflare Radar provider.
 *
 * Before Phase 1, pfblockerng.php:162 picked the TOP1M download URL with a
 * hardcoded if/else on the PfbTop1mSource enum. Phase 1 moved both provider's
 * facts into one descriptor table so pfblockerng.php (and, from Phase 2 on, the
 * parser/extractor) reads a single source of truth. Tranco/Cisco stay
 * BEHAVIOUR-PRESERVING throughout: this oracle pins their resolved URL to the
 * exact pre-ADR-59 literal, so any future edit to the table that drifts
 * tranco/cisco's URL fails loudly. Phase 4 adds OpenPageRank + Majestic as two
 * more rows in the same table -- their own shape is pinned separately below.
 * Phase 5 adds Cloudflare Radar -- the first (and so far only) header-auth
 * provider, whose real API shape (verified against Cloudflare's own docs, NOT
 * the ADR's original guess) is a single-column 'domain' CSV, no rank -- domain_col 0.
 */
#[CoversFunction('pfb_top1m_providers')]
final class Top1mProvidersTest extends TestCase
{
	/** Pre-ADR-59 literal from pfblockerng.php:163 -- must stay byte-identical. */
	public function testTrancoUrlIsPinnedToThePreChangeLiteral(): void
	{
		$this->assertSame(
			'https://tranco-list.eu/top-1m.csv.zip',
			pfb_top1m_providers()[PfbTop1mSource::Tranco->value]['url'],
			'tranco TOP1M URL must not drift from the pre-ADR-59 literal'
		);
	}

	/** Pre-ADR-59 literal from pfblockerng.php:165 -- must stay byte-identical. */
	public function testCiscoUrlIsPinnedToThePreChangeLiteral(): void
	{
		$this->assertSame(
			'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
			pfb_top1m_providers()[PfbTop1mSource::Cisco->value]['url'],
			'cisco TOP1M URL must not drift from the pre-ADR-59 literal'
		);
	}

	/** ADR-59 P4 -- the two new keyless providers' URLs; OpenPageRank's per #928 (was DomCop). */
	public function testOpenPageRankAndMajesticUrlsMatchTheAdrTable(): void
	{
		$this->assertSame(
			'https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip',
			pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]['url']
		);
		$this->assertSame(
			'https://downloads.majestic.com/majestic_million.csv',
			pfb_top1m_providers()[PfbTop1mSource::Majestic->value]['url']
		);
	}

	/** The provider table now carries exactly the four keyless sources (P4) plus Cloudflare (P5). */
	public function testFiveProvidersAreDescribed(): void
	{
		$this->assertSame(
			['tranco', 'cisco', 'openpagerank', 'majestic', 'cloudflare'],
			array_keys(pfb_top1m_providers())
		);
	}

	/**
	 * Tranco/Cisco keep today's implicit shape (zip container, rank_domain CSV
	 * parse, no auth) -- the fields later phases generalized the parser/extractor
	 * against, pinned here so no phase silently changes what Phase 1 shipped.
	 */
	public function testTrancoAndCiscoDescribeTodaysZipRankDomainNoAuthShape(): void
	{
		foreach ([PfbTop1mSource::Tranco->value, PfbTop1mSource::Cisco->value] as $id) {
			$descriptor = pfb_top1m_providers()[$id];
			$this->assertSame('zip', $descriptor['container'], "{$id}: container must be zip");
			$this->assertSame('rank_domain', $descriptor['parse'], "{$id}: parse must be rank_domain");
			$this->assertSame('none', $descriptor['auth'], "{$id}: auth must be none");
		}
	}

	/**
	 * ADR-59 P4 -- OpenPageRank/Majestic's own shape (distinct container/parse/domain_col
	 * per the ADR §2.2 table + Phase 2's 0-indexed domain_col convention): OpenPageRank's
	 * Domain is the 2nd CSV field (index 1, same index Tranco/Cisco use); Majestic's
	 * Domain is the 3rd field (index 2). Majestic's container is 'plain' (uncompressed
	 * CSV), not 'zip' -- the one provider so far that isn't a zip download.
	 */
	public function testOpenPageRankAndMajesticDescribeTheirOwnCsvShape(): void
	{
		$openpagerank = pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value];
		$this->assertSame('zip', $openpagerank['container'], 'openpagerank: container must be zip');
		$this->assertSame('csv', $openpagerank['parse'], 'openpagerank: parse must be csv');
		$this->assertTrue($openpagerank['header'], 'openpagerank: header row must be skipped');
		$this->assertSame(1, $openpagerank['domain_col'], 'openpagerank: Domain is the 2nd CSV field -> index 1');
		$this->assertSame('none', $openpagerank['auth'], 'openpagerank: auth must be none');

		$majestic = pfb_top1m_providers()[PfbTop1mSource::Majestic->value];
		$this->assertSame('plain', $majestic['container'], 'majestic: container must be plain (uncompressed)');
		$this->assertSame('csv', $majestic['parse'], 'majestic: parse must be csv');
		$this->assertTrue($majestic['header'], 'majestic: header row must be skipped');
		$this->assertSame(2, $majestic['domain_col'], 'majestic: Domain is the 3rd CSV field -> index 2');
		$this->assertSame('none', $majestic['auth'], 'majestic: auth must be none');
		$this->assertStringContainsString('CC BY 3.0', $majestic['licence'], 'majestic: CC BY 3.0 licence note must be present');
	}

	/**
	 * ADR-59 P5 -- Cloudflare Radar's REAL shape, verified against Cloudflare's own docs
	 * during this phase (not the ADR's original 2-column guess): a single 'domain' column
	 * (no rank) in a PLAIN (uncompressed) CSV, so domain_col is 0 -- not 1. Auth is a
	 * structured {header, scheme} array (distinct from every other provider's plain
	 * 'none' string), the only descriptor row that needs pfb_top1m_auth_headers().
	 */
	public function testCloudflareDescribesItsRealSingleColumnAuthedCsvShape(): void
	{
		$cloudflare = pfb_top1m_providers()[PfbTop1mSource::Cloudflare->value];
		$this->assertSame(
			'https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000',
			$cloudflare['url'],
			'cloudflare: URL must be the stable ranking_top_1000000 dataset alias'
		);
		$this->assertSame('plain', $cloudflare['container'], 'cloudflare: container must be plain (uncompressed CSV stream)');
		$this->assertSame('csv', $cloudflare['parse'], 'cloudflare: parse must be csv');
		$this->assertTrue($cloudflare['header'], 'cloudflare: header row (literal "domain") must be skipped');
		$this->assertSame(
			0,
			$cloudflare['domain_col'],
			'cloudflare: the dataset is a SINGLE domain column (no rank) -> index 0, not the ADR-guessed 1'
		);
		$this->assertIsArray($cloudflare['auth'], 'cloudflare: auth must be a structured header descriptor, not a plain string');
		$this->assertSame('Authorization', $cloudflare['auth']['header'], 'cloudflare: auth header name must be Authorization');
		$this->assertSame('Bearer', $cloudflare['auth']['scheme'], 'cloudflare: auth scheme must be Bearer');
		$this->assertStringContainsString('CC BY-NC', $cloudflare['licence'], 'cloudflare: CC BY-NC licence note must be present');
	}
}
