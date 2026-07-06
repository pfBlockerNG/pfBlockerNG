<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-59 Phase 5 — pfb_top1m_auth_headers().
 *
 * Cloudflare Radar (the first token-authenticated TOP1M provider) needs an
 * 'Authorization: Bearer <token>' header built from the user's top1m_token and the
 * active provider's 'auth' descriptor. This is pure/no-I/O (same extraction rationale
 * as pfb_download_http_headers(), Phase 3) so it is directly unit-testable; it is also
 * the ONLY code that touches the raw token before it reaches pfb_download(), so proving
 * it never logs anything (no pfb_logger call exists in its body at all) is the load-
 * bearing "the token never reaches a log" guarantee for the whole feature.
 */
#[CoversFunction('pfb_top1m_auth_headers')]
final class Top1mAuthHeadersTest extends TestCase
{
	private const CLOUDFLARE_AUTH = ['header' => 'Authorization', 'scheme' => 'Bearer'];

	/**
	 * The Cloudflare shape: a non-empty token produces exactly one Bearer header.
	 *
	 *  GIVEN a provider descriptor whose 'auth' needs a header (Cloudflare's shape)
	 *        and a real-looking token;
	 *   WHEN pfb_top1m_auth_headers() builds the caller headers;
	 *   THEN the result is a single 'Authorization: Bearer <token>' header.
	 */
	public function testHeaderAuthProviderWithTokenProducesBearerHeader(): void
	{
		$provider = ['auth' => self::CLOUDFLARE_AUTH];

		$this->assertSame(
			['Authorization: Bearer cf-abc123'],
			pfb_top1m_auth_headers($provider, 'cf-abc123')
		);
	}

	/**
	 * Safe-on-missing-token (#886 class): an EMPTY token yields no header at all --
	 * pfb_download() then sends the request with no Authorization header, which fails
	 * safely (the provider rejects it) rather than sending a malformed header.
	 *
	 *  GIVEN a provider descriptor whose 'auth' needs a header but NO token is stored;
	 *   WHEN pfb_top1m_auth_headers() builds the caller headers;
	 *   THEN the result is an empty list.
	 */
	public function testHeaderAuthProviderWithEmptyTokenProducesNoHeader(): void
	{
		$provider = ['auth' => self::CLOUDFLARE_AUTH];

		$this->assertSame([], pfb_top1m_auth_headers($provider, ''));
	}

	/**
	 * Every keyless provider (auth == 'none', Tranco/Cisco/DomCop/Majestic today) must
	 * never emit a header, EVEN IF a token happens to be stored (e.g. left over from a
	 * prior Cloudflare selection) -- only the active provider's OWN auth requirement
	 * governs whether the token is sent.
	 *
	 *  GIVEN a keyless provider descriptor (auth == 'none') and a non-empty token;
	 *   WHEN pfb_top1m_auth_headers() builds the caller headers;
	 *   THEN the result is an empty list -- the token is never attached.
	 */
	public function testKeylessProviderNeverEmitsAHeaderEvenWithATokenPresent(): void
	{
		$provider = ['auth' => 'none'];

		$this->assertSame([], pfb_top1m_auth_headers($provider, 'cf-abc123'));
	}

	/** A provider descriptor missing 'auth' entirely defaults to no header (defensive). */
	public function testMissingAuthKeyDefaultsToNoHeader(): void
	{
		$this->assertSame([], pfb_top1m_auth_headers([], 'cf-abc123'));
	}

	/** A schemeless header auth (no Bearer/Basic prefix) sends the token bare. */
	public function testEmptySchemeSendsTokenBareInTheHeaderValue(): void
	{
		$provider = ['auth' => ['header' => 'X-Api-Key', 'scheme' => '']];

		$this->assertSame(
			['X-Api-Key: raw-token'],
			pfb_top1m_auth_headers($provider, 'raw-token')
		);
	}
}
